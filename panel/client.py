#!/usr/bin/env python3
"""Управление клиентами VLESS+Reality в 3X-UI.

    client.py list
    client.py add <имя>
    client.py link <имя>
    client.py del <имя>
    client.py sync

Панель слушает только 127.0.0.1, поэтому скрипт живёт на VPN-сервере, а бот
вызывает его по SSH. API у версии 26.x переделан: клиенты — отдельный ресурс,
ключ в URL — email, а inbound передаётся рядом с объектом клиента.

Ссылки собираются здесь, а не берутся из панели: панель не знает домен и отдаёт
их с @localhost, а нам нужен именно домен — на него смотрит ротация адреса.
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
import time
import urllib.parse
import uuid as uuidlib

PANEL = "http://127.0.0.1:2053"
CONTAINER = "3x-ui"
INBOUND_ID = 1
NAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,32}$")


def env(path: str) -> dict[str, str]:
    out = {}
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, _, v = line.partition("=")
                out[k.strip()] = v.strip()
    return out


CREDS = env("/opt/panel/credentials")
PARAMS = env("/opt/panel/reality-params.env")
TOKEN = CREDS["PANEL_API_TOKEN"]


def api(method: str, path: str, payload: dict | None = None) -> dict:
    """Запрос к панели изнутри её контейнера — наружу порт не открыт."""
    cmd = ["docker", "exec", "-i", CONTAINER, "curl", "-s", "-X", method,
           f"{PANEL}{path}", "-H", f"Authorization: Bearer {TOKEN}"]
    if payload is not None:
        cmd += ["-H", "Content-Type: application/json", "--data-binary", "@-"]
    done = subprocess.run(cmd, input=json.dumps(payload) if payload else None,
                          capture_output=True, text=True, timeout=30)
    if done.returncode != 0:
        raise SystemExit(f"панель недоступна: {done.stderr.strip()[:200]}")
    try:
        return json.loads(done.stdout or "{}")
    except json.JSONDecodeError:
        raise SystemExit(f"панель ответила не-JSON: {done.stdout[:200]}") from None


LIVE_CONFIG = "/app/bin/config.json"


def restart_xray() -> None:
    """Пересобрать живой конфиг ядра из базы панели.

    Панель 3.11 применяет добавление клиента через core API и файл
    config.json не перезаписывает. Любой следующий перезапуск ядра читает
    файл — и клиента в нём нет: ключ выдан, в панели виден, а телефон
    получает timeout. Поэтому после каждой правки просим пересборку.
    """
    answer = api("POST", "/panel/api/server/restartXrayService")
    if not answer.get("success"):
        raise SystemExit(f"панель не перезапустила ядро: {(answer.get('msg') or '').strip()}")


def live_uuids() -> set[str]:
    """UUID, которые реально знает запущенное ядро (а не только база)."""
    done = subprocess.run(["docker", "exec", CONTAINER, "cat", LIVE_CONFIG],
                          capture_output=True, text=True, timeout=30)
    if done.returncode != 0:
        raise SystemExit(f"живой конфиг не читается: {done.stderr.strip()[:200]}")
    try:
        data = json.loads(done.stdout)
    except json.JSONDecodeError:
        raise SystemExit("живой конфиг не разбирается как JSON") from None
    out = set()
    for inbound in data.get("inbounds") or []:
        for client in (inbound.get("settings") or {}).get("clients") or []:
            if client.get("id"):
                out.add(client["id"])
    return out


def wait_live(uid: str, present: bool) -> None:
    """Дождаться, пока ядро действительно подхватит (или забудет) UUID."""
    for _ in range(20):
        if (uid in live_uuids()) == present:
            return
        time.sleep(0.5)
    raise SystemExit("ядро не подхватило правку: ключ есть в панели, но не в живом конфиге — "
                     "перезапустите контейнер 3x-ui и проверьте client.py list")


def clients() -> list[dict]:
    answer = api("GET", "/panel/api/clients/list")
    if not answer.get("success"):
        raise SystemExit(f"панель: {answer.get('msg')}")
    return answer.get("obj") or []


def human_bytes(n: int) -> str:
    for unit in ("Б", "КБ", "МБ", "ГБ", "ТБ"):
        if n < 1024 or unit == "ТБ":
            return f"{n:.0f}{unit}" if unit == "Б" else f"{n:.1f}{unit}"
        n /= 1024.0
    return f"{n:.1f}ТБ"


def build_link(uid: str, name: str, flow: str) -> str:
    query = {
        "type": "tcp", "security": "reality", "encryption": "none",
        "pbk": PARAMS["PUBLIC_KEY"], "fp": PARAMS.get("FINGERPRINT", "chrome"),
        "sni": PARAMS["SNI"], "sid": PARAMS["SHORT_ID"], "spx": "/",
    }
    if flow:
        query["flow"] = flow
    return (f"vless://{uid}@{PARAMS['HOST']}:{PARAMS['PORT']}"
            f"?{urllib.parse.urlencode(query)}#{urllib.parse.quote(name)}")


def find(name: str) -> dict | None:
    return next((c for c in clients() if c["email"] == name), None)


def cmd_list() -> None:
    found = clients()
    if not found:
        print("клиентов нет")
        return
    live = live_uuids()
    for c in found:
        traffic = c.get("traffic") or {}
        used = int(traffic.get("up", 0)) + int(traffic.get("down", 0))
        state = "вкл" if c.get("enable") else "ВЫКЛ"
        # Ключ может быть в панели и отсутствовать в ядре — тогда у человека timeout.
        if c["uuid"] not in live:
            state += " / НЕ В ЯДРЕ"
        print(f"{c['email']}\t{c['uuid']}\t{human_bytes(used)}\t{state}")


def cmd_add(name: str) -> None:
    if find(name):
        raise SystemExit(f"клиент {name} уже есть")
    uid = str(uuidlib.uuid4())
    flow = "xtls-rprx-vision"
    answer = api("POST", "/panel/api/clients/add", {
        # Обёртка {"client": ..., "inboundIds": [...]} — выяснена на живой панели:
        # inboundIds именно рядом с client, внутри он не принимается.
        "client": {
            "email": name, "uuid": uid, "flow": flow, "enable": True,
            "limitIp": 0, "totalGB": 0, "expiryTime": 0, "tgId": 0,
            "subId": uid, "comment": "выдан ботом",
        },
        "inboundIds": [INBOUND_ID],
    })
    if not answer.get("success"):
        raise SystemExit(f"панель: {(answer.get('msg') or '').strip()}")
    # Панель ИГНОРИРУЕТ присланный uuid и выдаёт свой, поэтому ссылку собираем
    # по тому, что реально сохранилось. Иначе клиент получит нерабочий ключ.
    created = find(name)
    if not created:
        raise SystemExit("клиент создан, но не читается обратно — проверьте панель")
    restart_xray()
    wait_live(created["uuid"], present=True)
    print(build_link(created["uuid"], name, created.get("flow") or flow))


def cmd_sync() -> None:
    """Заставить ядро перечитать клиентов из базы панели.

    Нужна, если ключ есть в панели, но помечен «НЕ В ЯДРЕ»: человек получит
    timeout, пока конфиг ядра не пересобран.
    """
    before = live_uuids()
    restart_xray()
    for _ in range(20):
        after = live_uuids()
        if after != before or len(after) == len(clients()):
            break
        time.sleep(0.5)
    else:
        after = live_uuids()
    known = {c["uuid"] for c in clients()}
    missing = known - after
    if missing:
        raise SystemExit(f"ядро всё ещё не знает {len(missing)} ключ(ей) — перезапустите контейнер {CONTAINER}")
    print(f"ядро знает все ключи: {len(known)}")


def cmd_link(name: str) -> None:
    c = find(name)
    if not c:
        raise SystemExit(f"клиента {name} нет")
    print(build_link(c["uuid"], name, c.get("flow") or ""))


def cmd_del(name: str) -> None:
    doomed = find(name)
    if not doomed:
        raise SystemExit(f"клиента {name} нет")
    answer = api("POST", f"/panel/api/clients/del/{urllib.parse.quote(name)}")
    if not answer.get("success"):
        raise SystemExit(f"панель: {(answer.get('msg') or '').strip()}")
    restart_xray()
    wait_live(doomed["uuid"], present=False)
    print(f"удалён: {name}")


def main() -> None:
    if len(sys.argv) < 2:
        raise SystemExit(__doc__)
    action = sys.argv[1]
    if action == "list":
        return cmd_list()
    if action == "sync":
        return cmd_sync()
    if len(sys.argv) < 3:
        raise SystemExit(f"{action}: нужно имя клиента")
    name = sys.argv[2]
    # Имя приходит из Telegram и попадает в URL и в команду — проверяем строго.
    if not NAME_RE.match(name):
        raise SystemExit("недопустимое имя: только латиница, цифры, дефис и подчёркивание, до 32 символов")
    {"add": cmd_add, "link": cmd_link, "del": cmd_del}.get(action, lambda _n: (_ for _ in ()).throw(
        SystemExit(f"неизвестная команда {action}")))(name)


if __name__ == "__main__":
    main()
