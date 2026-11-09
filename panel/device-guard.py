#!/usr/bin/env python3
"""Сторож устройств: один ключ — одно устройство, на уровне подключения.

    device-guard.py serve              служба (так её запускает systemd)
    device-guard.py status [--json]    кто сейчас подключён и откуда
    device-guard.py events [--since T] [--json]   что сторож заметил и сделал
    device-guard.py unblock <имя>      снять блокировки с ключа досрочно
    device-guard.py selftest           проверить, что всё на месте

Зачем. Привязку при скачивании подписки (sub-mirror.py) обходит любой, кто
отдал другу уже установленный профиль или файл конфига. Поймать это можно
только там, где идёт сам трафик: в ядре VLESS и в сервере Hysteria2.

Как отличить второе устройство от смены сети. Телефон, ушедший с Wi-Fi на
LTE, оставляет на сервере старые соединения — они висят, пока не истечёт
таймаут, — но новых со старого адреса уже не открывает и данных по ним не
гонит. Поэтому считаем только живое:
  * VLESS: адрес, с которого ядро видело новое соединение за последнюю минуту
    (xray api statsonlineiplist отдаёт время последнего доступа);
  * Hysteria2: QUIC-соединения, по которым шли данные за последнюю минуту
    (/dump/streams), а их адреса — из проверки ключа при входе.
Адреса сравниваются сетями /24 (IPv6 — /64): оператор может выпускать один
телефон через соседние адреса своего NAT, и это не повод считать его двумя.

Два живых адреса у ключа (при лимите 1) в пяти замерах из шести подряд —
это примерно полторы минуты одновременной работы — и есть второе устройство.
Тот, кто подключился раньше, остаётся. Пришедшего позже сторож:
  * в режиме enforce отрезает на BLOCK_MINUTES: в VLESS — правилом ядра для
    пары «ключ + сеть» (другие ключи из той же сети не страдают), в
    Hysteria2 — отказом при входе и разрывом текущего соединения;
  * в режиме notify только записывает событие.
Каждое событие ложится в журнал, откуда его забирает бот и присылает
администратору.

Лимит устройств на ключ берётся оттуда же, откуда его берёт зеркало
подписок (кнопки «Разрешить два устройства» в боте): /var/lib/sub-mirror/
devices.json, иначе DEVICES из настроек. 0 — не ограничивать.

Hysteria2 проверяет каждый вход через этот же процесс (auth: http), поэтому
новые ключи работают сразу, без перезапуска сервера Hysteria и обрыва чужих
сессий. Если сторож лежит — Hysteria никого не пустит, поэтому служба
перезапускается сама, а проверка входа не зависит ни от панели, ни от сети:
список ключей держится в памяти и на диске.

Настройки — /opt/panel/device-guard.env:
    MODE=enforce            или notify
    DEVICES=1               лимит по умолчанию
    BLOCK_MINUTES=30
    AUTH_LISTEN=127.0.0.1:8899
    HY2_API=http://127.0.0.1:8898
    HY2_SECRET=…            тот же, что trafficStats.secret в /etc/hysteria/config.yaml
"""
from __future__ import annotations

import collections
import http.server
import ipaddress
import json
import os
import re
import subprocess
import sys
import threading
import time
import urllib.request
from pathlib import Path

ENV_FILE = Path("/opt/panel/device-guard.env")
STATE_DIR = Path("/var/lib/device-guard")
STATE_FILE = STATE_DIR / "state.json"
EVENTS_FILE = STATE_DIR / "events.jsonl"
MIRROR_STATE = Path("/var/lib/sub-mirror/devices.json")

CONTAINER = "3x-ui"
XRAY = ["docker", "exec", "-i", CONTAINER, "/app/bin/xray-linux-amd64"]
XRAY_API = "--server=127.0.0.1:62789"
LIVE_CONFIG = "/app/bin/config.json"

POLL = 15.0            # секунд между замерами
FRESH = 60.0           # адрес/соединение «живое», если активность была не раньше
WINDOW = 6             # сколько последних замеров помним
STRIKES = 5            # в скольких из них должно быть превышение
FORGET = 600.0         # сеть, не появлявшаяся 10 минут, теряет «старшинство»
RULE_PREFIX = "guard-"
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


def settings() -> dict[str, str]:
    out = {"MODE": "enforce", "DEVICES": "1", "BLOCK_MINUTES": "30",
           "AUTH_LISTEN": "127.0.0.1:8899", "HY2_API": "http://127.0.0.1:8898",
           "HY2_SECRET": ""}
    if ENV_FILE.exists():
        for line in ENV_FILE.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, _, v = line.partition("=")
                out[k.strip()] = v.strip()
    return out


def log(text: str) -> None:
    print(text, file=sys.stderr, flush=True)


def net_of(ip: str) -> str:
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return ip
    prefix = 24 if address.version == 4 else 64
    return str(ipaddress.ip_network(f"{ip}/{prefix}", strict=False))


def host_of(addr: str) -> str:
    """'1.2.3.4:5678' или '[2001:db8::1]:5678' → адрес без порта."""
    if addr.startswith("["):
        return addr[1:addr.index("]")]
    return addr.rsplit(":", 1)[0] if addr.count(":") == 1 else addr


def run(cmd: list[str], data: str | None = None, timeout: float = 15) -> str:
    done = subprocess.run(cmd, input=data, capture_output=True, text=True, timeout=timeout)
    if done.returncode != 0:
        raise RuntimeError((done.stderr or done.stdout).strip()[:200])
    return done.stdout


# --- Состояние ---------------------------------------------------------------

class State:
    """Всё, что сторож помнит. Пишется на диск, чтобы перезапуск службы не
    снимал блокировки и не забывал ключи (без ключей Hysteria никого не пустит)."""

    def __init__(self) -> None:
        self.lock = threading.RLock()
        self.users: dict[str, str] = {}          # uuid → имя
        self.blocks: dict[str, dict] = {}        # "имя|сеть" → {until, ip, tag}
        self.hy2_auth: dict[str, list] = {}      # имя → [[ip, время], …]
        self.first_seen: dict[str, dict] = {}    # имя → {сеть: [первый, последний]}
        self.history: dict[str, collections.deque] = {}
        self.last_note: dict[str, float] = {}    # имя → когда последний раз сообщали
        self.load()

    def load(self) -> None:
        try:
            data = json.loads(STATE_FILE.read_text())
        except (OSError, ValueError):
            return
        self.users = data.get("users", {})
        self.blocks = data.get("blocks", {})
        self.first_seen = data.get("first_seen", {})
        self.last_note = data.get("last_note", {})
        self.hy2_auth = data.get("hy2_auth", {})

    def save(self) -> None:
        with self.lock:
            # hy2_auth тоже на диск: по нему команда status показывает адреса
            # Hysteria2, а сама служба после перезапуска знает, кто где.
            data = {"users": self.users, "blocks": self.blocks,
                    "first_seen": self.first_seen, "last_note": self.last_note,
                    "hy2_auth": self.hy2_auth}
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        tmp = STATE_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, ensure_ascii=False))
        os.chmod(tmp, 0o600)
        tmp.replace(STATE_FILE)

    def blocked(self, name: str, ip: str, now: float) -> bool:
        with self.lock:
            entry = self.blocks.get(f"{name}|{net_of(ip)}")
            return bool(entry and entry["until"] > now)


def event(kind: str, **fields) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    record = {"t": round(time.time()), "kind": kind, **fields}
    with EVENTS_FILE.open("a") as fh:
        fh.write(json.dumps(record, ensure_ascii=False) + "\n")
    log(f"событие: {json.dumps(record, ensure_ascii=False)}")


# --- Источники ---------------------------------------------------------------

def live_users() -> dict[str, str]:
    """uuid → имя для ключей, которые знает запущенное ядро.

    Выключенных в панели ключей в живом конфиге нет — значит, и Hysteria2 их
    не пустит. Раньше hy2-sync брал всех подряд, включая выключенных."""
    data = json.loads(run(["docker", "exec", CONTAINER, "cat", LIVE_CONFIG]))
    out = {}
    for inbound in data.get("inbounds") or []:
        if inbound.get("protocol") != "vless":
            continue
        for client in (inbound.get("settings") or {}).get("clients") or []:
            if client.get("id") and client.get("email"):
                out[client["id"].lower()] = client["email"]
    return out


def xray_live_ips(now: float) -> dict[str, dict[str, str]]:
    """имя → {сеть: адрес} по VLESS, только с новыми соединениями за FRESH."""
    data = json.loads(run(XRAY + ["api", "statsgetallonlineusers", XRAY_API]) or "{}")
    out: dict[str, dict[str, str]] = {}
    for stat in data.get("users") or []:
        name = stat.split(">>>")[1] if ">>>" in stat else stat
        ips = json.loads(run(XRAY + ["api", "statsonlineiplist", XRAY_API,
                                     "-email", name]) or "{}").get("ips") or {}
        fresh = {net_of(ip): ip for ip, seen in ips.items() if now - float(seen) <= FRESH}
        if fresh:
            out[name] = fresh
    return out


def hy2_request(cfg: dict, path: str, body: bytes | None = None) -> object:
    req = urllib.request.Request(cfg["HY2_API"] + path, data=body,
                                 headers={"Authorization": cfg["HY2_SECRET"],
                                          "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=5) as answer:
        text = answer.read().decode() or "null"
    return json.loads(text) if text.strip().startswith(("{", "[")) else None


def hy2_live_conns(cfg: dict, now: float) -> dict[str, int]:
    """имя → сколько QUIC-соединений гоняло данные за FRESH секунд."""
    dump = hy2_request(cfg, "/dump/streams") or {}
    active: dict[str, set] = {}
    for s in dump.get("streams") or []:
        try:
            last = parse_time(s.get("last_active_at", ""))
        except ValueError:
            continue
        if now - last <= FRESH:
            active.setdefault(s.get("auth", ""), set()).add(s.get("connection"))
    return {name: len(conns) for name, conns in active.items() if name}


def parse_time(text: str) -> float:
    """RFC 3339 с наносекундами, как его пишет Go, → unix-время."""
    from datetime import datetime
    text = text.strip()
    if "." in text:
        head, _, tail = text.partition(".")
        digits = tail[:len(tail) - len(tail.lstrip("0123456789"))]   # только ведущие цифры
        zone = tail[len(digits):]
        text = f"{head}.{digits[:6]}{zone}"
    return datetime.fromisoformat(text.replace("Z", "+00:00")).timestamp()


def device_limit(cfg: dict, uuid: str) -> int:
    try:
        links = json.loads(MIRROR_STATE.read_text()).get("links", {})
        if "limit" in links.get(uuid, {}):
            return int(links[uuid]["limit"] or 0)
    except (OSError, ValueError):
        pass
    return int(cfg.get("DEVICES", "1") or 0)


# --- Действия ----------------------------------------------------------------

def xray_rules() -> set[str]:
    data = json.loads(run(XRAY + ["api", "lsrules", XRAY_API]) or "{}")
    return {r.get("ruleTag", "") for r in data.get("rules") or []}


def xray_block(tag: str, name: str, net: str) -> None:
    rule = {"routing": {"rules": [{"ruleTag": tag, "user": [name], "source": [net],
                                   "outboundTag": "blocked"}]}}
    run(XRAY + ["api", "adrules", XRAY_API, "-append", "stdin:"], data=json.dumps(rule))


def xray_unblock(tag: str) -> None:
    try:
        run(XRAY + ["api", "rmrules", XRAY_API, tag])
    except RuntimeError:
        pass                          # правила уже нет (ядро перезапускали) — и ладно


class Guard:
    def __init__(self) -> None:
        self.cfg = settings()
        self.state = State()
        self._users_at = 0.0

    # --- ключи ---
    def refresh_users(self, force: bool = False) -> None:
        if not force and time.time() - self._users_at < 30:
            return
        try:
            users = live_users()
        except (RuntimeError, ValueError, subprocess.TimeoutExpired) as exc:
            log(f"список ключей не обновился ({exc}), работаю по сохранённому")
            return
        self._users_at = time.time()
        with self.state.lock:
            changed = users != self.state.users
            self.state.users = users
        if changed:
            self.state.save()

    # --- вход в Hysteria2 ---
    def auth(self, addr: str, secret: str) -> tuple[bool, str]:
        uuid = (secret or "").strip().lower()
        name = self.state.users.get(uuid)
        if name is None:
            # Ключ могли выдать секунду назад: перечитываем, но не чаще раза в 5 с
            # и только для того, что похоже на ключ. Мусор (сканеры, проверка
            # сторожа здоровья) не должен гонять docker exec на каждый вход.
            if UUID_RE.match(uuid) and time.time() - self._users_at > 5:
                self.refresh_users(force=True)
            name = self.state.users.get(uuid)
        if name is None:
            return False, ""
        ip, now = host_of(addr), time.time()
        if self.state.blocked(name, ip, now):
            return False, name
        with self.state.lock:
            seen = self.state.hy2_auth.setdefault(name, [])
            seen.append([ip, now])
            del seen[:-20]
        return True, name

    # --- замер ---
    def observe(self, now: float) -> dict[str, dict[str, str]]:
        """имя → {сеть: адрес} живых подключений по обоим протоколам."""
        seen: dict[str, dict[str, str]] = {}
        try:
            for name, nets in xray_live_ips(now).items():
                seen.setdefault(name, {}).update(nets)
        except (RuntimeError, ValueError, subprocess.TimeoutExpired) as exc:
            log(f"VLESS не опросился: {exc}")
        try:
            conns = hy2_live_conns(self.cfg, now) if self.cfg["HY2_SECRET"] else {}
        except (OSError, ValueError) as exc:
            log(f"Hysteria2 не опросился: {exc}")
            conns = {}
        with self.state.lock:
            for name, count in conns.items():
                # Адреса последних входов, по одному на каждое живое соединение.
                nets: dict[str, str] = {}
                for ip, _t in reversed(self.state.hy2_auth.get(name, [])):
                    if len(nets) >= count:
                        break
                    nets.setdefault(net_of(ip), ip)
                seen.setdefault(name, {}).update(nets)
        return seen

    def tick(self) -> None:
        now = time.time()
        self.refresh_users()
        seen = self.observe(now)
        uuid_of = {v: k for k, v in self.state.users.items()}
        with self.state.lock:
            for name in set(self.state.history) | set(seen):
                nets = seen.get(name, {})
                hist = self.state.history.setdefault(name, collections.deque(maxlen=WINDOW))
                hist.append(len(nets))
                first = self.state.first_seen.setdefault(name, {})
                for net in nets:
                    first.setdefault(net, [now, now])[1] = now
                for net in [n for n, (_f, last) in first.items() if now - last > FORGET]:
                    del first[net]
                if not first:
                    self.state.first_seen.pop(name, None)

                limit = device_limit(self.cfg, uuid_of.get(name, ""))
                if not limit or len(nets) <= limit:
                    continue
                if sum(1 for n in hist if n > limit) < STRIKES:
                    continue
                # Старшинство: кто раньше появился, тот и хозяин ключа.
                order = sorted(nets, key=lambda n: first.get(n, [now])[0])
                self.punish(name, limit, order[:limit], order[limit:], nets, now)
                hist.clear()
            self.expire(now)
        self.state.save()

    def punish(self, name: str, limit: int, keep: list, extra: list,
               nets: dict[str, str], now: float) -> None:
        mode = self.cfg["MODE"]
        intruders = [nets[n] for n in extra]
        if mode != "enforce":
            if now - self.state.last_note.get(name, 0) > 3600:
                self.state.last_note[name] = now
                event("shared", user=name, limit=limit, owner=[nets[n] for n in keep],
                      others=intruders, action="нет (режим notify)")
            return
        minutes = int(self.cfg.get("BLOCK_MINUTES", "30") or 30)
        for net in extra:
            key = f"{name}|{net}"
            tag = f"{RULE_PREFIX}{abs(hash(key)) % 10**10}"
            self.state.blocks[key] = {"until": now + minutes * 60, "ip": nets[net],
                                      "tag": tag, "user": name, "net": net}
            try:
                xray_block(tag, name, net)
            except (RuntimeError, subprocess.TimeoutExpired) as exc:
                log(f"правило VLESS не встало: {exc}")
        # Разрыв в Hysteria2 рвёт все соединения ключа, но хозяин тут же войдёт
        # снова, а пришлый получит отказ при входе.
        try:
            if self.cfg["HY2_SECRET"]:
                hy2_request(self.cfg, "/kick", json.dumps([name]).encode())
        except (OSError, ValueError) as exc:
            log(f"разрыв Hysteria2 не прошёл: {exc}")
        event("blocked", user=name, limit=limit, owner=[nets[n] for n in keep],
              others=intruders, minutes=minutes)

    def expire(self, now: float) -> None:
        live = None
        for key, entry in list(self.state.blocks.items()):
            if entry["until"] <= now:
                xray_unblock(entry["tag"])
                del self.state.blocks[key]
                event("unblocked", user=entry["user"], ip=entry["ip"], reason="истёк срок")
                continue
            # Ядро перезапускают при каждой выдаче ключа — правила при этом
            # пропадают. Возвращаем.
            if live is None:
                try:
                    live = xray_rules()
                except (RuntimeError, ValueError, subprocess.TimeoutExpired):
                    live = set()
                    continue
            if entry["tag"] not in live:
                try:
                    xray_block(entry["tag"], entry["user"], entry["net"])
                except (RuntimeError, subprocess.TimeoutExpired) as exc:
                    log(f"правило VLESS не вернулось: {exc}")

    def loop(self) -> None:
        while True:
            try:
                self.tick()
            except Exception as exc:                       # noqa: BLE001
                log(f"замер упал: {exc!r}")
            time.sleep(POLL)


# --- HTTP для Hysteria2 ------------------------------------------------------

def make_handler(guard: Guard):
    class Handler(http.server.BaseHTTPRequestHandler):
        server_version = "device-guard"
        sys_version = ""

        def log_message(self, fmt: str, *args) -> None:
            pass                         # в журнале не нужны ни ключи, ни адреса на каждый вход

        def do_POST(self) -> None:       # noqa: N802
            if self.path != "/auth":
                return self.send_error(404)
            try:
                size = int(self.headers.get("content-length") or 0)
                body = json.loads(self.rfile.read(min(size, 4096)) or b"{}")
                ok, name = guard.auth(str(body.get("addr", "")), str(body.get("auth", "")))
            except Exception as exc:     # noqa: BLE001
                log(f"проверка входа упала: {exc!r}")
                ok, name = False, ""
            answer = json.dumps({"ok": ok, "id": name}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(answer)))
            self.end_headers()
            self.wfile.write(answer)
    return Handler


def serve() -> None:
    guard = Guard()
    guard.refresh_users(force=True)
    host, _, port = guard.cfg["AUTH_LISTEN"].rpartition(":")
    server = http.server.ThreadingHTTPServer((host, int(port)), make_handler(guard))
    threading.Thread(target=guard.loop, name="poll", daemon=True).start()
    log(f"сторож устройств: режим {guard.cfg['MODE']}, лимит по умолчанию "
        f"{guard.cfg['DEVICES']}, ключей {len(guard.state.users)}, вход на {guard.cfg['AUTH_LISTEN']}")
    server.serve_forever()


# --- Команды для администратора и бота ---------------------------------------

def cmd_status(as_json: bool) -> None:
    guard = Guard()
    now = time.time()
    seen = guard.observe(now)
    blocks = {k: v for k, v in guard.state.blocks.items() if v["until"] > now}
    if as_json:
        print(json.dumps({"mode": guard.cfg["MODE"], "online": seen,
                          "blocks": list(blocks.values())}, ensure_ascii=False))
        return
    print(f"режим: {guard.cfg['MODE']}, лимит по умолчанию: {guard.cfg['DEVICES']}")
    if not seen:
        print("сейчас никто не подключён")
    for name, nets in sorted(seen.items()):
        print(f"  {name:<16} {len(nets)} сеть(и): {', '.join(nets.values())}")
    for b in blocks.values():
        print(f"  отрезан: {b['user']} с {b['ip']} ещё {int((b['until'] - now) // 60)} мин")


def cmd_events(since: float, as_json: bool) -> None:
    if not EVENTS_FILE.exists():
        print("[]" if as_json else "событий нет")
        return
    rows = []
    for line in EVENTS_FILE.read_text().splitlines():
        try:
            record = json.loads(line)
        except ValueError:
            continue
        if record.get("t", 0) > since:
            rows.append(record)
    if as_json:
        print(json.dumps(rows, ensure_ascii=False))
        return
    for r in rows[-50:]:
        when = time.strftime("%d.%m %H:%M", time.localtime(r["t"]))
        print(f"{when}  {r['kind']:<9} {r.get('user', '')}  "
              f"{json.dumps({k: v for k, v in r.items() if k not in ('t', 'kind', 'user')}, ensure_ascii=False)}")


def cmd_unblock(name: str) -> None:
    """Снимает блокировки и в файле состояния: работающая служба перечитает
    его не сразу, поэтому после правки её перезапускаем — это занимает
    полсекунды и Hysteria2 переживает это без обрыва уже вошедших."""
    state = State()
    gone = [k for k, v in state.blocks.items() if v["user"] == name]
    for key in gone:
        xray_unblock(state.blocks[key]["tag"])
        del state.blocks[key]
    state.first_seen.pop(name, None)
    state.save()
    subprocess.run(["systemctl", "restart", "device-guard"], capture_output=True)
    if gone:
        event("unblocked", user=name, reason="снято администратором")
    print(f"{name}: снято блокировок — {len(gone)}")


def cmd_selftest() -> None:
    cfg = settings()
    ok = True
    try:
        users = live_users()
        print(f"ключей в ядре VLESS: {len(users)}")
    except Exception as exc:                               # noqa: BLE001
        print(f"ядро VLESS: ОШИБКА {exc}")
        ok = False
    try:
        print(f"онлайн по VLESS: {len(xray_live_ips(time.time()))}")
    except Exception as exc:                               # noqa: BLE001
        print(f"API ядра: ОШИБКА {exc}")
        ok = False
    if cfg["HY2_SECRET"]:
        try:
            print(f"онлайн по Hysteria2: {hy2_request(cfg, '/online')}")
        except Exception as exc:                           # noqa: BLE001
            print(f"API Hysteria2: ОШИБКА {exc}")
            ok = False
    else:
        print("Hysteria2: HY2_SECRET не задан — сторожу виден только VLESS")
    print(f"режим: {cfg['MODE']}")
    raise SystemExit(0 if ok else 1)


if __name__ == "__main__":
    args = sys.argv[1:] or ["serve"]
    action = args[0]
    if action == "serve":
        serve()
    elif action == "status":
        cmd_status("--json" in args)
    elif action == "events":
        since = float(args[args.index("--since") + 1]) if "--since" in args else 0.0
        cmd_events(since, "--json" in args)
    elif action == "unblock" and len(args) > 1:
        cmd_unblock(args[1])
    elif action == "selftest":
        cmd_selftest()
    else:
        raise SystemExit(__doc__)
