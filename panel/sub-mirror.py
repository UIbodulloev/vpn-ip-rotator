#!/usr/bin/env python3
"""Зеркало подписок на самом VPN-сервере.

    sub-mirror.py serve       слушать HTTPS (так его запускает systemd)
    sub-mirror.py selftest    проверить, что воркер отвечает, ничего не занимая
    sub-mirror.py devices     кто к каким ссылкам привязан
    sub-mirror.py reset UUID  снять привязку: ссылка снова встанет на любое устройство
    sub-mirror.py limit UUID N  сколько устройств пускать по ссылке (0 — без счёта)
    sub-mirror.py drop UUID ID  убрать одно устройство из привязки (ID — из devices --json)

Зачем. Подписку раздаёт воркер на Cloudflare, но часть мобильных операторов
режет диапазоны, где живут бесплатные зоны Cloudflare: у человека не
открывается ссылка, хотя сам VPN работает. Адрес VPN-сервера у него работает
заведомо — через него же идёт туннель. Поэтому то же самое раздаётся отсюда.

Содержимое НЕ генерируется заново, а забирается у воркера и кладётся в кэш на
диске. Правила маршрутизации должны жить в одном месте: две копии логики
разъедутся, и разъедутся молча. Воркер недоступен — отдаём последнюю удачную
копию, потому что устаревшая подписка лучше отсутствующей.

Порт 443 занят Xray с Reality и трогать его нельзя: на нём держится вся
маскировка под обычный HTTPS. Поэтому 8443.

Одна ссылка — одно устройство. Считается здесь, на установке профиля: ровно
так это сделано в панелях вроде Remnawave. Приложение присылает заголовок
`x-hwid` — отпечаток устройства, — и ссылка привязывается к первому, кто её
установил; второму приходит 403. Заголовок присылают Happ, v2RayTun и
подобные; sing-box и Hiddify — нет, и для них привязка приблизительная: по
семейству приложения, числу сетей и частоте обновлений. Что именно считается,
видно в `devices`.

Чего это НЕ делает: уже установленный профиль продолжает работать, его никто
не отзывает, и человек, выгрузивший конфиг файлом, может отдать его другому.
Ограничение на самом канале — дело сервера, а не ссылки: у VLESS это
`limitIp` в панели (нужен журнал доступа Xray), у Hysteria2 такого нет вовсе.

Настройки — в /opt/panel/sub-mirror.env:
    UPSTREAM=https://sub.example.net
    HOSTNAME=sub2.example.net
    PORT=8443
    CERT_DIR=…               необязательно; по умолчанию /etc/letsencrypt/live/<HOSTNAME>
    DEVICES=1                сколько устройств пускать по одной ссылке; 0 — не считать
"""
from __future__ import annotations

import hashlib
import http.server
import ipaddress
import json
import os
import re
import secrets
import socket
import ssl
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

ENV_FILE = Path("/opt/panel/sub-mirror.env")
CACHE_DIR = Path("/var/cache/sub-mirror")
CACHE_TTL = 3600.0
FETCH_TIMEOUT = 15.0

STATE_FILE = Path("/var/lib/sub-mirror/devices.json")
# Этим адресом проверяют саму раздачу — установщик, selftest, рука
# администратора. Привязывать его к «устройству» нельзя: вторая же проверка
# получила бы 403 и выглядела как поломка.
PROBE_UUID = "00000000-0000-4000-8000-000000000000"
# Сколько разных сетей терпим у одного устройства. Телефон за месяц видит
# домашний Wi-Fi, рабочий, пару чужих и пул оператора — шесть /16 хватает, а
# компании друзей из разных городов не хватает сразу.
NET_BUDGET = 6
NET_WINDOW = 30 * 86400.0
# Два обновления из разных сетей в пределах этого времени — это два устройства:
# одно приложение обновляется раз в сутки по таймеру, а не дважды за десять
# минут из разных сетей.
OVERLAP = 900.0
# Первый час после привязки не придираемся: установка часто дёргает адрес
# несколько раз подряд, иногда уже на ходу, со сменой сети.
INSTALL_GRACE = 3600.0

# Пути берём только эти. Всё остальное — 404, и ничего из файловой системы
# наружу не отдаётся: зеркало не умеет читать диск по запросу.
ROUTES = (
    re.compile(r"^/$"),
    re.compile(r"^/sub/[0-9a-fA-F-]{36}$"),
    re.compile(r"^/vless/[0-9a-fA-F-]{36}$"),
)


def settings() -> dict[str, str]:
    out = {"PORT": "8443", "DEVICES": "1"}
    if ENV_FILE.exists():
        for line in ENV_FILE.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, _, v = line.partition("=")
                out[k.strip()] = v.strip()
    for required in ("UPSTREAM", "HOSTNAME"):
        if not out.get(required):
            raise SystemExit(f"в {ENV_FILE} не задан {required}")
    out["UPSTREAM"] = out["UPSTREAM"].rstrip("/")
    return out


def cache_file(path: str) -> Path:
    # Имя файла из пути: путь уже проверен по ROUTES, фантазии там неоткуда взяться.
    return CACHE_DIR / (path.strip("/").replace("/", "_") or "index")


# --- Одна ссылка — одно устройство -------------------------------------------
# Состояние маленькое, а запись редкая (раз в сутки на человека), поэтому
# хватает файла под блокировкой: база здесь была бы лишней зависимостью.
_state_lock = threading.Lock()


def load_state() -> dict:
    try:
        data = json.loads(STATE_FILE.read_text())
    except (OSError, ValueError):
        data = {}
    if not isinstance(data, dict) or not data.get("salt"):
        # Соль нужна, чтобы хранить сети хешами: адреса людей нам не нужны, а
        # сравнивать хеши так же удобно. Пропадёт соль — просто слетят привязки.
        data = {"salt": secrets.token_hex(16), "links": {}}
    data.setdefault("links", {})
    return data


def save_state(data: dict) -> None:
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = STATE_FILE.with_name(STATE_FILE.name + ".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=1))
    os.chmod(tmp, 0o600)
    tmp.replace(STATE_FILE)        # подмена одним движением: полуфайла не бывает


KNOWN_APPS = ("sing-box", "sfa", "sfi", "sfm", "hiddify", "v2raytun", "v2rayng",
              "happ", "clash", "nekobox", "nekoray", "karing", "streisand",
              "shadowrocket", "foxray", "v2box", "throne", "flclash")
# Семейства, которые устанавливают профиль по-настоящему. Остальное — «слабое»
# устройство: браузер, превью ссылки, неизвестный клиент.
APP_FAMILIES = {"sing-box" if n in ("sfa", "sfi", "sfm") else n for n in KNOWN_APPS}

# Кто открывает ссылку, чтобы нарисовать превью, а не установить профиль:
# мессенджеры и соцсети тянут её сами, как только ссылку кто-то отправил.
PREVIEW_BOTS = ("telegrambot", "whatsapp", "facebookexternalhit", "facebot", "twitterbot",
                "slackbot", "discordbot", "vkshare", "skypeuripreview", "viber",
                "linkedinbot", "applebot", "googlebot", "bingbot", "yandex", "embedly",
                "pinterest", "redditbot", "mattermost", "iframely", "preview")


def ua_family(ua: str) -> str:
    """Семейство приложения из User-Agent. Версия нам не нужна: она меняется
    при каждом обновлении, а устройство остаётся тем же."""
    low = (ua or "").lower()
    for name in KNOWN_APPS:
        if name in low:
            return "sing-box" if name in ("sfa", "sfi", "sfm") else name
    return (low.split("/")[0][:24] or "неизвестное")


def is_weak(device: dict) -> bool:
    """«Слабое» устройство: не настоящее VPN-приложение и без отпечатка.

    Так выглядят браузер без text/html в Accept, превью ссылки и неизвестные
    клиенты. Отказать им совсем нельзя — подменой агента обходился бы лимит, —
    но и место настоящего приложения они занимать не должны."""
    return device.get("kind") != "hwid" and device.get("ua") not in APP_FAMILIES


def net_hash(ip: str, salt: str) -> str:
    """Сеть клиента хешем. Берём /16 у IPv4 и /32 у IPv6: операторы гоняют
    адрес внутри своего пула, и по /24 один телефон выглядел бы десятком."""
    try:
        address = ipaddress.ip_address(ip)
        network = ipaddress.ip_network(f"{ip}/{16 if address.version == 4 else 32}",
                                       strict=False)
    except ValueError:
        network = ip
    return hashlib.blake2s(str(network).encode(), key=salt.encode()[:32],
                           digest_size=6).hexdigest()


def identity(headers, ip: str, salt: str) -> tuple[str, str, str]:
    """(вид, отпечаток, семейство приложения).

    Точный вид — `hwid`: приложение само присылает отпечаток устройства. Так
    делают Happ и v2RayTun, и тогда счёт устройств честный. sing-box и Hiddify
    отпечаток не присылают, и остаётся приблизительный `soft`.
    """
    hwid = (headers.get("x-hwid") or headers.get("x-device-id") or "").strip()
    family = ua_family(headers.get("user-agent", ""))
    if hwid:
        return "hwid", hashlib.blake2s(hwid.encode(), key=salt.encode()[:32],
                                       digest_size=8).hexdigest(), family
    return "soft", family, family


def looks_like_browser(headers) -> bool:
    """Это человек открыл ссылку в браузере, а не приложение её установило.

    Так делают и администратор из любопытства, и сам человек, прежде чем
    скопировать ссылку. Браузер профиль установить не может, а место
    устройства занял бы — и настоящее приложение получило бы отказ. Проверено
    на живом ключе: первой привязкой оказалась «mozilla», а sing-box после неё
    получил 403.
    """
    agent = (headers.get("user-agent") or "").lower()
    accept = (headers.get("accept") or "").lower()
    if any(bot in agent for bot in PREVIEW_BOTS) and not any(app in agent for app in KNOWN_APPS):
        return True                 # превью в мессенджере: ссылку отправили, а не установили
    return "mozilla" in agent and "text/html" in accept


def register(uuid: str, headers, ip: str, limit: int) -> tuple[bool, str]:
    """Пустить ли это устройство к подписке. Пишет состояние по ходу дела."""
    if uuid == PROBE_UUID or looks_like_browser(headers):
        return True, ""
    now = time.time()
    with _state_lock:
        state = load_state()
        kind, ident, family = identity(headers, ip, state["salt"])
        net = net_hash(ip, state["salt"])
        link = state["links"].setdefault(uuid, {"first": now, "devices": [],
                                                "denied": 0, "last_denied": 0})
        cap = int(link.get("limit", limit) or 0)

        def deny(state_: dict, link_: dict, when: float, why: str) -> tuple[bool, str]:
            link_["denied"] = link_.get("denied", 0) + 1
            link_["last_denied"] = when
            save_state(state_)
            return False, why

        mine = next((d for d in link["devices"]
                     if d["kind"] == kind and d["id"] == ident), None)
        if mine is None:
            mine = {"kind": kind, "id": ident, "ua": family, "first": now,
                    "last": now, "hits": 0, "nets": {}, "day": now, "today": 0}
            if cap and len(link["devices"]) >= cap:
                # Место занято. Настоящее приложение вытесняет «слабое»
                # устройство (браузер, превью, неизвестный клиент) — иначе
                # человек, открывший ссылку не там, остаётся без VPN, как было
                # с farah-phone. Слабое настоящее не вытесняет никогда: так
                # подменой агента лимит не обойти.
                weak = [d for d in link["devices"] if is_weak(d)]
                if is_weak(mine) or not weak:
                    return deny(state, link, now,
                                f"устройств по ссылке уже {len(link['devices'])} из {cap}")
                gone = min(weak, key=lambda d: d.get("last", 0))
                link["devices"].remove(gone)
                link["replaced"] = link.get("replaced", 0) + 1
                link["last_replaced"] = {"t": now, "was": gone.get("ua"), "now": family}
                print(f"место «{gone.get('ua')}» занял «{family}»", file=sys.stderr, flush=True)
            link["devices"].append(mine)

        # Приблизительная привязка (sing-box, Hiddify: отпечатка нет). Отказываем
        # только по тому, чего у одного устройства не бывает: десятка сетей за
        # месяц и двух сетей одновременно. Частоту обновлений считаем, но по ней
        # не отказываем: человек жмёт «обновить» как раз когда у него что-то не
        # работает, и получить отказ именно в этот момент — худшее из решений.
        # Точную привязку (hwid) этими правилами не стесняем вовсе.
        if cap and kind == "soft" and now - mine["first"] > INSTALL_GRACE:
            fresh = {k: t for k, t in mine["nets"].items() if now - t < NET_WINDOW}
            if net not in fresh and len(fresh) >= NET_BUDGET * cap:
                mine["nets"] = fresh
                return deny(state, link, now,
                            f"сетей за месяц {len(fresh)} при лимите {NET_BUDGET * cap}")
            if net != mine.get("net") and now - mine["last"] < OVERLAP:
                return deny(state, link, now,
                            "две разные сети в пределах "
                            f"{int(OVERLAP // 60)} минут — это два устройства")

        if now - mine.get("day", 0) > 86400:
            mine["day"], mine["today"] = now, 0
        mine["today"] = mine.get("today", 0) + 1
        mine["nets"] = {k: t for k, t in mine["nets"].items() if now - t < NET_WINDOW}
        mine["nets"][net] = now
        mine["net"] = net
        mine["last"] = now
        mine["hits"] = mine.get("hits", 0) + 1
        mine["ua"] = family
        save_state(state)
        return True, ""


def show_devices(as_json: bool = False) -> None:
    state = load_state()
    if as_json:
        print(json.dumps(state["links"], ensure_ascii=False))
        return
    if not state["links"]:
        return print("привязок нет: ни одну ссылку ещё не устанавливали")
    for uuid, link in sorted(state["links"].items(),
                             key=lambda kv: -max((d["last"] for d in kv[1]["devices"]),
                                                 default=0)):
        cap = link.get("limit", "по умолчанию")
        print(f"{uuid}  лимит {cap}  отказов {link.get('denied', 0)}")
        for d in link["devices"]:
            when = time.strftime("%d.%m %H:%M", time.localtime(d["last"]))
            day = d.get("today", 0)
            exact = "точная" if d["kind"] == "hwid" else "приблизительная"
            print(f"    {d['ua']:<12} {exact:<16} сетей {len(d['nets'])}  "
                  f"обновлений {d['hits']} (за сутки {day})  последнее {when}")


def reset_link(uuid: str) -> None:
    with _state_lock:
        state = load_state()
        if state["links"].pop(uuid, None) is None:
            raise SystemExit(f"привязки для {uuid} и не было")
        save_state(state)
    print(f"привязка снята: {uuid} снова встанет на любое устройство")


def drop_device(uuid: str, device_id: str) -> None:
    """Убрать одно устройство из привязки, не трогая остальные."""
    with _state_lock:
        state = load_state()
        link = state["links"].get(uuid)
        before = len((link or {}).get("devices") or [])
        if link:
            link["devices"] = [d for d in link["devices"] if str(d.get("id")) != device_id]
        if not link or len(link["devices"]) == before:
            raise SystemExit(f"у {uuid} нет устройства {device_id}")
        save_state(state)
    print(f"устройство {device_id} убрано: на его место встанет следующее, кто установит ссылку")


def set_limit(uuid: str, number: int) -> None:
    with _state_lock:
        state = load_state()
        link = state["links"].setdefault(uuid, {"first": time.time(), "devices": [],
                                                "denied": 0, "last_denied": 0})
        link["limit"] = number
        save_state(state)
    print(f"{uuid}: устройств по ссылке — {number or 'сколько угодно'}")


def fetch(upstream: str, path: str) -> tuple[bytes, str, bool]:
    """Содержимое, тип, признак «взято из кэша, свежее получить не вышло»."""
    cached = cache_file(path)
    if cached.exists() and time.time() - cached.stat().st_mtime < CACHE_TTL:
        meta = cached.with_suffix(cached.suffix + ".type")
        kind = meta.read_text().strip() if meta.exists() else "application/json"
        return cached.read_bytes(), kind, False

    request = urllib.request.Request(
        upstream + path, headers={"User-Agent": "sub-mirror/1.0"})
    try:
        with urllib.request.urlopen(request, timeout=FETCH_TIMEOUT) as answer:
            body = answer.read()
            kind = answer.headers.get("content-type", "application/json")
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        cached.write_bytes(body)
        cached.with_suffix(cached.suffix + ".type").write_text(kind)
        return body, kind, False
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        if cached.exists():
            meta = cached.with_suffix(cached.suffix + ".type")
            kind = meta.read_text().strip() if meta.exists() else "application/json"
            print(f"воркер недоступен ({exc}), отдаю копию из кэша", file=sys.stderr, flush=True)
            return cached.read_bytes(), kind, True
        raise


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "sub-mirror"
    sys_version = ""
    upstream = ""
    device_limit = 1

    def log_message(self, fmt: str, *args) -> None:
        # Без адресов клиентов: зеркало раздаёт ключи доступа, журнал с ними
        # рядом — лишний способ эти ключи потерять.
        print(f"{self.command} {self.path.split('/')[1] if '/' in self.path[1:] else self.path} "
              f"-> {args[1] if len(args) > 1 else ''}", file=sys.stderr, flush=True)

    def refuse(self, why: str, body: bool = True) -> None:
        """Отказ так, чтобы человек понял причину и из приложения, и из браузера."""
        print(f"отказ: {why}", file=sys.stderr, flush=True)
        text = ("Эта ссылка уже установлена на другом устройстве.\n\n"
                "Одна ссылка работает на одном устройстве. Попросите "
                "свою ссылку у того, кто дал вам эту.\n").encode()
        self.send_response(403)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(text)))
        self.send_header("Cache-Control", "no-store")
        # Заголовок из того же обихода, что и x-hwid: приложения, которые умеют
        # считать устройства, показывают человеку понятное сообщение сами.
        self.send_header("x-hwid-max-devices-reached", "true")
        self.end_headers()
        if body:
            self.wfile.write(text)

    def do_HEAD(self) -> None:                                 # noqa: N802
        """Некоторые клиенты сначала спрашивают заголовки. Без этого метода
        базовый обработчик отвечает 501, и клиент решает, что адрес битый."""
        self.do_GET(body=False)

    def do_GET(self, body: bool = True) -> None:               # noqa: N802
        path = self.path.split("?", 1)[0]
        if not any(r.match(path) for r in ROUTES):
            return self.send_error(404, "not found")
        if path.startswith("/sub/") and self.device_limit:
            try:
                allowed, why = register(path.rsplit("/", 1)[1].lower(), self.headers,
                                        self.client_address[0], self.device_limit)
            except OSError as exc:
                # Учёт устройств — дело второе. Не записалось состояние — пускаем
                # и жалуемся в журнал: остаться без VPN хуже, чем без учёта.
                print(f"учёт устройств не работает ({exc}), пускаю без счёта",
                      file=sys.stderr, flush=True)
                allowed, why = True, ""
            if not allowed:
                return self.refuse(why, body)
        try:
            content, kind, stale = fetch(self.upstream, path)
        except Exception as exc:                               # noqa: BLE001
            print(f"не удалось получить {path}: {exc}", file=sys.stderr, flush=True)
            return self.send_error(502, "upstream unavailable")
        self.send_response(200)
        self.send_header("Content-Type", kind)
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Cache-Control", "no-store")
        if path.startswith("/sub/"):
            self.send_header("profile-title", "VPN")
            self.send_header("profile-update-interval", "24")
        if stale:
            self.send_header("X-Mirror-Stale", "1")
        self.end_headers()
        if body:
            self.wfile.write(content)


def watch_certificate(context: ssl.SSLContext, cert: Path, key: Path) -> None:
    """Перечитывать сертификат после продления, не перезапуская службу."""
    last = cert.stat().st_mtime
    while True:
        time.sleep(3600)
        try:
            now = cert.stat().st_mtime
            if now != last:
                context.load_cert_chain(cert, key)
                last = now
                print("сертификат перечитан после продления", file=sys.stderr, flush=True)
        except OSError as exc:
            print(f"сертификат не перечитался: {exc}", file=sys.stderr, flush=True)


def serve() -> None:
    cfg = settings()
    host = cfg["HOSTNAME"]
    where = Path(cfg.get("CERT_DIR") or f"/etc/letsencrypt/live/{host}")
    cert, key = where / "fullchain.pem", where / "privkey.pem"
    if not cert.exists() or not key.exists():
        raise SystemExit(f"нет сертификата для {host}: ожидались {cert} и {key}")

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(cert, key)

    Handler.upstream = cfg["UPSTREAM"]
    Handler.device_limit = int(cfg.get("DEVICES", "1") or 0)
    server = http.server.ThreadingHTTPServer(("", int(cfg["PORT"])), Handler)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=watch_certificate, args=(context, cert, key),
                     daemon=True, name="cert-watch").start()
    print(f"зеркало подписок на :{cfg['PORT']}, источник {cfg['UPSTREAM']}, "
          f"устройств на ссылку: {Handler.device_limit or 'не считаем'}",
          file=sys.stderr, flush=True)
    server.serve_forever()


def selftest() -> None:
    cfg = settings()
    probe = "00000000-0000-4000-8000-000000000000"
    for path in ("/", f"/sub/{probe}"):
        try:
            body, kind, stale = fetch(cfg["UPSTREAM"], path)
            print(f"{path:16} {len(body):>7} байт  {kind.split(';')[0]}"
                  f"{'  (из кэша)' if stale else ''}")
        except Exception as exc:                               # noqa: BLE001
            print(f"{path:16} ОШИБКА: {exc}")
            raise SystemExit(1) from None
    host = cfg["HOSTNAME"]
    where = Path(cfg.get("CERT_DIR") or f"/etc/letsencrypt/live/{host}")
    print(f"сертификат {host}: "
          f"{'есть' if (where / 'fullchain.pem').exists() else 'НЕТ — выпустите certbot'}")
    try:
        print(f"{host} резолвится в: {socket.gethostbyname(host)}")
    except OSError as exc:
        print(f"{host} не резолвится: {exc}")


if __name__ == "__main__":
    action = sys.argv[1] if len(sys.argv) > 1 else "serve"
    if action == "serve":
        serve()
    elif action == "selftest":
        selftest()
    elif action == "devices":
        show_devices(as_json="--json" in sys.argv)
    elif action == "reset" and len(sys.argv) > 2:
        reset_link(sys.argv[2].lower())
    elif action == "limit" and len(sys.argv) > 3:
        set_limit(sys.argv[2].lower(), int(sys.argv[3]))
    elif action == "drop" and len(sys.argv) > 3:
        drop_device(sys.argv[2].lower(), sys.argv[3])
    else:
        raise SystemExit(__doc__)
