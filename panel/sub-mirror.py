#!/usr/bin/env python3
"""Зеркало подписок на самом VPN-сервере.

    sub-mirror.py serve       слушать HTTPS (так его запускает systemd)
    sub-mirror.py selftest    проверить, что воркер отвечает, ничего не занимая

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

Настройки — в /opt/panel/sub-mirror.env:
    UPSTREAM=https://sub.example.net
    HOSTNAME=sub2.example.net
    PORT=8443
    CERT_DIR=…               необязательно; по умолчанию /etc/letsencrypt/live/<HOSTNAME>
"""
from __future__ import annotations

import http.server
import os
import re
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

# Пути берём только эти. Всё остальное — 404, и ничего из файловой системы
# наружу не отдаётся: зеркало не умеет читать диск по запросу.
ROUTES = (
    re.compile(r"^/$"),
    re.compile(r"^/sub/[0-9a-fA-F-]{36}$"),
    re.compile(r"^/vless/[0-9a-fA-F-]{36}$"),
)


def settings() -> dict[str, str]:
    out = {"PORT": "8443"}
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

    def log_message(self, fmt: str, *args) -> None:
        # Без адресов клиентов: зеркало раздаёт ключи доступа, журнал с ними
        # рядом — лишний способ эти ключи потерять.
        print(f"{self.command} {self.path.split('/')[1] if '/' in self.path[1:] else self.path} "
              f"-> {args[1] if len(args) > 1 else ''}", file=sys.stderr, flush=True)

    def do_HEAD(self) -> None:                                 # noqa: N802
        """Некоторые клиенты сначала спрашивают заголовки. Без этого метода
        базовый обработчик отвечает 501, и клиент решает, что адрес битый."""
        self.do_GET(body=False)

    def do_GET(self, body: bool = True) -> None:               # noqa: N802
        path = self.path.split("?", 1)[0]
        if not any(r.match(path) for r in ROUTES):
            return self.send_error(404, "not found")
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
    server = http.server.ThreadingHTTPServer(("", int(cfg["PORT"])), Handler)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=watch_certificate, args=(context, cert, key),
                     daemon=True, name="cert-watch").start()
    print(f"зеркало подписок на :{cfg['PORT']}, источник {cfg['UPSTREAM']}",
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
    else:
        raise SystemExit(__doc__)
