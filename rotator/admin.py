"""Веб-админка: статистика и управление, вход по Google Authenticator.

Слушает только 127.0.0.1:8787 — наружу её выставляет nginx на medbot
(admin.mos8.online, HTTPS). Секрет для Authenticator выпускает бот командой
/admin и хранит в secrets.env как ADMIN_TOTP_SECRET.

Устройство:
  admin_ui.py     дизайн-система: стили, иконки, графики, каркас страницы
  admin_pages.py  страницы: обзор, люди, профиль, адреса, сервер, здоровье, задачи
  admin_ops.py    действия: те же операции, что у бота, с результатом на странице
  admin.py        вход, сессии, маршруты, подтверждения (этот файл)

Защита:
  * код TOTP (RFC 6238: SHA-1, 6 цифр, шаг 30 с, допуск ±1 шаг), один код — один вход;
  * 5 неверных кодов с адреса за 15 минут — адрес заблокирован на 15 минут;
    20 неверных за час со всех адресов — вход закрыт для всех на час;
  * о каждом входе, блокировке и действии бот пишет владельцу в Telegram;
  * сессия — случайный токен в cookie (Secure, HttpOnly, SameSite=Strict), 12 часов;
  * каждое действие — POST с токеном CSRF сессии; опасные переспрашивают;
  * страницы без скриптов вовсе: CSP запрещает их целиком.
"""
from __future__ import annotations

import base64
import collections
import hashlib
import hmac
import http.server
import re
import secrets as pysecrets
import struct
import threading
import time
import urllib.parse
from typing import Any

from . import admin_pages as pages
from . import log, modes
from .admin_ops import ISSUE_KINDS, NAME_RE, Ops
from .admin_ui import clock, document, esc, flash, icon, shell
from .stats import Stats

logger = log.get("admin")

LISTEN = ("127.0.0.1", 8787)
SESSION_TTL = 12 * 3600
IP_FAILS, IP_WINDOW, IP_LOCK = 5, 15 * 60, 15 * 60
ALL_FAILS, ALL_WINDOW, ALL_LOCK = 20, 3600, 3600

# Совместимость: старые вызовы и тесты берут это отсюда.
rotation_periods = pages.rotation_periods


# --- TOTP ---------------------------------------------------------------------

def new_secret() -> str:
    return base64.b32encode(pysecrets.token_bytes(20)).decode().rstrip("=")


def totp(secret: str, counter: int, digits: int = 6) -> str:
    key = base64.b32decode(secret.upper() + "=" * (-len(secret) % 8))
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = (struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF) % 10 ** digits
    return str(code).zfill(digits)


def otpauth_uri(secret: str, label: str = "VPN admin") -> str:
    return (f"otpauth://totp/{urllib.parse.quote(label)}?secret={secret}"
            f"&issuer={urllib.parse.quote('mos8 VPN')}&digits=6&period=30")


class Auth:
    def __init__(self, get_secret, notify):
        self.get_secret = get_secret
        self.notify = notify
        self.lock = threading.Lock()
        self.sessions: dict[str, dict] = {}
        self.fails: dict[str, collections.deque] = {}
        self.all_fails: collections.deque = collections.deque()
        self.locked_ip: dict[str, float] = {}
        self.locked_all = 0.0
        self.last_counter = 0

    def check_code(self, code: str, ip: str, now: float | None = None) -> tuple[bool, str]:
        now = now or time.time()
        secret = self.get_secret()
        if not secret:
            return False, "Вход не настроен: отправьте боту /admin."
        with self.lock:
            if now < self.locked_all:
                return False, "Слишком много неверных кодов. Вход закрыт до " + clock(self.locked_all) + "."
            if now < self.locked_ip.get(ip, 0):
                return False, "С этого адреса слишком много неверных кодов. Попробуйте после " \
                              + clock(self.locked_ip[ip]) + "."
            code = "".join(ch for ch in code if ch.isdigit())
            counter = int(now // 30)
            for step in (0, -1, 1):
                c = counter + step
                if len(code) == 6 and c > self.last_counter and hmac.compare_digest(totp(secret, c), code):
                    self.last_counter = c
                    self.fails.pop(ip, None)
                    return True, ""
            window = self.fails.setdefault(ip, collections.deque())
            for q in (window, self.all_fails):
                q.append(now)
            while window and now - window[0] > IP_WINDOW:
                window.popleft()
            while self.all_fails and now - self.all_fails[0] > ALL_WINDOW:
                self.all_fails.popleft()
            if len(self.all_fails) >= ALL_FAILS:
                self.locked_all = now + ALL_LOCK
                self.all_fails.clear()
                self.notify(f"🔐 Админка: {ALL_FAILS} неверных кодов за час — вход закрыт для всех на час. "
                            f"Последняя попытка с {ip}.")
            elif len(window) >= IP_FAILS:
                self.locked_ip[ip] = now + IP_LOCK
                window.clear()
                self.notify(f"🔐 Админка: {IP_FAILS} неверных кодов с {ip} — адрес заблокирован на 15 минут.")
            return False, "Неверный или уже использованный код."

    def open_session(self) -> str:
        token = pysecrets.token_urlsafe(32)
        with self.lock:
            now = time.time()
            self.sessions = {t: s for t, s in self.sessions.items() if s["exp"] > now}
            self.sessions[token] = {"exp": now + SESSION_TTL, "csrf": pysecrets.token_urlsafe(24), "flash": ""}
        return token

    def session(self, token: str) -> dict | None:
        with self.lock:
            s = self.sessions.get(token or "")
            return s if s and s["exp"] > time.time() else None

    def valid(self, token: str) -> bool:
        return self.session(token) is not None

    def close(self, token: str) -> None:
        with self.lock:
            self.sessions.pop(token, None)


# --- Вход ---------------------------------------------------------------------

def login_page(error: str = "") -> bytes:
    return document("Вход", f"""<div class="login"><div class="card">
<span class="mark">{icon("shield")}</span><h1>mos8 VPN</h1>
<p class="muted small" style="margin:0">Введите код из Google Authenticator</p>
<form method="post" action="/login" autocomplete="off">
<input name="code" inputmode="numeric" pattern="[0-9 ]*" maxlength="7" autofocus required aria-label="Код">
<div class="err">{esc(error)}</div><button class="btn primary">Войти</button></form></div></div>""")


# --- Подтверждения ------------------------------------------------------------
# action → (заголовок, текст, опасно ли). Нет в словаре — выполняется сразу.

def confirmation(action: str, form: dict[str, str], bot) -> tuple[str, str, bool] | None:
    name = esc(form.get("name", ""))
    if action == "key.delete":
        return "Удалить ключ", f"Ключ «{name}» перестанет работать сразу на всех устройствах. Вернуть его нельзя — " \
                               "только выдать новый.", True
    if action == "awg.revoke":
        return "Отозвать конфиг", f"Файл «{name}.conf» перестанет подключаться сразу.", True
    if action == "rotate":
        mode = form.get("mode", "")
        where = f" в {esc(form.get('zone'))}" if mode == modes.MOVE else ""
        return "Сменить адрес", f"{esc(modes.MODE_TITLES.get(mode, mode)).capitalize()}{where}. VPN будет недоступен " \
                                "несколько минут, DNS обновится сам. Клиенты переподключатся без вашего участия.", False
    if action == "unstick":
        return "Снять отметку", "Делайте это, только если смена адреса точно не идёт: иначе бот потеряет, " \
                                "на каком она шаге.", True
    if action.startswith("server."):
        what = action.split(".", 1)[1]
        if what in bot.SERVER_ACTIONS:
            heading, text, _button = bot.SERVER_ACTIONS[what]
            return heading, esc(text), what in ("delete", "storage-del", "backup-del")
        extra = {"restore": ("Восстановить диск", "Данные Backup будут записаны поверх текущего диска. Всё, что "
                             "появилось после его снятия, пропадёт. Сервер остановится и запустится снова.", True),
                 "create": ("Поднять сервер из шаблона", "Будет создан новый сервер — он тарифицируется отдельно. "
                            "DNS не меняется: это не смена адреса.", False),
                 "docker-restart": ("Перезапустить контейнеры", "Все подключения VPN оборвутся на несколько секунд.", False),
                 "backup-now": ("Сделать Backup", "Backup тарифицируется как дополнительное хранилище.", False)}
        if what in extra:
            return extra[what]
    return None


# --- HTTP ---------------------------------------------------------------------

def make_handler(bot, stats: Stats, auth: Auth, ops: Ops):
    class Handler(http.server.BaseHTTPRequestHandler):
        server_version = "admin"
        sys_version = ""

        def log_message(self, fmt: str, *args) -> None:
            pass

        # --- помощники ---
        def client_ip(self) -> str:
            # Слушаем только 127.0.0.1, так что заголовок ставит наш nginx.
            return (self.headers.get("X-Real-IP") or self.client_address[0]).strip()

        def token(self) -> str:
            for part in (self.headers.get("Cookie") or "").split(";"):
                k, _, v = part.strip().partition("=")
                if k == "adm":
                    return v
            return ""

        def reply(self, body: bytes, status: int = 200, extra: dict | None = None,
                  ctype: str = "text/html; charset=utf-8") -> None:
            self.send_response(status)
            headers = {"Content-Type": ctype, "Cache-Control": "no-store",
                       "X-Frame-Options": "DENY", "Referrer-Policy": "same-origin",
                       "X-Content-Type-Options": "nosniff",
                       "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; "
                                                  "img-src 'self' data:; form-action 'self'; frame-ancestors 'none'; "
                                                  "base-uri 'none'",
                       "Content-Length": str(len(body)), **(extra or {})}
            for k, v in headers.items():
                self.send_header(k, v)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def redirect(self, where: str, cookie: str | None = None) -> None:
            extra = {"Location": where}
            if cookie is not None:
                extra["Set-Cookie"] = cookie
            self.reply(b"", 303, extra)

        def back(self, fallback: str = "/") -> str:
            """Куда вернуться после действия: та же страница, с которой пришли."""
            ref = urllib.parse.urlsplit(self.headers.get("Referer") or "")
            path = ref.path + (f"?{ref.query}" if ref.query else "")
            return path if path.startswith("/") and not path.startswith("//") and path != "/do" else fallback

        def ctx(self, session: dict, query: dict) -> pages.Ctx:
            note, session["flash"] = session.get("flash", ""), ""
            return pages.Ctx(bot=bot, stats=stats, ops=ops, csrf=session["csrf"], q=query, note=note)

        def render(self, session: dict, result: tuple[str, str, str], refresh: int = 0, status: int = 200) -> None:
            title, active, content = result
            self.reply(shell(active, title, content, session["csrf"], refresh), status)

        # --- GET ---
        def do_HEAD(self) -> None:                                  # noqa: N802
            self.do_GET()

        def do_GET(self) -> None:                                   # noqa: N802
            url = urllib.parse.urlsplit(self.path)
            path = url.path
            query = {k: v[0] for k, v in urllib.parse.parse_qs(url.query).items()}
            if path == "/login":
                return self.reply(login_page())
            session = auth.session(self.token())
            if not session:
                return self.redirect("/login")
            try:
                c = self.ctx(session, query)
                if path == "/":
                    return self.render(session, pages.overview(c))
                if path == "/people":
                    return self.render(session, pages.people_page(c))
                if path == "/people/new":
                    return self.render(session, pages.new_person(c))
                if path == "/person":
                    return self.render(session, pages.person_page(c))
                if path == "/addresses":
                    return self.render(session, pages.addresses(c))
                if path == "/server":
                    return self.render(session, pages.server_page(c))
                if path == "/health":
                    return self.render(session, pages.health(c))
                if path == "/jobs":
                    return self.render(session, pages.jobs_page(c))
                if path.startswith("/jobs/"):
                    job = ops.jobs.get(path.rsplit("/", 1)[1])
                    if not job:
                        return self.redirect("/jobs")
                    return self.render(session, pages.job_page(c, job), refresh=3 if job.status == "running" else 0)
                if path == "/download/awg":
                    name = query.get("n", "")
                    conf = ops.awg_conf(name) if NAME_RE.match(name) else ""
                    if not conf:
                        session["flash"] = flash("bad", "Конфига с таким именем нет.")
                        return self.redirect("/people")
                    ops.audit(f"скачан конфиг AmneziaWG {name}")
                    return self.reply(conf.encode(), extra={
                        "Content-Disposition": f'attachment; filename="{name}.conf"'},
                        ctype="text/plain; charset=utf-8")
                self.render(session, ("Нет такой страницы", "", '<div class="empty">Такой страницы нет. '
                                      '<a href="/"><u>На обзор</u></a></div>'), status=404)
            except Exception as exc:                               # noqa: BLE001
                logger.exception("страница админки %s не собралась", path)
                self.render(session, ("Ошибка", "", flash("bad", f"Страница не собралась: {esc(exc)}")), status=500)

        # --- POST ---
        def form(self) -> dict[str, str]:
            size = min(int(self.headers.get("Content-Length") or 0), 8192)
            return {k: v[0] for k, v in urllib.parse.parse_qs(self.rfile.read(size).decode(errors="replace")).items()}

        def do_POST(self) -> None:                                  # noqa: N802
            form = self.form()
            if self.path == "/login":
                ip = self.client_ip()
                ok, why = auth.check_code(form.get("code", ""), ip)
                if not ok:
                    return self.reply(login_page(why), 401)
                token = auth.open_session()
                auth.notify(f"🔐 Вход в админку с {ip}")
                return self.redirect("/", f"adm={token}; Max-Age={SESSION_TTL}; Path=/; Secure; HttpOnly; SameSite=Strict")
            session = auth.session(self.token())
            if not session:
                return self.redirect("/login")
            if not hmac.compare_digest(form.get("csrf", ""), session["csrf"]):
                session["flash"] = flash("bad", "Форма устарела — повторите действие.")
                return self.redirect(self.back())
            if self.path == "/logout":
                auth.close(self.token())
                return self.redirect("/login", "adm=; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=Strict")
            if self.path != "/do":
                return self.reply(b"", 404)
            try:
                self.act(session, form)
            except Exception as exc:                               # noqa: BLE001
                logger.exception("действие админки %s упало", form.get("action"))
                session["flash"] = flash("bad", f"Не вышло: {esc(exc)}")
                self.redirect(self.back())

        def act(self, session: dict, form: dict[str, str]) -> None:
            action = form.get("action", "")
            name = form.get("name", "")
            if name and not NAME_RE.match(name):
                session["flash"] = flash("bad", "Имя — латиница, цифры, «-» и «_», до 32 символов.")
                return self.redirect(self.back())

            ask = confirmation(action, form, bot)
            if ask and form.get("confirm") != "1":
                title, text, danger = ask
                keep = {k: v for k, v in form.items() if k != "confirm"}
                c = self.ctx(session, {})
                return self.render(session, pages.confirm_page(c, title, text, keep, danger, self.back()))

            def done(result: tuple[bool, str], where: str | None = None) -> None:
                ok, text = result
                session["flash"] = flash("ok" if ok else "bad", esc(text))
                self.redirect(where or self.back())

            def job(j) -> None:
                self.redirect(f"/jobs/{j.id}")

            if action == "key.issue":
                kind = form.get("kind", "sub")
                if not name or kind not in ISSUE_KINDS:
                    session["flash"] = flash("bad", "Укажите имя и что выдать.")
                    return self.redirect("/people/new")
                if any(k["name"] == name for k in ops.keys()) and not kind.startswith("awg-"):
                    session["flash"] = flash("bad", f"Ключ «{esc(name)}» уже есть — выберите другое имя.")
                    return self.redirect("/people/new")
                return job(ops.key_issue(name, kind, form.get("tg") == "1"))
            if action == "key.delete":
                return done(ops.key_delete(name), "/people")
            if action == "key.resend":
                return done(ops.key_resend(name))
            if action == "key.unbind":
                return done(ops.key_unbind(name))
            if action == "key.limit":
                return done(ops.key_limit(name, 2 if form.get("n") == "2" else 1))
            if action == "key.unblock":
                return done(ops.key_unblock(name))
            if action == "key.sync":
                return done(ops.key_sync())
            if action == "awg.revoke":
                return done(ops.awg_revoke(name), "/people?f=awg")
            if action == "awg.send":
                return done(ops.awg_send(name))
            if action.startswith("server."):
                what = action.split(".", 1)[1]
                arg = form.get("arg", "")
                if what == "restore" and re.fullmatch(r"[0-9a-f-]{36}", arg):
                    return job(ops.server_job(f"restore:{arg}"))
                if what == "create" and re.fullmatch(r"[0-9a-f-]{36}", arg):
                    return job(ops.server_job("create", arg))
                if what in ("start", "stop", "reboot", "template", "backup-now", "backup-del", "storage-del",
                            "containers", "protocols", "docker-up", "docker-restart", "delete"):
                    return job(ops.server_job(what))
            if action == "rotate":
                mode = form.get("mode", "")
                if mode in modes.ALL_MODES:
                    return job(ops.rotate_job(mode, form.get("zone", "") if mode == modes.MOVE else ""))
            if action == "probe":
                return job(ops.probe_job())
            if action == "auto.pause":
                return done(ops.auto_pause(form.get("on") == "1"))
            if action == "auto.mode":
                return done(ops.auto_mode(form.get("mode", "")))
            if action == "unstick":
                return done(ops.unstick())
            if action.startswith("tg.") and action[3:] in ("costs", "servers", "status"):
                return done(ops.to_telegram(action[3:]))
            session["flash"] = flash("bad", "Неизвестное действие.")
            self.redirect(self.back())

    return Handler


def serve(bot, stats: Stats, stop_event: threading.Event) -> None:
    def notify(text: str) -> None:
        threading.Thread(target=bot.send, args=(esc(text),), daemon=True).start()

    auth = Auth(lambda: bot.secrets.get("ADMIN_TOTP_SECRET"), notify)
    ops = Ops(bot, stats)
    server = http.server.ThreadingHTTPServer(LISTEN, make_handler(bot, stats, auth, ops))
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, name="admin-http", daemon=True).start()
    logger.info("админка слушает %s:%s", *LISTEN)
    stop_event.wait()
    server.shutdown()
