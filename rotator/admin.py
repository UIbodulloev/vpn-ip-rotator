"""Веб-админка: вся статистика на одной странице, вход по Google Authenticator.

Слушает только 127.0.0.1:8787 — наружу её выставляет nginx на medbot
(admin.mos8.online, HTTPS). Секрет для Authenticator выпускает бот командой
/admin и хранит в secrets.env как ADMIN_TOTP_SECRET.

Защита входа:
  * код TOTP (RFC 6238: SHA-1, 6 цифр, шаг 30 с, допуск ±1 шаг);
  * один и тот же код дважды не принимается;
  * 5 неверных кодов с адреса за 15 минут — адрес заблокирован на 15 минут;
    20 неверных за час со всех адресов — вход закрыт для всех на час;
  * о каждом входе и каждой блокировке бот пишет владельцу в Telegram;
  * сессия — случайный токен в cookie (Secure, HttpOnly, SameSite=Strict), 12 часов.
Страницы без внешних скриптов и шрифтов: графики — встроенный SVG.
"""
from __future__ import annotations

import base64
import collections
import hashlib
import hmac
import html
import http.server
import secrets as pysecrets
import struct
import threading
import time
import urllib.parse
from typing import Any

from . import log
from .stats import PROTO_TITLES, PROTOS, Stats

logger = log.get("admin")

LISTEN = ("127.0.0.1", 8787)
SESSION_TTL = 12 * 3600
IP_FAILS, IP_WINDOW, IP_LOCK = 5, 15 * 60, 15 * 60
ALL_FAILS, ALL_WINDOW, ALL_LOCK = 20, 3600, 3600
MSK = 3 * 3600                     # время на страницах — московское


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
        self.sessions: dict[str, float] = {}
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
            self.sessions = {t: e for t, e in self.sessions.items() if e > now}
            self.sessions[token] = now + SESSION_TTL
        return token

    def valid(self, token: str) -> bool:
        with self.lock:
            return bool(token) and self.sessions.get(token, 0) > time.time()

    def close(self, token: str) -> None:
        with self.lock:
            self.sessions.pop(token, None)


# --- Форматирование -----------------------------------------------------------

def esc(v: Any) -> str:
    return html.escape(str(v), quote=True)


def size(n: float) -> str:
    n = float(n or 0)
    for unit in ("Б", "КБ", "МБ", "ГБ", "ТБ"):
        if n < 1024 or unit == "ТБ":
            return f"{n:.0f} {unit}" if unit in ("Б", "КБ") else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} ТБ"


def clock(ts: float) -> str:
    return time.strftime("%H:%M", time.gmtime(ts + MSK))


def when(ts: float) -> str:
    return time.strftime("%d.%m.%Y %H:%M", time.gmtime(ts + MSK)) if ts else "—"


def span(seconds: float) -> str:
    seconds = int(max(seconds, 0))
    d, h, m = seconds // 86400, seconds % 86400 // 3600, seconds % 3600 // 60
    if d:
        return f"{d} д {h} ч"
    if h:
        return f"{h} ч {m} мин"
    return f"{m} мин"


def ago(ts: float, now: float) -> str:
    if not ts:
        return "никогда"
    return "только что" if now - ts < 90 else span(now - ts) + " назад"


COLORS = {"vless": "var(--c1)", "hy2": "var(--c2)", "awg": "var(--c3)"}


def bars(series: list[tuple[int, dict[str, int]]]) -> str:
    """Столбики по дням, сложенные по протоколам. Чистый SVG."""
    if not series:
        return ""
    top = max(sum(v.values()) for _, v in series) or 1
    w, h, gap = 24, 160, 6
    width = len(series) * (w + gap)
    parts = [f'<svg viewBox="0 0 {width} {h + 22}" class="chart" role="img" '
             f'aria-label="Трафик по дням">']
    for i, (day, values) in enumerate(series):
        x, y = i * (w + gap), h
        tip = time.strftime("%d.%m", time.gmtime(day)) + ": " + ", ".join(
            f"{PROTO_TITLES[p]} {size(values.get(p, 0))}" for p in PROTOS if values.get(p))
        parts.append(f"<g><title>{esc(tip or time.strftime('%d.%m', time.gmtime(day)) + ': 0')}</title>")
        for p in PROTOS:
            v = values.get(p, 0)
            if not v:
                continue
            bh = max(v / top * h, 1.5)
            y -= bh
            parts.append(f'<rect x="{x}" y="{y:.1f}" width="{w}" height="{bh:.1f}" rx="3" fill="{COLORS[p]}"/>')
        parts.append(f'<rect x="{x}" y="0" width="{w}" height="{h}" fill="transparent"/></g>')
        if i % 5 == 0 or i == len(series) - 1:
            parts.append(f'<text x="{x + w / 2}" y="{h + 16}" text-anchor="middle">'
                         f'{time.strftime("%d.%m", time.gmtime(day))}</text>')
    parts.append("</svg>")
    return "".join(parts)


def spark(points: list[tuple[int, int]], label: str) -> str:
    if len(points) < 2:
        return '<p class="dim">данных пока мало — график появится через пару часов</p>'
    t0, t1 = points[0][0], points[-1][0]
    top = max(v for _, v in points) or 1
    w, h = 600, 70
    path = " ".join(f"{'M' if i == 0 else 'L'}{(t - t0) / max(t1 - t0, 1) * w:.1f},"
                    f"{h - v / top * (h - 6):.1f}" for i, (t, v) in enumerate(points))
    return (f'<svg viewBox="0 0 {w} {h}" class="spark" role="img" aria-label="{esc(label)}">'
            f'<path d="{path}" fill="none" stroke="var(--c2)" stroke-width="2"/></svg>'
            f'<p class="dim">{esc(label)}: максимум {top}, сейчас {points[-1][1]}</p>')


CSS = """
:root{--bg:#f5f6f8;--card:#fff;--ink:#16181d;--dim:#626a76;--line:#e2e5ea;--accent:#1d6fe0;
--c1:#2f7de1;--c2:#18a37a;--c3:#c9822b;--bad:#c63b3b;--ok:#1d7a43;--soft:#eef1f5}
@media (prefers-color-scheme:dark){:root{--bg:#121418;--card:#1b1e24;--ink:#e6e8eb;--dim:#9aa1ad;
--line:#2a2f37;--accent:#6aa9f5;--c1:#5b9cf0;--c2:#35c194;--c3:#e0a052;--bad:#ef6b6b;--ok:#5fcf8b;--soft:#23272e}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);
font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}
main{max-width:1100px;margin:0 auto;padding:20px 16px 60px}
header{display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap}
h1{font-size:22px;margin:0}h2{font-size:18px;margin:32px 0 10px}
nav a{color:var(--dim);margin-right:14px;text-decoration:none;font-size:14px}nav a:hover{color:var(--accent)}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:14px 16px}
.card b{display:block;font-size:24px;font-variant-numeric:tabular-nums}
.card span{color:var(--dim);font-size:13px}
.wrap{background:var(--card);border:1px solid var(--line);border-radius:12px;overflow-x:auto}
table{border-collapse:collapse;width:100%;font-variant-numeric:tabular-nums}
th,td{padding:8px 12px;text-align:left;border-bottom:1px solid var(--line);white-space:nowrap}
th{color:var(--dim);font-weight:500;font-size:13px}tr:last-child td{border-bottom:0}
td.n,th.n{text-align:right}.dim{color:var(--dim);font-size:13px}td .dim{white-space:normal;min-width:140px}
.on{color:var(--ok)}.bad{color:var(--bad)}.pill{display:inline-block;padding:1px 8px;border-radius:99px;
background:var(--soft);font-size:12px;margin-right:4px}
.chart{width:100%;height:auto;display:block}.chart text{fill:var(--dim);font-size:10px}
.spark{width:100%;height:70px;display:block}
.legend span{display:inline-flex;align-items:center;gap:6px;margin-right:16px;font-size:13px;color:var(--dim)}
.legend i{width:10px;height:10px;border-radius:3px;display:inline-block}
button{font:inherit;cursor:pointer;border-radius:8px;border:1px solid var(--line);background:var(--card);
color:var(--ink);padding:6px 12px}
.login{max-width:340px;margin:12vh auto;text-align:center}
.login input{font:600 28px/1 ui-monospace,monospace;letter-spacing:.3em;text-align:center;width:100%;
padding:12px;border-radius:10px;border:1px solid var(--line);background:var(--card);color:var(--ink)}
.login button{width:100%;margin-top:12px;padding:12px;background:var(--accent);color:#fff;border:0;font-weight:600}
.err{color:var(--bad);min-height:1.5em}
"""


def page(title: str, body: str) -> bytes:
    return (f'<!doctype html><html lang="ru"><head><meta charset="utf-8">'
            f'<meta name="viewport" content="width=device-width,initial-scale=1">'
            f'<meta name="robots" content="noindex,nofollow"><title>{esc(title)}</title>'
            f"<style>{CSS}</style></head><body>{body}</body></html>").encode()


def login_page(error: str = "") -> bytes:
    return page("Вход", f"""<main class="login"><h1>VPN · админка</h1>
<p class="dim">Код из Google Authenticator</p>
<form method="post" action="/login" autocomplete="off">
<input name="code" inputmode="numeric" pattern="[0-9 ]*" maxlength="7" autofocus required>
<p class="err">{esc(error)}</p><button>Войти</button></form></main>""")


# --- Сборка страницы ----------------------------------------------------------

def rotation_periods(history: list[dict], current_ip: str, now: float) -> list[dict]:
    """Каждый адрес: когда появился, когда ушёл, сколько прожил и почему сменён.

    history — от новых к старым: {"ts", "from", "to", "zone", "mode", "reason"}."""
    periods = []
    if history:
        periods.append({"ip": current_ip or history[0].get("to"), "start": history[0]["ts"], "end": None,
                        "zone": history[0].get("zone"), "why": "сейчас"})
    for i, r in enumerate(history):
        older = history[i + 1] if i + 1 < len(history) else None
        start = older["ts"] if older and older.get("to") == r.get("from") else None
        periods.append({"ip": r.get("from"), "start": start, "end": r["ts"],
                        "zone": (older or {}).get("zone"), "mode": r.get("mode"),
                        "why": "сам: адрес заблокирован" if str(r.get("reason", "")).startswith("auto")
                        else "вручную"})
    for p in periods:
        p["lived"] = ((p["end"] or now) - p["start"]) if p["start"] else None
    return periods


def dashboard(bot, stats: Stats) -> bytes:
    now = time.time()
    st = bot.engine.state
    snap = stats.latest or {}
    history = list(st["history"] or [])
    current_ip = st["ipv4"] or snap.get("server_ip", "?")
    today = int(now) // 86400 * 86400
    proto_day, proto_week, proto_month = (stats.by_proto(today), stats.by_proto(int(now) - 7 * 86400),
                                          stats.by_proto(int(now) - 30 * 86400))
    clients = stats.clients()
    traffic = {(c["proto"], c["client"]): c for c in clients}
    started = stats.started()

    guard = snap.get("guard") or {}
    online = guard.get("online") or {}
    blocks = guard.get("blocks") or []
    awg = snap.get("awg") or []
    awg_online = [p for p in awg if snap.get("ts", now) - p.get("handshake", 0) < 180]
    keys = sorted(set(snap.get("vless") or {}) - {"_error"} | set(snap.get("hy2") or {}) - {"_error"})
    system = snap.get("system") or {}
    periods = rotation_periods(history, current_ip, now)
    servers = stats.by_server()
    rot30 = [r for r in history if now - r["ts"] < 30 * 86400]
    lived = [p["lived"] for p in periods[1:] if p["lived"] and p["end"] and now - p["end"] < 30 * 86400]

    def total(d):
        return sum(d.values())

    # Сводка
    out = [f"""<main><header><h1>VPN · админка</h1>
<nav><a href="#traffic">Трафик</a><a href="#keys">Ключи</a><a href="#awg">AmneziaWG</a>
<a href="#servers">Адреса</a><a href="#health">Сервер</a><a href="#events">События</a></nav>
<form method="post" action="/logout"><button>Выйти</button></form></header>
<p class="dim">Обновлено {when(snap.get('collected', 0))} (снимок раз в 5 минут) · учёт трафика ведётся с {when(started)}</p>
<div class="grid">
<div class="card"><span>Ключи VLESS / Hysteria2</span><b>{len(keys)}</b><span>онлайн сейчас: {len(online)}</span></div>
<div class="card"><span>Клиенты AmneziaWG</span><b>{len(awg)}</b><span>онлайн сейчас: {len(awg_online)}</span></div>
<div class="card"><span>Трафик сегодня</span><b>{size(total(proto_day))}</b><span>за 7 дней: {size(total(proto_week))}</span></div>
<div class="card"><span>Трафик за 30 дней</span><b>{size(total(proto_month))}</b><span>
{' · '.join(f"{PROTO_TITLES[p]} {size(proto_month.get(p, 0))}" for p in PROTOS)}</span></div>
<div class="card"><span>Текущий адрес</span><b style="font-size:18px">{esc(current_ip)}</b>
<span>{esc(st['zone'] or '')} · живёт {span(now - history[0]['ts']) if history else '—'}</span></div>
<div class="card"><span>Смен адреса за 30 дней</span><b>{len(rot30)}</b><span>в среднем адрес живёт
{span(sum(lived) / len(lived)) if lived else '—'}</span></div>
</div>"""]

    # Трафик по дням
    out.append(f"""<h2 id="traffic">Трафик по дням, 30 дней</h2><div class="card">
<div class="legend">{''.join(f'<span><i style="background:{COLORS[p]}"></i>{PROTO_TITLES[p]}</span>' for p in PROTOS)}</div>
{bars(stats.daily(30))}<p class="dim">Наведите на столбик — увидите разбивку. Дни — по UTC.</p></div>""")

    # Ключи VLESS / Hysteria2
    rows = []
    vless_snap, hy2_snap = snap.get("vless") or {}, snap.get("hy2") or {}
    for name in keys:
        v, h = vless_snap.get(name) or {}, hy2_snap.get(name) or {}
        tv, th = traffic.get(("vless", name), {}), traffic.get(("hy2", name), {})
        nets = online.get(name) or {}
        seen = max(v.get("last_seen", 0), tv.get("last_hour", 0), th.get("last_hour", 0))
        state = ('<span class="on">● онлайн</span>' + (f' <span class="pill">{len(nets)} сети</span>' if len(nets) > 1 else "")
                 if nets or h.get("online") else f'<span class="dim">{ago(seen, now)}</span>')
        if any(b.get("user") == name for b in blocks):
            state += ' <span class="pill bad">отрезано лишнее</span>'
        if v and not v.get("enabled", True):
            state += ' <span class="pill">выключен</span>'
        rows.append(f"<tr><td>{esc(name)}</td><td>{state}</td>"
                    f"<td class='n'>{size(tv.get('day', 0) + th.get('day', 0))}</td>"
                    f"<td class='n'>{size(tv.get('month', 0) + th.get('month', 0))}</td>"
                    f"<td class='n'>{size(th.get('month', 0))}</td><td class='n'>{size(tv.get('month', 0))}</td>"
                    f"<td class='n'>{size(tv.get('all', 0) + th.get('all', 0))}</td></tr>")
    out.append(f"""<h2 id="keys">Ключи VLESS / Hysteria2 · {len(keys)}</h2><div class="wrap"><table>
<tr><th>Ключ</th><th>Сейчас</th><th class="n">Сутки</th><th class="n">30 дней</th><th class="n">из них Hysteria2</th>
<th class="n">из них VLESS</th><th class="n">Всего</th></tr>{''.join(rows) or '<tr><td colspan=7 class=dim>нет ключей</td></tr>'}
</table></div>""")

    # AmneziaWG
    rows = []
    for p in sorted(awg, key=lambda p: (-(p.get("handshake") or 0))):
        t = traffic.get(("awg", p.get("name")), {})
        live = snap.get("ts", now) - p.get("handshake", 0) < 180
        rows.append(f"<tr><td>{esc(p.get('name'))}</td><td><span class='pill'>{esc(p.get('server'))}</span></td>"
                    f"<td>{'<span class=on>● онлайн</span>' if live else '<span class=dim>' + ago(p.get('handshake', 0), now) + '</span>'}</td>"
                    f"<td class='n'>{size(t.get('day', 0))}</td><td class='n'>{size(t.get('month', 0))}</td>"
                    f"<td class='n'>{size(t.get('all', 0))}</td></tr>")
    out.append(f"""<h2 id="awg">AmneziaWG · {len(awg)} клиентов, онлайн {len(awg_online)}</h2><div class="wrap"><table>
<tr><th>Клиент</th><th>Где</th><th>Последний раз</th><th class="n">Сутки</th><th class="n">30 дней</th><th class="n">Всего</th></tr>
{''.join(rows) or '<tr><td colspan=6 class=dim>нет клиентов</td></tr>'}</table></div>""")

    # Адреса
    rows = []
    for p in periods:
        t = servers.get(p["ip"] or "", {})
        counted = size(t["total"]) if t else ('<span class="dim">учёта ещё не было</span>'
                                              if (p["end"] or now) < started else size(0))
        split = " · ".join(f"{PROTO_TITLES[x]} {size(t[x])}" for x in PROTOS if t.get(x)) if t else ""
        rows.append(f"<tr><td>{esc(p['ip'])}{' <span class=pill>сейчас</span>' if p['end'] is None else ''}</td>"
                    f"<td>{esc(p.get('zone') or '—')}</td><td>{when(p['start']) if p['start'] else '—'}</td>"
                    f"<td>{when(p['end']) if p['end'] else '—'}</td><td>{span(p['lived']) if p['lived'] else '—'}</td>"
                    f"<td>{esc(p['why'])}</td><td class='n'>{counted}<div class=dim>{split}</div></td></tr>")
    out.append(f"""<h2 id="servers">Адреса сервера · {len(history)} смен</h2>
<p class="dim">Трафик по адресу считается с начала учёта ({when(started)}); раньше счётчики по адресам
не велись, и восстановить их нельзя.</p><div class="wrap"><table>
<tr><th>Адрес</th><th>Локация</th><th>Появился</th><th>Сменён</th><th>Прожил</th><th>Причина смены</th><th class="n">Трафик</th></tr>
{''.join(rows) or '<tr><td colspan=7 class=dim>смен адреса ещё не было</td></tr>'}</table></div>""")

    # Сервер
    report = system.get("watchdog") or {}
    load = stats.load_series(24)
    out.append(f"""<h2 id="health">VPN-сервер</h2><div class="grid">
<div class="card"><span>Свободная память</span><b>{system.get('mem_avail', '?')} МБ</b><span>из {system.get('mem_total', '?')} · своп {system.get('swap_used', '?')} МБ</span></div>
<div class="card"><span>Диск</span><b>{system.get('disk_pct', '?')}%</b><span>занято</span></div>
<div class="card"><span>Нагрузка</span><b>{(system.get('load') or ['?'])[0]}</b><span>за 1 / 5 / 15 мин: {' / '.join(str(x) for x in system.get('load') or [])}</span></div>
<div class="card"><span>Работает без перезагрузки</span><b style="font-size:18px">{span(system.get('uptime', 0))}</b><span>{esc(snap.get('host', ''))}</span></div>
</div><div class="card" style="margin-top:12px">{spark([(t, (k or 0) + (a or 0)) for t, k, a, _m in load], 'Подключено людей за сутки (ключи + AmneziaWG)')}</div>
<div class="wrap" style="margin-top:12px"><table><tr><th>Проверка сторожа здоровья</th><th>Состояние</th></tr>
{''.join(f"<tr><td>{esc(k)}</td><td class='{'on' if v in ('ok', 'отвечает', 'работает', 'свежие') else ''}'>{esc(v)}</td></tr>" for k, v in report.items())}
</table></div>""")

    # События
    events = list(reversed(snap.get("events") or []))[:30]
    rows = []
    for e in events:
        text = e.get("text") or (f"ключ {e.get('user')}: " + {
            "blocked": f"второе устройство отрезано ({', '.join(e.get('others') or [])})",
            "shared": "работает на нескольких устройствах",
            "unblocked": "блокировка снята"}.get(e.get("kind"), e.get("kind", "")))
        rows.append(f"<tr><td>{when(e.get('t', 0))}</td><td><span class='pill'>{esc(e.get('source'))}</span></td>"
                    f"<td>{esc(text)}</td></tr>")
    out.append(f"""<h2 id="events">События</h2><div class="wrap"><table>
<tr><th>Когда</th><th>Сторож</th><th>Что</th></tr>{''.join(rows) or '<tr><td colspan=3 class=dim>событий нет</td></tr>'}
</table></div></main>""")
    return page("VPN · админка", "".join(out))


# --- HTTP ---------------------------------------------------------------------

def make_handler(bot, stats: Stats, auth: Auth):
    class Handler(http.server.BaseHTTPRequestHandler):
        server_version = "admin"
        sys_version = ""

        def log_message(self, fmt: str, *args) -> None:
            pass

        def client_ip(self) -> str:
            # Слушаем только 127.0.0.1, так что заголовок ставит наш nginx.
            return (self.headers.get("X-Real-IP") or self.client_address[0]).strip()

        def token(self) -> str:
            for part in (self.headers.get("Cookie") or "").split(";"):
                k, _, v = part.strip().partition("=")
                if k == "adm":
                    return v
            return ""

        def reply(self, body: bytes, status: int = 200, extra: dict | None = None) -> None:
            self.send_response(status)
            headers = {"Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store",
                       "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer",
                       "X-Content-Type-Options": "nosniff",
                       "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; "
                                                  "img-src 'self' data:; form-action 'self'; frame-ancestors 'none'",
                       "Content-Length": str(len(body)), **(extra or {})}
            for k, v in headers.items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def redirect(self, where: str, cookie: str | None = None) -> None:
            extra = {"Location": where}
            if cookie is not None:
                extra["Set-Cookie"] = cookie
            self.reply(b"", 303, extra)

        def do_GET(self) -> None:                                  # noqa: N802
            path = self.path.split("?", 1)[0]
            if path == "/login":
                return self.reply(login_page())
            if path != "/":
                return self.reply(page("Нет такой страницы", "<main><p>404</p></main>"), 404)
            if not auth.valid(self.token()):
                return self.redirect("/login")
            try:
                self.reply(dashboard(bot, stats))
            except Exception as exc:                               # noqa: BLE001
                logger.exception("админка не собралась")
                self.reply(page("Ошибка", f"<main><p>Страница не собралась: {esc(exc)}</p></main>"), 500)

        def do_POST(self) -> None:                                 # noqa: N802
            size_ = min(int(self.headers.get("Content-Length") or 0), 1024)
            form = urllib.parse.parse_qs(self.rfile.read(size_).decode(errors="replace"))
            if self.path == "/logout":
                auth.close(self.token())
                return self.redirect("/login", "adm=; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=Strict")
            if self.path != "/login":
                return self.reply(b"", 404)
            ip = self.client_ip()
            ok, why = auth.check_code((form.get("code") or [""])[0], ip)
            if not ok:
                return self.reply(login_page(why), 401)
            token = auth.open_session()
            auth.notify(f"🔐 Вход в админку с {ip}")
            self.redirect("/", f"adm={token}; Max-Age={SESSION_TTL}; Path=/; Secure; HttpOnly; SameSite=Strict")
    return Handler


def serve(bot, stats: Stats, stop_event: threading.Event) -> None:
    def notify(text: str) -> None:
        threading.Thread(target=bot.send, args=(esc(text),), daemon=True).start()

    auth = Auth(lambda: bot.secrets.get("ADMIN_TOTP_SECRET"), notify)
    server = http.server.ThreadingHTTPServer(LISTEN, make_handler(bot, stats, auth))
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, name="admin-http", daemon=True).start()
    logger.info("админка слушает %s:%s", *LISTEN)
    stop_event.wait()
    server.shutdown()
