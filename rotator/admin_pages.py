"""Страницы админки. Каждая возвращает (заголовок, активный раздел, содержимое)."""
from __future__ import annotations

import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Any

from . import modes
from .admin_ops import ISSUE_KINDS, Ops
from .admin_ui import (PROTO_NAME, PROTO_ORDER, ago, area, avatar, badge, bar_list, button, change, day,
                       donut, esc, flash, head, icon, kpi, kv, legend, seg, size, span, stacked_bars, when)
from .stats import Stats

MSK = 3 * 3600


@dataclass
class Ctx:
    bot: Any
    stats: Stats
    ops: Ops
    csrf: str
    q: dict[str, str] = field(default_factory=dict)
    note: str = ""                    # готовая плашка после действия
    now: float = field(default_factory=time.time)

    @property
    def snap(self) -> dict:
        return self.stats.latest or {}

    @property
    def state(self):
        return self.bot.engine.state


def link(path: str, **params) -> str:
    return path + ("?" + urllib.parse.urlencode({k: v for k, v in params.items() if v not in ("", None)})
                   if params else "")


# --- Сводные данные -----------------------------------------------------------

def people(c: Ctx) -> list[dict]:
    """Все, кто пользуется VPN: ключи (VLESS + Hysteria2) и клиенты AmneziaWG."""
    snap, now = c.snap, c.now
    traffic = {(r["proto"], r["client"]): r for r in c.stats.clients()}
    online = (snap.get("guard") or {}).get("online") or {}
    blocks = {b.get("user") for b in (snap.get("guard") or {}).get("blocks") or []}
    vless, hy2 = snap.get("vless") or {}, snap.get("hy2") or {}
    # Кто есть — решает панель, а не статистика: она отстаёт до 5 минут, а
    # Hysteria2 помнит трафик удалённого ключа до своего перезапуска.
    # Только что выданный ключ трафика ещё не имеет, но в списке он нужен.
    existing = c.ops.key_names()
    names = (set(vless) | set(hy2)) - {"_error"}
    if existing is not None:
        names = existing
    awg31 = c.ops.awg31_known()
    uuid_of = {k["name"]: k["uuid"] for k in c.ops.keys()}
    binds = c.ops.bindings()
    out = []
    for name in sorted(names):
        bound = binds.get(uuid_of.get(name, "")) or {}
        v, h = vless.get(name) or {}, hy2.get(name) or {}
        tv, th = traffic.get(("vless", name), {}), traffic.get(("hy2", name), {})
        live = bool(online.get(name)) or bool(h.get("online"))
        seen = max(v.get("last_seen", 0), tv.get("last_hour", 0), th.get("last_hour", 0))
        out.append({"kind": "key", "name": name, "protos": [p for p, t in (("hy2", th), ("vless", tv)) if t.get("all")]
                    or ["hy2", "vless"], "live": live, "seen": now if live else seen,
                    "nets": len(online.get(name) or {}), "blocked": name in blocks,
                    "enabled": v.get("enabled", True),
                    "devices": len(bound.get("devices") or []), "denied": bound.get("denied", 0),
                    "day": tv.get("day", 0) + th.get("day", 0), "month": tv.get("month", 0) + th.get("month", 0),
                    "all": tv.get("all", 0) + th.get("all", 0),
                    "href": link("/person", k="key", n=name)})
    for p in snap.get("awg") or []:
        if p.get("server") == "awg31" and awg31 is not None and p.get("name") not in awg31:
            continue                              # конфиг отозван, снимок ещё не обновился
        t = traffic.get(("awg", p.get("name")), {})
        live = snap.get("ts", now) - p.get("handshake", 0) < 180
        out.append({"kind": "awg", "name": p.get("name"), "server": p.get("server"), "protos": ["awg"],
                    "live": live, "seen": p.get("handshake", 0), "nets": 0, "blocked": False, "enabled": True,
                    "day": t.get("day", 0), "month": t.get("month", 0), "all": t.get("all", 0),
                    "href": link("/person", k="awg", n=p.get("name"), s=p.get("server"))})
    return out


def rotation_periods(history: list[dict], current_ip: str, now: float) -> list[dict]:
    """Каждый адрес: когда появился, когда ушёл, сколько прожил и почему сменён.
    history — от новых к старым: {"ts", "from", "to", "zone", "mode", "reason"}."""
    periods = []
    if history:
        periods.append({"ip": current_ip or history[0].get("to"), "start": history[0]["ts"], "end": None,
                        "zone": history[0].get("zone"), "why": "сейчас", "auto": False})
    for i, r in enumerate(history):
        older = history[i + 1] if i + 1 < len(history) else None
        start = older["ts"] if older and older.get("to") == r.get("from") else None
        auto = str(r.get("reason", "")).startswith("auto")
        periods.append({"ip": r.get("from"), "start": start, "end": r["ts"],
                        "zone": (older or {}).get("zone"), "mode": r.get("mode"), "auto": auto,
                        "why": "сам: адрес заблокирован" if auto else "вручную"})
    for p in periods:
        p["lived"] = ((p["end"] or now) - p["start"]) if p["start"] else None
    return periods


def alerts(c: Ctx) -> list[tuple[str, str]]:
    """Что требует внимания — для плашки на обзоре."""
    out = []
    snap, system = c.snap, (c.snap.get("system") or {})
    if not snap:
        return [("warn", "Статистики ещё нет — первый снимок придёт в течение 5 минут после запуска бота.")]
    if c.now - snap.get("collected", 0) > 20 * 60:
        out.append(("bad", f"Снимок с VPN-сервера не обновлялся {span(c.now - snap.get('collected', 0))} — "
                           "сервер мог стать недоступен."))
    try:
        stuck = [l["name"] for l in device_links(c) if l["stuck"]]
    except Exception:                                      # noqa: BLE001 — тревога не должна ронять обзор
        stuck = []
    if stuck:
        out.append(("warn", "Ссылку открыли не в приложении, и VPN-приложение получает отказ: "
                            + esc(", ".join(stuck)) + " — <a href='/devices'><u>исправить</u></a>."))
    for b in (snap.get("guard") or {}).get("blocks") or []:
        out.append(("warn", f"Ключ «{esc(b.get('user'))}» работал на двух устройствах — лишнее отрезано "
                            f"(<a href='{link('/person', k='key', n=b.get('user'))}'><u>открыть</u></a>)."))
    bad = [k for k, v in (system.get("watchdog") or {}).items()
           if v not in ("ok", "отвечает", "работает", "свежие") and not k in ("память", "диск", "нагрузка")]
    if bad:
        out.append(("bad", "Сторож здоровья видит проблему: " + esc(", ".join(bad)) +
                    " — <a href='/health'><u>подробнее</u></a>."))
    if (system.get("disk_pct") or 0) >= 88:
        out.append(("warn", f"Диск VPN-сервера занят на {system.get('disk_pct')}%."))
    if (system.get("mem_avail") or 999) < 120:
        out.append(("warn", f"Свободной памяти на VPN-сервере всего {system.get('mem_avail')} МБ."))
    if c.state["paused"]:
        out.append(("warn", "Автоматика на паузе: при блокировке адрес сам не сменится. "
                            "<a href='/addresses'><u>Включить</u></a>."))
    if c.state["pending"]:
        out.append(("bad", "Есть незавершённая смена адреса — <a href='/server'><u>разобраться</u></a>."))
    return out


# --- Обзор --------------------------------------------------------------------

def overview(c: Ctx) -> tuple[str, str, str]:
    rng = c.q.get("d", "30")
    days = {"7": 7, "30": 30, "90": 90}.get(rng, 30)
    now, snap, st = c.now, c.snap, c.state
    since = int(now) - days * 86400
    cur, prev = c.stats.by_proto(since), c.stats.by_proto(since - days * 86400, since)
    ppl = people(c)
    live = [p for p in ppl if p["live"]]
    history = list(st["history"] or [])
    rot30 = [r for r in history if now - r["ts"] < 30 * 86400]
    periods = rotation_periods(history, st["ipv4"], now)
    lived = [p["lived"] for p in periods[1:] if p["lived"] and p["end"] and now - p["end"] < 30 * 86400]
    started = c.stats.started()

    rng_key = "all" if days == 90 else "month"
    top = sorted(ppl, key=lambda p: -p[rng_key])
    top_items = [(p["name"], p["href"], p[rng_key], p["protos"][0]) for p in top if p[rng_key]][:7]

    out = [c.note, head("Обзор", f"Данные обновляются каждые 5 минут · последний снимок {ago(snap.get('collected'), now)}",
                        f'<a class="btn primary" href="/people/new">{icon("plus")}Выдать ключ</a>')]
    out += [flash(k, t) for k, t in alerts(c)]
    out.append('<div class="grid g4">')
    out.append(kpi("Онлайн сейчас", f"{len(live)}<span class='muted' style='font-size:16px'> / {len(ppl)}</span>",
                   f"ключей {sum(1 for p in live if p['kind'] == 'key')} · AmneziaWG "
                   f"{sum(1 for p in live if p['kind'] == 'awg')}", "people"))
    out.append(kpi(f"Трафик за {days} дн.", size(sum(cur.values())),
                   change(sum(cur.values()), sum(prev.values())) + f"<span>к прошлым {days} дн.</span>", "pulse"))
    out.append(kpi("Текущий адрес", f"<span style='font-size:19px'>{esc(st['ipv4'] or '—')}</span>",
                   f"{esc(st['zone'] or '')} · живёт {span(now - history[0]['ts']) if history else '—'}", "globe"))
    out.append(kpi("Смен адреса за 30 дней", str(len(rot30)),
                   f"адрес живёт в среднем {span(sum(lived) / len(lived)) if lived else '—'}", "refresh"))
    out.append("</div>")

    out.append('<div class="grid g21 sec">')
    out.append(f'<div class="card"><div class="card-head"><div><h2>Трафик по дням</h2>'
               f'<p class="sub">все протоколы, по московскому времени</p></div>'
               f'{seg([("7", "/?d=7", "7 дн"), ("30", "/?d=30", "30 дн"), ("90", "/?d=90", "90 дн")], rng)}</div>'
               f'{legend()}{stacked_bars(c.stats.daily(days, shift=MSK))}</div>')
    out.append(f'<div class="card"><h2>По протоколам</h2><p class="sub">за {days} дн.</p>'
               f'{donut(cur, size(sum(cur.values())), "всего")}</div>')
    out.append("</div>")

    out.append('<div class="grid g2 sec">')
    out.append(f'<div class="card"><div class="card-head"><div><h2>Больше всех</h2>'
               f'<p class="sub">трафик за {"30 дн" if days < 90 else "всё время"}</p></div>'
               f'<a class="btn sm ghost" href="/people">Все →</a></div>{bar_list(top_items, "трафика пока не было")}</div>')
    out.append(f'<div class="card"><h2>Последние сутки</h2><p class="sub">трафик по часам</p>'
               f'{area(c.stats.hourly_series(24), label="Трафик за сутки")}</div>')
    out.append("</div>")

    events = list(reversed(snap.get("events") or []))[:6]
    out.append(f'<div class="sec card"><div class="card-head"><div><h2>События</h2>'
               f'<p class="sub">сторож устройств и сторож здоровья</p></div>'
               f'<a class="btn sm ghost" href="/health#events">Все →</a></div>{feed(events)}</div>')
    out.append(f'<p class="muted small sec">Учёт трафика ведётся с {when(started)}.</p>')
    return "Обзор", "/", "".join(out)


def feed(events: list[dict]) -> str:
    if not events:
        return '<div class="empty">событий пока нет</div>'
    rows = []
    for e in events:
        kind = e.get("kind", "")
        if e.get("text"):
            text = esc(e["text"])
        else:
            text = f"Ключ <b>{esc(e.get('user'))}</b>: " + {
                "blocked": f"работал на двух устройствах — лишнее ({esc(', '.join(e.get('others') or []))}) "
                           f"отрезано на {e.get('minutes', 30)} мин",
                "shared": "работает на нескольких устройствах",
                "unblocked": "блокировка снята"}.get(kind, esc(kind))
        tone, ic = {"restarted": ("ok", "refresh"), "recovered": ("ok", "check"), "down": ("bad", "alert"),
                    "tight": ("warn", "alert"), "oom": ("warn", "alert"), "blocked": ("warn", "shield"),
                    "shared": ("warn", "shield"), "unblocked": ("ok", "unlock")}.get(kind, ("", "pulse"))
        rows.append(f'<div class="ev"><span class="ic {tone}">{icon(ic)}</span><p>{text}'
                    f'<br><span class="muted small">{esc(e.get("source", ""))}</span></p>'
                    f'<time>{when(e.get("t"))}</time></div>')
    return '<div class="feed">' + "".join(rows) + "</div>"


# --- Люди ---------------------------------------------------------------------

def people_page(c: Ctx) -> tuple[str, str, str]:
    f = c.q.get("f", "all")
    query = c.q.get("q", "").strip().lower()
    ppl = people(c)
    counts = {"all": len(ppl), "online": sum(p["live"] for p in ppl),
              "key": sum(p["kind"] == "key" for p in ppl), "awg": sum(p["kind"] == "awg" for p in ppl)}
    shown = [p for p in ppl if (f == "all" or (f == "online" and p["live"]) or p["kind"] == f)
             and (not query or query in p["name"].lower())]
    shown.sort(key=lambda p: (not p["live"], -p["month"], -(p["seen"] or 0)))
    top = max([p["month"] for p in shown] + [1])

    rows = ['<div class="row headrow"><span>Кто</span><span class="hide-m">Протокол</span>'
            '<span class="hide-m">Последний раз</span><span class="r">30 дней</span><span></span></div>']
    for p in shown:
        status = ('<span class="dot on"></span> онлайн' + (f" · {p['nets']} сети" if p["nets"] > 1 else "")
                  if p["live"] else f'<span class="dot"></span> {ago(p["seen"], c.now)}')
        extra = (" " + badge("отрезано лишнее", "warn") if p["blocked"] else "") + \
                (" " + badge("выключен") if not p["enabled"] else "") + \
                (" " + badge(f"{p['devices']} устр.") if p.get("devices", 0) >= 2 else "") + \
                (" " + badge(f"отказов {p['denied']}", "warn") if p.get("denied") else "")
        sub = ("ключ · " + " + ".join(PROTO_NAME[x] for x in p["protos"]) if p["kind"] == "key"
               else "AmneziaWG · " + ("роутер/файл" if p.get("server") == "awg31" else "приложение Amnezia"))
        plain = ("онлайн" if p["live"] else ago(p["seen"], c.now))
        rows.append(
            f'<a class="row" href="{p["href"]}"><div class="who">{avatar(p["name"], p["protos"][0])}<div>'
            f'<b>{esc(p["name"])}{extra}</b><span class="d-only">{esc(sub)}</span>'
            f'<span class="m-only"><i class="dot{" on" if p["live"] else ""}"></i> {esc(plain)} · '
            f'{"ключ" if p["kind"] == "key" else "AmneziaWG"}</span></div></div>'
            f'<div class="hide-m">{"".join(badge(PROTO_NAME[x], x) + " " for x in p["protos"])}</div>'
            f'<div class="hide-m small"><span class="inl">{status}</span></div>'
            f'<div class="r"><b class="num">{size(p["month"])}</b><div class="meter"><i style="width:'
            f'{p["month"] / top * 100:.1f}%"></i></div></div>'
            f'<span class="chev hide-m">›</span></a>')
    if len(rows) == 1:
        rows.append('<div class="empty">никого не нашлось</div>')

    filters = seg([(k, link("/people", f=k, q=c.q.get("q", "")), f"{label} {counts[k]}") for k, label in
                   (("all", "Все"), ("online", "Онлайн"), ("key", "Ключи"), ("awg", "AmneziaWG"))], f)
    search = (f'<form class="search" method="get" action="/people"><input type="hidden" name="f" value="{esc(f)}">'
              f'<input name="q" value="{esc(c.q.get("q", ""))}" placeholder="Поиск по имени" type="search"></form>')
    out = [c.note, head("Люди", f"{counts['all']} всего · онлайн {counts['online']}",
                        f'<a class="btn" href="/devices">{icon("shield")}Устройства</a>'
                        f'<a class="btn primary" href="/people/new">{icon("plus")}Выдать ключ</a>'),
           f'<div class="toolbar">{filters}{search}</div>', '<div class="list">', "".join(rows), "</div>"]
    return "Люди", "/people", "".join(out)


def person_page(c: Ctx) -> tuple[str, str, str]:
    kind, name, server = c.q.get("k", "key"), c.q.get("n", ""), c.q.get("s", "")
    p = next((x for x in people(c) if x["kind"] == kind and x["name"] == name
              and (kind != "awg" or x.get("server") == server)), None)
    if not p:
        gone = "Ключа больше нет — он удалён." if kind == "key" else "Такого клиента нет — конфиг отозван или удалён."
        return "Не найдено", "/people", c.note + head(name or "Не найдено", gone, back=("/people", "Люди"))

    protos = ["vless", "hy2"] if kind == "key" else ["awg"]
    who = [(pr, name) for pr in protos]
    totals = c.stats.client_total(who)
    status = ('<span class="dot on"></span> онлайн' if p["live"] else f'<span class="dot"></span> {ago(p["seen"], c.now)}')
    actions, cards = [], []

    if kind == "key":
        k = c.ops.key(name) or {}
        uuid = k.get("uuid", "")
        binding = (c.ops.bindings().get(uuid) or {}) if uuid else {}
        limit = binding.get("limit", "1 (по умолчанию)")
        devices = binding.get("devices") or []
        nets = ((c.snap.get("guard") or {}).get("online") or {}).get(name) or {}
        blocks = [b for b in (c.snap.get("guard") or {}).get("blocks") or [] if b.get("user") == name]
        actions.append(button("key.resend", "В Telegram", c.csrf, {"name": name}, "btn", "send"))
        sub, vlink = c.ops.sub_url(uuid), c.ops.vless_link(name) if uuid else ""
        cards.append(
            f'<div class="card"><h2>Ссылки</h2><p class="sub">отдайте человеку подписку — остальное приложение сделает само</p>'
            f'<p class="small muted" style="margin:0 0 6px">Подписка (sing-box, Hiddify)</p>'
            f'<div class="copy"><code>{esc(sub or "SUB_BASE_URL не задан")}</code></div>'
            f'<p class="small muted" style="margin:14px 0 6px">Ссылка vless:// — весь трафик через VPN, для любого приложения</p>'
            f'<div class="copy"><code>{esc(vlink or "—")}</code></div></div>')
        # Та же карточка, что в разделе «Устройства»: одни и те же действия везде.
        entry = next((l for l in device_links(c) if l["name"] == name), None)
        if entry:
            cards.append(link_card(c, entry, STUCK_TEXT if entry["stuck"] else "", title="Устройства"))
        cards.append(
            f'<div class="card danger-zone"><h2>Удалить ключ</h2><p class="sub">подписка и ссылка перестанут работать '
            f'сразу и на всех устройствах</p>{button("key.delete", "Удалить ключ", c.csrf, {"name": name}, "btn danger", "trash")}</div>')
    else:
        is_ours = server == "awg31"
        if is_ours:
            actions.append(f'<a class="btn" href="{link("/download/awg", n=name)}">{icon("download")}Скачать .conf</a>')
            actions.append(button("awg.send", "В Telegram", c.csrf, {"name": name}, "btn", "send"))
        cards.append(
            f'<div class="card"><h2>Подключение</h2><p class="sub">{"конфиг выпущен ботом (AmneziaWG 3.1)" if is_ours else "клиент приложения Amnezia — управляется в самом приложении Amnezia"}</p>'
            + kv([("Состояние", status), ("Где", esc(server)), ("Последнее рукопожатие", when(p["seen"]) if p["seen"] else "никогда")])
            + "</div>")
        if is_ours:
            cards.append(f'<div class="card danger-zone"><h2>Отозвать конфиг</h2><p class="sub">файл перестанет '
                         f'подключаться сразу</p>{button("awg.revoke", "Отозвать", c.csrf, {"name": name}, "btn danger", "trash")}</div>')

    sub_title = ("ключ · " + " + ".join(PROTO_NAME[x] for x in p["protos"]) if kind == "key"
                 else "AmneziaWG · " + server)
    out = [c.note, head(name, f"{esc(sub_title)}", "".join(actions), back=("/people", "Люди"))]
    out.append('<div class="grid g4">')
    out.append(kpi("Сейчас", status, f"последний раз {ago(p['seen'], c.now)}" if not p["live"] else ""))
    out.append(kpi("За сутки", size(p["day"])))
    out.append(kpi("За 30 дней", size(p["month"])))
    out.append(kpi("За всё время", size(p["all"]), f"↓ {size(totals['rx'])} · ↑ {size(totals['tx'])}"))
    out.append("</div>")
    out.append(f'<div class="card sec"><h2>Трафик по дням</h2><p class="sub">30 дней</p>{legend(protos)}'
               f'{stacked_bars(c.stats.daily(30, who, shift=MSK))}</div>')
    out.append('<div class="grid g2 sec">' + "".join(cards) + "</div>")
    return name, "/people", "".join(out)


def new_person(c: Ctx) -> tuple[str, str, str]:
    choices = "".join(
        f'<label class="choice"><input type="radio" name="kind" value="{k}" {"checked" if k == "sub" else ""}>'
        f'<div><b>{esc(t)}</b><span>{esc(d)}</span></div></label>' for k, (t, d) in ISSUE_KINDS.items())
    form = (f'<form method="post" action="/do" class="card" style="max-width:620px">'
            f'<input type="hidden" name="csrf" value="{esc(c.csrf)}"><input type="hidden" name="action" value="key.issue">'
            f'<div class="field"><label for="n">Имя</label><input type="text" id="n" name="name" required '
            f'pattern="[A-Za-z0-9_-]{{1,32}}" placeholder="например, oleg-iphone" autocomplete="off">'
            f'<span class="hint">Латиница, цифры, «-» и «_». Одно имя — на человека и устройство.</span></div>'
            f'<div class="field"><label>Что выдать</label><div class="choices">{choices}</div></div>'
            f'<label class="choice" style="margin-bottom:16px"><input type="checkbox" name="tg" value="1" checked>'
            f'<div><b>Прислать готовое сообщение в Telegram</b><span>Перешлёте его человеку целиком — там ссылка '
            f'и инструкция.</span></div></label>'
            f'<button class="btn primary">{icon("plus")}Выдать</button></form>')
    return "Новый ключ", "/people", c.note + head("Выдать ключ", "Ключ начнёт работать сразу, без перезапуска сервера.",
                                                  back=("/people", "Люди")) + form


# --- Устройства ---------------------------------------------------------------

APP_TITLES = {"sing-box": "sing-box", "hiddify": "Hiddify", "v2raytun": "v2RayTun", "v2rayng": "v2rayNG",
              "happ": "Happ", "mozilla": "браузер или превью ссылки", "неизвестное": "неизвестный клиент"}


def device_links(c: Ctx) -> list[dict]:
    """Ключи с их привязками: устройства, отказы, замены, живые сети."""
    from .admin_ops import is_weak
    bindings = c.ops.bindings()
    guard = c.snap.get("guard") or {}
    online, blocks = guard.get("online") or {}, guard.get("blocks") or []
    out = []
    for k in c.ops.keys():
        link = bindings.get(k["uuid"]) or {}
        devices = sorted(link.get("devices") or [], key=lambda d: d.get("first", 0))
        for d in devices:
            d["weak"] = is_weak(d)
        nets = online.get(k["name"]) or {}
        out.append({"name": k["name"], "uuid": k["uuid"], "devices": devices, "limit": link.get("limit"),
                    "denied": link.get("denied", 0), "last_denied": link.get("last_denied", 0),
                    "replaced": link.get("replaced", 0), "last_replaced": link.get("last_replaced"),
                    "nets": nets, "blocks": [b for b in blocks if b.get("user") == k["name"]],
                    # Место заняло не приложение, и приложение из-за этого получает отказ —
                    # ровно то, что было с farah-phone.
                    "stuck": bool(devices) and all(d["weak"] for d in devices) and link.get("denied", 0) > 0})
    return out


def device_row(c: Ctx, lk: dict, d: dict) -> str:
    app = APP_TITLES.get(d.get("ua"), d.get("ua") or "?")
    how = "точно, по отпечатку" if d.get("kind") == "hwid" else "примерно, по приложению"
    warn = badge("не приложение", "warn") if d.get("weak") else ""
    return (f'<div class="ev"><span class="ic {"warn" if d.get("weak") else ""}">{icon("server")}</span>'
            f'<p><b>{esc(app)}</b> {warn}<br><span class="muted small">{esc(how)} · сетей за месяц '
            f'{len(d.get("nets") or {})} · обновлений сегодня {d.get("today", 0)} · всего {d.get("hits", 0)}<br>'
            f'появилось {when(d.get("first"))} · последний раз {ago(d.get("last"), c.now)}</span></p>'
            f'<time>{button("key.drop", "Убрать", c.csrf, {"name": lk["name"], "device": d.get("id")}, "btn sm")}</time></div>')


STUCK_TEXT = ("Ссылку открыли не в VPN-приложении (браузер или превью), и само приложение получает отказ. "
              "Нажмите «Убрать» у этого устройства — или подождите: приложение вытеснит его при следующем обновлении.")


def link_card(c: Ctx, lk: dict, why: str, title: str = "") -> str:
    limit = lk["limit"] or 1
    actions = [button("key.unbind", "Снять все привязки", c.csrf, {"name": lk["name"]}, "btn sm")]
    for n in (1, 2, 3):
        if n != limit:
            actions.append(button("key.limit", f"Разрешить {n}", c.csrf, {"name": lk["name"], "n": n}, "btn sm"))
    if lk["blocks"]:
        actions.insert(0, button("key.unblock", "Снять блокировку", c.csrf, {"name": lk["name"]}, "btn sm", "unlock"))
    facts = [f"разрешено {limit}", f"привязано {len(lk['devices'])}"]
    if lk["denied"]:
        facts.append(f"отказов {lk['denied']}, последний {ago(lk['last_denied'], c.now)}")
    if lk["replaced"]:
        lr = lk["last_replaced"] or {}
        facts.append(f"заменено «{APP_TITLES.get(lr.get('was'), lr.get('was'))}» → "
                     f"«{APP_TITLES.get(lr.get('now'), lr.get('now'))}»")
    if len(lk["nets"]) > 1:
        facts.append("сейчас из сетей: " + ", ".join(lk["nets"].values()))
    devices = "".join(device_row(c, lk, d) for d in lk["devices"]) or '<div class="empty">ссылку ещё не устанавливали</div>'
    blocks = "".join(flash("warn", f"Отрезано {esc(b.get('ip'))} до {when(b.get('until'))}") for b in lk["blocks"])
    heading = esc(title) if title else f'<a href="{link("/person", k="key", n=lk["name"])}">{esc(lk["name"])}</a>'
    return (f'<div class="card"><div class="card-head"><div><h2>{heading}</h2>'
            f'<p class="sub">{esc(" · ".join(facts))}</p></div></div>'
            f'{flash("warn", why) if why else ""}{blocks}<div class="feed">{devices}</div>'
            f'<div class="actions" style="margin-top:12px">{"".join(actions)}</div></div>')


def devices_page(c: Ctx) -> tuple[str, str, str]:
    links = device_links(c)
    stuck = [l for l in links if l["stuck"]]
    many = [l for l in links if len(l["devices"]) >= 2 and not l["stuck"]]
    denied = [l for l in links if l["denied"] and not l["stuck"] and len(l["devices"]) < 2]
    live = [l for l in links if (len(l["nets"]) > 1 or l["blocks"]) and l not in many and l not in denied and l not in stuck]

    out = [c.note, head("Устройства", "Сколько устройств стоит на каждой ссылке, кому отказали и почему",
                        back=("/people", "Люди"))]
    out.append('<div class="grid g4">')
    out.append(kpi("Ссылок на 2+ устройствах", str(sum(len(l["devices"]) >= 2 for l in links)), "", "people"))
    out.append(kpi("Отказы при установке", str(sum(l["denied"] for l in links)),
                   f"у {sum(bool(l['denied']) for l in links)} ключей", "shield"))
    out.append(kpi("Место занял не приложение", str(len(stuck)), "браузер или превью ссылки", "alert"))
    out.append(kpi("Сейчас из 2+ сетей", str(sum(len(l["nets"]) > 1 for l in links)),
                   f"отрезано: {sum(len(l['blocks']) for l in links)}", "globe"))
    out.append("</div>")

    out.append('<div class="card sec"><h2>Как это работает</h2><p class="sub" style="margin:0">'
               'Ссылка привязывается к первому устройству, которое её <b>установило</b>. Если по ней пришло второе, '
               'оно получает отказ, а здесь растёт счётчик «отказов». Браузер и превью в мессенджерах место не занимают; '
               'если всё-таки заняли (старые привязки), настоящее приложение теперь вытесняет их само при следующем '
               'обновлении подписки. Отдельно сторож следит за живыми подключениями: два устройства одновременно '
               'дольше полутора минут — лишнее отрезается на 30 минут.</p></div>')

    def section(title: str, items: list[dict], why: str, empty: str) -> None:
        body = "".join(link_card(c, l, why) for l in items) or f'<div class="empty card">{esc(empty)}</div>'
        out.append(f'<div class="sec"><h2>{esc(title)} <span class="count">{len(items)}</span></h2>'
                   f'<div class="grid g2">{body}</div></div>')

    section("Требует внимания: место занял не приложение", stuck, STUCK_TEXT, "таких нет")
    section("Два и более устройства", many, "", "ни одна ссылка не стоит больше чем на одном устройстве")
    section("Пытались поставить на второе устройство", denied,
            "Ссылку пробовали установить ещё где-то и получили отказ. Если это тот же человек с новым "
            "телефоном — снимите привязку; если второе устройство его — разрешите 2.", "отказов не было")
    if live:
        section("Сейчас из нескольких сетей", live, "", "")
    return "Устройства", "/devices", "".join(out)


# --- Адреса -------------------------------------------------------------------

def addresses(c: Ctx) -> tuple[str, str, str]:
    st, now = c.state, c.now
    history = list(st["history"] or [])
    periods = rotation_periods(history, st["ipv4"], now)
    servers = c.stats.by_server()
    started = c.stats.started()
    rot30 = [r for r in history if now - r["ts"] < 30 * 86400]
    auto30 = sum(1 for r in rot30 if str(r.get("reason", "")).startswith("auto"))
    lived = [p["lived"] for p in periods[1:] if p["lived"] and p["end"] and now - p["end"] < 30 * 86400]
    mode = st["mode"] or c.bot.cfg.get("rotation.mode", "auto")

    out = [c.note, head("Адреса", "История адресов сервера, смена адреса и автоматика")]
    out.append('<div class="grid g4">')
    out.append(kpi("Текущий адрес", f"<span style='font-size:19px'>{esc(st['ipv4'] or '—')}</span>",
                   f"{esc(st['zone'] or '')} · живёт {span(now - history[0]['ts']) if history else '—'}", "globe"))
    out.append(kpi("Смен за 30 дней", str(len(rot30)), f"сами: {auto30} · вручную: {len(rot30) - auto30}", "refresh"))
    out.append(kpi("Адрес живёт в среднем", span(sum(lived) / len(lived)) if lived else "—", "за последние 30 дней"))
    out.append(kpi("Автоматика", "на паузе" if st["paused"] else "работает",
                   f"режим: {esc(mode)}", "pause" if st["paused"] else "play"))
    out.append("</div>")

    zones = c.ops.zones()
    zone_opts = "".join(f'<option value="{esc(z["id"])}" {"selected" if z["id"] == st["zone"] else ""}>'
                        f'{esc(z["id"])} — {esc(z.get("description", ""))}</option>' for z in zones)
    # Бот на medbot работает на Python 3.10: внутри {…} f-строки нельзя ни
    # обратный слэш, ни ту же кавычку, поэтому запасной вариант — заранее.
    zone_opts = zone_opts or '<option value="">—</option>'
    rotate = (f'<div class="card"><h2>Сменить адрес сейчас</h2><p class="sub">VPN будет недоступен несколько минут, '
              f'DNS обновится сам</p><form method="post" action="/do"><input type="hidden" name="csrf" value="{esc(c.csrf)}">'
              f'<input type="hidden" name="action" value="rotate"><div class="choices" style="margin-bottom:12px">'
              + "".join(f'<label class="choice"><input type="radio" name="mode" value="{m}" {"checked" if m == modes.CLONE else ""}>'
                        f'<div><b>{esc(modes.MODE_TITLES[m].capitalize())}</b></div></label>' for m in modes.ALL_MODES)
              + f'</div><div class="field"><label>Локация для переезда</label><select name="zone">{zone_opts}'
              f'</select><span class="hint">Нужна только для «переезда в другую локацию»</span></div>'
              f'<button class="btn primary">{icon("refresh")}Сменить адрес</button></form></div>')
    auto = (f'<div class="card"><h2>Автоматика</h2><p class="sub">меняет адрес сама, когда его блокируют</p>'
            + kv([("Состояние", badge("на паузе", "warn") if st["paused"] else badge("работает", "ok")),
                  ("Проверка каждые", f"{c.bot.cfg.get('detector.interval_sec')} с"),
                  ("Порог", f"{c.bot.cfg.get('detector.fail_threshold')} неудач подряд"),
                  ("Не чаще", f"{c.bot.cfg.get('rotation.max_per_day')} раз в сутки")])
            + f'<form method="post" action="/do" style="margin-top:14px"><input type="hidden" name="csrf" value="{esc(c.csrf)}">'
            f'<input type="hidden" name="action" value="auto.mode"><div class="field"><label>Режим</label><select name="mode">'
            + "".join(f'<option value="{m}" {"selected" if m == mode else ""}>{esc(t)}</option>' for m, t in
                      [("auto", "auto — выбирать самому")] + [(m, modes.MODE_TITLES[m]) for m in modes.ALL_MODES])
            + f'</select></div><div class="actions"><button class="btn">Сохранить режим</button>'
            f'</div></form><div class="actions" style="margin-top:8px">'
            + (button("auto.pause", "Включить автоматику", c.csrf, {"on": 0}, "btn primary", "play") if st["paused"]
               else button("auto.pause", "Поставить на паузу", c.csrf, {"on": 1}, "btn", "pause"))
            + "</div></div>")
    out.append(f'<div class="grid g2 sec">{rotate}{auto}</div>')

    steps = []
    for p in periods:
        t = servers.get(p["ip"] or "", {})
        traffic = (size(t["total"]) if t else "учёта ещё не было" if (p["end"] or now) < started else size(0))
        cls = "now" if p["end"] is None else ("auto" if p["auto"] else "")
        steps.append(
            f'<div class="st {cls}"><div style="display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap">'
            f'<div><b>{esc(p["ip"])}</b> {badge("сейчас", "ok") if p["end"] is None else ""}'
            f'<div class="muted">{esc(p.get("zone") or "—")} · {when(p["start"]) if p["start"] else "?"} → '
            f'{when(p["end"]) if p["end"] else "сейчас"} · прожил {span(p["lived"])}</div></div>'
            f'<div style="text-align:right"><b class="num">{esc(traffic)}</b>'
            f'<div class="muted">{esc(p["why"]) if p["end"] else ""}</div></div></div></div>')
    out.append(f'<div class="card sec"><h2>История адресов</h2><p class="sub">{len(history)} смен · трафик по адресу '
               f'считается с {when(started)}, раньше он не учитывался</p><div class="tl">{"".join(steps) or "<div class=empty>смен ещё не было</div>"}</div></div>')
    return "Адреса", "/addresses", "".join(out)


# --- Сервер -------------------------------------------------------------------

def server_page(c: Ctx) -> tuple[str, str, str]:
    info = c.ops.server_info(fresh=c.q.get("fresh") == "1")
    st = c.state
    out = [c.note, head("Сервер", "VPN-сервер в UpCloud: питание, контейнеры, резервные копии",
                        f'<a class="btn" href="/server?fresh=1">{icon("refresh")}Обновить</a>')]
    if st["pending"]:
        out.append(flash("bad", "Смена адреса не завершилась. Если она точно не идёт — снимите отметку. "
                         + button("unstick", "Снять отметку", c.csrf, cls="btn sm")))
    if info.get("error"):
        out.append(flash("bad", "Сервер не читается из UpCloud: " + esc(info["error"])))
        info = {}
    running = info.get("state") == "started"
    power = (button("server.stop", "Остановить", c.csrf, cls="btn", ic="pause") if running
             else button("server.start", "Запустить", c.csrf, cls="btn primary", ic="play"))
    out.append('<div class="grid g2">')
    out.append(f'<div class="card"><div class="card-head"><div><h2>{esc(info.get("hostname") or "сервер")}</h2>'
               f'<p class="sub">{esc(info.get("zone", ""))} · {esc(info.get("plan", ""))}</p></div>'
               f'{badge("работает", "ok") if running else badge(info.get("state") or "неизвестно", "bad")}</div>'
               + kv([("Адрес IPv4", esc(info.get("ipv4") or st["ipv4"])), ("Диск",
                     f'{esc(info.get("storage_size", "?"))} ГБ · {esc(info.get("storage_tier") or "standard")}'),
                     ("Storage Template", str(len(st["templates"]))), ("Backup", str(len(st["backups"])))])
               + f'<div class="actions" style="margin-top:16px">{power}'
               + button("server.reboot", "Перезагрузить", c.csrf, cls="btn", ic="power")
               + button("probe", "Проверить снаружи", c.csrf, cls="btn", ic="pulse") + "</div></div>")
    out.append(f'<div class="card"><h2>Контейнеры и протоколы</h2><p class="sub">3x-ui (VLESS), AmneziaWG, DNS — по SSH</p>'
               '<div class="actions">'
               + button("server.containers", "Показать состояние", c.csrf, cls="btn")
               + button("server.protocols", "Проверить протоколы", c.csrf, cls="btn")
               + button("server.docker-up", "Поднять остановленные", c.csrf, cls="btn")
               + button("server.docker-restart", "Перезапустить все", c.csrf, cls="btn danger", ic="refresh")
               + '</div><p class="sub" style="margin-top:14px">Сломанные контейнеры сторож здоровья поднимает сам '
               'раз в минуту — руками это нужно редко.</p></div>')
    out.append("</div>")

    backups = sorted(st["backups"], key=lambda b: -b.get("created", 0))
    templates = sorted(st["templates"], key=lambda t: -t.get("created", 0))
    b_rows = "".join(
        f'<div class="ev"><span class="ic">{icon("disk")}</span><p>Backup {esc(b["uuid"][:8])}…'
        f'<br><span class="muted small">{esc(b.get("zone"))} · {esc(b.get("size", "?"))} ГБ</span></p>'
        f'<time>{when(b.get("created"))}<br>{button("server.restore", "Восстановить", c.csrf, {"arg": b["uuid"]}, "btn sm")}</time></div>'
        for b in backups) or '<div class="empty">Backup нет</div>'
    t_rows = "".join(
        f'<div class="ev"><span class="ic">{icon("disk")}</span><p>Template {esc(t["uuid"][:8])}…'
        f'<br><span class="muted small">{esc(t.get("zone"))}</span></p>'
        f'<time>{when(t.get("created"))}<br>{button("server.create", "Поднять сервер", c.csrf, {"arg": t["uuid"]}, "btn sm")}</time></div>'
        for t in templates) or '<div class="empty">шаблонов нет</div>'
    out.append('<div class="grid g2 sec">')
    out.append(f'<div class="card"><div class="card-head"><div><h2>Backup</h2><p class="sub">копии диска для отката</p></div>'
               f'{button("server.backup-now", "Сделать", c.csrf, cls="btn sm", ic="plus")}</div>{b_rows}</div>')
    out.append(f'<div class="card"><div class="card-head"><div><h2>Storage Template</h2><p class="sub">образы для новых серверов и ротаций</p></div>'
               f'{button("server.template", "Снять", c.csrf, cls="btn sm", ic="plus")}</div>{t_rows}</div>')
    out.append("</div>")
    out.append('<div class="grid g2 sec">')
    out.append(f'<div class="card"><h2>Отчёты в Telegram</h2><p class="sub">подробные выкладки, которые бот считает по прайсу аккаунта</p>'
               f'<div class="actions">{button("tg.costs", "Расходы", c.csrf, cls="btn", ic="send")}'
               f'{button("tg.servers", "Все серверы аккаунта", c.csrf, cls="btn", ic="send")}'
               f'{button("tg.status", "Статус", c.csrf, cls="btn", ic="send")}{button("key.sync", "Синхронизировать ключи с ядром", c.csrf, cls="btn")}</div></div>')
    out.append(f'<div class="card danger-zone"><h2>Опасная зона</h2><p class="sub">необратимые действия — каждое переспросит</p>'
               f'<div class="actions">{button("server.backup-del", "Удалить все Backup", c.csrf, cls="btn danger")}'
               f'{button("server.storage-del", "Удалить всё хранящееся", c.csrf, cls="btn danger")}'
               f'{button("server.delete", "Удалить сервер", c.csrf, cls="btn danger", ic="trash")}</div></div>')
    out.append("</div>")
    return "Сервер", "/server", "".join(out)


# --- Здоровье -----------------------------------------------------------------

def health(c: Ctx) -> tuple[str, str, str]:
    snap = c.snap
    system = snap.get("system") or {}
    report = system.get("watchdog") or {}

    def gauge(label: str, value: float, top: float, text: str, warn: float) -> str:
        pct = max(0.0, min(value / top * 100 if top else 0, 100))
        color = "var(--bad)" if pct >= warn else "var(--accent)"
        return (f'<div class="card kpi"><div class="label">{esc(label)}</div><div class="value">{text}</div>'
                f'<div class="meter"><i style="width:{pct:.0f}%;background:{color}"></i></div></div>')

    mem_used = (system.get("mem_total") or 0) - (system.get("mem_avail") or 0)
    out = [c.note, head("Здоровье", f"VPN-сервер {esc(snap.get('host', ''))} · работает без перезагрузки "
                                    f"{span(system.get('uptime'))}")]
    out.append('<div class="grid g4">')
    out.append(gauge("Память", mem_used, system.get("mem_total") or 1,
                     f"{system.get('mem_avail', '?')} <span class='muted' style='font-size:14px'>МБ свободно</span>", 88))
    out.append(gauge("Своп", system.get("swap_used") or 0, 2048,
                     f"{system.get('swap_used', '?')} <span class='muted' style='font-size:14px'>МБ</span>", 70))
    out.append(gauge("Диск", system.get("disk_pct") or 0, 100, f"{system.get('disk_pct', '?')}%", 90))
    load = system.get("load") or [0, 0, 0]
    out.append(gauge("Нагрузка", load[0], 2, f"{load[0]}", 75))
    out.append("</div>")

    series = [(t, (k or 0) + (a or 0)) for t, k, a, _m in c.stats.load_series(24)]
    out.append(f'<div class="card sec"><h2>Подключено людей</h2><p class="sub">за сутки · ключи и AmneziaWG вместе</p>'
               f'{area(series, fmt=lambda v: str(round(v)), label="Подключено людей")}</div>')

    good = ("ok", "отвечает", "работает", "свежие")
    checks = "".join(
        f'<div class="ev"><span class="ic {"ok" if v in good else "warn" if k in ("память", "диск", "нагрузка") else "bad"}">'
        f'{icon("check" if v in good else "pulse" if k in ("память", "диск", "нагрузка") else "alert")}</span>'
        f'<p>{esc(k)}</p><time>{esc(v)}</time></div>' for k, v in report.items()) or '<div class="empty">нет данных</div>'
    out.append(f'<div class="grid g2 sec"><div class="card"><h2>Проверки сторожа здоровья</h2>'
               f'<p class="sub">раз в минуту · упавшее поднимается само</p>{checks}</div>'
               f'<div class="card" id="events"><h2>События</h2><p class="sub">последние 40</p>'
               f'{feed(list(reversed(snap.get("events") or [])))}</div></div>')
    return "Здоровье", "/health", "".join(out)


# --- Задачи и подтверждения ---------------------------------------------------

def jobs_page(c: Ctx) -> tuple[str, str, str]:
    jobs = sorted(c.ops.jobs.values(), key=lambda j: -j.started)
    rows = "".join(
        f'<a class="row" href="/jobs/{j.id}" style="grid-template-columns:minmax(0,1fr) auto auto">'
        f'<div class="who"><span class="ava">{icon("jobs")}</span><div><b>{esc(j.title)}</b>'
        f'<span>{when(j.started)}</span></div></div>'
        f'{badge({"running": "идёт", "done": "готово", "failed": "не вышло"}[j.status], {"running": "warn", "done": "ok", "failed": "bad"}[j.status])}'
        f'<span class="chev">›</span></a>' for j in jobs) or '<div class="empty">задач ещё не было</div>'
    return "Задачи", "/jobs", c.note + head("Задачи", "Долгие действия из админки и их ход") + f'<div class="list">{rows}</div>'


def job_page(c: Ctx, job) -> tuple[str, str, str]:
    st = {"running": ("warn", "идёт…"), "done": ("ok", "готово"), "failed": ("bad", "не вышло")}[job.status]
    out = [head(job.title, f"запущено {when(job.started)}" + (f" · заняло {span(job.finished - job.started)}"
                                                              if job.finished else ""), badge(st[1], st[0]),
                back=("/jobs", "Задачи"))]
    r = job.result
    if r.get("sub") or r.get("conf"):
        parts = []
        if r.get("sub"):
            parts.append(f'<p class="small muted" style="margin:0 0 6px">Подписка — отдайте человеку</p>'
                         f'<div class="copy"><code>{esc(r["sub"])}</code></div>')
        if r.get("link"):
            parts.append(f'<p class="small muted" style="margin:14px 0 6px">Ссылка vless://</p>'
                         f'<div class="copy"><code>{esc(r["link"])}</code></div>')
        if r.get("conf"):
            parts.append(f'<div class="actions" style="margin-top:14px"><a class="btn" href="'
                         f'{link("/download/awg", n=r["name"])}">{icon("download")}Скачать {esc(r["name"])}.conf</a></div>')
        out.append(f'<div class="card" style="margin-bottom:14px"><h2>Готово: {esc(r["name"])}</h2>'
                   f'<p class="sub">ключ уже работает</p>{"".join(parts)}'
                   f'<div class="actions" style="margin-top:14px"><a class="btn" href="'
                   f'{link("/person", k="key" if r.get("uuid") else "awg", n=r["name"], s="" if r.get("uuid") else "awg31")}">'
                   f'Открыть профиль →</a></div></div>')
    out.append(f'<div class="card"><h2>Журнал</h2><div class="log">{esc(chr(10).join(job.lines) or "начинаю…")}</div>'
               + ('<p class="muted small" style="margin:10px 0 0">Страница обновляется сама каждые 3 секунды.</p>'
                  if job.status == "running" else "") + "</div>")
    return job.title, "/jobs", "".join(out)


def confirm_page(c: Ctx, title: str, text: str, form: dict[str, str], danger: bool,
                 back: str = "/") -> tuple[str, str, str]:
    hidden = "".join(f'<input type="hidden" name="{esc(k)}" value="{esc(v)}">' for k, v in form.items())
    body = (f'<div class="card" style="max-width:560px">{flash("warn" if not danger else "bad", text)}'
            f'<form method="post" action="/do">{hidden}<input type="hidden" name="confirm" value="1">'
            f'<div class="actions"><button class="btn {"danger solid" if danger else "primary"}">Да, выполнить</button>'
            f'<a class="btn" href="{esc(back)}">Отмена</a></div></form></div>')
    return title, "", head(title, "Подтвердите действие") + body
