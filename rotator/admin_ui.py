"""Дизайн-система админки: стили, иконки, компоненты, графики.

Никаких внешних файлов, шрифтов и скриптов: всё рисуется на сервере, графики —
встроенный SVG. Страница открывается и там, где половина интернета недоступна,
и не зависит ни от одного CDN. Тема — светлая или тёмная по настройке системы.
"""
from __future__ import annotations

import html
import re
import time
from typing import Any, Iterable

MSK = 3 * 3600


# --- Форматирование -----------------------------------------------------------

def esc(v: Any) -> str:
    return html.escape("" if v is None else str(v), quote=True)


def size(n: float) -> str:
    n = float(n or 0)
    for unit in ("Б", "КБ", "МБ", "ГБ", "ТБ"):
        if n < 1024 or unit == "ТБ":
            return f"{n:.0f} {unit}" if unit in ("Б", "КБ") else f"{n:.1f} {unit}".replace(".", ",")
        n /= 1024
    return f"{n:.1f} ТБ"


def clock(ts: float) -> str:
    return time.strftime("%H:%M", time.gmtime(ts + MSK))


def when(ts: float | None) -> str:
    return time.strftime("%d.%m.%Y %H:%M", time.gmtime(ts + MSK)) if ts else "—"


def day(ts: float) -> str:
    return time.strftime("%d.%m", time.gmtime(ts + MSK))


def span(seconds: float | None) -> str:
    if seconds is None:
        return "—"
    seconds = int(max(seconds, 0))
    d, h, m = seconds // 86400, seconds % 86400 // 3600, seconds % 3600 // 60
    if d:
        return f"{d} д {h} ч"
    if h:
        return f"{h} ч {m} мин"
    return f"{m} мин"


def ago(ts: float | None, now: float) -> str:
    if not ts:
        return "никогда"
    return "только что" if now - ts < 90 else span(now - ts) + " назад"


def change(cur: float, prev: float) -> str:
    """Изменение к прошлому периоду: «▲ 12%» зелёным, «▼» приглушённо."""
    if not prev:
        return '<span class="delta">новое</span>' if cur else ""
    pct = (cur - prev) / prev * 100
    arrow, cls = ("▲", "up") if pct >= 0 else ("▼", "down")
    return f'<span class="delta {cls}">{arrow} {abs(pct):.0f}%</span>'


# --- Иконки (контурные, 24×24) ------------------------------------------------

_ICONS = {
    "overview": '<path d="M3 13h8V3H3zM13 21h8V11h-8zM3 21h8v-6H3zM13 3v6h8V3z"/>',
    "people": '<path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/>'
              '<path d="M22 21v-2a4 4 0 0 0-3-3.87M16 3.13a4 4 0 0 1 0 7.75"/>',
    "globe": '<circle cx="12" cy="12" r="10"/><path d="M2 12h20M12 2a15 15 0 0 1 0 20M12 2a15 15 0 0 0 0 20"/>',
    "server": '<rect x="2" y="3" width="20" height="8" rx="2"/><rect x="2" y="13" width="20" height="8" rx="2"/>'
              '<path d="M6 7h.01M6 17h.01"/>',
    "pulse": '<path d="M22 12h-4l-3 9L9 3l-3 9H2"/>',
    "jobs": '<path d="M12 2v4M12 18v4M4.93 4.93l2.83 2.83M16.24 16.24l2.83 2.83M2 12h4M18 12h4'
            'M4.93 19.07l2.83-2.83M16.24 7.76l2.83-2.83"/>',
    "plus": '<path d="M12 5v14M5 12h14"/>',
    "out": '<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4M16 17l5-5-5-5M21 12H9"/>',
    "back": '<path d="M15 18l-6-6 6-6"/>',
    "send": '<path d="M22 2L11 13M22 2l-7 20-4-9-9-4z"/>',
    "trash": '<path d="M3 6h18M8 6V4h8v2M19 6l-1 14H6L5 6"/>',
    "download": '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4M7 10l5 5 5-5M12 15V3"/>',
    "refresh": '<path d="M23 4v6h-6M1 20v-6h6"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/>',
    "power": '<path d="M18.36 6.64a9 9 0 1 1-12.73 0M12 2v10"/>',
    "shield": '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>',
    "unlock": '<rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 9.9-1"/>',
    "alert": '<path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>'
             '<path d="M12 9v4M12 17h.01"/>',
    "check": '<path d="M20 6L9 17l-5-5"/>',
    "pause": '<path d="M6 4h4v16H6zM14 4h4v16h-4z"/>',
    "play": '<path d="M5 3l14 9-14 9z"/>',
    "disk": '<ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/>',
    "copy": '<rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>',
}


def icon(name: str, cls: str = "i") -> str:
    return (f'<svg class="{cls}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" '
            f'stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">{_ICONS[name]}</svg>')


# --- Стили --------------------------------------------------------------------

CSS = """
:root{
 --bg:#f6f7f9;--surface:#fff;--surface-2:#f1f3f6;--ink:#0f1720;--ink-2:#4b5563;--ink-3:#8a94a3;
 --line:#e6e9ee;--accent:#4f5bd5;--accent-ink:#fff;--accent-soft:#eef0fd;
 --ok:#15803d;--ok-soft:#e8f6ee;--warn:#b45309;--warn-soft:#fdf3e4;--bad:#c53030;--bad-soft:#fdecec;
 --p-vless:#3b82f6;--p-hy2:#10b981;--p-awg:#f59e0b;
 --shadow:0 1px 2px rgba(16,24,40,.04),0 1px 3px rgba(16,24,40,.06);
 --r:14px;--side:232px;
}
@media (prefers-color-scheme:dark){:root{
 --bg:#0d0f13;--surface:#15181e;--surface-2:#1c2028;--ink:#e8ebf0;--ink-2:#b4bcc8;--ink-3:#7d8796;
 --line:#262b34;--accent:#8b93f5;--accent-ink:#0d0f13;--accent-soft:#1f2340;
 --ok:#4ade80;--ok-soft:#13281c;--warn:#fbbf24;--warn-soft:#2b2312;--bad:#f87171;--bad-soft:#2d1717;
 --shadow:none;}}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",
 Inter,Roboto,"Helvetica Neue",sans-serif;-webkit-font-smoothing:antialiased}
a{color:inherit;text-decoration:none}
.num{font-variant-numeric:tabular-nums}
.i{width:18px;height:18px;flex:none}

/* Каркас */
.side{position:fixed;inset:0 auto 0 0;width:var(--side);background:var(--surface);border-right:1px solid var(--line);
 display:flex;flex-direction:column;padding:20px 14px}
.brand{display:flex;align-items:center;gap:10px;font-weight:650;font-size:16px;padding:4px 10px 22px}
.mark{width:28px;height:28px;border-radius:8px;background:linear-gradient(135deg,var(--accent),#22c1a3);
 display:grid;place-items:center;color:#fff}
.mark .i{width:16px;height:16px}
.nav a{display:flex;align-items:center;gap:12px;padding:9px 10px;border-radius:10px;color:var(--ink-2);
 font-weight:500;margin-bottom:2px}
.nav a:hover{background:var(--surface-2);color:var(--ink)}
.nav a.on{background:var(--accent-soft);color:var(--accent)}
.side .foot{margin-top:auto}
.side .foot form button{width:100%;justify-content:flex-start;color:var(--ink-3)}
.main{margin-left:var(--side);min-height:100vh}
.wrap{max-width:1180px;margin:0 auto;padding:28px 32px 64px}
.top{display:none}
.tabs{display:none}

/* Заголовок страницы */
.head{display:flex;align-items:flex-end;justify-content:space-between;gap:16px;margin-bottom:22px;flex-wrap:wrap}
.head h1{font-size:24px;line-height:1.2;margin:0;font-weight:650;letter-spacing:-.01em}
.head p{margin:4px 0 0;color:var(--ink-3);font-size:14px}
.crumb{display:inline-flex;align-items:center;gap:4px;color:var(--ink-3);font-size:14px;margin-bottom:6px}
.crumb:hover{color:var(--ink)}
.actions{display:flex;gap:8px;flex-wrap:wrap}

/* Кнопки */
.btn{display:inline-flex;align-items:center;gap:8px;font:inherit;font-weight:550;font-size:14px;cursor:pointer;
 border-radius:10px;border:1px solid var(--line);background:var(--surface);color:var(--ink);padding:8px 14px;
 box-shadow:var(--shadow);white-space:nowrap}
.btn:hover{background:var(--surface-2)}
.btn.primary{background:var(--accent);border-color:var(--accent);color:var(--accent-ink)}
.btn.primary:hover{filter:brightness(1.07)}
.btn.danger{color:var(--bad)}
.btn.danger.solid{background:var(--bad);border-color:var(--bad);color:#fff}
.btn.ghost{border-color:transparent;box-shadow:none;background:transparent}
.btn.sm{padding:5px 10px;font-size:13px;border-radius:8px}
.btn[disabled]{opacity:.5;cursor:not-allowed}
form.inline{display:inline}

/* Карточки и сетки */
.grid{display:grid;gap:14px}
.g4{grid-template-columns:repeat(4,minmax(0,1fr))}.g3{grid-template-columns:repeat(3,minmax(0,1fr))}
.g2{grid-template-columns:repeat(2,minmax(0,1fr))}.g21{grid-template-columns:2fr 1fr}
.card{background:var(--surface);border:1px solid var(--line);border-radius:var(--r);padding:18px;box-shadow:var(--shadow);
 min-width:0}
.card h2{font-size:15px;font-weight:600;margin:0 0 4px}
.card .sub{color:var(--ink-3);font-size:13px;margin:0 0 14px}
.card-head{display:flex;justify-content:space-between;align-items:flex-start;gap:8px 12px;flex-wrap:wrap;margin-bottom:4px}
.sec{margin-top:26px}
.sec>h2{font-size:16px;font-weight:600;margin:0 0 12px;display:flex;align-items:center;gap:8px}
.sec>h2 .count{color:var(--ink-3);font-weight:500}

/* Показатели */
.kpi .label{color:var(--ink-3);font-size:13px;display:flex;align-items:center;gap:6px}
.kpi .value{font-size:26px;font-weight:650;letter-spacing:-.02em;margin:6px 0 2px;font-variant-numeric:tabular-nums}
.kpi .meta{color:var(--ink-3);font-size:13px;display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.delta{font-size:12px;font-weight:600;padding:1px 6px;border-radius:99px;background:var(--surface-2);color:var(--ink-2)}
.delta.up{color:var(--ok);background:var(--ok-soft)}.delta.down{color:var(--ink-2)}

/* Метки и статусы */
.dot{width:8px;height:8px;border-radius:50%;display:inline-block;background:var(--ink-3);flex:none}
.dot.on{background:var(--ok);box-shadow:0 0 0 3px var(--ok-soft)}.dot.bad{background:var(--bad)}.dot.warn{background:var(--warn)}
.badge{display:inline-flex;align-items:center;gap:5px;font-size:12px;font-weight:550;padding:2px 8px;border-radius:99px;
 background:var(--surface-2);color:var(--ink-2);white-space:nowrap}
.badge.vless{color:var(--p-vless);background:color-mix(in srgb,var(--p-vless) 12%,transparent)}
.badge.hy2{color:var(--p-hy2);background:color-mix(in srgb,var(--p-hy2) 12%,transparent)}
.badge.awg{color:var(--p-awg);background:color-mix(in srgb,var(--p-awg) 14%,transparent)}
.badge.ok{color:var(--ok);background:var(--ok-soft)}.badge.bad{color:var(--bad);background:var(--bad-soft)}
.badge.warn{color:var(--warn);background:var(--warn-soft)}
.muted{color:var(--ink-3)}.small{font-size:13px}

/* Списки (вместо таблиц — одинаково хорошо на телефоне и ноутбуке) */
.list{background:var(--surface);border:1px solid var(--line);border-radius:var(--r);box-shadow:var(--shadow);overflow:hidden}
.row{display:grid;grid-template-columns:minmax(0,2.2fr) minmax(0,1.3fr) minmax(0,1fr) minmax(0,1fr) 20px;gap:14px;
 align-items:center;padding:13px 18px;border-bottom:1px solid var(--line)}
.row:last-child{border-bottom:0}
a.row:hover{background:var(--surface-2)}
.row.headrow{color:var(--ink-3);font-size:12px;font-weight:550;text-transform:uppercase;letter-spacing:.04em;padding:10px 18px}
.who{display:flex;align-items:center;gap:12px;min-width:0}
.ava{width:34px;height:34px;border-radius:10px;display:grid;place-items:center;font-weight:650;font-size:14px;flex:none;
 background:var(--surface-2);color:var(--ink-2)}
.who b{display:block;font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.who span{color:var(--ink-3);font-size:13px}
.r{text-align:right}
.inl{display:inline-flex;align-items:center;gap:6px}
.m-only{display:none}.who .m-only .dot{width:7px;height:7px;box-shadow:none;margin-right:2px;vertical-align:1px}
.chev{color:var(--ink-3)}
.meter{height:6px;border-radius:99px;background:var(--surface-2);overflow:hidden;margin-top:6px}
.meter i{display:block;height:100%;border-radius:99px;background:var(--accent)}
.kv{display:grid;grid-template-columns:auto 1fr;gap:8px 18px;font-size:14px}
.kv dt{color:var(--ink-3)}.kv dd{margin:0;text-align:right;font-variant-numeric:tabular-nums;min-width:0;overflow-wrap:anywhere}

/* Фильтры */
.seg{display:inline-flex;background:var(--surface-2);border-radius:10px;padding:3px;gap:2px;max-width:100%;
 overflow-x:auto;scrollbar-width:none}
.seg a{padding:5px 12px;border-radius:8px;font-size:13px;font-weight:550;color:var(--ink-2);white-space:nowrap}
.seg a.on{background:var(--surface);color:var(--ink);box-shadow:var(--shadow)}
.toolbar{display:flex;gap:10px;align-items:center;justify-content:space-between;flex-wrap:wrap;margin-bottom:12px}
.search{display:flex;align-items:center;gap:8px;background:var(--surface);border:1px solid var(--line);border-radius:10px;
 padding:0 12px;min-width:220px}
.search input{border:0;background:transparent;font:inherit;color:var(--ink);padding:8px 0;outline:none;width:100%}

/* Графики */
.chart{width:100%;height:auto;display:block}
.chart .grid-l{stroke:var(--line)}.chart text{fill:var(--ink-3);font-size:11px}
.legend{display:flex;gap:16px;flex-wrap:wrap;font-size:13px;color:var(--ink-2);margin-bottom:10px}
.legend span{display:inline-flex;align-items:center;gap:6px}.legend i{width:9px;height:9px;border-radius:3px}
.donut-wrap{display:flex;gap:18px;align-items:center}
.donut-wrap ul{list-style:none;margin:0;padding:0;font-size:14px;display:grid;gap:8px;flex:1;min-width:0}
.donut-wrap li{display:flex;align-items:center;gap:8px}.donut-wrap li b{margin-left:auto;font-variant-numeric:tabular-nums;
 white-space:nowrap}.donut-wrap li .muted{width:34px;text-align:right}
.bars-list{display:grid;gap:12px}
.bars-list .bl{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:4px 12px;font-size:14px}
.bars-list .bl .meter{grid-column:1/-1;margin:0}

/* Лента событий и таймлайн */
.feed{display:grid}
.ev{display:grid;grid-template-columns:28px 1fr auto;gap:12px;padding:12px 0;border-bottom:1px solid var(--line);align-items:start}
.ev:last-child{border-bottom:0}
.ev .ic{width:28px;height:28px;border-radius:8px;display:grid;place-items:center;background:var(--surface-2);color:var(--ink-2)}
.ev .ic.ok{background:var(--ok-soft);color:var(--ok)}.ev .ic.bad{background:var(--bad-soft);color:var(--bad)}
.ev .ic.warn{background:var(--warn-soft);color:var(--warn)}
.ev .ic .i{width:15px;height:15px}
.ev p{margin:0;font-size:14px}.ev time{color:var(--ink-3);font-size:12px;white-space:nowrap}
.tl{position:relative;padding-left:22px}
.tl:before{content:"";position:absolute;left:6px;top:6px;bottom:6px;width:2px;background:var(--line)}
.tl .st{position:relative;padding:0 0 18px}
.tl .st:before{content:"";position:absolute;left:-20px;top:5px;width:10px;height:10px;border-radius:50%;
 background:var(--surface);border:2px solid var(--ink-3)}
.tl .st.now:before{border-color:var(--ok);background:var(--ok)}
.tl .st.auto:before{border-color:var(--warn)}
.tl .st b{font-variant-numeric:tabular-nums}
.tl .st .muted{font-size:13px}

/* Формы */
.field{display:grid;gap:6px;margin-bottom:14px}
.field label{font-size:13px;font-weight:550;color:var(--ink-2)}
.field input[type=text],.field select{font:inherit;padding:10px 12px;border-radius:10px;border:1px solid var(--line);
 background:var(--surface);color:var(--ink);width:100%}
.field .hint{font-size:12px;color:var(--ink-3)}
.choices{display:grid;gap:8px}
.choice{display:flex;gap:12px;align-items:flex-start;padding:12px 14px;border:1px solid var(--line);border-radius:12px;cursor:pointer}
.choice:has(input:checked){border-color:var(--accent);background:var(--accent-soft)}
.choice input{margin-top:3px;accent-color:var(--accent)}
.choice b{display:block;font-weight:600;font-size:14px}.choice span{color:var(--ink-3);font-size:13px}
.copy{display:flex;gap:8px;align-items:center;background:var(--surface-2);border-radius:10px;padding:10px 12px;
 font:13px/1.45 ui-monospace,SFMono-Regular,Menlo,monospace;overflow-wrap:anywhere}
.copy code{flex:1;min-width:0;user-select:all}

/* Сообщения */
.flash{display:flex;gap:10px;align-items:flex-start;padding:12px 14px;border-radius:12px;margin-bottom:18px;font-size:14px}
.flash.ok{background:var(--ok-soft);color:var(--ok)}.flash.bad{background:var(--bad-soft);color:var(--bad)}
.flash.warn{background:var(--warn-soft);color:var(--warn)}
.flash .i{margin-top:1px}
.danger-zone{border-color:color-mix(in srgb,var(--bad) 35%,var(--line))}
.log{background:var(--surface-2);border-radius:10px;padding:12px 14px;font:13px/1.6 ui-monospace,SFMono-Regular,Menlo,monospace;
 white-space:pre-wrap;overflow-wrap:anywhere;max-height:420px;overflow:auto}
.empty{padding:28px;text-align:center;color:var(--ink-3)}

/* Вход */
.login{min-height:100vh;display:grid;place-items:center;padding:20px}
.login .card{width:100%;max-width:360px;padding:28px;text-align:center}
.login .mark{width:44px;height:44px;border-radius:12px;margin:0 auto 14px}
.login .mark .i{width:22px;height:22px}
.login h1{font-size:20px;margin:0 0 4px}
.login input{font:600 26px/1 ui-monospace,monospace;letter-spacing:.35em;text-align:center;width:100%;padding:14px;
 border-radius:12px;border:1px solid var(--line);background:var(--surface-2);color:var(--ink);margin:18px 0 6px}
.login .btn{width:100%;justify-content:center;padding:12px}
.err{color:var(--bad);font-size:13px;min-height:20px;margin-bottom:8px}

/* Телефон */
@media (max-width:900px){
 .side{display:none}.main{margin-left:0}
 .top{display:flex;align-items:center;justify-content:space-between;position:sticky;top:0;z-index:5;
  background:color-mix(in srgb,var(--bg) 86%,transparent);backdrop-filter:blur(12px);-webkit-backdrop-filter:blur(12px);
  padding:12px 16px;border-bottom:1px solid var(--line)}
 .top .brand{padding:0;font-size:15px}
 .wrap{padding:18px 16px calc(96px + env(safe-area-inset-bottom))}
 .tabs{display:grid;grid-template-columns:repeat(5,1fr);position:fixed;inset:auto 0 0 0;z-index:5;
  background:color-mix(in srgb,var(--surface) 92%,transparent);backdrop-filter:blur(12px);-webkit-backdrop-filter:blur(12px);
  border-top:1px solid var(--line);padding:6px 4px calc(6px + env(safe-area-inset-bottom))}
 .tabs a{display:flex;flex-direction:column;align-items:center;gap:3px;font-size:11px;color:var(--ink-3);padding:4px 0;font-weight:550}
 .tabs a.on{color:var(--accent)}
 .tabs .i{width:22px;height:22px}
 .g4{grid-template-columns:repeat(2,minmax(0,1fr))}.g3,.g2,.g21{grid-template-columns:1fr}
 .head h1{font-size:21px}
 .kpi .value{font-size:22px}
 .row{grid-template-columns:minmax(0,1fr) auto;gap:4px 12px;padding:12px 14px}
 .row .hide-m{display:none}
 .who .d-only{display:none}.who .m-only{display:inline}
 .row.headrow{display:none}
 .card{padding:16px}
 .chart text{font-size:21px}
 .toolbar{flex-direction:column;align-items:stretch}.toolbar .search{min-width:0}
 .donut-wrap{flex-direction:column;align-items:stretch}.donut-wrap svg{margin:0 auto}
 .head .actions{width:100%}
 .head .actions .btn{flex:1;justify-content:center}
}
"""


# --- Каркас страницы ----------------------------------------------------------

NAV = [("/", "overview", "Обзор"), ("/people", "people", "Люди"), ("/addresses", "globe", "Адреса"),
       ("/server", "server", "Сервер"), ("/health", "pulse", "Здоровье")]


def document(title: str, body: str) -> bytes:
    return (f'<!doctype html><html lang="ru"><head><meta charset="utf-8">'
            f'<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">'
            f'<meta name="robots" content="noindex,nofollow"><meta name="color-scheme" content="light dark">'
            f'<title>{esc(title)} · mos8 VPN</title><style>{CSS}</style></head><body>{body}</body></html>').encode()


def shell(active: str, title: str, content: str, csrf: str, refresh: int = 0) -> bytes:
    """Боковое меню на ноутбуке, нижние вкладки на телефоне."""
    def links(cls: str) -> str:
        return "".join(f'<a href="{href}" class="{"on" if href == active else ""}">{icon(ic)}<span>{label}</span></a>'
                       for href, ic, label in NAV)
    logout = (f'<form method="post" action="/logout"><input type="hidden" name="csrf" value="{esc(csrf)}">'
              f'<button class="btn ghost">{icon("out")}Выйти</button></form>')
    meta = f'<meta http-equiv="refresh" content="{refresh}">' if refresh else ""
    brand = f'<div class="brand"><span class="mark">{icon("shield")}</span>mos8 VPN</div>'
    body = (f'{meta}<aside class="side">{brand}<nav class="nav">{links("nav")}'
            f'<a href="/devices" class="{"on" if active == "/devices" else ""}">{icon("shield")}<span>Устройства</span></a>'
            f'<a href="/jobs" class="{"on" if active == "/jobs" else ""}">{icon("jobs")}<span>Задачи</span></a></nav>'
            f'<div class="foot">{logout}</div></aside>'
            f'<header class="top">{brand}<div class="actions"><a class="btn sm ghost" href="/jobs">{icon("jobs")}</a>'
            f'{logout.replace("btn ghost", "btn sm ghost").replace(">Выйти<", "><")}</div></header>'
            f'<main class="main"><div class="wrap">{content}</div></main>'
            f'<nav class="tabs">{links("tabs")}</nav>')
    return document(title, body)


def head(title: str, subtitle: str = "", actions: str = "", back: tuple[str, str] | None = None) -> str:
    crumb = f'<a class="crumb" href="{back[0]}">{icon("back")}{esc(back[1])}</a>' if back else ""
    return (f'<div class="head"><div>{crumb}<h1>{esc(title)}</h1>'
            f'{f"<p>{subtitle}</p>" if subtitle else ""}</div>'
            f'{f"<div class=actions>{actions}</div>" if actions else ""}</div>')


def flash(kind: str, text: str) -> str:
    ic = {"ok": "check", "bad": "alert", "warn": "alert"}.get(kind, "check")
    return f'<div class="flash {kind}">{icon(ic)}<div>{text}</div></div>'


def kpi(label: str, value: str, meta: str = "", ic: str = "") -> str:
    return (f'<div class="card kpi"><div class="label">{icon(ic) if ic else ""}{esc(label)}</div>'
            f'<div class="value">{value}</div><div class="meta">{meta}</div></div>')


def badge(text: str, cls: str = "") -> str:
    return f'<span class="badge {cls}">{esc(text)}</span>'


def avatar(name: str, proto: str = "") -> str:
    words = re.findall(r"[^\W_]+", str(name))           # только буквы и цифры, без скобок
    letters = "".join(w[0] for w in words[:2]).upper() or "?"
    color = {"vless": "var(--p-vless)", "hy2": "var(--p-hy2)", "awg": "var(--p-awg)"}.get(proto, "")
    style = (f' style="background:color-mix(in srgb,{color} 14%,transparent);color:{color}"' if color else "")
    return f'<span class="ava"{style}>{esc(letters[:2])}</span>'


def button(action: str, label: str, csrf: str, fields: dict | None = None, cls: str = "btn",
           ic: str = "") -> str:
    """Кнопка-действие: POST /do с токеном CSRF. Опасные действия /do сначала
    переспросит на отдельной странице."""
    hidden = "".join(f'<input type="hidden" name="{esc(k)}" value="{esc(v)}">' for k, v in (fields or {}).items())
    return (f'<form method="post" action="/do" class="inline"><input type="hidden" name="csrf" value="{esc(csrf)}">'
            f'<input type="hidden" name="action" value="{esc(action)}">{hidden}'
            f'<button class="{cls}">{icon(ic) if ic else ""}{esc(label)}</button></form>')


def seg(options: Iterable[tuple[str, str]], current: str) -> str:
    return '<div class="seg">' + "".join(
        f'<a href="{href}" class="{"on" if key == current else ""}">{esc(label)}</a>'
        for key, href, label in options) + "</div>"


def kv(rows: Iterable[tuple[str, str]]) -> str:
    return '<dl class="kv">' + "".join(f"<dt>{esc(k)}</dt><dd>{v}</dd>" for k, v in rows) + "</dl>"


# --- Графики ------------------------------------------------------------------

PROTO_COLOR = {"vless": "var(--p-vless)", "hy2": "var(--p-hy2)", "awg": "var(--p-awg)"}
PROTO_NAME = {"vless": "VLESS", "hy2": "Hysteria2", "awg": "AmneziaWG"}
PROTO_ORDER = ("hy2", "vless", "awg")


def legend(protos: Iterable[str] = PROTO_ORDER) -> str:
    return '<div class="legend">' + "".join(
        f'<span><i style="background:{PROTO_COLOR[p]}"></i>{PROTO_NAME[p]}</span>' for p in protos) + "</div>"


def axis(n: float) -> str:
    """Короткая подпись оси: «375 МБ», «1,5 ГБ» — без лишних знаков."""
    n = float(n or 0)
    for unit in ("Б", "КБ", "МБ", "ГБ", "ТБ"):
        if n < 1024 or unit == "ТБ":
            text = f"{n:.0f}" if n >= 10 or n == int(n) else f"{n:.1f}".replace(".", ",")
            return f"{text} {unit}"
        n /= 1024
    return f"{n:.0f} ТБ"


def _x_labels(n: int) -> set[int]:
    """Какие столбики подписывать: примерно семь подписей, последняя всегда,
    и ни одна не наезжает на последнюю."""
    step = max(1, round(n / 7))
    marks = {i for i in range(0, n, step) if n - 1 - i >= step * 0.6}
    return marks | {n - 1}


def _nice_top(v: float) -> float:
    if v <= 0:
        return 1
    mag = 1024 ** max(0, min(4, int(__import__("math").log(v, 1024))))
    for step in (1, 2, 5, 10, 20, 50, 100, 200, 500, 1000):
        if v <= step * mag:
            return step * mag
    return v


def stacked_bars(series: list[tuple[int, dict[str, int]]], height: int = 190) -> str:
    """Столбики по дням, сложенные по протоколам, с сеткой и подписями оси."""
    if not series:
        return '<div class="empty">данных пока нет</div>'
    top = _nice_top(max(sum(v.values()) for _, v in series))
    n = len(series)
    left, bottom, width = 78, 30, 760
    plot_w, plot_h = width - left - 6, height - bottom - 8
    bw = plot_w / n
    labels = _x_labels(n)
    out = [f'<svg viewBox="0 0 {width} {height}" class="chart" role="img" aria-label="Трафик по дням">']
    for k in range(5):
        y = 8 + plot_h * k / 4
        out.append(f'<line class="grid-l" x1="{left}" x2="{width}" y1="{y:.1f}" y2="{y:.1f}"/>'
                   f'<text x="{left - 8}" y="{y + 4:.1f}" text-anchor="end">{esc(axis(top * (4 - k) / 4))}</text>')
    for i, (d, values) in enumerate(series):
        x = left + i * bw + bw * 0.18
        w = bw * 0.64
        y = 8 + plot_h
        tip = day(d) + " — " + (", ".join(f"{PROTO_NAME[p]} {size(values[p])}" for p in PROTO_ORDER
                                          if values.get(p)) or "нет трафика")
        out.append(f"<g><title>{esc(tip)}</title>")
        stack = [(p, values.get(p, 0)) for p in PROTO_ORDER if values.get(p)]
        for j, (p, v) in enumerate(stack):
            h = max(v / top * plot_h, 1.2)
            y -= h
            r = 3 if j == len(stack) - 1 else 0
            out.append(f'<rect x="{x:.1f}" y="{y:.1f}" width="{w:.1f}" height="{h:.1f}" rx="{r}" fill="{PROTO_COLOR[p]}"/>')
        out.append(f'<rect x="{left + i * bw:.1f}" y="8" width="{bw:.1f}" height="{plot_h}" fill="transparent"/></g>')
        if i in labels:
            out.append(f'<text x="{left + i * bw + bw / 2:.1f}" y="{height - 6}" text-anchor="middle">{day(d)}</text>')
    out.append("</svg>")
    return "".join(out)


def area(points: list[tuple[int, float]], fmt=size, height: int = 150, label: str = "") -> str:
    """Плавная площадь по точкам — нагрузка и подключения за сутки."""
    if len(points) < 2:
        return '<div class="empty">данных пока мало — график появится через час-другой</div>'
    top = _nice_top(max(v for _, v in points)) if fmt is size else max(max(v for _, v in points), 1)
    fmt = axis if fmt is size else fmt
    left, width, bottom = 78, 760, 30
    plot_w, plot_h = width - left - 6, height - bottom - 8
    t0, t1 = points[0][0], points[-1][0]
    xy = [(left + (t - t0) / max(t1 - t0, 1) * plot_w, 8 + plot_h - v / top * plot_h) for t, v in points]
    line = " ".join(f"{'M' if i == 0 else 'L'}{x:.1f},{y:.1f}" for i, (x, y) in enumerate(xy))
    fill = line + f" L{xy[-1][0]:.1f},{8 + plot_h} L{xy[0][0]:.1f},{8 + plot_h} Z"
    out = [f'<svg viewBox="0 0 {width} {height}" class="chart" role="img" aria-label="{esc(label)}">',
           '<defs><linearGradient id="ag" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="var(--accent)" '
           'stop-opacity=".28"/><stop offset="1" stop-color="var(--accent)" stop-opacity="0"/></linearGradient></defs>']
    for k in range(3):
        y = 8 + plot_h * k / 2
        out.append(f'<line class="grid-l" x1="{left}" x2="{width}" y1="{y:.1f}" y2="{y:.1f}"/>'
                   f'<text x="{left - 8}" y="{y + 4:.1f}" text-anchor="end">'
                   f'{esc(fmt(top * (2 - k) / 2))}</text>')
    out.append(f'<path d="{fill}" fill="url(#ag)"/><path d="{line}" fill="none" stroke="var(--accent)" stroke-width="2"/>')
    for i, anchor in ((0, "start"), (len(points) // 2, "middle"), (len(points) - 1, "end")):
        out.append(f'<text x="{xy[i][0]:.1f}" y="{height - 6}" text-anchor="{anchor}">{clock(points[i][0])}</text>')
    out.append("</svg>")
    return "".join(out)


def donut(parts: dict[str, int], center: str, caption: str) -> str:
    total = sum(parts.values())
    r, c = 52, 2 * 3.14159265 * 52
    arcs, offset = [], 0.0
    for p in PROTO_ORDER:
        v = parts.get(p, 0)
        if not v or not total:
            continue
        frac = v / total
        arcs.append(f'<circle r="{r}" cx="64" cy="64" fill="none" stroke="{PROTO_COLOR[p]}" stroke-width="14" '
                    f'stroke-dasharray="{frac * c:.2f} {c:.2f}" stroke-dashoffset="{-offset * c:.2f}" '
                    f'transform="rotate(-90 64 64)"/>')
        offset += frac
    ring = (f'<svg viewBox="0 0 128 128" width="128" height="128" role="img" aria-label="{esc(caption)}">'
            f'<circle r="{r}" cx="64" cy="64" fill="none" stroke="var(--surface-2)" stroke-width="14"/>'
            + "".join(arcs) +
            f'<text x="64" y="62" text-anchor="middle" style="font-size:17px;font-weight:650;fill:var(--ink)">{esc(center)}</text>'
            f'<text x="64" y="80" text-anchor="middle" style="font-size:11px;fill:var(--ink-3)">{esc(caption)}</text></svg>')
    items = "".join(
        f'<li><i class="dot" style="background:{PROTO_COLOR[p]}"></i>{PROTO_NAME[p]}'
        f'<b>{size(parts.get(p, 0))}</b><span class="muted small">{(parts.get(p, 0) / total * 100 if total else 0):.0f}%</span></li>'
        for p in PROTO_ORDER)
    return f'<div class="donut-wrap">{ring}<ul>{items}</ul></div>'


def bar_list(items: list[tuple[str, str, int, str]], empty: str = "пока пусто") -> str:
    """[(подпись, ссылка, значение, протокол)] — топ по трафику."""
    if not items:
        return f'<div class="empty">{esc(empty)}</div>'
    top = max(v for _, _, v, _ in items) or 1
    rows = []
    for label, href, v, proto in items:
        rows.append(f'<a class="bl" href="{href}"><span>{esc(label)}</span><b class="num">{size(v)}</b>'
                    f'<div class="meter"><i style="width:{max(v / top * 100, 2):.1f}%;'
                    f'background:{PROTO_COLOR.get(proto, "var(--accent)")}"></i></div></a>')
    return '<div class="bars-list">' + "".join(rows) + "</div>"
