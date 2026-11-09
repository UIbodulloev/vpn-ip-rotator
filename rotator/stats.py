"""Статистика: трафик по людям, протоколам и адресам сервера.

Раз в 5 минут бот берёт с VPN-сервера снимок накопительных счётчиков
(panel/stats-snapshot.py), считает разницу с прошлым снимком и складывает её
в почасовые корзины: час × адрес сервера × протокол × клиент. Корзины лежат
здесь, на medbot, а не на VPN-сервере: тот при ротации клонируется, и всё,
что легло на его диск после снятия копии, пропало бы.

Счётчики у источников сбрасываются: Hysteria2 — при перезапуске службы,
AmneziaWG — при перезапуске контейнера. Сброс видно по уменьшению: тогда
разница — это само новое значение.
"""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

from . import log

logger = log.get("stats")

PROTOS = ("vless", "hy2", "awg")
PROTO_TITLES = {"vless": "VLESS", "hy2": "Hysteria2", "awg": "AmneziaWG"}

SCHEMA = """
create table if not exists hourly (
    hour integer, server_ip text, proto text, client text, rx integer, tx integer,
    primary key (hour, server_ip, proto, client));
create table if not exists counters (
    proto text, id text, rx integer, tx integer, ts integer,
    primary key (proto, id));
create table if not exists load (
    ts integer primary key, server_ip text, keys_online integer, awg_online integer,
    mem_avail integer, swap_used integer, disk_pct integer, load1 real);
create table if not exists meta (k text primary key, v text);
"""


def delta(prev: int, cur: int) -> int:
    """Сколько прибавилось. Счётчик уменьшился — значит, его сбросили, и всё,
    что в нём сейчас, набежало после сброса."""
    return cur - prev if cur >= prev else cur


class Stats:
    def __init__(self, path: Path):
        self.path = path
        self.lock = threading.Lock()
        path.parent.mkdir(parents=True, exist_ok=True)
        self.latest: dict[str, Any] = {}
        self.latest_path = path.with_name("stats-latest.json")
        try:
            self.latest = json.loads(self.latest_path.read_text())
        except (OSError, ValueError):
            pass
        with self.db() as db:
            db.executescript(SCHEMA)
            db.execute("insert or ignore into meta values ('started', ?)", (str(int(time.time())),))

    def db(self) -> sqlite3.Connection:
        return sqlite3.connect(self.path, timeout=10)

    # --- запись -------------------------------------------------------------

    def ingest(self, snap: dict[str, Any], server_ip: str) -> int:
        """Разложить снимок. Возвращает, сколько байт прибавилось всего."""
        ts = int(snap.get("ts") or time.time())
        hour = ts // 3600 * 3600
        rows: list[tuple[str, str, str, int, int]] = []     # proto, id, client, rx, tx
        for name, c in (snap.get("vless") or {}).items():
            if isinstance(c, dict):
                rows.append(("vless", name, name, int(c.get("rx", 0)), int(c.get("tx", 0))))
        for name, c in (snap.get("hy2") or {}).items():
            if isinstance(c, dict):
                rows.append(("hy2", name, name, int(c.get("rx", 0)), int(c.get("tx", 0))))
        for p in snap.get("awg") or []:
            rows.append(("awg", f"{p.get('server')}:{p.get('id')}", str(p.get("name")),
                         int(p.get("rx", 0)), int(p.get("tx", 0))))

        added = 0
        with self.lock, self.db() as db:
            for proto, ident, client, rx, tx in rows:
                prev = db.execute("select rx, tx from counters where proto=? and id=?",
                                  (proto, ident)).fetchone()
                db.execute("insert or replace into counters values (?,?,?,?,?)",
                           (proto, ident, rx, tx, ts))
                if prev is None:
                    continue                      # первый снимок — только точка отсчёта
                drx, dtx = delta(prev[0], rx), delta(prev[1], tx)
                if drx or dtx:
                    added += drx + dtx
                    db.execute(
                        "insert into hourly values (?,?,?,?,?,?) on conflict(hour, server_ip, proto, client) "
                        "do update set rx = rx + excluded.rx, tx = tx + excluded.tx",
                        (hour, server_ip, proto, client, drx, dtx))
            system = snap.get("system") or {}
            online = (snap.get("guard") or {}).get("online") or {}
            awg_online = sum(1 for p in snap.get("awg") or [] if ts - int(p.get("handshake", 0)) < 180)
            db.execute("insert or replace into load values (?,?,?,?,?,?,?,?)",
                       (ts, server_ip, len(online), awg_online, system.get("mem_avail"),
                        system.get("swap_used"), system.get("disk_pct"),
                        (system.get("load") or [0])[0]))
            # Нагрузку храним 90 дней — дальше она никому не интересна.
            db.execute("delete from load where ts < ?", (ts - 90 * 86400,))
        self.latest = {**snap, "server_ip": server_ip, "collected": ts}
        tmp = self.latest_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.latest, ensure_ascii=False))
        tmp.replace(self.latest_path)
        return added

    # --- чтение -------------------------------------------------------------

    def started(self) -> int:
        with self.db() as db:
            row = db.execute("select v from meta where k='started'").fetchone()
        return int(row[0]) if row else int(time.time())

    def by_proto(self, since: int) -> dict[str, int]:
        with self.db() as db:
            rows = db.execute("select proto, sum(rx + tx) from hourly where hour >= ? group by proto",
                              (since,)).fetchall()
        return {p: int(v or 0) for p, v in rows}

    def daily(self, days: int) -> list[tuple[int, dict[str, int]]]:
        """[(начало суток UTC, {протокол: байт})] за последние days суток."""
        today = int(time.time()) // 86400 * 86400
        start = today - (days - 1) * 86400
        with self.db() as db:
            rows = db.execute("select hour / 86400 * 86400 as d, proto, sum(rx + tx) from hourly "
                              "where hour >= ? group by d, proto", (start,)).fetchall()
        out = {start + i * 86400: {} for i in range(days)}
        for d, proto, v in rows:
            out.setdefault(d, {})[proto] = int(v or 0)
        return sorted(out.items())

    def clients(self) -> list[dict[str, Any]]:
        """Каждый клиент: трафик за сутки, 7 и 30 дней и за всё время, по протоколам."""
        now = int(time.time())
        windows = {"day": now - 86400, "week": now - 7 * 86400, "month": now - 30 * 86400, "all": 0}
        out: dict[tuple[str, str], dict[str, Any]] = {}
        with self.db() as db:
            for key, since in windows.items():
                for proto, client, rx, tx in db.execute(
                        "select proto, client, sum(rx), sum(tx) from hourly where hour >= ? "
                        "group by proto, client", (since,)):
                    row = out.setdefault((proto, client), {"proto": proto, "client": client})
                    row[key] = int((rx or 0) + (tx or 0))
                    if key == "all":
                        row["rx"], row["tx"] = int(rx or 0), int(tx or 0)
            for proto, client, last in db.execute(
                    "select proto, client, max(hour) from hourly group by proto, client"):
                if (proto, client) in out:
                    out[(proto, client)]["last_hour"] = int(last)
        return sorted(out.values(), key=lambda r: -r.get("month", 0))

    def by_server(self) -> dict[str, dict[str, Any]]:
        with self.db() as db:
            rows = db.execute("select server_ip, proto, sum(rx + tx), min(hour), max(hour) "
                              "from hourly group by server_ip, proto").fetchall()
        out: dict[str, dict[str, Any]] = {}
        for ip, proto, total, first, last in rows:
            row = out.setdefault(ip, {"total": 0, "first": first, "last": last})
            row[proto] = int(total or 0)
            row["total"] += int(total or 0)
            row["first"], row["last"] = min(row["first"], first), max(row["last"], last)
        return out

    def load_series(self, hours: int = 24) -> list[tuple]:
        with self.db() as db:
            return db.execute("select ts, keys_online, awg_online, mem_avail from load where ts >= ? "
                              "order by ts", (int(time.time()) - hours * 3600,)).fetchall()


def collect_loop(bot, stats: Stats, stop_event: threading.Event, every: int = 300) -> None:
    """Раз в every секунд — снимок с VPN-сервера в базу."""
    stop_event.wait(45)
    while not stop_event.is_set():
        try:
            answer = bot._awg("/opt/panel/stats-snapshot.py", timeout=90)
            if answer.ok and answer.out.strip().startswith("{"):
                added = stats.ingest(json.loads(answer.out), bot.engine.state["ipv4"] or "?")
                # Аргументы журнал превращает в строки (маскирует секреты),
                # поэтому число форматируем сами.
                logger.info("снимок статистики: +%s МБ", f"{added / 1048576:.1f}")
            elif answer.code != 255:
                logger.warning("снимок статистики не удался: %s", answer.text(200))
        except Exception as exc:                               # noqa: BLE001
            logger.warning("снимок статистики не удался: %s", exc)
        stop_event.wait(every)
