#!/usr/bin/env python3
"""Снимок всех счётчиков VPN-сервера одним JSON — для статистики в админке.

    stats-snapshot.py           напечатать снимок

Ничего не хранит и ничего не меняет: только читает. Хранит и считает разницу
бот на medbot — он переживает смену адреса, а этот сервер при ротации
клонируется, и всё, что легло на диск после снятия копии, пропало бы.

Счётчики накопительные, как их ведёт источник:
  * VLESS — база панели 3x-ui (client_traffics: up/down с момента выдачи ключа);
  * Hysteria2 — API статистики (с момента запуска hysteria-server);
  * AmneziaWG — awg show dump (с момента подъёма интерфейса в контейнере).
Сбросы (перезапуск службы или контейнера) бот распознаёт по уменьшению счётчика.

Адреса людей сюда не попадают, кроме тех, что уже показывает сторож
устройств: сколько сетей у ключа сейчас и кто отрезан.
"""
from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import time
import urllib.request
from pathlib import Path

XUI_DB = "/opt/panel/db/x-ui.db"
GUARD_ENV = Path("/opt/panel/device-guard.env")
AWG31_CLIENTS = Path("/opt/awg31/clients")


def sh(cmd: list[str], timeout: float = 20) -> str:
    try:
        done = subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=timeout)
        return done.stdout if done.returncode == 0 else ""
    except (OSError, subprocess.TimeoutExpired):
        return ""


def vless() -> dict:
    out = {}
    try:
        db = sqlite3.connect(f"file:{XUI_DB}?mode=ro", uri=True, timeout=5)
        for email, up, down, enable, last in db.execute(
                "select email, up, down, enable, last_online from client_traffics"):
            # up — от клиента к серверу, down — к клиенту.
            out[email] = {"rx": int(down or 0), "tx": int(up or 0), "enabled": bool(enable),
                          "last_seen": int((last or 0) // 1000)}
    except sqlite3.Error as exc:
        out["_error"] = str(exc)
    return out


def hy2() -> dict:
    secret = ""
    try:
        for line in GUARD_ENV.read_text().splitlines():
            if line.startswith("HY2_SECRET="):
                secret = line.split("=", 1)[1].strip()
    except OSError:
        pass
    if not secret:
        return {}

    def get(path: str):
        req = urllib.request.Request("http://127.0.0.1:8898" + path, headers={"Authorization": secret})
        with urllib.request.urlopen(req, timeout=5) as answer:
            return json.loads(answer.read().decode() or "{}")

    try:
        traffic, online = get("/traffic"), get("/online")
    except (OSError, ValueError) as exc:
        return {"_error": str(exc)}
    out = {}
    for name in set(traffic) | set(online):
        t = traffic.get(name) or {}
        # tx/rx в API Hysteria — со стороны клиента (как и в /dump/streams):
        # rx — скачано клиентом, tx — отдано им. Сверено по живому ключу:
        # видео в браузере даёт rx на порядки больше tx.
        out[name] = {"rx": int(t.get("rx", 0)), "tx": int(t.get("tx", 0)),
                     "online": int(online.get(name, 0))}
    return out


def awg_names_amnezia() -> dict[str, str]:
    raw = sh(["docker", "exec", "amnezia-awg2", "cat", "/opt/amnezia/awg/clientsTable"])
    try:
        return {c["clientId"]: (c.get("userData") or {}).get("clientName") or c["clientId"][:8]
                for c in json.loads(raw or "[]")}
    except (ValueError, KeyError, TypeError):
        return {}


def awg_names_31() -> dict[str, str]:
    names = {}
    for conf in AWG31_CLIENTS.glob("*.conf") if AWG31_CLIENTS.is_dir() else []:
        for line in conf.read_text(errors="replace").splitlines():
            if line.startswith("Address"):
                names[line.split("=", 1)[1].strip().split("/")[0].split(",")[0].strip()] = conf.stem
                break
    return names


def awg() -> list[dict]:
    peers = []
    sources = [("amnezia-awg2", "awg0", awg_names_amnezia(), "key"),
               ("awg31", "awg1", awg_names_31(), "ip")]
    for container, iface, names, by in sources:
        dump = sh(["docker", "exec", container, "awg", "show", iface, "dump"])
        for line in dump.splitlines()[1:]:
            parts = line.split("\t")
            if len(parts) < 8:
                continue
            pub, _psk, _endpoint, ips, handshake, rx, tx = parts[:7]
            ip = ips.split("/")[0]
            name = names.get(pub if by == "key" else ip) or f"без имени {pub[:6]}"
            # rx/tx в awg — со стороны сервера: rx пришло от клиента.
            peers.append({"server": container, "name": name, "id": pub[:16],
                          "rx": int(tx), "tx": int(rx), "handshake": int(handshake)})
    return peers


def guard() -> dict:
    out = sh(["/opt/panel/device-guard.py", "status", "--json"], timeout=40)
    try:
        return json.loads(out or "{}")
    except ValueError:
        return {}


def system() -> dict:
    mem = {}
    for line in Path("/proc/meminfo").read_text().splitlines():
        key, value = line.split(":", 1)
        if key in ("MemTotal", "MemAvailable", "SwapTotal", "SwapFree"):
            mem[key] = int(value.split()[0]) // 1024
    disk = os.statvfs("/")
    try:
        report = json.loads(Path("/var/lib/vpn-watchdog/state.json").read_text()).get("report", {})
    except (OSError, ValueError):
        report = {}
    return {
        "mem_total": mem.get("MemTotal", 0), "mem_avail": mem.get("MemAvailable", 0),
        "swap_used": mem.get("SwapTotal", 0) - mem.get("SwapFree", 0),
        "disk_pct": 100 - disk.f_bavail * 100 // max(disk.f_blocks, 1),
        "load": [round(x, 2) for x in os.getloadavg()],
        "uptime": int(float(Path("/proc/uptime").read_text().split()[0])),
        "watchdog": report,
    }


def events() -> list[dict]:
    """Последние события обоих сторожей — для ленты в админке."""
    out = []
    for script, source in (("/opt/panel/device-guard.py", "устройства"),
                           ("/opt/panel/watchdog.py", "здоровье")):
        try:
            rows = json.loads(sh([script, "events", "--json"], timeout=30) or "[]")
        except ValueError:
            rows = []
        for r in rows[-30:]:
            r["source"] = source
            out.append(r)
    return sorted(out, key=lambda r: r.get("t", 0))[-40:]


def main() -> None:
    keys = vless()
    h = hy2()
    # Hysteria2 помнит трафик удалённого ключа до своего перезапуска. Ключи
    # живут в панели — что в ней нет, того в снимке тоже нет.
    if "_error" not in keys and "_error" not in h:
        h = {name: v for name, v in h.items() if name in keys}
    print(json.dumps({"ts": int(time.time()), "host": os.uname().nodename, "vless": keys,
                      "hy2": h, "awg": awg(), "guard": guard(), "system": system(),
                      "events": events()},
                     ensure_ascii=False))


if __name__ == "__main__":
    main()
