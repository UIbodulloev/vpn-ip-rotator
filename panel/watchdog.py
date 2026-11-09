#!/usr/bin/env python3
"""Сторож здоровья VPN-сервера: чинит сам, о важном сообщает в бот.

    watchdog.py check                один проход (раз в минуту по таймеру)
    watchdog.py events [--since T] [--json]   что случилось и что сделано
    watchdog.py status               последний проход: что в порядке, что нет
    watchdog.py install              поставить таймер (один раз)

Что делает каждую минуту:
  * службы hysteria-server, device-guard, sub-mirror, docker: упала — поднять;
  * контейнеры 3x-ui и AmneziaWG: не работает — docker restart;
  * не только «процесс жив», но и «отвечает»: ядро VLESS через свой API,
    Hysteria2 через API статистики, сторож устройств через проверку входа,
    зеркало подписок через HTTPS. Не отвечает два прохода подряд — перезапуск;
  * теснота: мало свободной памяти три минуты подряд, большой своп, полный
    диск, долгая перегрузка процессора, убитые ядром процессы (OOM);
  * раз в 5 минут — бот на medbot (через ops-доступ): лёг — перезапустить;
  * раз в 6 часов — списки в генераторе подписок: перешёл на запасные — сказать.

Сообщений сам не шлёт: токена бота здесь нет и не нужно. События ложатся в
журнал, бот забирает их раз в минуту и присылает владельцу. О тесноте
напоминает не чаще раза в 6 часов, о падениях — каждый раз.
"""
from __future__ import annotations

import json
import os
import re
import ssl
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

STATE_DIR = Path("/var/lib/vpn-watchdog")
STATE_FILE = STATE_DIR / "state.json"
EVENTS_FILE = STATE_DIR / "events.jsonl"
GUARD_ENV = Path("/opt/panel/device-guard.env")
HEALTH_URL = "https://origin.mos8.online/health"

UNITS = ["docker", "hysteria-server", "device-guard", "sub-mirror"]
CONTAINERS = ["3x-ui", "amnezia-awg2", "awg31", "amnezia-dns"]

MEM_LOW_MB = 80          # MemAvailable ниже — тесно
MEM_LOW_MINUTES = 3
SWAP_HIGH_MB = 1500
DISK_HIGH_PCT = 90
LOAD15_HIGH = 2.0        # одно ядро: 2.0 — очередь вдвое длиннее, чем можно разгрести
TIGHT_REPEAT = 6 * 3600
MEDBOT_EVERY = 300
HEALTH_EVERY = 6 * 3600


def sh(cmd: list[str], timeout: float = 20, data: str | None = None) -> tuple[int, str]:
    try:
        # errors="replace": чужой вывод режут по байтам (cut -c), и половинка
        # русской буквы не должна ронять весь проход сторожа.
        done = subprocess.run(cmd, input=data, capture_output=True, text=True,
                              errors="replace", timeout=timeout)
        return done.returncode, (done.stdout + done.stderr).strip()
    except subprocess.TimeoutExpired:
        return 124, "таймаут"
    except OSError as exc:
        return 127, str(exc)


def load_state() -> dict:
    try:
        return json.loads(STATE_FILE.read_text())
    except (OSError, ValueError):
        return {}


def save_state(state: dict) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    tmp = STATE_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, ensure_ascii=False, indent=1))
    tmp.replace(STATE_FILE)


def event(kind: str, text: str, **extra) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    record = {"t": round(time.time()), "kind": kind, "text": text, **extra}
    with EVENTS_FILE.open("a") as fh:
        fh.write(json.dumps(record, ensure_ascii=False) + "\n")
    print(f"событие: {kind}: {text}", file=sys.stderr, flush=True)
    # Журнал не растёт бесконечно: держим последние 1000 записей.
    lines = EVENTS_FILE.read_text().splitlines()
    if len(lines) > 1200:
        EVENTS_FILE.write_text("\n".join(lines[-1000:]) + "\n")


def env_value(path: Path, key: str) -> str:
    try:
        for line in path.read_text().splitlines():
            if line.startswith(key + "="):
                return line.split("=", 1)[1].strip()
    except OSError:
        pass
    return ""


# --- Проверки «отвечает ли» ---------------------------------------------------

def probe_xray() -> bool:
    rc, out = sh(["docker", "exec", "3x-ui", "/app/bin/xray-linux-amd64", "api",
                  "statsgetallonlineusers", "--server=127.0.0.1:62789"], timeout=15)
    if rc != 0:
        return False
    rc, out = sh(["ss", "-Hltn", "sport = :443"])
    return rc == 0 and bool(out)


def probe_hysteria() -> bool:
    secret = env_value(GUARD_ENV, "HY2_SECRET")
    if not secret:
        return True                         # API не настроен — судим по службе
    try:
        req = urllib.request.Request("http://127.0.0.1:8898/online", headers={"Authorization": secret})
        with urllib.request.urlopen(req, timeout=5) as answer:
            return answer.status == 200
    except OSError:
        return False


def probe_guard() -> bool:
    try:
        req = urllib.request.Request("http://127.0.0.1:8899/auth", method="POST",
                                     data=b'{"addr":"127.0.0.1:1","auth":"watchdog","tx":0}')
        with urllib.request.urlopen(req, timeout=10) as answer:
            return '"ok"' in answer.read().decode()
    except OSError:
        return False


def probe_mirror() -> bool:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE         # сертификат на имя, а ходим на 127.0.0.1
    try:
        with urllib.request.urlopen("https://127.0.0.1:8443/", timeout=10, context=ctx) as answer:
            return answer.status == 200
    except OSError:
        return False


# Что проверять и чем лечить. Лечим со второго подряд провала: один сбой
# бывает и у здорового (ядро как раз перезапускает панель при выдаче ключа).
PROBES = {
    "xray": (probe_xray, ["docker", "restart", "3x-ui"], "ядро VLESS (3x-ui)"),
    "hysteria": (probe_hysteria, ["systemctl", "restart", "hysteria-server"], "Hysteria2"),
    "guard": (probe_guard, ["systemctl", "restart", "device-guard"], "сторож устройств"),
    "mirror": (probe_mirror, ["systemctl", "restart", "sub-mirror"], "зеркало подписок"),
}


# --- Проход -------------------------------------------------------------------

def check() -> None:
    state = load_state()
    now = time.time()
    fails = state.setdefault("fails", {})
    notes = state.setdefault("last_note", {})
    report: dict[str, str] = {}

    def tight(key: str, text: str, **extra) -> None:
        if now - notes.get(key, 0) > TIGHT_REPEAT:
            notes[key] = now
            event("tight", text, check=key, **extra)

    def healed(key: str, title: str, back: bool) -> None:
        """Сообщить о починке всегда, о неудаче — не чаще раза в 30 минут:
        то, что не поднимается, иначе писало бы каждую минуту."""
        if back:
            event("restarted", f"{title} — перезапущено, работает", check=key)
            notes.pop("down:" + key, None)
        elif now - notes.get("down:" + key, 0) > 1800:
            notes["down:" + key] = now
            event("down", f"{title} — перезапуск не помог, нужен человек", check=key)

    # 1. Службы.
    for unit in UNITS:
        rc, _ = sh(["systemctl", "is-active", "--quiet", unit])
        if rc == 0:
            report[unit] = "ok"
            continue
        sh(["systemctl", "restart", unit], timeout=60)
        time.sleep(3)
        back = sh(["systemctl", "is-active", "--quiet", unit])[0] == 0
        report[unit] = "поднят" if back else "ЛЕЖИТ"
        healed(unit, f"служба {unit} упала", back)

    # 2. Контейнеры. Если сам docker не поднялся, смотреть их бессмысленно.
    if report.get("docker") != "ЛЕЖИТ":
        for name in CONTAINERS:
            rc, status = sh(["docker", "inspect", "-f", "{{.State.Status}}", name])
            if rc != 0:
                report[name] = "нет"         # такого контейнера нет — не наше дело
                continue
            if status == "running":
                report[name] = "ok"
                continue
            sh(["docker", "restart", name], timeout=90)
            time.sleep(3)
            back = sh(["docker", "inspect", "-f", "{{.State.Status}}", name])[1] == "running"
            report[name] = "поднят" if back else "ЛЕЖИТ"
            healed(name, f"контейнер {name} был в состоянии {status}", back)

    # 3. Отвечают ли.
    for key, (probe, fix, title) in PROBES.items():
        if probe():
            if fails.get(key, 0) >= 2:
                event("recovered", f"{title} снова отвечает", check=key)
            fails[key] = 0
            report[key] = "отвечает"
            continue
        fails[key] = fails.get(key, 0) + 1
        report[key] = f"не отвечает ({fails[key]})"
        # Лечим на втором провале и потом раз в 15 минут, пока не ответит.
        if fails[key] == 2 or (fails[key] > 2 and fails[key] % 15 == 2):
            sh(fix, timeout=90)
            time.sleep(5)
            back = probe()
            healed(key, f"{title} перестал отвечать", back)
            if back:
                fails[key] = 0
                report[key] = "перезапущен"

    # 4. Теснота.
    mem = {k: int(v.split()[0]) // 1024 for k, v in
           (line.split(":", 1) for line in Path("/proc/meminfo").read_text().splitlines())
           if k in ("MemAvailable", "SwapTotal", "SwapFree")}
    avail, swap = mem.get("MemAvailable", 0), mem.get("SwapTotal", 0) - mem.get("SwapFree", 0)
    report["память"] = f"свободно {avail} МБ, своп {swap} МБ"
    state["low_mem"] = state.get("low_mem", 0) + 1 if avail < MEM_LOW_MB else 0
    if state["low_mem"] >= MEM_LOW_MINUTES:
        top = sh(["ps", "-eo", "rss,comm", "--sort=-rss"])[1].splitlines()[1:4]
        tight("memory", f"свободной памяти {avail} МБ уже {state['low_mem']} мин — VPN может "
              f"тормозить. Больше всех едят: " + ", ".join(
                  f"{p.split()[1]} {int(p.split()[0]) // 1024} МБ" for p in top if len(p.split()) > 1))
    if swap > SWAP_HIGH_MB:
        tight("swap", f"в свопе {swap} МБ — сервер вынужден постоянно подкачивать память с диска")
    usage = os.statvfs("/")
    used_pct = 100 - usage.f_bavail * 100 // max(usage.f_blocks, 1)
    report["диск"] = f"занято {used_pct}%"
    if used_pct >= DISK_HIGH_PCT:
        tight("disk", f"диск заполнен на {used_pct}%")
    load15 = os.getloadavg()[2]
    report["нагрузка"] = f"{load15:.2f}"
    if load15 > LOAD15_HIGH:
        tight("cpu", f"процессор перегружен уже 15 минут (нагрузка {load15:.1f} на одно ядро)")
    since = int(state.get("oom_since", now - 60))
    rc, out = sh(["journalctl", "-k", "--since", f"@{since}", "--no-pager", "-o", "cat",
                  "-g", "Killed process|Out of memory"])
    state["oom_since"] = int(now)
    if rc == 0 and out and "No entries" not in out:
        victims = sorted(set(re.findall(r"\(([^)]+)\)", out)))[:5]
        event("oom", "не хватило памяти, ядро убило процесс(ы): " + (", ".join(victims) or "?"),
              check="oom")

    # 5. Бот на medbot — раз в 5 минут.
    if now - state.get("medbot_at", 0) >= MEDBOT_EVERY:
        state["medbot_at"] = now
        rc, out = sh(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "medbot-ops", "status"],
                     timeout=30)
        if rc != 0:
            state["medbot_fail"] = state.get("medbot_fail", 0) + 1
            report["бот"] = f"medbot не отвечает ({state['medbot_fail']})"
            if state["medbot_fail"] == 3:
                event("down", "medbot не отвечает по SSH уже 15 минут — бот, скорее всего, "
                      "тоже недоступен", check="medbot")
        else:
            if state.get("medbot_fail", 0) >= 3:
                event("recovered", "medbot снова на связи", check="medbot")
            state["medbot_fail"] = 0
            if re.search(r"бот:\s+active", out):
                report["бот"] = "работает"
            else:
                rc2, _ = sh(["ssh", "-o", "BatchMode=yes", "medbot-ops", "restart"], timeout=60)
                report["бот"] = "перезапущен" if rc2 == 0 else "ЛЕЖИТ"
                event("restarted" if rc2 == 0 else "down",
                      "бот на medbot не работал — " + ("перезапущен" if rc2 == 0 else "перезапуск не помог"),
                      check="bot")

    # 6. Списки в генераторе подписок — раз в 6 часов.
    if now - state.get("health_at", 0) >= HEALTH_EVERY:
        state["health_at"] = now
        try:
            # Свой User-Agent: стандартный Python-urllib Cloudflare отбивает 403.
            req = urllib.request.Request(HEALTH_URL, headers={"User-Agent": "vpn-watchdog/1.0"})
            with urllib.request.urlopen(req, timeout=20) as answer:
                health = json.loads(answer.read().decode())
            bad = [name for name in ("domains", "cidr") if health.get(name, {}).get("source") != "live"]
            bad += [b["url"].split("/")[2] for b in health.get("blocked", []) if b.get("source") != "live"]
            report["списки"] = "свежие" if not bad else "запасные: " + ", ".join(bad)
            if bad:
                tight("lists", "генератор подписок не смог обновить списки (" + ", ".join(bad)
                      + ") и раздаёт запасные. VPN работает, но часть российского может "
                      "идти через сервер")
        except (OSError, ValueError) as exc:
            report["списки"] = f"не проверить: {exc}"

    state["report"] = report
    state["checked_at"] = now
    save_state(state)


# --- Команды ------------------------------------------------------------------

def cmd_events(since: float, as_json: bool) -> None:
    rows = []
    if EVENTS_FILE.exists():
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
    if not rows:
        print("событий нет")
    for r in rows[-50:]:
        print(f"{time.strftime('%d.%m %H:%M', time.localtime(r['t']))}  {r['kind']:<10} {r['text']}")


def cmd_status() -> None:
    state = load_state()
    if not state.get("checked_at"):
        print("сторож здоровья ещё не делал проходов")
        return
    print(f"последний проход: {int(time.time() - state['checked_at'])} с назад")
    for key, value in state.get("report", {}).items():
        print(f"  {key:<16} {value}")


def cmd_install() -> None:
    me = os.path.realpath(__file__)
    Path("/etc/systemd/system/vpn-watchdog.service").write_text(f"""[Unit]
Description=Сторож здоровья VPN-сервера (один проход)
After=network-online.target docker.service

[Service]
Type=oneshot
ExecStart={me} check
TimeoutStartSec=240
""")
    Path("/etc/systemd/system/vpn-watchdog.timer").write_text("""[Unit]
Description=Сторож здоровья VPN-сервера раз в минуту

[Timer]
OnBootSec=2min
OnUnitActiveSec=1min
AccuracySec=10s

[Install]
WantedBy=timers.target
""")
    sh(["systemctl", "daemon-reload"])
    rc, out = sh(["systemctl", "enable", "--now", "vpn-watchdog.timer"])
    print("таймер включён" if rc == 0 else f"не вышло: {out}")


if __name__ == "__main__":
    args = sys.argv[1:] or ["status"]
    if args[0] == "check":
        check()
    elif args[0] == "events":
        since = float(args[args.index("--since") + 1]) if "--since" in args else 0.0
        cmd_events(since, "--json" in args)
    elif args[0] == "status":
        cmd_status()
    elif args[0] == "install":
        cmd_install()
    else:
        raise SystemExit(__doc__)
