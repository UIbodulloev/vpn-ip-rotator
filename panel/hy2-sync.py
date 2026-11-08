#!/usr/bin/env python3
"""Пользователи Hysteria2 — из той же панели, что и VLESS.

    hy2-sync.py            пересобрать конфиг и перезапустить службу
    hy2-sync.py --dry-run  показать, что получится, ничего не трогая

Источник правды один — панель 3x-ui. Пароль у человека совпадает с его UUID
в VLESS, поэтому выдавать и отзывать доступ по-прежнему можно одной командой
client.py, а здесь только отражается результат.

Настройки — /opt/panel/hysteria2.env:
    PORT=39443
    OBFS_PASSWORD=…        общий для всех: прячет сам протокол, не пускает внутрь
    DOMAIN=vpn.example.net сертификат берётся из /etc/letsencrypt/live/<DOMAIN>
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ENV_FILE = Path("/opt/panel/hysteria2.env")
CONFIG = Path("/etc/sing-box/config.json")
SERVICE = "sing-box"
CLIENT_PY = "/opt/panel/client.py"


def env() -> dict[str, str]:
    out: dict[str, str] = {}
    if not ENV_FILE.exists():
        raise SystemExit(f"нет {ENV_FILE} — сначала hysteria2-install.sh")
    for line in ENV_FILE.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, _, v = line.partition("=")
            out[k.strip()] = v.strip()
    for required in ("PORT", "OBFS_PASSWORD", "DOMAIN"):
        if not out.get(required):
            raise SystemExit(f"в {ENV_FILE} не задан {required}")
    return out


def clients() -> list[tuple[str, str]]:
    """Имя и UUID каждого клиента панели. UUID он же пароль Hysteria2."""
    done = subprocess.run([CLIENT_PY, "list"], capture_output=True, text=True, timeout=60)
    if done.returncode != 0:
        raise SystemExit(f"панель не ответила: {done.stderr.strip()[:200]}")
    out = []
    for line in done.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) == 4:
            out.append((parts[0], parts[1]))
    return out


def build(cfg: dict[str, str], people: list[tuple[str, str]]) -> dict:
    live = Path(f"/etc/letsencrypt/live/{cfg['DOMAIN']}")
    brutal = bool(cfg.get("UP_MBPS")) and bool(cfg.get("DOWN_MBPS"))
    return {
        "log": {"level": "warn", "timestamp": True},
        "inbounds": [{
            "type": "hysteria2",
            "tag": "hy2-in",
            "listen": "::",
            "listen_port": int(cfg["PORT"]),
            "users": [{"name": name, "password": uuid} for name, uuid in people],
            # По умолчанию BBR: ядро само подстраивается под потери. Если в
            # hysteria2.env заданы UP_MBPS/DOWN_MBPS, клиент объявляет полосу и
            # включается Brutal — он держит её, игнорируя потери. На дёрганой
            # соте это быстрее, но объявленная цифра становится и потолком, и
            # обязательством: больше не разгонится, меньше — зальёт канал.
            "ignore_client_bandwidth": not brutal,
            # Salamander превращает QUIC в случайный UDP. Это и есть главный
            # смысл всей затеи: у оператора душится TCP, а бесформенный UDP
            # проходит — ровно как AmneziaWG на своём порту.
            "obfs": {"type": "salamander", "password": cfg["OBFS_PASSWORD"]},
            # Кто всё-таки достучится без obfs, увидит обычный сайт, а не ошибку.
            "masquerade": "https://www.googletagmanager.com",
            "tls": {
                "enabled": True,
                "server_name": cfg["DOMAIN"],
                "certificate_path": str(live / "fullchain.pem"),
                "key_path": str(live / "privkey.pem"),
            },
        }],
        "outbounds": [{"type": "direct"}],
    }


def main() -> None:
    cfg = env()
    people = clients()
    if not people:
        print("в панели нет клиентов — конфиг без пользователей не имеет смысла", file=sys.stderr)
    config = build(cfg, people)
    text = json.dumps(config, ensure_ascii=False, indent=2) + "\n"

    if "--dry-run" in sys.argv:
        print(text)
        return

    if CONFIG.exists() and CONFIG.read_text() == text:
        print(f"без изменений: {len(people)} пользователь(ей)")
        return

    CONFIG.parent.mkdir(parents=True, exist_ok=True)
    CONFIG.write_text(text)
    CONFIG.chmod(0o600)
    # Перезапуск рвёт живые сессии на секунду. Это заметно меньшее зло, чем
    # ключ, который выдан и не работает до следующей перезагрузки.
    done = subprocess.run(["systemctl", "restart", SERVICE], capture_output=True, text=True)
    if done.returncode != 0:
        raise SystemExit(f"служба {SERVICE} не перезапустилась: {done.stderr.strip()[:300]}")
    print(f"Hysteria2: {len(people)} пользователь(ей), служба перезапущена")


if __name__ == "__main__":
    main()
