#!/usr/bin/env python3
"""Список AllowedIPs «весь интернет, кроме российского».

    split-tunnel.py                 напечатать строку AllowedIPs
    split-tunnel.py --stats         показать, во что обошлась точность

У WireGuard нет маршрутизации по именам сайтов — только по адресам. Поэтому
белые списки здесь делаются наоборот, чем в подписке: не «российское мимо
туннеля», а «в туннель всё, кроме российского». Результат тот же, запись
другая.

Почему не все 1410 российских зон: мелкие блоки раскалывают адресное
пространство, и дополнение к ним разрастается до десяти тысяч строк — такой
конфиг телефон переварит, а роутер может и нет. Блоки /18 и крупнее покрывают
98% российских адресов и дают около восьмисот строк. Остальные два процента —
мелкие сети, через VPN они работать не перестанут, просто пойдут не напрямую.

Источник тот же, что у подписки: russia.iplist.opencck.org.
"""
from __future__ import annotations

import ipaddress
import sys
import time
import urllib.request
from pathlib import Path

SOURCE = "https://russia.iplist.opencck.org/?format=text&data=cidr4"
CACHE = Path("/var/cache/awg31/ru-cidr4.txt")
CACHE_TTL = 86400.0
MIN_PREFIX = 18          # блоки крупнее этого; меньше — не берём
MERGE_GAP = 1024         # промежутки короче — приклеиваем, чтобы не дробить
DNS_INSIDE = "172.29.172.254/32"   # резолвер живёт в туннеле, его нельзя терять

# Служебное и локальное — мимо туннеля, иначе отвалятся роутер и принтер.
LOCAL = ("0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
         "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16",
         "224.0.0.0/4", "240.0.0.0/4")


def ru_networks() -> list[ipaddress.IPv4Network]:
    """Российские зоны. Источник недоступен — берём вчерашнюю копию:
    устаревший список лучше, чем сорванная выдача конфига."""
    fresh = CACHE.exists() and time.time() - CACHE.stat().st_mtime < CACHE_TTL
    if not fresh:
        try:
            with urllib.request.urlopen(SOURCE, timeout=30) as answer:
                CACHE.parent.mkdir(parents=True, exist_ok=True)
                CACHE.write_bytes(answer.read())
        except Exception as exc:                                   # noqa: BLE001
            if not CACHE.exists():
                raise SystemExit(f"список российских сетей недоступен: {exc}") from None
            print(f"предупреждение: источник недоступен ({exc}), беру копию из кэша",
                  file=sys.stderr)
    out = []
    for line in CACHE.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            net = ipaddress.ip_network(line, strict=False)
        except ValueError:
            continue
        if isinstance(net, ipaddress.IPv4Network) and net.prefixlen <= MIN_PREFIX:
            out.append(net)
    if len(out) < 50:
        raise SystemExit("список подозрительно короткий — не рискую выдавать конфиг")
    return out


def complement(blocks) -> list[ipaddress.IPv4Network]:
    blocks = sorted(ipaddress.collapse_addresses(blocks),
                    key=lambda n: int(n.network_address))
    gaps, cursor = [], 0
    for net in blocks:
        start, end = int(net.network_address), int(net.broadcast_address)
        if start - cursor > MERGE_GAP:
            gaps += ipaddress.summarize_address_range(
                ipaddress.IPv4Address(cursor), ipaddress.IPv4Address(start - 1))
        cursor = max(cursor, end + 1)
    if 0xFFFFFFFF - cursor > MERGE_GAP:
        gaps += ipaddress.summarize_address_range(
            ipaddress.IPv4Address(cursor), ipaddress.IPv4Address(0xFFFFFFFF))
    return list(ipaddress.collapse_addresses(gaps))


def main() -> None:
    ru = ru_networks()
    excluded = ru + [ipaddress.ip_network(n) for n in LOCAL]
    allowed = complement(excluded)
    line = ", ".join(str(n) for n in allowed) + ", " + DNS_INSIDE

    if "--stats" in sys.argv:
        covered = sum(n.num_addresses for n in ipaddress.collapse_addresses(ru))
        print(f"российских зон взято: {len(ru)} (блоки /{MIN_PREFIX} и крупнее)")
        print(f"покрыто адресов:      {covered:,}")
        print(f"строк в AllowedIPs:   {len(allowed) + 1}")
        print(f"размер строки:        {len(line) / 1024:.1f} КБ")
        return
    print(line)


if __name__ == "__main__":
    main()
