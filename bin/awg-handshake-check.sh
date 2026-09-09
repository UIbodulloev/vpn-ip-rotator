#!/usr/bin/env bash
# Проба уровня 2 для AmneziaWG: настоящий хендшейк, а не голый TCP.
#
# Смысл: если ТСПУ ловит фингерпринт, порт остаётся открытым, а сессия не встаёт.
# Отличить это можно только реальным подключением.
#
# Подготовка на РФ-сервере (один раз):
#   1. поставьте amneziawg-tools и amneziawg (или amneziawg-go);
#   2. заведите отдельный клиентский конфиг /etc/amnezia/amneziawg/probe0.conf
#      с AllowedIPs = 10.8.1.1/32 — тогда проба не перехватывает ваш трафик;
#   3. в config.toml: awg_probe_cmd = "/opt/vpn-rotator/bin/awg-handshake-check.sh probe0"
#
# Код 0 — хендшейк свежий, связь есть. Иначе — ненулевой.
set -euo pipefail

IFACE="${1:-probe0}"
MAX_AGE="${2:-180}"     # хендшейк считается живым, если он моложе стольких секунд

command -v awg >/dev/null || { echo "awg не установлен" >&2; exit 3; }

if ! awg show "$IFACE" >/dev/null 2>&1; then
    awg-quick up "$IFACE" >/dev/null 2>&1 || { echo "не поднялся $IFACE" >&2; exit 4; }
    trap 'awg-quick down "$IFACE" >/dev/null 2>&1 || true' EXIT
    sleep 5
fi

# Подтолкнуть хендшейк: без трафика он не инициируется.
ping -c1 -W3 -I "$IFACE" 10.8.1.1 >/dev/null 2>&1 || true
sleep 3

LATEST=$(awg show "$IFACE" latest-handshakes | awk '{print $2}' | sort -rn | head -1)
[[ -n "$LATEST" && "$LATEST" != "0" ]] || { echo "хендшейка не было" >&2; exit 1; }

AGE=$(( $(date +%s) - LATEST ))
if (( AGE > MAX_AGE )); then
    echo "последний хендшейк ${AGE} с назад — связи нет" >&2
    exit 1
fi
echo "хендшейк ${AGE} с назад"
