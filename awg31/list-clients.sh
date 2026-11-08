#!/bin/bash
# Список клиентов AmneziaWG 3.1: name<TAB>ip<TAB>трафик<TAB>последнее рукопожатие.
#
# Трафик — сумма принятого и отданного с момента последнего старта интерфейса:
# счётчики живут в ядре, а не на диске, поэтому перезапуск контейнера их
# обнуляет. Это не биллинг, а ответ на вопрос «этим ключом вообще пользуются?».
set -euo pipefail
DIR=/opt/awg31
[ -d "$DIR/clients" ] || { echo "нет выпущенных клиентов"; exit 0; }

NOW=$(date +%s)
# Соответствие публичный ключ -> имя берём из клиентских конфигов.
declare -A NAME_BY_IP
for f in "$DIR"/clients/*.conf; do
    [ -e "$f" ] || continue
    ip=$(grep -m1 '^Address' "$f" | grep -oE '[0-9.]+' | head -1)
    NAME_BY_IP["$ip"]=$(basename "$f" .conf)
done

human() {
    awk -v n="${1:-0}" 'BEGIN {
        split("Б КБ МБ ГБ ТБ", u, " ")
        i = 1
        while (n >= 1024 && i < 5) { n /= 1024; i++ }
        printf (i == 1 ? "%.0f%s" : "%.1f%s"), n, u[i]
    }'
}

ago() {
    awk -v s="$1" 'BEGIN {
        if (s < 90)        printf "%ds назад", s
        else if (s < 5400) printf "%dмин назад", s / 60
        else if (s < 86400 * 2) printf "%dч назад", s / 3600
        else               printf "%dд назад", s / 86400
    }'
}

docker exec awg31 awg show awg1 dump 2>/dev/null | tail -n +2 | while IFS=$'\t' read -r pub psk endpoint ips handshake rx tx keep; do
    ip=${ips%%/*}
    name=${NAME_BY_IP[$ip]:-"(без конфига)"}
    if [ "${handshake:-0}" -gt 0 ]; then
        seen=$(ago $(( NOW - handshake )))
    else
        seen="не подключался"
    fi
    printf '%s\t%s\t%s\t%s\n' "$name" "$ip" "$(human $(( ${rx:-0} + ${tx:-0} )))" "$seen"
done
