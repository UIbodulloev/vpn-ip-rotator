#!/bin/sh
# Перескок портов для Hysteria2.
#
#   hy2-porthop.sh status
#   hy2-porthop.sh on [диапазон]     по умолчанию 40000-40999
#   hy2-porthop.sh off
#
# Зачем. Сейчас канал висит на одном UDP-порту. Если оператор однажды закроет
# именно его, туннель умрёт целиком. С перескоком клиент рассылает пакеты по
# всему диапазону, а сервер сводит их на рабочий порт — закрыть придётся
# тысячу портов вместо одного.
#
# Цена: правило живёт в nat-таблице и не переживает перезагрузку само.
# Команда on ставит systemd-юнит, который возвращает его при старте.
set -eu

ENV_FILE=/opt/panel/hysteria2.env
CHAIN=PREROUTING
MARK="hy2-porthop"

die() { printf '!!! %s\n' "$*" >&2; exit 1; }
[ -f "$ENV_FILE" ] || die "Hysteria2 не установлен"
PORT=$(grep -m1 '^PORT=' "$ENV_FILE" | cut -d= -f2-)
[ -n "$PORT" ] || die "в $ENV_FILE не задан PORT"

current() {
    iptables -t nat -S "$CHAIN" 2>/dev/null | grep -E "comment --comment \"?$MARK" || true
}

case "${1:-status}" in
status)
    rule=$(current)
    if [ -n "$rule" ]; then
        printf 'перескок включён:\n%s\n' "$rule"
        iptables -t nat -L "$CHAIN" -nv 2>/dev/null | grep "$MARK" | awk '{print "пакетов поймано:", $1}'
    else
        printf 'перескок выключен, канал только на UDP %s\n' "$PORT"
    fi
    systemctl is-enabled hy2-porthop.service 2>/dev/null | sed 's/^/юнит: /' || echo "юнит: не установлен"
    ;;

on)
    RANGE="${2:-40000-40999}"
    case "$RANGE" in
        [0-9]*-[0-9]*) : ;;
        *) die "диапазон в виде 40000-40999" ;;
    esac
    LOW=${RANGE%-*}; HIGH=${RANGE#*-}
    [ "$LOW" -lt "$HIGH" ] || die "начало диапазона должно быть меньше конца"
    [ "$PORT" -lt "$LOW" ] || [ "$PORT" -gt "$HIGH" ] \
        || die "рабочий порт $PORT попадает в диапазон — выберите другой"

    [ -n "$(current)" ] && iptables -t nat -D "$CHAIN" -p udp --dport "$LOW:$HIGH" \
        -m comment --comment "$MARK" -j REDIRECT --to-ports "$PORT" 2>/dev/null || true
    iptables -t nat -A "$CHAIN" -p udp --dport "$LOW:$HIGH" \
        -m comment --comment "$MARK" -j REDIRECT --to-ports "$PORT"

    cat > /etc/systemd/system/hy2-porthop.service <<EOF
[Unit]
Description=Перескок портов Hysteria2
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/opt/panel/hy2-porthop.sh on $RANGE
ExecStop=/opt/panel/hy2-porthop.sh off

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable hy2-porthop.service >/dev/null 2>&1 || true
    printf 'перескок включён: UDP %s-%s сводятся на %s\n' "$LOW" "$HIGH" "$PORT"
    printf 'теперь допишите в %s строку и перевыпустите подписку:\n' "$ENV_FILE"
    printf '  PORTS=%s:%s\n' "$LOW" "$HIGH"
    ;;

off)
    iptables -t nat -S "$CHAIN" 2>/dev/null | grep "$MARK" | sed 's/^-A /-D /' \
        | while read -r rule; do
            # shellcheck disable=SC2086
            iptables -t nat $rule 2>/dev/null || true
        done
    systemctl disable --now hy2-porthop.service >/dev/null 2>&1 || true
    rm -f /etc/systemd/system/hy2-porthop.service
    systemctl daemon-reload 2>/dev/null || true
    printf 'перескок выключен, уберите строку PORTS из %s и перевыпустите подписку\n' "$ENV_FILE"
    ;;

*)
    die "команды: status | on [диапазон] | off"
    ;;
esac
