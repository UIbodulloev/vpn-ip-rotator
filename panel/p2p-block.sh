#!/bin/sh
# Блокировка BitTorrent для клиентов VPN.
#
#   p2p-block.sh on       включить
#   p2p-block.sh off      выключить
#   p2p-block.sh status   показать состояние и счётчики
#
# Зачем: жалобы правообладателей приходят владельцу IP — UpCloud, а он вправе
# приостановить сервер. Блокировка снижает риск, но НЕ устраняет его: клиенты
# BitTorrent умеют шифровать протокол (MSE/PE), и тогда сигнатуры не видны.
# Честная оценка — ловятся клиенты с настройками по умолчанию, не все.
#
# Правила висят в отдельной цепочке P2PBLOCK, поэтому off убирает их начисто,
# ничего больше не задевая.
set -eu

CHAIN=P2PBLOCK
UNIT=/etc/systemd/system/p2p-block.service

hook_in() {
    # DOCKER-USER — трафик клиентов WG (его форвардит docker), OUTPUT — то,
    # что xray отправляет от имени самого хоста.
    for parent in DOCKER-USER OUTPUT; do
        iptables -C "$parent" -j "$CHAIN" 2>/dev/null || iptables -I "$parent" 1 -j "$CHAIN"
    done
}

hook_out() {
    for parent in DOCKER-USER OUTPUT; do
        while iptables -C "$parent" -j "$CHAIN" 2>/dev/null; do
            iptables -D "$parent" -j "$CHAIN"
        done
    done
}

on() {
    iptables -N "$CHAIN" 2>/dev/null || iptables -F "$CHAIN"
    # Рукопожатие BitTorrent — первые байты каждого peer-соединения.
    iptables -A "$CHAIN" -m string --algo bm --string "BitTorrent protocol" -j DROP
    # Запросы DHT: поиск пиров без трекера.
    iptables -A "$CHAIN" -m string --algo bm --string "d1:ad2:id20:" -j DROP
    iptables -A "$CHAIN" -m string --algo bm --string "get_peers"     -j DROP
    iptables -A "$CHAIN" -m string --algo bm --string "announce_peer" -j DROP
    # Обращение к HTTP-трекеру.
    iptables -A "$CHAIN" -m string --algo bm --string "info_hash="    -j DROP
    iptables -A "$CHAIN" -j RETURN
    hook_in

    cat > "$UNIT" <<UNITEOF
[Unit]
Description=Блокировка BitTorrent для клиентов VPN
After=docker.service
Requires=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/opt/panel/p2p-block.sh on

[Install]
WantedBy=multi-user.target
UNITEOF
    systemctl daemon-reload
    systemctl enable p2p-block.service >/dev/null 2>&1 || true
    echo "включено (и переживёт перезагрузку)"
}

off() {
    hook_out
    iptables -F "$CHAIN" 2>/dev/null || true
    iptables -X "$CHAIN" 2>/dev/null || true
    systemctl disable p2p-block.service >/dev/null 2>&1 || true
    rm -f "$UNIT"
    systemctl daemon-reload 2>/dev/null || true
    echo "выключено, правила убраны"
}

status() {
    if iptables -L "$CHAIN" -n >/dev/null 2>&1; then
        echo "состояние: ВКЛЮЧЕНО"
        echo
        echo "сколько пакетов отброшено по каждому признаку:"
        iptables -L "$CHAIN" -n -v -x | sed 1d
    else
        echo "состояние: выключено"
    fi
}

case "${1:-status}" in
    on)     on ;;
    off)    off ;;
    status) status ;;
    *)      echo "использование: $0 on|off|status" >&2; exit 2 ;;
esac
