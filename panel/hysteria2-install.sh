#!/bin/bash
# Hysteria2 на VPN-сервере: туннель по UDP рядом с VLESS.
#
#   ./hysteria2-install.sh vpn.example.net [порт]
#
# Зачем. У мобильных операторов в России душат длинные TCP-соединения к
# иностранным адресам: VLESS подключается и ползёт. UDP при этом проходит —
# AmneziaWG на своём порту работает на полной скорости. Hysteria2 — это QUIC
# поверх UDP, а обфускация salamander превращает его в бесформенный UDP, так
# что для оператора он выглядит как тот же AmneziaWG.
#
# Что это даёт по сравнению с AmneziaWG: та же одна ссылка-подписка, белые
# списки, домен вместо адреса — переезд сервера людей не касается.
#
# Пользователи берутся из панели 3x-ui: пароль человека совпадает с его UUID
# в VLESS. Выдача и отзыв — по-прежнему client.py.
set -euo pipefail

DOMAIN="${1:?укажите домен VPN: ./hysteria2-install.sh vpn.example.net}"
PORT="${2:-39443}"
VER="${SINGBOX_VERSION:-1.14.4}"
BIN=/opt/panel/sing-box
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

say()  { printf '\033[1;32m==>\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m!!!\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || die "нужен root"
case "$PORT" in *[!0-9]*) die "порт — только цифры" ;; esac

# --- проверки до того, как что-то менять ------------------------------------

say "проверяю, куда указывает $DOMAIN"
MY_IP=$(curl -fsS --max-time 10 https://api.ipify.org) || die "не удалось узнать собственный адрес"
HOST_IP=$(getent ahostsv4 "$DOMAIN" | awk 'NR==1{print $1}' || true)
[ "$HOST_IP" = "$MY_IP" ] || die "$DOMAIN указывает на ${HOST_IP:-никуда}, а сервер — $MY_IP"

ss -lnuH "sport = :$PORT" | grep -q . && die "UDP-порт $PORT уже занят"
say "UDP $PORT свободен"

# --- бинарник ---------------------------------------------------------------

if [ -x "$BIN" ] && "$BIN" version 2>/dev/null | grep -q "$VER"; then
    say "sing-box $VER уже на месте"
else
    TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
    URL="https://github.com/SagerNet/sing-box/releases/download/v$VER/sing-box-$VER-linux-amd64.tar.gz"
    say "скачиваю $URL"
    curl -fsSL -o "$TMP/sb.tgz" "$URL" || die "не скачалось — проверьте, что версия v$VER существует"
    tar xzf "$TMP/sb.tgz" -C "$TMP" || die "архив не распаковался"
    FOUND=$(find "$TMP" -name sing-box -type f | head -1)
    [ -n "$FOUND" ] || die "в архиве нет бинарника sing-box"
    chmod 755 "$FOUND"
    # Проверяем ДО установки: сломанный бинарник оставит службу в перезапусках.
    GOT=$("$FOUND" version 2>/dev/null | head -1) || die "скачанный бинарник не запускается"
    say "скачано: $GOT"
    install -m 755 "$FOUND" "$BIN"
fi

# --- сертификат -------------------------------------------------------------

if [ -f "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" ]; then
    say "сертификат для $DOMAIN уже есть"
else
    command -v certbot >/dev/null || {
        say "ставлю certbot"
        DEBIAN_FRONTEND=noninteractive apt-get update -qq
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq certbot >/dev/null
    }
    ss -tlnH "sport = :80" | grep -q . && die "порт 80 занят, а он нужен для выпуска сертификата"
    say "выпускаю сертификат Let's Encrypt для $DOMAIN"
    certbot certonly --standalone --non-interactive --agree-tos \
        --register-unsafely-without-email -d "$DOMAIN" \
        || die "сертификат не выпустился — проверьте, что порт 80 открыт снаружи"
fi

# --- настройки --------------------------------------------------------------

if [ -f /opt/panel/hysteria2.env ]; then
    say "настройки уже есть, пароль обфускации не меняю"
    # shellcheck disable=SC1091
    . /opt/panel/hysteria2.env
    OBFS="$OBFS_PASSWORD"
else
    OBFS=$(openssl rand -base64 24 | tr -d '/+=' | cut -c1-24)
    cat > /opt/panel/hysteria2.env <<EOF
PORT=$PORT
OBFS_PASSWORD=$OBFS
DOMAIN=$DOMAIN
EOF
    chmod 600 /opt/panel/hysteria2.env
    say "сгенерирован пароль обфускации"
fi

if [ "$(readlink -f "$HERE/hy2-sync.py")" != "$(readlink -f /opt/panel/hy2-sync.py)" ]; then
    install -m 755 "$HERE/hy2-sync.py" /opt/panel/hy2-sync.py
else
    chmod 755 /opt/panel/hy2-sync.py
fi

# --- служба -----------------------------------------------------------------

say "ставлю службу"
cat > /etc/systemd/system/sing-box.service <<EOF
[Unit]
Description=Hysteria2 (sing-box)
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=$BIN run -c /etc/sing-box/config.json
Restart=always
RestartSec=5
LimitNOFILE=infinity
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadOnlyPaths=/etc/letsencrypt /etc/sing-box
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload

say "собираю конфиг из клиентов панели"
/opt/panel/hy2-sync.py || die "конфиг не собрался"
systemctl enable --now sing-box >/dev/null
sleep 3
systemctl is-active --quiet sing-box || {
    journalctl -u sing-box -n 20 --no-pager
    die "служба не поднялась"
}

ss -lnuH "sport = :$PORT" | grep -q . || die "служба запущена, но UDP $PORT не слушает"

echo
say "готово"
echo "  UDP-порт:            $PORT"
echo "  пароль обфускации:   $OBFS"
echo
echo "Эти два значения нужны генератору подписок:"
echo "  в subs/deploy.sh — переменные VPN_HY2_PORT и VPN_HY2_OBFS"
