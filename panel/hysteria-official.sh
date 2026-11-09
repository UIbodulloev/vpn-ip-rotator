#!/bin/bash
# Hysteria2 на официальном сервере + сторож устройств.
#
#   hysteria-official.sh install     поставить и переключить (обрыв Hysteria2 ~2 с)
#   hysteria-official.sh rollback    вернуть Hysteria2 на sing-box как было
#   hysteria-official.sh status
#
# Зачем менять сервер. Протокол тот же, клиенты и подписки не меняются: тот же
# порт, пароль (UUID), obfs и сертификат. Но у официального сервера есть то,
# чего нет у sing-box:
#   * проверка входа внешней службой (auth: http). Через неё сторож устройств
#     отказывает второму устройству по ключу, а новые ключи начинают работать
#     сразу — без перезапуска сервера, который рвал сессии всем при каждой
#     выдаче и отзыве ключа;
#   * API статистики: кто онлайн, по каким соединениям идут данные, разрыв
#     сессий ключа.
#
# Откат автоматический: не поднялся новый сервер — возвращается sing-box.
set -euo pipefail

VERSION="app/v2.13.0"
BASE="https://github.com/apernet/hysteria/releases/download/${VERSION}"
BIN=/usr/local/bin/hysteria
CONF_DIR=/etc/hysteria
CONF=$CONF_DIR/config.yaml
HY2_ENV=/opt/panel/hysteria2.env
GUARD_ENV=/opt/panel/device-guard.env
GUARD=/opt/panel/device-guard.py
HOOK=/etc/letsencrypt/renewal-hooks/deploy/hysteria-restart

say()  { printf '\033[1;32m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m /!\\\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m!!!\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || die "нужен root"
[ -f "$HY2_ENV" ] || die "нет $HY2_ENV — Hysteria2 здесь не настроен"
get() { grep -m1 "^$1=" "$HY2_ENV" | cut -d= -f2-; }
PORT=$(get PORT); OBFS=$(get OBFS_PASSWORD); DOMAIN=$(get DOMAIN)
[ -n "$PORT" ] && [ -n "$OBFS" ] && [ -n "$DOMAIN" ] || die "в $HY2_ENV нужны PORT, OBFS_PASSWORD, DOMAIN"
LIVE=/etc/letsencrypt/live/$DOMAIN

listening() { ss -ulnp | grep -q ":$PORT .*$1"; }

install_binary() {
    local tmp; tmp=$(mktemp -d)
    say "скачиваю hysteria ${VERSION#app/}"
    curl -fsSL --max-time 120 -o "$tmp/hysteria-linux-amd64" "$BASE/hysteria-linux-amd64"
    curl -fsSL --max-time 30 -o "$tmp/hashes.txt" "$BASE/hashes.txt"
    local want got
    want=$(grep -E ' (build/)?hysteria-linux-amd64$' "$tmp/hashes.txt" | awk '{print $1}')
    got=$(sha256sum "$tmp/hysteria-linux-amd64" | awk '{print $1}')
    [ -n "$want" ] && [ "$want" = "$got" ] || die "контрольная сумма не сошлась ($got ≠ $want)"
    install -m 0755 "$tmp/hysteria-linux-amd64" "$BIN"
    rm -rf "$tmp"
    say "контрольная сумма сошлась: $("$BIN" version 2>/dev/null | grep -m1 -i version || echo ok)"
}

write_config() {
    local secret="$1"
    mkdir -p "$CONF_DIR"
    umask 077
    cat > "$CONF" <<EOF
# Создано hysteria-official.sh. Пользователей здесь нет: каждый вход
# проверяет device-guard по живому списку ключей панели.
listen: :$PORT

tls:
  cert: $LIVE/fullchain.pem
  key: $LIVE/privkey.pem

obfs:
  type: salamander
  salamander:
    password: $OBFS

auth:
  type: http
  http:
    url: http://127.0.0.1:8899/auth

# Как было и в sing-box: полосу не объявляем, работает BBR.
ignoreClientBandwidth: true

# Окна QUIC с запасом под мобильные 50–100 Мбит/с при задержке до 100 мс.
quic:
  initStreamReceiveWindow: 8388608
  maxStreamReceiveWindow: 16777216
  initConnReceiveWindow: 20971520
  maxConnReceiveWindow: 41943040
  maxIdleTimeout: 30s

masquerade:
  type: proxy
  proxy:
    url: https://www.googletagmanager.com
    rewriteHost: true

trafficStats:
  listen: 127.0.0.1:8898
  secret: $secret
EOF
    chmod 600 "$CONF"
}

write_units() {
    cat > /etc/systemd/system/device-guard.service <<'EOF'
[Unit]
Description=Сторож устройств VPN (один ключ — одно устройство)
After=docker.service network-online.target
Wants=network-online.target

[Service]
ExecStart=/opt/panel/device-guard.py serve
Restart=always
RestartSec=2
StateDirectory=device-guard

[Install]
WantedBy=multi-user.target
EOF
    cat > /etc/systemd/system/hysteria-server.service <<EOF
[Unit]
Description=Hysteria2 (официальный сервер)
After=network-online.target device-guard.service
Wants=network-online.target device-guard.service

[Service]
ExecStart=$BIN server -c $CONF
Restart=always
RestartSec=3
LimitNOFILE=1048576
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadOnlyPaths=/etc/letsencrypt $CONF_DIR

[Install]
WantedBy=multi-user.target
EOF
    # Сертификат продлевается раз в два месяца — перечитываем его перезапуском.
    mkdir -p "$(dirname "$HOOK")"
    printf '#!/bin/sh\nsystemctl is-active --quiet hysteria-server && systemctl restart hysteria-server || true\n' > "$HOOK"
    chmod 755 "$HOOK"
    systemctl daemon-reload
}

cmd_install() {
    [ -x "$GUARD" ] || die "нет $GUARD — сначала положите device-guard.py"
    [ -f "$LIVE/fullchain.pem" ] || die "нет сертификата $LIVE"
    [ -x "$BIN" ] && "$BIN" version 2>/dev/null | grep -q "${VERSION#app/}" || install_binary

    local secret
    secret=$(grep -m1 '^HY2_SECRET=' "$GUARD_ENV" 2>/dev/null | cut -d= -f2- || true)
    [ -n "$secret" ] || secret=$(head -c 24 /dev/urandom | base64 | tr -d '/+=' )
    if [ ! -f "$GUARD_ENV" ]; then
        umask 077
        printf 'MODE=enforce\nDEVICES=1\nBLOCK_MINUTES=30\nAUTH_LISTEN=127.0.0.1:8899\nHY2_API=http://127.0.0.1:8898\nHY2_SECRET=%s\n' "$secret" > "$GUARD_ENV"
    elif ! grep -q '^HY2_SECRET=' "$GUARD_ENV"; then
        printf 'HY2_SECRET=%s\n' "$secret" >> "$GUARD_ENV"
    fi
    write_config "$secret"
    write_units

    say "запускаю сторож"
    systemctl enable --now device-guard >/dev/null 2>&1
    sleep 2
    systemctl is-active --quiet device-guard || die "сторож не запустился: journalctl -u device-guard"
    curl -fsS -m 3 -X POST -d '{"addr":"127.0.0.1:1","auth":"проверка","tx":0}' \
        http://127.0.0.1:8899/auth | grep -q '"ok": false' || die "сторож не отвечает на проверку входа"

    say "переключаю Hysteria2: sing-box → официальный сервер"
    systemctl disable --now sing-box >/dev/null 2>&1 || true
    systemctl enable --now hysteria-server >/dev/null 2>&1 || true
    for _ in 1 2 3 4 5 6 7 8 9 10; do listening hysteria && break; sleep 0.5; done
    if ! listening hysteria; then
        warn "официальный сервер не поднялся, возвращаю sing-box"
        journalctl -u hysteria-server -n 15 --no-pager >&2 || true
        systemctl disable --now hysteria-server >/dev/null 2>&1 || true
        systemctl enable --now sing-box >/dev/null 2>&1
        die "откат выполнен, Hysteria2 снова на sing-box"
    fi
    say "Hysteria2 слушает UDP $PORT, вход проверяет сторож"
    "$GUARD" selftest || true
}

cmd_rollback() {
    systemctl disable --now hysteria-server >/dev/null 2>&1 || true
    systemctl enable --now sing-box >/dev/null 2>&1
    /opt/panel/hy2-sync.py || true
    say "Hysteria2 снова на sing-box. Сторож продолжает следить за VLESS."
}

cmd_status() {
    for unit in hysteria-server device-guard sing-box; do
        printf '%-16s %s\n' "$unit" "$(systemctl is-active "$unit" 2>/dev/null || true)"
    done
    ss -ulnp | grep ":$PORT " || echo "на UDP $PORT никто не слушает"
}

case "${1:-status}" in
    install)  cmd_install ;;
    rollback) cmd_rollback ;;
    status)   cmd_status ;;
    *) die "команды: install | rollback | status" ;;
esac
