#!/bin/bash
# Установка зеркала подписок на VPN-сервере.
#
#   ./sub-mirror-install.sh sub2.example.net https://sub.example.net
#
# Первый аргумент — имя, по которому зеркало будет открываться у людей.
# Второй — адрес воркера, у которого зеркало берёт содержимое.
#
# До запуска нужна DNS-запись: CNAME <имя> -> vpn.<домен>, БЕЗ Cloudflare
# (серое облако). CNAME, а не A: тогда при ротации адреса имя уезжает следом
# само, и ничего обновлять не надо.
set -euo pipefail

HOST="${1:?укажите имя: ./sub-mirror-install.sh sub2.example.net https://sub.example.net}"
UPSTREAM="${2:?укажите адрес воркера вторым аргументом}"
PORT="${PORT:-8443}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

say()  { printf '\033[1;32m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m /!\\\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m!!!\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || die "нужен root"

# --- проверки до того, как что-то менять ------------------------------------

say "проверяю, куда указывает $HOST"
MY_IP=$(curl -fsS --max-time 10 https://api.ipify.org || true)
[ -n "$MY_IP" ] || die "не удалось узнать собственный адрес"
HOST_IP=$(getent ahostsv4 "$HOST" | awk 'NR==1{print $1}' || true)
[ -n "$HOST_IP" ] || die "$HOST не резолвится — создайте CNAME на vpn-домен, серым облаком"
[ "$HOST_IP" = "$MY_IP" ] || die "$HOST указывает на $HOST_IP, а сервер — $MY_IP.
Если запись только что создана, подождите минуту. Если она оранжевая в
Cloudflare — переключите на серую: зеркало существует как раз чтобы обойти
Cloudflare, и проксировать его через него бессмысленно."
say "$HOST -> $HOST_IP, это мы"

say "проверяю, что воркер отвечает"
curl -fsS --max-time 15 -o /dev/null "$UPSTREAM/" || die "$UPSTREAM не отвечает"

ss -tlnH "sport = :80" | grep -q . && die "порт 80 занят, а он нужен для выпуска сертификата"
ss -tlnH "sport = :$PORT" | grep -q . && die "порт $PORT занят"

# --- настройки --------------------------------------------------------------

say "записываю настройки"
install -d -m 755 /opt/panel
cat > /opt/panel/sub-mirror.env <<EOF
UPSTREAM=$UPSTREAM
HOSTNAME=$HOST
PORT=$PORT
EOF
chmod 644 /opt/panel/sub-mirror.env
# Скрипт могут запускать и из репозитория, и уже из /opt/panel — во втором
# случае копировать нечего, и install ругнулся бы на файл сам в себя.
if [ "$(readlink -f "$HERE/sub-mirror.py")" != "$(readlink -f /opt/panel/sub-mirror.py)" ]; then
    install -m 755 "$HERE/sub-mirror.py" /opt/panel/sub-mirror.py
else
    chmod 755 /opt/panel/sub-mirror.py
fi
install -d -m 750 /var/cache/sub-mirror

say "проверяю связь с воркером глазами зеркала"
/opt/panel/sub-mirror.py selftest

# --- сертификат -------------------------------------------------------------

if [ -f "/etc/letsencrypt/live/$HOST/fullchain.pem" ]; then
    say "сертификат для $HOST уже есть"
else
    if ! command -v certbot >/dev/null; then
        say "ставлю certbot"
        DEBIAN_FRONTEND=noninteractive apt-get update -qq
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq certbot >/dev/null
    fi
    say "выпускаю сертификат Let's Encrypt (порт 80)"
    certbot certonly --standalone --non-interactive --agree-tos \
        --register-unsafely-without-email -d "$HOST" \
        || die "сертификат не выпустился.
Частая причина — закрытый снаружи порт 80: проверьте фаервол UpCloud,
Let's Encrypt должен достучаться до этого сервера на 80."
fi

# --- служба -----------------------------------------------------------------

say "ставлю службу"
cat > /etc/systemd/system/sub-mirror.service <<EOF
[Unit]
Description=Зеркало подписок VPN
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/opt/panel/sub-mirror.py serve
Restart=always
RestartSec=5
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/cache/sub-mirror
ReadOnlyPaths=/etc/letsencrypt

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now sub-mirror.service >/dev/null
sleep 2
systemctl is-active --quiet sub-mirror.service || {
    journalctl -u sub-mirror.service -n 20 --no-pager
    die "служба не поднялась"
}

# --- проверка ---------------------------------------------------------------

say "проверяю снаружи"
PROBE="00000000-0000-4000-8000-000000000000"
CODE=$(curl -fsS --max-time 20 -o /tmp/sub-mirror-check.json -w '%{http_code}' \
    "https://$HOST:$PORT/sub/$PROBE" || true)
[ "$CODE" = "200" ] || die "зеркало ответило $CODE — смотрите journalctl -u sub-mirror"
python3 -c '
import json, sys
cfg = json.load(open("/tmp/sub-mirror-check.json"))
rule = [r for r in cfg["route"]["rules"] if r.get("outbound") == "direct" and r.get("domain_suffix")][0]
print("  российских имён:", len(rule["domain"]) + len(rule["domain_suffix"]))
print("  IP-зон:", len(rule["ip_cidr"]))
print("  сервер:", [o for o in cfg["outbounds"] if o["tag"] == "proxy"][0]["server"])
' || die "зеркало отдало не конфиг"
rm -f /tmp/sub-mirror-check.json

echo
say "готово"
echo "Страница для людей:  https://$HOST:$PORT/"
echo "Подписка:            https://$HOST:$PORT/sub/<uuid>"
echo
echo "Укажите этот адрес боту: ⚙️ Настройки → Генератор подписок →"
echo "  https://$HOST:$PORT"
