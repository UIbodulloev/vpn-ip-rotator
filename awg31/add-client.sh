#!/bin/bash
# Выпуск клиентского конфига AmneziaWG 3.1.
#
#   /opt/awg31/add-client.sh keenetic-home
#
# Параметры обфускации у клиента и сервера должны совпадать байт в байт, поэтому
# они берутся из одного файла obfuscation.conf, а не дублируются руками.
set -euo pipefail

NAME="${1:?укажите имя клиента: add-client.sh keenetic-home}"
# Имя может прийти из Telegram — строго ограничиваем набор символов.
[[ "$NAME" =~ ^[A-Za-z0-9_-]{1,32}$ ]] || { echo "недопустимое имя: только латиница, цифры, дефис и подчёркивание"; exit 2; }
DIR=/opt/awg31
CONF=$DIR/awg1.conf
CONTAINER=awg31
ENDPOINT_HOST="${ENDPOINT_HOST:-vpn.example.net}"

# shellcheck source=/dev/null
source "$DIR/keys.env"

awg() { docker exec -i "$CONTAINER" awg "$@"; }

# Следующий свободный адрес в подсети.
# `|| true`: при пустом конфиге grep возвращает 1, и pipefail убил бы скрипт.
USED=$(grep -oP 'AllowedIPs = \K[0-9.]+' "$CONF" 2>/dev/null | awk -F. '{print $4}' | sort -n | tail -1 || true)
NEXT=$(( ${USED:-1} + 1 ))
[ "$NEXT" -lt 255 ] || { echo "подсеть $SUBNET.0/24 исчерпана"; exit 1; }
CLIENT_IP="$SUBNET.$NEXT"

CLI_KEY=$(awg genkey)
CLI_PUB=$(printf '%s' "$CLI_KEY" | awg pubkey)
PSK=$(awg genpsk)

# Пир добавляется и в файл, и в живой интерфейс: файл — чтобы пережить перезапуск,
# интерфейс — чтобы клиент заработал сразу.
{
  echo
  echo "# $NAME ($(date +%Y-%m-%d))"
  echo "[Peer]"
  echo "PublicKey = $CLI_PUB"
  echo "PresharedKey = $PSK"
  echo "AllowedIPs = $CLIENT_IP/32"
} >> "$CONF"

printf '%s' "$PSK" > "$DIR/.psk.tmp"
docker cp "$DIR/.psk.tmp" "$CONTAINER:/tmp/psk" >/dev/null
docker exec "$CONTAINER" awg set awg1 peer "$CLI_PUB" preshared-key /tmp/psk allowed-ips "$CLIENT_IP/32"
docker exec "$CONTAINER" rm -f /tmp/psk
rm -f "$DIR/.psk.tmp"

OUT="$DIR/clients/$NAME.conf"
mkdir -p "$DIR/clients"
{
  echo "[Interface]"
  echo "PrivateKey = $CLI_KEY"
  echo "Address = $CLIENT_IP/32"
  echo "DNS = 172.29.172.254"
  cat "$DIR/obfuscation.conf"
  echo
  echo "[Peer]"
  echo "PublicKey = $SRV_PUB"
  echo "PresharedKey = $PSK"
  echo "AllowedIPs = 0.0.0.0/0, ::/0"
  echo "Endpoint = $ENDPOINT_HOST:$PORT"
  echo "PersistentKeepalive = 25"
} > "$OUT"
chmod 600 "$OUT"

echo "готово: $OUT  (адрес в туннеле $CLIENT_IP)"
