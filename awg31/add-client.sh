#!/bin/bash
# Выпуск клиентского конфига AmneziaWG 3.1.
#
#   /opt/awg31/add-client.sh keenetic-home
#
# Параметры обфускации у клиента и сервера должны совпадать байт в байт, поэтому
# они берутся из одного файла obfuscation.conf, а не дублируются руками.
set -euo pipefail

NAME="${1:?укажите имя клиента: add-client.sh keenetic-home [split]}"
MODE="${2:-full}"        # full — весь трафик в туннель; split — кроме российского
# Имя может прийти из Telegram — строго ограничиваем набор символов.
[[ "$NAME" =~ ^[A-Za-z0-9_-]{1,32}$ ]] || { echo "недопустимое имя: только латиница, цифры, дефис и подчёркивание"; exit 2; }
DIR=/opt/awg31
CONF=$DIR/awg1.conf
CONTAINER=awg31
# Домен берём оттуда же, откуда его берут VLESS и подписка, — один источник
# правды. Иначе копия скрипта из репозитория затирает рабочий домен примером,
# и конфиги уходят людям с мёртвым адресом.
PARAMS=/opt/panel/reality-params.env
if [ -z "${ENDPOINT_HOST:-}" ] && [ -f "$PARAMS" ]; then
    ENDPOINT_HOST=$(grep -m1 '^HOST=' "$PARAMS" | cut -d= -f2- | tr -d ' ')
fi
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
  if [ "$MODE" = "split" ]; then
      # Российские адреса идут мимо туннеля — банки и Госуслуги видят домашний
      # адрес. IPv6 целиком оставляем в туннеле: списка российских сетей для
      # него нет, и дыру лучше закрыть, чем оставить.
      echo "AllowedIPs = $("$DIR/split-tunnel.py"), ::/0"
  else
      echo "AllowedIPs = 0.0.0.0/0, ::/0"
  fi
  echo "Endpoint = $ENDPOINT_HOST:$PORT"
  echo "PersistentKeepalive = 25"
} > "$OUT"
chmod 600 "$OUT"

if [ "$MODE" = "split" ]; then
    echo "готово: $OUT  (адрес в туннеле $CLIENT_IP, российское мимо VPN)"
else
    echo "готово: $OUT  (адрес в туннеле $CLIENT_IP)"
fi
