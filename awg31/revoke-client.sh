#!/bin/bash
# Отзыв клиента AmneziaWG 3.1: убирает пира из живого интерфейса и из конфига.
set -euo pipefail

NAME="${1:?укажите имя клиента}"
# Имя приходит из Telegram — строго ограничиваем набор символов.
[[ "$NAME" =~ ^[A-Za-z0-9_-]{1,32}$ ]] || { echo "недопустимое имя: только латиница, цифры, дефис и подчёркивание"; exit 2; }

DIR=/opt/awg31
CONF=$DIR/awg1.conf
FILE=$DIR/clients/$NAME.conf
[ -f "$FILE" ] || { echo "клиента $NAME нет"; exit 1; }

CLIENT_IP=$(grep -m1 '^Address' "$FILE" | grep -oE '[0-9.]+' | head -1)
# Публичный ключ выводим из приватного: в клиентском конфиге хранится только он.
CLI_PUB=$(grep -m1 '^PrivateKey' "$FILE" | cut -d= -f2- | tr -d ' ' | docker exec -i awg31 awg pubkey)

docker exec awg31 awg set awg1 peer "$CLI_PUB" remove
# Из файла убираем блок [Peer] целиком — по адресу, он уникален.
python3 - "$CONF" "$CLIENT_IP" <<'PYEOF'
import re, sys
path, ip = sys.argv[1], sys.argv[2]
text = open(path).read()
# Блок = необязательный комментарий с именем, [Peer] и его строки до пустой строки.
pattern = re.compile(r'\n(?:#[^\n]*\n)?\[Peer\]\n(?:[^\n\[]*\n)*?AllowedIPs = ' + re.escape(ip) + r'/32\n', re.M)
new, n = pattern.subn('\n', text)
if n == 0:
    print("предупреждение: блок в awg1.conf не найден, пир убран только из интерфейса")
open(path, 'w').write(new)
PYEOF

rm -f "$FILE"
echo "отозван: $NAME ($CLIENT_IP)"
