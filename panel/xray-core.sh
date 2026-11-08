#!/bin/sh
# Версия ядра Xray внутри контейнера 3x-ui.
#
#   xray-core.sh status
#   xray-core.sh pin 26.6.27
#   xray-core.sh restore
#
# Зачем. С Xray 26.9.8 сервер REALITY отвергает ClientHello, в котором нет
# X25519MLKEM768 перед обычным X25519, и молча отдаёт клиенту настоящий
# сертификат сайта-прикрытия. Клиенты на ядре sing-box (сам sing-box, Hiddify,
# Karing) этот ключевой обмен из ClientHello вырезают — и получают
# «reality verification failed». Клиенты на ядре Xray (v2rayNG, Streisand)
# работают. Пока правка не доехала до sing-box, ядро можно откатить.
#
# Откат обратим: прежний бинарник сохраняется рядом. Обновление образа 3x-ui
# вернёт ядро из образа — после него pin надо повторить.
set -eu

CONTAINER=3x-ui
BIN=/app/bin/xray-linux-amd64
BACKUP=/app/bin/xray-linux-amd64.before-pin
STORE=/opt/panel/xray-pinned

say() { printf '%s\n' "$*"; }
die() { printf '!!! %s\n' "$*" >&2; exit 1; }

running_version() {
    docker exec "$CONTAINER" "$BIN" -version 2>/dev/null | head -1
}

case "${1:-status}" in
status)
    say "ядро в контейнере: $(running_version)"
    if docker exec "$CONTAINER" test -f "$BACKUP" 2>/dev/null; then
        say "откат возможен: сохранён прежний бинарник"
    else
        say "откат не нужен: ядро штатное, из образа"
    fi
    if [ -d "$STORE" ]; then
        say "скачанные версии: $(ls "$STORE" 2>/dev/null | tr '\n' ' ')"
    fi
    ;;

pin)
    VER="${2:?укажите версию: xray-core.sh pin 26.6.27}"
    case "$VER" in
        *[!0-9.]*) die "версия — только цифры и точки, например 26.6.27" ;;
    esac
    mkdir -p "$STORE"
    DEST="$STORE/xray-$VER"
    if [ ! -x "$DEST" ]; then
        TMP=$(mktemp -d)
        trap 'rm -rf "$TMP"' EXIT
        URL="https://github.com/XTLS/Xray-core/releases/download/v$VER/Xray-linux-64.zip"
        say "скачиваю $URL"
        curl -fsSL -o "$TMP/x.zip" "$URL" || die "не скачалось — проверьте, что версия v$VER существует"
        # Через python3, а не unzip: на минимальном сервере unzip обычно нет,
        # а python3 стоит — на нём же работает client.py.
        python3 - "$TMP/x.zip" "$TMP" <<'PYEOF' || die "архив не распаковался"
import sys, zipfile
with zipfile.ZipFile(sys.argv[1]) as z:
    names = [n for n in z.namelist() if n.rsplit("/", 1)[-1] == "xray"]
    if not names:
        raise SystemExit("в архиве нет бинарника xray")
    with z.open(names[0]) as src, open(sys.argv[2] + "/xray", "wb") as dst:
        dst.write(src.read())
PYEOF
        [ -f "$TMP/xray" ] || die "в архиве нет бинарника xray"
        chmod 755 "$TMP/xray"
        # Проверяем ДО подмены: сломанный бинарник оставит сервер без VPN.
        GOT=$("$TMP/xray" -version 2>/dev/null | head -1) || die "скачанный бинарник не запускается"
        say "скачано: $GOT"
        case "$GOT" in
            *"$VER"*) : ;;
            *) die "бинарник называет себя иначе: $GOT" ;;
        esac
        mv "$TMP/xray" "$DEST"
    else
        say "беру уже скачанное: $DEST"
    fi

    say "сейчас работает: $(running_version)"
    if ! docker exec "$CONTAINER" test -f "$BACKUP"; then
        docker exec "$CONTAINER" cp "$BIN" "$BACKUP" || die "не удалось сохранить прежнее ядро"
        say "прежнее ядро сохранено в контейнере"
    fi
    docker cp "$DEST" "$CONTAINER:$BIN" || die "не удалось положить ядро в контейнер"
    docker exec "$CONTAINER" chmod 755 "$BIN"
    docker restart "$CONTAINER" >/dev/null
    sleep 5
    say "теперь работает: $(running_version)"
    say "проверьте клиентов: /opt/panel/client.py list"
    ;;

restore)
    docker exec "$CONTAINER" test -f "$BACKUP" || die "сохранённого ядра нет — откатывать не к чему"
    docker exec "$CONTAINER" cp "$BACKUP" "$BIN"
    docker exec "$CONTAINER" rm -f "$BACKUP"
    docker restart "$CONTAINER" >/dev/null
    sleep 5
    say "вернул штатное ядро: $(running_version)"
    ;;

*)
    die "команды: status | pin <версия> | restore"
    ;;
esac
