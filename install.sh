#!/usr/bin/env bash
# Установка vpn-ip-rotator на российский сервер, рядом с уже работающими проектами.
set -euo pipefail

APP_DIR=/opt/vpn-rotator
ETC_DIR=/etc/vpn-rotator
STATE_DIR=/var/lib/vpn-rotator
SERVICE_USER=vpnrotator
UNIT=/etc/systemd/system/vpn-rotator.service
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

say()  { printf '\033[1;32m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m /!\\\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m!!!\033[0m %s\n' "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "запускать от root: sudo ./install.sh"

# --- зависимости ------------------------------------------------------------

command -v python3 >/dev/null || die "нужен python3 (3.9+, желательно 3.11+)"
PYVER=$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])')
say "python $PYVER"
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)' \
  || die "нужен python 3.9 или новее (сейчас $PYVER)"

if ! python3 -m venv --help >/dev/null 2>&1; then
  say "ставлю python3-venv"
  (apt-get update -qq && apt-get install -y -qq python3-venv) || die "поставьте python3-venv вручную"
fi

# --- пользователь и каталоги ------------------------------------------------

if ! id -u "$SERVICE_USER" >/dev/null 2>&1; then
  say "создаю системного пользователя $SERVICE_USER"
  useradd --system --home-dir "$APP_DIR" --shell /usr/sbin/nologin "$SERVICE_USER"
fi

install -d -m 0755 "$APP_DIR"
install -d -m 0750 -o "$SERVICE_USER" -g "$SERVICE_USER" "$ETC_DIR" "$STATE_DIR"

if [[ "$SRC" != "$APP_DIR" ]]; then
  say "копирую код в $APP_DIR"
  rm -rf "$APP_DIR/rotator"
  cp -r "$SRC/rotator" "$APP_DIR/rotator"
  cp "$SRC/requirements.txt" "$APP_DIR/"
  rm -rf "$APP_DIR/bin"
  cp -r "$SRC/bin" "$APP_DIR/bin"
  chmod +x "$APP_DIR"/bin/*.sh
  [[ -d "$SRC/tests" ]] && { rm -rf "$APP_DIR/tests"; cp -r "$SRC/tests" "$APP_DIR/tests"; }
fi

# --- виртуальное окружение --------------------------------------------------

if [[ ! -x "$APP_DIR/venv/bin/python" ]]; then
  say "создаю venv"
  python3 -m venv "$APP_DIR/venv"
fi
say "ставлю зависимости"
"$APP_DIR/venv/bin/pip" install -q --upgrade pip
"$APP_DIR/venv/bin/pip" install -q -r "$APP_DIR/requirements.txt"

# --- конфиг -----------------------------------------------------------------

if [[ ! -f "$ETC_DIR/config.toml" ]]; then
  say "кладу config.toml (dry_run=true — ротации пока только имитируются)"
  cp "$SRC/config.example.toml" "$ETC_DIR/config.toml"
  chown "$SERVICE_USER:$SERVICE_USER" "$ETC_DIR/config.toml"
  chmod 0640 "$ETC_DIR/config.toml"
else
  say "config.toml уже есть — не трогаю"
fi

# --- бутстрап-секреты -------------------------------------------------------

ask() {                     # ask ПЕРЕМЕННАЯ "подсказка" [--secret]
  local var="$1" prompt="$2" secret="${3:-}" current="" value=""
  current=$(grep -E "^${var}=" "$ETC_DIR/secrets.env" 2>/dev/null | cut -d= -f2- || true)
  local shown="—"
  [[ -n "$current" ]] && shown=$([[ -n "$secret" ]] && echo "задано" || echo "$current")
  if [[ -n "$secret" ]]; then
    read -rsp "$prompt [$shown]: " value; echo
  else
    read -rp  "$prompt [$shown]: " value
  fi
  [[ -z "$value" ]] && value="$current"
  [[ -z "$value" ]] && die "$var обязателен"
  printf '%s=%s\n' "$var" "$value" >> "$ETC_DIR/secrets.env.new"
}

if [[ -f "$ETC_DIR/secrets.env" ]] && grep -q '^TG_BOT_TOKEN=' "$ETC_DIR/secrets.env"; then
  say "secrets.env уже заполнен — пропускаю опрос (перезалить: rotator setup --local)"
else
  echo
  say "Четыре значения, без которых агент не поднимет канал до Telegram."
  echo "    Всё остальное зальёте потом командой /setup прямо в чате."
  echo
  : > "$ETC_DIR/secrets.env.new"
  ask RELAY_URLS  "URL релея (через запятую, напр. https://relay.example.net)"
  ask RELAY_KEY   "Ключ релея (значение RELAY_KEY воркера)" --secret
  ask TG_BOT_TOKEN "Токен бота от @BotFather" --secret
  ask TG_ADMIN_ID "Ваш chat_id в Telegram (узнать: @userinfobot)"

  # Значения, уже лежавшие в файле, переносим.
  if [[ -f "$ETC_DIR/secrets.env" ]]; then
    while IFS= read -r line; do
      key="${line%%=*}"
      grep -q "^${key}=" "$ETC_DIR/secrets.env.new" || printf '%s\n' "$line" >> "$ETC_DIR/secrets.env.new"
    done < <(grep -E '^[A-Z_]+=' "$ETC_DIR/secrets.env" || true)
  fi
  mv "$ETC_DIR/secrets.env.new" "$ETC_DIR/secrets.env"
fi

chown "$SERVICE_USER:$SERVICE_USER" "$ETC_DIR/secrets.env"
chmod 0600 "$ETC_DIR/secrets.env"
chown -R "$SERVICE_USER:$SERVICE_USER" "$STATE_DIR" "$APP_DIR"

# --- systemd ----------------------------------------------------------------

say "ставлю systemd-юнит"
cp "$SRC/systemd/vpn-rotator.service" "$UNIT"
systemctl daemon-reload
systemctl enable --now vpn-rotator >/dev/null

sleep 2
if systemctl is-active --quiet vpn-rotator; then
  say "сервис запущен"
else
  warn "сервис не поднялся — смотрите: journalctl -u vpn-rotator -n 50"
fi

cat <<'NEXT'

Дальше — в Telegram, боту:

  /check    проверить связь и доступы
  /setup    залить токены UpCloud и Cloudflare, zone_id, id записей
  /probe    первая проба

Пока в config.toml стоит dry_run = true, ротации только имитируются.
Снимете его, когда /check станет зелёным и вы прогоните пункт 3 из README.

  журнал:     journalctl -u vpn-rotator -f
  настройки:  /etc/vpn-rotator/config.toml
NEXT
