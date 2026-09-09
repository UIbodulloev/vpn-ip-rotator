#!/usr/bin/env bash
# Развёртывание релея без node и wrangler — напрямую через REST API Cloudflare.
#
# Зачем: wrangler тянет ~300 МБ node_modules, а разворачивать релей часто
# приходится с той же машины, где лишней памяти нет. Здесь хватает curl и python3.
#
#   export CF_DEPLOY_TOKEN=$(cat ~/.cf-deploy-token)
#   ./deploy.sh relay.example.net
#
# Токен нужен с правами:
#   Account → Workers Scripts → Edit
#   Zone    → Workers Routes  → Edit
#   Zone    → DNS            → Edit
#   Zone    → Zone           → Read
set -euo pipefail

HOSTNAME_ARG="${1:-}"
SCRIPT_NAME="${WORKER_NAME:-vpn-rotator-relay}"
COMPAT_DATE="${COMPAT_DATE:-2026-01-01}"
API="https://api.cloudflare.com/client/v4"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

say()  { printf '\033[1;32m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m /!\\\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m!!!\033[0m %s\n' "$*" >&2; exit 1; }

[[ -n "$HOSTNAME_ARG" ]] || die "укажите хост релея: ./deploy.sh relay.example.net"
[[ -n "${CF_DEPLOY_TOKEN:-}" ]] || die "нет CF_DEPLOY_TOKEN"
command -v python3 >/dev/null || die "нужен python3 для разбора JSON"

ZONE_NAME="${CF_ZONE_NAME:-${HOSTNAME_ARG#*.}}"

# --- разбор ответов ---------------------------------------------------------

# jq_get <json> <выражение python поверх переменной d>
jq_get() { python3 -c '
import json,sys
d=json.loads(sys.stdin.read() or "{}")
try:
    print(eval(sys.argv[1]))
except Exception:
    print("")
' "$1"; }

api() {                      # api МЕТОД ПУТЬ [аргументы curl...]
    local method="$1" path="$2"; shift 2
    curl -sS -X "$method" "$API$path" \
        -H "Authorization: Bearer $CF_DEPLOY_TOKEN" \
        "$@"
}

check_ok() {                 # check_ok <json> <что делали>
    local body="$1" what="$2"
    local ok; ok=$(printf '%s' "$body" | jq_get 'd.get("success")')
    if [[ "$ok" != "True" ]]; then
        printf '%s' "$body" | python3 -m json.tool 2>/dev/null | head -20 >&2
        die "$what — не удалось"
    fi
}

# --- 1. токен ---------------------------------------------------------------

say "проверяю токен"
RESP=$(api GET /user/tokens/verify)
check_ok "$RESP" "проверка токена"
say "токен действителен"

# --- 2. account_id и zone_id ------------------------------------------------

if [[ -n "${CF_ACCOUNT_ID:-}" ]]; then
    ACCOUNT_ID="$CF_ACCOUNT_ID"
else
    RESP=$(api GET /accounts)
    ACCOUNT_ID=$(printf '%s' "$RESP" | jq_get 'd["result"][0]["id"]')
    [[ -n "$ACCOUNT_ID" ]] || die "не удалось определить account_id — задайте CF_ACCOUNT_ID вручную"
fi
say "account_id: $ACCOUNT_ID"

if [[ -n "${CF_ZONE_ID:-}" ]]; then
    ZONE_ID="$CF_ZONE_ID"
else
    RESP=$(api GET "/zones?name=$ZONE_NAME")
    ZONE_ID=$(printf '%s' "$RESP" | jq_get 'd["result"][0]["id"]')
    [[ -n "$ZONE_ID" ]] || die "зона $ZONE_NAME не найдена — задайте CF_ZONE_ID вручную"
fi
say "зона $ZONE_NAME: $ZONE_ID"

# --- 3. ключ релея ----------------------------------------------------------

if [[ -z "${RELAY_KEY:-}" ]]; then
    RELAY_KEY=$(python3 -c 'import secrets; print(secrets.token_hex(32))')
    GENERATED=1
fi

# --- 4. заливка воркера -----------------------------------------------------

say "заливаю воркер $SCRIPT_NAME"
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT

# Секрет уходит биндингом прямо в метаданных — отдельный вызов не нужен.
RELAY_KEY="$RELAY_KEY" COMPAT_DATE="$COMPAT_DATE" python3 > "$TMP/metadata.json" <<'PYEOF'
import json, os
print(json.dumps({
    "main_module": "worker.js",
    "compatibility_date": os.environ["COMPAT_DATE"],
    "bindings": [
        {"type": "secret_text", "name": "RELAY_KEY", "text": os.environ["RELAY_KEY"]}
    ],
}))
PYEOF

RESP=$(api PUT "/accounts/$ACCOUNT_ID/workers/scripts/$SCRIPT_NAME" \
    -F "metadata=<$TMP/metadata.json;type=application/json" \
    -F "worker.js=@$HERE/worker.js;type=application/javascript+module")
check_ok "$RESP" "заливка воркера"
say "воркер залит"

# --- 5. DNS-запись под маршрут ----------------------------------------------

# Маршруту нужна проксируемая запись на этом хосте. Адрес фиктивный
# (192.0.2.1 из документационного диапазона) — трафик всё равно забирает воркер.
say "настраиваю DNS $HOSTNAME_ARG"
EXISTING=$(api GET "/zones/$ZONE_ID/dns_records?name=$HOSTNAME_ARG&type=A")
RECORD_ID=$(printf '%s' "$EXISTING" | jq_get 'd["result"][0]["id"]')
DNS_BODY='{"type":"A","name":"'"$HOSTNAME_ARG"'","content":"192.0.2.1","proxied":true,"ttl":1}'

if [[ -n "$RECORD_ID" ]]; then
    RESP=$(api PATCH "/zones/$ZONE_ID/dns_records/$RECORD_ID" \
        -H "Content-Type: application/json" --data "$DNS_BODY")
    check_ok "$RESP" "обновление DNS-записи"
    say "запись обновлена (проксируется)"
else
    RESP=$(api POST "/zones/$ZONE_ID/dns_records" \
        -H "Content-Type: application/json" --data "$DNS_BODY")
    check_ok "$RESP" "создание DNS-записи"
    say "запись создана (проксируется)"
fi

# --- 6. маршрут -------------------------------------------------------------

say "привязываю маршрут $HOSTNAME_ARG/*"
PATTERN="$HOSTNAME_ARG/*"
ROUTES=$(api GET "/zones/$ZONE_ID/workers/routes")
ROUTE_ID=$(PATTERN="$PATTERN" python3 -c '
import json,os,sys
d=json.loads(sys.stdin.read() or "{}")
for r in d.get("result") or []:
    if r.get("pattern")==os.environ["PATTERN"]:
        print(r["id"]); break
' <<<"$ROUTES")
ROUTE_BODY='{"pattern":"'"$PATTERN"'","script":"'"$SCRIPT_NAME"'"}'

if [[ -n "$ROUTE_ID" ]]; then
    RESP=$(api PUT "/zones/$ZONE_ID/workers/routes/$ROUTE_ID" \
        -H "Content-Type: application/json" --data "$ROUTE_BODY")
    check_ok "$RESP" "обновление маршрута"
else
    RESP=$(api POST "/zones/$ZONE_ID/workers/routes" \
        -H "Content-Type: application/json" --data "$ROUTE_BODY")
    check_ok "$RESP" "создание маршрута"
fi
say "маршрут привязан"

# --- 7. проверка ------------------------------------------------------------

say "жду, пока маршрут поднимется"
HEALTH=""
for _ in $(seq 1 20); do
    HEALTH=$(curl -sS --max-time 10 -H "X-Relay-Key: $RELAY_KEY" \
        "https://$HOSTNAME_ARG/healthz" 2>/dev/null || true)
    [[ "$HEALTH" == "ok" ]] && break
    sleep 5
done

echo
if [[ "$HEALTH" == "ok" ]]; then
    say "релей отвечает: https://$HOSTNAME_ARG/healthz → ok"
else
    warn "healthz пока не отвечает (ответ: ${HEALTH:-пусто})."
    warn "DNS и маршруты Cloudflare иногда расходятся до минуты — проверьте вручную:"
    warn "  curl -H 'X-Relay-Key: <ключ>' https://$HOSTNAME_ARG/healthz"
fi

# Проверяем, что это не open proxy: без ключа должно быть 403.
CODE=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 10 "https://$HOSTNAME_ARG/healthz" || true)
[[ "$CODE" == "403" ]] && say "без ключа отдаёт 403 — доступ закрыт" || warn "без ключа код $CODE (ожидался 403)"

echo
echo "В secrets.env агента:"
echo "  RELAY_URLS=https://$HOSTNAME_ARG"
if [[ -n "${GENERATED:-}" ]]; then
    echo "  RELAY_KEY=$RELAY_KEY"
    echo
    warn "ключ сгенерирован сейчас и больше нигде не хранится — сохраните его."
else
    echo "  RELAY_KEY=<тот, что вы передали в RELAY_KEY>"
fi
