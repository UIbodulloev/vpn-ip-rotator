#!/usr/bin/env bash
# Развёртывание генератора подписок. Без node и wrangler — только curl и python3.
#
#   export CF_DEPLOY_TOKEN=$(cat ~/.cf-deploy-token)
#   ./deploy.sh sub.example.net
#
# Параметры Reality берутся с VPN-сервера из /opt/panel/reality-params.env либо
# из переменных окружения VPN_HOST, VPN_PORT, VPN_PUBLIC_KEY, VPN_SHORT_ID, VPN_SNI.
#
# Токен нужен с правами: Account → Workers Scripts → Edit, Zone → Workers Routes
# → Edit, Zone → DNS → Edit, Zone → Zone → Read. После развёртывания отзовите его.
set -euo pipefail

HOSTNAME_ARG="${1:?укажите хост подписок: ./deploy.sh sub.example.net}"
SCRIPT_NAME="${WORKER_NAME:-vpn-subscriptions}"
COMPAT_DATE="${COMPAT_DATE:-2026-01-01}"
API="https://api.cloudflare.com/client/v4"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PARAMS_FILE="${PARAMS_FILE:-/opt/panel/reality-params.env}"

say()  { printf '\033[1;32m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m /!\\\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m!!!\033[0m %s\n' "$*" >&2; exit 1; }

[[ -n "${CF_DEPLOY_TOKEN:-}" ]] || die "нет CF_DEPLOY_TOKEN"
command -v python3 >/dev/null || die "нужен python3"

# Параметры Reality: из файла на сервере, если он есть, иначе из окружения.
if [[ -f "$PARAMS_FILE" ]]; then
    say "беру параметры Reality из $PARAMS_FILE"
    # shellcheck disable=SC1090
    source <(grep -E '^[A-Z_]+=' "$PARAMS_FILE")
    VPN_HOST="${VPN_HOST:-${HOST:-}}"
    VPN_PORT="${VPN_PORT:-${PORT:-443}}"
    VPN_PUBLIC_KEY="${VPN_PUBLIC_KEY:-${PUBLIC_KEY:-}}"
    VPN_SHORT_ID="${VPN_SHORT_ID:-${SHORT_ID:-}}"
    VPN_SNI="${VPN_SNI:-${SNI:-}}"
    VPN_FINGERPRINT="${VPN_FINGERPRINT:-${FINGERPRINT:-chrome}}"
fi
for v in VPN_HOST VPN_PUBLIC_KEY VPN_SHORT_ID VPN_SNI; do
    [[ -n "${!v:-}" ]] || die "не задан $v — укажите в окружении или в $PARAMS_FILE"
done
VPN_PORT="${VPN_PORT:-443}"
VPN_FINGERPRINT="${VPN_FINGERPRINT:-chrome}"

ZONE_NAME="${CF_ZONE_NAME:-${HOSTNAME_ARG#*.}}"

jq_get() { python3 -c '
import json,sys
d=json.loads(sys.stdin.read() or "{}")
try: print(eval(sys.argv[1]))
except Exception: print("")
' "$1"; }

api() { local m="$1" p="$2"; shift 2; curl -sS -X "$m" "$API$p" -H "Authorization: Bearer $CF_DEPLOY_TOKEN" "$@"; }
check_ok() { local b="$1" w="$2"; [[ "$(printf '%s' "$b" | jq_get 'd.get("success")')" == "True" ]] \
    || { printf '%s' "$b" | python3 -m json.tool 2>/dev/null | head -20 >&2; die "$w — не удалось"; }; }

say "проверяю токен"; check_ok "$(api GET /user/tokens/verify)" "проверка токена"

ACCOUNT_ID="${CF_ACCOUNT_ID:-$(api GET /accounts | jq_get 'd["result"][0]["id"]')}"
[[ -n "$ACCOUNT_ID" ]] || die "не определился account_id — задайте CF_ACCOUNT_ID"
ZONE_ID="${CF_ZONE_ID:-$(api GET "/zones?name=$ZONE_NAME" | jq_get 'd["result"][0]["id"]')}"
[[ -n "$ZONE_ID" ]] || die "зона $ZONE_NAME не найдена — задайте CF_ZONE_ID"
say "account $ACCOUNT_ID, зона $ZONE_NAME"

TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
# Параметры Reality едут биндингами: в коде Worker их нет, менять можно
# переразвёртыванием, не трогая логику.
VPN_HOST="$VPN_HOST" VPN_PORT="$VPN_PORT" VPN_PUBLIC_KEY="$VPN_PUBLIC_KEY" \
VPN_SHORT_ID="$VPN_SHORT_ID" VPN_SNI="$VPN_SNI" VPN_FINGERPRINT="$VPN_FINGERPRINT" \
COMPAT_DATE="$COMPAT_DATE" python3 > "$TMP/metadata.json" <<'PYEOF'
import json, os
keys = ("VPN_HOST","VPN_PORT","VPN_PUBLIC_KEY","VPN_SHORT_ID","VPN_SNI","VPN_FINGERPRINT")
print(json.dumps({
    "main_module": "worker.js",
    "compatibility_date": os.environ["COMPAT_DATE"],
    "bindings": [{"type": "plain_text", "name": k, "text": os.environ[k]} for k in keys],
}))
PYEOF

say "заливаю воркер $SCRIPT_NAME"
check_ok "$(api PUT "/accounts/$ACCOUNT_ID/workers/scripts/$SCRIPT_NAME" \
    -F "metadata=<$TMP/metadata.json;type=application/json" \
    -F "worker.js=@$HERE/worker.js;type=application/javascript+module")" "заливка воркера"

say "настраиваю DNS $HOSTNAME_ARG"
EXISTING=$(api GET "/zones/$ZONE_ID/dns_records?name=$HOSTNAME_ARG&type=A")
RECORD_ID=$(printf '%s' "$EXISTING" | jq_get 'd["result"][0]["id"]')
DNS='{"type":"A","name":"'"$HOSTNAME_ARG"'","content":"192.0.2.1","proxied":true,"ttl":1}'
if [[ -n "$RECORD_ID" ]]; then
    check_ok "$(api PATCH "/zones/$ZONE_ID/dns_records/$RECORD_ID" -H 'Content-Type: application/json' --data "$DNS")" "обновление DNS"
else
    check_ok "$(api POST "/zones/$ZONE_ID/dns_records" -H 'Content-Type: application/json' --data "$DNS")" "создание DNS"
fi

say "привязываю маршрут $HOSTNAME_ARG/*"
ROUTES=$(api GET "/zones/$ZONE_ID/workers/routes")
ROUTE_ID=$(PATTERN="$HOSTNAME_ARG/*" python3 -c '
import json,os,sys
d=json.loads(sys.stdin.read() or "{}")
for r in d.get("result") or []:
    if r.get("pattern")==os.environ["PATTERN"]: print(r["id"]); break
' <<<"$ROUTES")
BODY='{"pattern":"'"$HOSTNAME_ARG"'/*","script":"'"$SCRIPT_NAME"'"}'
if [[ -n "$ROUTE_ID" ]]; then
    check_ok "$(api PUT "/zones/$ZONE_ID/workers/routes/$ROUTE_ID" -H 'Content-Type: application/json' --data "$BODY")" "обновление маршрута"
else
    check_ok "$(api POST "/zones/$ZONE_ID/workers/routes" -H 'Content-Type: application/json' --data "$BODY")" "создание маршрута"
fi

say "проверяю"
PROBE="00000000-0000-4000-8000-000000000000"
for _ in $(seq 1 20); do
    CODE=$(curl -sS -o "$TMP/sub.json" -w '%{http_code}' --max-time 10 "https://$HOSTNAME_ARG/sub/$PROBE" || true)
    [[ "$CODE" == "200" ]] && break
    sleep 5
done
echo
if [[ "${CODE:-}" == "200" ]]; then
    say "подписка отвечает: https://$HOSTNAME_ARG/sub/<uuid>"
    python3 - "$TMP/sub.json" <<'PYEOF'
import json, sys
cfg = json.load(open(sys.argv[1]))
# Проверяем связность ссылок: правило не должно указывать на несуществующий тег.
outs = {o["tag"] for o in cfg["outbounds"]}
sets = {r["tag"] for r in cfg["route"]["rule_set"]}
problems = []
for rule in cfg["route"]["rules"]:
    if rule.get("outbound") and rule["outbound"] not in outs:
        problems.append(f"route: нет outbound {rule['outbound']}")
    for tag in rule.get("rule_set", []):
        if tag not in sets:
            problems.append(f"route: нет rule_set {tag}")
if cfg["route"]["final"] not in outs:
    problems.append("route.final указывает в пустоту")
servers = {s["tag"] for s in cfg["dns"]["servers"]}
for rule in cfg["dns"]["rules"]:
    if rule.get("server") and rule["server"] not in servers:
        problems.append(f"dns: нет сервера {rule['server']}")
    for tag in rule.get("rule_set", []):
        if tag not in sets:
            problems.append(f"dns: нет rule_set {tag}")
if cfg["dns"]["final"] not in servers:
    problems.append("dns.final указывает в пустоту")
for s in cfg["dns"]["servers"]:
    if s.get("detour") and s["detour"] not in outs:
        problems.append(f"dns: detour {s['detour']} не существует")
print("ссылки внутри конфига:", "; ".join(problems) if problems else "все теги на месте ✅")
print("правил маршрутизации:", len(cfg["route"]["rules"]), "| наборов правил:", len(sets))
PYEOF
else
    warn "подписка пока не отвечает (код ${CODE:-нет}) — DNS и маршруты Cloudflare расходятся до минуты"
fi
CODE=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 10 "https://$HOSTNAME_ARG/sub/not-a-uuid" || true)
[[ "$CODE" == "404" ]] && say "мусор в пути отбивается 404" || warn "на мусорный путь ответ $CODE"
echo
echo "Страница для пользователей: https://$HOSTNAME_ARG/"
echo "Подписка:                   https://$HOSTNAME_ARG/sub/<uuid-клиента>"
echo "Ссылка vless:               https://$HOSTNAME_ARG/vless/<uuid-клиента>"
