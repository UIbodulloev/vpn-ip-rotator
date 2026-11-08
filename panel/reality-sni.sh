#!/bin/bash
# Смена сайта-прикрытия REALITY — того имени, под которое VLESS выдаёт себя.
#
#   /opt/panel/reality-sni.sh status              что стоит сейчас
#   /opt/panel/reality-sni.sh check www.icloud.com   пригоден ли этот сайт
#   /opt/panel/reality-sni.sh set www.icloud.com     поставить, старое имя оставить
#   /opt/panel/reality-sni.sh drop-old               убрать старое имя после перехода
#
# Зачем это может понадобиться. ТСПУ принимает решение о замедлении по имени
# сайта в приветствии TLS (SNI), а не по адресу. Пока в этом поле стоит домен
# Google, наш VLESS едет в той же очереди, что и YouTube, — к нашему серверу,
# но с гугловым именем на конверте.
#
# Почему старое имя остаётся. Имя лежит внутри подписки, а телефоны перечитывают
# её раз в сутки. Убрать старое сразу значит отключить всех до того, как они
# обновятся. Поэтому `set` держит оба имени, а `drop-old` убирает прежнее —
# после развёртывания воркера и суток ожидания.
set -euo pipefail

DB=/opt/panel/db/x-ui.db
PARAMS=/opt/panel/reality-params.env
CONTAINER=3x-ui
SING=/opt/panel/sing-box

say()  { printf '\033[1;32m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m /!\\\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m!!!\033[0m %s\n' "$*" >&2; exit 1; }

[ -f "$DB" ] || die "нет базы панели: $DB"

read_json() { python3 -I - "$DB" "$@"; }

status() {
    python3 -I - "$DB" <<'PYEOF'
import json, sqlite3, sys
db = sqlite3.connect(sys.argv[1])
for pid, stream in db.execute("select port, stream_settings from inbounds where protocol='vless'"):
    rs = json.loads(stream).get("realitySettings", {})
    print(f"порт {pid}")
    print("  кем прикидывается :", ", ".join(rs.get("serverNames", [])) or "—")
    print("  куда уходит проба :", rs.get("dest", "—"))
PYEOF
    [ -f "$PARAMS" ] && echo "  в подписке        : $(grep -m1 '^SNI=' "$PARAMS" | cut -d= -f2)"
}

# Пригодность сайта: REALITY требует TLS 1.3 и X25519, а h2 нужен, чтобы
# прикрытие выглядело как настоящий сайт, а не как заглушка.
check() {
    local host="$1" out tls alpn verify
    out=$(echo | timeout 15 openssl s_client -connect "$host:443" -servername "$host" \
          -tls1_3 -groups X25519 -alpn h2 2>&1) || true
    tls=$(grep -m1 '^Protocol:' <<<"$out" | awk '{print $2}')
    alpn=$(grep -m1 '^ALPN protocol:' <<<"$out" | awk '{print $3}')
    verify=$(grep -m1 'Verify return code' <<<"$out" | cut -d: -f2 | tr -d ' ')
    echo "  TLS 1.3 + X25519 : ${tls:-НЕТ}"
    echo "  ALPN h2          : ${alpn:-нет}"
    echo "  сертификат       : ${verify:-?}"
    [ "$tls" = "TLSv1.3" ] || return 1
    [ "$alpn" = "h2" ] || return 1
    [[ "$verify" == 0* ]] || return 1
    case "$host" in
        *google*|*youtube*|*gstatic*|*ggpht*)
            warn "это домен Google: по такому имени трафик и замедляют";;
    esac
    return 0
}

# Настоящая проверка: поднять клиента с новым именем и выйти через него в сеть.
# Без неё «готово» означает только то, что база изменилась.
verify_tunnel() {
    local sni="$1" uuid tmp port=11099 pid code
    uuid=$(python3 -I - "$DB" <<'PYEOF'
import json, sqlite3, sys
db = sqlite3.connect(sys.argv[1])
row = db.execute("select settings from inbounds where protocol='vless'").fetchone()
print(json.loads(row[0])["clients"][0]["id"])
PYEOF
)
    [ -n "$uuid" ] || { warn "в панели нет ни одного клиента — проверить нечем"; return 0; }
    [ -x "$SING" ] || { warn "нет $SING — проверить нечем"; return 0; }
    tmp=$(mktemp -d)
    python3 -I - "$tmp/c.json" "$uuid" "$sni" "$port" "$PARAMS" <<'PYEOF'
import json, sys
path, uuid, sni, port, params = sys.argv[1:6]
env = dict(l.strip().split("=", 1) for l in open(params)
           if "=" in l and not l.startswith("#"))
json.dump({
    "log": {"level": "error"},
    "inbounds": [{"type": "socks", "tag": "in", "listen": "127.0.0.1",
                  "listen_port": int(port)}],
    "outbounds": [{"type": "vless", "tag": "out", "server": env["HOST"],
                   "server_port": int(env.get("PORT", 443)), "uuid": uuid,
                   "flow": "xtls-rprx-vision",
                   "tls": {"enabled": True, "server_name": sni,
                           "utls": {"enabled": True, "fingerprint": "chrome"},
                           "reality": {"enabled": True,
                                       "public_key": env["PUBLIC_KEY"],
                                       "short_id": env["SHORT_ID"]}}}],
    "route": {"final": "out"},
}, open(path, "w"), indent=1)
PYEOF
    "$SING" run -c "$tmp/c.json" >"$tmp/log" 2>&1 &
    pid=$!
    sleep 4
    code=$(curl -sS --socks5-hostname "127.0.0.1:$port" --max-time 25 \
           -o /dev/null -w '%{http_code}' https://www.youtube.com/ 2>/dev/null || true)
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
    if [ "$code" = "200" ]; then
        say "туннель с именем $sni работает: youtube.com отдал 200"
    else
        warn "через туннель с именем $sni ответ «$code» — смотрите $tmp/log"
        return 1
    fi
    rm -rf "$tmp"
}

set_sni() {
    local host="$1" old
    say "проверяю $host"
    check "$host" || die "сайт не годится в прикрытие"

    cp -a "$DB" "$DB.before-sni" && say "база сохранена: $DB.before-sni"
    old=$(python3 -I - "$DB" "$host" <<'PYEOF'
import json, sqlite3, sys
db = sqlite3.connect(sys.argv[1]); host = sys.argv[2]
rows = db.execute("select id, stream_settings from inbounds where protocol='vless'").fetchall()
was = []
for pid, stream in rows:
    cfg = json.loads(stream)
    rs = cfg.setdefault("realitySettings", {})
    names = rs.get("serverNames", [])
    was += [n for n in names if n != host]
    # Новое имя первым, прежние — следом: пока телефоны не перечитают подписку,
    # они продолжают присылать старое, и отключать их нельзя.
    rs["serverNames"] = [host] + [n for n in names if n != host]
    rs["dest"] = f"{host}:443"
    db.execute("update inbounds set stream_settings=? where id=?",
               (json.dumps(cfg), pid))
db.commit()
print(" ".join(dict.fromkeys(was)))
PYEOF
)
    [ -n "$old" ] && say "прежние имена оставлены на время перехода: $old"

    if [ -f "$PARAMS" ]; then
        sed -i "s#^SNI=.*#SNI=$host#" "$PARAMS"
        say "в подписку пойдёт имя $host"
    fi

    say "перезапускаю панель, чтобы ядро перечитало настройки"
    docker restart "$CONTAINER" >/dev/null
    for _ in $(seq 1 20); do
        sleep 2
        docker exec "$CONTAINER" sh -c 'pgrep -f xray >/dev/null' 2>/dev/null && break
    done

    verify_tunnel "$host" || die "новое имя не поехало — откат: cp $DB.before-sni $DB && docker restart $CONTAINER"
    [ -n "$old" ] && verify_tunnel "${old%% *}" || true

    echo
    say "осталось два шага"
    echo "  1. Развернуть воркер, чтобы имя попало в подписки:"
    echo "     cd ~/vpn-ip-rotator/subs && ./deploy.sh origin.mos8.online"
    echo "  2. Через сутки убрать прежнее имя: $0 drop-old"
    echo "     Простые ссылки vless:// придётся выдать заново — в них имя внутри."
}

drop_old() {
    local keep
    keep=$(grep -m1 '^SNI=' "$PARAMS" | cut -d= -f2)
    [ -n "$keep" ] || die "не понял, какое имя оставить: нет SNI в $PARAMS"
    python3 -I - "$DB" "$keep" <<'PYEOF'
import json, sqlite3, sys
db = sqlite3.connect(sys.argv[1]); keep = sys.argv[2]
for pid, stream in db.execute("select id, stream_settings from inbounds where protocol='vless'").fetchall():
    cfg = json.loads(stream)
    cfg.setdefault("realitySettings", {})["serverNames"] = [keep]
    db.execute("update inbounds set stream_settings=? where id=?", (json.dumps(cfg), pid))
db.commit()
print(f"оставлено одно имя: {keep}")
PYEOF
    docker restart "$CONTAINER" >/dev/null
    sleep 6
    verify_tunnel "$keep"
}

case "${1:-status}" in
    status)   status;;
    check)    check "${2:?укажите домен}" && say "годится" || die "не годится";;
    set)      set_sni "${2:?укажите домен}";;
    drop-old) drop_old;;
    *)        die "известные команды: status | check <домен> | set <домен> | drop-old";;
esac
