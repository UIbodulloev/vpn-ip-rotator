#!/bin/bash
# Один раз на medbot (root): admin.mos8.online → веб-админка бота.
#
#   ops/setup-admin-web.sh
#
# DNS-запись admin.mos8.online → адрес medbot должна уже быть (без прокси
# Cloudflare). Сертификат выпускается через webroot, продлевает его certbot.timer,
# после продления nginx перечитывает его хуком.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SITE=/etc/nginx/sites-available/vpn-admin
WEBROOT=/var/www/html
DOMAIN=admin.mos8.online

mkdir -p "$WEBROOT"
if [ ! -f "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" ]; then
    # Сначала только HTTP — чтобы certbot мог пройти проверку.
    cat > "$SITE" <<EOF
server {
    listen 80;
    listen [::]:80;
    server_name $DOMAIN;
    location /.well-known/acme-challenge/ { root $WEBROOT; }
    location / { return 404; }
}
EOF
    ln -sf "$SITE" /etc/nginx/sites-enabled/vpn-admin
    nginx -t -q && systemctl reload nginx
    certbot certonly --webroot -w "$WEBROOT" -d "$DOMAIN" --non-interactive --agree-tos \
        --register-unsafely-without-email --keep-until-expiring -q
fi

install -m 0644 "$HERE/nginx-admin.conf" "$SITE"
ln -sf "$SITE" /etc/nginx/sites-enabled/vpn-admin
nginx -t -q
systemctl reload nginx

mkdir -p /etc/letsencrypt/renewal-hooks/deploy
printf '#!/bin/sh\nsystemctl reload nginx\n' > /etc/letsencrypt/renewal-hooks/deploy/nginx-reload
chmod 755 /etc/letsencrypt/renewal-hooks/deploy/nginx-reload

echo "готово: https://$DOMAIN"
