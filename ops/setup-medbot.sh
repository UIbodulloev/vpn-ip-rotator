#!/bin/bash
# Один раз на medbot (root): пустить VPN-сервер управлять ботом — и только им.
#
#   ops/setup-medbot.sh "ssh-ed25519 AAAA… vpn-server-ops"
#
# Создаёт пользователя vpnops без пароля и без shell. Его единственный ключ
# можно использовать только для /usr/local/sbin/vpn-rotator-ops: ни входа в
# консоль, ни пробросов портов, ни доступа к медицинскому проекту и базе.
set -euo pipefail

KEY="${1:?передайте публичный ключ VPN-сервера}"
[[ "$KEY" =~ ^ssh-ed25519\ [A-Za-z0-9+/=]+(\ .*)?$ ]] || { echo "ожидался ключ ssh-ed25519" >&2; exit 1; }
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

install -o root -g root -m 0755 "$HERE/vpn-rotator-ops" /usr/local/sbin/vpn-rotator-ops

id vpnops >/dev/null 2>&1 || useradd --system --create-home --shell /bin/sh vpnops
passwd -l vpnops >/dev/null

install -d -o vpnops -g vpnops -m 0700 /home/vpnops/.ssh
printf 'restrict,command="sudo -n /usr/local/sbin/vpn-rotator-ops" %s\n' "$KEY" \
    > /home/vpnops/.ssh/authorized_keys
chown vpnops:vpnops /home/vpnops/.ssh/authorized_keys
chmod 0600 /home/vpnops/.ssh/authorized_keys

cat > /etc/sudoers.d/vpnops <<'EOF'
# VPN-сервер управляет ботом только через этот скрипт (ops/vpn-rotator-ops).
Defaults!/usr/local/sbin/vpn-rotator-ops env_keep += "SSH_ORIGINAL_COMMAND"
vpnops ALL=(root) NOPASSWD: /usr/local/sbin/vpn-rotator-ops
EOF
chmod 0440 /etc/sudoers.d/vpnops
visudo -cf /etc/sudoers.d/vpnops >/dev/null

echo "готово: vpnops может только status, logs, test, deploy, rollback, restart"
