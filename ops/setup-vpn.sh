#!/bin/bash
# Один раз на VPN-сервере (root): пульт vpnctl и самостоятельный Claude CLI.
#
#   ops/setup-vpn.sh
#
# Печатает публичный ключ — его нужно один раз поставить на medbot:
#   ops/setup-medbot.sh "<ключ>"
set -euo pipefail

REPO=/root/vpn-ip-rotator
KEY=/root/.ssh/medbot_ops

[ -d "$REPO/.git" ] || git clone -q https://github.com/UIbodulloev/vpn-ip-rotator.git "$REPO"

# Ключ только для medbot-ops: на той стороне он пускает лишь в vpn-rotator-ops.
[ -f "$KEY" ] || ssh-keygen -q -t ed25519 -N '' -C vpn-server-ops -f "$KEY"
touch /root/.ssh/config; chmod 600 /root/.ssh/config
grep -q '^Host medbot-ops$' /root/.ssh/config || cat >> /root/.ssh/config <<EOF

Host medbot-ops
    HostName 91.218.115.82
    User vpnops
    IdentityFile $KEY
    IdentitiesOnly yes
    StrictHostKeyChecking accept-new
    ServerAliveInterval 30
EOF

ln -sf "$REPO/ops/vpnctl" /usr/local/bin/vpnctl
install -d -m 700 /root/.config/vpn

# git push через уже вошедший gh — отдельный токен не нужен.
command -v gh >/dev/null && gh auth setup-git >/dev/null 2>&1 || true
git -C "$REPO" config user.name  >/dev/null || git -C "$REPO" config user.name  "Firdavs"
git -C "$REPO" config user.email >/dev/null || git -C "$REPO" config user.email "firdavsim@gmail.com"

# Claude CLI: рутинное — без вопросов, секреты — не читать.
python3 -I - <<'PY'
import json, pathlib
path = pathlib.Path("/root/.claude/settings.json")
data = json.loads(path.read_text()) if path.exists() else {}
perm = data.setdefault("permissions", {})
allow = set(perm.get("allow", []))
allow.update([
    "Bash(vpnctl:*)", "Bash(git:*)", "Bash(gh:*)",
    "Bash(python3 -m unittest:*)", "Bash(python3 -m py_compile:*)", "Bash(bash -n:*)",
    "Bash(systemctl status:*)", "Bash(systemctl is-active:*)", "Bash(journalctl:*)",
    "Bash(/opt/panel/device-guard.py:*)", "Bash(/opt/panel/sub-mirror.py:*)",
    "Bash(/opt/panel/client.py:*)", "Bash(/opt/panel/reality-sni.sh:*)",
    "Bash(/opt/panel/hysteria-official.sh status)", "Bash(/opt/panel/hy2-porthop.sh status)",
    "Bash(docker ps:*)", "Bash(docker logs:*)", "Bash(free:*)", "Bash(ss:*)", "Bash(curl:*)",
    "Edit(/root/vpn-ip-rotator/**)", "Write(/root/vpn-ip-rotator/**)",
])
perm["allow"] = sorted(allow)
deny = set(perm.get("deny", []))
deny.update([
    "Read(/root/.config/vpn/**)", "Read(/opt/panel/credentials)",
    "Read(/opt/panel/device-guard.env)", "Read(/opt/panel/hysteria2.env)",
    "Read(/etc/hysteria/**)", "Read(/root/.ssh/**)", "Read(/root/.config/gh/**)",
    "Bash(git push --force:*)", "Bash(git push -f:*)",
])
perm["deny"] = sorted(deny)
path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n")
PY

# Где бы ни запустили claude, он знает, куда идти.
cat > /root/.claude/CLAUDE.md <<'EOF'
Ты на VPN-сервере личного VPN. Вся система описана в /root/vpn-ip-rotator/CLAUDE.md —
прочитай его перед любой работой и работай из /root/vpn-ip-rotator.
Пульт управления обоими серверами — команда vpnctl (vpnctl status для начала).
EOF

echo "готово. Публичный ключ для medbot:"
cat "$KEY.pub"
