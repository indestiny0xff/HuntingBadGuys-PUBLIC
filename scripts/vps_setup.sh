#!/usr/bin/env bash
# Prepare a fresh Ubuntu 22.04 / 24.04 (or Debian 12) VPS for Hunting Bad Guys.
#
#   curl -fsSL https://raw.githubusercontent.com/indestiny0xff/HuntingBadGuys-PUBLIC/main/scripts/vps_setup.sh | sudo bash
#   # or: sudo bash scripts/vps_setup.sh
#
# What it does (idempotent, safe to re-run):
#   1. system updates + unattended security upgrades
#   2. Docker Engine + Compose plugin from Docker's repository
#   3. UFW firewall: allow SSH, 80, 443; deny everything else
#   4. fail2ban for SSH
#   5. clones the repository into /opt/huntingbadguys (if not present)
#
# It does NOT change SSH settings or create users; harden SSH separately
# (key-only auth, disable root login) before exposing the box.
set -euo pipefail

APP_DIR="${APP_DIR:-/opt/huntingbadguys}"
REPO_URL="${REPO_URL:-https://github.com/indestiny0xff/HuntingBadGuys-PUBLIC.git}"
SSH_PORT="${SSH_PORT:-22}"

[[ $EUID -ne 0 ]] && { echo "Run as root: sudo bash $0"; exit 1; }
export DEBIAN_FRONTEND=noninteractive

echo "[1/5] System packages"
apt-get update -qq
apt-get upgrade -y -qq
apt-get install -y -qq ca-certificates curl git gnupg ufw fail2ban unattended-upgrades
dpkg-reconfigure -f noninteractive unattended-upgrades

echo "[2/5] Docker Engine"
if ! command -v docker >/dev/null 2>&1; then
  install -m 0755 -d /etc/apt/keyrings
  . /etc/os-release
  curl -fsSL "https://download.docker.com/linux/${ID}/gpg" | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
  chmod a+r /etc/apt/keyrings/docker.gpg
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/${ID} ${VERSION_CODENAME} stable" \
    > /etc/apt/sources.list.d/docker.list
  apt-get update -qq
  apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
fi
systemctl enable --now docker

echo "[3/5] Firewall"
ufw default deny incoming
ufw default allow outgoing
ufw allow "${SSH_PORT}/tcp" comment "SSH"
ufw allow 80/tcp comment "HTTP"
ufw allow 443/tcp comment "HTTPS"
ufw allow 443/udp comment "HTTP/3"
ufw --force enable

echo "[4/5] fail2ban"
cat > /etc/fail2ban/jail.d/sshd.local <<EOF
[sshd]
enabled = true
port = ${SSH_PORT}
maxretry = 5
bantime = 1h
EOF
systemctl enable --now fail2ban
systemctl restart fail2ban

echo "[5/5] Application checkout"
if [ ! -d "${APP_DIR}/.git" ]; then
  git clone "${REPO_URL}" "${APP_DIR}"
fi
chmod 700 "${APP_DIR}"

cat <<EOF

Done. Next:
  cd ${APP_DIR}
  cp .env.example .env && nano .env     # set SITE_ADDRESS, secrets, admin password
  docker compose up -d
  docker compose logs -f app            # watch the first start
EOF
