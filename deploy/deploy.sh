#!/usr/bin/env bash
#
# HoneySOC — one-command honeypot deployment (Infrastructure as Code)
# ------------------------------------------------------------------
# Rebuilds the entire honeypot I set up by hand over two days:
#   SSH hardening -> UFW -> Docker -> customised Cowrie persona ->
#   fail2ban -> Telegram alert service.
#
# Target: a FRESH Ubuntu 24.04 VPS, run as root.
# Usage:
#   1) edit the CONFIG block below
#   2) scp this script to the server
#   3) bash deploy.sh
#
# Idempotent-ish: safe to re-run; it recreates configs and the container.
# WARNING: this intentionally exposes a honeypot on tcp/22 and tcp/23.
#          Only run it on a throwaway box you own.
set -euo pipefail

# ============================ CONFIG ============================
ADMIN_SSH_PORT=22222                 # real SSH moves here (key-only)
HONEY_HOSTNAME="prod-db-02"          # persona the attacker sees
KERNEL_VERSION="6.1.0-28-amd64"
KERNEL_BUILD="#1 SMP PREEMPT_DYNAMIC Debian 6.1.119-1 (2024-11-22)"
# Telegram alerting (leave blank to skip). Keep these OUT of git.
TELEGRAM_TOKEN="${TELEGRAM_TOKEN:-}"
TELEGRAM_CHAT_ID="${TELEGRAM_CHAT_ID:-}"
# ===============================================================

log() { echo -e "\n\033[1;34m[+] $*\033[0m"; }

# --- 0. sanity -------------------------------------------------
[ "$(id -u)" -eq 0 ] || { echo "run as root"; exit 1; }
if [ ! -s /root/.ssh/authorized_keys ]; then
  echo "REFUSING: no SSH key in /root/.ssh/authorized_keys."
  echo "Add your public key first, or you will lock yourself out."
  exit 1
fi

# --- 1. patch --------------------------------------------------
log "Updating base system"
export DEBIAN_FRONTEND=noninteractive
apt-get update -y && apt-get upgrade -y

# --- 2. SSH hardening -----------------------------------------
# First-match-wins drop-in named 00- so it beats cloud-init's 50-.
log "Hardening SSH -> port ${ADMIN_SSH_PORT}, keys only"
cat > /etc/ssh/sshd_config.d/00-honeysoc.conf <<EOF
Port ${ADMIN_SSH_PORT}
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin prohibit-password
EOF
sshd -t                              # validate BEFORE applying
systemctl restart ssh.socket 2>/dev/null || true
systemctl restart ssh

# --- 3. firewall (default-deny) -------------------------------
log "Configuring UFW (deny inbound; allow admin + honeypot ports)"
apt-get install -y ufw
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow ${ADMIN_SSH_PORT}/tcp      # me
ufw allow 22/tcp                     # honeypot SSH
ufw allow 23/tcp                     # honeypot Telnet
ufw --force enable

# --- 4. Docker -------------------------------------------------
log "Installing Docker"
apt-get install -y docker.io
systemctl enable --now docker

# --- 5. Cowrie persona (anti-fingerprinting) ------------------
# Consistent Debian-12 "database server" story: hostname, hosts,
# passwd all agree; default Cowrie tells (svr04 / Phil California) gone.
log "Building custom honeyfs persona (${HONEY_HOSTNAME})"
mkdir -p /root/cowrie-custom/honeyfs/etc
echo "${HONEY_HOSTNAME}" > /root/cowrie-custom/honeyfs/etc/hostname
cat > /root/cowrie-custom/honeyfs/etc/hosts <<EOF
127.0.0.1       localhost
127.0.1.1       ${HONEY_HOSTNAME}
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
EOF
cat > /root/cowrie-custom/honeyfs/etc/passwd <<'EOF'
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
_apt:x:42:65534::/nonexistent:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:998:998:systemd Network Management:/:/usr/sbin/nologin
messagebus:x:100:107::/nonexistent:/usr/sbin/nologin
sshd:x:101:65534::/run/sshd:/usr/sbin/nologin
mysql:x:102:110:MySQL Server,,,:/nonexistent:/bin/false
phil:x:1000:1000:Phil Turner,,,:/home/phil:/bin/bash
EOF

log "Launching Cowrie honeypot (SSH :22, Telnet :23)"
docker rm -f cowrie 2>/dev/null || true
docker run -d --name cowrie --restart unless-stopped \
  -p 22:2222 -p 23:2223 \
  -e COWRIE_TELNET_ENABLED=yes \
  -e COWRIE_HONEYPOT_HOSTNAME="${HONEY_HOSTNAME}" \
  -e COWRIE_HONEYPOT_CONTENTS_PATH=/cowrie/honeyfs \
  -e COWRIE_SHELL_KERNEL_VERSION="${KERNEL_VERSION}" \
  -e "COWRIE_SHELL_KERNEL_BUILD_STRING=${KERNEL_BUILD}" \
  -v cowrie-var:/cowrie/cowrie-git/var \
  -v /root/cowrie-custom/honeyfs:/cowrie/honeyfs:ro \
  cowrie/cowrie:latest

# --- 6. fail2ban (protect the REAL ssh, not the trap) ---------
log "Installing fail2ban on the admin SSH port"
apt-get install -y fail2ban
cat > /etc/fail2ban/jail.local <<EOF
[DEFAULT]
bantime  = 1h
findtime = 10m
maxretry = 4

[sshd]
enabled  = true
port     = ${ADMIN_SSH_PORT}
backend  = systemd
EOF
systemctl enable --now fail2ban
systemctl restart fail2ban

# --- 7. Telegram alerting service -----------------------------
if [ -n "$TELEGRAM_TOKEN" ] && [ -n "$TELEGRAM_CHAT_ID" ]; then
  log "Deploying Telegram alert service"
  mkdir -p /root/honeysoc-alerts
  cat > /root/honeysoc-alerts/.env <<EOF
TELEGRAM_TOKEN=${TELEGRAM_TOKEN}
TELEGRAM_CHAT_ID=${TELEGRAM_CHAT_ID}
EOF
  chmod 600 /root/honeysoc-alerts/.env
  # alert.py is shipped alongside this script
  if [ -f "$(dirname "$0")/alert.py" ]; then
    cp "$(dirname "$0")/alert.py" /root/honeysoc-alerts/alert.py
    cat > /etc/systemd/system/honeysoc-alerts.service <<'EOF'
[Unit]
Description=HoneySOC Telegram Alerts
After=network.target docker.service

[Service]
Type=simple
ExecStart=/usr/bin/python3 /root/honeysoc-alerts/alert.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable --now honeysoc-alerts
  else
    echo "    (alert.py not found next to script — skipping service)"
  fi
else
  echo "    (TELEGRAM_* not set — skipping alerting)"
fi

# --- done ------------------------------------------------------
log "Deployment complete."
echo "  Admin SSH : ssh -p ${ADMIN_SSH_PORT} root@<this-host>   (key only)"
echo "  Honeypot  : tcp/22 (SSH) + tcp/23 (Telnet)  -> Cowrie"
echo "  Logs      : docker volume cowrie-var (cowrie.json)"
docker ps --filter name=cowrie
