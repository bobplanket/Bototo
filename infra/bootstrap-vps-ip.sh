#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")"/.. && pwd)"
LOG_FILE="/var/log/autollm-bootstrap.log"

log() {
  local msg="$1"
  echo "[BOOTSTRAP] ${msg}" | tee -a "${LOG_FILE}"
}

ensure_root() {
  if [[ "$(id -u)" -ne 0 ]]; then
    log "This script must run with sudo/root privileges."
    exit 1
  fi
}

run_once() {
  local flag_file="/var/lib/autollm_bootstrap/$1"
  if [[ -f "${flag_file}" ]]; then
    return 1
  fi
  mkdir -p "$(dirname "${flag_file}")"
  touch "${flag_file}"
  return 0
}

apt_install() {
  DEBIAN_FRONTEND=noninteractive apt-get install -y "$@"
}

detect_vps_ip() {
  log "Detecting VPS public IP address"
  local ip=""
  # Try multiple services for reliability
  ip=$(curl -4 -sf ifconfig.me 2>/dev/null || true)
  if [[ -z "$ip" ]]; then
    ip=$(curl -4 -sf ipinfo.io/ip 2>/dev/null || true)
  fi
  if [[ -z "$ip" ]]; then
    ip=$(curl -4 -sf icanhazip.com 2>/dev/null || true)
  fi
  if [[ -z "$ip" ]]; then
    log "ERROR: Could not detect public IP address"
    exit 1
  fi
  log "Detected public IP: ${ip}"
  echo "${ip}"
}

hardening_ssh() {
  run_once ssh_hardening || return 0
  log "Hardening SSH daemon"
  sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
  sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
  systemctl restart ssh
}

ensure_user_trader() {
  run_once user_trader || return 0
  log "Ensuring non-root user trader exists"
  if ! id trader >/dev/null 2>&1; then
    useradd --create-home --shell /bin/bash trader
  fi
  mkdir -p /home/trader/.ssh
  chmod 700 /home/trader/.ssh
  chown -R trader:trader /home/trader/.ssh
}

install_base_packages() {
  run_once base_packages || return 0
  log "Installing base packages"
  apt-get update -y
  apt_install build-essential git curl wget software-properties-common unzip jq gnupg lsb-release ufw fail2ban tmux htop python3 python3-venv python3-pip age sops libffi-dev libssl-dev pkg-config libpq-dev libsodium-dev libxml2-dev libxslt1-dev zlib1g-dev libncurses5-dev libdbus-1-dev libglib2.0-dev libnss3-dev libx11-dev libxkbfile-dev libharfbuzz-dev libsecret-1-dev libwebkit2gtk-4.0-dev libjpeg-dev libfreetype6-dev libatlas-base-dev gfortran cmake
}

install_unattended_upgrades() {
  run_once unattended_upgrades || return 0
  log "Configuring unattended-upgrades"
  apt_install unattended-upgrades
  dpkg-reconfigure --priority=low unattended-upgrades
}

configure_firewall() {
  run_once firewall || return 0
  log "Configuring UFW firewall"
  ufw default deny incoming
  ufw default allow outgoing
  ufw allow 22/tcp
  ufw allow 80/tcp
  ufw allow 443/tcp
  ufw allow 4222/tcp  # NATS
  ufw allow 9090/tcp  # Prometheus
  ufw allow 4002/tcp  # IBKR paper gateway
  ufw allow 4001/tcp  # IBKR live gateway (optional)
  ufw --force enable
}

configure_fail2ban() {
  run_once fail2ban || return 0
  log "Configuring fail2ban"
  cat <<'JAIL' >/etc/fail2ban/jail.d/autollm.local
[sshd]
enabled = true
filter = sshd
port    = ssh
logpath = /var/log/auth.log
maxretry = 4
findtime = 600
bantime = 3600
JAIL
  systemctl enable --now fail2ban
}

configure_auditd() {
  run_once auditd || return 0
  log "Installing auditd"
  apt_install auditd audispd-plugins
  systemctl enable --now auditd
}

install_node() {
  run_once node_install || return 0
  log "Installing Node.js 20 LTS"
  curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
  apt_install nodejs
}

install_poetry() {
  run_once poetry_install || return 0
  log "Installing Poetry"
  curl -sSL https://install.python-poetry.org | python3 - --version 1.7.1
}

install_talib() {
  run_once ta_lib || return 0
  log "Installing TA-Lib binaries"
  local build_dir="/tmp/ta-lib"
  mkdir -p "${build_dir}"
  cd "${build_dir}"
  curl -fsSL http://prdownloads.sourceforge.net/ta-lib/ta-lib-0.4.0-src.tar.gz -o ta-lib.tar.gz
  tar -xzf ta-lib.tar.gz
  cd ta-lib-0.4.0
  ./configure --prefix=/usr
  make
  make install
  cd /
  rm -rf "${build_dir}"
}

install_docker_rootless() {
  run_once docker_rootless || return 0
  log "Installing Docker (rootless)"
  apt_install uidmap dbus-user-session
  curl -fsSL https://get.docker.com | sh
  usermod -aG docker trader
  su - trader -c "dockerd-rootless-setuptool.sh install" || log "Rootless mode setup skipped (may need manual config)"
}

setup_compose() {
  run_once docker_compose || return 0
  log "Installing Docker Compose plugin"
  mkdir -p /usr/lib/docker/cli-plugins
  curl -SL https://github.com/docker/compose/releases/download/v2.24.5/docker-compose-linux-x86_64 -o /usr/lib/docker/cli-plugins/docker-compose
  chmod +x /usr/lib/docker/cli-plugins/docker-compose
}

install_monitoring_stack() {
  run_once monitoring_stack || return 0
  log "Preparing monitoring stack directories"
  mkdir -p /opt/autollm/{prometheus,grafana,loki}
  cp -r "${REPO_ROOT}/infra/prometheus" /opt/autollm/prometheus 2>/dev/null || true
  cp -r "${REPO_ROOT}/infra/grafana" /opt/autollm/grafana 2>/dev/null || true
  cp -r "${REPO_ROOT}/infra/loki" /opt/autollm/loki 2>/dev/null || true
  chown -R trader:trader /opt/autollm
}

setup_age_keys() {
  run_once age_keys || return 0
  log "Preparing age/sops key storage"
  mkdir -p "${REPO_ROOT}/secrets"
  if [[ ! -f "${REPO_ROOT}/secrets/age.key" ]]; then
    age-keygen -o "${REPO_ROOT}/secrets/age.key"
  fi
  chown -R trader:trader "${REPO_ROOT}/secrets"
  chmod 600 "${REPO_ROOT}/secrets/age.key"
}

generate_secrets() {
  run_once generate_secrets || return 0
  log "Generating cryptographic secrets"

  # Generate JWT secret
  local jwt_secret=$(openssl rand -hex 32)

  # Generate signing keys using Python
  su - trader -c "cd ${REPO_ROOT} && python3 - <<'PY'
import base64
import pathlib
try:
    import nacl.signing
except ImportError:
    import subprocess
    subprocess.check_call(['pip3', 'install', '--user', 'PyNaCl'])
    import nacl.signing

root = pathlib.Path('${REPO_ROOT}/secrets')
root.mkdir(exist_ok=True)

for prefix in ('llm', 'risk'):
    key_file = root / f'{prefix}_signing_key.age'
    pub_file = root / f'{prefix}_pub.key'
    if not key_file.exists():
        key = nacl.signing.SigningKey.generate()
        key_file.write_text(base64.b64encode(bytes(key)).decode())
        pub_file.write_text(base64.b64encode(bytes(key.verify_key)).decode())
        print(f'Generated {prefix} signing key')
PY
"

  # Update .env if it exists, otherwise create from template
  if [[ -f "${REPO_ROOT}/.env" ]]; then
    sed -i "s/^JWT_SECRET=.*/JWT_SECRET=${jwt_secret}/" "${REPO_ROOT}/.env"
  else
    cp "${REPO_ROOT}/.env.template" "${REPO_ROOT}/.env"
    sed -i "s/^JWT_SECRET=.*/JWT_SECRET=${jwt_secret}/" "${REPO_ROOT}/.env"
  fi

  chown trader:trader "${REPO_ROOT}/.env"
  chmod 600 "${REPO_ROOT}/.env"
  log "Generated JWT secret and signing keys"
}

configure_caddy_ip() {
  local vps_ip="$1"
  log "Configuring Caddy for IP-based HTTPS: ${vps_ip}"

  cat > "${REPO_ROOT}/infra/caddy/Caddyfile" <<CADDY
https://${vps_ip} {
  encode zstd gzip

  tls internal {
    on_demand
  }

  # Gateway API routes
  reverse_proxy /api/* gateway-api:8000
  reverse_proxy /admin/* gateway-api:8000

  # Monitoring dashboards
  reverse_proxy /grafana/* grafana:3000
  reverse_proxy /prometheus/* prometheus:9090

  # Health check
  route /health {
    respond "ok" 200
  }
}

# Redirect HTTP to HTTPS
http://${vps_ip} {
  redir https://${vps_ip}{uri} permanent
}
CADDY

  log "Caddy configured for https://${vps_ip}"
}

configure_env_for_ip() {
  local vps_ip="$1"
  log "Updating .env for IP-based deployment"

  # Update WebAuthn settings for IP address
  sed -i "s|^WEBAUTHN_RP_ID=.*|WEBAUTHN_RP_ID=${vps_ip}|" "${REPO_ROOT}/.env"
  sed -i "s|^WEBAUTHN_ORIGIN=.*|WEBAUTHN_ORIGIN=https://${vps_ip}|" "${REPO_ROOT}/.env"

  log "Updated WebAuthn configuration for IP: ${vps_ip}"
  log "NOTE: WebAuthn may have browser compatibility issues with IP addresses"
  log "Safari/iOS require domain names; use TOTP fallback for those devices"
}

add_ib_gateway_to_compose() {
  run_once ib_gateway_compose || return 0
  log "Adding IB Gateway container to docker-compose.yml"

  # Check if ib-gateway already exists
  if grep -q "ib-gateway:" "${REPO_ROOT}/infra/docker-compose.yml"; then
    log "IB Gateway already configured in docker-compose.yml"
    return 0
  fi

  # Insert ib-gateway service before execution-ib service
  local tmp_file="${REPO_ROOT}/infra/docker-compose.yml.tmp"
  awk '
  /^  execution-ib:/ {
    print "  ib-gateway:"
    print "    image: ghcr.io/gnzsnz/ib-gateway:latest"
    print "    environment:"
    print "      - TWS_USERID=${IB_USERID:-edemo}"
    print "      - TWS_PASSWORD=${IB_PASSWORD:-demouser}"
    print "      - TRADING_MODE=${IB_TRADING_MODE:-paper}"
    print "      - VNC_SERVER_PASSWORD=password"
    print "    ports:"
    print "      - \"4002:4002\"  # Paper trading"
    print "      - \"4001:4001\"  # Live trading"
    print "      - \"5900:5900\"  # VNC for debugging"
    print "    networks:"
    print "      - internal"
    print "    restart: unless-stopped"
    print "    healthcheck:"
    print "      test: [\"CMD\", \"nc\", \"-z\", \"localhost\", \"4002\"]"
    print "      interval: 30s"
    print "      timeout: 10s"
    print "      retries: 3"
    print ""
  }
  { print }
  ' "${REPO_ROOT}/infra/docker-compose.yml" > "${tmp_file}"

  mv "${tmp_file}" "${REPO_ROOT}/infra/docker-compose.yml"

  # Update execution-ib to depend on ib-gateway
  sed -i '/execution-ib:/,/^  [^ ]/ {
    /depends_on:/a\
      - ib-gateway
  }' "${REPO_ROOT}/infra/docker-compose.yml"

  log "IB Gateway container added to docker-compose.yml"
}

update_env_for_ibkr() {
  log "Checking IBKR configuration in .env"

  # Add IB credentials if not present
  if ! grep -q "IB_USERID" "${REPO_ROOT}/.env"; then
    cat >> "${REPO_ROOT}/.env" <<'IBENV'

# IB Gateway Credentials (paper trading defaults)
IB_USERID=edemo
IB_PASSWORD=demouser
IB_TRADING_MODE=paper
IBENV
    log "Added IB Gateway credentials to .env (using paper trading defaults)"
  fi

  log "IBKR configuration ready"
  log "To use real account, update IB_USERID, IB_PASSWORD in .env"
  log "For live trading, set IB_TRADING_MODE=live and IB_PORT=4001"
}

create_data_directories() {
  run_once data_dirs || return 0
  log "Creating data directories"
  mkdir -p "${REPO_ROOT}/data/storage"
  mkdir -p "${REPO_ROOT}/reports"
  chown -R trader:trader "${REPO_ROOT}/data"
  chown -R trader:trader "${REPO_ROOT}/reports"
}

configure_watchdog() {
  run_once watchdog || return 0
  log "Configuring systemd watchdog timers"
  cat <<UNIT >/etc/systemd/system/autollm-watchdog.service
[Unit]
Description=AutoLLM Health Watchdog
After=network-online.target

[Service]
Type=simple
User=trader
Environment=PYTHONUNBUFFERED=1
WorkingDirectory=${REPO_ROOT}
ExecStart=/home/trader/.local/bin/poetry run python scripts/watchdog.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
UNIT
  systemctl daemon-reload
  systemctl enable autollm-watchdog.service || log "Watchdog service will be enabled after first compose up"
}

configure_healthchecks() {
  run_once healthchecks || return 0
  log "Setting up healthcheck cron"
  cat <<CRON >/etc/cron.d/autollm-health
*/5 * * * * trader ${REPO_ROOT}/scripts/healthcheck.sh >> /var/log/autollm-health.log 2>&1
CRON
}

print_completion_summary() {
  local vps_ip="$1"
  log "=========================================="
  log "Bootstrap completed successfully!"
  log "=========================================="
  log ""
  log "VPS Public IP: ${vps_ip}"
  log "Admin UI: https://${vps_ip}/admin"
  log "API Docs: https://${vps_ip}/api/docs"
  log "Grafana: https://${vps_ip}/grafana"
  log "Prometheus: https://${vps_ip}/prometheus"
  log ""
  log "IMPORTANT NEXT STEPS:"
  log "1. Review and update ${REPO_ROOT}/.env with your API keys:"
  log "   - OPENAI_API_KEY"
  log "   - FINNHUB_API_KEY"
  log "   - IB_USERID, IB_PASSWORD (for real IBKR account)"
  log "   - SMTP and Telegram credentials"
  log ""
  log "2. For IBKR paper trading (DEFAULT):"
  log "   - Uses demo account (edemo/demouser)"
  log "   - Set IB_ENABLED=1 in .env"
  log "   - Port 4002 (paper)"
  log ""
  log "3. For IBKR live trading:"
  log "   - Set IB_USERID and IB_PASSWORD in .env"
  log "   - Set IB_TRADING_MODE=live in .env"
  log "   - Set IB_PORT=4001 in .env"
  log "   - Set LIVE=1 in .env"
  log ""
  log "4. Start services:"
  log "   cd ${REPO_ROOT}/infra"
  log "   docker compose up -d"
  log ""
  log "5. View logs:"
  log "   docker compose logs -f"
  log ""
  log "6. Test connection:"
  log "   curl -k https://${vps_ip}/health"
  log ""
  log "SECURITY NOTES:"
  log "- Using self-signed certificate (browser will show warning)"
  log "- WebAuthn may not work on Safari/iOS with IP addresses"
  log "- Use TOTP authentication as fallback"
  log "- Generated JWT secret and signing keys in ${REPO_ROOT}/secrets/"
  log "- Keep secrets/ directory secure and backed up!"
  log ""
  log "For detailed IBKR setup guide, see VPS_IBKR_SETUP.md"
  log "=========================================="
}

main() {
  ensure_root
  log "Starting VPS IP-based bootstrap sequence"

  # Detect VPS IP first
  local vps_ip
  vps_ip=$(detect_vps_ip)

  # System hardening and base setup
  ensure_user_trader
  install_base_packages
  hardening_ssh
  install_unattended_upgrades
  configure_firewall
  configure_fail2ban
  configure_auditd

  # Development tools
  install_node
  install_poetry
  install_talib

  # Container runtime
  install_docker_rootless
  setup_compose

  # Application setup
  install_monitoring_stack
  create_data_directories
  setup_age_keys
  generate_secrets

  # IP-based configuration
  configure_caddy_ip "${vps_ip}"
  configure_env_for_ip "${vps_ip}"

  # IBKR specific setup
  add_ib_gateway_to_compose
  update_env_for_ibkr

  # Operational tools
  configure_watchdog
  configure_healthchecks

  # Set ownership
  chown -R trader:trader "${REPO_ROOT}"

  # Summary
  print_completion_summary "${vps_ip}"
}

main "$@"