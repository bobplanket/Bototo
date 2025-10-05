#!/usr/bin/env bash
################################################################################
# AutoLLM Trader - Production Bootstrap Script for Debian 13
#
# This script is fully idempotent, failsafe, and configures a virgin VPS from
# scratch with all dependencies, security hardening, and production services.
#
# Usage: sudo ./bootstrap.sh [DOMAIN]
# Example: sudo ./bootstrap.sh bototo.willhardy.fr
#
# Requirements:
#   - Fresh Debian 13 VPS
#   - Root/sudo access
#   - Domain pointing to VPS IP (A record)
################################################################################
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")"/.. && pwd)"
LOG_FILE="/var/log/autollm-bootstrap.log"
ERROR_LOG="/var/log/autollm-bootstrap-errors.log"
DOMAIN="${1:-}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

################################################################################
# Logging & Error Handling
################################################################################

log() {
  local level="$1"
  shift
  local msg="$*"
  local timestamp=$(date '+%Y-%m-%d %H:%M:%S')

  case "$level" in
    INFO)  echo -e "${GREEN}[INFO]${NC} ${msg}" ;;
    WARN)  echo -e "${YELLOW}[WARN]${NC} ${msg}" ;;
    ERROR) echo -e "${RED}[ERROR]${NC} ${msg}" ;;
    DEBUG) echo -e "${BLUE}[DEBUG]${NC} ${msg}" ;;
  esac

  echo "[${timestamp}] [${level}] ${msg}" | tee -a "${LOG_FILE}"
}

log_error() {
  log ERROR "$@"
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >> "${ERROR_LOG}"
}

trap_error() {
  local line_no=$1
  local bash_lineno=$2
  local last_command="${BASH_COMMAND}"
  log_error "Command failed at line ${line_no}: ${last_command}"
  log_error "See ${ERROR_LOG} for details"
  exit 1
}

trap 'trap_error ${LINENO} ${BASH_LINENO}' ERR

################################################################################
# Pre-flight Checks
################################################################################

ensure_root() {
  if [[ "$(id -u)" -ne 0 ]]; then
    log ERROR "This script must run with sudo/root privileges"
    exit 1
  fi
}

ensure_debian13() {
  if [[ ! -f /etc/debian_version ]]; then
    log ERROR "This script requires Debian Linux"
    exit 1
  fi

  local version=$(cat /etc/debian_version | cut -d. -f1)
  if [[ "$version" -lt 13 ]]; then
    log WARN "Detected Debian ${version}. This script is optimized for Debian 13+"
  fi

  log INFO "Detected Debian $(cat /etc/debian_version)"
}

validate_domain() {
  if [[ -z "$DOMAIN" ]]; then
    log ERROR "Domain name required"
    echo ""
    echo "Usage: sudo ./bootstrap.sh DOMAIN"
    echo "Example: sudo ./bootstrap.sh bototo.willhardy.fr"
    exit 1
  fi

  log INFO "Domain: ${DOMAIN}"

  # Validate domain format
  if ! echo "$DOMAIN" | grep -qE '^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'; then
    log ERROR "Invalid domain format: ${DOMAIN}"
    exit 1
  fi

  # Check DNS resolution
  log INFO "Checking DNS resolution for ${DOMAIN}..."
  if ! host "$DOMAIN" >/dev/null 2>&1; then
    log WARN "Domain ${DOMAIN} does not resolve yet. Continuing anyway..."
    log WARN "Make sure to configure DNS A record pointing to this VPS"
  else
    local resolved_ip=$(host "$DOMAIN" | grep "has address" | head -1 | awk '{print $NF}')
    log INFO "Domain resolves to: ${resolved_ip}"
  fi
}

################################################################################
# Idempotency Framework
################################################################################

run_once() {
  local task_id="$1"
  local flag_file="/var/lib/autollm_bootstrap/${task_id}.done"

  if [[ -f "${flag_file}" ]]; then
    log DEBUG "Task already completed: ${task_id}"
    return 1
  fi

  mkdir -p "$(dirname "${flag_file}")"
  return 0
}

mark_done() {
  local task_id="$1"
  local flag_file="/var/lib/autollm_bootstrap/${task_id}.done"
  mkdir -p "$(dirname "${flag_file}")"
  touch "${flag_file}"
  log DEBUG "Task marked complete: ${task_id}"
}

safe_apt_install() {
  local max_retries=3
  local retry=0

  while [[ $retry -lt $max_retries ]]; do
    if DEBIAN_FRONTEND=noninteractive apt-get install -y "$@" 2>&1 | tee -a "${LOG_FILE}"; then
      return 0
    fi

    retry=$((retry + 1))
    log WARN "apt-get install failed, retry ${retry}/${max_retries}"
    sleep 5
  done

  log_error "Failed to install packages after ${max_retries} attempts: $*"
  return 1
}

################################################################################
# System User Management
################################################################################

ensure_user_trader() {
  if ! run_once user_trader; then return 0; fi

  log INFO "Creating non-root user: trader"

  if ! id trader >/dev/null 2>&1; then
    useradd --create-home --shell /bin/bash trader

    # Add to docker group (will be created later)
    groupadd -f docker
    usermod -aG docker trader

    log INFO "User 'trader' created"
  else
    log INFO "User 'trader' already exists"
  fi

  # Ensure .ssh directory
  mkdir -p /home/trader/.ssh
  chmod 700 /home/trader/.ssh
  chown -R trader:trader /home/trader/.ssh

  # Setup sudo without password for trader (operational convenience)
  if ! grep -q "^trader ALL=" /etc/sudoers.d/trader 2>/dev/null; then
    echo "trader ALL=(ALL) NOPASSWD: /usr/bin/docker, /usr/bin/docker-compose, /usr/bin/systemctl" > /etc/sudoers.d/trader
    chmod 440 /etc/sudoers.d/trader
    log INFO "Configured sudo for trader user"
  fi

  mark_done user_trader
}

################################################################################
# Base System Configuration
################################################################################

update_system() {
  if ! run_once system_update; then return 0; fi

  log INFO "Updating system packages..."

  apt-get update -y 2>&1 | tee -a "${LOG_FILE}"
  DEBIAN_FRONTEND=noninteractive apt-get upgrade -y 2>&1 | tee -a "${LOG_FILE}"

  mark_done system_update
}

install_base_packages() {
  if ! run_once base_packages; then return 0; fi

  log INFO "Installing base packages..."

  safe_apt_install \
    build-essential \
    git \
    curl \
    wget \
    unzip \
    jq \
    gnupg \
    lsb-release \
    ca-certificates \
    apt-transport-https \
    dnsutils \
    net-tools \
    htop \
    tmux \
    vim \
    ncdu \
    iotop \
    sysstat

  mark_done base_packages
}

configure_timezone() {
  if ! run_once timezone; then return 0; fi

  log INFO "Configuring timezone to UTC"

  timedatectl set-timezone UTC || log WARN "Failed to set timezone"

  mark_done timezone
}

################################################################################
# Security Hardening
################################################################################

hardening_ssh() {
  if ! run_once ssh_hardening; then return 0; fi

  log INFO "Hardening SSH configuration"

  # Backup original config
  cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup.$(date +%Y%m%d)

  # Apply hardening
  sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
  sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
  sed -i 's/^#\?PubkeyAuthentication.*/PubkeyAuthentication yes/' /etc/ssh/sshd_config
  sed -i 's/^#\?PermitEmptyPasswords.*/PermitEmptyPasswords no/' /etc/ssh/sshd_config
  sed -i 's/^#\?X11Forwarding.*/X11Forwarding no/' /etc/ssh/sshd_config
  sed -i 's/^#\?MaxAuthTries.*/MaxAuthTries 3/' /etc/ssh/sshd_config

  # Test config before restarting
  if sshd -t; then
    systemctl restart ssh
    log INFO "SSH hardening applied"
  else
    log_error "SSH config test failed, reverting"
    mv /etc/ssh/sshd_config.backup.$(date +%Y%m%d) /etc/ssh/sshd_config
    return 1
  fi

  mark_done ssh_hardening
}

install_unattended_upgrades() {
  if ! run_once unattended_upgrades; then return 0; fi

  log INFO "Configuring automatic security updates"

  safe_apt_install unattended-upgrades apt-listchanges

  # Configure for security updates only
  cat > /etc/apt/apt.conf.d/50unattended-upgrades <<'EOF'
Unattended-Upgrade::Origins-Pattern {
  "origin=Debian,codename=${distro_codename},label=Debian-Security";
};
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
EOF

  cat > /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF

  systemctl restart unattended-upgrades
  log INFO "Automatic security updates enabled"

  mark_done unattended_upgrades
}

configure_firewall() {
  if ! run_once firewall; then return 0; fi

  log INFO "Configuring UFW firewall"

  safe_apt_install ufw

  # Reset to defaults
  ufw --force reset

  # Default policies
  ufw default deny incoming
  ufw default allow outgoing

  # Essential ports
  ufw allow 22/tcp comment 'SSH'
  ufw allow 80/tcp comment 'HTTP'
  ufw allow 443/tcp comment 'HTTPS'

  # Application ports
  ufw allow 4222/tcp comment 'NATS'
  ufw allow 4002/tcp comment 'IBKR Paper'
  ufw allow 4001/tcp comment 'IBKR Live'

  # Rate limit SSH
  ufw limit 22/tcp

  # Enable firewall
  ufw --force enable

  log INFO "UFW firewall configured and enabled"

  mark_done firewall
}

configure_fail2ban() {
  if ! run_once fail2ban; then return 0; fi

  log INFO "Configuring fail2ban"

  safe_apt_install fail2ban

  # Custom configuration
  cat > /etc/fail2ban/jail.d/autollm.local <<'EOF'
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3
destemail = root@localhost
sendername = Fail2Ban
action = %(action_mwl)s

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
EOF

  systemctl enable fail2ban
  systemctl restart fail2ban

  log INFO "fail2ban configured and running"

  mark_done fail2ban
}

configure_auditd() {
  if ! run_once auditd; then return 0; fi

  log INFO "Installing auditd for security auditing"

  safe_apt_install auditd audispd-plugins

  systemctl enable auditd
  systemctl start auditd || log WARN "auditd may require reboot to start"

  log INFO "auditd installed"

  mark_done auditd
}

################################################################################
# Development Tools
################################################################################

install_python_environment() {
  if ! run_once python_env; then return 0; fi

  log INFO "Installing Python environment"

  safe_apt_install \
    python3 \
    python3-venv \
    python3-pip \
    python3-dev \
    libffi-dev \
    libssl-dev \
    pkg-config

  # Ensure pip is up to date
  python3 -m pip install --upgrade pip setuptools wheel

  mark_done python_env
}

install_poetry() {
  if ! run_once poetry_install; then return 0; fi

  log INFO "Installing Poetry 1.7.1"

  # Install as trader user
  su - trader -c 'curl -sSL https://install.python-poetry.org | python3 - --version 1.7.1' 2>&1 | tee -a "${LOG_FILE}"

  # Add to PATH in .bashrc
  if ! grep -q 'poetry/bin' /home/trader/.bashrc; then
    echo 'export PATH="$HOME/.local/bin:$PATH"' >> /home/trader/.bashrc
  fi

  log INFO "Poetry installed"

  mark_done poetry_install
}

install_nodejs() {
  if ! run_once nodejs_install; then return 0; fi

  log INFO "Installing Node.js 20 LTS"

  curl -fsSL https://deb.nodesource.com/setup_20.x | bash - 2>&1 | tee -a "${LOG_FILE}"
  safe_apt_install nodejs

  # Verify installation
  node --version | tee -a "${LOG_FILE}"
  npm --version | tee -a "${LOG_FILE}"

  log INFO "Node.js 20 installed"

  mark_done nodejs_install
}

install_talib() {
  if ! run_once ta_lib; then return 0; fi

  log INFO "Installing TA-Lib from source"

  # Install build dependencies
  safe_apt_install \
    libpq-dev \
    libsodium-dev \
    libxml2-dev \
    libxslt1-dev \
    zlib1g-dev \
    libncurses-dev \
    libjpeg-dev \
    libfreetype-dev \
    libopenblas-dev \
    gfortran \
    cmake

  # Build TA-Lib
  local build_dir="/tmp/ta-lib-build"
  mkdir -p "${build_dir}"
  cd "${build_dir}"

  log INFO "Downloading TA-Lib 0.4.0..."
  curl -fsSL http://prdownloads.sourceforge.net/ta-lib/ta-lib-0.4.0-src.tar.gz -o ta-lib.tar.gz
  tar -xzf ta-lib.tar.gz
  cd ta-lib

  log INFO "Compiling TA-Lib..."
  ./configure --prefix=/usr
  make
  make install
  ldconfig

  cd /
  rm -rf "${build_dir}"

  log INFO "TA-Lib installed successfully"

  mark_done ta_lib
}

install_age_sops() {
  if ! run_once age_sops; then return 0; fi

  log INFO "Installing age and sops for secret management"

  # Install age
  local age_version="1.1.1"
  wget -q "https://github.com/FiloSottile/age/releases/download/v${age_version}/age-v${age_version}-linux-amd64.tar.gz" -O /tmp/age.tar.gz
  tar -xzf /tmp/age.tar.gz -C /tmp
  mv /tmp/age/age /usr/local/bin/
  mv /tmp/age/age-keygen /usr/local/bin/
  chmod +x /usr/local/bin/age*
  rm -rf /tmp/age*

  # Install sops
  local sops_version="3.8.1"
  wget -q "https://github.com/getsops/sops/releases/download/v${sops_version}/sops-v${sops_version}.linux.amd64" -O /usr/local/bin/sops
  chmod +x /usr/local/bin/sops

  log INFO "age and sops installed"

  mark_done age_sops
}

################################################################################
# Container Runtime
################################################################################

install_docker() {
  if ! run_once docker_install; then return 0; fi

  log INFO "Installing Docker"

  # Add Docker's official GPG key
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
  chmod a+r /etc/apt/keyrings/docker.asc

  # Add Docker repository
  echo \
    "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian \
    $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
    tee /etc/apt/sources.list.d/docker.list > /dev/null

  apt-get update -y

  # Install Docker
  safe_apt_install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

  # Start and enable Docker
  systemctl enable docker
  systemctl start docker

  # Add trader to docker group
  usermod -aG docker trader

  # Verify installation
  docker --version | tee -a "${LOG_FILE}"

  log INFO "Docker installed successfully"

  mark_done docker_install
}

configure_docker_daemon() {
  if ! run_once docker_daemon; then return 0; fi

  log INFO "Configuring Docker daemon"

  mkdir -p /etc/docker

  cat > /etc/docker/daemon.json <<'EOF'
{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  },
  "live-restore": true,
  "userland-proxy": false
}
EOF

  systemctl restart docker

  log INFO "Docker daemon configured"

  mark_done docker_daemon
}

################################################################################
# Application Setup
################################################################################

setup_directories() {
  if ! run_once directories; then return 0; fi

  log INFO "Creating application directories"

  # Application data
  mkdir -p "${REPO_ROOT}/data/storage"
  mkdir -p "${REPO_ROOT}/data/parquet"
  mkdir -p "${REPO_ROOT}/reports"
  mkdir -p "${REPO_ROOT}/secrets"
  mkdir -p "${REPO_ROOT}/logs"

  # Monitoring
  mkdir -p /opt/autollm/{prometheus,grafana,loki}

  # Ensure proper ownership
  chown -R trader:trader "${REPO_ROOT}"
  chown -R trader:trader /opt/autollm

  log INFO "Directories created"

  mark_done directories
}

generate_secrets() {
  if ! run_once secrets; then return 0; fi

  log INFO "Generating cryptographic secrets"

  # Generate age key for sops
  if [[ ! -f "${REPO_ROOT}/secrets/age.key" ]]; then
    su - trader -c "age-keygen -o ${REPO_ROOT}/secrets/age.key"
    chmod 600 "${REPO_ROOT}/secrets/age.key"
    log INFO "Generated age key"
  fi

  # Generate signing keys
  su - trader -c "cd ${REPO_ROOT} && python3 - <<'PYSCRIPT'
import base64
import pathlib
import sys

try:
    import nacl.signing
except ImportError:
    import subprocess
    subprocess.check_call([sys.executable, '-m', 'pip', 'install', '--user', 'PyNaCl'])
    import nacl.signing

root = pathlib.Path('secrets')
root.mkdir(exist_ok=True)

for prefix in ('llm', 'risk'):
    key_file = root / f'{prefix}_signing_key.age'
    pub_file = root / f'{prefix}_pub.key'

    if not key_file.exists():
        key = nacl.signing.SigningKey.generate()
        key_file.write_text(base64.b64encode(bytes(key)).decode())
        pub_file.write_text(base64.b64encode(bytes(key.verify_key)).decode())
        key_file.chmod(0o600)
        pub_file.chmod(0o600)
        print(f'Generated {prefix} signing key')
    else:
        print(f'{prefix} signing key already exists')
PYSCRIPT
" 2>&1 | tee -a "${LOG_FILE}"

  # Set proper permissions
  chmod 700 "${REPO_ROOT}/secrets"
  chmod 600 "${REPO_ROOT}/secrets/"* 2>/dev/null || true
  chown -R trader:trader "${REPO_ROOT}/secrets"

  log INFO "Cryptographic secrets generated"

  mark_done secrets
}

configure_env_file() {
  if ! run_once env_file; then return 0; fi

  log INFO "Configuring .env file"

  if [[ ! -f "${REPO_ROOT}/.env" ]]; then
    cp "${REPO_ROOT}/.env.template" "${REPO_ROOT}/.env"
  fi

  # Generate strong JWT secret
  local jwt_secret=$(openssl rand -hex 32)
  sed -i "s|^JWT_SECRET=.*|JWT_SECRET=${jwt_secret}|" "${REPO_ROOT}/.env"

  # Generate strong database password
  local db_password=$(openssl rand -hex 16)
  sed -i "s|^POSTGRES_PASSWORD=.*|POSTGRES_PASSWORD=${db_password}|" "${REPO_ROOT}/.env"

  # Configure domain
  sed -i "s|^WEBAUTHN_RP_ID=.*|WEBAUTHN_RP_ID=${DOMAIN}|" "${REPO_ROOT}/.env"
  sed -i "s|^WEBAUTHN_ORIGIN=.*|WEBAUTHN_ORIGIN=https://${DOMAIN}|" "${REPO_ROOT}/.env"

  # Configure IBKR defaults (paper trading)
  sed -i "s|^IB_ENABLED=.*|IB_ENABLED=1|" "${REPO_ROOT}/.env"
  sed -i "s|^IB_HOST=.*|IB_HOST=ib-gateway|" "${REPO_ROOT}/.env"
  sed -i "s|^IB_PORT=.*|IB_PORT=4002|" "${REPO_ROOT}/.env"

  # Add IB Gateway credentials if not present
  if ! grep -q "IB_USERID" "${REPO_ROOT}/.env"; then
    cat >> "${REPO_ROOT}/.env" <<'IBKR'

# IB Gateway Configuration
IB_USERID=edemo
IB_PASSWORD=demouser
IB_TRADING_MODE=paper
IBKR
  fi

  # Set proper permissions
  chmod 600 "${REPO_ROOT}/.env"
  chown trader:trader "${REPO_ROOT}/.env"

  log INFO ".env file configured"

  mark_done env_file
}

generate_additional_secrets() {
  if ! run_once additional_passwords; then return 0; fi

  log INFO "Generating additional secure passwords"

  # Generate Grafana admin password
  local grafana_pass=$(openssl rand -base64 32)
  if ! grep -q "GF_SECURITY_ADMIN_PASSWORD" "${REPO_ROOT}/.env"; then
    echo "" >> "${REPO_ROOT}/.env"
    echo "# Grafana Admin (Generated)" >> "${REPO_ROOT}/.env"
    echo "GF_SECURITY_ADMIN_PASSWORD=${grafana_pass}" >> "${REPO_ROOT}/.env"
  fi

  # Save Grafana password securely
  echo "${grafana_pass}" > "${REPO_ROOT}/secrets/grafana_admin_password.txt"
  chmod 600 "${REPO_ROOT}/secrets/grafana_admin_password.txt"
  chown trader:trader "${REPO_ROOT}/secrets/grafana_admin_password.txt"

  # Generate VNC password for IB Gateway
  local vnc_pass=$(openssl rand -base64 12)
  if ! grep -q "VNC_PASSWORD" "${REPO_ROOT}/.env"; then
    echo "VNC_PASSWORD=${vnc_pass}" >> "${REPO_ROOT}/.env"
  fi
  echo "${vnc_pass}" > "${REPO_ROOT}/secrets/vnc_password.txt"
  chmod 600 "${REPO_ROOT}/secrets/vnc_password.txt"
  chown trader:trader "${REPO_ROOT}/secrets/vnc_password.txt"

  # Generate Redis password
  local redis_pass=$(openssl rand -base64 24)
  if ! grep -q "REDIS_PASSWORD" "${REPO_ROOT}/.env"; then
    echo "REDIS_PASSWORD=${redis_pass}" >> "${REPO_ROOT}/.env"
  fi

  log INFO "Additional passwords generated and saved to secrets/"
  log WARN "Grafana password: See secrets/grafana_admin_password.txt"

  mark_done additional_passwords
}

encrypt_secrets_with_sops() {
  if ! run_once encrypt_secrets; then return 0; fi

  log INFO "Encrypting secrets with sops"

  # Extract age public key
  local age_pubkey=$(grep "# public key:" "${REPO_ROOT}/secrets/age.key" | cut -d: -f2 | tr -d ' ')

  if [[ -z "$age_pubkey" ]]; then
    log ERROR "Could not extract age public key"
    return 1
  fi

  # Create .sops.yaml config
  cat > "${REPO_ROOT}/.sops.yaml" <<SOPS
creation_rules:
  - path_regex: \.env$
    age: ${age_pubkey}
    encrypted_regex: '^(.*PASSWORD.*|.*SECRET.*|.*TOKEN.*|.*KEY.*|.*USERID.*)$'
  - path_regex: secrets/.*\.enc$
    age: ${age_pubkey}
SOPS

  # Encrypt .env file
  export SOPS_AGE_KEY_FILE="${REPO_ROOT}/secrets/age.key"
  su - trader -c "cd ${REPO_ROOT} && SOPS_AGE_KEY_FILE=secrets/age.key sops --encrypt .env > .env.enc" 2>&1 | tee -a "${LOG_FILE}"

  if [[ ! -f "${REPO_ROOT}/.env.enc" ]]; then
    log WARN "SOPS encryption failed, keeping .env in plain text"
    log WARN "Install sops manually: https://github.com/getsops/sops"
    return 0
  fi

  # Secure original .env (keep for emergency)
  chmod 600 "${REPO_ROOT}/.env"
  chown trader:trader "${REPO_ROOT}/.env.enc"

  log INFO "Secrets encrypted with sops → .env.enc"
  log INFO "Original .env kept for emergency (chmod 600)"
  log WARN "Use scripts/docker-compose-sops.sh for operations"

  mark_done encrypt_secrets
}

create_sops_wrapper() {
  if ! run_once sops_wrapper; then return 0; fi

  log INFO "Creating sops wrapper scripts"

  mkdir -p "${REPO_ROOT}/scripts"

  # Docker Compose wrapper
  cat > "${REPO_ROOT}/scripts/docker-compose-sops.sh" <<'WRAPPER'
#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")"/.. && pwd)"
ENV_FILE="${REPO_ROOT}/.env"
ENV_FILE_ENC="${REPO_ROOT}/.env.enc"
AGE_KEY_FILE="${SOPS_AGE_KEY_FILE:-${REPO_ROOT}/secrets/age.key}"

load_env_file() {
  local file_path="$1"
  if [[ ! -f "${file_path}" ]]; then
    return
  fi

  set -a
  # shellcheck source=/dev/null
  source "${file_path}"
  set +a
}

if [[ -f "${ENV_FILE_ENC}" ]]; then
  if ! command -v sops >/dev/null 2>&1; then
    >&2 echo "[ERROR] sops is required to decrypt ${ENV_FILE_ENC}."
    exit 1
  fi

  if [[ ! -f "${AGE_KEY_FILE}" ]]; then
    >&2 echo "[ERROR] Age key not found at ${AGE_KEY_FILE}."
    exit 1
  fi

  tmp_env=$(mktemp)
  SOPS_AGE_KEY_FILE="${AGE_KEY_FILE}" sops --decrypt "${ENV_FILE_ENC}" > "${tmp_env}"
  load_env_file "${tmp_env}"
  rm -f "${tmp_env}"
else
  load_env_file "${ENV_FILE}"
fi

cd "${REPO_ROOT}/infra"
exec docker compose "$@"
WRAPPER

  chmod +x "${REPO_ROOT}/scripts/docker-compose-sops.sh"
  chown trader:trader "${REPO_ROOT}/scripts/docker-compose-sops.sh"

  # Update systemd service to use wrapper
  if [[ -f /etc/systemd/system/autollm-stack.service ]]; then
    sed -i "s|ExecStart=/usr/bin/docker compose up -d|ExecStart=${REPO_ROOT}/scripts/docker-compose-sops.sh up -d|" \
      /etc/systemd/system/autollm-stack.service
    sed -i "s|ExecStop=/usr/bin/docker compose down|ExecStop=${REPO_ROOT}/scripts/docker-compose-sops.sh down|" \
      /etc/systemd/system/autollm-stack.service
    systemctl daemon-reload
    log INFO "Updated systemd service to use sops wrapper"
  fi

  log INFO "SOPS wrappers created"

  mark_done sops_wrapper
}

install_precommit_hooks() {
  if ! run_once precommit_hooks; then return 0; fi

  log INFO "Installing pre-commit hooks"

  su - trader -c "cd ${REPO_ROOT} && python3 -m pip install --user pre-commit" 2>&1 | tee -a "${LOG_FILE}"

  local user_base
  user_base=$(su - trader -c "python3 -m site --user-base")
  su - trader -c "cd ${REPO_ROOT} && PATH=\"${user_base}/bin:\\$PATH\" pre-commit install" 2>&1 | tee -a "${LOG_FILE}"

  log INFO "Pre-commit hooks installed"

  mark_done precommit_hooks
}

configure_caddy() {
  if ! run_once caddy_config; then return 0; fi

  log INFO "Configuring Caddy reverse proxy for ${DOMAIN}"

  cat > "${REPO_ROOT}/infra/caddy/Caddyfile" <<CADDY
${DOMAIN} {
  encode zstd gzip

  # Automatic HTTPS with Let's Encrypt
  tls {
    protocols tls1.2 tls1.3
  }

  # Security headers
  header {
    Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
    X-Content-Type-Options "nosniff"
    X-Frame-Options "DENY"
    X-XSS-Protection "1; mode=block"
    Referrer-Policy "strict-origin-when-cross-origin"
    -Server
  }

  # API routes
  reverse_proxy /api/* gateway-api:8000

  # Admin UI
  reverse_proxy /admin/* gateway-api:8000

  # Monitoring dashboards (optional: add authentication)
  reverse_proxy /grafana/* grafana:3000
  reverse_proxy /prometheus/* prometheus:9090

  # Health check endpoint
  route /health {
    respond "ok" 200
  }

  # Rate limiting
  rate_limit {
    zone dynamic {
      key {http.request.remote}
      events 100
      window 1m
    }
  }
}

# Redirect www to non-www
www.${DOMAIN} {
  redir https://${DOMAIN}{uri} permanent
}
CADDY

  log INFO "Caddy configured for ${DOMAIN}"

  mark_done caddy_config
}

add_ib_gateway_to_compose() {
  if ! run_once ib_gateway; then return 0; fi

  log INFO "Adding IB Gateway to docker-compose.yml"

  # Check if already exists
  if grep -q "ib-gateway:" "${REPO_ROOT}/infra/docker-compose.yml"; then
    log INFO "IB Gateway already in docker-compose.yml"
    mark_done ib_gateway
    return 0
  fi

  # Backup original
  cp "${REPO_ROOT}/infra/docker-compose.yml" "${REPO_ROOT}/infra/docker-compose.yml.backup"

  # Insert ib-gateway before execution-ib
  awk '
  /^  execution-ib:/ {
    print "  ib-gateway:"
    print "    image: ghcr.io/gnzsnz/ib-gateway:latest"
    print "    environment:"
    print "      - TWS_USERID=\${IB_USERID:-edemo}"
    print "      - TWS_PASSWORD=\${IB_PASSWORD:-demouser}"
    print "      - TRADING_MODE=\${IB_TRADING_MODE:-paper}"
    print "      - VNC_SERVER_PASSWORD=\${VNC_PASSWORD:-autollm123}"
    print "    ports:"
    print "      - \"4002:4002\""
    print "      - \"4001:4001\""
    print "      - \"5900:5900\""
    print "    networks:"
    print "      - internal"
    print "    restart: unless-stopped"
    print "    healthcheck:"
    print "      test: [\"CMD\", \"nc\", \"-z\", \"localhost\", \"4002\"]"
    print "      interval: 30s"
    print "      timeout: 10s"
    print "      retries: 3"
    print "      start_period: 60s"
    print ""
  }
  { print }
  ' "${REPO_ROOT}/infra/docker-compose.yml.backup" > "${REPO_ROOT}/infra/docker-compose.yml"

  # Add ib-gateway to execution-ib depends_on
  sed -i '/execution-ib:/,/^  [^ ]/ {
    /depends_on:/,/^[^ ]/ {
      /depends_on:/a\
      - ib-gateway
    }
  }' "${REPO_ROOT}/infra/docker-compose.yml"

  log INFO "IB Gateway added to docker-compose.yml"

  mark_done ib_gateway
}

install_monitoring_stack() {
  if ! run_once monitoring_stack; then return 0; fi

  log INFO "Setting up monitoring stack"

  # Copy monitoring configs if they exist
  [[ -d "${REPO_ROOT}/infra/prometheus" ]] && cp -r "${REPO_ROOT}/infra/prometheus" /opt/autollm/ 2>/dev/null || true
  [[ -d "${REPO_ROOT}/infra/grafana" ]] && cp -r "${REPO_ROOT}/infra/grafana" /opt/autollm/ 2>/dev/null || true
  [[ -d "${REPO_ROOT}/infra/loki" ]] && cp -r "${REPO_ROOT}/infra/loki" /opt/autollm/ 2>/dev/null || true

  chown -R trader:trader /opt/autollm

  log INFO "Monitoring stack configured"

  mark_done monitoring_stack
}

################################################################################
# Systemd Services & Watchdog
################################################################################

configure_watchdog() {
  if ! run_once watchdog; then return 0; fi

  log INFO "Configuring systemd watchdog"

  cat > /etc/systemd/system/autollm-watchdog.service <<UNIT
[Unit]
Description=AutoLLM Trader Health Watchdog
After=network-online.target docker.service
Wants=network-online.target

[Service]
Type=simple
User=trader
Group=trader
Environment=PYTHONUNBUFFERED=1
WorkingDirectory=${REPO_ROOT}
ExecStart=/home/trader/.local/bin/poetry run python scripts/watchdog.py
Restart=always
RestartSec=30
StandardOutput=append:${REPO_ROOT}/logs/watchdog.log
StandardError=append:${REPO_ROOT}/logs/watchdog-error.log

[Install]
WantedBy=multi-user.target
UNIT

  systemctl daemon-reload
  systemctl enable autollm-watchdog.service

  log INFO "Watchdog service configured"

  mark_done watchdog
}

configure_docker_compose_service() {
  if ! run_once compose_service; then return 0; fi

  log INFO "Configuring docker-compose systemd service"

  cat > /etc/systemd/system/autollm-stack.service <<UNIT
[Unit]
Description=AutoLLM Trader Docker Stack
Requires=docker.service
After=docker.service network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
User=trader
Group=trader
WorkingDirectory=${REPO_ROOT}/infra
Environment="LIVE=0"
ExecStart=/usr/bin/docker compose up -d
ExecStop=/usr/bin/docker compose down
TimeoutStartSec=300
StandardOutput=append:${REPO_ROOT}/logs/compose.log
StandardError=append:${REPO_ROOT}/logs/compose-error.log

[Install]
WantedBy=multi-user.target
UNIT

  systemctl daemon-reload
  systemctl enable autollm-stack.service

  log INFO "Docker Compose service configured"

  mark_done compose_service
}

configure_healthcheck_cron() {
  if ! run_once healthcheck_cron; then return 0; fi

  log INFO "Configuring healthcheck cron"

  # Create healthcheck script if it doesn't exist
  if [[ ! -f "${REPO_ROOT}/scripts/healthcheck.sh" ]]; then
    cat > "${REPO_ROOT}/scripts/healthcheck.sh" <<'HEALTHCHECK'
#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")"/.. && pwd)"
cd "${REPO_ROOT}/infra"

# Check if all services are running
if ! docker compose ps --quiet --all | grep -q .; then
  echo "[ERROR] No docker containers running"
  exit 1
fi

# Check for unhealthy containers
unhealthy=$(docker compose ps --format json | jq -r 'select(.Health == "unhealthy") | .Name' || true)
if [[ -n "$unhealthy" ]]; then
  echo "[ERROR] Unhealthy containers: ${unhealthy}"
  exit 1
fi

# Check API health endpoint
if ! curl -sf http://localhost:8000/health >/dev/null; then
  echo "[ERROR] API health check failed"
  exit 1
fi

echo "[OK] All systems healthy"
HEALTHCHECK
    chmod +x "${REPO_ROOT}/scripts/healthcheck.sh"
    chown trader:trader "${REPO_ROOT}/scripts/healthcheck.sh"
  fi

  # Add cron job
  cat > /etc/cron.d/autollm-health <<CRON
# AutoLLM Trader Health Checks
*/5 * * * * trader ${REPO_ROOT}/scripts/healthcheck.sh >> ${REPO_ROOT}/logs/healthcheck.log 2>&1
CRON

  chmod 644 /etc/cron.d/autollm-health

  log INFO "Healthcheck cron configured"

  mark_done healthcheck_cron
}

################################################################################
# Final Steps
################################################################################

build_ui() {
  if ! run_once ui_build; then return 0; fi

  log INFO "Building admin UI"

  if [[ -d "${REPO_ROOT}/apps/gateway_api/ui" ]]; then
    cd "${REPO_ROOT}/apps/gateway_api/ui"

    # Install dependencies and build as trader user
    su - trader -c "cd ${REPO_ROOT}/apps/gateway_api/ui && npm install && npm run build" 2>&1 | tee -a "${LOG_FILE}"

    log INFO "Admin UI built successfully"
  else
    log WARN "Admin UI directory not found, skipping"
  fi

  mark_done ui_build
}

verify_installation() {
  log INFO "Verifying installation..."

  local errors=0

  # Check user
  if ! id trader >/dev/null 2>&1; then
    log_error "User 'trader' not found"
    errors=$((errors + 1))
  fi

  # Check Docker
  if ! docker --version >/dev/null 2>&1; then
    log_error "Docker not installed"
    errors=$((errors + 1))
  fi

  # Check directories
  for dir in "${REPO_ROOT}/data" "${REPO_ROOT}/secrets" "${REPO_ROOT}/logs"; do
    if [[ ! -d "$dir" ]]; then
      log_error "Directory missing: ${dir}"
      errors=$((errors + 1))
    fi
  done

  # Check .env
  if [[ ! -f "${REPO_ROOT}/.env" ]]; then
    log_error ".env file not found"
    errors=$((errors + 1))
  fi

  # Check secrets
  for secret in age.key llm_signing_key.age risk_signing_key.age; do
    if [[ ! -f "${REPO_ROOT}/secrets/${secret}" ]]; then
      log_error "Secret missing: ${secret}"
      errors=$((errors + 1))
    fi
  done

  if [[ $errors -eq 0 ]]; then
    log INFO "✓ Installation verification passed"
    return 0
  else
    log_error "Installation verification failed with ${errors} errors"
    return 1
  fi
}

print_summary() {
  local domain="$1"

  cat <<SUMMARY

${GREEN}╔════════════════════════════════════════════════════════════════════╗
║                                                                    ║
║         AutoLLM Trader - Bootstrap Complete! 🚀                   ║
║                                                                    ║
╚════════════════════════════════════════════════════════════════════╝${NC}

${BLUE}═══════════════════════════════════════════════════════════════════${NC}
${GREEN}DOMAIN CONFIGURATION${NC}
${BLUE}═══════════════════════════════════════════════════════════════════${NC}

  Domain:       https://${domain}
  Admin UI:     https://${domain}/admin
  API Docs:     https://${domain}/api/docs
  Grafana:      https://${domain}/grafana
  Prometheus:   https://${domain}/prometheus

${YELLOW}⚠ IMPORTANT: Ensure DNS A record points to this VPS IP${NC}

${BLUE}═══════════════════════════════════════════════════════════════════${NC}
${GREEN}NEXT STEPS${NC}
${BLUE}═══════════════════════════════════════════════════════════════════${NC}

1. ${YELLOW}Configure API Keys${NC} (edit ${REPO_ROOT}/.env):
   - OPENAI_API_KEY         (for LLM agents)
   - FINNHUB_API_KEY        (for market data)
   - IB_USERID/PASSWORD     (for real IBKR account)
   - SMTP credentials       (for email alerts)
   - TELEGRAM_BOT_TOKEN     (for Telegram alerts)

2. ${YELLOW}Start Services${NC}:
   ${GREEN}sudo systemctl start autollm-stack${NC}

   Or manually:
   ${GREEN}cd ${REPO_ROOT} && ./scripts/docker-compose-sops.sh up -d${NC}

3. ${YELLOW}View Logs${NC}:
   ${GREEN}cd ${REPO_ROOT} && ./scripts/docker-compose-sops.sh logs -f${NC}

4. ${YELLOW}Check Status${NC}:
   ${GREEN}cd ${REPO_ROOT} && ./scripts/docker-compose-sops.sh ps${NC}
  ${GREEN}curl https://${domain}/health${NC}

${BLUE}═══════════════════════════════════════════════════════════════════${NC}
${GREEN}IBKR TRADING CONFIGURATION${NC}
${BLUE}═══════════════════════════════════════════════════════════════════${NC}

${YELLOW}Paper Trading (DEFAULT - CONFIGURED):${NC}
  - IB_ENABLED=1
  - IB_PORT=4002
  - IB_USERID=edemo (demo account)
  - LIVE=0

${YELLOW}Real IBKR Paper Account:${NC}
  Update .env:
    IB_USERID=your_username
    IB_PASSWORD=your_password
    IB_ACCOUNT=DU1234567
  Then restart: ${GREEN}docker compose restart ib-gateway execution-ib${NC}

${YELLOW}Live Trading (PRODUCTION):${NC}
  ⚠️  ONLY after extensive paper testing!
  Update .env:
    LIVE=1
    IB_PORT=4001
    IB_TRADING_MODE=live
    IB_ACCOUNT=U1234567

${BLUE}═══════════════════════════════════════════════════════════════════${NC}
${GREEN}MONITORING & OPERATIONS${NC}
${BLUE}═══════════════════════════════════════════════════════════════════${NC}

  Logs:          ${REPO_ROOT}/logs/
  Bootstrap Log: /var/log/autollm-bootstrap.log
  Error Log:     /var/log/autollm-bootstrap-errors.log

  Services:
    • autollm-stack        (main docker compose)
    • autollm-watchdog     (health monitoring)

  Healthcheck runs every 5 minutes via cron

${BLUE}═══════════════════════════════════════════════════════════════════${NC}
${GREEN}SECURITY NOTES${NC}
${BLUE}═══════════════════════════════════════════════════════════════════${NC}

  ✓ SSH hardened (password auth disabled)
  ✓ UFW firewall configured
  ✓ fail2ban active
  ✓ Automatic security updates enabled
  ✓ Secrets generated in ${REPO_ROOT}/secrets/
  ✓ Grafana admin password: secrets/grafana_admin_password.txt
  ✓ VNC password: secrets/vnc_password.txt
  ✓ SOPS encryption: .env.enc (if sops available)

  ${YELLOW}⚠ BACKUP YOUR SECRETS DIRECTORY!${NC}
  ${YELLOW}⚠ Keep .env/.env.enc files secure (contains API keys)${NC}
  ${YELLOW}⚠ Use scripts/docker-compose-sops.sh for operations${NC}

${BLUE}═══════════════════════════════════════════════════════════════════${NC}
${GREEN}USEFUL COMMANDS${NC}
${BLUE}═══════════════════════════════════════════════════════════════════${NC}

  Start:    ${GREEN}sudo systemctl start autollm-stack${NC}
  Stop:     ${GREEN}sudo systemctl stop autollm-stack${NC}
  Status:   ${GREEN}sudo systemctl status autollm-stack${NC}
  Logs:     ${GREEN}cd ${REPO_ROOT}/infra && docker compose logs -f${NC}
  Restart:  ${GREEN}docker compose restart SERVICE_NAME${NC}

  Kill Switch:  ${GREEN}cd ${REPO_ROOT} && make kill${NC}
  Backup:       ${GREEN}tar czf backup.tar.gz .env secrets/ data/${NC}

${BLUE}═══════════════════════════════════════════════════════════════════${NC}

For detailed documentation:
  • VPS Setup:        VPS_IBKR_SETUP.md
  • Quick Start:      QUICK_START_VPS.md
  • Production Tasks: PRODUCTION_READY_TASKLIST.md
  • Architecture:     README.md

${GREEN}Installation completed at: $(date)${NC}
${GREEN}Bootstrap log saved to: /var/log/autollm-bootstrap.log${NC}

${YELLOW}Ready to trade! 📈${NC}

SUMMARY
}

################################################################################
# Main Execution Flow
################################################################################

main() {
  echo "╔════════════════════════════════════════════════════════════════════╗"
  echo "║                                                                    ║"
  echo "║       AutoLLM Trader - Production Bootstrap for Debian 13         ║"
  echo "║                                                                    ║"
  echo "╚════════════════════════════════════════════════════════════════════╝"
  echo ""

  # Pre-flight checks
  ensure_root
  ensure_debian13
  validate_domain

  log INFO "Starting bootstrap for domain: ${DOMAIN}"
  log INFO "Repository root: ${REPO_ROOT}"

  # Phase 1: System Setup
  log INFO "=== Phase 1: System Setup ==="
  update_system
  install_base_packages
  configure_timezone
  ensure_user_trader

  # Phase 2: Security Hardening
  log INFO "=== Phase 2: Security Hardening ==="
  hardening_ssh
  install_unattended_upgrades
  configure_firewall
  configure_fail2ban
  configure_auditd

  # Phase 3: Development Tools
  log INFO "=== Phase 3: Development Tools ==="
  install_python_environment
  install_poetry
  install_nodejs
  install_talib
  install_age_sops

  # Phase 4: Container Runtime
  log INFO "=== Phase 4: Container Runtime ==="
  install_docker
  configure_docker_daemon

  # Phase 5: Application Configuration
  log INFO "=== Phase 5: Application Configuration ==="
  setup_directories
  generate_secrets
  configure_env_file
  generate_additional_secrets  # NEW: Grafana, VNC, Redis passwords
  encrypt_secrets_with_sops    # NEW: SOPS encryption
  create_sops_wrapper          # NEW: Wrapper scripts
  install_precommit_hooks      # NEW: Local tooling
  configure_caddy
  add_ib_gateway_to_compose
  install_monitoring_stack

  # Phase 6: Services & Automation
  log INFO "=== Phase 6: Services & Automation ==="
  configure_watchdog
  configure_docker_compose_service
  configure_healthcheck_cron

  # Phase 7: Build & Verify
  log INFO "=== Phase 7: Build & Verification ==="
  build_ui
  verify_installation

  # Print summary
  print_summary "${DOMAIN}"

  log INFO "Bootstrap completed successfully!"
  log INFO "Log file: ${LOG_FILE}"

  return 0
}

# Run main function
main "$@"
