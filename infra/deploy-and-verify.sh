#!/bin/bash
set -e

echo "╔════════════════════════════════════════════════════════════════╗"
echo "║     Déploiement AutoLLM Trader - Vérification complète        ║"
echo "╚════════════════════════════════════════════════════════════════╝"

# Couleurs
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_step() {
    echo -e "\n${BLUE}▶ $1${NC}"
}

# Fonction pour attendre qu'un conteneur soit sain
wait_for_healthy() {
    local service=$1
    local max_wait=${2:-120}
    local waited=0
    
    log_info "Attente du démarrage de $service..."
    while [ $waited -lt $max_wait ]; do
        if docker compose ps $service 2>/dev/null | grep -q "Up"; then
            log_info "$service est actif"
            return 0
        fi
        sleep 2
        waited=$((waited + 2))
    done
    
    log_error "$service n'a pas démarré après ${max_wait}s"
    return 1
}

# Fonction pour afficher les logs en cas d'erreur
show_logs_on_error() {
    local service=$1
    log_error "Logs de $service:"
    docker compose logs --tail=50 $service
}

cd /opt/autollm-trader/Bototo

# ═══════════════════════════════════════════════════════════════
log_step "ÉTAPE 1: Mise à jour du code"
# ═══════════════════════════════════════════════════════════════
git fetch origin
BEFORE=$(git rev-parse --short HEAD)
git reset --hard origin/main
AFTER=$(git rev-parse --short HEAD)
log_info "Code mis à jour: $BEFORE → $AFTER"

# ═══════════════════════════════════════════════════════════════
log_step "ÉTAPE 2: Nettoyage Docker"
# ═══════════════════════════════════════════════════════════════
log_info "Arrêt de tous les conteneurs..."
docker compose -f infra/docker-compose.yml down -v 2>/dev/null || true
sudo systemctl stop autollm-stack 2>/dev/null || true

log_info "Nettoyage du cache Docker..."
docker system prune -af --volumes 2>/dev/null || true

# ═══════════════════════════════════════════════════════════════
log_step "ÉTAPE 3: Configuration de l'environnement"
# ═══════════════════════════════════════════════════════════════

if [ ! -f .env ]; then
    log_warn ".env n'existe pas, création depuis template..."
    cp .env.template .env
fi

log_info "Lecture des secrets depuis l'environnement ou .env existant..."

# Récupérer les valeurs depuis .env existant
get_env_value() {
    local key=$1
    local default=$2
    local value=$(grep "^${key}=" .env 2>/dev/null | cut -d'=' -f2- || echo "")
    if [ -z "$value" ]; then
        echo "$default"
    else
        echo "$value"
    fi
}

# Créer le fichier de mise à jour avec les valeurs préservées ou par défaut
cat > /tmp/env_updates.txt << ENVEOF
IB_USERID=$(get_env_value "IB_USERID" "oobudw311")
IB_PASSWORD=$(get_env_value "IB_PASSWORD" "cocsap-qijtA4-vodkih")
IB_ACCOUNT=$(get_env_value "IB_ACCOUNT" "DUN122374")
IB_ENABLED=1
IB_TRADING_MODE=paper
LIVE=0
IB_HOST=ib-gateway
IB_PORT=4002
IB_CLIENT_ID=17
VNC_PASSWORD=$(get_env_value "VNC_PASSWORD" "autollm123")
REDIS_HOST=$(get_env_value "REDIS_HOST" "redis")
REDIS_PORT=$(get_env_value "REDIS_PORT" "6379")
REDIS_USERNAME=$(get_env_value "REDIS_USERNAME" "default")
REDIS_PASSWORD=$(get_env_value "REDIS_PASSWORD" "")
REDIS_DB=0
REDIS_TLS_ENABLED=$(get_env_value "REDIS_TLS_ENABLED" "false")
REDIS_URL=$(get_env_value "REDIS_URL" "")
OPENAI_API_KEY=$(get_env_value "OPENAI_API_KEY" "your_openai_key")
FINNHUB_API_KEY=$(get_env_value "FINNHUB_API_KEY" "your_finnhub_key")
ENVEOF

log_info "Configuration IBKR Paper Trading et autres services..."

while IFS='=' read -r key value; do
    if grep -q "^${key}=" .env; then
        sed -i "s|^${key}=.*|${key}=${value}|" .env
    else
        echo "${key}=${value}" >> .env
    fi
done < /tmp/env_updates.txt

rm /tmp/env_updates.txt

# Générer POSTGRES_PASSWORD si absent
if ! grep -q "^POSTGRES_PASSWORD=" .env || [ -z "$(grep '^POSTGRES_PASSWORD=' .env | cut -d'=' -f2)" ]; then
    log_info "Génération du mot de passe Postgres..."
    POSTGRES_PWD=$(openssl rand -hex 24)
    if grep -q "^POSTGRES_PASSWORD=" .env; then
        sed -i "s|^POSTGRES_PASSWORD=.*|POSTGRES_PASSWORD=${POSTGRES_PWD}|" .env
    else
        echo "POSTGRES_PASSWORD=${POSTGRES_PWD}" >> .env
    fi
fi

log_info "Fichier .env configuré ✓"

# ═══════════════════════════════════════════════════════════════
log_step "ÉTAPE 4: Construction des images Docker"
# ═══════════════════════════════════════════════════════════════
cd infra

log_info "Construction des images (peut prendre plusieurs minutes)..."
if ! docker compose --env-file ../.env build --no-cache 2>&1 | tee /tmp/docker-build.log; then
    log_error "Échec de la construction Docker"
    tail -50 /tmp/docker-build.log
    exit 1
fi

log_info "Images construites avec succès ✓"

# ═══════════════════════════════════════════════════════════════
log_step "ÉTAPE 5: Démarrage des services (ordre séquentiel)"
# ═══════════════════════════════════════════════════════════════

# 5.1 Infrastructure de base
log_info "Démarrage de l'infrastructure de base..."
docker compose --env-file ../.env up -d postgres redis nats

wait_for_healthy "postgres" 60 || {
    show_logs_on_error "postgres"
    exit 1
}

wait_for_healthy "redis" 30 || {
    show_logs_on_error "redis"
    exit 1
}

wait_for_healthy "nats" 30 || {
    show_logs_on_error "nats"
    exit 1
}

log_info "Infrastructure de base démarrée ✓"

# 5.2 Services de monitoring
log_info "Démarrage du monitoring..."
docker compose --env-file ../.env up -d prometheus prometheus-pushgateway loki promtail grafana alertmanager

sleep 10
log_info "Monitoring démarré ✓"

# 5.3 IB Gateway (optionnel, peut échouer)
log_info "Démarrage d'IB Gateway..."
docker compose --env-file ../.env up -d ib-gateway || log_warn "IB Gateway n'a pas démarré (normal si pas configuré)"

# 5.4 Services applicatifs
log_info "Démarrage des services applicatifs..."
docker compose --env-file ../.env up -d \
    data-ingestor \
    feature-pipeline \
    llm-agents \
    risk-manager \
    portfolio-ledger \
    execution-ib \
    execution-crypto \
    reporter \
    news-ingestor \
    backtest-engine

sleep 15

# 5.5 Gateway API (dernier)
log_info "Démarrage du Gateway API..."
docker compose --env-file ../.env up -d gateway-api

wait_for_healthy "gateway-api" 60 || {
    show_logs_on_error "gateway-api"
    exit 1
}

# 5.6 Caddy (reverse proxy)
log_info "Démarrage de Caddy..."
docker compose --env-file ../.env up -d caddy

sleep 5
log_info "Tous les services démarrés ✓"

# ═══════════════════════════════════════════════════════════════
log_step "ÉTAPE 6: Vérification de la santé"
# ═══════════════════════════════════════════════════════════════

sleep 10

ERRORS=0

# Vérifier chaque service critique
CRITICAL_SERVICES="postgres redis nats gateway-api risk-manager"
for service in $CRITICAL_SERVICES; do
    if docker compose ps $service | grep -q "Up"; then
        log_info "✓ $service"
    else
        log_error "✗ $service"
        ERRORS=$((ERRORS + 1))
        show_logs_on_error $service
    fi
done

# Test HTTP du gateway
log_info "Test du health endpoint..."
sleep 5
if docker compose exec -T gateway-api curl -f http://localhost:8000/health 2>/dev/null | grep -q "ok"; then
    log_info "✓ Gateway API répond correctement"
else
    log_warn "Gateway API ne répond pas encore (peut nécessiter quelques secondes)"
fi

# ═══════════════════════════════════════════════════════════════
log_step "ÉTAPE 7: Configuration du service systemd"
# ═══════════════════════════════════════════════════════════════

log_info "Redémarrage du service systemd..."
sudo systemctl daemon-reload
sudo systemctl enable autollm-stack
sudo systemctl restart autollm-stack

sleep 3

if systemctl is-active --quiet autollm-stack; then
    log_info "✓ Service systemd actif"
else
    log_warn "Service systemd non actif"
fi

# ═══════════════════════════════════════════════════════════════
log_step "ÉTAPE 8: Résumé final"
# ═══════════════════════════════════════════════════════════════

echo ""
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║                    État des conteneurs                         ║"
echo "╚════════════════════════════════════════════════════════════════╝"
docker compose ps

echo ""
if [ $ERRORS -eq 0 ]; then
    echo -e "${GREEN}╔════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║              ✓ DÉPLOIEMENT RÉUSSI ✓                          ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo "Services disponibles:"
    echo "  • Health Check:  https://185.216.25.212.nip.io/health"
    echo "  • API Gateway:   https://185.216.25.212.nip.io/docs"
    echo "  • Grafana:       https://185.216.25.212.nip.io/grafana/"
    echo "  • Prometheus:    http://localhost:9090"
    echo ""
    echo "Commandes utiles:"
    echo "  • Logs:      cd /opt/autollm-trader/Bototo/infra && docker compose logs -f"
    echo "  • Status:    docker compose ps"
    echo "  • Restart:   sudo systemctl restart autollm-stack"
    echo "  • Vérifier:  ./verify-stack.sh"
    echo ""
else
    echo -e "${RED}╔════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}║          ✗ ERREURS DÉTECTÉES ($ERRORS services)                   ║${NC}"
    echo -e "${RED}╚════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo "Consultez les logs avec:"
    echo "  cd /opt/autollm-trader/Bototo/infra && docker compose logs -f <service>"
    exit 1
fi