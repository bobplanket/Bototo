#!/bin/bash
set -e

echo "=== Déploiement AutoLLM Trader sur VPS ==="

# Couleurs pour l'affichage
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# 1. Mise à jour du code
log_info "Mise à jour du code depuis Git..."
cd /opt/autollm-trader/Bototo
git fetch origin
git reset --hard origin/main
log_info "Code mis à jour vers $(git rev-parse --short HEAD)"

# 2. Nettoyage du cache Docker
log_info "Nettoyage du cache Docker..."
docker system prune -af --volumes || log_warn "Erreur lors du nettoyage Docker (non bloquant)"

# 3. Mise à jour du fichier .env
log_info "Mise à jour du fichier .env..."

# Vérifier si .env existe, sinon le créer depuis .env.template
if [ ! -f .env ]; then
    log_warn ".env n'existe pas, création depuis .env.template..."
    cp .env.template .env
fi

# Mettre à jour les variables IBKR
log_info "Configuration IBKR (Paper Trading)..."
sed -i 's/^IB_USERID=.*/IB_USERID=oobudw311/' .env
sed -i 's/^IB_PASSWORD=.*/IB_PASSWORD=cocsap-qijtA4-vodkih/' .env
sed -i 's/^IB_ACCOUNT=.*/IB_ACCOUNT=DUN122374/' .env
sed -i 's/^IB_ENABLED=.*/IB_ENABLED=1/' .env
sed -i 's/^IB_TRADING_MODE=.*/IB_TRADING_MODE=paper/' .env
sed -i 's/^LIVE=.*/LIVE=0/' .env

# Mettre à jour les variables Redis Upstash
log_info "Configuration Redis Upstash avec TLS..."
sed -i 's|^REDIS_URL=.*|REDIS_URL=rediss://default:AVWbAAIncDFmM2EzY2JmOGMxOWI0YTJjYjg0MmZhZmU4NmJiZTkxNHAxMjE5MTU@boss-sole-21915.upstash.io:6379|' .env
sed -i 's/^REDIS_HOST=.*/REDIS_HOST=boss-sole-21915.upstash.io/' .env
sed -i 's/^REDIS_PORT=.*/REDIS_PORT=6379/' .env
sed -i 's/^REDIS_USERNAME=.*/REDIS_USERNAME=default/' .env
sed -i 's/^REDIS_PASSWORD=.*/REDIS_PASSWORD=AVWbAAIncDFmM2EzY2JmOGMxOWI0YTJjYjg0MmZhZmU4NmJiZTkxNHAxMjE5MTU/' .env
sed -i 's/^REDIS_DB=.*/REDIS_DB=0/' .env
sed -i 's/^REDIS_TLS_ENABLED=.*/REDIS_TLS_ENABLED=true/' .env

# Ajouter REDIS_TLS_ENABLED si elle n'existe pas
if ! grep -q "^REDIS_TLS_ENABLED=" .env; then
    echo "REDIS_TLS_ENABLED=true" >> .env
fi

# Mettre à jour OpenAI API Key (corriger le > en fin de ligne si présent)
log_info "Configuration OpenAI..."
sed -i 's/^OPENAI_API_KEY=.*/OPENAI_API_KEY=sk-proj-aD8FmGKRRbGcqq-NwNoRq5jp3t2rbZK3e9RYsVHn8xTJz90cZA9o_RHKzMteJWGfMeVckVPSwhT3BlbkFJT3EQ8HFt5XCKOQ/' .env

# Mettre à jour Finnhub
log_info "Configuration Finnhub..."
sed -i 's/^FINNHUB_API_KEY=.*/FINNHUB_API_KEY=d3gsjrpr01qpep6872k0d3gsjrpr01qpep6872kg/' .env

# Vérifier que POSTGRES_PASSWORD est défini
if ! grep -q "^POSTGRES_PASSWORD=" .env || [ -z "$(grep '^POSTGRES_PASSWORD=' .env | cut -d'=' -f2)" ]; then
    log_info "Génération d'un mot de passe Postgres..."
    POSTGRES_PWD=$(openssl rand -hex 24)
    sed -i "s/^POSTGRES_PASSWORD=.*/POSTGRES_PASSWORD=${POSTGRES_PWD}/" .env
fi

log_info "Fichier .env configuré"

# 4. Arrêt des services existants
log_info "Arrêt des services existants..."
docker compose -f infra/docker-compose.yml down || log_warn "Aucun service à arrêter"
sudo systemctl stop autollm-stack 2>/dev/null || log_warn "Service systemd non actif"

# 5. Reconstruction et démarrage de la stack
log_info "Construction des images Docker..."
cd /opt/autollm-trader/Bototo/infra
docker compose --env-file ../.env build --no-cache

log_info "Démarrage de la stack Docker..."
docker compose --env-file ../.env up -d

# 6. Attendre que les services démarrent
log_info "Attente du démarrage des services (30s)..."
sleep 30

# 7. Vérification du statut
log_info "Vérification du statut des conteneurs..."
docker compose --env-file ../.env ps

# 8. Redémarrage du service systemd
log_info "Redémarrage du service systemd..."
sudo systemctl restart autollm-stack
sleep 5
sudo systemctl status autollm-stack --no-pager

# 9. Affichage des logs
log_info "Affichage des logs récents..."
docker compose --env-file ../.env logs --tail=50

echo ""
log_info "=== Déploiement terminé ==="
log_info "Vérifiez les logs avec: cd /opt/autollm-trader/Bototo/infra && docker compose logs -f"
log_info "Health check: curl https://185.216.25.212.nip.io/health"
log_info "Grafana: https://185.216.25.212.nip.io/grafana/"

# Vérifier si des conteneurs ont échoué
FAILED=$(docker compose --env-file ../.env ps --filter "status=exited" --format "{{.Name}}" | wc -l)
if [ "$FAILED" -gt 0 ]; then
    log_error "$FAILED conteneur(s) en échec. Consultez les logs avec 'docker compose logs <service>'"
    exit 1
fi

log_info "Tous les conteneurs sont opérationnels ✓"