#!/bin/bash
set -e

echo "=== Vérification de la Stack AutoLLM Trader ==="

# Couleurs
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

ERRORS=0

check_pass() {
    echo -e "${GREEN}✓${NC} $1"
}

check_fail() {
    echo -e "${RED}✗${NC} $1"
    ERRORS=$((ERRORS + 1))
}

check_warn() {
    echo -e "${YELLOW}⚠${NC} $1"
}

echo ""
echo "1. Vérification du code Git..."
cd /opt/autollm-trader/Bototo
CURRENT_COMMIT=$(git rev-parse --short HEAD)
check_pass "Commit actuel: $CURRENT_COMMIT"

echo ""
echo "2. Vérification du fichier .env..."
if [ -f .env ]; then
    check_pass "Fichier .env existe"
    
    # Vérifier les variables critiques
    if grep -q "^REDIS_TLS_ENABLED=true" .env; then
        check_pass "REDIS_TLS_ENABLED=true"
    else
        check_fail "REDIS_TLS_ENABLED manquant ou incorrect"
    fi
    
    if grep -q "^IB_USERID=oobudw311" .env; then
        check_pass "IB_USERID configuré"
    else
        check_fail "IB_USERID non configuré"
    fi
    
    if grep -q "^REDIS_HOST=boss-sole-21915.upstash.io" .env; then
        check_pass "REDIS_HOST Upstash configuré"
    else
        check_fail "REDIS_HOST non configuré"
    fi
    
    if grep -q "^OPENAI_API_KEY=sk-proj-" .env; then
        check_pass "OPENAI_API_KEY configuré"
    else
        check_fail "OPENAI_API_KEY non configuré"
    fi
else
    check_fail "Fichier .env manquant"
fi

echo ""
echo "3. Vérification des conteneurs Docker..."
cd infra
RUNNING=$(docker compose ps --filter "status=running" --format "{{.Name}}" | wc -l)
TOTAL=$(docker compose ps --format "{{.Name}}" | wc -l)

if [ "$RUNNING" -eq "$TOTAL" ] && [ "$TOTAL" -gt 0 ]; then
    check_pass "$RUNNING/$TOTAL conteneurs actifs"
else
    check_fail "Seulement $RUNNING/$TOTAL conteneurs actifs"
    echo ""
    echo "Conteneurs en échec:"
    docker compose ps --filter "status=exited"
fi

echo ""
echo "4. Vérification des services critiques..."

# NATS
if docker compose ps nats | grep -q "Up"; then
    check_pass "NATS actif"
else
    check_fail "NATS non actif"
fi

# Postgres
if docker compose ps postgres | grep -q "Up"; then
    check_pass "Postgres actif"
else
    check_fail "Postgres non actif"
fi

# Gateway API
if docker compose ps gateway-api | grep -q "Up"; then
    check_pass "Gateway API actif"
    
    # Test de santé HTTP
    sleep 2
    if docker compose exec -T gateway-api curl -f http://localhost:8000/health 2>/dev/null; then
        check_pass "Gateway API répond au health check"
    else
        check_warn "Gateway API ne répond pas encore au health check"
    fi
else
    check_fail "Gateway API non actif"
fi

# Risk Manager
if docker compose ps risk-manager | grep -q "Up"; then
    check_pass "Risk Manager actif"
else
    check_fail "Risk Manager non actif"
fi

# IB Gateway
if docker compose ps ib-gateway | grep -q "Up"; then
    check_pass "IB Gateway actif"
else
    check_warn "IB Gateway non actif (optionnel)"
fi

echo ""
echo "5. Vérification du service systemd..."
if systemctl is-active --quiet autollm-stack; then
    check_pass "Service systemd actif"
else
    check_warn "Service systemd non actif"
fi

echo ""
echo "6. Test de connectivité externe..."

# Test Caddy
if curl -f -k https://185.216.25.212.nip.io/health -m 5 2>/dev/null; then
    check_pass "Caddy répond (HTTPS)"
else
    check_warn "Caddy ne répond pas encore (peut nécessiter quelques minutes)"
fi

echo ""
echo "7. Vérification des logs récents..."
echo "Dernières erreurs critiques dans les logs:"
docker compose logs --tail=100 | grep -i "error\|fatal\|exception" | tail -10 || echo "Aucune erreur récente"

echo ""
echo "========================================"
if [ $ERRORS -eq 0 ]; then
    echo -e "${GREEN}✓ Tous les tests passés!${NC}"
    echo ""
    echo "Services disponibles:"
    echo "  - API Gateway: https://185.216.25.212.nip.io/health"
    echo "  - Grafana: https://185.216.25.212.nip.io/grafana/"
    echo "  - Prometheus: http://localhost:9090"
    echo ""
    echo "Commandes utiles:"
    echo "  - Logs: cd /opt/autollm-trader/Bototo/infra && docker compose logs -f"
    echo "  - Status: docker compose ps"
    echo "  - Restart: sudo systemctl restart autollm-stack"
    exit 0
else
    echo -e "${RED}✗ $ERRORS test(s) échoué(s)${NC}"
    echo ""
    echo "Consultez les logs avec:"
    echo "  cd /opt/autollm-trader/Bototo/infra && docker compose logs -f <service>"
    exit 1
fi