#!/usr/bin/env bash
# Quick setup script for IBKR paper trading on VPS
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")"/.. && pwd)"

echo "=========================================="
echo "AutoLLM Trader - IBKR Paper Trading Setup"
echo "=========================================="
echo ""

# Check if .env exists
if [[ ! -f "${REPO_ROOT}/.env" ]]; then
  echo "ERROR: .env file not found. Run bootstrap first."
  echo "sudo ${REPO_ROOT}/infra/bootstrap-vps-ip.sh"
  exit 1
fi

# Update .env for paper trading
echo "Configuring .env for IBKR paper trading..."

# Enable IBKR
sed -i 's/^IB_ENABLED=.*/IB_ENABLED=1/' "${REPO_ROOT}/.env"

# Set paper trading mode
sed -i 's/^IB_PORT=.*/IB_PORT=4002/' "${REPO_ROOT}/.env"

# Ensure paper account
if ! grep -q "^IB_ACCOUNT=" "${REPO_ROOT}/.env"; then
  echo "IB_ACCOUNT=DU0000000" >> "${REPO_ROOT}/.env"
else
  sed -i 's/^IB_ACCOUNT=.*/IB_ACCOUNT=DU0000000/' "${REPO_ROOT}/.env"
fi

# Ensure LIVE=0 for paper trading
sed -i 's/^LIVE=.*/LIVE=0/' "${REPO_ROOT}/.env"

echo "✓ IBKR paper trading enabled"
echo ""

# Prompt for OpenAI API key if not set
if grep -q "^OPENAI_API_KEY=your_openai_key" "${REPO_ROOT}/.env" || ! grep -q "^OPENAI_API_KEY=" "${REPO_ROOT}/.env"; then
  echo "OpenAI API key not configured."
  read -p "Enter your OpenAI API key (or press Enter to skip): " openai_key
  if [[ -n "$openai_key" ]]; then
    sed -i "s|^OPENAI_API_KEY=.*|OPENAI_API_KEY=${openai_key}|" "${REPO_ROOT}/.env"
    echo "✓ OpenAI API key configured"
  else
    echo "⚠ Skipping OpenAI API key - system will use fallback heuristics"
  fi
  echo ""
fi

# Prompt for Finnhub API key if not set
if grep -q "^FINNHUB_API_KEY=your_finnhub_key" "${REPO_ROOT}/.env" || ! grep -q "^FINNHUB_API_KEY=" "${REPO_ROOT}/.env"; then
  echo "Finnhub API key not configured."
  read -p "Enter your Finnhub API key (or press Enter to skip): " finnhub_key
  if [[ -n "$finnhub_key" ]]; then
    sed -i "s|^FINNHUB_API_KEY=.*|FINNHUB_API_KEY=${finnhub_key}|" "${REPO_ROOT}/.env"
    echo "✓ Finnhub API key configured"
  else
    echo "⚠ Skipping Finnhub API key - market data ingestion will be limited"
  fi
  echo ""
fi

echo "=========================================="
echo "Configuration complete!"
echo "=========================================="
echo ""
echo "Current IBKR settings:"
echo "  IB_ENABLED=1"
echo "  IB_PORT=4002 (paper)"
echo "  IB_HOST=ib-gateway"
echo "  LIVE=0 (paper mode)"
echo ""
echo "Next steps:"
echo ""
echo "1. Start the services:"
echo "   cd ${REPO_ROOT}/infra"
echo "   docker compose up -d"
echo ""
echo "2. Check logs:"
echo "   docker compose logs -f execution-ib"
echo "   docker compose logs -f ib-gateway"
echo ""
echo "3. Verify IB Gateway is running:"
echo "   docker compose ps | grep ib-gateway"
echo "   nc -zv localhost 4002"
echo ""
echo "4. Test the flow:"
echo "   curl -k https://$(curl -s ifconfig.me)/health"
echo ""
echo "For detailed testing guide, see VPS_IBKR_SETUP.md"
echo "=========================================="