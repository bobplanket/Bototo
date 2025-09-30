# Quick Start - VPS Deployment with IBKR

This guide provides the fastest path to deploy AutoLLM Trader on your VPS with IBKR paper trading.

## Prerequisites

- Fresh Ubuntu 22.04 LTS VPS
- Root or sudo access
- SSH key authentication configured
- VPS specs: PERF-16 (Ryzen 9 9900X, 8 vCores, 16GB RAM) ✓

## One-Command Bootstrap

SSH into your VPS and run:

```bash
# Clone repository
git clone https://github.com/your-org/autollm-trader.git
cd autollm-trader

# Run bootstrap (automatically detects VPS IP and configures everything)
sudo ./infra/bootstrap-vps-ip.sh
```

**What this does:**
- Detects your VPS public IP address
- Installs all dependencies (Docker, Node, Python, TA-Lib, etc.)
- Hardens SSH, firewall, fail2ban
- Generates cryptographic secrets (JWT, signing keys)
- Configures Caddy for HTTPS with self-signed certificate on your IP
- Adds IB Gateway container to docker-compose
- Sets up monitoring stack (Prometheus, Grafana, Loki)

**Duration:** ~15-20 minutes

## Quick IBKR Paper Trading Setup

After bootstrap completes:

```bash
# Configure for paper trading and add API keys
./scripts/setup_ibkr_paper.sh
```

This interactive script will:
- Enable IBKR integration (`IB_ENABLED=1`)
- Configure paper trading mode (port 4002)
- Prompt for OpenAI API key (optional)
- Prompt for Finnhub API key (optional)

## Start Services

```bash
cd infra
docker compose up -d
```

## Verify Deployment

```bash
# Check all services are running
docker compose ps

# Check IB Gateway connection
docker compose logs ib-gateway | tail -20
docker compose logs execution-ib | tail -20

# Test API health
curl -k https://$(curl -s ifconfig.me)/health
```

Expected output: `ok`

## Access Dashboards

Get your VPS IP:
```bash
curl ifconfig.me
```

Then access:
- **Admin UI:** `https://YOUR_IP/admin`
- **API Docs:** `https://YOUR_IP/api/docs`
- **Grafana:** `https://YOUR_IP/grafana` (admin/admin)
- **Prometheus:** `https://YOUR_IP/prometheus`

**Note:** Browser will show security warning for self-signed certificate. Click "Advanced" → "Proceed" to accept.

## Configuration Files

All configuration is in `.env` file:

```bash
nano .env
```

### Key Settings for IBKR Paper Trading

```bash
# Enable IBKR
IB_ENABLED=1
IB_HOST=ib-gateway
IB_PORT=4002              # 4002 = paper, 4001 = live
IB_CLIENT_ID=17
IB_ACCOUNT=DU0000000      # Paper account (replace with real if needed)

# IB Gateway Credentials (paper demo)
IB_USERID=edemo
IB_PASSWORD=demouser
IB_TRADING_MODE=paper     # paper or live

# Trading mode
LIVE=0                    # 0 = paper, 1 = live

# LLM (optional but recommended)
OPENAI_API_KEY=sk-...

# Market data
FINNHUB_API_KEY=...
```

### Using Real IBKR Paper Account

If you have an IBKR paper trading account (not demo):

1. Update `.env`:
   ```bash
   IB_USERID=your_username
   IB_PASSWORD=your_password
   IB_ACCOUNT=DU1234567    # Your paper account number
   ```

2. Restart services:
   ```bash
   docker compose restart ib-gateway execution-ib
   ```

## Testing the Flow

### 1. Check Service Health

```bash
# All services should be "Up"
docker compose ps

# No error logs
docker compose logs --tail=50 | grep -i error
```

### 2. Test Market Data Ingestion

```bash
docker compose logs -f data-ingestor
```

Should see messages like: `Fetched market data for AAPL`

### 3. Test LLM Intent Generation (if OpenAI configured)

```bash
docker compose logs -f llm-agents
```

Should see: `LLM agent proposed intent` or `Using fallback heuristics`

### 4. Test IBKR Execution

Monitor execution service:
```bash
docker compose logs -f execution-ib
```

When an approved order arrives, you should see:
```
Received IBKR order symbol=AAPL qty=10
Connected to IBKR isPaper=True
IBKR trade completed status=filled
```

### 5. View Grafana Dashboards

1. Open `https://YOUR_IP/grafana`
2. Login: admin/admin
3. Navigate to "AutoLLM Overview" dashboard
4. Should see metrics: intents, executions, positions

## Common Issues

### IB Gateway Not Connecting

```bash
# Check IB Gateway logs
docker compose logs ib-gateway

# Restart IB Gateway
docker compose restart ib-gateway

# Verify port is accessible
nc -zv localhost 4002
```

### Services Not Starting

```bash
# Check for missing secrets
ls -la secrets/

# Should have:
# - age.key
# - llm_signing_key.age
# - llm_pub.key
# - risk_signing_key.age
# - risk_pub.key

# If missing, regenerate:
cd secrets
age-keygen -o age.key
python3 ../scripts/generate_keys.py
```

### Cannot Access HTTPS

```bash
# Check firewall
sudo ufw status

# Should allow: 22, 80, 443

# Check Caddy
docker compose logs caddy
```

### WebAuthn Not Working

IP-based WebAuthn doesn't work on Safari/iOS. Use TOTP instead:

1. Login with username/password
2. Enable TOTP in admin settings
3. Scan QR code with authenticator app

## Monitoring & Logs

### Real-time logs
```bash
# All services
docker compose logs -f

# Specific service
docker compose logs -f execution-ib

# Filter errors
docker compose logs -f | grep -i error
```

### Prometheus Metrics
- `llm_intents_total` - Total LLM intents generated
- `risk_rejections_total` - Orders blocked by risk manager
- `execution_latency_seconds` - Time to execute orders
- `open_positions` - Current open positions

### Grafana Alerts
Alertmanager forwards to `/api/alert` endpoint in reporter service.

## Upgrading to Live Trading

**⚠️ ONLY after thorough paper trading testing!**

1. Complete security checklist in `PRODUCTION_READY_TASKLIST.md` Phase 1
2. Update `.env`:
   ```bash
   LIVE=1
   IB_TRADING_MODE=live
   IB_PORT=4001
   IB_USERID=your_live_username
   IB_PASSWORD=your_live_password
   IB_ACCOUNT=U1234567  # Live account (starts with U, not DU)
   ```
3. Restart:
   ```bash
   docker compose down
   docker compose up -d
   ```
4. **Monitor continuously for first 24 hours**

## Backups

Essential files to backup:
- `.env` (contains API keys)
- `secrets/` (cryptographic keys)
- `data/` (DuckDB, kill switch flags)
- `docker-compose.yml` (if modified)

Recommended: Use `borgmatic` or `restic` pointing at `/opt/autollm`

## Performance Tuning

Your PERF-16 VPS is over-provisioned for this workload. To optimize:

1. **Reduce Docker resource limits** (optional):
   ```yaml
   # In docker-compose.yml, add to memory-intensive services:
   deploy:
     resources:
       limits:
         cpus: '2'
         memory: 2G
   ```

2. **Adjust Python worker counts**:
   ```bash
   # In .env
   MAX_CONCURRENT_TASKS=32  # Default is 64
   ```

3. **Monitor resource usage**:
   ```bash
   docker stats
   htop
   ```

Expected usage at idle:
- CPU: ~10-15%
- RAM: ~4-6 GB
- Disk I/O: minimal

Under load (active trading):
- CPU: ~30-50%
- RAM: ~6-10 GB

## Next Steps

1. ✅ Bootstrap completed
2. ✅ Services running
3. ✅ IBKR connected (paper)
4. ⏳ **Test paper trading for 1-2 weeks**
5. ⏳ Implement Phase 1 security hardening (see `PRODUCTION_READY_TASKLIST.md`)
6. ⏳ Add real API keys (OpenAI, Finnhub, exchanges)
7. ⏳ Configure email/Telegram alerts
8. ⏳ Set up backups (borgmatic)
9. ⏳ Review and tune risk parameters (`configs/risk.yaml`)
10. ⏳ Consider live trading (after extensive testing)

## Support

- Detailed IBKR setup: `VPS_IBKR_SETUP.md`
- Full production checklist: `PRODUCTION_READY_TASKLIST.md`
- Architecture overview: `README.md`
- Issues: Check logs with `docker compose logs -f`

## Quick Command Reference

```bash
# Start services
docker compose up -d

# Stop services
docker compose down

# Restart specific service
docker compose restart execution-ib

# View logs
docker compose logs -f

# Check status
docker compose ps

# Kill switch (emergency stop)
make kill

# Update code
git pull
docker compose build
docker compose up -d

# Backup
tar czf autollm-backup-$(date +%Y%m%d).tar.gz .env secrets/ data/

# Monitor resources
docker stats
```

---

**You're now running AutoLLM Trader on your VPS with IBKR paper trading!**

Test thoroughly before considering live trading. Review all security measures in `PRODUCTION_READY_TASKLIST.md` Phase 1.