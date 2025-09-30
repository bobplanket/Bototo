# Quick Start - Production Deployment

Complete guide to deploy AutoLLM Trader on a fresh Debian 13 VPS with IBKR trading.

## Prerequisites

✅ **Fresh Debian 13 VPS**
- Minimum: 4 vCores, 8GB RAM, 50GB SSD
- Recommended: 8 vCores, 16GB RAM, 150GB NVMe (like PERF-16)

✅ **Domain Name**
- Domain pointing to VPS IP address (A record)
- Example: `bototo.willhardy.fr`

✅ **SSH Access**
- Root or sudo access
- SSH key authentication configured

✅ **IBKR Account** (optional for initial setup)
- Paper trading works with demo account
- Real paper or live account for actual trading

## Single-Command Installation

SSH into your VPS and run:

```bash
# Clone the repository
git clone https://github.com/your-org/autollm-trader.git
cd autollm-trader

# Make bootstrap executable
chmod +x infra/bootstrap.sh

# Run bootstrap with your domain
sudo ./infra/bootstrap.sh bototo.willhardy.fr
```

**That's it!** The script is fully idempotent and will:

### Phase 1: System Setup (5-10 min)
- ✅ Update Debian packages
- ✅ Install base tools (git, curl, jq, htop, etc.)
- ✅ Configure UTC timezone
- ✅ Create `trader` user with sudo access

### Phase 2: Security Hardening (2-3 min)
- ✅ Harden SSH (disable password auth, disable root login)
- ✅ Configure UFW firewall (allow 22, 80, 443, 4222, 4001, 4002)
- ✅ Install and configure fail2ban (SSH brute-force protection)
- ✅ Install auditd for security auditing
- ✅ Enable automatic security updates

### Phase 3: Development Tools (10-15 min)
- ✅ Python 3 + pip + venv
- ✅ Poetry 1.7.1
- ✅ Node.js 20 LTS + npm
- ✅ TA-Lib compiled from source
- ✅ age + sops for secret management

### Phase 4: Container Runtime (3-5 min)
- ✅ Docker CE with compose plugin
- ✅ Configure Docker daemon (log rotation, live-restore)
- ✅ Add trader user to docker group

### Phase 5: Application Configuration (2-3 min)
- ✅ Create directory structure (data, secrets, logs, reports)
- ✅ Generate cryptographic secrets (age key, JWT, signing keys)
- ✅ Configure .env from template
- ✅ Setup Caddy with automatic Let's Encrypt SSL
- ✅ Add IB Gateway container to docker-compose.yml
- ✅ Copy monitoring stack configs

### Phase 6: Services & Automation (1-2 min)
- ✅ Configure systemd watchdog service
- ✅ Configure docker-compose systemd service
- ✅ Setup healthcheck cron (every 5 minutes)

### Phase 7: Build & Verify (5-10 min)
- ✅ Build React admin UI
- ✅ Verify installation
- ✅ Print comprehensive summary

**Total time:** 30-50 minutes depending on VPS performance

## Post-Installation Configuration

After bootstrap completes, configure your API keys:

```bash
nano .env
```

### Essential API Keys

```bash
# LLM (optional but recommended)
OPENAI_API_KEY=sk-...

# Market Data
FINNHUB_API_KEY=...

# IBKR (if using real account)
IB_USERID=your_username
IB_PASSWORD=your_password
IB_ACCOUNT=DU1234567  # Paper account (DU prefix)

# Notifications (optional)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your_email@gmail.com
SMTP_PASSWORD=app_password
REPORT_RECIPIENTS=you@example.com

TELEGRAM_BOT_TOKEN=123456:ABC...
TELEGRAM_CHAT_ID=123456789
```

## Start Services

### Option 1: Using systemd (recommended)

```bash
sudo systemctl start autollm-stack
sudo systemctl status autollm-stack
```

### Option 2: Manual docker compose

```bash
cd infra
docker compose up -d
```

### Monitor startup logs

```bash
docker compose logs -f
```

Wait for all services to show healthy:
```
✓ caddy
✓ gateway-api
✓ ib-gateway (if IB_ENABLED=1)
✓ nats
✓ postgres
✓ redis
✓ ... (all other services)
```

## Access Dashboards

Once DNS propagates and Let's Encrypt issues certificate (~2-5 minutes):

- **Admin UI:** https://bototo.willhardy.fr/admin
- **API Docs:** https://bototo.willhardy.fr/api/docs
- **Grafana:** https://bototo.willhardy.fr/grafana (admin/admin)
- **Prometheus:** https://bototo.willhardy.fr/prometheus
- **Health Check:** https://bototo.willhardy.fr/health

## IBKR Trading Modes

### Paper Trading with Demo Account (DEFAULT)

Already configured by bootstrap:
```bash
IB_ENABLED=1
IB_HOST=ib-gateway
IB_PORT=4002
IB_USERID=edemo
IB_PASSWORD=demouser
IB_TRADING_MODE=paper
LIVE=0
```

**No changes needed!** Just start services.

### Paper Trading with Real IBKR Paper Account

Update `.env`:
```bash
IB_USERID=your_ibkr_username
IB_PASSWORD=your_ibkr_password
IB_ACCOUNT=DU1234567  # Your paper account number
```

Restart services:
```bash
docker compose restart ib-gateway execution-ib
```

### Live Trading (PRODUCTION) ⚠️

**ONLY after extensive paper testing and Phase 1 security hardening!**

Update `.env`:
```bash
LIVE=1
IB_PORT=4001
IB_TRADING_MODE=live
IB_USERID=your_live_username
IB_PASSWORD=your_live_password
IB_ACCOUNT=U1234567  # Live account (U prefix, not DU)
```

Restart:
```bash
docker compose down
docker compose up -d
```

**Monitor continuously for first 24 hours!**

## Verification Checklist

### 1. Check DNS Resolution

```bash
host bototo.willhardy.fr
# Should return your VPS IP
```

### 2. Check SSL Certificate

```bash
curl -I https://bototo.willhardy.fr/health
# Should return: HTTP/2 200
# With valid Let's Encrypt certificate
```

### 3. Check All Services Running

```bash
cd infra
docker compose ps
```

All services should show `Up` or `Up (healthy)`:
```
NAME                STATUS
caddy               Up
gateway-api         Up (healthy)
ib-gateway          Up (healthy)
execution-ib        Up
llm-agents          Up
nats                Up
postgres            Up (healthy)
prometheus          Up
redis               Up
...
```

### 4. Check IBKR Connection

```bash
docker compose logs ib-gateway | tail -20
docker compose logs execution-ib | tail -20
```

Should see:
```
[INFO] Connected to IBKR isPaper=True
```

### 5. Test API Health

```bash
curl https://bototo.willhardy.fr/health
# Expected: ok
```

### 6. Test Market Data Ingestion

```bash
docker compose logs -f data-ingestor
```

Should see messages like:
```
[INFO] Fetched market data for AAPL
[INFO] Published market data to NATS
```

### 7. Test LLM Agents (if OpenAI configured)

```bash
docker compose logs -f llm-agents
```

Should see:
```
[INFO] LLM agent proposed intent
```

Or fallback to heuristics:
```
[INFO] Using momentum heuristics (no OpenAI key)
```

### 8. Check Grafana Dashboards

1. Open https://bototo.willhardy.fr/grafana
2. Login with admin/admin
3. Change password when prompted
4. Navigate to "Dashboards" → "AutoLLM Overview"
5. Verify metrics are populating

## Common Operations

### View Logs

```bash
# All services
docker compose logs -f

# Specific service
docker compose logs -f execution-ib

# Last 100 lines
docker compose logs --tail=100

# Filter errors
docker compose logs -f | grep -i error
```

### Restart Service

```bash
docker compose restart SERVICE_NAME

# Example: restart IBKR components
docker compose restart ib-gateway execution-ib
```

### Stop Everything

```bash
# Graceful stop
docker compose down

# Or via systemd
sudo systemctl stop autollm-stack
```

### Update Code

```bash
cd /path/to/autollm-trader
git pull
docker compose build
docker compose up -d
```

### Emergency Kill Switch

Immediately flatten all positions and halt trading:

```bash
cd /path/to/autollm-trader
make kill
```

This will:
- Send NATS kill-switch message
- Cancel all IBKR orders
- Create kill_switch.flag file
- Halt LLM agent new intents

### Backup Critical Files

```bash
tar czf backup-$(date +%Y%m%d).tar.gz \
  .env \
  secrets/ \
  data/ \
  configs/
```

**Store backups securely off-site!**

## Monitoring & Alerting

### Prometheus Metrics

Access: https://bototo.willhardy.fr/prometheus

Key metrics:
- `llm_intents_total` - LLM intent generation count
- `risk_rejections_total` - Orders rejected by risk manager
- `execution_latency_seconds` - Order execution time
- `open_positions` - Current open positions gauge
- `portfolio_nav_usd` - Net asset value

### Grafana Dashboards

Access: https://bototo.willhardy.fr/grafana

Available dashboards:
- **AutoLLM Overview** - System-wide metrics
- **LLM Performance** - Agent analysis metrics
- **Risk Analytics** - Risk manager decisions
- **Execution Performance** - Order fill statistics
- **Portfolio P&L** - Profit/loss tracking

### Email/Telegram Alerts

Configure in `.env`:
```bash
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=bot@example.com
SMTP_PASSWORD=app_password

TELEGRAM_BOT_TOKEN=123456:ABC...
TELEGRAM_CHAT_ID=123456789
```

Daily reports sent automatically at market close.

Prometheus alerts forward to reporter service for immediate notifications.

### Healthcheck Logs

Automated healthchecks run every 5 minutes:
```bash
tail -f logs/healthcheck.log
```

## Troubleshooting

### Bootstrap Failed Mid-Way

The script is **idempotent** - safe to re-run:
```bash
sudo ./infra/bootstrap.sh bototo.willhardy.fr
```

It will skip completed tasks and resume where it failed.

### DNS Not Resolving

Check your DNS provider's A record:
```
Type: A
Name: bototo (or @ for root domain)
Value: YOUR_VPS_IP
TTL: 300
```

Propagation can take 5-60 minutes.

### SSL Certificate Not Issuing

Caddy auto-issues Let's Encrypt certificates. Check logs:
```bash
docker compose logs caddy
```

Common issues:
- DNS not propagated yet (wait 5-10 min)
- Port 80/443 blocked by firewall (check UFW)
- Domain doesn't point to VPS

### IB Gateway Not Connecting

Check credentials:
```bash
grep IB_ .env
```

Check logs:
```bash
docker compose logs ib-gateway
docker compose logs execution-ib
```

Common issues:
- Wrong username/password
- Paper account using live port (4001) instead of paper port (4002)
- TWS not accepting API connections (check IBKR settings)

### Services Not Starting

Check Docker:
```bash
sudo systemctl status docker
docker ps -a
```

Check logs:
```bash
docker compose logs
journalctl -xe
```

### Out of Disk Space

Check usage:
```bash
df -h
docker system df
```

Clean up:
```bash
docker system prune -a --volumes
```

### High CPU/Memory Usage

Monitor resources:
```bash
docker stats
htop
```

Adjust resource limits in `docker-compose.yml` if needed.

## Performance Tuning

Your PERF-16 VPS is over-provisioned. Expected resource usage:

### At Idle
- **CPU:** 10-15%
- **RAM:** 4-6 GB
- **Disk I/O:** <10 MB/s

### Under Load (Active Trading)
- **CPU:** 30-50%
- **RAM:** 6-10 GB
- **Disk I/O:** 20-50 MB/s

### Network
- **Bandwidth:** <1 Mbps average
- **Latency to IBKR:** <50ms optimal

## Security Best Practices

✅ **Completed by Bootstrap:**
- SSH hardened (password auth disabled)
- UFW firewall configured
- fail2ban active
- Automatic security updates
- Secrets generated securely

⚠️ **Your Responsibility:**

1. **Backup secrets directory regularly**
   ```bash
   tar czf secrets-backup.tar.gz secrets/
   # Store encrypted off-site
   ```

2. **Rotate credentials every 90 days**
   - API keys (OpenAI, Finnhub)
   - IBKR password
   - JWT secret
   - Database passwords

3. **Monitor logs daily**
   ```bash
   grep -i error logs/*.log
   ```

4. **Review Phase 1 security tasks** in `PRODUCTION_READY_TASKLIST.md` before live trading

5. **Use TOTP/WebAuthn** for admin UI access

6. **Keep system updated**
   ```bash
   sudo apt update && sudo apt upgrade -y
   docker compose pull
   docker compose up -d
   ```

## Going to Production

### Paper Trading Checklist (1-2 weeks)

- ✅ Bootstrap completed successfully
- ✅ All services healthy
- ✅ IBKR paper account connected
- ✅ LLM agents generating intents (or using heuristics)
- ✅ Risk manager rejecting invalid orders
- ✅ Orders executing successfully in paper account
- ✅ Grafana dashboards showing data
- ✅ Email/Telegram alerts working
- ✅ Healthchecks passing
- ✅ Monitor for 1-2 weeks, review all executions

### Live Trading Checklist (before enabling)

- ✅ **Paper trading successful for 2+ weeks**
- ✅ **Complete Phase 1 security hardening** (see PRODUCTION_READY_TASKLIST.md)
  - NATS TLS + authentication
  - Redis password
  - Rate limiting on API
  - Audit logging enabled
  - JWT rotation configured
- ✅ **Risk parameters tuned** (configs/risk.yaml)
- ✅ **Position limits set appropriately**
- ✅ **Max drawdown configured**
- ✅ **Kill-switch tested**
- ✅ **Backup/recovery tested**
- ✅ **Monitoring alerts tested**
- ✅ **Real IBKR live account funded**
- ✅ **Team notified and monitoring 24/7 first week**

**Only then:**
```bash
# Update .env
LIVE=1
IB_PORT=4001
IB_TRADING_MODE=live
IB_ACCOUNT=U1234567

# Restart
docker compose down && docker compose up -d
```

## Useful Commands Reference

```bash
# System
sudo systemctl status autollm-stack
sudo systemctl restart autollm-stack
journalctl -u autollm-stack -f

# Docker
docker compose ps
docker compose logs -f [SERVICE]
docker compose restart [SERVICE]
docker compose down
docker compose up -d

# Monitoring
curl https://bototo.willhardy.fr/health
docker stats
htop
df -h

# Logs
tail -f logs/watchdog.log
tail -f logs/healthcheck.log
tail -f /var/log/autollm-bootstrap.log

# Emergency
make kill  # Emergency kill switch

# Backup
tar czf backup.tar.gz .env secrets/ data/

# Update
git pull
docker compose build
docker compose up -d
```

## Support & Documentation

- **This Guide:** QUICK_START.md
- **IBKR Setup:** VPS_IBKR_SETUP.md
- **Production Tasks:** PRODUCTION_READY_TASKLIST.md
- **Architecture:** README.md
- **Logs:** logs/*.log
- **Bootstrap Log:** /var/log/autollm-bootstrap.log

## Next Steps

1. ✅ Bootstrap completed
2. ✅ Services running
3. ⏳ Configure API keys (OpenAI, Finnhub)
4. ⏳ Test paper trading for 1-2 weeks
5. ⏳ Complete Phase 1 security hardening
6. ⏳ Review risk parameters
7. ⏳ Configure alerts (email/Telegram)
8. ⏳ Setup backups (borgmatic/restic)
9. ⏳ Monitor and tune
10. ⏳ Consider live trading (after extensive testing)

---

**Your AutoLLM Trader is now deployed! 🚀**

Test thoroughly in paper mode before considering live trading.