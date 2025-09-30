# 🚀 SETUP AUTOLLM TRADER SUR VPS AVEC IBKR

**VPS:** PERF-16 (Ryzen 9 9900X, 8 vCores, 16GB RAM, 150GB NVMe)
**Domaine:** bototo.willhardy.fr (avec HTTPS Let's Encrypt automatique)
**OS:** Debian 13 (vierge)
**Broker:** IBKR Paper/Live

---

## ✅ ÉTAPE 1: PRÉREQUIS

### 1.1 VPS Debian 13

- ✅ VPS fraîchement installé (Debian 13)
- ✅ Accès SSH root ou sudo
- ✅ Authentification par clé SSH configurée

### 1.2 Configuration DNS

**IMPORTANT:** Configure DNS AVANT de lancer bootstrap:

```
Type: A
Name: bototo (ou @ pour domaine racine)
Value: <IP_DU_VPS>
TTL: 300
```

Vérifie la résolution:
```bash
host bototo.willhardy.fr
# Doit retourner l'IP du VPS
```

⚠️ **La propagation DNS peut prendre 5-60 minutes**

### 1.3 Credentials IBKR

#### Paper Trading (recommandé pour test)

1. Connecte-toi au [IBKR Portal](https://www.interactivebrokers.com/portal)
2. Va dans **Settings → Paper Trading Account**
3. Note ton **Paper Account Number** (commence par `DU`)
4. Génère ou récupère ton **username/password** paper

**Ou utilise le compte démo:**
- Username: `edemo`
- Password: `demouser`
- Account: `DU0000000`

#### Live Trading

1. Ton compte live doit être **validé** ✅
2. Note ton **Live Account Number** (commence par `U`)
3. Active **TWS API** dans portal:
   - Settings → API → Settings
   - Enable "Enable ActiveX and Socket Clients"
   - Socket port: `4001` (live) ou `4002` (paper)

### 1.4 API Keys (optionnel mais recommandé)

- **OpenAI API Key** (pour agents LLM)
- **Finnhub API Key** (pour market data)

---

## 🔧 ÉTAPE 2: INSTALLATION AUTOMATIQUE

### 2.1 Connexion SSH

```bash
ssh root@<IP_VPS>
```

### 2.2 Clone Repository

```bash
cd /opt
git clone https://github.com/YOUR_ORG/autollm-trader.git
cd autollm-trader
```

### 2.3 Lance Bootstrap (UNE SEULE COMMANDE!)

```bash
sudo ./infra/bootstrap.sh bototo.willhardy.fr
```

**Durée estimée: 30-50 minutes** (selon performance VPS)

### Ce Que le Script Fait (Automatiquement)

#### Phase 1: System Setup (5-10 min)
- ✅ Update Debian packages
- ✅ Install outils de base (git, curl, jq, htop, tmux, vim...)
- ✅ Configure timezone UTC
- ✅ Crée user `trader` avec sudo

#### Phase 2: Security Hardening (2-3 min)
- ✅ SSH hardening (disable password, disable root login)
- ✅ UFW firewall (ports 22, 80, 443, 4222, 4001, 4002)
- ✅ fail2ban pour SSH brute-force protection
- ✅ auditd pour security auditing
- ✅ Automatic security updates

#### Phase 3: Development Tools (10-15 min)
- ✅ Python 3 + pip + venv
- ✅ Poetry 1.7.1
- ✅ Node.js 20 LTS
- ✅ TA-Lib (compilé from source)
- ✅ age + sops (secret management)

#### Phase 4: Container Runtime (3-5 min)
- ✅ Docker CE + compose plugin
- ✅ Configure Docker daemon (log rotation, live-restore)
- ✅ User `trader` dans docker group

#### Phase 5: Application Configuration (2-3 min)
- ✅ Directories (data, secrets, logs, reports)
- ✅ Generate secrets (age key, JWT, signing keys ed25519)
- ✅ Configure `.env` from template
- ✅ **Caddy avec Let's Encrypt SSL automatique** 🔒
- ✅ Add IB Gateway container to docker-compose.yml
- ✅ Monitoring stack (Prometheus, Grafana, Loki)

#### Phase 6: Services & Automation (1-2 min)
- ✅ Systemd watchdog service
- ✅ Docker-compose systemd service
- ✅ Healthcheck cron (every 5 min)

#### Phase 7: Build & Verify (5-10 min)
- ✅ Build React admin UI
- ✅ Verify installation
- ✅ Print summary

### 2.4 Output du Bootstrap

À la fin, tu verras un beau résumé:

```
╔════════════════════════════════════════════════════════════════════╗
║                                                                    ║
║         AutoLLM Trader - Bootstrap Complete! 🚀                   ║
║                                                                    ║
╚════════════════════════════════════════════════════════════════════╝

Domain:       https://bototo.willhardy.fr
Admin UI:     https://bototo.willhardy.fr/admin
API Docs:     https://bototo.willhardy.fr/api/docs
Grafana:      https://bototo.willhardy.fr/grafana
Prometheus:   https://bototo.willhardy.fr/prometheus

... (instructions détaillées)
```

---

## 🔑 ÉTAPE 3: CONFIGURATION IBKR

### 3.1 Éditer .env

Le bootstrap a déjà créé `.env` avec des secrets générés. Tu dois juste ajouter tes API keys:

```bash
cd /opt/autollm-trader
nano .env
```

### 3.2 Configuration Paper Trading (Par Défaut)

Le bootstrap a déjà configuré IBKR paper trading avec compte démo:

```bash
# === IBKR Configuration ===
IB_ENABLED=1              # ✅ Déjà activé
IB_HOST=ib-gateway        # ✅ Container name
IB_PORT=4002              # ✅ Paper port
IB_CLIENT_ID=17
IB_ACCOUNT=DU0000000      # ✅ Compte démo

# IB Gateway Credentials
IB_USERID=edemo           # ✅ Compte démo
IB_PASSWORD=demouser      # ✅ Compte démo
IB_TRADING_MODE=paper     # ✅ Mode paper

# Trading Mode
LIVE=0                    # ✅ Paper mode
```

**Aucune modif nécessaire pour tester!** Passe à l'étape 4.

### 3.3 Configuration avec Compte Paper IBKR Réel

Si tu as un compte paper IBKR réel:

```bash
IB_ENABLED=1
IB_HOST=ib-gateway
IB_PORT=4002              # Paper port
IB_CLIENT_ID=17
IB_ACCOUNT=DU1234567      # ⚠️ Ton account number

# IB Gateway Credentials
IB_USERID=ton_username    # ⚠️ Ton username
IB_PASSWORD=ton_password  # ⚠️ Ton password
IB_TRADING_MODE=paper

LIVE=0
```

### 3.4 Configuration Live Trading (PRODUCTION) ⚠️

**⚠️ UNIQUEMENT après extensive testing en paper!**

```bash
IB_ENABLED=1
IB_HOST=ib-gateway
IB_PORT=4001              # ⚠️ Live port (pas 4002!)
IB_CLIENT_ID=17
IB_ACCOUNT=U1234567       # ⚠️ Compte live (U prefix, pas DU!)

# IB Gateway Credentials
IB_USERID=ton_username    # ⚠️ Username LIVE
IB_PASSWORD=ton_password  # ⚠️ Password LIVE
IB_TRADING_MODE=live      # ⚠️ Mode live

LIVE=1                    # ⚠️ Production mode
```

### 3.5 Ajouter API Keys (Recommandé)

```bash
# === LLM ===
OPENAI_API_KEY=sk-...     # ⚠️ Ta clé OpenAI

# === Market Data ===
FINNHUB_API_KEY=...       # ⚠️ Ta clé Finnhub

# === Notifications ===
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=bot@example.com
SMTP_PASSWORD=app_password
REPORT_RECIPIENTS=toi@example.com

TELEGRAM_BOT_TOKEN=123456:ABC...
TELEGRAM_CHAT_ID=123456789
```

---

## 🚀 ÉTAPE 4: DÉMARRER LES SERVICES

### 4.1 Démarrage via systemd (Recommandé)

```bash
sudo systemctl start autollm-stack
sudo systemctl status autollm-stack
```

### 4.2 Ou Démarrage Manuel

```bash
cd /opt/autollm-trader/infra
docker compose up -d
```

### 4.3 Voir les Logs

```bash
docker compose logs -f
```

Attends que tous les services soient `healthy`:
```
✓ caddy
✓ gateway-api
✓ ib-gateway (après ~60 secondes)
✓ nats
✓ postgres
✓ redis
✓ execution-ib
✓ llm-agents
...
```

---

## ✅ ÉTAPE 5: VÉRIFICATION

### 5.1 Vérifier DNS & SSL

```bash
curl -I https://bototo.willhardy.fr/health
```

Devrait retourner:
```
HTTP/2 200
...
ok
```

⚠️ Si erreur SSL: attends 2-5 min pour Let's Encrypt.

### 5.2 Vérifier Services Docker

```bash
cd /opt/autollm-trader/infra
docker compose ps
```

Tous les services doivent être `Up` ou `Up (healthy)`.

### 5.3 Vérifier IB Gateway

```bash
docker compose logs ib-gateway | tail -20
```

Cherche:
```
[INFO] IB Gateway starting...
[INFO] Connected to TWS
```

### 5.4 Vérifier Connexion IBKR

```bash
docker compose logs execution-ib | tail -20
```

Cherche:
```
[INFO] Connecting to IBKR host=ib-gateway port=4002
[INFO] Connected to IBKR isPaper=True
```

### 5.5 Vérifier Market Data

```bash
docker compose logs data-ingestor | tail -20
```

Cherche:
```
[INFO] Fetched market data for AAPL
[INFO] Published to NATS subject=market.bars.AAPL
```

### 5.6 Vérifier LLM Agents

```bash
docker compose logs llm-agents | tail -20
```

Avec OpenAI key:
```
[INFO] LLM agent proposed intent for AAPL
```

Sans OpenAI key (fallback):
```
[INFO] Using momentum heuristics (no OpenAI key)
```

---

## 🎯 ÉTAPE 6: TESTER LE FLOW COMPLET

### 6.1 Accéder aux Dashboards

**Admin UI:**
https://bototo.willhardy.fr/admin

**API Docs (Swagger):**
https://bototo.willhardy.fr/api/docs

**Grafana:**
https://bototo.willhardy.fr/grafana
Login: `admin` / `admin` (change password!)

**Prometheus:**
https://bototo.willhardy.fr/prometheus

### 6.2 Créer un Compte Admin

1. Ouvre https://bototo.willhardy.fr/admin
2. Register avec WebAuthn (clé FIDO2) ou TOTP
3. Configure TOTP si WebAuthn indisponible

### 6.3 Tester une Intention LLM

Avec OpenAI configuré, le système va:

1. **Data Ingestor** récupère market data (AAPL, SPY, etc.)
2. **Feature Pipeline** calcule indicators (SMA, RSI, ATR...)
3. **LLM Agents** analyse et propose intent:
   ```json
   {
     "symbol": "AAPL",
     "side": "BUY",
     "qty": 10,
     "type": "MKT",
     "rationale": "Strong momentum + positive sentiment"
   }
   ```
4. **Risk Manager** valide:
   - Position limits
   - Drawdown limits
   - Market session
   - Kill switch status
5. **Execution IB** envoie à IBKR:
   ```
   [INFO] Received IBKR order symbol=AAPL qty=10
   [INFO] IBKR trade completed status=filled avg_price=178.23
   ```
6. **Portfolio Ledger** enregistre execution
7. **Reporter** envoie notification (email/Telegram)

### 6.4 Vérifier dans Grafana

1. Ouvre https://bototo.willhardy.fr/grafana
2. Dashboard "AutoLLM Overview"
3. Vérifie:
   - **LLM Intents**: Counter augmente
   - **Executions**: Orders filled
   - **Open Positions**: Position AAPL visible
   - **P&L**: Tracking profit/loss

---

## 🔥 ÉTAPE 7: MONITORING & OPÉRATIONS

### 7.1 Logs Temps Réel

```bash
# Tous les services
docker compose logs -f

# Service spécifique
docker compose logs -f execution-ib

# Filtrer erreurs
docker compose logs -f | grep -i error
```

### 7.2 Métriques Prometheus

Ouvre https://bototo.willhardy.fr/prometheus

Queries utiles:
```promql
# Nombre d'intents LLM
llm_intents_total

# Rejections risk manager
risk_rejections_total

# Latence execution
histogram_quantile(0.95, execution_latency_seconds)

# Open positions
open_positions

# NAV
portfolio_nav_usd
```

### 7.3 Healthchecks Automatiques

Le cron vérifie chaque 5 minutes:
```bash
tail -f /opt/autollm-trader/logs/healthcheck.log
```

### 7.4 Restart un Service

```bash
cd /opt/autollm-trader/infra
docker compose restart SERVICE_NAME

# Exemple: restart IBKR
docker compose restart ib-gateway execution-ib
```

### 7.5 Stop Everything

```bash
# Graceful
docker compose down

# Via systemd
sudo systemctl stop autollm-stack
```

### 7.6 Update Code

```bash
cd /opt/autollm-trader
git pull
docker compose build
docker compose up -d
```

---

## 🚨 KILL SWITCH (URGENCE)

En cas d'urgence, flatten toutes positions et halt trading:

```bash
cd /opt/autollm-trader
make kill
```

Ceci va:
- ✅ Broadcaster `risk.kill_switch.activated` sur NATS
- ✅ Cancel all IBKR orders (`reqGlobalCancel`)
- ✅ Créer `data/kill_switch.flag`
- ✅ Halt LLM agents (no new intents)

Pour réactiver:
```bash
rm data/kill_switch.flag
docker compose restart llm-agents risk-manager
```

---

## 🛠️ TROUBLESHOOTING

### DNS ne résout pas

Vérifie ta config DNS chez ton provider:
```bash
host bototo.willhardy.fr
```

Propagation: 5-60 minutes.

### Certificat SSL ne s'émet pas

Caddy génère auto avec Let's Encrypt. Check logs:
```bash
docker compose logs caddy
```

Causes communes:
- DNS pas propagé (attends 5-10 min)
- Port 80/443 bloqué par firewall
- Domain ne pointe pas vers VPS

### IB Gateway ne connecte pas

Check credentials:
```bash
grep IB_ /opt/autollm-trader/.env
```

Check logs:
```bash
docker compose logs ib-gateway
docker compose logs execution-ib
```

Causes communes:
- Wrong username/password
- Paper account avec live port (4001 au lieu de 4002)
- TWS API pas activé dans IBKR portal

### Services ne démarrent pas

```bash
sudo systemctl status docker
docker ps -a
docker compose logs
```

### Manque d'espace disque

```bash
df -h
docker system df
```

Clean up:
```bash
docker system prune -a --volumes
```

### High CPU/RAM

```bash
docker stats
htop
```

Ajuste resource limits dans `docker-compose.yml` si besoin.

---

## 📊 PERFORMANCE ATTENDUE (PERF-16 VPS)

### Au Repos (Idle)
- **CPU:** 10-15%
- **RAM:** 4-6 GB
- **Disk I/O:** <10 MB/s
- **Network:** <100 KB/s

### Sous Charge (Trading Actif)
- **CPU:** 30-50%
- **RAM:** 6-10 GB
- **Disk I/O:** 20-50 MB/s
- **Network:** <1 MB/s

### Latence IBKR
- **Optimal:** <50ms
- **Acceptable:** <200ms

---

## 🔒 SÉCURITÉ

### ✅ Fait par Bootstrap

- SSH hardened (password auth disabled, root login disabled)
- UFW firewall configured
- fail2ban active
- Automatic security updates
- Secrets générés securely (age, JWT, signing keys)

### ⚠️ Ta Responsabilité

1. **Backup secrets régulièrement:**
   ```bash
   tar czf secrets-backup.tar.gz secrets/
   # Store encrypted off-site!
   ```

2. **Rotate credentials tous les 90 jours:**
   - API keys (OpenAI, Finnhub)
   - IBKR password
   - JWT secret
   - Database passwords

3. **Monitor logs daily:**
   ```bash
   grep -i error logs/*.log
   ```

4. **Complete Phase 1 security** (voir `PRODUCTION_READY_TASKLIST.md`) avant live trading:
   - NATS TLS + auth
   - Redis password
   - Rate limiting API
   - Audit logging

5. **Use WebAuthn/TOTP** pour admin UI

6. **Keep system updated:**
   ```bash
   sudo apt update && sudo apt upgrade -y
   docker compose pull
   docker compose up -d
   ```

---

## 📈 PASSAGE EN LIVE TRADING

### Checklist Paper Trading (1-2 semaines)

- ✅ Bootstrap completed successfully
- ✅ All services healthy
- ✅ IBKR paper account connected
- ✅ LLM agents generating intents
- ✅ Risk manager rejecting invalid orders
- ✅ Orders executing in paper
- ✅ Grafana dashboards showing data
- ✅ Email/Telegram alerts working
- ✅ Healthchecks passing
- ✅ **Monitor for 1-2 weeks minimum**

### Checklist Live Trading (avant activation)

- ✅ **Paper trading successful 2+ weeks**
- ✅ **Complete Phase 1 security hardening** (see PRODUCTION_READY_TASKLIST.md)
  - NATS TLS + authentication
  - Redis password
  - Rate limiting
  - Audit logs
  - JWT rotation
- ✅ **Risk parameters tuned** (configs/risk.yaml)
- ✅ **Position limits set**
- ✅ **Max drawdown configured**
- ✅ **Kill-switch tested**
- ✅ **Backup/recovery tested**
- ✅ **Monitoring alerts tested**
- ✅ **Real IBKR live account funded**
- ✅ **Team monitoring 24/7 first week**

**Seulement après:**
```bash
nano .env
# Modifie:
# LIVE=1
# IB_PORT=4001
# IB_TRADING_MODE=live
# IB_ACCOUNT=U1234567

docker compose down
docker compose up -d
```

---

## 📚 DOCUMENTATION

- **Ce Guide:** VPS_IBKR_SETUP.md
- **Quick Start:** QUICK_START.md
- **Production Tasks:** PRODUCTION_READY_TASKLIST.md
- **Architecture:** README.md
- **Logs Bootstrap:** `/var/log/autollm-bootstrap.log`
- **Logs Services:** `/opt/autollm-trader/logs/`

---

## 🎯 COMMANDES UTILES

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
make kill

# Backup
tar czf backup.tar.gz .env secrets/ data/

# Update
git pull && docker compose build && docker compose up -d
```

---

## ✅ NEXT STEPS

1. ✅ Bootstrap terminé
2. ✅ Services running
3. ⏳ Configure API keys (OpenAI, Finnhub)
4. ⏳ Test paper trading 1-2 weeks
5. ⏳ Complete Phase 1 security
6. ⏳ Review risk parameters
7. ⏳ Configure alerts (email/Telegram)
8. ⏳ Setup backups (borgmatic/restic)
9. ⏳ Monitor and tune
10. ⏳ Consider live trading (extensive testing first!)

---

**Ton AutoLLM Trader est maintenant déployé! 🚀**

Teste thoroughement en paper avant d'envisager live trading.