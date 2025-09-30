# 🚀 AUTOLLM TRADER - PRODUCTION READY TASKLIST

**Objectif:** Amener le projet de 75% à 95%+ production-ready
**Effort estimé:** 7-9 semaines (1 dev full-time)
**Priorité:** Sécurité → Stabilité → Fonctionnalités → Optimisations

---

## 📋 PHASE 1: SÉCURITÉ & STABILITÉ CRITIQUE (Semaines 1-2)

### 🔐 TASK 1.1: Sécuriser les Secrets et Authentication (Priorité: CRITIQUE)

**Contexte:**
Actuellement, plusieurs secrets sont en clair ou avec valeurs par défaut (JWT_SECRET="replace_me", Postgres password="changeme", pas d'auth NATS/Redis). Ceci expose le système à des attaques triviales.

**Actions:**

1. **Générer secrets cryptographiques forts**
   ```bash
   # Dans infra/bootstrap.sh, ajouter la génération automatique de secrets
   # Après la ligne 45 (section "Generate secrets")

   # Générer JWT secret (64 bytes)
   JWT_SECRET=$(openssl rand -base64 64 | tr -d '\n')
   echo "JWT_SECRET=${JWT_SECRET}" >> /opt/autollm/.env.secrets

   # Générer Redis password
   REDIS_PASSWORD=$(openssl rand -base64 32 | tr -d '\n')
   echo "REDIS_PASSWORD=${REDIS_PASSWORD}" >> /opt/autollm/.env.secrets

   # Générer Postgres password
   POSTGRES_PASSWORD=$(openssl rand -base64 32 | tr -d '\n')
   echo "POSTGRES_PASSWORD=${POSTGRES_PASSWORD}" >> /opt/autollm/.env.secrets

   # Générer Grafana admin password
   GRAFANA_ADMIN_PASSWORD=$(openssl rand -base64 24 | tr -d '\n')
   echo "GRAFANA_ADMIN_PASSWORD=${GRAFANA_ADMIN_PASSWORD}" >> /opt/autollm/.env.secrets

   # Encryter avec sops
   sops -e /opt/autollm/.env.secrets > /opt/autollm/.env.secrets.enc
   rm /opt/autollm/.env.secrets

   echo "✓ Secrets generated and encrypted with sops"
   ```

2. **Mettre à jour .env.template avec les secrets obligatoires**
   ```bash
   # Éditer .env.template
   cat >> .env.template <<'EOF'

   # Security (CRITICAL - GENERATE WITH: openssl rand -base64 64)
   JWT_SECRET=__GENERATED_BY_BOOTSTRAP__
   JWT_ALGORITHM=HS256
   JWT_EXPIRE_MINUTES=15

   # Redis Auth
   REDIS_PASSWORD=__GENERATED_BY_BOOTSTRAP__

   # Postgres
   POSTGRES_PASSWORD=__GENERATED_BY_BOOTSTRAP__

   # Grafana
   GRAFANA_ADMIN_PASSWORD=__GENERATED_BY_BOOTSTRAP__

   # NATS Auth (if TLS enabled)
   NATS_USER=autollm_trader
   NATS_PASSWORD=__GENERATED_BY_BOOTSTRAP__
   EOF
   ```

3. **Activer NATS TLS + Authentication**
   ```bash
   # Créer infra/nats/nats-server.conf
   mkdir -p infra/nats
   cat > infra/nats/nats-server.conf <<'EOF'
   listen: 0.0.0.0:4222
   http: 0.0.0.0:8222

   # TLS Configuration
   tls {
     cert_file: "/etc/nats/certs/server-cert.pem"
     key_file: "/etc/nats/certs/server-key.pem"
     ca_file: "/etc/nats/certs/ca-cert.pem"
     verify: true
   }

   # Authentication
   authorization {
     users = [
       {user: "$NATS_USER", password: "$NATS_PASSWORD"}
     ]
   }

   # JetStream
   jetstream {
     store_dir: /data/jetstream
     max_mem: 1G
     max_file: 10G
   }

   # Logging
   log_file: "/var/log/nats/nats-server.log"
   logtime: true
   debug: false
   trace: false
   EOF

   # Générer certificats self-signed (pour dev/staging)
   # En production, utiliser Let's Encrypt ou certificats signés
   mkdir -p infra/nats/certs
   cd infra/nats/certs

   # CA
   openssl req -x509 -newkey rsa:4096 -days 3650 -nodes \
     -keyout ca-key.pem -out ca-cert.pem \
     -subj "/CN=NATS CA/O=AutoLLM Trader"

   # Server cert
   openssl req -newkey rsa:4096 -nodes \
     -keyout server-key.pem -out server-req.pem \
     -subj "/CN=nats-server/O=AutoLLM Trader"

   openssl x509 -req -in server-req.pem -days 730 \
     -CA ca-cert.pem -CAkey ca-key.pem -CAcreateserial \
     -out server-cert.pem

   rm server-req.pem
   cd -
   ```

4. **Mettre à jour docker-compose.yml pour NATS TLS + Auth**
   ```yaml
   # Dans infra/docker-compose.yml, service nats:
   nats:
     image: nats:2.10-alpine
     volumes:
       - ./nats/nats-server.conf:/etc/nats/nats-server.conf:ro
       - ./nats/certs:/etc/nats/certs:ro
       - nats-data:/data
     ports:
       - "4222:4222"
       - "8222:8222"  # HTTP monitoring
     environment:
       - NATS_USER=${NATS_USER}
       - NATS_PASSWORD=${NATS_PASSWORD}
     command: ["-c", "/etc/nats/nats-server.conf"]
     healthcheck:
       test: ["CMD", "wget", "--spider", "http://localhost:8222/healthz"]
       interval: 10s
       timeout: 5s
       retries: 3
   ```

5. **Activer Redis password**
   ```yaml
   # Dans infra/docker-compose.yml, service redis:
   redis:
     image: redis:7-alpine
     command: redis-server --requirepass ${REDIS_PASSWORD}
     volumes:
       - redis-data:/data
     ports:
       - "6379:6379"
     healthcheck:
       test: ["CMD", "redis-cli", "--raw", "incr", "ping"]
       interval: 10s
       timeout: 5s
       retries: 3
   ```

6. **Mettre à jour tous les clients NATS pour TLS + Auth**
   ```python
   # Dans autollm_trader/messaging/nats_client.py
   import os
   import ssl
   import nats
   from nats.errors import TimeoutError

   class NATSClient:
       def __init__(self):
           self.nc = None
           self.js = None
           self.nats_url = os.getenv("NATS_URL", "nats://localhost:4222")
           self.nats_user = os.getenv("NATS_USER")
           self.nats_password = os.getenv("NATS_PASSWORD")
           self.nats_tls_enabled = os.getenv("NATS_TLS_ENABLED", "false").lower() == "true"

       async def connect(self):
           options = {
               "servers": [self.nats_url],
               "max_reconnect_attempts": -1,  # Infinite retries
               "reconnect_time_wait": 2,
               "name": "autollm-trader",
           }

           # Add auth if credentials provided
           if self.nats_user and self.nats_password:
               options["user"] = self.nats_user
               options["password"] = self.nats_password

           # Add TLS if enabled
           if self.nats_tls_enabled:
               ssl_ctx = ssl.create_default_context(
                   purpose=ssl.Purpose.SERVER_AUTH,
                   cafile="/etc/nats/certs/ca-cert.pem"
               )
               options["tls"] = ssl_ctx

           self.nc = await nats.connect(**options)
           self.js = self.nc.jetstream()

       async def disconnect(self):
           if self.nc:
               await self.nc.drain()
               await self.nc.close()
   ```

7. **Mettre à jour gateway_api pour utiliser JWT secret depuis env**
   ```python
   # Dans apps/gateway_api/src/auth.py
   import os
   from jose import jwt, JWTError
   from datetime import datetime, timedelta

   class AuthService:
       def __init__(self):
           self.jwt_secret = os.getenv("JWT_SECRET")
           if not self.jwt_secret or self.jwt_secret == "replace_me":
               raise ValueError("JWT_SECRET must be set to a strong random value")

           self.jwt_algorithm = os.getenv("JWT_ALGORITHM", "HS256")
           self.jwt_expire_minutes = int(os.getenv("JWT_EXPIRE_MINUTES", "15"))
   ```

8. **Ajouter rate limiting à gateway_api**
   ```python
   # Dans apps/gateway_api/src/main.py
   from slowapi import Limiter, _rate_limit_exceeded_handler
   from slowapi.util import get_remote_address
   from slowapi.errors import RateLimitExceeded

   limiter = Limiter(key_func=get_remote_address, default_limits=["100/minute"])
   app.state.limiter = limiter
   app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

   # Appliquer rate limiting sur endpoints sensibles
   @app.post("/api/orders/manual")
   @limiter.limit("10/minute")
   async def create_manual_order(request: Request, order: ManualOrderRequest, ...):
       ...

   @app.post("/api/risk/kill")
   @limiter.limit("5/hour")
   async def trigger_kill_switch(request: Request, ...):
       ...
   ```

9. **Restreindre CORS**
   ```python
   # Dans apps/gateway_api/src/main.py
   from fastapi.middleware.cors import CORSMiddleware

   # BEFORE (insecure):
   # allow_origins=["*"]

   # AFTER (secure):
   allowed_origins = os.getenv("CORS_ALLOWED_ORIGINS", "").split(",")
   if not allowed_origins or allowed_origins == [""]:
       allowed_origins = ["http://localhost:3000"]  # Dev default

   app.add_middleware(
       CORSMiddleware,
       allow_origins=allowed_origins,
       allow_credentials=True,
       allow_methods=["GET", "POST", "PUT", "DELETE"],
       allow_headers=["*"],
   )
   ```

10. **Créer table audit_log pour actions admin**
    ```sql
    -- Dans autollm_trader/storage/postgres.py, ajouter migration
    CREATE TABLE IF NOT EXISTS audit_log (
        id SERIAL PRIMARY KEY,
        ts TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        user_id VARCHAR(255) NOT NULL,
        action VARCHAR(100) NOT NULL,
        resource VARCHAR(255),
        details JSONB,
        ip_address INET,
        user_agent TEXT
    );

    CREATE INDEX idx_audit_log_ts ON audit_log(ts DESC);
    CREATE INDEX idx_audit_log_user ON audit_log(user_id);
    CREATE INDEX idx_audit_log_action ON audit_log(action);
    ```

    ```python
    # Ajouter méthode log_audit dans LedgerStore
    async def log_audit(self, user_id: str, action: str, resource: str = None,
                       details: dict = None, ip: str = None, user_agent: str = None):
        async with self.pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO audit_log (user_id, action, resource, details, ip_address, user_agent)
                VALUES ($1, $2, $3, $4, $5, $6)
                """,
                user_id, action, resource, details, ip, user_agent
            )

    # Dans gateway_api, logger toutes les actions admin
    @app.post("/api/orders/manual")
    async def create_manual_order(order: ManualOrderRequest, request: Request,
                                 current_user: dict = Depends(get_current_user)):
        await ledger.log_audit(
            user_id=current_user["sub"],
            action="CREATE_MANUAL_ORDER",
            resource=f"symbol={order.symbol}",
            details=order.dict(),
            ip=request.client.host,
            user_agent=request.headers.get("user-agent")
        )
        ...
    ```

11. **Mettre à jour pyproject.toml pour ajouter slowapi**
    ```toml
    [tool.poetry.dependencies]
    slowapi = "^0.1.9"
    ```

**Tests de validation:**
```bash
# 1. Vérifier que JWT_SECRET est bien généré (non "replace_me")
grep JWT_SECRET .env.secrets.enc

# 2. Tester connexion NATS avec TLS
nats sub -s nats://user:pass@localhost:4222 --tlscert=infra/nats/certs/ca-cert.pem test

# 3. Tester rate limiting
for i in {1..15}; do curl -X POST http://localhost:8000/api/orders/manual; done
# Devrait retourner 429 après 10 requêtes

# 4. Vérifier logs audit
psql -U autollm -d autollm -c "SELECT * FROM audit_log ORDER BY ts DESC LIMIT 10;"
```

**Critères d'acceptation:**
- [ ] JWT_SECRET généré automatiquement (64+ bytes)
- [ ] NATS TLS activé avec certificats
- [ ] NATS authentication user/password
- [ ] Redis requirepass activé
- [ ] Rate limiting actif (10 req/min sur /api/orders/manual)
- [ ] CORS restrictif (whitelist origins)
- [ ] Audit log table créée et fonctionnelle
- [ ] Tous les services se connectent avec auth
- [ ] Tests passent avec nouvelles config

---

### 💰 TASK 1.2: Portfolio Ledger - Calcul PnL et Event Replay (Priorité: HAUTE)

**Contexte:**
Actuellement, `unrealized_pnl` est toujours 0 car pas de mark-to-market. De plus, l'état des positions est perdu au redémarrage du service (pas de replay des événements).

**Actions:**

1. **Ajouter colonnes et index manquants à la table positions**
   ```sql
   -- Dans autollm_trader/storage/postgres.py
   ALTER TABLE positions ADD COLUMN IF NOT EXISTS last_price DECIMAL(18,8);
   ALTER TABLE positions ADD COLUMN IF NOT EXISTS last_update TIMESTAMPTZ DEFAULT NOW();
   ALTER TABLE positions ADD COLUMN IF NOT EXISTS cost_basis DECIMAL(18,2);

   CREATE INDEX IF NOT EXISTS idx_positions_last_update ON positions(last_update);
   ```

2. **Créer service de mark-to-market en temps réel**
   ```python
   # Dans apps/portfolio_ledger/src/mtm_service.py (nouveau fichier)
   import asyncio
   from decimal import Decimal
   from autollm_trader.messaging.nats_client import NATSClient
   from autollm_trader.storage.postgres import LedgerStore
   from autollm_trader.logger import get_logger

   logger = get_logger(__name__)

   class MarkToMarketService:
       def __init__(self, ledger: LedgerStore, nats: NATSClient):
           self.ledger = ledger
           self.nats = nats
           self.price_cache = {}  # {symbol: last_price}

       async def start(self):
           await self.nats.connect()

           # Subscribe to market ticks
           await self.nats.js.subscribe(
               "market.ticks.>",
               cb=self.on_tick,
               stream="MARKET",
               durable="portfolio-mtm"
           )
           logger.info("Mark-to-market service started")

       async def on_tick(self, msg):
           try:
               data = json.loads(msg.data.decode())
               symbol = data["symbol"]
               price = Decimal(str(data["price"]))

               self.price_cache[symbol] = price

               # Update position unrealized PnL
               await self.update_position_pnl(symbol, price)

               await msg.ack()
           except Exception as e:
               logger.error(f"MTM tick error: {e}", exc_info=True)

       async def update_position_pnl(self, symbol: str, current_price: Decimal):
           async with self.ledger.pool.acquire() as conn:
               # Fetch position
               row = await conn.fetchrow(
                   "SELECT qty, avg_price, cost_basis FROM positions WHERE symbol = $1",
                   symbol
               )

               if not row or row["qty"] == 0:
                   return

               qty = Decimal(str(row["qty"]))
               avg_price = Decimal(str(row["avg_price"]))
               cost_basis = Decimal(str(row["cost_basis"])) if row["cost_basis"] else (qty * avg_price)

               # Calculate unrealized PnL
               market_value = qty * current_price
               unrealized_pnl = market_value - cost_basis

               # Update position
               await conn.execute(
                   """
                   UPDATE positions
                   SET last_price = $1, unrealized_pnl = $2, last_update = NOW()
                   WHERE symbol = $3
                   """,
                   current_price, unrealized_pnl, symbol
               )

               logger.debug(f"Updated {symbol} PnL: {unrealized_pnl:.2f}")

       async def run_periodic_snapshot(self):
           """Snapshot toutes les positions toutes les 5 minutes"""
           while True:
               await asyncio.sleep(300)  # 5 min
               try:
                   async with self.ledger.pool.acquire() as conn:
                       positions = await conn.fetch("SELECT * FROM positions WHERE qty != 0")

                       for pos in positions:
                           symbol = pos["symbol"]
                           if symbol in self.price_cache:
                               await self.update_position_pnl(symbol, self.price_cache[symbol])
               except Exception as e:
                   logger.error(f"Periodic snapshot error: {e}")
   ```

3. **Implémenter event replay au démarrage du service**
   ```python
   # Dans apps/portfolio_ledger/src/service.py
   class PortfolioLedgerService:
       async def replay_executions(self):
           """Rejoue tous les événements d'exécution pour reconstruire l'état"""
           logger.info("Starting execution event replay...")

           async with self.ledger.pool.acquire() as conn:
               # Clear positions (sera recalculé)
               await conn.execute("TRUNCATE TABLE positions")

               # Fetch all executions ordered by timestamp
               executions = await conn.fetch(
                   """
                   SELECT * FROM executions
                   WHERE status = 'filled'
                   ORDER BY ts ASC
                   """
               )

               logger.info(f"Replaying {len(executions)} executions...")

               for exec_row in executions:
                   symbol = exec_row["symbol"]
                   side = exec_row["side"]
                   qty = Decimal(str(exec_row["qty"]))
                   price = Decimal(str(exec_row["price"]))

                   # Upsert position
                   await self.ledger.upsert_position(
                       symbol=symbol,
                       side=side,
                       qty=qty,
                       price=price
                   )

               logger.info("Event replay completed")

       async def start(self):
           await self.nats.connect()
           await self.ledger.connect()

           # Replay events on startup
           await self.replay_executions()

           # Start MTM service
           self.mtm = MarkToMarketService(self.ledger, self.nats)
           await self.mtm.start()
           asyncio.create_task(self.mtm.run_periodic_snapshot())

           # Subscribe to new executions
           await self.nats.js.subscribe(
               "exec.order.*",
               cb=self.on_execution,
               stream="EXECUTION",
               durable="ledger-consumer"
           )
   ```

4. **Améliorer upsert_position pour gérer cost_basis**
   ```python
   # Dans autollm_trader/storage/postgres.py
   async def upsert_position(self, symbol: str, side: str, qty: Decimal, price: Decimal):
       async with self.pool.acquire() as conn:
           # Fetch existing position
           row = await conn.fetchrow("SELECT * FROM positions WHERE symbol = $1", symbol)

           if row:
               old_qty = Decimal(str(row["qty"]))
               old_avg = Decimal(str(row["avg_price"]))
               old_cost_basis = Decimal(str(row["cost_basis"] or 0))
               realized_pnl = Decimal(str(row["realized_pnl"] or 0))

               if side == "BUY":
                   new_qty = old_qty + qty
                   new_cost_basis = old_cost_basis + (qty * price)
                   new_avg = new_cost_basis / new_qty if new_qty != 0 else Decimal(0)
                   new_realized = realized_pnl
               else:  # SELL
                   new_qty = old_qty - qty

                   # Calculate realized PnL on this trade
                   trade_realized = qty * (price - old_avg)
                   new_realized = realized_pnl + trade_realized

                   if new_qty > 0:
                       new_cost_basis = old_cost_basis - (qty * old_avg)
                       new_avg = new_cost_basis / new_qty
                   else:
                       new_cost_basis = Decimal(0)
                       new_avg = Decimal(0)

               await conn.execute(
                   """
                   UPDATE positions
                   SET qty = $1, avg_price = $2, cost_basis = $3,
                       realized_pnl = $4, last_update = NOW()
                   WHERE symbol = $5
                   """,
                   new_qty, new_avg, new_cost_basis, new_realized, symbol
               )
           else:
               # New position
               cost_basis = qty * price if side == "BUY" else Decimal(0)
               await conn.execute(
                   """
                   INSERT INTO positions (symbol, qty, avg_price, cost_basis, realized_pnl)
                   VALUES ($1, $2, $3, $4, 0)
                   """,
                   symbol, qty if side == "BUY" else -qty, price, cost_basis
               )
   ```

5. **Ajouter endpoint API pour equity curve historique**
   ```python
   # Dans apps/gateway_api/src/main.py
   from datetime import datetime, timedelta

   @app.get("/api/portfolio/equity")
   async def get_equity_curve(
       start: str = None,
       end: str = None,
       interval: str = "1h"
   ):
       """Retourne l'equity curve (NAV over time)"""
       # TODO: Implémenter avec table snapshots ou aggregation executions
       pass

   @app.get("/api/portfolio/metrics")
   async def get_portfolio_metrics():
       """Retourne métriques: total PnL, win rate, Sharpe, max DD"""
       async with ledger.pool.acquire() as conn:
           # Total realized PnL
           realized = await conn.fetchval(
               "SELECT COALESCE(SUM(realized_pnl), 0) FROM positions"
           )

           # Total unrealized PnL
           unrealized = await conn.fetchval(
               "SELECT COALESCE(SUM(unrealized_pnl), 0) FROM positions"
           )

           # Trades count
           total_trades = await conn.fetchval(
               "SELECT COUNT(*) FROM executions WHERE status = 'filled'"
           )

           # Win rate (approximation: realized > 0)
           winning_trades = await conn.fetchval(
               """
               SELECT COUNT(DISTINCT symbol) FROM positions
               WHERE realized_pnl > 0
               """
           )
           win_rate = winning_trades / total_trades if total_trades > 0 else 0

           return {
               "realized_pnl": float(realized),
               "unrealized_pnl": float(unrealized),
               "total_pnl": float(realized + unrealized),
               "total_trades": total_trades,
               "win_rate": win_rate,
               # TODO: Sharpe, max drawdown (nécessite equity curve)
           }
   ```

6. **Créer script de reconciliation avec broker**
   ```python
   # Dans scripts/reconcile_positions.py (nouveau fichier)
   import asyncio
   import os
   from ib_insync import IB
   from autollm_trader.storage.postgres import LedgerStore
   from autollm_trader.logger import get_logger

   logger = get_logger(__name__)

   async def reconcile_ib_positions():
       """Compare positions ledger vs IBKR et alerte si divergence"""
       ib = IB()
       await ib.connectAsync(
           host=os.getenv("IB_HOST", "127.0.0.1"),
           port=int(os.getenv("IB_PORT", 4002)),
           clientId=999
       )

       ledger = LedgerStore()
       await ledger.connect()

       # Fetch IBKR positions
       ib_positions = {}
       for pos in ib.positions():
           symbol = pos.contract.symbol
           ib_positions[symbol] = float(pos.position)

       # Fetch ledger positions
       async with ledger.pool.acquire() as conn:
           rows = await conn.fetch("SELECT symbol, qty FROM positions WHERE qty != 0")
           ledger_positions = {row["symbol"]: float(row["qty"]) for row in rows}

       # Compare
       all_symbols = set(ib_positions.keys()) | set(ledger_positions.keys())
       discrepancies = []

       for symbol in all_symbols:
           ib_qty = ib_positions.get(symbol, 0)
           ledger_qty = ledger_positions.get(symbol, 0)

           if abs(ib_qty - ledger_qty) > 0.01:  # Tolerance
               discrepancies.append({
                   "symbol": symbol,
                   "ib_qty": ib_qty,
                   "ledger_qty": ledger_qty,
                   "diff": ib_qty - ledger_qty
               })

       if discrepancies:
           logger.error(f"Position reconciliation FAILED: {discrepancies}")
           # TODO: Send alert via reporter
       else:
           logger.info("Position reconciliation OK")

       ib.disconnect()
       await ledger.pool.close()

   if __name__ == "__main__":
       asyncio.run(reconcile_ib_positions())
   ```

7. **Ajouter cron job dans bootstrap.sh pour reconciliation quotidienne**
   ```bash
   # Dans infra/bootstrap.sh, section "Setup systemd services"
   cat > /etc/cron.daily/autollm-reconcile <<'EOF'
   #!/bin/bash
   cd /opt/autollm
   /usr/local/bin/poetry run python scripts/reconcile_positions.py
   EOF
   chmod +x /etc/cron.daily/autollm-reconcile
   ```

**Tests de validation:**
```bash
# 1. Insérer des executions fictives
psql -U autollm -d autollm -c "
INSERT INTO executions (symbol, side, qty, price, broker, status, payload) VALUES
('AAPL', 'BUY', 100, 150.0, 'paper', 'filled', '{}'),
('AAPL', 'SELL', 50, 155.0, 'paper', 'filled', '{}');
"

# 2. Restart ledger service et vérifier replay
docker-compose restart portfolio_ledger
docker-compose logs portfolio_ledger | grep "Replaying"

# 3. Vérifier PnL calculé
psql -U autollm -d autollm -c "SELECT * FROM positions WHERE symbol = 'AAPL';"
# Devrait montrer: qty=50, realized_pnl=250 (50 * (155-150))

# 4. Tester MTM avec tick
# TODO: Publish fake tick via NATS et vérifier unrealized_pnl update

# 5. Tester reconciliation
python scripts/reconcile_positions.py
```

**Critères d'acceptation:**
- [ ] Column `cost_basis` ajoutée à table positions
- [ ] `realized_pnl` calculé correctement sur SELL
- [ ] `unrealized_pnl` mis à jour en temps réel via MTM service
- [ ] Event replay au boot fonctionne (positions reconstruites)
- [ ] Endpoint `/api/portfolio/metrics` retourne PnL total
- [ ] Script reconciliation détecte divergences
- [ ] Tests unitaires pour upsert_position avec PnL
- [ ] Documentation mise à jour

---

### 📅 TASK 1.3: Risk Manager - Market Calendars & Dependency Checks (Priorité: HAUTE)

**Contexte:**
Le risk manager a des stubs pour market calendars (NYSE, EURONEXT) et dependency checks (require_data_stream, require_broker_connection) mais ne les valide pas.

**Actions:**

1. **Installer pandas-market-calendars**
   ```bash
   poetry add pandas-market-calendars
   ```

2. **Créer service de gestion des calendriers**
   ```python
   # Dans autollm_trader/utils/market_calendars.py (nouveau fichier)
   from datetime import datetime, time
   import pandas_market_calendars as mcal
   from typing import Optional
   from autollm_trader.logger import get_logger

   logger = get_logger(__name__)

   class MarketCalendarService:
       def __init__(self):
           self.calendars = {
               "NYSE": mcal.get_calendar("NYSE"),
               "NASDAQ": mcal.get_calendar("NASDAQ"),
               "XNYS": mcal.get_calendar("XNYS"),  # Alias NYSE
               "EURONEXT": mcal.get_calendar("EUREX"),  # Approximation
               "CRYPTO": None,  # 24/7
           }

       def is_market_open(self, venue: str, dt: Optional[datetime] = None) -> bool:
           """Vérifie si le marché est ouvert à un instant donné"""
           if dt is None:
               dt = datetime.now()

           if venue == "CRYPTO":
               return True  # 24/7

           calendar = self.calendars.get(venue)
           if not calendar:
               logger.warning(f"Unknown venue {venue}, assuming open")
               return True

           # Check if trading day
           schedule = calendar.schedule(start_date=dt.date(), end_date=dt.date())
           if schedule.empty:
               return False  # Not a trading day

           # Check if within trading hours
           market_open = schedule.iloc[0]["market_open"].to_pydatetime()
           market_close = schedule.iloc[0]["market_close"].to_pydatetime()

           return market_open <= dt <= market_close

       def is_pre_market(self, venue: str, dt: Optional[datetime] = None) -> bool:
           """Vérifie si on est en pre-market"""
           if dt is None:
               dt = datetime.now()

           if venue == "CRYPTO":
               return False

           calendar = self.calendars.get(venue)
           if not calendar:
               return False

           schedule = calendar.schedule(start_date=dt.date(), end_date=dt.date())
           if schedule.empty:
               return False

           market_open = schedule.iloc[0]["market_open"].to_pydatetime()

           # Pre-market: 4:00 AM - 9:30 AM EST for NYSE
           pre_market_start = market_open.replace(hour=4, minute=0)

           return pre_market_start <= dt < market_open

       def next_market_open(self, venue: str, dt: Optional[datetime] = None) -> datetime:
           """Retourne la prochaine ouverture du marché"""
           if dt is None:
               dt = datetime.now()

           if venue == "CRYPTO":
               return dt  # Always open

           calendar = self.calendars.get(venue)
           if not calendar:
               return dt

           schedule = calendar.schedule(
               start_date=dt.date(),
               end_date=(dt + pd.Timedelta(days=7)).date()
           )

           for _, row in schedule.iterrows():
               market_open = row["market_open"].to_pydatetime()
               if market_open > dt:
                   return market_open

           return dt  # Fallback
   ```

3. **Intégrer calendar checks dans risk evaluator**
   ```python
   # Dans apps/risk_manager/src/rules.py
   from autollm_trader.utils.market_calendars import MarketCalendarService

   class RiskEvaluator:
       def __init__(self, config: RiskConfig, state: PortfolioState):
           self.config = config
           self.state = state
           self.market_cal = MarketCalendarService()

       def evaluate_intent(self, intent: dict) -> tuple[bool, list[str]]:
           """Évalue un intent LLM, retourne (approved, rejection_reasons)"""
           reasons = []

           # ... existing checks ...

           # Market Calendar Check
           if not self._check_market_hours(intent):
               reasons.append("market_closed")

           approved = len(reasons) == 0
           return approved, reasons

       def _check_market_hours(self, intent: dict) -> bool:
           """Vérifie que le marché est ouvert"""
           symbol = intent.get("symbol")

           # Get venue from symbols.yaml
           venue = self.config.symbols.get(symbol, {}).get("venue", "NYSE")

           # Check if market is open
           is_open = self.market_cal.is_market_open(venue)

           if not is_open:
               # Check if after-hours allowed
               allow_afterhours = self.config.market_calendars.get(venue, {}).get(
                   "allow_afterhours", False
               )

               if not allow_afterhours:
                   logger.warning(
                       f"Rejecting {symbol} order: market {venue} is closed and "
                       f"after-hours not allowed"
                   )
                   return False

           return True
   ```

4. **Ajouter dependency checks (data stream, broker connection)**
   ```python
   # Dans apps/risk_manager/src/service.py
   import asyncio
   from datetime import datetime, timedelta

   class RiskManagerService:
       def __init__(self):
           self.last_tick = {}  # {symbol: timestamp}
           self.broker_connected = False
           self.nats_connected = False

       async def check_dependencies(self) -> dict[str, bool]:
           """Vérifie que toutes les dépendances sont OK"""
           checks = {}

           # Check NATS connection
           checks["nats"] = self.nats.nc is not None and self.nats.nc.is_connected

           # Check broker connection (via heartbeat topic)
           # TODO: execution services should publish heartbeat
           checks["broker"] = self.broker_connected

           # Check data stream freshness (<60s)
           checks["data_stream"] = self._check_data_freshness()

           return checks

       def _check_data_freshness(self) -> bool:
           """Vérifie que les données de marché sont récentes"""
           now = datetime.now()
           threshold = timedelta(seconds=60)

           # Au moins 1 symbole doit avoir reçu un tick récent
           for symbol, last_ts in self.last_tick.items():
               if now - last_ts < threshold:
                   return True

           return False

       async def on_market_tick(self, msg):
           """Update last tick timestamp"""
           data = json.loads(msg.data.decode())
           symbol = data["symbol"]
           self.last_tick[symbol] = datetime.now()
           await msg.ack()

       async def start(self):
           await self.nats.connect()

           # Subscribe to market ticks for freshness check
           await self.nats.js.subscribe(
               "market.ticks.>",
               cb=self.on_market_tick,
               stream="MARKET",
               durable="risk-tick-monitor"
           )

           # Subscribe to broker heartbeat
           await self.nats.js.subscribe(
               "exec.heartbeat",
               cb=self.on_broker_heartbeat,
               stream="EXECUTION",
               durable="risk-broker-monitor"
           )

           # Periodic dependency check
           asyncio.create_task(self.run_dependency_check())

       async def run_dependency_check(self):
           """Vérifie les dépendances toutes les 30s"""
           while True:
               await asyncio.sleep(30)

               checks = await self.check_dependencies()
               all_ok = all(checks.values())

               if not all_ok:
                   logger.error(f"Dependency check FAILED: {checks}")

                   # Si require_broker_connection=true et broker down → trigger alert
                   if self.config.dependency_checks.get("require_broker_connection") and not checks["broker"]:
                       await self.nats.nc.publish(
                           "alerts.critical",
                           json.dumps({
                               "alert": "broker_disconnected",
                               "timestamp": datetime.now().isoformat()
                           }).encode()
                       )
               else:
                   logger.debug("Dependency check OK")
   ```

5. **Ajouter heartbeat aux execution services**
   ```python
   # Dans apps/execution_ib/src/service.py
   class IBExecutorService:
       async def start(self):
           # ... existing code ...

           # Start heartbeat
           asyncio.create_task(self.publish_heartbeat())

       async def publish_heartbeat(self):
           """Publish heartbeat toutes les 10s"""
           while True:
               await asyncio.sleep(10)

               try:
                   status = "connected" if self.ib.isConnected() else "disconnected"
                   await self.nats.nc.publish(
                       "exec.heartbeat",
                       json.dumps({
                           "service": "execution_ib",
                           "status": status,
                           "timestamp": datetime.now().isoformat()
                       }).encode()
                   )
               except Exception as e:
                   logger.error(f"Heartbeat publish failed: {e}")

   # Même chose pour execution_crypto
   ```

6. **Mettre à jour configs/risk.yaml avec calendars**
   ```yaml
   # Dans configs/risk.yaml, ajouter section market_calendars
   market_calendars:
     NYSE:
       allow_afterhours: false
       allow_premarket: false
     NASDAQ:
       allow_afterhours: false
       allow_premarket: false
     CRYPTO:
       allow_afterhours: true  # 24/7
       allow_premarket: true

   dependency_checks:
     require_broker_connection: true
     require_data_stream: true
     data_freshness_threshold_seconds: 60
   ```

7. **Ajouter tests unitaires pour calendars**
   ```python
   # Dans tests/unit/test_market_calendars.py (nouveau fichier)
   from datetime import datetime
   from autollm_trader.utils.market_calendars import MarketCalendarService
   import pytest

   def test_nyse_open_on_weekday():
       cal = MarketCalendarService()

       # Friday Dec 20, 2024 at 2:00 PM EST (market open)
       dt = datetime(2024, 12, 20, 14, 0, 0)
       assert cal.is_market_open("NYSE", dt) is True

   def test_nyse_closed_on_weekend():
       cal = MarketCalendarService()

       # Saturday Dec 21, 2024
       dt = datetime(2024, 12, 21, 14, 0, 0)
       assert cal.is_market_open("NYSE", dt) is False

   def test_nyse_closed_after_hours():
       cal = MarketCalendarService()

       # Friday Dec 20, 2024 at 5:00 PM EST (after close)
       dt = datetime(2024, 12, 20, 17, 0, 0)
       assert cal.is_market_open("NYSE", dt) is False

   def test_crypto_always_open():
       cal = MarketCalendarService()

       # Sunday 3 AM
       dt = datetime(2024, 12, 22, 3, 0, 0)
       assert cal.is_market_open("CRYPTO", dt) is True
   ```

**Tests de validation:**
```bash
# 1. Tester calendar service
poetry run python -c "
from autollm_trader.utils.market_calendars import MarketCalendarService
from datetime import datetime
cal = MarketCalendarService()
print('NYSE open now:', cal.is_market_open('NYSE'))
print('Next open:', cal.next_market_open('NYSE'))
"

# 2. Soumettre intent hors heures de marché
# Devrait être rejeté avec reason="market_closed"

# 3. Vérifier dependency checks
docker-compose logs risk_manager | grep "Dependency check"

# 4. Simuler broker disconnect et vérifier alert
docker-compose stop execution_ib
sleep 60
docker-compose logs risk_manager | grep "broker_disconnected"
```

**Critères d'acceptation:**
- [ ] pandas-market-calendars installé
- [ ] MarketCalendarService implémenté
- [ ] Risk evaluator rejette ordres hors heures (si allow_afterhours=false)
- [ ] Dependency checks exécutés toutes les 30s
- [ ] Heartbeat publié par execution services
- [ ] Alerte envoyée si broker disconnected
- [ ] Tests unitaires calendars passent
- [ ] Config risk.yaml mise à jour

---

### ✅ TASK 1.4: Tests Coverage à 80%+ (Priorité: HAUTE)

**Contexte:**
Coverage estimé à ~40%. Besoin d'augmenter à 80%+ pour garantir stabilité en production.

**Actions:**

1. **Installer coverage tools**
   ```bash
   # Déjà présent dans pyproject.toml
   poetry add --group dev pytest-cov coverage
   ```

2. **Configurer pytest pour coverage automatique**
   ```toml
   # Dans pyproject.toml, section [tool.pytest.ini_options]
   [tool.pytest.ini_options]
   asyncio_mode = "auto"
   addopts = """
     --strict-markers
     --disable-warnings
     --cov=autollm_trader
     --cov=apps
     --cov-report=html
     --cov-report=term-missing
     --cov-fail-under=80
   """
   testpaths = ["tests"]
   ```

3. **Créer tests manquants pour data_ingestor**
   ```python
   # Dans tests/unit/test_data_ingestor.py (nouveau fichier)
   import pytest
   from unittest.mock import AsyncMock, patch, MagicMock
   from apps.data_ingestor.src.sources import FinnhubSource, YFinanceSource, SyntheticSource

   @pytest.mark.asyncio
   async def test_finnhub_source_quote():
       with patch("finnhub.Client") as mock_client:
           mock_client.return_value.quote.return_value = {
               "c": 150.5,  # current price
               "h": 151.0,  # high
               "l": 149.0,  # low
               "o": 150.0,  # open
               "pc": 149.5,  # previous close
               "t": 1704067200  # timestamp
           }

           source = FinnhubSource(api_key="test_key", symbols=["AAPL"])
           tick = await source.fetch_tick("AAPL")

           assert tick is not None
           assert tick.symbol == "AAPL"
           assert tick.price == 150.5
           assert tick.venue == "FINNHUB"

   @pytest.mark.asyncio
   async def test_yfinance_source_bars():
       with patch("yfinance.Ticker") as mock_ticker:
           mock_data = MagicMock()
           mock_data.empty = False
           mock_data.iloc = [MagicMock(
               Index=pd.Timestamp("2024-01-01 09:30:00"),
               Close=150.5,
               Volume=1000000
           )]
           mock_ticker.return_value.history.return_value = mock_data

           source = YFinanceSource(symbols=["AAPL"], interval="1m")
           bars = await source.fetch_bars("AAPL")

           assert len(bars) > 0
           assert bars[0].symbol == "AAPL"

   def test_synthetic_source_generates_random_data():
       source = SyntheticSource(symbols=["TEST"], base_price=100.0)
       tick = source.fetch_tick("TEST")

       assert tick is not None
       assert 95.0 <= tick.price <= 105.0  # +/- 5% variance
   ```

4. **Créer tests pour news_ingestor webhook**
   ```python
   # Dans tests/unit/test_news_ingestor.py (nouveau fichier)
   import pytest
   from fastapi.testclient import TestClient
   from apps.news_ingestor.src.main import app
   import hmac
   import hashlib

   client = TestClient(app)

   def test_miniflux_webhook_valid_signature():
       payload = {"feed_id": 1, "entry_url": "https://example.com/article"}
       secret = "test_secret"

       # Calculate HMAC
       signature = hmac.new(
           secret.encode(),
           json.dumps(payload).encode(),
           hashlib.sha256
       ).hexdigest()

       response = client.post(
           "/webhook/miniflux",
           json=payload,
           headers={"X-Miniflux-Signature": signature}
       )

       assert response.status_code == 200

   def test_miniflux_webhook_invalid_signature():
       payload = {"feed_id": 1, "entry_url": "https://example.com/article"}

       response = client.post(
           "/webhook/miniflux",
           json=payload,
           headers={"X-Miniflux-Signature": "invalid"}
       )

       assert response.status_code == 403

   @pytest.mark.asyncio
   async def test_sentiment_analyzer_positive():
       from apps.news_ingestor.src.analyzer import SentimentAnalyzer

       analyzer = SentimentAnalyzer()
       text = "Apple stock surges to record high on strong earnings!"

       sentiment = analyzer.analyze_sentiment(text)
       assert sentiment in ["positive", "neutral"]  # TextBlob threshold

   @pytest.mark.asyncio
   async def test_ticker_extraction():
       from apps.news_ingestor.src.analyzer import extract_tickers

       text = "Today $AAPL and $MSFT announced partnership. $TSLA unaffected."
       tickers = extract_tickers(text)

       assert "AAPL" in tickers
       assert "MSFT" in tickers
       assert "TSLA" in tickers
       assert len(tickers) == 3
   ```

5. **Créer tests pour feature_pipeline**
   ```python
   # Dans tests/unit/test_feature_pipeline.py (nouveau fichier)
   import pytest
   import numpy as np
   from apps.feature_pipeline.src.processor import FeatureProcessor

   def test_calculate_sma():
       processor = FeatureProcessor()
       prices = [100, 102, 101, 103, 105]

       sma = processor.calculate_sma(prices, period=3)

       # Last 3: [101, 103, 105] → mean = 103
       assert abs(sma - 103.0) < 0.1

   def test_calculate_rsi():
       processor = FeatureProcessor()
       prices = [100, 102, 104, 103, 105, 107, 106, 108, 110, 109, 111, 113, 112, 114]

       rsi = processor.calculate_rsi(prices, period=14)

       assert 0 <= rsi <= 100
       assert rsi > 50  # Uptrend should have RSI > 50

   def test_calculate_atr():
       processor = FeatureProcessor()
       highs = [102, 104, 103, 105, 107]
       lows = [98, 100, 99, 101, 103]
       closes = [100, 102, 101, 103, 105]

       atr = processor.calculate_atr(highs, lows, closes, period=3)

       assert atr > 0

   @pytest.mark.asyncio
   async def test_duckdb_upsert():
       from autollm_trader.storage.duckdb import FeatureStore

       store = FeatureStore(db_path=":memory:")  # In-memory DB
       await store.connect()

       features = {"SMA_5": 100.5, "RSI_14": 55.3}
       await store.upsert_snapshot("AAPL", "1m", features)

       # Fetch back
       row = await store.fetch_latest("AAPL", "1m")
       assert row is not None
       assert row["features"]["SMA_5"] == 100.5
   ```

6. **Créer tests pour gateway_api auth**
   ```python
   # Dans tests/unit/test_gateway_auth.py (nouveau fichier)
   import pytest
   from apps.gateway_api.src.auth import AuthService
   from datetime import datetime, timedelta

   def test_create_jwt_token():
       auth = AuthService()
       auth.jwt_secret = "test_secret_key_32_bytes_long"

       token = auth.create_access_token(
           data={"sub": "test_user", "role": "admin"}
       )

       assert isinstance(token, str)
       assert len(token) > 50  # JWT is long

   def test_verify_jwt_token_valid():
       auth = AuthService()
       auth.jwt_secret = "test_secret_key_32_bytes_long"

       token = auth.create_access_token(data={"sub": "test_user"})
       payload = auth.verify_token(token)

       assert payload is not None
       assert payload["sub"] == "test_user"

   def test_verify_jwt_token_expired():
       auth = AuthService()
       auth.jwt_secret = "test_secret_key_32_bytes_long"
       auth.jwt_expire_minutes = -1  # Expire immediately

       token = auth.create_access_token(data={"sub": "test_user"})
       payload = auth.verify_token(token)

       assert payload is None  # Expired

   def test_verify_jwt_token_invalid():
       auth = AuthService()
       auth.jwt_secret = "test_secret_key_32_bytes_long"

       payload = auth.verify_token("invalid.token.here")
       assert payload is None
   ```

7. **Créer tests pour portfolio_ledger PnL**
   ```python
   # Dans tests/unit/test_portfolio_pnl.py (nouveau fichier)
   import pytest
   from decimal import Decimal
   from autollm_trader.storage.postgres import LedgerStore

   @pytest.mark.asyncio
   async def test_upsert_position_buy():
       # Mock LedgerStore avec testcontainers Postgres
       # Ou utiliser sqlite en mémoire pour tests
       store = LedgerStore()  # TODO: Mock pool

       await store.upsert_position("AAPL", "BUY", Decimal("100"), Decimal("150.0"))

       # Verify
       # assert position.qty == 100
       # assert position.avg_price == 150.0
       # assert position.cost_basis == 15000.0

   @pytest.mark.asyncio
   async def test_upsert_position_sell_partial():
       store = LedgerStore()

       # Initial position
       await store.upsert_position("AAPL", "BUY", Decimal("100"), Decimal("150.0"))

       # Sell 50 at higher price
       await store.upsert_position("AAPL", "SELL", Decimal("50"), Decimal("155.0"))

       # Verify
       # assert position.qty == 50
       # assert position.realized_pnl == 250.0  # 50 * (155 - 150)
   ```

8. **Créer tests e2e pour flow complet**
   ```python
   # Dans tests/e2e/test_full_flow.py (améliorer existant)
   import pytest
   import asyncio
   from apps.llm_agents.src.service import LLMAgentService
   from apps.risk_manager.src.service import RiskManagerService
   from apps.execution_ib.src.service import IBExecutorService

   @pytest.mark.asyncio
   async def test_intent_to_execution_approved():
       """Test flow: LLM → Risk → Execution (approved)"""
       # Setup services with mocks
       llm_service = LLMAgentService()
       risk_service = RiskManagerService()
       exec_service = IBExecutorService()

       # TODO: Start services, inject fake intent, verify execution
       # This requires test NATS, test Postgres, etc.
       pass

   @pytest.mark.asyncio
   async def test_intent_rejected_by_risk():
       """Test flow: LLM → Risk (rejected) → No execution"""
       # TODO: Inject intent that violates risk limits
       pass
   ```

9. **Configurer CI pour fail si coverage < 80%**
   ```yaml
   # Dans .github/workflows/ci.yml
   - name: Run tests with coverage
     run: |
       poetry run pytest --cov --cov-fail-under=80

   - name: Upload coverage to Codecov
     uses: codecov/codecov-action@v3
     with:
       files: ./coverage.xml
       fail_ci_if_error: true
   ```

10. **Créer rapport coverage HTML**
    ```bash
    # Ajouter target dans Makefile
    coverage:
    	$(POETRY) run pytest --cov --cov-report=html
    	@echo "Coverage report generated in htmlcov/index.html"
    	open htmlcov/index.html  # macOS
    ```

**Tests de validation:**
```bash
# 1. Run tests avec coverage
make coverage

# 2. Vérifier coverage report
open htmlcov/index.html

# 3. Identifier modules < 80%
poetry run coverage report --show-missing

# 4. Ajouter tests pour modules manquants jusqu'à 80%+

# 5. Vérifier CI passe
git push && gh pr checks
```

**Critères d'acceptation:**
- [ ] Coverage global ≥ 80%
- [ ] Tests data_ingestor (sources)
- [ ] Tests news_ingestor (webhook, sentiment)
- [ ] Tests feature_pipeline (indicators, DuckDB)
- [ ] Tests gateway_api (auth, JWT)
- [ ] Tests portfolio_ledger (PnL calculation)
- [ ] Tests risk_manager (calendar, limits)
- [ ] Tests e2e flow complet
- [ ] CI fail si coverage < 80%
- [ ] Coverage report HTML généré

---

## 📦 PHASE 2: FONCTIONNALITÉS CRITIQUES (Semaines 3-5)

### 🪙 TASK 2.1: Execution Crypto Complète (CCXT Live) (Priorité: HAUTE)

**Contexte:**
Le service execution_crypto est un stub (30%). Besoin d'intégrer CCXT pour trading live sur exchanges crypto.

**Actions:**

1. **Créer adaptateur CCXT générique**
   ```python
   # Dans apps/execution_crypto/src/ccxt_adapter.py (nouveau fichier)
   import ccxt
   import asyncio
   from decimal import Decimal
   from typing import Optional, Dict
   from autollm_trader.logger import get_logger

   logger = get_logger(__name__)

   class CCXTAdapter:
       def __init__(self, exchange_id: str, api_key: str, api_secret: str,
                    testnet: bool = True):
           self.exchange_id = exchange_id

           # Initialize exchange
           exchange_class = getattr(ccxt, exchange_id)

           config = {
               "apiKey": api_key,
               "secret": api_secret,
               "enableRateLimit": True,
               "options": {"defaultType": "spot"}  # or "future"
           }

           if testnet:
               config["urls"] = {"api": exchange_class().urls.get("test", {})}

           self.exchange = exchange_class(config)
           self.exchange.load_markets()

           logger.info(f"CCXT {exchange_id} adapter initialized (testnet={testnet})")

       async def place_order(self, symbol: str, side: str, qty: Decimal,
                           order_type: str = "market", price: Optional[Decimal] = None) -> Dict:
           """Place order on exchange"""
           try:
               # CCXT format: BTC/USDT
               ccxt_symbol = symbol.replace("_", "/")

               if order_type == "market":
                   if side == "BUY":
                       order = await self.exchange.create_market_buy_order(
                           ccxt_symbol, float(qty)
                       )
                   else:
                       order = await self.exchange.create_market_sell_order(
                           ccxt_symbol, float(qty)
                       )
               else:  # limit
                   if not price:
                       raise ValueError("Limit order requires price")

                   if side == "BUY":
                       order = await self.exchange.create_limit_buy_order(
                           ccxt_symbol, float(qty), float(price)
                       )
                   else:
                       order = await self.exchange.create_limit_sell_order(
                           ccxt_symbol, float(qty), float(price)
                       )

               logger.info(f"Order placed: {order}")
               return order

           except ccxt.InsufficientFunds as e:
               logger.error(f"Insufficient funds: {e}")
               raise
           except ccxt.InvalidOrder as e:
               logger.error(f"Invalid order: {e}")
               raise
           except Exception as e:
               logger.error(f"Order placement failed: {e}", exc_info=True)
               raise

       async def fetch_balance(self) -> Dict:
           """Fetch account balance"""
           balance = await self.exchange.fetch_balance()
           return balance

       async def fetch_order(self, order_id: str, symbol: str) -> Dict:
           """Fetch order status"""
           ccxt_symbol = symbol.replace("_", "/")
           order = await self.exchange.fetch_order(order_id, ccxt_symbol)
           return order

       async def cancel_order(self, order_id: str, symbol: str):
           """Cancel order"""
           ccxt_symbol = symbol.replace("_", "/")
           await self.exchange.cancel_order(order_id, ccxt_symbol)
           logger.info(f"Order {order_id} cancelled")

       async def cancel_all_orders(self, symbol: Optional[str] = None):
           """Cancel all open orders"""
           if symbol:
               ccxt_symbol = symbol.replace("_", "/")
               orders = await self.exchange.fetch_open_orders(ccxt_symbol)
           else:
               orders = await self.exchange.fetch_open_orders()

           for order in orders:
               await self.cancel_order(order["id"], order["symbol"])

           logger.info(f"Cancelled {len(orders)} orders")

       def close(self):
           """Close connection"""
           self.exchange.close()
   ```

2. **Créer service d'exécution crypto**
   ```python
   # Dans apps/execution_crypto/src/service.py (remplacer stub)
   import json
   import asyncio
   from autollm_trader.messaging.nats_client import NATSClient
   from autollm_trader.logger import get_logger
   from autollm_trader.security.signature import verify_signature
   from .ccxt_adapter import CCXTAdapter
   import os

   logger = get_logger(__name__)

   class CryptoExecutorService:
       def __init__(self):
           self.nats = NATSClient()

           # Load config
           self.enabled = os.getenv("CRYPTO_ENABLED", "false").lower() == "true"
           self.exchange_id = os.getenv("CRYPTO_EXCHANGE", "binance")
           self.api_key = os.getenv(f"{self.exchange_id.upper()}_API_KEY")
           self.api_secret = os.getenv(f"{self.exchange_id.upper()}_API_SECRET")
           self.testnet = os.getenv("CRYPTO_TESTNET", "true").lower() == "true"

           self.risk_pub_key = os.getenv("RISK_SIGNING_PUB_KEY")

           if self.enabled:
               if not self.api_key or not self.api_secret:
                   raise ValueError(f"Missing API credentials for {self.exchange_id}")

               self.adapter = CCXTAdapter(
                   self.exchange_id,
                   self.api_key,
                   self.api_secret,
                   testnet=self.testnet
               )
           else:
               self.adapter = None
               logger.warning("Crypto execution DISABLED (CRYPTO_ENABLED=false)")

       async def start(self):
           await self.nats.connect()

           # Subscribe to approved orders (crypto only)
           await self.nats.js.subscribe(
               "risk.order.approved",
               cb=self.on_approved_order,
               stream="RISK",
               durable="crypto-executor"
           )

           # Publish heartbeat
           asyncio.create_task(self.publish_heartbeat())

           logger.info("Crypto executor service started")

       async def on_approved_order(self, msg):
           try:
               data = json.loads(msg.data.decode())
               symbol = data["symbol"]

               # Filter crypto symbols only (e.g., BTC_USDT, ETH_USDT)
               if "_" not in symbol or not symbol.endswith("USDT"):
                   await msg.ack()
                   return  # Not a crypto symbol

               # Verify risk signature
               if not verify_signature(
                   data["payload"],
                   data["risk_signature"],
                   self.risk_pub_key
               ):
                   logger.error("Invalid risk signature, rejecting")
                   await msg.ack()
                   return

               # Execute
               if self.enabled and self.adapter:
                   await self.execute_order(data)
               else:
                   logger.warning(f"Crypto disabled, skipping order {symbol}")

               await msg.ack()

           except Exception as e:
               logger.error(f"Order execution error: {e}", exc_info=True)
               await msg.nak()

       async def execute_order(self, order_data: dict):
           """Execute order via CCXT"""
           symbol = order_data["symbol"]
           side = order_data["side"]
           qty = Decimal(str(order_data["qty"]))
           order_type = order_data.get("order_type", "market")
           price = Decimal(str(order_data["price"])) if "price" in order_data else None

           try:
               # Place order
               result = await self.adapter.place_order(
                   symbol, side, qty, order_type, price
               )

               # Monitor fill (for limit orders)
               if order_type == "limit":
                   await self.monitor_order_fill(result["id"], symbol)

               # Publish execution event
               await self.nats.nc.publish(
                   f"exec.order.filled",
                   json.dumps({
                       "symbol": symbol,
                       "side": side,
                       "qty": float(qty),
                       "price": float(result.get("price", price)),
                       "broker": self.exchange_id,
                       "order_id": result["id"],
                       "timestamp": result["timestamp"],
                       "fee": result.get("fee", {}),
                       "llm_signature": order_data["llm_signature"],
                       "risk_signature": order_data["risk_signature"]
                   }).encode()
               )

               logger.info(f"Order {result['id']} filled: {symbol} {side} {qty}")

           except Exception as e:
               logger.error(f"Execution failed: {e}")

               # Publish rejection event
               await self.nats.nc.publish(
                   f"exec.order.rejected",
                   json.dumps({
                       "symbol": symbol,
                       "reason": str(e),
                       "broker": self.exchange_id
                   }).encode()
               )

       async def monitor_order_fill(self, order_id: str, symbol: str, timeout: int = 60):
           """Monitor limit order until filled or timeout"""
           start = asyncio.get_event_loop().time()

           while True:
               await asyncio.sleep(2)

               order = await self.adapter.fetch_order(order_id, symbol)
               status = order["status"]

               if status == "closed":
                   logger.info(f"Order {order_id} filled")
                   return order

               if asyncio.get_event_loop().time() - start > timeout:
                   logger.warning(f"Order {order_id} timeout, cancelling")
                   await self.adapter.cancel_order(order_id, symbol)
                   raise TimeoutError(f"Order {order_id} not filled within {timeout}s")

       async def publish_heartbeat(self):
           """Publish heartbeat every 10s"""
           while True:
               await asyncio.sleep(10)

               try:
                   status = "connected" if self.enabled else "disabled"
                   await self.nats.nc.publish(
                       "exec.heartbeat",
                       json.dumps({
                           "service": "execution_crypto",
                           "exchange": self.exchange_id,
                           "status": status,
                           "timestamp": datetime.now().isoformat()
                       }).encode()
                   )
               except Exception as e:
                   logger.error(f"Heartbeat failed: {e}")
   ```

3. **Mettre à jour .env.template avec crypto credentials**
   ```bash
   # Crypto Execution
   CRYPTO_ENABLED=false
   CRYPTO_EXCHANGE=binance  # or coinbase, kraken, etc.
   CRYPTO_TESTNET=true

   # Exchange API Keys (SECURE - DO NOT COMMIT)
   BINANCE_API_KEY=
   BINANCE_API_SECRET=
   COINBASE_API_KEY=
   COINBASE_API_SECRET=
   ```

4. **Ajouter support fees/slippage dans ledger**
   ```python
   # Dans autollm_trader/storage/postgres.py
   # Ajouter colonne fees à table executions
   ALTER TABLE executions ADD COLUMN IF NOT EXISTS fee DECIMAL(18,8);
   ALTER TABLE executions ADD COLUMN IF NOT EXISTS fee_currency VARCHAR(10);

   # Update upsert_position pour inclure fees dans cost_basis
   async def upsert_position(..., fee: Decimal = Decimal(0)):
       # ...
       if side == "BUY":
           new_cost_basis = old_cost_basis + (qty * price) + fee
       else:
           # Fee réduit le PnL réalisé
           trade_realized = qty * (price - old_avg) - fee
   ```

5. **Créer script de flatten positions crypto**
   ```python
   # Dans scripts/flatten_crypto.py (nouveau fichier)
   import asyncio
   from apps.execution_crypto.src.ccxt_adapter import CCXTAdapter
   from autollm_trader.storage.postgres import LedgerStore
   import os

   async def flatten_all_crypto():
       """Ferme toutes les positions crypto (pour kill-switch)"""
       adapter = CCXTAdapter(
           exchange_id=os.getenv("CRYPTO_EXCHANGE", "binance"),
           api_key=os.getenv("BINANCE_API_KEY"),
           api_secret=os.getenv("BINANCE_API_SECRET"),
           testnet=os.getenv("CRYPTO_TESTNET", "true").lower() == "true"
       )

       ledger = LedgerStore()
       await ledger.connect()

       # Fetch crypto positions from ledger
       async with ledger.pool.acquire() as conn:
           positions = await conn.fetch(
               "SELECT * FROM positions WHERE symbol LIKE '%_USDT' AND qty != 0"
           )

       for pos in positions:
           symbol = pos["symbol"]
           qty = abs(float(pos["qty"]))
           side = "SELL" if pos["qty"] > 0 else "BUY"

           try:
               result = await adapter.place_order(symbol, side, qty, "market")
               print(f"Closed {symbol}: {side} {qty} → {result['id']}")
           except Exception as e:
               print(f"Failed to close {symbol}: {e}")

       adapter.close()
       await ledger.pool.close()

   if __name__ == "__main__":
       asyncio.run(flatten_all_crypto())
   ```

6. **Intégrer flatten_crypto au kill-switch**
   ```python
   # Dans apps/risk_manager/src/cli.py
   import subprocess

   def trigger_kill_switch():
       # ... existing code ...

       # Flatten crypto positions
       if os.getenv("CRYPTO_ENABLED", "false").lower() == "true":
           print("Flattening crypto positions...")
           subprocess.run(["python", "scripts/flatten_crypto.py"])
   ```

7. **Ajouter tests unitaires CCXT adapter**
   ```python
   # Dans tests/unit/test_ccxt_adapter.py (nouveau fichier)
   import pytest
   from unittest.mock import AsyncMock, patch, MagicMock
   from apps.execution_crypto.src.ccxt_adapter import CCXTAdapter
   from decimal import Decimal

   @pytest.mark.asyncio
   async def test_place_market_buy_order():
       with patch("ccxt.binance") as mock_binance_class:
           mock_exchange = MagicMock()
           mock_exchange.create_market_buy_order = AsyncMock(return_value={
               "id": "12345",
               "symbol": "BTC/USDT",
               "side": "buy",
               "price": 50000.0,
               "amount": 0.1,
               "timestamp": 1704067200000
           })
           mock_binance_class.return_value = mock_exchange

           adapter = CCXTAdapter("binance", "key", "secret", testnet=True)
           result = await adapter.place_order("BTC_USDT", "BUY", Decimal("0.1"), "market")

           assert result["id"] == "12345"
           assert result["side"] == "buy"

   @pytest.mark.asyncio
   async def test_insufficient_funds_error():
       with patch("ccxt.binance") as mock_binance_class:
           mock_exchange = MagicMock()
           mock_exchange.create_market_buy_order = AsyncMock(
               side_effect=ccxt.InsufficientFunds("Not enough balance")
           )
           mock_binance_class.return_value = mock_exchange

           adapter = CCXTAdapter("binance", "key", "secret", testnet=True)

           with pytest.raises(ccxt.InsufficientFunds):
               await adapter.place_order("BTC_USDT", "BUY", Decimal("100"), "market")
   ```

**Tests de validation:**
```bash
# 1. Configurer testnet Binance
export CRYPTO_ENABLED=true
export CRYPTO_TESTNET=true
export BINANCE_API_KEY="your_testnet_key"
export BINANCE_API_SECRET="your_testnet_secret"

# 2. Démarrer service
docker-compose up execution_crypto

# 3. Publier fake approved order
nats pub risk.order.approved '{
  "symbol": "BTC_USDT",
  "side": "BUY",
  "qty": 0.001,
  "order_type": "market",
  "llm_signature": "...",
  "risk_signature": "...",
  "payload": "..."
}'

# 4. Vérifier ordre sur Binance testnet UI

# 5. Vérifier event exec.order.filled
nats sub exec.order.filled

# 6. Tester flatten
python scripts/flatten_crypto.py
```

**Critères d'acceptation:**
- [ ] CCXTAdapter implémenté (market/limit orders)
- [ ] CryptoExecutorService complet
- [ ] Support Binance testnet
- [ ] Fees inclus dans cost_basis
- [ ] Heartbeat publié
- [ ] Script flatten_crypto.py
- [ ] Intégration kill-switch
- [ ] Tests unitaires CCXT
- [ ] Documentation .env.template
- [ ] E2E test avec testnet

---

### 📊 TASK 2.2: Feature Pipeline - Indicateurs Avancés & ML Features (Priorité: HAUTE)

**Contexte:**
Feature pipeline limité à SMA/RSI/ATR. Besoin de MACD, Bollinger Bands, Volume Profile, et features ML.

**Actions:**

1. **Installer dépendances supplémentaires**
   ```bash
   poetry add ta  # Technical Analysis Library (80+ indicators)
   ```

2. **Étendre FeatureProcessor avec indicateurs avancés**
   ```python
   # Dans apps/feature_pipeline/src/processor.py
   import ta
   from ta.trend import MACD, EMAIndicator
   from ta.volatility import BollingerBands
   from ta.volume import VolumeWeightedAveragePrice, OnBalanceVolumeIndicator
   from scipy import stats
   import numpy as np

   class FeatureProcessor:
       def calculate_features(self, bars: list) -> dict:
           """Calculate all features from bars"""
           if len(bars) < 50:
               return {}

           closes = [float(b.close) for b in bars]
           highs = [float(b.high) for b in bars]
           lows = [float(b.low) for b in bars]
           volumes = [float(b.volume) for b in bars]

           df = pd.DataFrame({
               "close": closes,
               "high": highs,
               "low": lows,
               "volume": volumes
           })

           features = {}

           # === TREND INDICATORS ===
           features["SMA_5"] = df["close"].rolling(5).mean().iloc[-1]
           features["SMA_20"] = df["close"].rolling(20).mean().iloc[-1]
           features["EMA_12"] = EMAIndicator(df["close"], window=12).ema_indicator().iloc[-1]
           features["EMA_26"] = EMAIndicator(df["close"], window=26).ema_indicator().iloc[-1]

           # MACD
           macd = MACD(df["close"])
           features["MACD"] = macd.macd().iloc[-1]
           features["MACD_signal"] = macd.macd_signal().iloc[-1]
           features["MACD_diff"] = macd.macd_diff().iloc[-1]

           # === MOMENTUM INDICATORS ===
           features["RSI_14"] = ta.momentum.RSIIndicator(df["close"], window=14).rsi().iloc[-1]
           features["Stochastic_K"] = ta.momentum.StochasticOscillator(
               df["high"], df["low"], df["close"]
           ).stoch().iloc[-1]

           # === VOLATILITY INDICATORS ===
           features["ATR"] = ta.volatility.AverageTrueRange(
               df["high"], df["low"], df["close"]
           ).average_true_range().iloc[-1]

           bb = BollingerBands(df["close"], window=20, window_dev=2)
           features["BB_upper"] = bb.bollinger_hband().iloc[-1]
           features["BB_middle"] = bb.bollinger_mavg().iloc[-1]
           features["BB_lower"] = bb.bollinger_lband().iloc[-1]
           features["BB_width"] = bb.bollinger_wband().iloc[-1]
           features["BB_pct"] = bb.bollinger_pband().iloc[-1]  # % position in bands

           # === VOLUME INDICATORS ===
           features["OBV"] = OnBalanceVolumeIndicator(df["close"], df["volume"]).on_balance_volume().iloc[-1]
           features["VWAP"] = (df["close"] * df["volume"]).sum() / df["volume"].sum()

           # Volume SMA ratio
           vol_sma = df["volume"].rolling(20).mean().iloc[-1]
           features["Volume_ratio"] = df["volume"].iloc[-1] / vol_sma if vol_sma > 0 else 1.0

           # === ML FEATURES ===

           # Returns (1-period, 5-period, 20-period)
           features["Return_1"] = (closes[-1] - closes[-2]) / closes[-2] if len(closes) > 1 else 0
           features["Return_5"] = (closes[-1] - closes[-6]) / closes[-6] if len(closes) > 5 else 0
           features["Return_20"] = (closes[-1] - closes[-21]) / closes[-21] if len(closes) > 20 else 0

           # Rolling statistics (20-period)
           returns_20 = pd.Series(closes).pct_change().tail(20)
           features["Return_mean_20"] = returns_20.mean()
           features["Return_std_20"] = returns_20.std()
           features["Return_skew_20"] = returns_20.skew()
           features["Return_kurt_20"] = returns_20.kurtosis()

           # Z-score (distance from mean in std devs)
           mean_20 = df["close"].rolling(20).mean().iloc[-1]
           std_20 = df["close"].rolling(20).std().iloc[-1]
           features["Zscore_20"] = (closes[-1] - mean_20) / std_20 if std_20 > 0 else 0

           # Lag features (yesterday, 2 days ago, 5 days ago)
           features["Close_lag_1"] = closes[-2] if len(closes) > 1 else closes[-1]
           features["Close_lag_2"] = closes[-3] if len(closes) > 2 else closes[-1]
           features["Close_lag_5"] = closes[-6] if len(closes) > 5 else closes[-1]

           # Autocorrelation (trend persistence)
           if len(returns_20) > 5:
               features["Autocorr_5"] = returns_20.autocorr(lag=5)
           else:
               features["Autocorr_5"] = 0

           # Range (high-low normalized by close)
           features["Range_pct"] = (highs[-1] - lows[-1]) / closes[-1]

           # Momentum (rate of change)
           features["Momentum_10"] = (closes[-1] - closes[-11]) / closes[-11] if len(closes) > 10 else 0

           return features
   ```

3. **Ajouter normalization/standardization**
   ```python
   # Dans apps/feature_pipeline/src/processor.py
   from sklearn.preprocessing import StandardScaler
   import pickle

   class FeatureProcessor:
       def __init__(self):
           self.scalers = {}  # {symbol: StandardScaler}
           self.scaler_path = "data/scalers"
           os.makedirs(self.scaler_path, exist_ok=True)

       def normalize_features(self, symbol: str, features: dict) -> dict:
           """Normalize features using fitted scaler"""
           # Load or create scaler
           scaler_file = f"{self.scaler_path}/{symbol}_scaler.pkl"

           if symbol not in self.scalers:
               if os.path.exists(scaler_file):
                   with open(scaler_file, "rb") as f:
                       self.scalers[symbol] = pickle.load(f)
               else:
                   self.scalers[symbol] = StandardScaler()

           scaler = self.scalers[symbol]

           # Convert to array
           feature_names = sorted(features.keys())
           values = np.array([[features[k] for k in feature_names]])

           # Fit or transform
           if not hasattr(scaler, "mean_"):
               # First time: fit
               scaled = scaler.fit_transform(values)

               # Save scaler
               with open(scaler_file, "wb") as f:
                   pickle.dump(scaler, f)
           else:
               # Transform only
               scaled = scaler.transform(values)

           # Convert back to dict
           normalized = {k: scaled[0][i] for i, k in enumerate(feature_names)}

           return normalized
   ```

4. **Créer service de feature engineering en temps réel**
   ```python
   # Dans apps/feature_pipeline/src/main.py (améliorer existant)
   class FeaturePipelineService:
       async def on_bar(self, msg):
           """Process new bar and calculate features"""
           try:
               data = json.loads(msg.data.decode())
               symbol = data["symbol"]
               timeframe = data["timeframe"]

               # Add to buffer
               self.bar_buffers[symbol][timeframe].append(data)

               # Calculate features if enough bars
               bars = self.bar_buffers[symbol][timeframe]
               if len(bars) >= 50:
                   features = self.processor.calculate_features(bars)

                   # Normalize
                   normalized = self.processor.normalize_features(symbol, features)

                   # Store in DuckDB
                   await self.feature_store.upsert_snapshot(
                       symbol, timeframe, normalized
                   )

                   # Publish
                   await self.nats.nc.publish(
                       f"features.snapshot.{symbol}",
                       json.dumps({
                           "symbol": symbol,
                           "timeframe": timeframe,
                           "features": normalized,
                           "timestamp": datetime.now().isoformat()
                       }).encode()
                   )

                   logger.debug(f"Published {len(normalized)} features for {symbol}")

               await msg.ack()
           except Exception as e:
               logger.error(f"Bar processing error: {e}", exc_info=True)
               await msg.nak()
   ```

5. **Ajouter endpoint API pour feature exploration**
   ```python
   # Dans apps/gateway_api/src/main.py
   @app.get("/api/features/{symbol}")
   async def get_features(symbol: str, timeframe: str = "1m"):
       """Fetch latest features for symbol"""
       async with feature_store.conn() as conn:
           row = await conn.fetchrow(
               """
               SELECT * FROM feature_snapshots
               WHERE symbol = $1 AND timeframe = $2
               ORDER BY ts DESC LIMIT 1
               """,
               symbol, timeframe
           )

           if not row:
               raise HTTPException(404, "Features not found")

           return {
               "symbol": symbol,
               "timeframe": timeframe,
               "timestamp": row["ts"].isoformat(),
               "features": row["features"]
           }

   @app.get("/api/features/{symbol}/history")
   async def get_feature_history(
       symbol: str,
       start: str,
       end: str,
       timeframe: str = "1m"
   ):
       """Fetch historical features for backtesting"""
       async with feature_store.conn() as conn:
           rows = await conn.fetch(
               """
               SELECT * FROM feature_snapshots
               WHERE symbol = $1 AND timeframe = $2
                 AND ts BETWEEN $3 AND $4
               ORDER BY ts ASC
               """,
               symbol, timeframe,
               datetime.fromisoformat(start),
               datetime.fromisoformat(end)
           )

           return [
               {
                   "timestamp": row["ts"].isoformat(),
                   "features": row["features"]
               }
               for row in rows
           ]
   ```

6. **Ajouter TTL sur snapshots DuckDB**
   ```python
   # Dans autollm_trader/storage/duckdb.py
   class FeatureStore:
       async def cleanup_old_snapshots(self, retention_days: int = 90):
           """Delete snapshots older than retention period"""
           cutoff = datetime.now() - timedelta(days=retention_days)

           self.conn.execute(
               """
               DELETE FROM feature_snapshots
               WHERE ts < ?
               """,
               [cutoff]
           )

           deleted = self.conn.execute("SELECT changes()").fetchone()[0]
           logger.info(f"Cleaned up {deleted} old snapshots (>{retention_days} days)")

       async def run_periodic_cleanup(self):
           """Run cleanup daily"""
           while True:
               await asyncio.sleep(86400)  # 24h
               await self.cleanup_old_snapshots()

   # Dans apps/feature_pipeline/src/main.py
   async def start(self):
       # ...
       asyncio.create_task(self.feature_store.run_periodic_cleanup())
   ```

7. **Créer script d'export Parquet pour ML training**
   ```python
   # Dans scripts/export_features_parquet.py (nouveau fichier)
   import duckdb
   import argparse
   from datetime import datetime

   def export_features(symbol: str, start: str, end: str, output: str):
       """Export features to Parquet for ML training"""
       conn = duckdb.connect("data/storage/features.duckdb", read_only=True)

       query = f"""
       COPY (
           SELECT * FROM feature_snapshots
           WHERE symbol = '{symbol}'
             AND ts BETWEEN '{start}' AND '{end}'
           ORDER BY ts ASC
       ) TO '{output}' (FORMAT PARQUET)
       """

       conn.execute(query)
       print(f"Exported features to {output}")

   if __name__ == "__main__":
       parser = argparse.ArgumentParser()
       parser.add_argument("--symbol", required=True)
       parser.add_argument("--start", required=True)
       parser.add_argument("--end", required=True)
       parser.add_argument("--output", default="data/features.parquet")

       args = parser.parse_args()
       export_features(args.symbol, args.start, args.end, args.output)
   ```

8. **Tests unitaires pour nouveaux indicateurs**
   ```python
   # Dans tests/unit/test_feature_processor.py
   def test_calculate_macd():
       processor = FeatureProcessor()

       # Generate fake bars
       closes = [100 + i*0.5 for i in range(50)]  # Uptrend
       bars = [MagicMock(close=c, high=c+1, low=c-1, volume=1000) for c in closes]

       features = processor.calculate_features(bars)

       assert "MACD" in features
       assert "MACD_signal" in features
       assert "MACD_diff" in features
       assert features["MACD"] != 0  # Should have signal

   def test_calculate_bollinger_bands():
       processor = FeatureProcessor()
       closes = [100] * 50  # Flat, low volatility
       bars = [MagicMock(close=c, high=c+0.5, low=c-0.5, volume=1000) for c in closes]

       features = processor.calculate_features(bars)

       assert "BB_upper" in features
       assert "BB_middle" in features
       assert "BB_lower" in features
       assert features["BB_middle"] == 100  # SMA should be 100
       assert features["BB_width"] < 5  # Narrow bands

   def test_normalize_features():
       processor = FeatureProcessor()

       features = {"SMA_5": 100.0, "RSI_14": 50.0, "MACD": 2.5}
       normalized = processor.normalize_features("TEST", features)

       # First time: mean ~0, std ~1 after normalization
       assert -3 < normalized["SMA_5"] < 3
   ```

**Tests de validation:**
```bash
# 1. Vérifier calcul features
docker-compose logs feature_pipeline | grep "Published.*features"

# 2. Fetch features via API
curl http://localhost:8000/api/features/AAPL

# 3. Export to Parquet
python scripts/export_features_parquet.py --symbol AAPL --start 2024-01-01 --end 2024-03-31 --output data/aapl_features.parquet

# 4. Charger Parquet dans pandas
python -c "
import pandas as pd
df = pd.read_parquet('data/aapl_features.parquet')
print(df.columns)
print(df.head())
"

# 5. Vérifier cleanup
# Attendre 24h ou forcer: docker-compose exec feature_pipeline python -c "from src.main import FeatureStore; store = FeatureStore(); store.cleanup_old_snapshots(retention_days=1)"
```

**Critères d'acceptation:**
- [ ] Library `ta` installée
- [ ] 20+ indicateurs calculés (MACD, Bollinger, OBV, VWAP, etc.)
- [ ] ML features (returns, z-scores, lags, autocorr)
- [ ] Normalization avec StandardScaler
- [ ] Endpoint API /api/features/{symbol}
- [ ] Export Parquet pour ML training
- [ ] TTL cleanup (90 jours)
- [ ] Tests unitaires pour nouveaux indicateurs
- [ ] Documentation features disponibles

---

### 🤖 TASK 2.3: LLM Agents - Sentence-Transformers & Multi-Model Support (Priorité: MOYENNE)

**Contexte:**
Embeddings actuellement hash-based (simpliste). Besoin de sentence-transformers pour embeddings de qualité, et support multi-modèles (Claude, Mistral).

**Actions:**

1. **Installer sentence-transformers**
   ```bash
   poetry add sentence-transformers torch
   ```

2. **Créer service d'embeddings**
   ```python
   # Dans autollm_trader/llm/embeddings.py (nouveau fichier)
   from sentence_transformers import SentenceTransformer
   import numpy as np
   from autollm_trader.logger import get_logger

   logger = get_logger(__name__)

   class EmbeddingService:
       def __init__(self, model_name: str = "all-MiniLM-L6-v2"):
           """
           Initialise sentence-transformers model

           Popular models:
           - all-MiniLM-L6-v2: Fast, 384-dim, good for general text
           - all-mpnet-base-v2: High quality, 768-dim
           - paraphrase-multilingual-MiniLM-L12-v2: Multilingual
           """
           logger.info(f"Loading embedding model: {model_name}")
           self.model = SentenceTransformer(model_name)
           self.dim = self.model.get_sentence_embedding_dimension()
           logger.info(f"Embedding model loaded (dim={self.dim})")

       def embed(self, text: str) -> np.ndarray:
           """Embed single text"""
           return self.model.encode(text, convert_to_numpy=True)

       def embed_batch(self, texts: list[str]) -> np.ndarray:
           """Embed multiple texts"""
           return self.model.encode(texts, convert_to_numpy=True, batch_size=32)
   ```

3. **Remplacer hash embeddings dans LayeredMemory**
   ```python
   # Dans apps/llm_agents/src/memory.py
   from autollm_trader.llm.embeddings import EmbeddingService

   class LayeredMemory:
       def __init__(self, layers: list[LayerConfig]):
           self.layers = layers

           # Initialize embedding service
           self.embeddings = EmbeddingService(
               model_name=os.getenv("EMBEDDING_MODEL", "all-MiniLM-L6-v2")
           )
           self.dim = self.embeddings.dim

           # Initialize FAISS indexes with correct dimension
           for layer in self.layers:
               layer.index = faiss.IndexFlatIP(self.dim)  # Inner product

       def add(self, text: str, metadata: dict, importance: float = 0.5):
           """Add memory with sentence-transformer embedding"""
           # Embed text
           vector = self.embeddings.embed(text)

           # Normalize for cosine similarity (IndexFlatIP with normalized vectors = cosine)
           faiss.normalize_L2(vector.reshape(1, -1))

           # Add to appropriate layer
           layer = self._select_layer(metadata.get("timestamp"))
           layer.index.add(vector.reshape(1, -1))
           layer.metadata.append({
               "text": text,
               "timestamp": metadata.get("timestamp"),
               "importance": importance,
               **metadata
           })

       def query(self, query_text: str, k: int = 5) -> list[dict]:
           """Query memories with semantic search"""
           # Embed query
           query_vector = self.embeddings.embed(query_text)
           faiss.normalize_L2(query_vector.reshape(1, -1))

           results = []

           # Search each layer
           for layer in self.layers:
               if layer.index.ntotal == 0:
                   continue

               distances, indices = layer.index.search(
                   query_vector.reshape(1, -1),
                   min(k, layer.index.ntotal)
               )

               for dist, idx in zip(distances[0], indices[0]):
                   if idx < len(layer.metadata):
                       mem = layer.metadata[idx]

                       # Score = relevancy + recency + importance
                       relevancy = float(dist)  # Cosine similarity
                       recency = self._calculate_recency(mem["timestamp"])
                       importance = mem.get("importance", 0.5)

                       score = (
                           0.5 * relevancy +
                           0.3 * recency +
                           0.2 * importance
                       )

                       results.append({
                           "text": mem["text"],
                           "score": score,
                           "relevancy": relevancy,
                           "recency": recency,
                           "importance": importance,
                           "metadata": mem
                       })

           # Sort by score
           results.sort(key=lambda x: x["score"], reverse=True)
           return results[:k]
   ```

4. **Installer litellm pour multi-model support**
   ```bash
   poetry add litellm
   ```

5. **Créer LLM client unifié**
   ```python
   # Dans autollm_trader/llm/client.py (nouveau fichier)
   from litellm import completion
   import os
   from typing import Optional
   from autollm_trader.logger import get_logger

   logger = get_logger(__name__)

   class UnifiedLLMClient:
       def __init__(self):
           self.provider = os.getenv("LLM_PROVIDER", "openai")  # openai, anthropic, openrouter
           self.model = os.getenv("LLM_MODEL", "gpt-4o-mini")
           self.api_key = self._get_api_key()

           logger.info(f"LLM Client initialized: provider={self.provider}, model={self.model}")

       def _get_api_key(self) -> str:
           """Get API key based on provider"""
           if self.provider == "openai":
               return os.getenv("OPENAI_API_KEY")
           elif self.provider == "anthropic":
               return os.getenv("ANTHROPIC_API_KEY")
           elif self.provider == "openrouter":
               return os.getenv("OPENROUTER_API_KEY")
           else:
               raise ValueError(f"Unknown provider: {self.provider}")

       def chat(self, messages: list[dict], temperature: float = 0.7,
                max_tokens: Optional[int] = None) -> str:
           """Send chat completion request"""
           try:
               response = completion(
                   model=self.model,
                   messages=messages,
                   temperature=temperature,
                   max_tokens=max_tokens,
                   api_key=self.api_key
               )

               return response.choices[0].message.content

           except Exception as e:
               logger.error(f"LLM completion failed: {e}")
               raise

       def chat_structured(self, messages: list[dict], response_format: dict,
                          temperature: float = 0.7) -> dict:
           """Chat with structured JSON output (OpenAI function calling)"""
           try:
               response = completion(
                   model=self.model,
                   messages=messages,
                   temperature=temperature,
                   response_format=response_format,
                   api_key=self.api_key
               )

               return json.loads(response.choices[0].message.content)

           except Exception as e:
               logger.error(f"Structured LLM completion failed: {e}")
               raise
   ```

6. **Remplacer OpenAI client par UnifiedLLMClient**
   ```python
   # Dans apps/llm_agents/src/llm_client.py
   from autollm_trader.llm.client import UnifiedLLMClient

   class LLMClient:
       def __init__(self):
           self.client = UnifiedLLMClient()
           self.fallback_enabled = os.getenv("LLM_FALLBACK_ENABLED", "true").lower() == "true"

       def run_analyst(self, symbol: str, context: dict) -> dict:
           """Run analyst agent"""
           try:
               messages = [
                   {"role": "system", "content": ANALYST_SYSTEM_PROMPT},
                   {"role": "user", "content": self._format_analyst_prompt(symbol, context)}
               ]

               response_format = {
                   "type": "json_schema",
                   "json_schema": AnalystOutput.model_json_schema()
               }

               result = self.client.chat_structured(messages, response_format, temperature=0.7)
               return AnalystOutput(**result).dict()

           except Exception as e:
               logger.error(f"Analyst LLM failed: {e}")

               if self.fallback_enabled:
                   logger.warning("Using fallback heuristic")
                   return self._fallback_analyst(symbol, context)
               else:
                   raise
   ```

7. **Mettre à jour .env.template**
   ```bash
   # LLM Configuration
   LLM_PROVIDER=openai  # openai, anthropic, openrouter
   LLM_MODEL=gpt-4o-mini  # or claude-3-5-sonnet-20241022, mistral-large-latest
   LLM_FALLBACK_ENABLED=true

   # API Keys
   OPENAI_API_KEY=
   ANTHROPIC_API_KEY=
   OPENROUTER_API_KEY=

   # Embeddings
   EMBEDDING_MODEL=all-MiniLM-L6-v2  # sentence-transformers model
   ```

8. **Créer script de comparaison embeddings**
   ```python
   # Dans scripts/compare_embeddings.py (nouveau fichier)
   from autollm_trader.llm.embeddings import EmbeddingService
   from sklearn.metrics.pairwise import cosine_similarity

   def compare_embeddings():
       """Compare embedding quality"""
       embedder = EmbeddingService()

       texts = [
           "Apple stock price surges on strong earnings",
           "AAPL shares jump after quarterly results",
           "Bitcoin price crashes below $40k",
           "The weather is nice today"
       ]

       embeddings = embedder.embed_batch(texts)

       # Compute similarity matrix
       sim_matrix = cosine_similarity(embeddings)

       print("Similarity Matrix:")
       print("                     ", " | ".join([f"Text{i}" for i in range(len(texts))]))
       for i, row in enumerate(sim_matrix):
           print(f"Text{i}: {texts[i][:30]:30s}", " | ".join([f"{x:.3f}" for x in row]))

       # Expect: Text0 & Text1 high similarity (both about Apple earnings)
       # Text2 low similarity (different topic)
       # Text3 very low similarity (unrelated)

       assert sim_matrix[0][1] > 0.7, "Similar texts should have high cosine similarity"
       assert sim_matrix[0][3] < 0.3, "Unrelated texts should have low similarity"

       print("\n✓ Embedding quality check passed")

   if __name__ == "__main__":
       compare_embeddings()
   ```

**Tests de validation:**
```bash
# 1. Tester embeddings
python scripts/compare_embeddings.py

# 2. Tester multi-model support
export LLM_PROVIDER=anthropic
export ANTHROPIC_API_KEY="your_key"
export LLM_MODEL="claude-3-5-sonnet-20241022"

docker-compose restart llm_agents
docker-compose logs llm_agents | grep "LLM Client initialized"

# 3. Tester memory query avec semantic search
# TODO: Ajouter endpoint API pour tester query

# 4. Comparer temps d'inférence hash vs sentence-transformers
# (sentence-transformers sera plus lent mais beaucoup plus précis)
```

**Critères d'acceptation:**
- [ ] sentence-transformers installé
- [ ] EmbeddingService implémenté
- [ ] LayeredMemory utilise sentence-transformers
- [ ] litellm installé
- [ ] UnifiedLLMClient supporte OpenAI/Anthropic/OpenRouter
- [ ] Fallback heuristic si LLM fail
- [ ] .env.template mis à jour
- [ ] Script compare_embeddings.py
- [ ] Tests unitaires embeddings
- [ ] Documentation modèles supportés

---

### 📈 TASK 2.4: Backtest Engine Vectorized & LLM Integration (Priorité: MOYENNE)

**Contexte:**
Backtest engine actuel est simpliste (SMA crossover en boucle Python). Besoin de backtest vectorized rapide avec intégration LLM agents.

**Actions:**

1. **Installer vectorbt**
   ```bash
   poetry add vectorbt quantstats empyrical
   ```

2. **Créer backtest vectorized avec vectorbt**
   ```python
   # Dans apps/backtest_engine/src/vectorized.py (nouveau fichier)
   import vectorbt as vbt
   import pandas as pd
   import numpy as np
   import yfinance as yf
   from datetime import datetime
   from autollm_trader.logger import get_logger
   import json

   logger = get_logger(__name__)

   class VectorizedBacktest:
       def __init__(self, symbol: str, start: str, end: str,
                    initial_capital: float = 100000.0,
                    commission: float = 0.001):  # 0.1% commission
           self.symbol = symbol
           self.start = start
           self.end = end
           self.initial_capital = initial_capital
           self.commission = commission

           # Download data
           logger.info(f"Downloading {symbol} data from {start} to {end}")
           self.data = yf.download(symbol, start=start, end=end, interval="1d")

       def run_sma_strategy(self, fast_period: int = 10, slow_period: int = 30):
           """Simple SMA crossover strategy"""
           close = self.data["Close"]

           # Calculate SMAs
           fast_sma = vbt.MA.run(close, fast_period)
           slow_sma = vbt.MA.run(slow_period, close)

           # Generate signals
           entries = fast_sma.ma_crossed_above(slow_sma)
           exits = fast_sma.ma_crossed_below(slow_sma)

           # Run backtest
           portfolio = vbt.Portfolio.from_signals(
               close,
               entries,
               exits,
               init_cash=self.initial_capital,
               fees=self.commission,
               freq="1D"
           )

           return portfolio

       def run_rsi_strategy(self, rsi_period: int = 14,
                           oversold: int = 30, overbought: int = 70):
           """RSI mean-reversion strategy"""
           close = self.data["Close"]

           # Calculate RSI
           rsi = vbt.RSI.run(close, window=rsi_period)

           # Generate signals
           entries = rsi.rsi_below(oversold)
           exits = rsi.rsi_above(overbought)

           # Run backtest
           portfolio = vbt.Portfolio.from_signals(
               close,
               entries,
               exits,
               init_cash=self.initial_capital,
               fees=self.commission,
               freq="1D"
           )

           return portfolio

       def get_metrics(self, portfolio: vbt.Portfolio) -> dict:
           """Extract performance metrics"""
           stats = portfolio.stats()

           return {
               "total_return": float(stats["Total Return [%]"]),
               "sharpe_ratio": float(stats["Sharpe Ratio"]),
               "max_drawdown": float(stats["Max Drawdown [%]"]),
               "total_trades": int(stats["Total Trades"]),
               "win_rate": float(stats["Win Rate [%]"]),
               "profit_factor": float(stats["Profit Factor"]),
               "final_value": float(portfolio.final_value()),
               "buy_and_hold_return": float(
                   (self.data["Close"].iloc[-1] / self.data["Close"].iloc[0] - 1) * 100
               )
           }

       def generate_report(self, portfolio: vbt.Portfolio, output_path: str):
           """Generate backtest report"""
           metrics = self.get_metrics(portfolio)

           report = {
               "symbol": self.symbol,
               "start_date": self.start,
               "end_date": self.end,
               "initial_capital": self.initial_capital,
               "commission": self.commission,
               "metrics": metrics,
               "trades": portfolio.trades.records_readable.to_dict("records"),
               "equity_curve": portfolio.value().to_dict()
           }

           with open(output_path, "w") as f:
               json.dump(report, f, indent=2, default=str)

           logger.info(f"Report saved to {output_path}")
           return report
   ```

3. **Créer backtest avec intégration LLM (replay historique)**
   ```python
   # Dans apps/backtest_engine/src/llm_backtest.py (nouveau fichier)
   import asyncio
   from datetime import datetime, timedelta
   from autollm_trader.storage.duckdb import FeatureStore
   from apps.llm_agents.src.graph import create_trading_graph
   from apps.llm_agents.src.memory import LayeredMemory
   from autollm_trader.logger import get_logger
   import pandas as pd
   import yfinance as yf

   logger = get_logger(__name__)

   class LLMBacktest:
       """Backtest with actual LLM decision replay"""

       def __init__(self, symbol: str, start: str, end: str,
                    initial_capital: float = 100000.0):
           self.symbol = symbol
           self.start = datetime.fromisoformat(start)
           self.end = datetime.fromisoformat(end)
           self.initial_capital = initial_capital

           # Initialize components
           self.feature_store = FeatureStore()
           self.memory = LayeredMemory([])  # TODO: Initialize with config
           self.graph = create_trading_graph()

           # State
           self.cash = initial_capital
           self.position = 0
           self.trades = []
           self.equity_curve = []

       async def run(self):
           """Run backtest day by day"""
           logger.info(f"Running LLM backtest for {self.symbol} from {self.start} to {self.end}")

           # Download historical prices
           prices = yf.download(self.symbol, start=self.start, end=self.end, interval="1d")

           current_date = self.start
           while current_date <= self.end:
               # Fetch features for this date
               features = await self._fetch_features(current_date)

               if not features:
                   current_date += timedelta(days=1)
                   continue

               # Get LLM decision
               decision = await self._get_llm_decision(current_date, features)

               # Execute trade
               if current_date.strftime("%Y-%m-%d") in prices.index:
                   price = float(prices.loc[current_date.strftime("%Y-%m-%d"), "Close"])
                   self._execute_trade(decision, price, current_date)

               # Record equity
               equity = self.cash + (self.position * price if price else 0)
               self.equity_curve.append({
                   "date": current_date,
                   "equity": equity,
                   "cash": self.cash,
                   "position": self.position
               })

               current_date += timedelta(days=1)

           logger.info(f"Backtest completed: {len(self.trades)} trades")
           return self._calculate_metrics()

       async def _fetch_features(self, date: datetime) -> dict:
           """Fetch features from DuckDB for given date"""
           async with self.feature_store.conn() as conn:
               row = await conn.fetchrow(
                   """
                   SELECT features FROM feature_snapshots
                   WHERE symbol = $1 AND DATE(ts) = $2
                   ORDER BY ts DESC LIMIT 1
                   """,
                   self.symbol, date.date()
               )
               return row["features"] if row else None

       async def _get_llm_decision(self, date: datetime, features: dict) -> dict:
           """Run LLM graph to get trading decision"""
           # Query memory for relevant context
           memories = self.memory.query(
               f"Recent market analysis for {self.symbol}",
               k=5
           )

           # Prepare state
           state = {
               "symbol": self.symbol,
               "date": date,
               "features": features,
               "memories": [m["text"] for m in memories],
               "position": self.position,
               "cash": self.cash
           }

           # Run graph
           result = await self.graph.ainvoke(state)

           # Extract decision
           decision = result.get("trader_decision", {})
           return decision

       def _execute_trade(self, decision: dict, price: float, date: datetime):
           """Execute trade based on LLM decision"""
           action = decision.get("action", "HOLD")
           confidence = decision.get("confidence", 0)

           if action == "BUY" and confidence > 0.6 and self.cash > 0:
               # Buy with 100% of cash (simplification)
               qty = int(self.cash / price)
               if qty > 0:
                   cost = qty * price * 1.001  # 0.1% commission
                   self.cash -= cost
                   self.position += qty

                   self.trades.append({
                       "date": date,
                       "action": "BUY",
                       "qty": qty,
                       "price": price,
                       "confidence": confidence
                   })

                   logger.info(f"{date.date()} BUY {qty} @ {price:.2f} (conf={confidence:.2f})")

           elif action == "SELL" and confidence > 0.6 and self.position > 0:
               # Sell entire position
               qty = self.position
               proceeds = qty * price * 0.999  # 0.1% commission
               self.cash += proceeds
               self.position = 0

               self.trades.append({
                   "date": date,
                   "action": "SELL",
                   "qty": qty,
                   "price": price,
                   "confidence": confidence
               })

               logger.info(f"{date.date()} SELL {qty} @ {price:.2f} (conf={confidence:.2f})")

       def _calculate_metrics(self) -> dict:
           """Calculate backtest metrics"""
           if not self.equity_curve:
               return {}

           equity_series = pd.Series([e["equity"] for e in self.equity_curve])
           returns = equity_series.pct_change().dropna()

           final_equity = self.equity_curve[-1]["equity"]
           total_return = (final_equity / self.initial_capital - 1) * 100

           # Max drawdown
           cummax = equity_series.cummax()
           drawdown = (equity_series - cummax) / cummax
           max_drawdown = drawdown.min() * 100

           # Sharpe ratio (annualized)
           sharpe = (returns.mean() / returns.std()) * np.sqrt(252) if returns.std() > 0 else 0

           # Win rate
           winning_trades = sum(1 for t in self.trades if t["action"] == "SELL" and self.trades[self.trades.index(t) - 1]["price"] < t["price"])
           win_rate = (winning_trades / len([t for t in self.trades if t["action"] == "SELL"])) * 100 if self.trades else 0

           return {
               "total_return": total_return,
               "sharpe_ratio": sharpe,
               "max_drawdown": max_drawdown,
               "total_trades": len(self.trades),
               "win_rate": win_rate,
               "final_equity": final_equity
           }
   ```

4. **Créer CLI amélioré**
   ```python
   # Dans apps/backtest_engine/src/cli.py (améliorer existant)
   import argparse
   import asyncio
   from .vectorized import VectorizedBacktest
   from .llm_backtest import LLMBacktest
   import quantstats as qs

   def main():
       parser = argparse.ArgumentParser(description="Backtest Engine")
       parser.add_argument("--symbol", required=True)
       parser.add_argument("--start", required=True)
       parser.add_argument("--end", required=True)
       parser.add_argument("--strategy", default="sma", choices=["sma", "rsi", "llm"])
       parser.add_argument("--capital", type=float, default=100000)
       parser.add_argument("--report-dir", default="reports")
       parser.add_argument("--html-report", action="store_true", help="Generate HTML report")

       args = parser.parse_args()

       if args.strategy == "llm":
           # LLM backtest (async)
           backtest = LLMBacktest(args.symbol, args.start, args.end, args.capital)
           metrics = asyncio.run(backtest.run())
       else:
           # Vectorized backtest
           backtest = VectorizedBacktest(args.symbol, args.start, args.end, args.capital)

           if args.strategy == "sma":
               portfolio = backtest.run_sma_strategy()
           elif args.strategy == "rsi":
               portfolio = backtest.run_rsi_strategy()

           metrics = backtest.get_metrics(portfolio)

           # Generate report
           output_path = f"{args.report_dir}/backtest_{args.symbol}_{args.start}_{args.end}.json"
           backtest.generate_report(portfolio, output_path)

           # Generate HTML report with quantstats
           if args.html_report:
               returns = portfolio.returns()
               html_path = f"{args.report_dir}/backtest_{args.symbol}_{args.start}_{args.end}.html"
               qs.reports.html(returns, output=html_path, title=f"{args.symbol} Backtest")
               print(f"HTML report: {html_path}")

       print("\n=== BACKTEST RESULTS ===")
       for key, value in metrics.items():
           print(f"{key}: {value}")

   if __name__ == "__main__":
       main()
   ```

5. **Ajouter walk-forward optimization**
   ```python
   # Dans apps/backtest_engine/src/optimizer.py (nouveau fichier)
   from itertools import product
   from .vectorized import VectorizedBacktest
   import pandas as pd

   class WalkForwardOptimizer:
       """Walk-forward optimization pour éviter overfitting"""

       def __init__(self, symbol: str, start: str, end: str,
                    in_sample_days: int = 252, out_sample_days: int = 63):
           self.symbol = symbol
           self.start = datetime.fromisoformat(start)
           self.end = datetime.fromisoformat(end)
           self.in_sample_days = in_sample_days
           self.out_sample_days = out_sample_days

       def optimize_sma(self, fast_range: range, slow_range: range):
           """Grid search pour optimiser paramètres SMA"""
           results = []

           # Walk-forward windows
           current_start = self.start
           while current_start + timedelta(days=self.in_sample_days + self.out_sample_days) <= self.end:
               in_sample_end = current_start + timedelta(days=self.in_sample_days)
               out_sample_end = in_sample_end + timedelta(days=self.out_sample_days)

               # Grid search sur in-sample
               best_params = None
               best_sharpe = -999

               for fast, slow in product(fast_range, slow_range):
                   if fast >= slow:
                       continue

                   backtest = VectorizedBacktest(
                       self.symbol,
                       current_start.strftime("%Y-%m-%d"),
                       in_sample_end.strftime("%Y-%m-%d")
                   )

                   portfolio = backtest.run_sma_strategy(fast, slow)
                   metrics = backtest.get_metrics(portfolio)
                   sharpe = metrics["sharpe_ratio"]

                   if sharpe > best_sharpe:
                       best_sharpe = sharpe
                       best_params = (fast, slow)

               # Test sur out-sample avec best params
               backtest_out = VectorizedBacktest(
                   self.symbol,
                   in_sample_end.strftime("%Y-%m-%d"),
                   out_sample_end.strftime("%Y-%m-%d")
               )
               portfolio_out = backtest_out.run_sma_strategy(*best_params)
               metrics_out = backtest_out.get_metrics(portfolio_out)

               results.append({
                   "in_sample_start": current_start,
                   "in_sample_end": in_sample_end,
                   "out_sample_end": out_sample_end,
                   "best_params": best_params,
                   "in_sample_sharpe": best_sharpe,
                   "out_sample_sharpe": metrics_out["sharpe_ratio"],
                   "out_sample_return": metrics_out["total_return"]
               })

               current_start = out_sample_end

           return pd.DataFrame(results)
   ```

6. **Créer visualizations avec matplotlib**
   ```python
   # Dans apps/backtest_engine/src/visualization.py (nouveau fichier)
   import matplotlib.pyplot as plt
   import seaborn as sns
   import pandas as pd

   sns.set_style("darkgrid")

   def plot_equity_curve(equity_curve: list, output_path: str):
       """Plot equity curve"""
       df = pd.DataFrame(equity_curve)

       fig, ax = plt.subplots(figsize=(12, 6))
       ax.plot(df["date"], df["equity"], label="Portfolio Value", linewidth=2)
       ax.fill_between(df["date"], df["equity"], alpha=0.3)
       ax.set_xlabel("Date")
       ax.set_ylabel("Equity ($)")
       ax.set_title("Backtest Equity Curve")
       ax.legend()
       ax.grid(True)

       plt.tight_layout()
       plt.savefig(output_path, dpi=150)
       plt.close()

   def plot_drawdown(equity_curve: list, output_path: str):
       """Plot drawdown chart"""
       df = pd.DataFrame(equity_curve)
       equity = df["equity"]
       cummax = equity.cummax()
       drawdown = (equity - cummax) / cummax * 100

       fig, ax = plt.subplots(figsize=(12, 4))
       ax.fill_between(df["date"], drawdown, 0, color="red", alpha=0.3)
       ax.plot(df["date"], drawdown, color="red", linewidth=1)
       ax.set_xlabel("Date")
       ax.set_ylabel("Drawdown (%)")
       ax.set_title("Drawdown Over Time")
       ax.grid(True)

       plt.tight_layout()
       plt.savefig(output_path, dpi=150)
       plt.close()

   def plot_trade_distribution(trades: list, output_path: str):
       """Plot trade PnL distribution"""
       df = pd.DataFrame(trades)

       # Calculate PnL per trade (simplified)
       # TODO: Improve calculation

       fig, ax = plt.subplots(figsize=(10, 6))
       # ax.hist(pnl, bins=30, edgecolor="black", alpha=0.7)
       ax.set_xlabel("Trade P&L ($)")
       ax.set_ylabel("Frequency")
       ax.set_title("Trade P&L Distribution")
       ax.grid(True, axis="y")

       plt.tight_layout()
       plt.savefig(output_path, dpi=150)
       plt.close()
   ```

7. **Mettre à jour Makefile**
   ```makefile
   # Dans Makefile
   backtest-sma:
   	$(POETRY) run python -m apps.backtest_engine.src.cli \
   		--symbol AAPL --start 2023-01-01 --end 2023-12-31 \
   		--strategy sma --html-report

   backtest-llm:
   	$(POETRY) run python -m apps.backtest_engine.src.cli \
   		--symbol AAPL --start 2023-01-01 --end 2023-12-31 \
   		--strategy llm

   optimize:
   	$(POETRY) run python -m apps.backtest_engine.src.optimizer \
   		--symbol AAPL --start 2022-01-01 --end 2023-12-31
   ```

**Tests de validation:**
```bash
# 1. Backtest vectorized SMA
make backtest-sma
open reports/backtest_AAPL_2023-01-01_2023-12-31.html

# 2. Backtest LLM (nécessite features historiques dans DuckDB)
make backtest-llm

# 3. Walk-forward optimization
make optimize

# 4. Comparer vectorized vs LLM performance
# Expected: vectorized beaucoup plus rapide (~10x), LLM plus précis si well-tuned
```

**Critères d'acceptation:**
- [ ] vectorbt installé
- [ ] VectorizedBacktest implémenté (SMA, RSI)
- [ ] LLMBacktest avec replay historique
- [ ] quantstats HTML reports
- [ ] Walk-forward optimizer
- [ ] Visualizations (equity curve, drawdown)
- [ ] CLI support --strategy llm
- [ ] Makefile targets
- [ ] Tests unitaires backtest
- [ ] Documentation stratégies disponibles

---

## 📡 PHASE 3: OBSERVABILITÉ AVANCÉE (Semaines 6-7)

### 🔭 TASK 3.1: OpenTelemetry Distributed Tracing (Priorité: HAUTE)

**Contexte:**
Pas de traces distribuées pour suivre flow intent → risk → execution. Debugging multi-services difficile.

**Actions:**

1. **Installer OpenTelemetry**
   ```bash
   poetry add opentelemetry-api opentelemetry-sdk
   poetry add opentelemetry-instrumentation-fastapi
   poetry add opentelemetry-instrumentation-asyncpg
   poetry add opentelemetry-instrumentation-redis
   poetry add opentelemetry-exporter-jaeger
   ```

2. **Créer service de tracing**
   ```python
   # Dans autollm_trader/observability/tracing.py (nouveau fichier)
   from opentelemetry import trace
   from opentelemetry.sdk.trace import TracerProvider
   from opentelemetry.sdk.trace.export import BatchSpanProcessor
   from opentelemetry.exporter.jaeger.thrift import JaegerExporter
   from opentelemetry.sdk.resources import Resource
   from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
   from opentelemetry.instrumentation.asyncpg import AsyncPGInstrumentor
   from opentelemetry.instrumentation.redis import RedisInstrumentor
   import os
   from autollm_trader.logger import get_logger

   logger = get_logger(__name__)

   def setup_tracing(service_name: str):
       """Setup OpenTelemetry tracing"""
       jaeger_host = os.getenv("JAEGER_HOST", "localhost")
       jaeger_port = int(os.getenv("JAEGER_PORT", "6831"))

       # Create resource
       resource = Resource.create({"service.name": service_name})

       # Create tracer provider
       tracer_provider = TracerProvider(resource=resource)

       # Create Jaeger exporter
       jaeger_exporter = JaegerExporter(
           agent_host_name=jaeger_host,
           agent_port=jaeger_port,
       )

       # Add span processor
       tracer_provider.add_span_processor(
           BatchSpanProcessor(jaeger_exporter)
       )

       # Set global tracer provider
       trace.set_tracer_provider(tracer_provider)

       logger.info(f"Tracing initialized for {service_name} → Jaeger at {jaeger_host}:{jaeger_port}")

   def instrument_fastapi(app):
       """Instrument FastAPI app"""
       FastAPIInstrumentor.instrument_app(app)

   def instrument_asyncpg():
       """Instrument asyncpg (Postgres)"""
       AsyncPGInstrumentor().instrument()

   def instrument_redis():
       """Instrument Redis"""
       RedisInstrumentor().instrument()
   ```

3. **Intégrer tracing dans tous les services**
   ```python
   # Dans apps/gateway_api/src/main.py
   from autollm_trader.observability.tracing import setup_tracing, instrument_fastapi

   setup_tracing("gateway_api")
   instrument_fastapi(app)

   # Dans apps/llm_agents/src/main.py
   from autollm_trader.observability.tracing import setup_tracing

   setup_tracing("llm_agents")

   # Etc. pour tous les services
   ```

4. **Ajouter traces manuelles pour flow critique**
   ```python
   # Dans apps/llm_agents/src/service.py
   from opentelemetry import trace

   tracer = trace.get_tracer(__name__)

   async def process_features(self, features: dict):
       with tracer.start_as_current_span("llm.process_features") as span:
           span.set_attribute("symbol", features["symbol"])

           # Query memory
           with tracer.start_as_current_span("llm.query_memory"):
               memories = self.memory.query(features["symbol"], k=5)
               span.set_attribute("memory.results", len(memories))

           # Run graph
           with tracer.start_as_current_span("llm.run_graph"):
               decision = await self.graph.ainvoke({
                   "symbol": features["symbol"],
                   "features": features,
                   "memories": memories
               })
               span.set_attribute("decision.action", decision.get("action"))
               span.set_attribute("decision.confidence", decision.get("confidence"))

           return decision

   # Dans apps/risk_manager/src/service.py
   async def evaluate_intent(self, intent: dict):
       with tracer.start_as_current_span("risk.evaluate_intent") as span:
           span.set_attribute("symbol", intent["symbol"])
           span.set_attribute("side", intent["side"])

           # Evaluate
           with tracer.start_as_current_span("risk.check_limits"):
               approved, reasons = self.evaluator.evaluate_intent(intent)
               span.set_attribute("approved", approved)
               span.set_attribute("rejection_reasons", ",".join(reasons))

           return approved, reasons
   ```

5. **Ajouter Jaeger dans docker-compose**
   ```yaml
   # Dans infra/docker-compose.yml
   jaeger:
     image: jaegertracing/all-in-one:1.51
     ports:
       - "5775:5775/udp"   # zipkin.thrift compact
       - "6831:6831/udp"   # jaeger.thrift compact
       - "6832:6832/udp"   # jaeger.thrift binary
       - "5778:5778"       # serve configs
       - "16686:16686"     # UI
       - "14268:14268"     # jaeger.thrift HTTP
       - "14250:14250"     # model.proto gRPC
       - "9411:9411"       # zipkin
     environment:
       - COLLECTOR_ZIPKIN_HOST_PORT=:9411
       - COLLECTOR_OTLP_ENABLED=true
     networks:
       - autollm

   # Ajouter JAEGER_HOST dans tous les services
   gateway_api:
     environment:
       - JAEGER_HOST=jaeger
       - JAEGER_PORT=6831
   ```

6. **Créer dashboard Grafana pour traces**
   ```json
   // Dans infra/grafana/provisioning/datasources/jaeger.yml
   apiVersion: 1

   datasources:
     - name: Jaeger
       type: jaeger
       access: proxy
       url: http://jaeger:16686
       isDefault: false
   ```

7. **Ajouter métriques de latency par span**
   ```python
   # Dans autollm_trader/observability/tracing.py
   from opentelemetry.instrumentation.system_metrics import SystemMetricsInstrumentor
   from opentelemetry.instrumentation.runtime_metrics import RuntimeMetricsInstrumentor

   def setup_metrics():
       """Setup system and runtime metrics"""
       SystemMetricsInstrumentor().instrument()
       RuntimeMetricsInstrumentor().instrument()
   ```

**Tests de validation:**
```bash
# 1. Start Jaeger
docker-compose up jaeger

# 2. Access Jaeger UI
open http://localhost:16686

# 3. Trigger intent flow
curl -X POST http://localhost:8000/api/orders/manual -d '{...}'

# 4. Search traces in Jaeger UI
# Service: llm_agents → Operation: llm.process_features
# Should see full trace: gateway_api → llm_agents → risk_manager → execution_ib

# 5. Analyze latency breakdown
# Expected: memory query <50ms, LLM call ~500ms, risk eval <10ms, execution <2s
```

**Critères d'acceptation:**
- [ ] OpenTelemetry installé
- [ ] TracingService implémenté
- [ ] Tous les services instrumentés
- [ ] Spans manuels pour flow critique
- [ ] Jaeger running in docker-compose
- [ ] Grafana datasource Jaeger
- [ ] Traces visibles dans UI
- [ ] Latency breakdown analysable
- [ ] Documentation tracing

---

### 📊 TASK 3.2: Dashboards Grafana Détaillés (Priorité: HAUTE)

**Contexte:**
Dashboard `autollm.json` présent mais basique. Besoin de dashboards détaillés par service.

**Actions:**

1. **Créer dashboard Overview système**
   ```json
   // Dans infra/grafana/dashboards/overview.json
   {
     "title": "AutoLLM Trader - System Overview",
     "panels": [
       {
         "title": "Services Health",
         "targets": [
           {
             "expr": "up{job=~\".*autollm.*\"}",
             "legendFormat": "{{job}}"
           }
         ],
         "type": "stat"
       },
       {
         "title": "Total Intents (24h)",
         "targets": [
           {
             "expr": "sum(increase(llm_intents_total[24h]))"
           }
         ],
         "type": "stat"
       },
       {
         "title": "Risk Rejection Rate",
         "targets": [
           {
             "expr": "sum(rate(risk_rejections_total[5m])) / sum(rate(llm_intents_total[5m])) * 100"
           }
         ],
         "type": "gauge",
         "fieldConfig": {
           "min": 0,
           "max": 100,
           "thresholds": [
             {"value": 0, "color": "green"},
             {"value": 50, "color": "yellow"},
             {"value": 80, "color": "red"}
           ]
         }
       },
       {
         "title": "Execution Latency (p95)",
         "targets": [
           {
             "expr": "histogram_quantile(0.95, rate(execution_latency_seconds_bucket[5m]))"
           }
         ],
         "type": "graph"
       },
       {
         "title": "Open Positions",
         "targets": [
           {
             "expr": "open_positions"
           }
         ],
         "type": "graph"
       },
       {
         "title": "Intents by Symbol",
         "targets": [
           {
             "expr": "sum by (symbol) (increase(llm_intents_total[1h]))"
           }
         ],
         "type": "piechart"
       }
     ]
   }
   ```

2. **Créer dashboard LLM Agents**
   ```json
   // Dans infra/grafana/dashboards/llm_agents.json
   {
     "title": "LLM Agents Performance",
     "panels": [
       {
         "title": "LLM Latency by Stage",
         "targets": [
           {
             "expr": "rate(llm_stage_duration_seconds_sum[5m]) / rate(llm_stage_duration_seconds_count[5m])",
             "legendFormat": "{{stage}}"
           }
         ],
         "type": "graph"
       },
       {
         "title": "Memory Query Latency",
         "targets": [
           {
             "expr": "histogram_quantile(0.95, rate(memory_query_duration_seconds_bucket[5m]))"
           }
         ],
         "type": "graph"
       },
       {
         "title": "LLM Token Usage",
         "targets": [
           {
             "expr": "rate(llm_tokens_total[5m])",
             "legendFormat": "{{type}}"
           }
         ],
         "type": "graph"
       },
       {
         "title": "Decision Distribution",
         "targets": [
           {
             "expr": "sum by (action) (increase(llm_intents_total[1h]))"
           }
         ],
         "type": "piechart"
       },
       {
         "title": "Confidence Histogram",
         "targets": [
           {
             "expr": "histogram_quantile(0.50, rate(llm_confidence_bucket[5m]))",
             "legendFormat": "p50"
           },
           {
             "expr": "histogram_quantile(0.95, rate(llm_confidence_bucket[5m]))",
             "legendFormat": "p95"
           }
         ],
         "type": "graph"
       }
     ]
   }
   ```

3. **Créer dashboard Risk Manager**
   ```json
   // Dans infra/grafana/dashboards/risk_manager.json
   {
     "title": "Risk Manager",
     "panels": [
       {
         "title": "Rejections by Reason",
         "targets": [
           {
             "expr": "sum by (reason) (increase(risk_rejections_total[1h]))"
           }
         ],
         "type": "bargauge"
       },
       {
         "title": "Current Exposure",
         "targets": [
           {
             "expr": "risk_current_exposure_usd"
           }
         ],
         "type": "stat"
       },
       {
         "title": "Position Limits Status",
         "targets": [
           {
             "expr": "risk_position_limit_used_pct"
           }
         ],
         "type": "gauge",
         "fieldConfig": {
           "max": 100,
           "thresholds": [
             {"value": 0, "color": "green"},
             {"value": 70, "color": "yellow"},
             {"value": 90, "color": "red"}
           ]
         }
       },
       {
         "title": "Throttling Status",
         "targets": [
           {
             "expr": "rate(risk_throttled_total[5m])"
           }
         ],
         "type": "graph"
       },
       {
         "title": "Kill Switch Events",
         "targets": [
           {
             "expr": "increase(risk_kill_switch_total[24h])"
           }
         ],
         "type": "table"
       }
     ]
   }
   ```

4. **Créer dashboard Portfolio & PnL**
   ```json
   // Dans infra/grafana/dashboards/portfolio.json
   {
     "title": "Portfolio & P&L",
     "panels": [
       {
         "title": "Total P&L (Realized + Unrealized)",
         "targets": [
           {
             "expr": "portfolio_realized_pnl + portfolio_unrealized_pnl"
           }
         ],
         "type": "stat",
         "fieldConfig": {
           "unit": "currencyUSD"
         }
       },
       {
         "title": "Equity Curve",
         "targets": [
           {
             "expr": "portfolio_equity"
           }
         ],
         "type": "graph"
       },
       {
         "title": "Drawdown",
         "targets": [
           {
             "expr": "(portfolio_equity - portfolio_equity_max) / portfolio_equity_max * 100"
           }
         ],
         "type": "graph"
       },
       {
         "title": "Win Rate (24h)",
         "targets": [
           {
             "expr": "sum(increase(trades_winning_total[24h])) / sum(increase(trades_total[24h])) * 100"
           }
         ],
         "type": "gauge"
       },
       {
         "title": "Positions by Symbol",
         "targets": [
           {
             "expr": "sum by (symbol) (portfolio_position_qty)"
           }
         ],
         "type": "table"
       },
       {
         "title": "P&L by Symbol",
         "targets": [
           {
             "expr": "sum by (symbol) (portfolio_pnl_by_symbol)"
           }
         ],
         "type": "bargauge"
       }
     ]
   }
   ```

5. **Créer dashboard Execution Services**
   ```json
   // Dans infra/grafana/dashboards/execution.json
   {
     "title": "Execution Services",
     "panels": [
       {
         "title": "Execution Success Rate",
         "targets": [
           {
             "expr": "sum(rate(exec_orders_filled_total[5m])) / sum(rate(exec_orders_total[5m])) * 100"
           }
         ],
         "type": "gauge"
       },
       {
         "title": "Execution Latency by Broker",
         "targets": [
           {
             "expr": "histogram_quantile(0.95, rate(execution_latency_seconds_bucket[5m]))",
             "legendFormat": "{{broker}}"
           }
         ],
         "type": "graph"
       },
       {
         "title": "Orders by Status",
         "targets": [
           {
             "expr": "sum by (status) (increase(exec_orders_total[1h]))"
           }
         ],
         "type": "piechart"
       },
       {
         "title": "Broker Connection Status",
         "targets": [
           {
             "expr": "exec_broker_connected"
           }
         ],
         "type": "stat"
       },
       {
         "title": "Fill Rate Over Time",
         "targets": [
           {
             "expr": "rate(exec_orders_filled_total[5m])"
           }
         ],
         "type": "graph"
       }
     ]
   }
   ```

6. **Provisionner tous les dashboards**
   ```yaml
   # Dans infra/grafana/provisioning/dashboards/dashboard.yml
   apiVersion: 1

   providers:
     - name: 'AutoLLM Dashboards'
       orgId: 1
       folder: 'AutoLLM Trader'
       type: file
       disableDeletion: false
       updateIntervalSeconds: 10
       allowUiUpdates: true
       options:
         path: /etc/grafana/provisioning/dashboards
         foldersFromFilesStructure: true
   ```

7. **Ajouter métriques manquantes dans services**
   ```python
   # Dans apps/risk_manager/src/service.py
   from prometheus_client import Gauge, Counter

   # Current exposure
   exposure_gauge = Gauge("risk_current_exposure_usd", "Current portfolio exposure in USD")

   # Position limit usage
   position_limit_gauge = Gauge("risk_position_limit_used_pct", "Position limit usage percentage")

   # Throttled requests
   throttled_counter = Counter("risk_throttled_total", "Total throttled requests")

   async def evaluate_intent(self, intent: dict):
       # ... existing code ...

       # Update metrics
       exposure_gauge.set(self.state.calculate_exposure())
       position_limit_gauge.set(self.state.get_position_limit_usage() * 100)

       if self._is_throttled():
           throttled_counter.inc()

   # Dans apps/portfolio_ledger/src/service.py
   from prometheus_client import Gauge

   realized_pnl_gauge = Gauge("portfolio_realized_pnl", "Total realized P&L")
   unrealized_pnl_gauge = Gauge("portfolio_unrealized_pnl", "Total unrealized P&L")
   equity_gauge = Gauge("portfolio_equity", "Total portfolio equity")

   async def update_metrics(self):
       """Update portfolio metrics for Prometheus"""
       async with self.ledger.pool.acquire() as conn:
           realized = await conn.fetchval("SELECT SUM(realized_pnl) FROM positions")
           unrealized = await conn.fetchval("SELECT SUM(unrealized_pnl) FROM positions")

           realized_pnl_gauge.set(float(realized or 0))
           unrealized_pnl_gauge.set(float(unrealized or 0))
           equity_gauge.set(float((realized or 0) + (unrealized or 0) + self.initial_capital))

   # Call update_metrics() periodically
   asyncio.create_task(self.run_periodic_metrics())
   ```

**Tests de validation:**
```bash
# 1. Provisionner dashboards
docker-compose restart grafana

# 2. Accéder Grafana
open http://localhost:3000

# 3. Vérifier dashboards dans folder "AutoLLM Trader"
# - System Overview
# - LLM Agents Performance
# - Risk Manager
# - Portfolio & P&L
# - Execution Services

# 4. Vérifier métriques temps réel
# Trigger quelques trades et observer dashboards

# 5. Tester alertes (configurer dans dashboard panels)
```

**Critères d'acceptation:**
- [ ] 5 dashboards créés (overview, llm, risk, portfolio, execution)
- [ ] Métriques manquantes ajoutées (exposure, pnl, equity)
- [ ] Dashboards provisionnés automatiquement
- [ ] Panels avec thresholds colors
- [ ] Graphes temps réel fonctionnels
- [ ] Variables dashboard pour filter par symbol
- [ ] Documentation dashboards

---

### 🚨 TASK 3.3: Alertes Prometheus & Integration (Priorité: MOYENNE)

**Contexte:**
`alertmanager.yml` vide. Pas d'alertes configurées pour incidents critiques.

**Actions:**

1. **Créer règles d'alertes Prometheus**
   ```yaml
   # Dans infra/prometheus/alerts.yml (nouveau fichier)
   groups:
     - name: autollm_critical
       interval: 30s
       rules:
         - alert: ServiceDown
           expr: up{job=~".*autollm.*"} == 0
           for: 1m
           labels:
             severity: critical
           annotations:
             summary: "Service {{ $labels.job }} is down"
             description: "Service {{ $labels.job }} has been down for more than 1 minute."

         - alert: HighRiskRejectionRate
           expr: |
             sum(rate(risk_rejections_total[5m])) / sum(rate(llm_intents_total[5m])) > 0.5
           for: 5m
           labels:
             severity: warning
           annotations:
             summary: "High risk rejection rate (>50%)"
             description: "Risk manager is rejecting >50% of intents for 5 minutes."

         - alert: BrokerDisconnected
           expr: exec_broker_connected == 0
           for: 2m
           labels:
             severity: critical
           annotations:
             summary: "Broker {{ $labels.broker }} disconnected"
             description: "Execution service lost connection to broker."

         - alert: HighExecutionLatency
           expr: |
             histogram_quantile(0.95, rate(execution_latency_seconds_bucket[5m])) > 5
           for: 10m
           labels:
             severity: warning
           annotations:
             summary: "High execution latency (p95 > 5s)"
             description: "95th percentile execution latency is above 5 seconds."

         - alert: MaxDrawdownExceeded
           expr: |
             (portfolio_equity - portfolio_equity_max) / portfolio_equity_max * 100 < -10
           for: 5m
           labels:
             severity: critical
           annotations:
             summary: "Max drawdown exceeded (-10%)"
             description: "Portfolio drawdown is below -10% threshold."

         - alert: KillSwitchActivated
           expr: increase(risk_kill_switch_total[1m]) > 0
           labels:
             severity: critical
           annotations:
             summary: "Kill switch activated!"
             description: "Emergency kill switch has been triggered. All trading halted."

         - alert: NATSDisconnected
           expr: nats_connected == 0
           for: 1m
           labels:
             severity: critical
           annotations:
             summary: "NATS message bus disconnected"
             description: "Service {{ $labels.service }} lost NATS connection."

         - alert: HighMemoryUsage
           expr: |
             (process_resident_memory_bytes / 1024 / 1024 / 1024) > 4
           for: 5m
           labels:
             severity: warning
           annotations:
             summary: "High memory usage (>4GB) on {{ $labels.job }}"
             description: "Service is consuming more than 4GB of RAM."

     - name: autollm_warnings
       interval: 1m
       rules:
         - alert: DataStreamStale
           expr: |
             time() - market_tick_last_timestamp > 120
           for: 2m
           labels:
             severity: warning
           annotations:
             summary: "Market data stream is stale (>2min)"
             description: "No market ticks received for {{ $labels.symbol }} in 2 minutes."

         - alert: LLMHighTokenUsage
           expr: rate(llm_tokens_total[5m]) > 10000
           for: 10m
           labels:
             severity: warning
           annotations:
             summary: "High LLM token usage (>10k/5min)"
             description: "LLM service is consuming tokens rapidly. Check for loops or bugs."

         - alert: PositionLimitNearMax
           expr: risk_position_limit_used_pct > 90
           for: 5m
           labels:
             severity: warning
           annotations:
             summary: "Position limit near maximum (>90%)"
             description: "Current positions are using >90% of allowed limits."
   ```

2. **Charger alertes dans prometheus.yml**
   ```yaml
   # Dans infra/prometheus/prometheus.yml
   global:
     scrape_interval: 15s
     evaluation_interval: 15s

   # Alertmanager configuration
   alerting:
     alertmanagers:
       - static_configs:
           - targets: ['alertmanager:9093']

   # Load alert rules
   rule_files:
     - '/etc/prometheus/alerts.yml'

   scrape_configs:
     # ... existing scrape configs ...
   ```

3. **Configurer Alertmanager**
   ```yaml
   # Dans infra/prometheus/alertmanager.yml (remplacer contenu vide)
   global:
     resolve_timeout: 5m
     smtp_smarthost: '${SMTP_HOST}:${SMTP_PORT}'
     smtp_from: 'alertmanager@autollm-trader.com'
     smtp_auth_username: '${SMTP_USERNAME}'
     smtp_auth_password: '${SMTP_PASSWORD}'

   route:
     group_by: ['alertname', 'severity']
     group_wait: 10s
     group_interval: 10s
     repeat_interval: 12h
     receiver: 'default'

     routes:
       - match:
           severity: critical
         receiver: 'critical'
         continue: true

       - match:
           severity: warning
         receiver: 'warnings'

   receivers:
     - name: 'default'
       webhook_configs:
         - url: 'http://reporter:8000/alert'
           send_resolved: true

     - name: 'critical'
       email_configs:
         - to: '${ALERT_EMAIL_CRITICAL}'
           headers:
             Subject: '[CRITICAL] AutoLLM Alert: {{ .GroupLabels.alertname }}'
           html: |
             <h2>Critical Alert</h2>
             <p><strong>Alert:</strong> {{ .GroupLabels.alertname }}</p>
             <p><strong>Summary:</strong> {{ .CommonAnnotations.summary }}</p>
             <p><strong>Description:</strong> {{ .CommonAnnotations.description }}</p>
             <p><strong>Time:</strong> {{ .StartsAt }}</p>

       webhook_configs:
         - url: 'http://reporter:8000/alert'
           send_resolved: true

     - name: 'warnings'
       webhook_configs:
         - url: 'http://reporter:8000/alert'
           send_resolved: true

   inhibit_rules:
     - source_match:
         severity: 'critical'
       target_match:
         severity: 'warning'
       equal: ['alertname']
   ```

4. **Améliorer reporter webhook pour alertes**
   ```python
   # Dans apps/reporter/src/service.py
   from pydantic import BaseModel
   from typing import List, Dict

   class PrometheusAlert(BaseModel):
       status: str
       labels: Dict[str, str]
       annotations: Dict[str, str]
       startsAt: str
       endsAt: str = None
       generatorURL: str = None

   class AlertmanagerPayload(BaseModel):
       version: str
       groupKey: str
       status: str
       receiver: str
       groupLabels: Dict[str, str]
       commonLabels: Dict[str, str]
       commonAnnotations: Dict[str, str]
       externalURL: str
       alerts: List[PrometheusAlert]

   @app.post("/alert")
   async def receive_alert(payload: AlertmanagerPayload):
       """Receive alert from Alertmanager"""
       logger.info(f"Received alert: {payload.groupLabels.get('alertname')}")

       for alert in payload.alerts:
           severity = alert.labels.get("severity", "unknown")
           alertname = alert.labels.get("alertname")
           summary = alert.annotations.get("summary")
           description = alert.annotations.get("description")

           # Format message
           message = f"""
   🚨 **{severity.upper()}**: {alertname}

   **Summary:** {summary}
   **Description:** {description}
   **Status:** {alert.status}
   **Started:** {alert.startsAt}
           """

           # Send to email
           if severity == "critical":
               await self.send_email(
                   to=os.getenv("ALERT_EMAIL_CRITICAL").split(","),
                   subject=f"[CRITICAL] {alertname}",
                   body=message
               )

           # Send to Telegram
           await self.send_telegram(message)

           # Store in database (optional)
           # await self.store_alert(alert)

       return {"status": "ok"}
   ```

5. **Implémenter Telegram notifications**
   ```python
   # Dans apps/reporter/src/service.py
   from aiogram import Bot
   from aiogram.client.default import DefaultBotProperties
   from aiogram.enums import ParseMode

   class ReporterService:
       def __init__(self):
           # ... existing code ...

           # Telegram bot
           self.telegram_token = os.getenv("TELEGRAM_BOT_TOKEN")
           self.telegram_chat_id = os.getenv("TELEGRAM_CHAT_ID")

           if self.telegram_token:
               self.telegram_bot = Bot(
                   token=self.telegram_token,
                   default=DefaultBotProperties(parse_mode=ParseMode.MARKDOWN)
               )
           else:
               self.telegram_bot = None
               logger.warning("Telegram bot not configured")

       async def send_telegram(self, message: str):
           """Send message to Telegram"""
           if not self.telegram_bot:
               return

           try:
               await self.telegram_bot.send_message(
                   chat_id=self.telegram_chat_id,
                   text=message
               )
               logger.info("Telegram message sent")
           except Exception as e:
               logger.error(f"Telegram send failed: {e}")
   ```

6. **Ajouter métriques manquantes**
   ```python
   # Dans autollm_trader/messaging/nats_client.py
   from prometheus_client import Gauge

   nats_connected = Gauge("nats_connected", "NATS connection status", ["service"])

   class NATSClient:
       def __init__(self, service_name: str):
           self.service_name = service_name
           # ...

       async def connect(self):
           # ... existing code ...
           nats_connected.labels(service=self.service_name).set(1)

       async def disconnect(self):
           # ... existing code ...
           nats_connected.labels(service=self.service_name).set(0)

   # Dans apps/data_ingestor/src/service.py
   from prometheus_client import Gauge

   last_tick_timestamp = Gauge(
       "market_tick_last_timestamp",
       "Timestamp of last market tick",
       ["symbol"]
   )

   async def on_tick(self, tick: MarketTick):
       # ... existing code ...
       last_tick_timestamp.labels(symbol=tick.symbol).set(time.time())
   ```

7. **Mettre à jour .env.template**
   ```bash
   # Alerting
   ALERT_EMAIL_CRITICAL=admin@example.com,trader@example.com
   TELEGRAM_BOT_TOKEN=
   TELEGRAM_CHAT_ID=
   ```

**Tests de validation:**
```bash
# 1. Reload Prometheus config
docker-compose exec prometheus kill -HUP 1

# 2. Vérifier rules chargées
open http://localhost:9090/rules

# 3. Tester alert en simulant condition
# Ex: stopper un service
docker-compose stop llm_agents

# Attendre 1 min et vérifier:
open http://localhost:9090/alerts
# ServiceDown devrait être en "firing"

# 4. Vérifier Alertmanager a reçu l'alerte
open http://localhost:9093

# 5. Vérifier webhook reporter
docker-compose logs reporter | grep "Received alert"

# 6. Vérifier email/Telegram reçu

# 7. Résoudre alert
docker-compose start llm_agents
# Alert devrait passer à "resolved"
```

**Critères d'acceptation:**
- [ ] alerts.yml créé avec 10+ règles
- [ ] Prometheus charge les règles
- [ ] Alertmanager configuré (email + webhook)
- [ ] Reporter reçoit alertes
- [ ] Telegram notifications fonctionnelles
- [ ] Métriques manquantes ajoutées (nats_connected, etc.)
- [ ] Inhibit rules pour éviter spam
- [ ] Tests alertes passent
- [ ] Documentation alertes

---

## 🎨 PHASE 4: FONCTIONNALITÉS AVANCÉES (Semaines 8-9)

### 💻 TASK 4.1: Admin UI React - Dashboard Complet (Priorité: MOYENNE)

**Contexte:**
UI React actuelle minimaliste. Besoin de dashboard complet avec positions, trades, logs temps réel, graph décisions.

**Actions:**

1. **Setup enhanced React app**
   ```bash
   cd apps/gateway_api/ui

   # Installer dépendances supplémentaires
   npm install --save recharts
   npm install --save @tanstack/react-query
   npm install --save @tanstack/react-table
   npm install --save socket.io-client
   npm install --save react-json-view
   npm install --save react-hot-toast
   ```

2. **Créer composant Dashboard principal**
   ```tsx
   // Dans apps/gateway_api/ui/src/components/Dashboard.tsx (nouveau fichier)
   import React, { useEffect, useState } from 'react';
   import { useQuery } from '@tanstack/react-query';
   import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend } from 'recharts';
   import { api } from '../api';

   interface DashboardMetrics {
     realized_pnl: number;
     unrealized_pnl: number;
     total_pnl: number;
     total_trades: number;
     win_rate: number;
     open_positions: number;
   }

   export function Dashboard() {
     const { data: metrics, isLoading } = useQuery<DashboardMetrics>({
       queryKey: ['dashboard-metrics'],
       queryFn: () => api.get('/api/portfolio/metrics'),
       refetchInterval: 5000, // 5s
     });

     const { data: equityCurve } = useQuery({
       queryKey: ['equity-curve'],
       queryFn: () => api.get('/api/portfolio/equity'),
       refetchInterval: 60000, // 1min
     });

     if (isLoading) return <div>Loading...</div>;

     return (
       <div className="dashboard">
         <div className="metrics-grid">
           <MetricCard
             title="Total P&L"
             value={`$${metrics?.total_pnl.toFixed(2)}`}
             color={metrics && metrics.total_pnl >= 0 ? 'green' : 'red'}
           />
           <MetricCard
             title="Realized P&L"
             value={`$${metrics?.realized_pnl.toFixed(2)}`}
           />
           <MetricCard
             title="Unrealized P&L"
             value={`$${metrics?.unrealized_pnl.toFixed(2)}`}
           />
           <MetricCard
             title="Win Rate"
             value={`${(metrics?.win_rate * 100).toFixed(1)}%`}
           />
           <MetricCard
             title="Total Trades"
             value={metrics?.total_trades.toString() || '0'}
           />
           <MetricCard
             title="Open Positions"
             value={metrics?.open_positions.toString() || '0'}
           />
         </div>

         <div className="equity-chart">
           <h3>Equity Curve</h3>
           <LineChart width={800} height={400} data={equityCurve}>
             <CartesianGrid strokeDasharray="3 3" />
             <XAxis dataKey="timestamp" />
             <YAxis />
             <Tooltip />
             <Legend />
             <Line type="monotone" dataKey="equity" stroke="#8884d8" />
           </LineChart>
         </div>
       </div>
     );
   }

   function MetricCard({ title, value, color = 'blue' }: any) {
     return (
       <div className={`metric-card metric-${color}`}>
         <h4>{title}</h4>
         <div className="value">{value}</div>
       </div>
     );
   }
   ```

3. **Créer composant Positions Table**
   ```tsx
   // Dans apps/gateway_api/ui/src/components/PositionsTable.tsx
   import React from 'react';
   import { useQuery } from '@tanstack/react-query';
   import { useReactTable, getCoreRowModel, flexRender } from '@tanstack/react-table';

   export function PositionsTable() {
     const { data: positions = [] } = useQuery({
       queryKey: ['positions'],
       queryFn: () => api.get('/api/positions'),
       refetchInterval: 5000,
     });

     const columns = [
       { accessorKey: 'symbol', header: 'Symbol' },
       { accessorKey: 'qty', header: 'Quantity' },
       { accessorKey: 'avg_price', header: 'Avg Price' },
       { accessorKey: 'last_price', header: 'Last Price' },
       {
         accessorKey: 'unrealized_pnl',
         header: 'Unrealized P&L',
         cell: (info: any) => (
           <span className={info.getValue() >= 0 ? 'positive' : 'negative'}>
             ${info.getValue().toFixed(2)}
           </span>
         ),
       },
       {
         accessorKey: 'realized_pnl',
         header: 'Realized P&L',
         cell: (info: any) => (
           <span className={info.getValue() >= 0 ? 'positive' : 'negative'}>
             ${info.getValue().toFixed(2)}
           </span>
         ),
       },
     ];

     const table = useReactTable({
       data: positions,
       columns,
       getCoreRowModel: getCoreRowModel(),
     });

     return (
       <div className="positions-table">
         <h3>Open Positions</h3>
         <table>
           <thead>
             {table.getHeaderGroups().map((headerGroup) => (
               <tr key={headerGroup.id}>
                 {headerGroup.headers.map((header) => (
                   <th key={header.id}>
                     {flexRender(header.column.columnDef.header, header.getContext())}
                   </th>
                 ))}
               </tr>
             ))}
           </thead>
           <tbody>
             {table.getRowModel().rows.map((row) => (
               <tr key={row.id}>
                 {row.getVisibleCells().map((cell) => (
                   <td key={cell.id}>
                     {flexRender(cell.column.columnDef.cell, cell.getContext())}
                   </td>
                 ))}
               </tr>
             ))}
           </tbody>
         </table>
       </div>
     );
   }
   ```

4. **Créer composant Live Logs (WebSocket)**
   ```tsx
   // Dans apps/gateway_api/ui/src/components/LiveLogs.tsx
   import React, { useEffect, useState } from 'react';
   import { io, Socket } from 'socket.io-client';
   import ReactJson from 'react-json-view';

   export function LiveLogs() {
     const [logs, setLogs] = useState<any[]>([]);
     const [socket, setSocket] = useState<Socket | null>(null);

     useEffect(() => {
       const newSocket = io('ws://localhost:8000/ws/logs');

       newSocket.on('connect', () => {
         console.log('WebSocket connected');
       });

       newSocket.on('log', (log: any) => {
         setLogs((prev) => [log, ...prev].slice(0, 100)); // Keep last 100
       });

       setSocket(newSocket);

       return () => {
         newSocket.close();
       };
     }, []);

     return (
       <div className="live-logs">
         <h3>Live Logs</h3>
         <div className="logs-container">
           {logs.map((log, idx) => (
             <div key={idx} className={`log-entry log-${log.level}`}>
               <span className="timestamp">{log.timestamp}</span>
               <span className="service">[{log.service}]</span>
               <span className="message">{log.message}</span>
               {log.data && <ReactJson src={log.data} collapsed={true} theme="monokai" />}
             </div>
           ))}
         </div>
       </div>
     );
   }
   ```

5. **Ajouter WebSocket endpoint dans gateway**
   ```python
   # Dans apps/gateway_api/src/main.py
   from fastapi import WebSocket, WebSocketDisconnect
   import asyncio
   import json

   class ConnectionManager:
       def __init__(self):
           self.active_connections: list[WebSocket] = []

       async def connect(self, websocket: WebSocket):
           await websocket.accept()
           self.active_connections.append(websocket)

       def disconnect(self, websocket: WebSocket):
           self.active_connections.remove(websocket)

       async def broadcast(self, message: str):
           for connection in self.active_connections:
               try:
                   await connection.send_text(message)
               except:
                   pass

   manager = ConnectionManager()

   @app.websocket("/ws/logs")
   async def websocket_logs(websocket: WebSocket):
       await manager.connect(websocket)

       try:
           # Subscribe to NATS log stream
           async def forward_logs():
               await nats.js.subscribe(
                   "logs.>",
                   cb=lambda msg: manager.broadcast(msg.data.decode()),
                   stream="LOGS",
                   durable="ws-logs"
               )

           asyncio.create_task(forward_logs())

           while True:
               await websocket.receive_text()

       except WebSocketDisconnect:
           manager.disconnect(websocket)
   ```

6. **Créer composant LLM Decision Graph**
   ```tsx
   // Dans apps/gateway_api/ui/src/components/LLMDecisionGraph.tsx
   import React from 'react';
   import { useQuery } from '@tanstack/react-query';
   import { ScatterChart, Scatter, XAxis, YAxis, CartesianGrid, Tooltip, Cell } from 'recharts';

   export function LLMDecisionGraph() {
     const { data: decisions = [] } = useQuery({
       queryKey: ['llm-decisions'],
       queryFn: () => api.get('/api/llm/decisions'),
       refetchInterval: 10000,
     });

     // Transform data: x = confidence, y = return (if executed)
     const chartData = decisions.map((d: any) => ({
       confidence: d.confidence,
       return_pct: d.return_pct,
       action: d.action,
     }));

     return (
       <div className="llm-decision-graph">
         <h3>LLM Decisions: Confidence vs. Actual Return</h3>
         <ScatterChart width={600} height={400} data={chartData}>
           <CartesianGrid strokeDasharray="3 3" />
           <XAxis dataKey="confidence" name="Confidence" label="Confidence" />
           <YAxis dataKey="return_pct" name="Return %" label="Return %" />
           <Tooltip cursor={{ strokeDasharray: '3 3' }} />
           <Scatter name="Decisions" fill="#8884d8">
             {chartData.map((entry: any, index: number) => (
               <Cell key={`cell-${index}`} fill={entry.action === 'BUY' ? 'green' : 'red'} />
             ))}
           </Scatter>
         </ScatterChart>
       </div>
     );
   }
   ```

7. **Créer layout responsive**
   ```tsx
   // Dans apps/gateway_api/ui/src/App.tsx
   import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
   import { Dashboard } from './components/Dashboard';
   import { PositionsTable } from './components/PositionsTable';
   import { LiveLogs } from './components/LiveLogs';
   import { LLMDecisionGraph } from './components/LLMDecisionGraph';
   import { Toaster } from 'react-hot-toast';

   const queryClient = new QueryClient();

   function App() {
     return (
       <QueryClientProvider client={queryClient}>
         <div className="app">
           <header>
             <h1>AutoLLM Trader Dashboard</h1>
           </header>

           <main className="dashboard-layout">
             <section className="main-panel">
               <Dashboard />
               <PositionsTable />
             </section>

             <aside className="side-panel">
               <LLMDecisionGraph />
               <LiveLogs />
             </aside>
           </main>

           <Toaster position="bottom-right" />
         </div>
       </QueryClientProvider>
     );
   }

   export default App;
   ```

8. **Ajouter styles CSS**
   ```css
   /* Dans apps/gateway_api/ui/src/index.css */
   .dashboard-layout {
     display: grid;
     grid-template-columns: 2fr 1fr;
     gap: 20px;
     padding: 20px;
   }

   .metrics-grid {
     display: grid;
     grid-template-columns: repeat(3, 1fr);
     gap: 15px;
     margin-bottom: 30px;
   }

   .metric-card {
     background: white;
     padding: 20px;
     border-radius: 8px;
     box-shadow: 0 2px 4px rgba(0,0,0,0.1);
   }

   .metric-card.metric-green { border-left: 4px solid #22c55e; }
   .metric-card.metric-red { border-left: 4px solid #ef4444; }
   .metric-card.metric-blue { border-left: 4px solid #3b82f6; }

   .metric-card h4 {
     margin: 0 0 10px 0;
     color: #666;
     font-size: 14px;
   }

   .metric-card .value {
     font-size: 28px;
     font-weight: bold;
   }

   .positions-table table {
     width: 100%;
     border-collapse: collapse;
   }

   .positions-table th,
   .positions-table td {
     padding: 12px;
     text-align: left;
     border-bottom: 1px solid #ddd;
   }

   .positive { color: #22c55e; }
   .negative { color: #ef4444; }

   .live-logs {
     max-height: 600px;
     overflow-y: auto;
   }

   .log-entry {
     padding: 8px;
     margin: 4px 0;
     border-left: 3px solid #3b82f6;
     background: #f9fafb;
     font-family: monospace;
     font-size: 12px;
   }

   .log-entry.log-error { border-left-color: #ef4444; }
   .log-entry.log-warning { border-left-color: #f59e0b; }
   ```

**Tests de validation:**
```bash
# 1. Build UI
cd apps/gateway_api/ui
npm run build

# 2. Start services
docker-compose up

# 3. Access dashboard
open http://localhost:8000/admin

# 4. Vérifier composants:
# - Metrics cards update toutes les 5s
# - Equity curve chart
# - Positions table
# - Live logs streaming
# - LLM decision graph

# 5. Test WebSocket
# Trigger quelques trades et observer live logs

# 6. Test responsive design
# Resize browser window
```

**Critères d'acceptation:**
- [ ] Dashboard React amélioré
- [ ] Metrics cards temps réel
- [ ] Equity curve graph (recharts)
- [ ] Positions table (react-table)
- [ ] Live logs WebSocket
- [ ] LLM decision graph
- [ ] Layout responsive
- [ ] Toasts notifications
- [ ] API endpoints manquants ajoutés
- [ ] Build production optimisé

---

### 📦 TASK 4.2: Infrastructure Cloud & Deployment (Priorité: BASSE)

**Contexte:**
Actuellement self-hosted Ubuntu 22.04. Pour scaling et HA, besoin de cloud deployment (optionnel).

**Actions:**

1. **Créer Terraform AWS infrastructure**
   ```hcl
   # Dans infra/terraform/main.tf (nouveau fichier)
   terraform {
     required_version = ">= 1.0"
     required_providers {
       aws = {
         source  = "hashicorp/aws"
         version = "~> 5.0"
       }
     }
   }

   provider "aws" {
     region = var.aws_region
   }

   # VPC
   resource "aws_vpc" "main" {
     cidr_block           = "10.0.0.0/16"
     enable_dns_hostnames = true
     enable_dns_support   = true

     tags = {
       Name = "autollm-trader-vpc"
     }
   }

   # Subnets
   resource "aws_subnet" "public" {
     count                   = 2
     vpc_id                  = aws_vpc.main.id
     cidr_block              = "10.0.${count.index}.0/24"
     availability_zone       = data.aws_availability_zones.available.names[count.index]
     map_public_ip_on_launch = true

     tags = {
       Name = "autollm-public-${count.index}"
     }
   }

   resource "aws_subnet" "private" {
     count             = 2
     vpc_id            = aws_vpc.main.id
     cidr_block        = "10.0.${count.index + 10}.0/24"
     availability_zone = data.aws_availability_zones.available.names[count.index]

     tags = {
       Name = "autollm-private-${count.index}"
     }
   }

   # ECS Cluster
   resource "aws_ecs_cluster" "main" {
     name = "autollm-trader-cluster"

     setting {
       name  = "containerInsights"
       value = "enabled"
     }
   }

   # RDS Postgres
   resource "aws_db_instance" "postgres" {
     identifier           = "autollm-postgres"
     engine               = "postgres"
     engine_version       = "15.4"
     instance_class       = "db.t3.medium"
     allocated_storage    = 100
     storage_type         = "gp3"
     db_name              = "autollm"
     username             = var.db_username
     password             = var.db_password
     skip_final_snapshot  = false
     final_snapshot_identifier = "autollm-final-snapshot"

     vpc_security_group_ids = [aws_security_group.rds.id]
     db_subnet_group_name   = aws_db_subnet_group.main.name

     backup_retention_period = 7
     backup_window           = "03:00-04:00"
     maintenance_window      = "mon:04:00-mon:05:00"

     multi_az = true
   }

   # ElastiCache Redis
   resource "aws_elasticache_cluster" "redis" {
     cluster_id           = "autollm-redis"
     engine               = "redis"
     node_type            = "cache.t3.medium"
     num_cache_nodes      = 1
     parameter_group_name = "default.redis7"
     engine_version       = "7.0"
     port                 = 6379

     subnet_group_name    = aws_elasticache_subnet_group.main.name
     security_group_ids   = [aws_security_group.redis.id]
   }

   # ALB for gateway
   resource "aws_lb" "main" {
     name               = "autollm-alb"
     internal           = false
     load_balancer_type = "application"
     security_groups    = [aws_security_group.alb.id]
     subnets            = aws_subnet.public[*].id
   }

   # ECS Task Definitions (example for gateway_api)
   resource "aws_ecs_task_definition" "gateway_api" {
     family                   = "gateway-api"
     network_mode             = "awsvpc"
     requires_compatibilities = ["FARGATE"]
     cpu                      = "512"
     memory                   = "1024"

     container_definitions = jsonencode([
       {
         name      = "gateway-api"
         image     = "${var.ecr_registry}/gateway-api:latest"
         essential = true

         portMappings = [
           {
             containerPort = 8000
             protocol      = "tcp"
           }
         ]

         environment = [
           { name = "POSTGRES_HOST", value = aws_db_instance.postgres.address },
           { name = "REDIS_HOST", value = aws_elasticache_cluster.redis.cache_nodes[0].address },
           { name = "NATS_URL", value = "nats://${aws_instance.nats.private_ip}:4222" }
         ]

         secrets = [
           {
             name      = "JWT_SECRET"
             valueFrom = aws_secretsmanager_secret.jwt_secret.arn
           }
         ]

         logConfiguration = {
           logDriver = "awslogs"
           options = {
             "awslogs-group"         = aws_cloudwatch_log_group.main.name
             "awslogs-region"        = var.aws_region
             "awslogs-stream-prefix" = "gateway-api"
           }
         }
       }
     ])
   }

   # ECS Service
   resource "aws_ecs_service" "gateway_api" {
     name            = "gateway-api"
     cluster         = aws_ecs_cluster.main.id
     task_definition = aws_ecs_task_definition.gateway_api.arn
     desired_count   = 2
     launch_type     = "FARGATE"

     network_configuration {
       subnets         = aws_subnet.private[*].id
       security_groups = [aws_security_group.ecs_tasks.id]
     }

     load_balancer {
       target_group_arn = aws_lb_target_group.gateway_api.arn
       container_name   = "gateway-api"
       container_port   = 8000
     }
   }

   # S3 for backups
   resource "aws_s3_bucket" "backups" {
     bucket = "autollm-trader-backups"

     versioning {
       enabled = true
     }

     lifecycle_rule {
       enabled = true

       transition {
         days          = 30
         storage_class = "GLACIER"
       }

       expiration {
         days = 365
       }
     }
   }

   # Secrets Manager
   resource "aws_secretsmanager_secret" "jwt_secret" {
     name = "autollm/jwt-secret"
   }

   resource "aws_secretsmanager_secret_version" "jwt_secret" {
     secret_id     = aws_secretsmanager_secret.jwt_secret.id
     secret_string = var.jwt_secret
   }

   # CloudWatch Log Group
   resource "aws_cloudwatch_log_group" "main" {
     name              = "/ecs/autollm-trader"
     retention_in_days = 30
   }

   # Outputs
   output "alb_dns_name" {
     value = aws_lb.main.dns_name
   }

   output "rds_endpoint" {
     value = aws_db_instance.postgres.endpoint
   }

   output "redis_endpoint" {
     value = aws_elasticache_cluster.redis.cache_nodes[0].address
   }
   ```

2. **Variables Terraform**
   ```hcl
   # Dans infra/terraform/variables.tf
   variable "aws_region" {
     default = "us-east-1"
   }

   variable "db_username" {
     default = "autollm"
   }

   variable "db_password" {
     sensitive = true
   }

   variable "jwt_secret" {
     sensitive = true
   }

   variable "ecr_registry" {
     description = "ECR registry URL"
   }
   ```

3. **Créer Kubernetes manifests (alternative)**
   ```yaml
   # Dans infra/k8s/namespace.yaml
   apiVersion: v1
   kind: Namespace
   metadata:
     name: autollm-trader

   ---
   # Dans infra/k8s/gateway-api-deployment.yaml
   apiVersion: apps/v1
   kind: Deployment
   metadata:
     name: gateway-api
     namespace: autollm-trader
   spec:
     replicas: 2
     selector:
       matchLabels:
         app: gateway-api
     template:
       metadata:
         labels:
           app: gateway-api
       spec:
         containers:
           - name: gateway-api
             image: ${ECR_REGISTRY}/gateway-api:latest
             ports:
               - containerPort: 8000
             env:
               - name: POSTGRES_HOST
                 value: postgres.autollm-trader.svc.cluster.local
               - name: REDIS_HOST
                 value: redis.autollm-trader.svc.cluster.local
               - name: NATS_URL
                 value: nats://nats.autollm-trader.svc.cluster.local:4222
             envFrom:
               - secretRef:
                   name: autollm-secrets
             resources:
               requests:
                 memory: "512Mi"
                 cpu: "250m"
               limits:
                 memory: "1Gi"
                 cpu: "500m"
             livenessProbe:
               httpGet:
                 path: /health
                 port: 8000
               initialDelaySeconds: 30
               periodSeconds: 10
             readinessProbe:
               httpGet:
                 path: /health
                 port: 8000
               initialDelaySeconds: 10
               periodSeconds: 5

   ---
   apiVersion: v1
   kind: Service
   metadata:
     name: gateway-api
     namespace: autollm-trader
   spec:
     selector:
       app: gateway-api
     ports:
       - protocol: TCP
         port: 8000
         targetPort: 8000
     type: ClusterIP

   ---
   apiVersion: networking.k8s.io/v1
   kind: Ingress
   metadata:
     name: gateway-api-ingress
     namespace: autollm-trader
     annotations:
       cert-manager.io/cluster-issuer: letsencrypt-prod
   spec:
     ingressClassName: nginx
     tls:
       - hosts:
           - api.autollm-trader.com
         secretName: gateway-api-tls
     rules:
       - host: api.autollm-trader.com
         http:
           paths:
             - path: /
               pathType: Prefix
               backend:
                 service:
                   name: gateway-api
                   port:
                     number: 8000
   ```

4. **Créer Helm chart**
   ```yaml
   # Dans infra/helm/autollm-trader/Chart.yaml
   apiVersion: v2
   name: autollm-trader
   description: AutoLLM Trader Platform
   version: 0.1.0
   appVersion: "1.0.0"

   # Dans infra/helm/autollm-trader/values.yaml
   replicaCount: 2

   image:
     registry: ${ECR_REGISTRY}
     pullPolicy: IfNotPresent
     tag: "latest"

   services:
     gatewayApi:
       enabled: true
       replicas: 2
       resources:
         requests:
           memory: 512Mi
           cpu: 250m
         limits:
           memory: 1Gi
           cpu: 500m

     llmAgents:
       enabled: true
       replicas: 1
       resources:
         requests:
           memory: 2Gi
           cpu: 1000m

     # ... autres services ...

   postgres:
     enabled: true
     host: postgres.autollm-trader.svc.cluster.local
     port: 5432
     database: autollm

   redis:
     enabled: true
     host: redis.autollm-trader.svc.cluster.local
     port: 6379

   nats:
     enabled: true
     host: nats.autollm-trader.svc.cluster.local
     port: 4222

   secrets:
     jwtSecret: ""
     postgresPassword: ""
     redisPassword: ""

   ingress:
     enabled: true
     className: nginx
     annotations:
       cert-manager.io/cluster-issuer: letsencrypt-prod
     hosts:
       - host: api.autollm-trader.com
         paths:
           - path: /
             pathType: Prefix
     tls:
       - secretName: gateway-api-tls
         hosts:
           - api.autollm-trader.com
   ```

5. **CI/CD GitHub Actions pour déploiement**
   ```yaml
   # Dans .github/workflows/deploy.yml
   name: Deploy to AWS ECS

   on:
     push:
       branches: [main]
       tags: ['v*']

   env:
     AWS_REGION: us-east-1
     ECR_REGISTRY: ${{ secrets.ECR_REGISTRY }}

   jobs:
     build-and-push:
       runs-on: ubuntu-latest
       strategy:
         matrix:
           service:
             - gateway_api
             - llm_agents
             - risk_manager
             - execution_ib
             - portfolio_ledger
             - reporter
             - data_ingestor
             - news_ingestor
             - feature_pipeline

       steps:
         - uses: actions/checkout@v3

         - name: Configure AWS credentials
           uses: aws-actions/configure-aws-credentials@v2
           with:
             aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
             aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
             aws-region: ${{ env.AWS_REGION }}

         - name: Login to Amazon ECR
           id: login-ecr
           uses: aws-actions/amazon-ecr-login@v1

         - name: Build, tag, and push image
           env:
             ECR_REPOSITORY: autollm-${{ matrix.service }}
             IMAGE_TAG: ${{ github.sha }}
           run: |
             docker build -t $ECR_REGISTRY/$ECR_REPOSITORY:$IMAGE_TAG \
               -f infra/dockerfiles/${{ matrix.service }}.Dockerfile .
             docker tag $ECR_REGISTRY/$ECR_REPOSITORY:$IMAGE_TAG \
               $ECR_REGISTRY/$ECR_REPOSITORY:latest
             docker push $ECR_REGISTRY/$ECR_REPOSITORY:$IMAGE_TAG
             docker push $ECR_REGISTRY/$ECR_REPOSITORY:latest

     deploy:
       needs: build-and-push
       runs-on: ubuntu-latest

       steps:
         - uses: actions/checkout@v3

         - name: Deploy to ECS
           run: |
             aws ecs update-service \
               --cluster autollm-trader-cluster \
               --service gateway-api \
               --force-new-deployment
   ```

6. **Backup automatique avec Borgmatic**
   ```yaml
   # Dans infra/borgmatic/config.yaml
   location:
     source_directories:
       - /opt/autollm/data
       - /opt/autollm/configs

     repositories:
       - path: s3://s3.amazonaws.com/autollm-trader-backups/borg
         label: aws-s3

     exclude_patterns:
       - '*.log'
       - '__pycache__'
       - '.mypy_cache'

   storage:
     compression: lz4
     encryption_passphrase: "${BORG_PASSPHRASE}"
     archive_name_format: 'autollm-{now:%Y-%m-%dT%H:%M:%S}'

   retention:
     keep_daily: 7
     keep_weekly: 4
     keep_monthly: 6

   consistency:
     checks:
       - repository
       - archives

   hooks:
     before_backup:
       - echo "Starting backup..."
       - pg_dump -h localhost -U autollm autollm > /tmp/postgres_backup.sql

     after_backup:
       - echo "Backup completed"
       - rm /tmp/postgres_backup.sql

     on_error:
       - echo "Backup failed!" | mail -s "Backup Error" admin@example.com
   ```

7. **Disaster recovery script**
   ```bash
   # Dans scripts/disaster_recovery.sh
   #!/bin/bash
   set -e

   echo "=== AutoLLM Trader Disaster Recovery ==="

   # 1. Restore Postgres from backup
   echo "Restoring Postgres..."
   aws s3 cp s3://autollm-trader-backups/postgres/latest.sql /tmp/restore.sql
   psql -h $POSTGRES_HOST -U $POSTGRES_USER -d autollm -f /tmp/restore.sql

   # 2. Restore DuckDB
   echo "Restoring DuckDB..."
   aws s3 cp s3://autollm-trader-backups/duckdb/features.duckdb data/storage/

   # 3. Restore configs
   echo "Restoring configs..."
   aws s3 sync s3://autollm-trader-backups/configs/ configs/

   # 4. Restore secrets
   echo "Restoring secrets..."
   aws secretsmanager get-secret-value --secret-id autollm/jwt-secret --query SecretString --output text > .env.secrets

   # 5. Restart services
   echo "Restarting services..."
   make down
   make up

   echo "✓ Recovery completed"
   ```

**Tests de validation:**
```bash
# Terraform
cd infra/terraform
terraform init
terraform plan
terraform apply

# Kubernetes
cd infra/k8s
kubectl apply -f namespace.yaml
kubectl apply -f gateway-api-deployment.yaml

# Helm
helm install autollm-trader infra/helm/autollm-trader \
  --namespace autollm-trader \
  --set image.registry=$ECR_REGISTRY \
  --set secrets.jwtSecret=$JWT_SECRET

# Test borgmatic backup
borgmatic --config infra/borgmatic/config.yaml --create

# Test disaster recovery
bash scripts/disaster_recovery.sh
```

**Critères d'acceptation:**
- [ ] Terraform AWS infrastructure
- [ ] Kubernetes manifests
- [ ] Helm chart
- [ ] CI/CD GitHub Actions
- [ ] Borgmatic backup config
- [ ] Disaster recovery script
- [ ] Documentation déploiement
- [ ] Coûts AWS estimés

---

### 🎯 TASK 4.3: Fonctionnalités Advanced Risk (Priorité: BASSE)

**Contexte:**
Risk manager actuel a les bases. Pour production avancée: VaR, correlation matrix, circuit breaker dynamique.

**Actions:**

1. **Implémenter VaR (Value at Risk)**
   ```python
   # Dans autollm_trader/risk/var.py (nouveau fichier)
   import numpy as np
   import pandas as pd
   from scipy import stats
   from typing import Dict, List

   class VaRCalculator:
       """Calculate Value at Risk for portfolio"""

       def __init__(self, confidence_level: float = 0.95):
           self.confidence_level = confidence_level

       def calculate_historical_var(self, returns: pd.Series, portfolio_value: float) -> float:
           """Historical VaR (non-parametric)"""
           # Sort returns
           sorted_returns = returns.sort_values()

           # Find percentile
           percentile_idx = int((1 - self.confidence_level) * len(sorted_returns))
           var_return = sorted_returns.iloc[percentile_idx]

           # Convert to dollar amount
           var_dollar = abs(var_return * portfolio_value)

           return var_dollar

       def calculate_parametric_var(self, returns: pd.Series, portfolio_value: float) -> float:
           """Parametric VaR (assumes normal distribution)"""
           mean = returns.mean()
           std = returns.std()

           # Z-score for confidence level
           z_score = stats.norm.ppf(1 - self.confidence_level)

           # VaR
           var_return = mean + z_score * std
           var_dollar = abs(var_return * portfolio_value)

           return var_dollar

       def calculate_cvar(self, returns: pd.Series, portfolio_value: float) -> float:
           """Conditional VaR (Expected Shortfall)"""
           var = self.calculate_historical_var(returns, portfolio_value)

           # CVaR = average of losses beyond VaR
           var_threshold = -var / portfolio_value
           tail_losses = returns[returns <= var_threshold]

           if len(tail_losses) == 0:
               return var

           cvar_return = tail_losses.mean()
           cvar_dollar = abs(cvar_return * portfolio_value)

           return cvar_dollar

       def monte_carlo_var(self, returns: pd.Series, portfolio_value: float,
                          num_simulations: int = 10000, horizon_days: int = 1) -> float:
           """Monte Carlo VaR simulation"""
           mean = returns.mean()
           std = returns.std()

           # Simulate returns
           simulated_returns = np.random.normal(
               mean * horizon_days,
               std * np.sqrt(horizon_days),
               num_simulations
           )

           # Sort and find VaR
           sorted_returns = np.sort(simulated_returns)
           percentile_idx = int((1 - self.confidence_level) * len(sorted_returns))
           var_return = sorted_returns[percentile_idx]

           var_dollar = abs(var_return * portfolio_value)

           return var_dollar
   ```

2. **Créer correlation matrix pour diversification**
   ```python
   # Dans autollm_trader/risk/correlation.py (nouveau fichier)
   import pandas as pd
   import numpy as np
   from typing import Dict, List

   class CorrelationAnalyzer:
       """Analyze portfolio correlation and concentration risk"""

       def __init__(self, lookback_days: int = 60):
           self.lookback_days = lookback_days
           self.price_history = {}  # {symbol: [prices]}

       def add_price(self, symbol: str, price: float):
           """Add price data point"""
           if symbol not in self.price_history:
               self.price_history[symbol] = []

           self.price_history[symbol].append(price)

           # Keep only lookback period
           if len(self.price_history[symbol]) > self.lookback_days:
               self.price_history[symbol].pop(0)

       def calculate_correlation_matrix(self) -> pd.DataFrame:
           """Calculate correlation matrix between symbols"""
           # Convert to DataFrame
           df = pd.DataFrame(self.price_history)

           # Calculate returns
           returns = df.pct_change().dropna()

           # Correlation matrix
           corr_matrix = returns.corr()

           return corr_matrix

       def check_concentration_risk(self, positions: Dict[str, float],
                                    max_correlation: float = 0.7) -> List[tuple]:
           """Check for high concentration (highly correlated positions)"""
           corr_matrix = self.calculate_correlation_matrix()
           warnings = []

           # Check each pair of positions
           for symbol1, qty1 in positions.items():
               for symbol2, qty2 in positions.items():
                   if symbol1 >= symbol2:  # Avoid duplicates
                       continue

                   if symbol1 not in corr_matrix or symbol2 not in corr_matrix:
                       continue

                   correlation = corr_matrix.loc[symbol1, symbol2]

                   if abs(correlation) > max_correlation:
                       warnings.append((
                           symbol1, symbol2, correlation,
                           f"High correlation ({correlation:.2f}) between {symbol1} and {symbol2}"
                       ))

           return warnings

       def calculate_portfolio_variance(self, positions: Dict[str, float],
                                       weights: Dict[str, float]) -> float:
           """Calculate portfolio variance using correlation matrix"""
           corr_matrix = self.calculate_correlation_matrix()

           # Calculate individual volatilities
           volatilities = {}
           for symbol in positions.keys():
               if symbol in self.price_history and len(self.price_history[symbol]) > 1:
                   prices = pd.Series(self.price_history[symbol])
                   returns = prices.pct_change().dropna()
                   volatilities[symbol] = returns.std()

           # Calculate portfolio variance
           variance = 0
           for symbol1, weight1 in weights.items():
               for symbol2, weight2 in weights.items():
                   if symbol1 not in volatilities or symbol2 not in volatilities:
                       continue

                   if symbol1 not in corr_matrix or symbol2 not in corr_matrix:
                       correlation = 1.0 if symbol1 == symbol2 else 0.0
                   else:
                       correlation = corr_matrix.loc[symbol1, symbol2]

                   variance += (
                       weight1 * weight2 *
                       volatilities[symbol1] * volatilities[symbol2] *
                       correlation
                   )

           return variance
   ```

3. **Circuit breaker dynamique**
   ```python
   # Dans autollm_trader/risk/circuit_breaker.py (nouveau fichier)
   from datetime import datetime, timedelta
   from collections import deque
   from typing import Tuple

   class CircuitBreaker:
       """Dynamic circuit breaker based on market volatility"""

       def __init__(self):
           self.state = "CLOSED"  # CLOSED, OPEN, HALF_OPEN
           self.volatility_window = deque(maxlen=20)  # Last 20 price changes
           self.last_state_change = datetime.now()
           self.failure_count = 0
           self.cooldown_minutes = 5

       def add_price_change(self, pct_change: float):
           """Add price change to volatility tracker"""
           self.volatility_window.append(abs(pct_change))

       def calculate_volatility(self) -> float:
           """Calculate current market volatility"""
           if len(self.volatility_window) < 5:
               return 0.0

           return np.std(self.volatility_window)

       def should_halt_trading(self) -> Tuple[bool, str]:
           """Determine if trading should be halted"""
           volatility = self.calculate_volatility()

           # Thresholds
           HIGH_VOLATILITY = 0.03  # 3% avg volatility
           EXTREME_VOLATILITY = 0.05  # 5% avg volatility

           if self.state == "OPEN":
               # Check cooldown period
               if datetime.now() - self.last_state_change > timedelta(minutes=self.cooldown_minutes):
                   if volatility < HIGH_VOLATILITY:
                       self.state = "HALF_OPEN"
                       logger.info("Circuit breaker: OPEN → HALF_OPEN (cooldown complete, volatility normalized)")
                       return False, ""
                   else:
                       return True, "Circuit breaker OPEN: cooling down"
               else:
                   return True, "Circuit breaker OPEN: cooling down"

           elif self.state == "HALF_OPEN":
               # Test with reduced exposure
               if volatility > HIGH_VOLATILITY:
                   self.state = "OPEN"
                   self.last_state_change = datetime.now()
                   logger.warning("Circuit breaker: HALF_OPEN → OPEN (volatility spike)")
                   return True, "Circuit breaker reopened due to volatility"
               elif self.failure_count < 3:
                   # Allow limited trading
                   return False, ""
               else:
                   self.state = "OPEN"
                   self.last_state_change = datetime.now()
                   return True, "Circuit breaker: too many failures in HALF_OPEN"

           elif self.state == "CLOSED":
               # Normal operation
               if volatility > EXTREME_VOLATILITY:
                   self.state = "OPEN"
                   self.last_state_change = datetime.now()
                   logger.critical(f"Circuit breaker OPENED: extreme volatility ({volatility:.3f})")
                   return True, f"Circuit breaker: extreme volatility ({volatility:.3f})"
               elif volatility > HIGH_VOLATILITY:
                   logger.warning(f"High volatility detected ({volatility:.3f}), monitoring...")
                   return False, "High volatility warning"

           return False, ""

       def record_trade_result(self, success: bool):
           """Record trade result in HALF_OPEN state"""
           if self.state == "HALF_OPEN":
               if success:
                   self.failure_count = 0
                   self.state = "CLOSED"
                   logger.info("Circuit breaker: HALF_OPEN → CLOSED (trades successful)")
               else:
                   self.failure_count += 1
   ```

4. **Intégrer dans Risk Manager**
   ```python
   # Dans apps/risk_manager/src/service.py
   from autollm_trader.risk.var import VaRCalculator
   from autollm_trader.risk.correlation import CorrelationAnalyzer
   from autollm_trader.risk.circuit_breaker import CircuitBreaker

   class RiskManagerService:
       def __init__(self):
           # ... existing code ...

           # Advanced risk components
           self.var_calculator = VaRCalculator(confidence_level=0.95)
           self.correlation_analyzer = CorrelationAnalyzer(lookback_days=60)
           self.circuit_breaker = CircuitBreaker()

           # Historical returns for VaR
           self.portfolio_returns = []

       async def evaluate_intent_advanced(self, intent: dict) -> tuple[bool, list[str]]:
           """Evaluate with advanced risk checks"""
           reasons = []

           # Basic checks first
           approved, basic_reasons = self.evaluator.evaluate_intent(intent)
           reasons.extend(basic_reasons)

           if not approved:
               return False, reasons

           # VaR check
           if len(self.portfolio_returns) > 30:  # Need history
               portfolio_value = self.state.get_total_value()
               var_95 = self.var_calculator.calculate_historical_var(
                   pd.Series(self.portfolio_returns),
                   portfolio_value
               )

               max_var = portfolio_value * 0.05  # Max 5% VaR

               if var_95 > max_var:
                   reasons.append(f"var_exceeded_{var_95:.0f}")
                   return False, reasons

           # Correlation check
           correlation_warnings = self.correlation_analyzer.check_concentration_risk(
               self.state.positions,
               max_correlation=0.7
           )

           if len(correlation_warnings) > 3:  # Too many correlated positions
               reasons.append("high_correlation_risk")
               return False, reasons

           # Circuit breaker check
           should_halt, halt_reason = self.circuit_breaker.should_halt_trading()

           if should_halt:
               reasons.append(f"circuit_breaker_{halt_reason}")
               return False, reasons

           return True, reasons

       async def on_market_tick(self, msg):
           """Update advanced risk models with market data"""
           data = json.loads(msg.data.decode())
           symbol = data["symbol"]
           price = float(data["price"])

           # Update correlation analyzer
           self.correlation_analyzer.add_price(symbol, price)

           # Update circuit breaker
           if symbol in self.last_prices:
               pct_change = (price - self.last_prices[symbol]) / self.last_prices[symbol]
               self.circuit_breaker.add_price_change(pct_change)

           self.last_prices[symbol] = price

           await msg.ack()
   ```

5. **Ajouter endpoint API pour risk metrics**
   ```python
   # Dans apps/gateway_api/src/main.py
   @app.get("/api/risk/metrics")
   async def get_risk_metrics():
       """Get advanced risk metrics"""
       # Fetch from risk manager via NATS request-reply
       response = await nats.nc.request(
           "risk.metrics.request",
           b"",
           timeout=5
       )

       metrics = json.loads(response.data.decode())
       return metrics

   # Dans apps/risk_manager/src/service.py
   async def handle_metrics_request(self, msg):
       """Handle metrics request"""
       portfolio_value = self.state.get_total_value()

       if len(self.portfolio_returns) > 30:
           var_95 = self.var_calculator.calculate_historical_var(
               pd.Series(self.portfolio_returns),
               portfolio_value
           )
           cvar_95 = self.var_calculator.calculate_cvar(
               pd.Series(self.portfolio_returns),
               portfolio_value
           )
       else:
           var_95 = 0
           cvar_95 = 0

       correlation_warnings = self.correlation_analyzer.check_concentration_risk(
           self.state.positions,
           max_correlation=0.7
       )

       metrics = {
           "portfolio_value": portfolio_value,
           "var_95": var_95,
           "cvar_95": cvar_95,
           "circuit_breaker_state": self.circuit_breaker.state,
           "correlation_warnings": len(correlation_warnings),
           "current_exposure": self.state.calculate_exposure(),
           "max_exposure": self.config.limits.max_gross_exposure
       }

       await msg.respond(json.dumps(metrics).encode())
   ```

**Tests de validation:**
```bash
# 1. Test VaR calculation
python -c "
from autollm_trader.risk.var import VaRCalculator
import pandas as pd
import numpy as np

# Generate fake returns
returns = pd.Series(np.random.normal(-0.001, 0.02, 100))
var_calc = VaRCalculator(confidence_level=0.95)
var = var_calc.calculate_historical_var(returns, 100000)
print(f'VaR (95%): \${var:.2f}')
"

# 2. Test correlation analyzer
# TODO: Feed historical prices and check correlation matrix

# 3. Test circuit breaker
# Simulate high volatility and verify trading halted

# 4. Fetch risk metrics via API
curl http://localhost:8000/api/risk/metrics
```

**Critères d'acceptation:**
- [ ] VaRCalculator implémenté (historical, parametric, CVaR, Monte Carlo)
- [ ] CorrelationAnalyzer avec concentration risk checks
- [ ] CircuitBreaker dynamique (OPEN/CLOSED/HALF_OPEN)
- [ ] Intégration dans RiskManagerService
- [ ] Endpoint /api/risk/metrics
- [ ] Tests unitaires VaR/correlation
- [ ] Documentation modèles de risque

---

## ✅ CHECKLIST FINALE & MÉTRIQUES DE SUCCÈS

### Checklist Phase 1 (Sécurité & Stabilité)
- [ ] JWT secret généré automatiquement
- [ ] NATS TLS + authentication
- [ ] Redis password activé
- [ ] Rate limiting API (10 req/min)
- [ ] CORS restrictif
- [ ] Audit log fonctionnel
- [ ] Portfolio PnL mark-to-market
- [ ] Event replay au boot
- [ ] Reconciliation broker
- [ ] Market calendars (pandas-market-calendars)
- [ ] Dependency checks (NATS, broker, data stream)
- [ ] Tests coverage ≥ 80%

### Checklist Phase 2 (Fonctionnalités)
- [ ] Execution crypto CCXT live (Binance/Coinbase)
- [ ] 20+ indicateurs techniques (MACD, Bollinger, OBV, etc.)
- [ ] ML features (z-scores, lags, autocorr)
- [ ] Normalization StandardScaler
- [ ] Sentence-transformers embeddings
- [ ] Multi-model LLM support (OpenAI/Anthropic/OpenRouter)
- [ ] Backtest vectorized (vectorbt)
- [ ] LLM backtest replay historique
- [ ] quantstats HTML reports

### Checklist Phase 3 (Observabilité)
- [ ] OpenTelemetry traces distribuées
- [ ] Jaeger running
- [ ] 5 dashboards Grafana (overview, llm, risk, portfolio, execution)
- [ ] 10+ règles d'alertes Prometheus
- [ ] Alertmanager configuré (email + webhook)
- [ ] Telegram notifications
- [ ] Métriques manquantes ajoutées

### Checklist Phase 4 (Avancé)
- [ ] Dashboard React complet
- [ ] WebSocket live logs
- [ ] Equity curve graph
- [ ] Positions table temps réel
- [ ] LLM decision graph
- [ ] Terraform AWS (optionnel)
- [ ] Kubernetes manifests (optionnel)
- [ ] Borgmatic backup
- [ ] VaR calculator
- [ ] Correlation matrix
- [ ] Circuit breaker dynamique

### Métriques de Succès Production
**Sécurité:**
- ✅ 0 secrets en clair dans le code
- ✅ Auth 2FA obligatoire (WebAuthn/TOTP)
- ✅ Rate limiting actif sur tous les endpoints publics
- ✅ Audit log complet des actions admin
- ✅ NATS/Redis/Postgres avec auth

**Performance:**
- ✅ Latency tick → intent < 500ms (p95)
- ✅ Intent → execution < 2s (p95)
- ✅ Tests coverage > 80%
- ✅ Uptime > 99.5%

**Business:**
- ✅ Backtest Sharpe ratio > 1.5
- ✅ Max drawdown < 10%
- ✅ Win rate > 55%
- ✅ Risk rejection rate < 30%

**Observabilité:**
- ✅ Traces end-to-end visibles dans Jaeger
- ✅ Dashboards Grafana pour chaque service
- ✅ Alertes < 5min MTTR (Mean Time To Respond)
- ✅ Logs centralisés dans Loki

---

## 📚 DOCUMENTATION À METTRE À JOUR

1. **README.md**
   - Ajouter section "Advanced Features" (VaR, correlation, circuit breaker)
   - Documenter nouveaux endpoints API
   - Mise à jour architecture diagram avec tracing

2. **DEPLOYMENT.md** (nouveau)
   - Guide déploiement AWS Terraform
   - Guide déploiement Kubernetes/Helm
   - Checklist pre-production
   - Disaster recovery procedures

3. **SECURITY.md** (nouveau)
   - Politique de secrets
   - Procédure rotation secrets
   - Audit log format
   - Incident response playbook

4. **API.md** (nouveau)
   - Documentation complète OpenAPI/Swagger
   - Exemples curl pour tous les endpoints
   - Rate limiting policies
   - WebSocket protocols

5. **MONITORING.md** (nouveau)
   - Guide dashboards Grafana
   - Liste complète des alertes Prometheus
   - Procédure investigation incidents
   - SLOs/SLIs

---

## 🎯 PRIORISATION RECOMMANDÉE

**Sprint 1 (Semaines 1-2) - CRITIQUE:**
- TASK 1.1: Sécurité (JWT, NATS, Redis, rate limiting)
- TASK 1.2: Portfolio PnL + replay
- TASK 1.3: Market calendars

**Sprint 2 (Semaines 3-4) - HAUTE:**
- TASK 1.4: Tests coverage 80%+
- TASK 2.1: Execution crypto complète
- TASK 2.2: Feature pipeline avancée

**Sprint 3 (Semaines 5-6) - HAUTE:**
- TASK 2.3: LLM embeddings + multi-model
- TASK 3.1: OpenTelemetry tracing
- TASK 3.2: Dashboards Grafana

**Sprint 4 (Semaines 7-8) - MOYENNE:**
- TASK 2.4: Backtest vectorized
- TASK 3.3: Alertes Prometheus
- TASK 4.1: Admin UI React

**Sprint 5 (Semaine 9) - BASSE (Optionnel):**
- TASK 4.2: Infrastructure cloud
- TASK 4.3: Advanced risk (VaR, correlation)

---

## 💰 ESTIMATION COÛTS AWS (Optionnel)

Si déploiement cloud (Phase 4, TASK 4.2):

- **ECS Fargate:** ~$150/mois (12 services × 0.5 vCPU × $0.04/h)
- **RDS Postgres (db.t3.medium Multi-AZ):** ~$120/mois
- **ElastiCache Redis (cache.t3.medium):** ~$50/mois
- **ALB:** ~$25/mois
- **ECR Storage:** ~$10/mois (50GB)
- **CloudWatch Logs:** ~$20/mois
- **S3 Backups:** ~$5/mois (100GB)
- **Data Transfer:** ~$50/mois

**Total estimé:** ~$430/mois (avec auto-scaling, peut varier)

---

## 🏁 CONCLUSION

Ce document couvre **toutes les tâches nécessaires** pour amener AutoLLM Trader de **75% à 95%+ production-ready** en **9 semaines**.

**Effort total estimé:** 320-360 heures (1 dev full-time)

**Impact attendu:**
- Sécurité: 🔴 CRITIQUE → 🟢 EXCELLENT
- Stabilité: 🟡 MOYENNE → 🟢 HAUTE
- Observabilité: 🟡 BASIQUE → 🟢 COMPLETE
- Fonctionnalités: 🟡 75% → 🟢 95%+

Bonne chance pour l'implémentation! 🚀