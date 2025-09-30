# AutoLLM Trader

AutoLLM Trader is a modular, production-ready autonomous trading platform that combines LangGraph-based multi-agent analysis, deterministic risk controls, and broker adapters for paper or live trading. The stack targets Ubuntu 22.04 LTS deployments with hardened infrastructure and full observability.

## Capabilities
- **Data ingestion**: real-time market data via Finnhub, yfinance, CCXT, plus streaming news through Miniflux webhooks and optional WebSub bridges.
- **Feature engineering**: DuckDB-backed feature store enriched with TA-Lib, pandas-ta and statistical indicators, published over NATS JetStream.
- **Multi-agent LLM analysis**: LangGraph orchestrates analyst, debate, and trader personas with layered FAISS memory (FINMEM-style) and deterministic JSON outputs.
- **Risk management**: external rule engine enforces position limits, drawdown, throttling, market session calendars, and kill-switches before any execution.
- **Execution adapters**: paper/live routing for IBKR (`ib_insync`) and crypto venues / Freqtrade bridge, with full audit trails in Postgres.
- **Portfolio ledger & reporting**: append-only event store, daily reports (email/Telegram), and backtest utilities (`yfinance` SMA sample + Freqtrade integration).
- **Observability**: Prometheus, Grafana dashboards, Loki + Promtail logging, Alertmanager hooks into reporter service.
- **Secure admin UI**: FastAPI + React admin console with WebAuthn passkeys, TOTP fallback, JWT short-lived tokens, and FIDO2 confirmation for sensitive actions.

## Repository Layout
```
infra/                 # bootstrap & container orchestration
apps/                  # microservices
  gateway_api/         # FastAPI gateway + WebAuthn/TOTP auth & admin UI
  data_ingestor/       # market data subscriptions & normalization
  news_ingestor/       # Miniflux/webhook news enrichment with sentiment
  feature_pipeline/    # indicators + DuckDB feature store
  llm_agents/          # LangGraph state machine & FINMEM memory
  risk_manager/        # deterministic risk checks & approvals
  execution_ib/        # IBKR paper/live adapter
  execution_crypto/    # Crypto adapter + Freqtrade bridge
  portfolio_ledger/    # Postgres-backed ledger service
  backtest_engine/     # CLI backtests & report generation
  reporter/            # Daily reports + alert intake
configs/               # risk/symbol/feed configuration
scripts/               # operational helpers (seed, migrate, flatten)
.tests/                # unit, integration, e2e suites
```

## Prerequisites
- Ubuntu 22.04 LTS host (root or sudo access)
- FIDO2/WebAuthn security key for UI admin
- API keys: Finnhub, CCXT exchanges, Miniflux token, IBKR paper/live credentials (optional but recommended)
- `age` key pair for `sops`

## Bootstrap & Deployment
1. **Clone & prepare**
   ```bash
   git clone https://github.com/your-org/autollm-trader.git
   cd autollm-trader
   ```

2. **Generate secrets**
   ```bash
   mkdir -p secrets
   age-keygen -o secrets/age.key
   export SOPS_AGE_KEY_FILE=secrets/age.key
   python - <<'PY'
import base64, nacl.signing, pathlib
root = pathlib.Path('secrets')
root.mkdir(exist_ok=True)
for prefix in ('llm', 'risk'):
    key = nacl.signing.SigningKey.generate()
    (root / f"{prefix}_signing_key.age").write_text(base64.b64encode(bytes(key)).decode())
    (root / f"{prefix}_pub.key").write_text(base64.b64encode(bytes(key.verify_key)).decode())
PY
   ```

3. **Edit environment**
   ```bash
   cp .env.template .env
   # populate API keys, JWT secrets, database credentials, Miniflux settings, etc.
   ```

4. **Run bootstrap** (installs hardened stack, docker rootless, monitoring, dependencies)
   ```bash
   sudo make bootstrap
   ```

   The script is idempotent and enforces: SSH hardening, unattended-upgrades, ufw/fail2ban/auditd, rootless Docker, Node 20, Poetry 1.7.1, TA-Lib, Prometheus/Grafana/Loki/Alertmanager, Miniflux scaffolding, and systemd watchdog.

5. **Deploy containers**
   ```bash
   make paper   # paper-trading stack (LIVE=0)
   # or
   make live    # live trading (requires live credentials and kill-switch checks)
   ```

6. **Admin UI build**
   ```bash
   cd apps/gateway_api/ui
   npm install
   npm run build
   cd -
   ```
   The static bundle is served at `https://<domain>/admin` via Caddy reverse proxy with automatic TLS.

## Operations
- `make up` / `make down` – manage production compose stack.
- `make logs` – tail docker-compose logs.
- `make kill` – engage global kill switch (flattens positions, writes flag file, broadcasts NATS `risk.kill_switch.activated`).
- `make backtest IB=symbol=AAPL,start=2023-01-01,end=2023-03-31` – run sample SMA backtest, writes `reports/backtest_*.json`.
- `make freqtrade-backtest CONFIG=configs/strategies/llm.json` – trigger remote Freqtrade backtest via REST API.
- `make seed` – seed Miniflux feeds from `configs/miniflux.json`.
- `make migrate` – initialize DuckDB feature schema.

### IBKR gateway
- Positionne `IB_ENABLED=1` (et, si besoin, `LIVE=1`) dans `.env` pour activer l'adaptateur `ib_insync`.
- Vérifie que TWS ou IB Gateway tourne et accepte les connexions depuis l’hôte défini (`IB_HOST`, `IB_PORT`, `IB_CLIENT_ID`).
- Renseigne `IB_ACCOUNT` (compte paper ou live). Le service tente une reconnexion automatique et applique `reqGlobalCancel` lorsque le kill-switch est déclenché.
- Tant que `IB_ENABLED=0`, l’adaptateur reste en mode « paper broker » interne : utile pour les tests hors connexion IBKR.

### LLM OpenAI
- Fournis une clé API via `OPENAI_API_KEY` et, optionnellement, surcharge le modèle dans la section `[llm]` (par défaut `gpt-4o-mini`).
- Les agents analyste / débat / trader fonctionnent via LangGraph + LangChain et respectent un budget de tokens par intention (`token_budget_per_intent`). Sans clé, la plateforme retombe automatiquement sur les heuristiques momentum d’origine.

## Authentication & Security
- **WebAuthn/TOTP**: `/api/auth/webauthn/*` flows manage passkey registration and login; `/api/auth/totp/*` provides FIDO2 fallback. Credentials stored encrypted via `sops`.
- **JWT**: short-lived access tokens (default 15 min), refresh triggered through FIDO2 challenge.
- **Signatures**: Trade intents signed with LLM ed25519 key, validated by risk manager; approvals re-signed with risk key before execution adapters accept.
- **Kill switch**: REST endpoint (`/api/risk/kill`), Make target, and CLI script `scripts/flatten_all.py` all converge on NATS broadcast + filesystem markers (`data/kill_switch.flag`).
- **Audit**: Risk manager writes rejections, approvals, and tags to NATS; ledger persists execution payloads in Postgres with JSONB snapshots.

## Observability
- Prometheus at `https://<domain>/prometheus` (reverse-proxied by Caddy).
- Grafana dashboards auto-provisioned (`infra/grafana/dashboards/autollm.json`).
- Loki + Promtail collect JSON logs; Alertmanager forwards alerts to reporter service `/alert`.
- Key metrics: `llm_intents_total`, `risk_rejections_total`, `execution_latency_seconds`, `open_positions` gauge.

## Testing & CI
- **Unit tests**: `make unit` exercises signature management, risk evaluation, memory retrieval.
- **Integration**: `make integration` covers backtest CLI and other service interactions.
- **E2E**: `LIVE=0 make e2e` simulates chained flow from LLM graph to execution.
- GitHub Actions workflow `.github/workflows/ci.yml` runs linting (ruff), typing (mypy), pytest with coverage, and Trivy security scan. A scheduled `e2e-paper-test` workflow validates paper trading pipeline daily.

## Configuration
- `configs/risk.yaml` – ATR-based limits, order throttling, market calendars, kill switch settings.
- `configs/symbols.yaml` – instrument metadata (sector/venue/tick sizes) for risk calculations.
- `configs/feeds.yaml` – data ingestion toggles per provider.
- `configs/miniflux.json` – seed feeds and webhook info.

## Backups & Disaster Recovery
- Integrate `borgmatic` (not included in repo) pointing at `/opt/autollm` volumes and Postgres dumps.
- Secrets encrypted with `sops` + `age`; configure `SOPS_AGE_KEY_FILE` for CI/CD.

## Notes
- The default DuckDB/Parquet paths live under `data/storage/` (workspace-write sandbox safe).
- TA-Lib compilation handled during bootstrap; ensure build deps remain installed for container builds.
- Regenerate lockfile locally with `poetry lock` after adjusting dependencies.
