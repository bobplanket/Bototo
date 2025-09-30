PYTHON = python3
POETRY = poetry
PROJECT = autollm-trader

.PHONY: bootstrap install lint format test unit integration e2e up down logs seed paper live kill backtest freqtrade-backtest migrate duckdb-migrate dev start stop clean

bootstrap:
	bash infra/bootstrap.sh

install:
	$(POETRY) install

lint:
	$(POETRY) run ruff check .
	$(POETRY) run mypy autollm_trader apps

format:
	$(POETRY) run ruff format .

unit:
	$(POETRY) run pytest tests/unit -vv

integration:
	$(POETRY) run pytest tests/integration -vv

E2E_ENV?=paper
e2e:
	LIVE=$(E2E_ENV) $(POETRY) run pytest tests/e2e -vv

up:
	docker compose -f infra/docker-compose.yml up -d

up-dev:
	docker compose -f infra/docker-compose.dev.yml up -d

paper:
	LIVE=0 docker compose -f infra/docker-compose.yml up -d

live:
	LIVE=1 docker compose -f infra/docker-compose.yml up -d

kill:
	$(POETRY) run python -m apps.risk_manager.src.cli kill-switch

backtest:
	$(POETRY) run python -m apps.backtest_engine.src.cli ${ARGS}

freqtrade-backtest:
	$(POETRY) run python -m apps.execution_crypto.src.freqtrade_bridge --config $$CONFIG --dry-run

seed:
	$(POETRY) run python scripts/seed_miniflux.py

migrate:
	$(POETRY) run python scripts/migrate_duckdb.py

flatten:
	$(POETRY) run python scripts/flatten_all.py

logs:
	docker compose -f infra/docker-compose.yml logs -f

clean:
	docker compose -f infra/docker-compose.yml down -v
	docker compose -f infra/docker-compose.dev.yml down -v
	rm -rf .mypy_cache .ruff_cache __pycache__ *.pyc

