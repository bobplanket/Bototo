from __future__ import annotations

import argparse
import json
from pathlib import Path

import httpx

from autollm_trader.config import get_settings
from autollm_trader.logger import configure_logging, get_logger

configure_logging()
logger = get_logger(__name__)
settings = get_settings()


def run_backtest(config_path: Path, dry_run: bool = True) -> None:
    base_url = settings.brokers.freqtrade_host
    if not base_url:
        raise RuntimeError("FREQTRADE_API_HOST not configured")
    payload = json.loads(config_path.read_text())
    endpoint = "/api/v1/backtest" if dry_run else "/api/v1/live"
    headers = {"Authorization": f"Bearer {settings.brokers.freqtrade_token}"} if settings.brokers.freqtrade_token else {}
    with httpx.Client(timeout=30) as client:
        response = client.post(f"{base_url}{endpoint}", json=payload, headers=headers)
        response.raise_for_status()
        logger.info("Freqtrade response", extra={"response": response.json()})


def main() -> None:
    parser = argparse.ArgumentParser(description="Trigger Freqtrade backtest")
    parser.add_argument("--config", required=True)
    parser.add_argument("--dry-run", action="store_true", default=True)
    args = parser.parse_args()
    run_backtest(Path(args.config), dry_run=args.dry_run)


if __name__ == "__main__":
    main()
