from __future__ import annotations

import json
from pathlib import Path

import httpx

from autollm_trader.config import get_settings
from autollm_trader.logger import configure_logging, get_logger

configure_logging()
logger = get_logger(__name__)
settings = get_settings()


def seed() -> None:
    config_path = Path("configs/miniflux.json")
    if not config_path.exists():
        raise FileNotFoundError(config_path)
    payload = json.loads(config_path.read_text())
    base_url = getattr(settings, "MINIFLUX_BASE_URL", None)
    token = getattr(settings, "MINIFLUX_API_TOKEN", None)
    if not base_url or not token:
        logger.warning("MINIFLUX_BASE_URL or token not configured; skipping remote seed")
        return
    headers = {"X-Auth-Token": token}
    with httpx.Client(timeout=10) as client:
        for feed in payload.get("feeds", []):
            resp = client.post(f"{base_url}/v1/feeds", json=feed, headers=headers)
            resp.raise_for_status()
            logger.info("Seeded feed", extra={"title": feed["title"]})


def main() -> None:
    seed()


if __name__ == "__main__":
    main()
