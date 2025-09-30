from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from autollm_trader.config import get_settings


def load_feeds(path: Path | None = None) -> dict[str, Any]:
    settings = get_settings()
    cfg_path = path or settings.risk.feeds_config_path
    with cfg_path.open() as fh:
        return yaml.safe_load(fh)


def feed_symbols(config: dict[str, Any], category: str) -> list[str]:
    section = config.get(category, {})
    symbols: list[str] = []
    for feed in section.values():
        if not feed.get("enabled", True):
            continue
        symbols.extend(feed.get("symbols", []))
    return list(dict.fromkeys(symbols))


@dataclass
class FeedConfig:
    equities: dict[str, Any]
    crypto: dict[str, Any]
    news: dict[str, Any]

    @classmethod
    def load(cls) -> "FeedConfig":
        data = load_feeds()
        return cls(
            equities=data.get("equities", {}),
            crypto=data.get("crypto", {}),
            news=data.get("news", {}),
        )


__all__ = ["FeedConfig", "load_feeds", "feed_symbols"]
