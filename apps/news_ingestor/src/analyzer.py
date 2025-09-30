from __future__ import annotations

import re
from typing import Iterable

import httpx
import trafilatura
import yaml
from textblob import TextBlob

from autollm_trader.config import get_settings
from autollm_trader.logger import get_logger

logger = get_logger(__name__)

TICKER_RE = re.compile(r"\b[A-Z]{1,5}\b")


async def fetch_content(url: str) -> str:
    async with httpx.AsyncClient(timeout=10) as client:
        response = await client.get(url)
        response.raise_for_status()
        downloaded = trafilatura.fetch_url(url, no_ssl=True)
        if downloaded:
            extracted = trafilatura.extract(downloaded, include_comments=False, include_images=False)
            if extracted:
                return extracted
        return response.text


def extract_tickers(text: str) -> list[str]:
    settings = get_settings()
    with settings.risk.symbols_config_path.open() as fh:
        config = yaml.safe_load(fh) or {}
    symbols = {item.get("symbol") for item in config.get("symbols", [])}
    tickers = {match for match in TICKER_RE.findall(text) if match in symbols}
    return sorted(tickers)


def sentiment(text: str) -> str:
    blob = TextBlob(text)
    polarity = blob.sentiment.polarity
    if polarity > 0.1:
        return "positive"
    if polarity < -0.1:
        return "negative"
    return "neutral"


__all__ = ["fetch_content", "extract_tickers", "sentiment"]
