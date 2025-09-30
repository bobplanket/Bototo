from __future__ import annotations

import asyncio
import json
from collections import defaultdict, deque
from typing import Deque, Dict

import numpy as np
import pandas as pd

try:
    import talib  # type: ignore
except ImportError:  # pragma: no cover
    talib = None

from autollm_trader.logger import get_logger
from autollm_trader.messaging.nats_client import nats_connection
from autollm_trader.models import FeatureSnapshot, MarketBar
from autollm_trader.storage.duckdb import DuckDbFeatureStore

logger = get_logger(__name__)

WINDOW = 50


class FeaturePipeline:
    def __init__(self, store: DuckDbFeatureStore | None = None) -> None:
        self.store = store or DuckDbFeatureStore()
        self.bars: Dict[str, Deque[MarketBar]] = defaultdict(lambda: deque(maxlen=WINDOW))

    def _compute_indicators(self, bars: Deque[MarketBar]) -> dict[str, float]:
        closes = np.array([bar.close for bar in bars], dtype=float)
        highs = np.array([bar.high for bar in bars], dtype=float)
        lows = np.array([bar.low for bar in bars], dtype=float)
        if closes.size == 0:
            return {}
        features: dict[str, float] = {}
        series = pd.Series(closes)
        features["sma_5"] = float(series.rolling(window=5).mean().iloc[-1]) if closes.size >= 5 else np.nan
        features["sma_20"] = float(series.rolling(window=20).mean().iloc[-1]) if closes.size >= 20 else np.nan
        if talib is not None and closes.size >= 14:
            rsi = talib.RSI(closes, timeperiod=14)
            features["rsi_14"] = float(rsi[-1])
        else:
            delta = np.diff(closes)
            up = delta.clip(min=0).mean() if delta.size else 0.0
            down = -delta.clip(max=0).mean() if delta.size else 0.0
            rs = up / down if down else np.inf
            features["rsi_14"] = float(100 - (100 / (1 + rs))) if np.isfinite(rs) else 100.0
        true_range = np.maximum(highs[1:], closes[:-1]) - np.minimum(lows[1:], closes[:-1]) if closes.size > 1 else np.array([0.0])
        atr = true_range.mean() if true_range.size else 0.0
        features["atr"] = float(atr)
        return features

    async def handle_bar(self, bar: MarketBar) -> None:
        key = f"{bar.symbol}:{bar.timeframe}"
        bucket = self.bars[key]
        bucket.append(bar)
        features = self._compute_indicators(bucket)
        snapshot = FeatureSnapshot(
            ts=bar.ts,
            symbol=bar.symbol,
            features=features,
            window=bar.timeframe,
        )
        self.store.insert_snapshot(snapshot.ts, snapshot.symbol, snapshot.window, snapshot.features)
        client = await nats_connection.connect()
        await client.publish(
            f"features.snapshot.{bar.symbol}",
            snapshot.model_dump_json().encode(),
        )


pipeline = FeaturePipeline()


async def stream_bars() -> None:
    async def callback(msg) -> None:  # type: ignore[no-untyped-def]
        bar = MarketBar.model_validate_json(msg.data)
        await pipeline.handle_bar(bar)

    client = await nats_connection.connect()
    await client.subscribe("market.bars.>", cb=callback)
    while True:
        await asyncio.sleep(60)


__all__ = ["FeaturePipeline", "pipeline", "stream_bars"]
