"""High level orchestration around feature calculation and caching."""
from __future__ import annotations

import pandas as pd
import numpy as np

from autollm_trader.logger import get_logger

from .feature_cache import FeatureCache
from .feature_calculator import TechnicalFeatureCalculator

logger = get_logger(__name__)


class FeaturePipeline:
    """Compute, validate, and cache technical features."""

    def __init__(self, redis_url: str, cache_ttl: int = 3600, *, cache: FeatureCache | None = None) -> None:
        self.cache = cache or FeatureCache(redis_url, ttl_seconds=cache_ttl)
        self.calculator = TechnicalFeatureCalculator()

    async def get_features(
        self,
        symbol: str,
        timeframe: str,
        ohlcv: pd.DataFrame,
        *,
        use_cache: bool = True,
    ) -> pd.DataFrame:
        if use_cache:
            cached = await self.cache.get_features(symbol, timeframe)
            if cached is not None and not cached.empty:
                logger.debug("Feature cache hit", extra={"symbol": symbol, "timeframe": timeframe})
                return cached

        computed = self.calculator.calculate_all_features(ohlcv)
        self._validate(computed)

        if use_cache:
            await self.cache.set_features(symbol, timeframe, computed)

        return computed

    async def invalidate(self, symbol: str, timeframe: str) -> None:
        await self.cache.invalidate(symbol, timeframe)

    def _validate(self, frame: pd.DataFrame) -> None:
        required = ["close", "returns", "rsi_14", "atr_14"]
        for column in required:
            if column not in frame.columns:
                raise ValueError(f"feature column missing: {column}")
            if frame[column].isna().mean() > 0.3:
                raise ValueError(f"too many NaNs in feature column {column}")

        inf_cols: list[str] = []
        for column in frame.columns:
            if np.isinf(frame[column]).any():
                inf_cols.append(column)
        if inf_cols:
            raise ValueError(f"infinite values detected in columns: {inf_cols}")

        logger.debug("Feature validation passed", extra={"rows": len(frame)})


__all__ = ["FeaturePipeline"]
