"""Utility for computing technical indicators for OHLCV data."""
from __future__ import annotations

import numpy as np
import pandas as pd

from autollm_trader.logger import get_logger

logger = get_logger(__name__)


class TechnicalFeatureCalculator:
    """Compute a set of basic technical indicators."""

    def __init__(self) -> None:
        self._eps = np.finfo(float).eps

    def calculate_all_features(self, ohlcv: pd.DataFrame) -> pd.DataFrame:
        frame = ohlcv.copy()
        required = {"open", "high", "low", "close", "volume"}
        missing = required - set(frame.columns.str.lower())
        if missing:
            raise ValueError(f"OHLCV frame is missing columns: {missing}")

        # Normalise column casing
        frame.columns = [col.lower() for col in frame.columns]
        close = frame["close"]
        high = frame["high"]
        low = frame["low"]

        features = pd.DataFrame(index=frame.index)
        features["close"] = close
        features["returns"] = close.pct_change().fillna(0.0)

        features["sma_14"] = close.rolling(window=14, min_periods=1).mean()
        features["ema_14"] = close.ewm(span=14, adjust=False).mean()

        features["rsi_14"] = self._relative_strength_index(close, window=14)

        macd_fast = close.ewm(span=12, adjust=False).mean()
        macd_slow = close.ewm(span=26, adjust=False).mean()
        macd = macd_fast - macd_slow
        signal = macd.ewm(span=9, adjust=False).mean()
        features["macd"] = macd
        features["macd_signal"] = signal
        features["macd_hist"] = macd - signal

        bb_mid = close.rolling(window=20, min_periods=1).mean()
        bb_std = close.rolling(window=20, min_periods=1).std(ddof=0)
        features["bb_mid"] = bb_mid
        features["bb_upper"] = bb_mid + 2 * bb_std
        features["bb_lower"] = bb_mid - 2 * bb_std

        features["atr_14"] = self._average_true_range(high, low, close, window=14)

        features["volume_sma_20"] = frame["volume"].rolling(window=20, min_periods=1).mean()
        features.dropna(inplace=True)

        logger.debug("Calculated features", extra={"rows": len(features), "columns": len(features.columns)})
        return features

    def _relative_strength_index(self, close: pd.Series, window: int) -> pd.Series:
        delta = close.diff()
        up = delta.clip(lower=0)
        down = -delta.clip(upper=0)
        roll_up = up.ewm(alpha=1 / window, adjust=False).mean()
        roll_down = down.ewm(alpha=1 / window, adjust=False).mean()
        rs = (roll_up + self._eps) / (roll_down + self._eps)
        rsi = 100 - (100 / (1 + rs))
        return rsi.fillna(0)

    def _average_true_range(
        self,
        high: pd.Series,
        low: pd.Series,
        close: pd.Series,
        window: int,
    ) -> pd.Series:
        high_low = high - low
        high_close = (high - close.shift()).abs()
        low_close = (low - close.shift()).abs()
        true_range = pd.concat([high_low, high_close, low_close], axis=1).max(axis=1)
        atr = true_range.rolling(window=window, min_periods=1).mean()
        return atr.fillna(0)


__all__ = ["TechnicalFeatureCalculator"]
