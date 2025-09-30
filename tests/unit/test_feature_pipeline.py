from __future__ import annotations

import pandas as pd
import pytest

from apps.data_ingestor.src.feature_cache import FeatureCache
from apps.data_ingestor.src.feature_pipeline import FeaturePipeline
from apps.data_ingestor.src.feature_calculator import TechnicalFeatureCalculator


class DummyRedis:
    def __init__(self) -> None:
        self.store: dict[str, str] = {}

    async def get(self, key: str):
        return self.store.get(key)

    async def setex(self, key: str, ttl: int, value: str) -> None:  # noqa: ARG002 - ttl unused in dummy
        self.store[key] = value

    async def delete(self, key: str) -> None:
        self.store.pop(key, None)


@pytest.fixture()
def sample_ohlcv() -> pd.DataFrame:
    index = pd.date_range("2024-01-01", periods=50, freq="1min")
    data = {
        "open": pd.Series(range(50), index=index) + 100,
        "high": pd.Series(range(50), index=index) + 101,
        "low": pd.Series(range(50), index=index) + 99,
        "close": pd.Series(range(50), index=index) + 100.5,
        "volume": pd.Series([1_000 + i for i in range(50)], index=index),
    }
    return pd.DataFrame(data)


@pytest.mark.asyncio
async def test_feature_cache_roundtrip(sample_ohlcv: pd.DataFrame) -> None:
    dummy = DummyRedis()
    cache = FeatureCache("redis://localhost", client=dummy)
    calculator = TechnicalFeatureCalculator()
    features = calculator.calculate_all_features(sample_ohlcv)

    await cache.set_features("BTC/USDT", "1m", features)
    cached = await cache.get_features("BTC/USDT", "1m")
    assert cached is not None
    assert list(cached.columns) == list(features.columns)


@pytest.mark.asyncio
async def test_feature_pipeline_uses_cache(sample_ohlcv: pd.DataFrame) -> None:
    dummy = DummyRedis()
    cache = FeatureCache("redis://localhost", client=dummy)
    pipeline = FeaturePipeline("redis://localhost", cache=cache)

    features = await pipeline.get_features("AAPL", "1m", sample_ohlcv, use_cache=True)
    assert not features.empty

    # mutate cache to ensure next call hits cached payload
    cached = await cache.get_features("AAPL", "1m")
    assert cached is not None
    cached["close"] = cached["close"] + 1
    await cache.set_features("AAPL", "1m", cached)

    repeat = await pipeline.get_features("AAPL", "1m", sample_ohlcv, use_cache=True)
    assert repeat.iloc[0]["close"] == pytest.approx(cached.iloc[0]["close"])


@pytest.mark.asyncio
async def test_feature_validation_detects_missing_column(sample_ohlcv: pd.DataFrame) -> None:
    dummy = DummyRedis()
    cache = FeatureCache("redis://localhost", client=dummy)
    pipeline = FeaturePipeline("redis://localhost", cache=cache)

    bad = sample_ohlcv.copy().drop(columns=["open"])
    with pytest.raises(ValueError):
        await pipeline.get_features("AAPL", "1m", bad, use_cache=False)
