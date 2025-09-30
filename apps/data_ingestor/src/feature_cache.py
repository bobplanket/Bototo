"""Redis-backed cache for computed feature DataFrames."""
from __future__ import annotations

import json
from typing import Any

import pandas as pd
import redis.asyncio as redis

from autollm_trader.logger import get_logger

logger = get_logger(__name__)


class FeatureCache:
    """Simple TTL cache for feature matrices using Redis."""

    def __init__(self, redis_url: str, ttl_seconds: int = 3600, client: Any | None = None) -> None:
        self.ttl_seconds = ttl_seconds
        self._redis = client or redis.from_url(redis_url)

    async def get_features(self, symbol: str, timeframe: str) -> pd.DataFrame | None:
        key = self._key(symbol, timeframe)
        payload = await self._redis.get(key)
        if not payload:
            return None
        try:
            rows: list[dict[str, Any]] = json.loads(payload)
        except json.JSONDecodeError:  # pragma: no cover - defensive
            logger.warning("Invalid JSON encountered in feature cache", extra={"key": key})
            await self._redis.delete(key)
            return None
        return pd.DataFrame(rows)

    async def set_features(self, symbol: str, timeframe: str, frame: pd.DataFrame) -> None:
        key = self._key(symbol, timeframe)
        data = frame.to_dict(orient="records")
        await self._redis.setex(key, self.ttl_seconds, json.dumps(data, default=_json_serializer))

    async def invalidate(self, symbol: str, timeframe: str) -> None:
        await self._redis.delete(self._key(symbol, timeframe))

    def _key(self, symbol: str, timeframe: str) -> str:
        return f"features:{symbol}:{timeframe}"


def _json_serializer(value: Any) -> Any:
    if isinstance(value, (pd.Timestamp, pd.Timedelta)):
        return value.isoformat()
    return value


__all__ = ["FeatureCache"]
