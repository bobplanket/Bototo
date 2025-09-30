from __future__ import annotations

import datetime as dt
import pathlib
from contextlib import contextmanager

import duckdb
import pandas as pd

from autollm_trader.config import get_settings
from autollm_trader.logger import get_logger

logger = get_logger(__name__)


class DuckDbFeatureStore:
    def __init__(self, path: pathlib.Path | None = None) -> None:
        settings = get_settings()
        self._path = path or settings.duckdb.path
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._con = duckdb.connect(str(self._path))
        logger.info("Connected to DuckDB", extra={"path": str(self._path)})
        self._init_tables()

    def _init_tables(self) -> None:
        self._con.execute(
            """
            CREATE TABLE IF NOT EXISTS feature_snapshots (
                ts TIMESTAMP,
                symbol VARCHAR,
                window VARCHAR,
                features MAP(VARCHAR, DOUBLE)
            )
            """
        )

    def insert_snapshot(self, ts: dt.datetime, symbol: str, window: str, features: dict[str, float]) -> None:
        logger.debug("Inserting feature snapshot", extra={"symbol": symbol, "window": window})
        self._con.execute(
            "INSERT INTO feature_snapshots VALUES (?, ?, ?, ?)",
            [ts, symbol, window, features],
        )

    def load_history(self, symbol: str, window: str, start: dt.datetime | None = None) -> pd.DataFrame:
        query = "SELECT * FROM feature_snapshots WHERE symbol = ? AND window = ?"
        params: list[object] = [symbol, window]
        if start:
            query += " AND ts >= ?"
            params.append(start)
        query += " ORDER BY ts"
        df = self._con.execute(query, params).fetchdf()
        return df

    def close(self) -> None:
        self._con.close()


@contextmanager
def feature_store(path: pathlib.Path | None = None) -> DuckDbFeatureStore:
    store = DuckDbFeatureStore(path)
    try:
        yield store
    finally:
        store.close()


__all__ = ["DuckDbFeatureStore", "feature_store"]
