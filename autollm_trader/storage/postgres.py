from __future__ import annotations

from typing import Any

from sqlalchemy import Column, DateTime, Float, Integer, MetaData, String, Table, create_engine
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.engine import Engine
from sqlalchemy.sql import select

from autollm_trader.config import get_settings
from autollm_trader.logger import get_logger

logger = get_logger(__name__)


metadata = MetaData()

executions = Table(
    "executions",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("ts", DateTime(timezone=True), nullable=False),
    Column("symbol", String, nullable=False),
    Column("side", String, nullable=False),
    Column("qty", Float, nullable=False),
    Column("price", Float, nullable=True),
    Column("broker", String, nullable=False),
    Column("status", String, nullable=False),
    Column("payload", JSONB, nullable=False),
)

positions = Table(
    "positions",
    metadata,
    Column("symbol", String, primary_key=True),
    Column("qty", Float, nullable=False),
    Column("avg_price", Float, nullable=False),
    Column("realized_pnl", Float, nullable=False, default=0.0),
    Column("unrealized_pnl", Float, nullable=False, default=0.0),
)


class LedgerStore:
    def __init__(self, engine: Engine | None = None) -> None:
        settings = get_settings()
        self._engine = engine or create_engine(settings.database.dsn.replace("asyncpg", "psycopg"), future=True)
        metadata.create_all(self._engine)
        logger.info("Connected to Postgres ledger")

    @property
    def engine(self) -> Engine:
        return self._engine

    def insert_execution(self, payload: dict[str, Any]) -> None:
        with self._engine.begin() as conn:
            conn.execute(executions.insert().values(**payload))

    def upsert_position(self, symbol: str, qty: float, avg_price: float, realized: float, unrealized: float) -> None:
        with self._engine.begin() as conn:
            conn.execute(
                positions.insert()
                .values(
                    symbol=symbol,
                    qty=qty,
                    avg_price=avg_price,
                    realized_pnl=realized,
                    unrealized_pnl=unrealized,
                )
                .on_conflict_do_update(
                    index_elements=[positions.c.symbol],
                    set_={
                        "qty": qty,
                        "avg_price": avg_price,
                        "realized_pnl": realized,
                        "unrealized_pnl": unrealized,
                    },
                )
            )

    def fetch_positions(self) -> list[dict[str, Any]]:
        with self._engine.connect() as conn:
            rows = conn.execute(select(positions)).mappings().all()
            return [dict(row) for row in rows]


__all__ = ["LedgerStore"]
