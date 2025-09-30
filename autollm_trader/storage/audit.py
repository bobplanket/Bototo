"""Async audit logging storage for security-relevant events."""
from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

import asyncpg

from autollm_trader.config import get_settings
from autollm_trader.logger import get_logger

logger = get_logger(__name__)

_AUDIT_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS audit_events (
    id BIGSERIAL PRIMARY KEY,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    user_id TEXT,
    ip_address TEXT,
    method VARCHAR(10) NOT NULL,
    path TEXT NOT NULL,
    status_code INTEGER NOT NULL,
    duration_ms DOUBLE PRECISION,
    user_agent TEXT,
    metadata JSONB
);
"""

_AUDIT_INDEXES = (
    "CREATE INDEX IF NOT EXISTS idx_audit_occurred_at ON audit_events (occurred_at DESC)",
    "CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_events (user_id, occurred_at DESC)",
    "CREATE INDEX IF NOT EXISTS idx_audit_path ON audit_events (path, occurred_at DESC)",
)


@dataclass(slots=True)
class AuditEvent:
    """Representation of a security event to persist."""

    timestamp: datetime
    user_id: str | None
    ip_address: str | None
    method: str
    path: str
    status_code: int
    duration_ms: float | None
    user_agent: str | None
    metadata: dict[str, Any] | None = None

    def as_tuple(self) -> tuple[Any, ...]:
        payload = self.metadata or {}
        return (
            self.timestamp,
            self.user_id,
            self.ip_address,
            self.method,
            self.path,
            self.status_code,
            self.duration_ms,
            self.user_agent,
            json.dumps(payload) if payload else None,
        )


class AuditLogWriter:
    """Persist audit events asynchronously using asyncpg."""

    def __init__(self) -> None:
        self._pool: asyncpg.Pool | None = None
        self._lock = asyncio.Lock()

    async def connect(self) -> None:
        if self._pool is not None:
            return
        async with self._lock:
            if self._pool is not None:
                return
            settings = get_settings()
            dsn = settings.database.async_dsn
            logger.info("Initialising audit log writer", extra={"dsn": dsn})
            self._pool = await asyncpg.create_pool(dsn, min_size=1, max_size=5)
            async with self._pool.acquire() as conn:
                await conn.execute(_AUDIT_TABLE_SQL)
                for stmt in _AUDIT_INDEXES:
                    await conn.execute(stmt)

    async def close(self) -> None:
        if self._pool is None:
            return
        async with self._lock:
            if self._pool is None:
                return
            await self._pool.close()
            self._pool = None
            logger.info("Closed audit log writer")

    async def write_event(self, event: AuditEvent | dict[str, Any]) -> None:
        if isinstance(event, dict):
            event_obj = AuditEvent(**event)
        else:
            event_obj = event

        if event_obj.timestamp.tzinfo is None:
            event_obj.timestamp = event_obj.timestamp.replace(tzinfo=timezone.utc)

        if self._pool is None:
            await self.connect()

        assert self._pool is not None
        try:
            async with self._pool.acquire() as conn:
                await conn.execute(
                    """
                    INSERT INTO audit_events (
                        occurred_at,
                        user_id,
                        ip_address,
                        method,
                        path,
                        status_code,
                        duration_ms,
                        user_agent,
                        metadata
                    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb)
                    """,
                    *event_obj.as_tuple(),
                )
        except Exception as exc:  # noqa: BLE001
            logger.error("Failed to persist audit event", exc_info=exc, extra={"path": event_obj.path})


__all__ = ["AuditLogWriter", "AuditEvent"]
