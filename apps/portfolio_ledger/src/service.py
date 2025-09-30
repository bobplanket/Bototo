from __future__ import annotations

import asyncio
import json
from typing import Any

from autollm_trader.logger import get_logger
from autollm_trader.messaging.nats_client import nats_connection
from autollm_trader.models import ExecutionEvent
from autollm_trader.storage.postgres import LedgerStore

logger = get_logger(__name__)


class PortfolioLedgerService:
    def __init__(self) -> None:
        self.store = LedgerStore()
        self._tasks: list[asyncio.Task[None]] = []
        self._lock = asyncio.Lock()

    async def start(self) -> None:
        async with self._lock:
            if self._tasks:
                return
            client = await nats_connection.connect()
            await client.subscribe("exec.order.filled", cb=self._on_execution)
            self._tasks.append(asyncio.create_task(self._heartbeat()))
            logger.info("Portfolio ledger subscribed to executions")

    async def stop(self) -> None:
        async with self._lock:
            for task in self._tasks:
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
            self._tasks.clear()
            await nats_connection.close()

    async def _heartbeat(self) -> None:
        while True:
            await asyncio.sleep(60)

    async def _on_execution(self, msg) -> None:  # type: ignore[no-untyped-def]
        event = ExecutionEvent.model_validate_json(msg.data)
        payload = {
            "ts": event.ts,
            "symbol": event.symbol,
            "side": event.side,
            "qty": event.qty,
            "price": event.fill_price,
            "broker": event.broker,
            "status": event.status,
            "payload": json.loads(event.model_dump_json()),
        }
        self.store.insert_execution(payload)
        qty = event.qty if event.side == "BUY" else -event.qty
        self.store.upsert_position(
            symbol=event.symbol,
            qty=qty,
            avg_price=event.fill_price or 0,
            realized=0.0,
            unrealized=0.0,
        )
        logger.info("Execution recorded", extra={"symbol": event.symbol})


service = PortfolioLedgerService()


async def run_service() -> None:
    await service.start()
    while True:
        await asyncio.sleep(60)


__all__ = ["service", "run_service", "PortfolioLedgerService"]
