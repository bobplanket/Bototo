from __future__ import annotations

import asyncio
import json
from typing import Any

from autollm_trader.logger import get_logger
from autollm_trader.messaging.nats_client import nats_connection
from autollm_trader.metrics.prom import RISK_REJECTIONS_COUNTER
from autollm_trader.models import ExecutionEvent, RejectedOrder, TradeIntent

from .rules import RiskEvaluator

logger = get_logger(__name__)


class RiskManagerService:
    def __init__(self) -> None:
        self.evaluator = RiskEvaluator()
        self._tasks: list[asyncio.Task[None]] = []
        self._lock = asyncio.Lock()

    async def start(self) -> None:
        async with self._lock:
            if self._tasks:
                return
            client = await nats_connection.connect()
            await client.subscribe("llm.intent.proposed", cb=self._on_intent)
            await client.subscribe("market.ticks.>", cb=self._on_tick)
            self._tasks.append(asyncio.create_task(self._heartbeat()))
            logger.info("Risk manager subscribed to intents")

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

    async def _on_tick(self, msg) -> None:  # type: ignore[no-untyped-def]
        data = json.loads(msg.data.decode())
        symbol = data.get("symbol")
        bid = float(data.get("bid", 0))
        ask = float(data.get("ask", 0))
        self.evaluator.update_market(symbol, bid, ask)

    async def _on_intent(self, msg) -> None:  # type: ignore[no-untyped-def]
        intent = TradeIntent.model_validate_json(msg.data)
        evaluation, order = self.evaluator.evaluate(intent)
        client = await nats_connection.connect()
        if not evaluation.approved or order is None:
            reason = evaluation.reasons[0] if evaluation.reasons else "rejected"
            RISK_REJECTIONS_COUNTER.labels(reason=reason).inc()
            rejection = RejectedOrder(
                ts=intent.ts,
                symbol=intent.symbol,
                side=intent.side,
                qty=intent.qty,
                reason=reason,
                risk_tags=evaluation.tags,
                version=1,
            )
            await client.publish("risk.order.rejected", rejection.model_dump_json().encode())
            logger.warning("Intent rejected", extra={"symbol": intent.symbol, "reason": reason})
            return
        await client.publish("risk.order.approved", order.model_dump_json().encode())
        logger.info("Intent approved", extra={"symbol": intent.symbol, "qty": order.qty})


service = RiskManagerService()


async def run_service() -> None:
    await service.start()
    while True:
        await asyncio.sleep(60)


__all__ = ["service", "run_service", "RiskManagerService"]
