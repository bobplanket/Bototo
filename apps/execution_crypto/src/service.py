from __future__ import annotations

import asyncio
import json
from typing import Any

import httpx
from ccxt.base.errors import BaseError, InsufficientFunds, InvalidOrder

from autollm_trader.config import get_settings
from autollm_trader.logger import get_logger
from autollm_trader.messaging.nats_client import nats_connection
from autollm_trader.metrics.prom import EXECUTION_LATENCY
from autollm_trader.models import ApprovedOrder, ExecutionEvent
from autollm_trader.utils.time import utc_now

from .exchange_manager import (
    ExchangeCredentialsMissing,
    ExchangeInitializationError,
    ExchangeManager,
)

logger = get_logger(__name__)
settings = get_settings()


class FreqtradeBridge:
    def __init__(self) -> None:
        self.base_url = settings.brokers.freqtrade_host
        self.token = settings.brokers.freqtrade_token

    @property
    def is_configured(self) -> bool:
        return bool(self.base_url)

    async def execute(self, order: ApprovedOrder) -> ExecutionEvent:
        if self.base_url:
            async with httpx.AsyncClient(timeout=10) as client:
                headers = {"Authorization": f"Bearer {self.token}"} if self.token else {}
                payload = {
                    "pair": order.symbol.replace("/", "-"),
                    "side": order.side.lower(),
                    "amount": order.qty,
                }
                response = await client.post(f"{self.base_url}/api/v1/orders", json=payload, headers=headers)
                response.raise_for_status()
                data = response.json()
                fill_price = float(data.get("price", 0.0))
        else:
            await asyncio.sleep(0.1)
            fill_price = 100.0
        event = ExecutionEvent(
            ts=utc_now(),
            symbol=order.symbol,
            side=order.side,
            qty=order.qty,
            status="filled",
            broker=order.broker,
            fill_price=fill_price,
            intent_id=order.correlated_intent.llm_signature if order.correlated_intent else None,
            order_id=f"{order.symbol}-{utc_now().timestamp()}",
        )
        return event


class CryptoExecutorService:
    def __init__(self) -> None:
        self.bridge = FreqtradeBridge()
        self.exchange_manager = ExchangeManager()
        self._supported_brokers = set(self.exchange_manager.supported_brokers)
        self._tasks: list[asyncio.Task[None]] = []
        self._lock = asyncio.Lock()

    async def start(self) -> None:
        async with self._lock:
            if self._tasks:
                return
            client = await nats_connection.connect()
            await client.subscribe("risk.order.approved", cb=self._on_order)
            self._tasks.append(asyncio.create_task(self._heartbeat()))
            logger.info("Execution-crypto subscribed to approved orders")

    async def stop(self) -> None:
        async with self._lock:
            for task in self._tasks:
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
            self._tasks.clear()
            await self.exchange_manager.close()
            await nats_connection.close()

    async def _heartbeat(self) -> None:
        while True:
            await asyncio.sleep(60)

    async def _on_order(self, msg) -> None:  # type: ignore[no-untyped-def]
        order = ApprovedOrder.model_validate_json(msg.data)
        if order.broker not in self._supported_brokers and not self.bridge.is_configured:
            return
        logger.info(
            "Executing crypto order",
            extra={"symbol": order.symbol, "broker": order.broker, "qty": order.qty},
        )

        try:
            with EXECUTION_LATENCY.labels(symbol=order.symbol, side=order.side).time():
                if order.broker in self._supported_brokers:
                    event = await self._execute_ccxt_order(order)
                elif self.bridge.is_configured:
                    event = await self.bridge.execute(order)
                else:  # pragma: no cover - guard rail
                    return
        except ExchangeCredentialsMissing as exc:
            logger.error("Missing exchange credentials", extra={"broker": exc.broker})
            if self.bridge.is_configured:
                event = await self.bridge.execute(order)
            else:
                event = self._build_rejected_event(order, reason="missing_credentials")
        except ExchangeInitializationError as exc:  # pragma: no cover - network dependent
            logger.error("Exchange initialisation failed", extra={"broker": exc.broker})
            event = self._build_rejected_event(order, reason="initialisation_failed")
        except InsufficientFunds as exc:
            logger.warning("Exchange rejected order (insufficient funds)", extra={"broker": order.broker})
            event = self._build_rejected_event(order, reason="insufficient_funds", message=str(exc))
        except InvalidOrder as exc:
            logger.warning("Invalid order for exchange", extra={"broker": order.broker, "error": str(exc)})
            event = self._build_rejected_event(order, reason="invalid_order", message=str(exc))
        except BaseError as exc:  # pragma: no cover - network dependent
            logger.exception("Exchange error", extra={"broker": order.broker})
            event = self._build_rejected_event(order, reason="exchange_error", message=str(exc))
        except Exception as exc:  # noqa: BLE001
            logger.exception("Unexpected crypto execution failure")
            event = self._build_rejected_event(order, reason="unexpected_error", message=str(exc))

        client = await nats_connection.connect()
        await client.publish("exec.order.filled", event.model_dump_json().encode())

    async def _execute_ccxt_order(self, order: ApprovedOrder) -> ExecutionEvent:
        exchange = await self.exchange_manager.get_exchange(order.broker)
        side = order.side.lower()
        ccxt_symbol = order.symbol
        amount = float(order.qty)

        if order.type == "MKT":
            result = await exchange.create_market_order(ccxt_symbol, side, amount)
        else:
            if order.limit_price is None:
                raise InvalidOrder("limit_price required for limit orders")
            price = float(order.limit_price)
            result = await exchange.create_limit_order(ccxt_symbol, side, amount, price)

        status = self._normalise_status(result.get("status"))
        fill_price = self._resolve_fill_price(result)
        order_id = str(result.get("id") or f"{order.symbol}-{int(utc_now().timestamp())}")

        logger.info(
            "Exchange order executed",
            extra={
                "broker": order.broker,
                "status": status,
                "order_id": order_id,
                "fill_price": fill_price,
            },
        )

        return self._build_event(order, status=status, fill_price=fill_price, order_id=order_id)

    def _resolve_fill_price(self, payload: dict[str, Any]) -> float | None:
        for key in ("average", "price", "lastTradeTimestamp"):
            value = payload.get(key)
            if value:
                try:
                    return float(value)
                except (TypeError, ValueError):  # pragma: no cover - defensive
                    continue
        return None

    def _normalise_status(self, status: str | None) -> str:
        mapping = {
            None: "submitted",
            "pending": "submitted",
            "open": "submitted",
            "closed": "filled",
            "canceled": "canceled",
            "cancelled": "canceled",
            "rejected": "rejected",
        }
        return mapping.get(status, status or "submitted")

    def _build_event(
        self,
        order: ApprovedOrder,
        *,
        status: str,
        fill_price: float | None,
        order_id: str,
    ) -> ExecutionEvent:
        return ExecutionEvent(
            ts=utc_now(),
            symbol=order.symbol,
            side=order.side,
            qty=order.qty,
            status=status,
            broker=order.broker,
            fill_price=fill_price,
            intent_id=order.correlated_intent.llm_signature if order.correlated_intent else None,
            order_id=order_id,
        )

    def _build_rejected_event(
        self,
        order: ApprovedOrder,
        *,
        reason: str,
        message: str | None = None,
    ) -> ExecutionEvent:
        if message:
            logger.debug("Rejecting order", extra={"broker": order.broker, "reason": reason, "message": message})
        return self._build_event(order, status="rejected", fill_price=None, order_id=f"ERR-{reason}")


service = CryptoExecutorService()


async def run_service() -> None:
    await service.start()
    while True:
        await asyncio.sleep(60)


__all__ = ["service", "run_service", "CryptoExecutorService"]
