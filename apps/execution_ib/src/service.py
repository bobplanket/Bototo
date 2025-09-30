from __future__ import annotations

import asyncio
import json

from ib_insync import IB, MarketOrder, LimitOrder, Stock, Trade, util

from autollm_trader.config import get_settings
from autollm_trader.logger import get_logger
from autollm_trader.messaging.nats_client import nats_connection
from autollm_trader.metrics.prom import EXECUTION_LATENCY
from autollm_trader.models import ApprovedOrder, ExecutionEvent
from autollm_trader.utils.time import utc_now

logger = get_logger(__name__)
settings = get_settings()

# Ensure ib_insync cooperates with asyncio event loop
util.useAsyncio()


class PaperBroker:
    async def execute(self, order: ApprovedOrder) -> ExecutionEvent:
        await asyncio.sleep(0.05)
        fill_price = 100.0
        return ExecutionEvent(
            ts=utc_now(),
            symbol=order.symbol,
            side=order.side,
            qty=order.qty,
            status="filled",
            broker=order.broker,
            fill_price=fill_price,
            intent_id=order.correlated_intent.llm_signature if order.correlated_intent else None,
            order_id=f"SIM-{order.symbol}-{int(utc_now().timestamp())}",
        )


class IBGateway:
    def __init__(self) -> None:
        self._ib = IB()
        self._lock = asyncio.Lock()
        self._connected = False
        self._settings = settings.brokers
        self._ib.errorEvent += self._on_error

    async def connect(self) -> None:
        async with self._lock:
            if self._connected and self._ib.isConnected():
                return
            host = self._settings.ib_host
            port = self._settings.ib_port
            client_id = self._settings.ib_client_id
            logger.info(
                "Connecting to IBKR",
                extra={"host": host, "port": port, "client_id": client_id},
            )
            await self._ib.connectAsync(host, port, clientId=client_id, timeout=15.0)
            self._connected = True
            logger.info("Connected to IBKR", extra={"isPaper": not settings.brokers.live_flag})

    async def disconnect(self) -> None:
        async with self._lock:
            if self._ib.isConnected():
                self._ib.disconnect()
            self._connected = False

    def _on_error(self, req_id: int, code: int, message: str, _: str) -> None:  # noqa: D401
        logger.error("IBKR error", extra={"req_id": req_id, "code": code, "message": message})

    async def execute(self, order: ApprovedOrder) -> ExecutionEvent:
        await self.connect()
        async with self._lock:
            contract = await self._qualify_contract(order.symbol)
            ib_order = self._build_order(order)
            trade = self._ib.placeOrder(contract, ib_order)
        trade = await self._await_completion(trade)
        status = trade.orderStatus.status or "submitted"
        avg_price = trade.orderStatus.avgFillPrice or 0.0
        fill_price = avg_price if avg_price > 0 else None
        logger.info(
            "IBKR trade completed",
            extra={
                "symbol": order.symbol,
                "status": status,
                "order_id": trade.order.orderId,
                "avg_price": fill_price,
            },
        )
        return ExecutionEvent(
            ts=utc_now(),
            symbol=order.symbol,
            side=order.side,
            qty=order.qty,
            status=status.lower(),
            broker=order.broker,
            fill_price=fill_price,
            intent_id=order.correlated_intent.llm_signature if order.correlated_intent else None,
            order_id=str(trade.order.orderId),
        )

    async def cancel_all(self) -> None:
        if not self._ib.isConnected():
            return
        logger.warning("Issuing global cancel to IBKR")
        self._ib.reqGlobalCancel()
        await self._ib.waitOnUpdate(timeout=2)

    async def _qualify_contract(self, symbol: str):  # type: ignore[override]
        contract = Stock(symbol, "SMART", "USD")
        contracts = await self._ib.qualifyContractsAsync(contract)
        if not contracts:
            raise RuntimeError(f"Unable to qualify contract for {symbol}")
        return contracts[0]

    def _build_order(self, approved: ApprovedOrder):  # type: ignore[override]
        action = approved.side
        quantity = approved.qty
        tif = approved.timeInForce
        account = self._settings.ib_account
        if approved.type == "LMT" and approved.limit_price:
            order = LimitOrder(action, quantity, approved.limit_price)
        else:
            order = MarketOrder(action, quantity)
        order.account = account
        order.tif = tif
        order.transmit = True
        if approved.correlated_intent:
            order.orderRef = approved.correlated_intent.llm_signature[:12]
        return order

    async def _await_completion(self, trade: Trade, timeout: float = 30.0) -> Trade:
        deadline = asyncio.get_running_loop().time() + timeout
        while True:
            await self._ib.waitOnUpdate(timeout=1)
            if trade.isDone():
                return trade
            if asyncio.get_running_loop().time() >= deadline:
                raise TimeoutError("IBKR order timed out waiting for fill")


class IBExecutorService:
    def __init__(self) -> None:
        self._tasks: list[asyncio.Task[None]] = []
        self._lock = asyncio.Lock()
        self._ib_enabled = settings.brokers.ib_enabled
        self._gateway = IBGateway() if self._ib_enabled else None
        self._paper = PaperBroker()

    async def start(self) -> None:
        async with self._lock:
            if self._tasks:
                return
            client = await nats_connection.connect()
            await client.subscribe("risk.order.approved", cb=self._on_order)
            await client.subscribe("risk.kill_switch.activated", cb=self._on_kill_switch)
            self._tasks.append(asyncio.create_task(self._heartbeat()))
            logger.info("Execution-IB ready", extra={"ib_enabled": self._ib_enabled})

    async def stop(self) -> None:
        async with self._lock:
            for task in self._tasks:
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
            self._tasks.clear()
            if self._gateway is not None:
                await self._gateway.disconnect()
            await nats_connection.close()

    async def _heartbeat(self) -> None:
        while True:
            await asyncio.sleep(60)

    async def _on_order(self, msg) -> None:  # type: ignore[no-untyped-def]
        order = ApprovedOrder.model_validate_json(msg.data)
        if order.broker != "IBKR":
            return
        logger.info("Received IBKR order", extra={"symbol": order.symbol, "qty": order.qty})
        try:
            with EXECUTION_LATENCY.labels(symbol=order.symbol, side=order.side).time():
                if self._ib_enabled and self._gateway is not None:
                    event = await self._gateway.execute(order)
                else:
                    event = await self._paper.execute(order)
        except Exception as exc:  # noqa: BLE001
            logger.exception("Order execution failed", exc_info=exc)
            event = ExecutionEvent(
                ts=utc_now(),
                symbol=order.symbol,
                side=order.side,
                qty=order.qty,
                status="rejected",
                broker=order.broker,
                fill_price=None,
                intent_id=order.correlated_intent.llm_signature if order.correlated_intent else None,
                order_id="ERROR",
            )
            subject = "exec.order.rejected"
        else:
            subject = "exec.order.filled" if event.status == "filled" else "exec.order.submitted"
        client = await nats_connection.connect()
        await client.publish(subject, event.model_dump_json().encode())

    async def _on_kill_switch(self, msg) -> None:  # type: ignore[no-untyped-def]
        payload = json.loads(msg.data.decode())
        logger.warning("Kill switch activated", extra=payload)
        if self._gateway is not None:
            await self._gateway.cancel_all()


service = IBExecutorService()


async def run_service() -> None:
    await service.start()
    while True:
        await asyncio.sleep(60)


__all__ = ["service", "run_service", "IBExecutorService"]
