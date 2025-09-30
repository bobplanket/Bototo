from __future__ import annotations

import pytest
from ccxt.base.errors import InvalidOrder

from apps.execution_crypto.src.service import CryptoExecutorService
from autollm_trader.models import ApprovedOrder, IntentReasoning, RiskParameters, TradeIntent
from autollm_trader.utils.time import utc_now


class StubExchange:
    def __init__(self) -> None:
        self.market_orders: list[tuple[str, str, float]] = []
        self.limit_orders: list[tuple[str, str, float, float]] = []

    async def create_market_order(self, symbol: str, side: str, amount: float):
        self.market_orders.append((symbol, side, amount))
        return {"id": "abc123", "status": "closed", "average": "123.45"}

    async def create_limit_order(self, symbol: str, side: str, amount: float, price: float):
        self.limit_orders.append((symbol, side, amount, price))
        return {"id": "def456", "status": "open", "price": price}


class StubManager:
    def __init__(self) -> None:
        self.supported_brokers = ("BINANCE",)
        self.exchange = StubExchange()

    async def get_exchange(self, broker: str):
        assert broker == "BINANCE"
        return self.exchange

    async def close(self) -> None:  # pragma: no cover - not exercised here
        return None


def build_order(order_type: str = "MKT", limit_price: float | None = None) -> ApprovedOrder:
    intent = TradeIntent(
        symbol="BTC/USDT",
        venue="BINANCE",
        side="BUY",
        qty=0.1,
        timeInForce="DAY",
        reasoning=IntentReasoning(summary="test", evidence_ids=[]),
        risk=RiskParameters(max_slippage_bps=10, stop_loss=None, take_profit=None),
        llm_signature="intent-sig",
    )
    return ApprovedOrder(
        ts=utc_now(),
        broker="BINANCE",
        route="SPOT",
        symbol="BTC/USDT",
        side="BUY",
        qty=0.1,
        type=order_type,
        limit_price=limit_price,
        risk_tags=[],
        risk_signature="risk-sig",
        version=1,
        correlated_intent=intent,
    )


@pytest.mark.asyncio
async def test_execute_ccxt_order_market(monkeypatch: pytest.MonkeyPatch) -> None:
    service = CryptoExecutorService()
    stub_manager = StubManager()
    service.exchange_manager = stub_manager  # type: ignore[assignment]
    service._supported_brokers = set(stub_manager.supported_brokers)

    order = build_order("MKT")
    event = await service._execute_ccxt_order(order)

    assert event.status == "filled"
    assert stub_manager.exchange.market_orders == [("BTC/USDT", "buy", pytest.approx(0.1))]
    assert event.fill_price == pytest.approx(123.45)
    assert event.order_id == "abc123"


@pytest.mark.asyncio
async def test_execute_ccxt_order_limit_requires_price(monkeypatch: pytest.MonkeyPatch) -> None:
    service = CryptoExecutorService()
    stub_manager = StubManager()
    service.exchange_manager = stub_manager  # type: ignore[assignment]
    service._supported_brokers = set(stub_manager.supported_brokers)

    order = build_order("LMT", limit_price=None)
    with pytest.raises(InvalidOrder):
        await service._execute_ccxt_order(order)


def test_build_rejected_event():
    service = CryptoExecutorService()
    order = build_order()
    event = service._build_rejected_event(order, reason="missing_credentials")
    assert event.status == "rejected"
    assert event.order_id.startswith("ERR-")
