from __future__ import annotations

import importlib
import json
from types import SimpleNamespace

import pytest
from pytest import MonkeyPatch

from autollm_trader.config import get_settings
from autollm_trader.models import ApprovedOrder
from autollm_trader.utils.time import utc_now


@pytest.mark.asyncio
async def test_ib_executor_paper_mode(monkeypatch: MonkeyPatch) -> None:
    monkeypatch.setenv("BROKERS__IB_ENABLED", "0")
    monkeypatch.setenv("BROKERS__LIVE_FLAG", "0")
    get_settings.cache_clear()
    module = importlib.import_module("apps.execution_ib.src.service")
    importlib.reload(module)
    service = module.IBExecutorService()
    assert service._gateway is None
    mock_client = SimpleNamespace()

    async def fake_connect():
        return mock_client

    async def fake_publish(subject: str, payload: bytes) -> None:
        fake_publish.calls.append((subject, payload))

    fake_publish.calls = []
    mock_client.publish = fake_publish
    monkeypatch.setattr(module.nats_connection, "connect", fake_connect)
    order = ApprovedOrder(
        ts=utc_now(),
        broker="IBKR",
        route="SMART",
        symbol="AAPL",
        side="BUY",
        qty=10,
        type="MKT",
        limit_price=None,
        risk_tags=["test"],
        risk_signature="sig",
        version=1,
    )
    msg = SimpleNamespace(data=order.model_dump_json().encode())
    await service._on_order(msg)
    assert fake_publish.calls, "publish should be invoked"
    subject, payload = fake_publish.calls[-1]
    assert subject == "exec.order.filled"


@pytest.mark.asyncio
async def test_ib_executor_kill_switch(monkeypatch: MonkeyPatch) -> None:
    monkeypatch.setenv("BROKERS__IB_ENABLED", "1")
    monkeypatch.setenv("BROKERS__LIVE_FLAG", "0")
    get_settings.cache_clear()
    module = importlib.import_module("apps.execution_ib.src.service")
    importlib.reload(module)
    service = module.IBExecutorService()
    gateway = SimpleNamespace()
    async def cancel_all() -> None:
        cancel_all.called = True
    cancel_all.called = False
    gateway.cancel_all = cancel_all
    service._gateway = gateway  # type: ignore[attr-defined]
    payload = {"reason": "test"}
    msg = SimpleNamespace(data=json.dumps(payload).encode())
    await service._on_kill_switch(msg)
    assert cancel_all.called is True
