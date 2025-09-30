from __future__ import annotations

import pytest

from apps.execution_crypto.src import exchange_manager


class DummyExchange:
    def __init__(self) -> None:
        self.load_calls = 0
        self.closed = False

    async def load_markets(self) -> None:
        self.load_calls += 1

    async def close(self) -> None:
        self.closed = True


@pytest.mark.asyncio
async def test_exchange_manager_requires_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    manager = exchange_manager.ExchangeManager()
    monkeypatch.setattr(exchange_manager.settings, "binance_api_key", None)
    monkeypatch.setattr(exchange_manager.settings, "binance_api_secret", None)

    with pytest.raises(exchange_manager.ExchangeCredentialsMissing):
        await manager.get_exchange("BINANCE")


@pytest.mark.asyncio
async def test_exchange_manager_initialises_once(monkeypatch: pytest.MonkeyPatch) -> None:
    dummy = DummyExchange()
    manager = exchange_manager.ExchangeManager()

    monkeypatch.setattr(exchange_manager.settings, "binance_api_key", "key")
    monkeypatch.setattr(exchange_manager.settings, "binance_api_secret", "secret")

    monkeypatch.setattr(exchange_manager.ExchangeManager, "_create_client", lambda self, exchange_id, creds: dummy)

    first = await manager.get_exchange("BINANCE")
    second = await manager.get_exchange("BINANCE")

    assert first is second
    assert dummy.load_calls == 1

    await manager.close()
    assert dummy.closed is True
