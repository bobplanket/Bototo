from __future__ import annotations

import asyncio
from collections.abc import Mapping
from typing import Any

import ccxt.async_support as ccxt
from ccxt.base.errors import BaseError

from autollm_trader.config import get_settings
from autollm_trader.logger import get_logger

logger = get_logger(__name__)
settings = get_settings()


class ExchangeCredentialsMissing(RuntimeError):
    """Raised when an exchange is selected but credentials are missing."""

    def __init__(self, broker: str) -> None:
        super().__init__(f"Credentials missing for exchange broker '{broker}'")
        self.broker = broker


class ExchangeInitializationError(RuntimeError):
    """Raised when an exchange fails to initialise."""

    def __init__(self, broker: str, reason: BaseError | Exception) -> None:
        super().__init__(f"Failed to initialise exchange '{broker}': {reason}")
        self.broker = broker
        self.reason = reason


class ExchangeManager:
    """Lazy manager for CCXT exchange clients with credential handling."""

    _BROKER_TO_EXCHANGE = {
        "BINANCE": "binance",
        "COINBASE": "coinbase",
        "KRAKEN": "kraken",
    }

    def __init__(self) -> None:
        self._clients: dict[str, ccxt.Exchange] = {}
        self._lock = asyncio.Lock()

    @property
    def supported_brokers(self) -> tuple[str, ...]:
        return tuple(self._BROKER_TO_EXCHANGE.keys())

    async def get_exchange(self, broker: str) -> ccxt.Exchange:
        """Return an initialised CCXT exchange client for the broker."""
        exchange_id = self._map_broker(broker)
        async with self._lock:
            if exchange_id in self._clients:
                return self._clients[exchange_id]
            credentials = self._credentials_for(exchange_id, broker)
            try:
                client = self._create_client(exchange_id, credentials)
                await client.load_markets()
            except BaseError as exc:  # pragma: no cover - ccxt specific
                logger.exception("Failed to initialise exchange", extra={"broker": broker})
                raise ExchangeInitializationError(broker, exc) from exc
            self._clients[exchange_id] = client
            logger.info("Initialised exchange", extra={"broker": broker, "exchange_id": exchange_id})
            return client

    async def close(self) -> None:
        async with self._lock:
            for exchange in self._clients.values():
                try:
                    await exchange.close()  # type: ignore[attr-defined]
                except BaseError:  # pragma: no cover - best effort close
                    logger.debug("Exchange close raised", exc_info=True)
                except Exception:  # noqa: BLE001
                    logger.debug("Exchange close raised", exc_info=True)
            self._clients.clear()

    def _map_broker(self, broker: str) -> str:
        try:
            return self._BROKER_TO_EXCHANGE[broker.upper()]
        except KeyError as exc:
            raise ExchangeCredentialsMissing(broker) from exc

    def _credentials_for(self, exchange_id: str, broker: str) -> Mapping[str, Any]:
        if exchange_id == "binance":
            key = settings.binance_api_key
            secret = settings.binance_api_secret
            if not key or not secret:
                raise ExchangeCredentialsMissing(broker)
            return {"apiKey": key, "secret": secret, "enableRateLimit": True}

        if exchange_id == "coinbase":
            key = settings.coinbase_api_key
            secret = settings.coinbase_api_secret
            passphrase = settings.coinbase_api_passphrase
            if not key or not secret or not passphrase:
                raise ExchangeCredentialsMissing(broker)
            return {
                "apiKey": key,
                "secret": secret,
                "password": passphrase,
                "enableRateLimit": True,
            }

        if exchange_id == "kraken":
            key = settings.kraken_api_key
            secret = settings.kraken_api_secret
            if not key or not secret:
                raise ExchangeCredentialsMissing(broker)
            return {"apiKey": key, "secret": secret, "enableRateLimit": True}

        raise ExchangeCredentialsMissing(broker)

    def _create_client(self, exchange_id: str, creds: Mapping[str, Any]) -> ccxt.Exchange:
        exchange_cls = getattr(ccxt, exchange_id)
        params = {"timeout": 10_000, **creds, "options": {"defaultType": "spot"}}
        return exchange_cls(params)


__all__ = [
    "ExchangeManager",
    "ExchangeCredentialsMissing",
    "ExchangeInitializationError",
]
