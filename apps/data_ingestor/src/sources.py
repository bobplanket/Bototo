from __future__ import annotations

import asyncio
import random
from typing import Awaitable, Callable

import os

import httpx
import yfinance

from autollm_trader.logger import get_logger
from autollm_trader.messaging.nats_client import nats_connection
from autollm_trader.models import MarketBar, MarketTick
from autollm_trader.utils.time import utc_now

logger = get_logger(__name__)

Publisher = Callable[[str, bytes], Awaitable[None]]


class BaseMarketSource:
    def __init__(self, symbols: list[str], venue: str, publish: Publisher, interval: float = 1.0) -> None:
        self.symbols = symbols
        self.venue = venue
        self.publish = publish
        self.interval = interval
        self._running = False

    async def start(self) -> None:
        self._running = True
        while self._running:
            await self.tick()
            await asyncio.sleep(self.interval)

    async def stop(self) -> None:
        self._running = False

    async def tick(self) -> None:
        raise NotImplementedError


class SyntheticSource(BaseMarketSource):
    async def tick(self) -> None:
        for symbol in self.symbols:
            base_price = 100 + hash(symbol) % 20
            delta = random.uniform(-1, 1)
            price = max(1.0, base_price + delta)
            bid = price - 0.05
            ask = price + 0.05
            tick = MarketTick(
                ts=utc_now(),
                venue=self.venue,
                symbol=symbol,
                bid=bid,
                ask=ask,
                last=price,
                volume=random.uniform(1_000, 10_000),
            )
            await self.publish(
                f"market.ticks.{self.venue}.{symbol.replace('/', '_')}",
                tick.model_dump_json().encode(),
            )


class FinnhubSource(BaseMarketSource):
    def __init__(self, symbols: list[str], publish: Publisher, token: str | None) -> None:
        super().__init__(symbols, venue="FINNHUB", publish=publish, interval=5.0)
        self.token = token

    async def tick(self) -> None:
        if not self.token:
            logger.warning("FINNHUB token missing, falling back to synthetic source")
            synthetic = SyntheticSource(self.symbols, self.venue, self.publish)
            await synthetic.tick()
            return
        async with httpx.AsyncClient(timeout=5) as client:
            for symbol in self.symbols:
                params = {"symbol": symbol, "token": self.token}
                resp = await client.get("https://finnhub.io/api/v1/quote", params=params)
                data = resp.json()
                tick = MarketTick(
                    ts=utc_now(),
                    venue=self.venue,
                    symbol=symbol,
                    bid=float(data.get("b", data.get("c", 0)) or 0),
                    ask=float(data.get("a", data.get("c", 0)) or 0),
                    last=float(data.get("c", 0)),
                    volume=float(data.get("v", 0)),
                )
                await self.publish(
                    f"market.ticks.{self.venue}.{symbol}",
                    tick.model_dump_json().encode(),
                )


class YFinanceSource(BaseMarketSource):
    def __init__(self, symbols: list[str], publish: Publisher, interval: str = "1m") -> None:
        super().__init__(symbols, venue="YFINANCE", publish=publish, interval=60.0)
        self.interval_str = interval

    async def tick(self) -> None:
        loop = asyncio.get_event_loop()
        for symbol in self.symbols:
            data = await loop.run_in_executor(None, lambda: yfinance.Ticker(symbol).history(period="1d", interval=self.interval_str).tail(1))
            if data.empty:
                continue
            row = data.iloc[-1]
            bar = MarketBar(
                ts=utc_now(),
                venue=self.venue,
                symbol=symbol,
                timeframe=self.interval_str,
                open=float(row["Open"]),
                high=float(row["High"]),
                low=float(row["Low"]),
                close=float(row["Close"]),
                volume=float(row["Volume"]),
            )
            await self.publish(
                f"market.bars.{self.interval_str}.{symbol}",
                bar.model_dump_json().encode(),
            )


class CcxtSource(BaseMarketSource):
    def __init__(self, exchange_id: str, symbols: list[str], publish: Publisher, interval: float = 5.0) -> None:
        super().__init__(symbols, venue=exchange_id.upper(), publish=publish, interval=interval)
        import ccxt  # pylint: disable=import-outside-toplevel

        self.exchange = getattr(ccxt, exchange_id)({"enableRateLimit": True})

    async def tick(self) -> None:
        loop = asyncio.get_event_loop()
        for symbol in self.symbols:
            ticker = await loop.run_in_executor(None, lambda: self.exchange.fetch_ticker(symbol))
            tick = MarketTick(
                ts=utc_now(),
                venue=self.venue,
                symbol=symbol,
                bid=float(ticker.get("bid", 0)),
                ask=float(ticker.get("ask", 0)),
                last=float(ticker.get("last", 0)),
                volume=float(ticker.get("quoteVolume", 0)),
            )
            await self.publish(
                f"market.ticks.{self.venue}.{symbol.replace('/', '_')}",
                tick.model_dump_json().encode(),
            )


async def create_sources(publish: Publisher) -> list[BaseMarketSource]:
    from .config import FeedConfig  # local import to avoid cycle

    config = FeedConfig.load()
    sources: list[BaseMarketSource] = []
    equities = config.equities
    finnhub_cfg = equities.get("finnhub", {})
    if finnhub_cfg.get("enabled", True):
        sources.append(
            FinnhubSource(
                symbols=finnhub_cfg.get("symbols", []),
                publish=publish,
                token=os.getenv("FINNHUB_API_KEY"),
            )
        )
    yfinance_cfg = equities.get("yfinance", {})
    if yfinance_cfg.get("enabled", True):
        sources.append(
            YFinanceSource(
                symbols=yfinance_cfg.get("symbols", []),
                publish=publish,
                interval=yfinance_cfg.get("interval", "1m"),
            )
        )
    crypto = config.crypto.get("ccxt", {})
    if crypto.get("enabled", True):
        sources.append(
            CcxtSource(
                exchange_id=crypto.get("exchange", "binance"),
                symbols=crypto.get("symbols", []),
                publish=publish,
            )
        )
    if not sources:
        sources.append(SyntheticSource(symbols=["AAPL"], venue="SYNTH", publish=publish))
    return sources


__all__ = [
    "BaseMarketSource",
    "SyntheticSource",
    "FinnhubSource",
    "YFinanceSource",
    "CcxtSource",
    "create_sources",
]
