from __future__ import annotations

import asyncio
from typing import Awaitable, Callable

from autollm_trader.logger import get_logger
from autollm_trader.messaging.nats_client import nats_connection

from .sources import BaseMarketSource, create_sources

logger = get_logger(__name__)

Publisher = Callable[[str, bytes], Awaitable[None]]


async def _publish(subject: str, data: bytes) -> None:
    client = await nats_connection.connect()
    await client.publish(subject, data)


class DataIngestorService:
    def __init__(self) -> None:
        self.sources: list[BaseMarketSource] = []
        self.tasks: list[asyncio.Task[None]] = []
        self._lock = asyncio.Lock()

    async def start(self) -> None:
        async with self._lock:
            if self.tasks:
                return
            logger.info("Starting data sources")
            self.sources = await create_sources(_publish)
            for source in self.sources:
                task = asyncio.create_task(source.start())
                self.tasks.append(task)

    async def stop(self) -> None:
        async with self._lock:
            logger.info("Stopping data sources")
            for source in self.sources:
                await source.stop()
            for task in self.tasks:
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
            self.tasks.clear()


service = DataIngestorService()

__all__ = ["DataIngestorService", "service"]
