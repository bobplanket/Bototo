from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from typing import AsyncIterator, Awaitable, Callable

from nats.aio.client import Client
from nats.aio.msg import Msg
from nats.js.api import StreamConfig

from autollm_trader.config import get_settings
from autollm_trader.logger import get_logger

logger = get_logger(__name__)


class NatsConnection:
    def __init__(self, url: str | None = None) -> None:
        settings = get_settings()
        self._url = url or settings.messaging.nats_url
        self._client: Client | None = None
        self._lock = asyncio.Lock()

    async def connect(self) -> Client:
        async with self._lock:
            if self._client is None or self._client.is_closed:
                logger.info("Connecting to NATS", extra={"url": self._url})
                client = Client()
                await client.connect(self._url, reconnect=True, max_reconnect_attempts=-1)
                self._client = client
        assert self._client is not None
        return self._client

    async def close(self) -> None:
        async with self._lock:
            if self._client and not self._client.is_closed:
                await self._client.drain()
                await self._client.close()
                logger.info("Closed NATS connection")

    @asynccontextmanager
    async def publisher(self) -> AsyncIterator[Callable[[str, bytes], Awaitable[None]]]:
        client = await self.connect()

        async def _publish(subject: str, data: bytes) -> None:
            logger.debug("Publishing to NATS", extra={"subject": subject})
            await client.publish(subject, data)

        try:
            yield _publish
        finally:
            if get_settings().environment == "test":
                await self.close()

    async def subscribe(self, subject: str, queue: str | None = None, cb: Callable[[Msg], Awaitable[None]] | None = None) -> tuple[Client, asyncio.Future[None]]:
        client = await self.connect()
        logger.info("Subscribing to subject", extra={"subject": subject, "queue": queue})
        future = await client.subscribe(subject, queue=queue, cb=cb)
        return client, future

    async def ensure_stream(self, name: str, subjects: list[str]) -> None:
        client = await self.connect()
        js = client.jetstream()
        try:
            await js.add_stream(StreamConfig(name=name, subjects=subjects))
            logger.info("Created NATS stream", extra={"name": name})
        except Exception as exc:  # noqa: BLE001
            if "stream name already in use" in str(exc).lower():
                logger.debug("Stream already exists", extra={"name": name})
            else:
                raise


nats_connection = NatsConnection()

__all__ = ["NatsConnection", "nats_connection"]
