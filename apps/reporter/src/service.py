from __future__ import annotations

import asyncio
import json
from email.message import EmailMessage
from typing import Sequence

import aiosmtplib

from autollm_trader.config import get_settings
from autollm_trader.logger import get_logger
from autollm_trader.storage.postgres import LedgerStore

logger = get_logger(__name__)
settings = get_settings()


class ReporterService:
    def __init__(self) -> None:
        self.store = LedgerStore()
        self._task: asyncio.Task[None] | None = None

    async def start(self) -> None:
        if self._task is None:
            self._task = asyncio.create_task(self._run())
            logger.info("Reporter started")

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None
            logger.info("Reporter stopped")

    async def _run(self) -> None:
        while True:
            await self.send_report()
            await asyncio.sleep(24 * 60 * 60)

    async def send_report(self) -> None:
        positions = self.store.fetch_positions()
        body = json.dumps(positions, indent=2)
        await self._send_email(body)
        logger.info("Report dispatched", extra={"positions": len(positions)})

    async def _send_email(self, body: str) -> None:
        recipients = settings.reporter.report_recipients
        if not recipients:
            logger.warning("No report recipients configured")
            return
        message = EmailMessage()
        message["From"] = settings.reporter.smtp_username
        message["To"] = ", ".join(recipients)
        message["Subject"] = "AutoLLM Daily Report"
        message.set_content(body)
        try:
            await aiosmtplib.send(
                message,
                hostname=settings.reporter.smtp_host,
                port=settings.reporter.smtp_port,
                username=settings.reporter.smtp_username,
                password=settings.reporter.smtp_password,
                start_tls=True,
            )
        except Exception as exc:  # noqa: BLE001
            logger.exception("Failed to send email", exc_info=exc)


service = ReporterService()


async def run_service() -> None:
    await service.start()
    while True:
        await asyncio.sleep(60)


__all__ = ["service", "run_service", "ReporterService"]
