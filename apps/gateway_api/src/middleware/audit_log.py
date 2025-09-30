"""Audit logging middleware for Gateway API."""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any, Callable

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

from autollm_trader.logger import get_logger
from autollm_trader.storage.audit import AuditLogWriter

from ..dependencies import get_auth_service

logger = get_logger(__name__)


class AuditLogMiddleware(BaseHTTPMiddleware):
    """Capture security-sensitive events for forensic analysis."""

    AUDITED_PATHS = {
        "/api/auth/login",
        "/api/auth/logout",
        "/api/auth/register",
        "/api/auth/webauthn/register/verify",
        "/api/auth/webauthn/login/verify",
        "/api/risk/kill",
        "/api/admin",
    }

    def __init__(
        self,
        app: ASGIApp,
        *,
        writer: AuditLogWriter,
        auth_service_factory: Callable[[], Any] | None = None,
    ) -> None:
        super().__init__(app)
        self._default_writer = writer
        self._auth_service_factory = auth_service_factory or get_auth_service

    async def dispatch(self, request: Request, call_next: Callable[[Request], Any]) -> Response:
        if not self._should_audit(request.url.path):
            return await call_next(request)

        start_time = datetime.now(tz=timezone.utc)
        response: Response | None = None
        try:
            response = await call_next(request)
            return response
        finally:
            duration_ms: float | None = None
            if response is not None:
                duration_ms = (datetime.now(tz=timezone.utc) - start_time).total_seconds() * 1000

            user_id = self._resolve_user(request)
            ip_address = request.client.host if request.client else None
            user_agent = request.headers.get("user-agent")
            metadata: dict[str, Any] = {
                "query": dict(request.query_params),
                "headers": {
                    "x-forwarded-for": request.headers.get("x-forwarded-for"),
                    "x-request-id": request.headers.get("x-request-id"),
                },
            }

            event = {
                "timestamp": start_time,
                "user_id": user_id,
                "ip_address": ip_address,
                "method": request.method,
                "path": request.url.path,
                "status_code": response.status_code if response else 500,
                "duration_ms": duration_ms,
                "user_agent": user_agent,
                "metadata": metadata,
            }

            writer = getattr(request.app.state, "audit_logger", self._default_writer)
            asyncio.create_task(self._persist_event(writer, event))

    def _should_audit(self, path: str) -> bool:
        for pattern in self.AUDITED_PATHS:
            if pattern.endswith("*") and path.startswith(pattern[:-1]):
                return True
            if path == pattern:
                return True
        return False

    def _resolve_user(self, request: Request) -> str | None:
        authorization = request.headers.get("authorization")
        if not authorization:
            return None
        scheme, _, token = authorization.partition(" ")
        if scheme.lower() != "bearer" or not token:
            return None
        try:
            auth_service = self._auth_service_factory()
            payload = auth_service.tokens.decode(token)
            return payload.get("sub") or payload.get("username")
        except Exception:  # noqa: BLE001 - audit logging must never break requests
            logger.debug("Failed to decode token for audit log", exc_info=True)
            return None

    async def _persist_event(self, writer: AuditLogWriter, event: dict[str, Any]) -> None:
        try:
            await writer.write_event(event)
        except Exception as exc:  # noqa: BLE001
            logger.error("Failed to write audit log event", exc_info=exc, extra={"path": event.get("path")})
