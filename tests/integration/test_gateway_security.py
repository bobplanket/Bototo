from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient

from apps.gateway_api.src import main
from apps.gateway_api.src.auth import AuthService, FileAuthRepository
from apps.gateway_api.src.rate_limit import limiter
from autollm_trader.config import get_settings


class StubAuditLogger:
    def __init__(self) -> None:
        self.events: list[dict[str, object]] = []

    async def connect(self) -> None:  # pragma: no cover - no-op for tests
        return None

    async def close(self) -> None:  # pragma: no cover - no-op for tests
        return None

    async def write_event(self, event: dict[str, object]) -> None:
        self.events.append(event)


@pytest.mark.asyncio
async def test_rate_limit_exceeded() -> None:
    app = main.app
    limiter.reset()

    if not any(route.path == "/__rate_test" for route in app.router.routes):
        async def handler(request):  # type: ignore[no-untyped-def]
            return {"status": "ok"}

        app.router.add_api_route(
            "/__rate_test",
            limiter.limit("2/minute")(handler),
            methods=["GET"],
        )

    transport = ASGITransport(app=app, lifespan=None)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        ok1 = await client.get("/__rate_test")
        ok2 = await client.get("/__rate_test")
        blocked = await client.get("/__rate_test")

    assert ok1.status_code == 200
    assert ok2.status_code == 200
    assert blocked.status_code == 429
    assert blocked.json()["detail"].lower().startswith("rate limit")


@pytest.mark.asyncio
async def test_audit_log_created(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    app = main.app
    limiter.reset()

    audit_stub = StubAuditLogger()
    original_logger = app.state.audit_logger
    app.state.audit_logger = audit_stub

    repo = FileAuthRepository(path=tmp_path / "users.json")
    auth_service = AuthService(repository=repo)
    monkeypatch.setattr("apps.gateway_api.src.dependencies._auth_service", auth_service, raising=False)

    async def fake_connect():
        return None

    async def fake_close():
        return None

    @asynccontextmanager
    async def fake_publisher():
        async def _publish(subject: str, data: bytes) -> None:
            return None

        yield _publish

    monkeypatch.setattr(main.nats_connection, "connect", fake_connect)
    monkeypatch.setattr(main.nats_connection, "close", fake_close)
    monkeypatch.setattr(main.nats_connection, "publisher", fake_publisher)

    settings = get_settings()
    original_kill = settings.risk.kill_switch_file
    settings.risk.kill_switch_file = tmp_path / "kill.flag"

    token = auth_service.tokens.create("admin", ["admin"])
    headers = {"Authorization": f"Bearer {token}"}
    payload = {"user": "admin", "reason": "test"}

    transport = ASGITransport(app=app, lifespan=None)
    try:
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.post("/api/risk/kill", json=payload, headers=headers)
            await asyncio.sleep(0)

        assert response.status_code == 200
        assert audit_stub.events, "expected audit event to be recorded"
        event = audit_stub.events[-1]
        assert event["path"] == "/api/risk/kill"
        assert event["user_id"] == "admin"
        assert event["status_code"] == 200
    finally:
        app.state.audit_logger = original_logger
        settings.risk.kill_switch_file = original_kill
