from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from slowapi.errors import RateLimitExceeded

from autollm_trader.config import get_settings
from autollm_trader.logger import configure_logging, get_logger
from autollm_trader.messaging.nats_client import nats_connection
from autollm_trader.metrics.prom import LLM_INTENTS_COUNTER
from autollm_trader.models import TradeIntent
from autollm_trader.security.signature import signature_manager
from autollm_trader.storage.audit import AuditLogWriter
from autollm_trader.storage.postgres import LedgerStore
from autollm_trader.utils.time import utc_now

from webauthn.helpers.options import options_to_json
from webauthn.helpers.structs import AuthenticationCredential, RegistrationCredential

from .auth import AuthService
from .dependencies import get_auth_service, get_current_user, require_admin
from .models import KillSwitchRequest, ManualIntentRequest, TradeIntentResponse, WebhookNewsItem
from .middleware import AuditLogMiddleware
from .rate_limit import custom_rate_limit_handler, get_rate_limit, limiter
from .observability import (
    metrics_middleware,
    setup_observability,
    track_auth_attempt,
    track_kill_switch,
    track_manual_order,
    track_webhook,
)

logger = get_logger(__name__)

app = FastAPI(title="AutoLLM Trader Gateway", version="1.0.0")
configure_logging()

audit_log_writer = AuditLogWriter()
app.state.audit_logger = audit_log_writer

# Add rate limiter state and exception handler
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, custom_rate_limit_handler)

# Setup observability (Prometheus metrics)
setup_observability(app)

# Add custom metrics middleware
app.middleware("http")(metrics_middleware)

# Audit logging middleware (must run after metrics to capture status)
app.add_middleware(AuditLogMiddleware, writer=audit_log_writer)

settings = get_settings()
ledger_store = LedgerStore()

static_dir = Path(__file__).resolve().parent.parent / 'static'
if static_dir.exists():
    app.mount('/admin', StaticFiles(directory=static_dir, html=True), name='admin')

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)


@app.on_event("startup")
async def startup() -> None:
    app.state.audit_logger = audit_log_writer
    await audit_log_writer.connect()
    await nats_connection.connect()
    await nats_connection.ensure_stream(
        name="INTENTS",
        subjects=[
            settings.messaging.intent_subject,
            settings.messaging.approved_subject,
            "exec.order.*",
        ],
    )
    logger.info("Gateway API started")


@app.on_event("shutdown")
async def shutdown() -> None:
    await nats_connection.close()
    await audit_log_writer.close()
    logger.info("Gateway API stopped")


@app.get("/health", response_class=PlainTextResponse)
@limiter.limit(get_rate_limit("health"))
async def health(request: Request) -> str:
    return "ok"


@app.post("/api/auth/webauthn/register/options")
@limiter.limit(get_rate_limit("auth"))
async def webauthn_register_options(request: Request, body: dict[str, str], auth_service: AuthService = Depends(get_auth_service)) -> JSONResponse:
    username = body.get("username")
    display_name = body.get("display_name", body.get("username"))
    if not username:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="username missing")
    options = auth_service.registration_options(username=username, display_name=display_name)
    return JSONResponse(content=json.loads(options_to_json(options)))


@app.post("/api/auth/webauthn/register/verify")
async def webauthn_register_verify(body: dict[str, Any], auth_service: AuthService = Depends(get_auth_service)) -> dict[str, Any]:
    username = body.get("username")
    credential = RegistrationCredential.model_validate(body.get("credential"))
    stored = auth_service.verify_registration(username=username, credential=credential)
    return {"credential_id": stored.credential_id}


@app.post("/api/auth/webauthn/login/options")
async def webauthn_login_options(body: dict[str, str], auth_service: AuthService = Depends(get_auth_service)) -> JSONResponse:
    username = body.get("username")
    if not username:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="username missing")
    options = auth_service.authentication_options(username=username)
    return JSONResponse(content=json.loads(options_to_json(options)))


@app.post("/api/auth/webauthn/login/verify")
async def webauthn_login_verify(body: dict[str, Any], auth_service: AuthService = Depends(get_auth_service)) -> dict[str, str]:
    username = body.get("username")
    credential = AuthenticationCredential.model_validate(body.get("credential"))
    token = auth_service.verify_authentication(username=username, credential=credential)
    return {"access_token": token, "token_type": "bearer"}


@app.post("/api/auth/totp/enable")
async def totp_enable(body: dict[str, str], auth_service: AuthService = Depends(get_auth_service)) -> dict[str, str]:
    username = body.get("username")
    if not username:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="username missing")
    secret = auth_service.enable_totp(username)
    return {"secret": secret}


@app.post("/api/auth/totp/verify")
async def totp_verify(body: dict[str, str], auth_service: AuthService = Depends(get_auth_service)) -> dict[str, str]:
    username = body.get("username")
    code = body.get("code")
    if not username or not code:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="missing username or code")
    token = auth_service.verify_totp(username=username, code=code)
    return {"access_token": token, "token_type": "bearer"}


@app.post("/api/orders/manual", response_model=TradeIntentResponse)
@limiter.limit(get_rate_limit("trading"))
async def create_manual_intent(
    http_request: Request,
    request: ManualIntentRequest,
    user: dict[str, Any] = Depends(require_admin),
) -> TradeIntentResponse:
    ts = utc_now().isoformat()
    payload = {
        "ts": ts,
        "symbol": request.symbol,
        "side": request.side,
        "qty": request.qty,
        "timeInForce": request.time_in_force,
        "reasoning": {
            "summary": request.reasoning_summary,
            "evidence_ids": request.evidence_ids,
        },
        "risk": {
            "max_slippage_bps": request.max_slippage_bps,
            "stop_loss": request.stop_loss,
            "take_profit": request.take_profit,
        },
        "version": 1,
    }
    llm_signature = signature_manager.sign_llm(payload)
    payload["llm_signature"] = llm_signature
    intent = TradeIntent.model_validate(payload)
    async with nats_connection.publisher() as publish:
        await publish(settings.messaging.intent_subject, intent.model_dump_json().encode())
    LLM_INTENTS_COUNTER.labels(symbol=intent.symbol, side=intent.side, status="manual").inc()
    track_manual_order(symbol=request.symbol, side=request.side)
    return TradeIntentResponse(intent=intent, published=True)


@app.post("/api/risk/kill")
async def activate_kill_switch(
    request: KillSwitchRequest,
    _: dict[str, Any] = Depends(require_admin),
) -> dict[str, str]:
    kill_file = settings.risk.kill_switch_file
    kill_file.parent.mkdir(parents=True, exist_ok=True)
    kill_file.write_text(f"{utc_now().isoformat()} {request.user} {request.reason}\n")
    async with nats_connection.publisher() as publish:
        payload = {"ts": utc_now().isoformat(), "reason": request.reason, "user": request.user}
        await publish("risk.kill_switch.activated", json.dumps(payload).encode())
    track_kill_switch(user=request.user)
    return {"status": "kill_switch_engaged"}


@app.post("/api/news/webhook")
@limiter.limit(get_rate_limit("webhook"))
async def news_webhook(
    http_request: Request,
    item: WebhookNewsItem,
    _: dict[str, Any] = Depends(get_current_user),
) -> dict[str, str]:
    message = {
        "id": item.id,
        "ts": item.published_at.isoformat(),
        "title": item.title,
        "url": str(item.url),
        "summary": item.summary,
        "categories": item.categories,
        "content": item.content,
    }
    async with nats_connection.publisher() as publish:
        await publish("news.item.created", json.dumps(message).encode())
    track_webhook(webhook_type="news")
    return {"status": "accepted"}


@app.get("/api/positions")
async def get_positions(_: dict[str, Any] = Depends(get_current_user)) -> list[dict[str, Any]]:
    positions = ledger_store.fetch_positions()
    for pos in positions:
        pos["symbol"] = pos["symbol"]
    return positions


@app.exception_handler(Exception)
async def global_exception_handler(_: Request, exc: Exception) -> JSONResponse:
    logger.exception("Unhandled exception", exc_info=exc)
    return JSONResponse(status_code=500, content={"detail": "internal_error"})


def run() -> None:
    import uvicorn

    uvicorn.run("apps.gateway_api.src.main:app", host="0.0.0.0", port=8000, reload=False)


if __name__ == "__main__":
    run()
