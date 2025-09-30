from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, status
from fastapi.responses import PlainTextResponse

from autollm_trader.config import get_settings
from autollm_trader.logger import configure_logging, get_logger
from autollm_trader.metrics.instrumentation import setup_instrumentation
from autollm_trader.messaging.nats_client import nats_connection
from autollm_trader.models import NewsItem
from autollm_trader.utils.time import utc_now

from .analyzer import extract_tickers, fetch_content, sentiment
from .models import MinifluxWebhook

configure_logging()
logger = get_logger(__name__)
settings = get_settings()

app = FastAPI(title="News Ingestor", version="1.0.0")
setup_instrumentation(app, service_name="news-ingestor", version=app.version or "1.0.0")


async def publish(subject: str, payload: dict[str, Any]) -> None:
    client = await nats_connection.connect()
    await client.publish(subject, json.dumps(payload).encode())


def verify_signature(secret: str, provided: str) -> bool:
    digest = hmac.new(secret.encode(), b"miniflux", hashlib.sha256).hexdigest()
    return hmac.compare_digest(digest, provided)


@app.on_event("startup")
async def startup() -> None:
    await nats_connection.connect()
    logger.info("News ingestor ready")


@app.on_event("shutdown")
async def shutdown() -> None:
    await nats_connection.close()
    logger.info("News ingestor stopped")


@app.get("/health", response_class=PlainTextResponse)
async def health() -> str:
    return "ok"


@app.post("/webhook/miniflux")
async def miniflux_webhook(
    payload: dict[str, Any],
    x_miniflux_signature: str | None = Header(default=None),
) -> dict[str, str]:
    secret = getattr(settings, "MINIFLUX_WEBHOOK_SECRET", "")
    if secret and (not x_miniflux_signature or not verify_signature(secret, x_miniflux_signature)):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="invalid signature")
    webhook = MinifluxWebhook.from_payload(payload)
    if secret and webhook.secret_token != secret:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="invalid secret")
    body = webhook.entry.content or webhook.entry.summary or ""
    if webhook.entry.url:
        try:
            extracted = await fetch_content(str(webhook.entry.url))
            if extracted:
                body = extracted
        except Exception:  # noqa: BLE001
            logger.exception("Failed to fetch article", extra={"url": str(webhook.entry.url)})
    ticker_list = extract_tickers(body)
    polarity = sentiment(body)
    news_item = NewsItem(
        id=f"news:{webhook.entry.id}",
        ts=webhook.entry.published_at,
        title=webhook.entry.title,
        url=webhook.entry.url,
        summary=webhook.entry.summary or webhook.entry.title,
        body=body,
        tickers=ticker_list,
        source="miniflux",
        sentiment=polarity,
        importance=min(1.0, max(0.1, len(ticker_list) * 0.2)),
    )
    await publish("news.item.created", news_item.model_dump(mode="json"))
    return {"status": "accepted"}


def run() -> None:
    import uvicorn

    uvicorn.run("apps.news_ingestor.src.main:app", host="0.0.0.0", port=8084, reload=False)


if __name__ == "__main__":
    run()
