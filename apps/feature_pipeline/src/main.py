from __future__ import annotations

import asyncio

from fastapi import FastAPI
from fastapi.responses import PlainTextResponse

from autollm_trader.logger import configure_logging, get_logger
from autollm_trader.metrics.instrumentation import setup_instrumentation

from .processor import pipeline, stream_bars

configure_logging()
logger = get_logger(__name__)

app = FastAPI(title="Feature Pipeline", version="1.0.0")
setup_instrumentation(app, service_name="feature-pipeline", version=app.version or "1.0.0")


@app.on_event("startup")
async def startup() -> None:
    asyncio.create_task(stream_bars())
    logger.info("Feature pipeline started")


@app.get("/health", response_class=PlainTextResponse)
async def health() -> str:
    return "ok"


def run() -> None:
    import uvicorn

    uvicorn.run("apps.feature_pipeline.src.main:app", host="0.0.0.0", port=8085, reload=False)


if __name__ == "__main__":
    run()
