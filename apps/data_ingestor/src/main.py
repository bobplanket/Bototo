from __future__ import annotations

from fastapi import FastAPI
from fastapi.responses import PlainTextResponse

from autollm_trader.logger import configure_logging, get_logger
from autollm_trader.metrics.instrumentation import setup_instrumentation

from .service import service

configure_logging()
logger = get_logger(__name__)

app = FastAPI(title="Data Ingestor", version="1.0.0")
setup_instrumentation(app, service_name="data-ingestor", version=app.version or "1.0.0")


@app.on_event("startup")
async def startup() -> None:
    await service.start()
    logger.info("Data ingestor running")


@app.on_event("shutdown")
async def shutdown() -> None:
    await service.stop()
    logger.info("Data ingestor stopped")


@app.get("/health", response_class=PlainTextResponse)
async def health() -> str:
    return "ok"


def run() -> None:
    import uvicorn

    uvicorn.run("apps.data_ingestor.src.main:app", host="0.0.0.0", port=8081, reload=False)


if __name__ == "__main__":
    run()
