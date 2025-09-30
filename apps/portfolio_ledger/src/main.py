from __future__ import annotations

from fastapi import FastAPI
from fastapi.responses import PlainTextResponse

from autollm_trader.logger import configure_logging, get_logger
from autollm_trader.metrics.instrumentation import setup_instrumentation
from autollm_trader.storage.postgres import LedgerStore

from .service import service

configure_logging()
logger = get_logger(__name__)

app = FastAPI(title="Portfolio Ledger", version="1.0.0")
setup_instrumentation(app, service_name="portfolio-ledger", version=app.version or "1.0.0")
store = LedgerStore()


@app.on_event("startup")
async def startup() -> None:
    await service.start()
    logger.info("Portfolio ledger started")


@app.on_event("shutdown")
async def shutdown() -> None:
    await service.stop()
    logger.info("Portfolio ledger stopped")


@app.get("/health", response_class=PlainTextResponse)
async def health() -> str:
    return "ok"


@app.get("/positions")
async def positions() -> list[dict[str, object]]:
    return store.fetch_positions()


def run() -> None:
    import uvicorn

    uvicorn.run("apps.portfolio_ledger.src.main:app", host="0.0.0.0", port=8073, reload=False)


if __name__ == "__main__":
    run()
