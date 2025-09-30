from __future__ import annotations

from fastapi import FastAPI
from fastapi.responses import PlainTextResponse

from autollm_trader.logger import configure_logging, get_logger
from autollm_trader.metrics.instrumentation import setup_instrumentation

from .service import service

configure_logging()
logger = get_logger(__name__)

app = FastAPI(title="Reporter", version="1.0.0")
setup_instrumentation(app, service_name="reporter", version=app.version or "1.0.0")


@app.on_event("startup")
async def startup() -> None:
    await service.start()
    logger.info("Reporter started")


@app.on_event("shutdown")
async def shutdown() -> None:
    await service.stop()
    logger.info("Reporter stopped")


@app.get("/health", response_class=PlainTextResponse)
async def health() -> str:
    return "ok"


@app.post("/alert")
async def alert(payload: dict[str, object]) -> dict[str, str]:
    logger.warning("Received alert", extra={"payload": payload})
    return {"status": "received"}


def run() -> None:
    import uvicorn

    uvicorn.run("apps.reporter.src.main:app", host="0.0.0.0", port=8074, reload=False)


if __name__ == "__main__":
    run()
