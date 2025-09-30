from __future__ import annotations

from fastapi import FastAPI, Header, HTTPException, status
from fastapi.responses import PlainTextResponse

from autollm_trader.config import get_settings
from autollm_trader.logger import configure_logging, get_logger
from autollm_trader.metrics.instrumentation import setup_instrumentation

from .service import service

configure_logging()
logger = get_logger(__name__)
settings = get_settings()

app = FastAPI(title="Risk Manager", version="1.0.0")
setup_instrumentation(app, service_name="risk-manager", version=app.version or "1.0.0")


def require_api_key(api_key: str) -> None:
    expected = getattr(settings, "RISK_MANAGER_API_KEY", None)
    if expected and api_key != expected:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="invalid api key")


@app.on_event("startup")
async def startup() -> None:
    await service.start()
    logger.info("Risk manager started")


@app.on_event("shutdown")
async def shutdown() -> None:
    await service.stop()
    logger.info("Risk manager stopped")


@app.get("/health", response_class=PlainTextResponse)
async def health() -> str:
    return "ok"


@app.post("/kill")
async def kill_switch(x_api_key: str = Header(...)) -> dict[str, str]:
    require_api_key(x_api_key)
    kill_file = settings.risk.kill_switch_file
    kill_file.parent.mkdir(parents=True, exist_ok=True)
    kill_file.write_text("manual kill\n")
    return {"status": "kill_switch_engaged"}


def run() -> None:
    import uvicorn

    uvicorn.run("apps.risk_manager.src.main:app", host="0.0.0.0", port=8070, reload=False)


if __name__ == "__main__":
    run()
