from __future__ import annotations

import asyncio
import os
import sys
from typing import Sequence

import httpx

SERVICES: Sequence[str] = (
    "http://gateway-api:8000/health",
    "http://risk-manager:8070/health",
    "http://execution-ib:8071/health",
    "http://execution-crypto:8072/health",
)


async def check(url: str) -> tuple[str, bool]:
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            resp = await client.get(url)
            return url, resp.status_code == 200
    except Exception:  # noqa: BLE001
        return url, False


async def main() -> None:
    interval = int(os.getenv("WATCHDOG_INTERVAL", "60"))
    while True:
        results = await asyncio.gather(*(check(svc) for svc in SERVICES))
        for url, ok in results:
            status = "OK" if ok else "FAIL"
            print(f"WATCHDOG {url} {status}")
        await asyncio.sleep(interval)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        sys.exit(0)
