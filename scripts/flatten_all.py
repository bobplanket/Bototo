from __future__ import annotations

import asyncio
import json

from autollm_trader.messaging.nats_client import nats_connection
from autollm_trader.utils.time import utc_now


async def main_async() -> None:
    client = await nats_connection.connect()
    payload = {"ts": utc_now().isoformat(), "action": "flatten"}
    await client.publish("risk.kill_switch.activated", json.dumps(payload).encode())
    await nats_connection.close()


def main() -> None:
    asyncio.run(main_async())


if __name__ == "__main__":
    main()
