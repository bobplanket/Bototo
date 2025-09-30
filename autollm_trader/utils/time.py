from __future__ import annotations

import datetime as dt
from zoneinfo import ZoneInfo


def utc_now() -> dt.datetime:
    return dt.datetime.now(tz=dt.timezone.utc)


def to_timezone(ts: dt.datetime, tz: str) -> dt.datetime:
    return ts.astimezone(ZoneInfo(tz))


__all__ = ["utc_now", "to_timezone"]
