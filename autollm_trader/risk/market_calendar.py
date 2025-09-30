"""Market calendar utilities for trading eligibility checks."""
from __future__ import annotations

from datetime import datetime, time, timezone
from functools import lru_cache
from typing import Literal

import pandas_market_calendars as mcal

from autollm_trader.logger import get_logger

logger = get_logger(__name__)

MarketType = Literal["NYSE", "NASDAQ", "CME", "CBOE", "FOREX"]


@lru_cache(maxsize=16)
def _load_calendar(market: MarketType) -> mcal.MarketCalendar:
    if market == "CME":
        return mcal.get_calendar("CME_Equity")
    if market == "CBOE":
        return mcal.get_calendar("CBOE_Index_Options")
    return mcal.get_calendar(market)


class MarketCalendar:
    """Helper to check whether a venue is currently open."""

    _venue_map: dict[str, MarketType] = {
        "NYSE": "NYSE",
        "NASDAQ": "NASDAQ",
        "ARCA": "NYSE",
        "CME": "CME",
        "CBOE": "CBOE",
        "FOREX": "FOREX",
    }

    def resolve_market(self, venue: str | None) -> MarketType | None:
        if not venue:
            return None
        return self._venue_map.get(venue.upper())

    def is_market_open(
        self,
        market: MarketType,
        *,
        dt: datetime | None = None,
        allow_extended_hours: bool = False,
    ) -> bool:
        moment = dt.astimezone(timezone.utc) if dt else datetime.now(tz=timezone.utc)

        if market == "FOREX":
            return self._is_forex_open(moment)

        calendar = _load_calendar(market)
        schedule = calendar.schedule(start_date=moment.date(), end_date=moment.date())
        if schedule.empty:
            logger.debug("Market closed - non trading day", extra={"market": market, "date": moment.date()})
            return False

        open_time = schedule.iloc[0]["market_open"].to_pydatetime().astimezone(timezone.utc)
        close_time = schedule.iloc[0]["market_close"].to_pydatetime().astimezone(timezone.utc)

        if allow_extended_hours:
            extended_open = open_time.replace(hour=4, minute=0)
            extended_close = close_time.replace(hour=20, minute=0)
            return extended_open <= moment <= extended_close

        return open_time <= moment <= close_time

    def _is_forex_open(self, moment: datetime) -> bool:
        weekday = moment.weekday()
        if weekday == 5:  # Saturday
            return False
        if weekday == 6:  # Sunday
            return moment.time() >= time(hour=21, minute=0)
        if weekday == 4:  # Friday
            return moment.time() <= time(hour=21, minute=0)
        return True


__all__ = ["MarketCalendar", "MarketType"]
