"""Market calendar service using pandas-market-calendars."""
from __future__ import annotations

from datetime import datetime, time
from typing import List, Optional

import pandas as pd
import pandas_market_calendars as mcal
from zoneinfo import ZoneInfo

from autollm_trader.logger import get_logger

logger = get_logger(__name__)


class MarketCalendarService:
    """Service to check market hours and trading days."""

    def __init__(self):
        """Initialize market calendar service with common exchanges."""
        self.calendars = {}

        # Load common exchange calendars
        self._load_calendar("NYSE")
        self._load_calendar("NASDAQ")
        self._load_calendar("CME")  # Chicago Mercantile Exchange (futures)
        self._load_calendar("XHKG")  # Hong Kong
        self._load_calendar("XLON")  # London
        self._load_calendar("XTKS")  # Tokyo

        logger.info(f"Initialized market calendars for {len(self.calendars)} exchanges")

    def _load_calendar(self, exchange: str) -> None:
        """Load calendar for exchange."""
        try:
            calendar = mcal.get_calendar(exchange)
            self.calendars[exchange] = calendar
            logger.debug(f"Loaded calendar for {exchange}")
        except Exception as e:
            logger.warning(f"Failed to load calendar for {exchange}: {e}")

    def is_market_open(self, exchange: str, check_time: Optional[datetime] = None) -> bool:
        """
        Check if market is currently open.

        Args:
            exchange: Exchange code (NYSE, NASDAQ, etc.)
            check_time: Time to check (default: now)

        Returns:
            True if market is open
        """
        if exchange not in self.calendars:
            logger.warning(f"Calendar not found for {exchange}, assuming open")
            return True

        if check_time is None:
            check_time = datetime.now(ZoneInfo("UTC"))

        calendar = self.calendars[exchange]

        # Get market schedule for the day
        schedule = calendar.schedule(
            start_date=check_time.date(),
            end_date=check_time.date(),
        )

        if schedule.empty:
            # No trading session today
            return False

        # Check if current time is within market hours
        market_open = schedule.iloc[0]["market_open"].to_pydatetime()
        market_close = schedule.iloc[0]["market_close"].to_pydatetime()

        # Make check_time timezone-aware if needed
        if check_time.tzinfo is None:
            check_time = check_time.replace(tzinfo=ZoneInfo("UTC"))

        return market_open <= check_time <= market_close

    def next_market_open(self, exchange: str, from_time: Optional[datetime] = None) -> datetime:
        """
        Get next market open time.

        Args:
            exchange: Exchange code
            from_time: Start time to check from (default: now)

        Returns:
            Next market open datetime
        """
        if exchange not in self.calendars:
            raise ValueError(f"Calendar not found for {exchange}")

        if from_time is None:
            from_time = datetime.now(ZoneInfo("UTC"))

        calendar = self.calendars[exchange]

        # Get schedule for next 30 days
        end_date = from_time + pd.Timedelta(days=30)
        schedule = calendar.schedule(
            start_date=from_time.date(),
            end_date=end_date.date(),
        )

        if schedule.empty:
            raise ValueError(f"No trading sessions found for {exchange}")

        # Find next open time after from_time
        for _, row in schedule.iterrows():
            market_open = row["market_open"].to_pydatetime()
            if market_open > from_time:
                return market_open

        raise ValueError(f"No market open time found for {exchange}")

    def next_market_close(self, exchange: str, from_time: Optional[datetime] = None) -> datetime:
        """
        Get next market close time.

        Args:
            exchange: Exchange code
            from_time: Start time to check from (default: now)

        Returns:
            Next market close datetime
        """
        if exchange not in self.calendars:
            raise ValueError(f"Calendar not found for {exchange}")

        if from_time is None:
            from_time = datetime.now(ZoneInfo("UTC"))

        calendar = self.calendars[exchange]

        # Get schedule for next 30 days
        end_date = from_time + pd.Timedelta(days=30)
        schedule = calendar.schedule(
            start_date=from_time.date(),
            end_date=end_date.date(),
        )

        if schedule.empty:
            raise ValueError(f"No trading sessions found for {exchange}")

        # Find next close time after from_time
        for _, row in schedule.iterrows():
            market_close = row["market_close"].to_pydatetime()
            if market_close > from_time:
                return market_close

        raise ValueError(f"No market close time found for {exchange}")

    def get_trading_days(
        self,
        exchange: str,
        start_date: datetime,
        end_date: datetime,
    ) -> List[datetime]:
        """
        Get list of trading days in date range.

        Args:
            exchange: Exchange code
            start_date: Start date
            end_date: End date

        Returns:
            List of trading day datetimes
        """
        if exchange not in self.calendars:
            raise ValueError(f"Calendar not found for {exchange}")

        calendar = self.calendars[exchange]

        schedule = calendar.schedule(
            start_date=start_date.date(),
            end_date=end_date.date(),
        )

        trading_days = [row["market_open"].to_pydatetime() for _, row in schedule.iterrows()]

        return trading_days

    def is_trading_day(self, exchange: str, check_date: datetime) -> bool:
        """
        Check if date is a trading day.

        Args:
            exchange: Exchange code
            check_date: Date to check

        Returns:
            True if trading day
        """
        if exchange not in self.calendars:
            logger.warning(f"Calendar not found for {exchange}")
            return True

        calendar = self.calendars[exchange]

        schedule = calendar.schedule(
            start_date=check_date.date(),
            end_date=check_date.date(),
        )

        return not schedule.empty

    def time_until_open(self, exchange: str) -> Optional[pd.Timedelta]:
        """
        Get time until next market open.

        Args:
            exchange: Exchange code

        Returns:
            Timedelta until open, or None if market is open
        """
        now = datetime.now(ZoneInfo("UTC"))

        if self.is_market_open(exchange, now):
            return None

        next_open = self.next_market_open(exchange, now)
        return pd.Timedelta(next_open - now)

    def time_until_close(self, exchange: str) -> Optional[pd.Timedelta]:
        """
        Get time until next market close.

        Args:
            exchange: Exchange code

        Returns:
            Timedelta until close, or None if market is closed
        """
        now = datetime.now(ZoneInfo("UTC"))

        if not self.is_market_open(exchange, now):
            return None

        next_close = self.next_market_close(exchange, now)
        return pd.Timedelta(next_close - now)


# Global singleton instance
_market_calendar_service: Optional[MarketCalendarService] = None


def get_market_calendar_service() -> MarketCalendarService:
    """Get or create market calendar service singleton."""
    global _market_calendar_service
    if _market_calendar_service is None:
        _market_calendar_service = MarketCalendarService()
    return _market_calendar_service