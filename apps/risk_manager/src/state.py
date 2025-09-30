from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, field
from typing import DefaultDict, Dict

from autollm_trader.utils.time import utc_now


@dataclass
class Position:
    symbol: str
    sector: str
    qty: float
    avg_price: float


@dataclass
class PortfolioState:
    nav: float
    positions: Dict[str, Position] = field(default_factory=dict)
    sector_exposure: DefaultDict[str, float] = field(default_factory=lambda: DefaultDict(float))
    gross_exposure: float = 0.0
    last_order_ts: dt.datetime | None = None
    trades_today: int = 0
    day_start_nav: float | None = None
    max_drawdown: float = 0.0

    def reset_day(self) -> None:
        self.trades_today = 0
        self.day_start_nav = self.nav

    def update_nav(self, delta: float) -> None:
        self.nav += delta
        if self.day_start_nav is None:
            self.day_start_nav = self.nav
        drawdown = (self.day_start_nav - self.nav) / self.day_start_nav if self.day_start_nav else 0.0
        self.max_drawdown = max(self.max_drawdown, drawdown)

    def record_trade(self, symbol: str, qty: float, price: float, sector: str) -> None:
        position = self.positions.get(symbol)
        notional = qty * price
        self.gross_exposure += abs(notional)
        if position:
            total_qty = position.qty + qty
            if total_qty == 0:
                del self.positions[symbol]
                self.sector_exposure[sector] -= position.qty * position.avg_price
            else:
                new_notional = position.qty * position.avg_price + notional
                position.qty = total_qty
                position.avg_price = new_notional / total_qty
                self.positions[symbol] = position
                self.sector_exposure[sector] += notional
        else:
            self.positions[symbol] = Position(symbol=symbol, sector=sector, qty=qty, avg_price=price)
            self.sector_exposure[sector] += notional
        self.last_order_ts = utc_now()
        self.trades_today += 1


__all__ = ["PortfolioState", "Position"]
