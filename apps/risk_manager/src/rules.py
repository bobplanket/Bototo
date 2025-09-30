from __future__ import annotations

import datetime as dt
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Tuple

import yaml

from autollm_trader.config import get_settings
from autollm_trader.logger import get_logger
from autollm_trader.models import ApprovedOrder, RiskEvaluation, TradeIntent
from autollm_trader.risk.market_calendar import MarketCalendar
from autollm_trader.security.signature import signature_manager
from autollm_trader.utils.time import utc_now

from .config import RiskConfig, load_config
from .state import PortfolioState

logger = get_logger(__name__)


@dataclass
class SymbolInfo:
    symbol: str
    sector: str
    venue: str
    currency: str
    tick_size: float


class RiskEvaluator:
    def __init__(self, config: RiskConfig | None = None, calendar: MarketCalendar | None = None) -> None:
        self.config = config or load_config()
        self.state = PortfolioState(nav=get_settings().risk.nav_initial_usd)
        self.symbols = self._load_symbols()
        self.last_prices: Dict[str, float] = {}
        self.last_spreads: Dict[str, float] = {}
        self.calendar = calendar or MarketCalendar()

    def _load_symbols(self) -> Dict[str, SymbolInfo]:
        cfg_path = get_settings().risk.symbols_config_path
        data = yaml.safe_load(cfg_path.read_text())
        mapping: Dict[str, SymbolInfo] = {}
        for item in data.get("symbols", []):
            mapping[item["symbol"]] = SymbolInfo(
                symbol=item["symbol"],
                sector=item.get("sector", "Unknown"),
                venue=item.get("venue", "Unknown"),
                currency=item.get("currency", "USD"),
                tick_size=float(item.get("tick_size", 0.01)),
            )
        return mapping

    def update_market(self, symbol: str, bid: float, ask: float) -> None:
        mid = (bid + ask) / 2
        self.last_prices[symbol] = mid
        self.last_spreads[symbol] = max(0.0, (ask - bid) / mid * 10_000 if mid else 0.0)

    def evaluate(self, intent: TradeIntent) -> Tuple[RiskEvaluation, ApprovedOrder | None]:
        logger.info("Evaluating intent", extra={"symbol": intent.symbol, "qty": intent.qty})
        reasons: list[str] = []
        tags: list[str] = []
        canonical_payload = intent.model_dump(exclude={"llm_signature"}, mode="json")
        if not signature_manager.verify_llm(canonical_payload, intent.llm_signature):
            reasons.append("invalid_signature")
            return RiskEvaluation(intent=intent, approved=False, reasons=reasons, tags=tags), None
        kill_file = Path(self.config.kill_switch_file)
        if kill_file.exists():
            reasons.append("kill_switch_active")
            return RiskEvaluation(intent=intent, approved=False, reasons=reasons, tags=tags), None
        symbol_info = self.symbols.get(intent.symbol)
        if not symbol_info:
            reasons.append("unknown_symbol")
            return RiskEvaluation(intent=intent, approved=False, reasons=reasons, tags=tags), None
        market = self.calendar.resolve_market(symbol_info.venue)
        if market and not self.calendar.is_market_open(market):
            reasons.append("market_closed")
            return RiskEvaluation(intent=intent, approved=False, reasons=reasons, tags=tags), None
        price = self.last_prices.get(intent.symbol, 0.0) or 100.0
        notional = price * intent.qty
        nav = self.state.nav
        max_order = nav * self.config.position_limits.max_order_notional_pct_nav
        if notional > max_order:
            reasons.append("order_notional_limit")
        gross_after = self.state.gross_exposure + abs(notional)
        if gross_after > nav * self.config.position_limits.max_gross_exposure_pct_nav:
            reasons.append("gross_exposure_limit")
        position = self.state.positions.get(intent.symbol)
        current_qty = position.qty if position else 0.0
        target_qty = current_qty + intent.qty if intent.side == "BUY" else current_qty - intent.qty
        pos_notional = abs(target_qty * price)
        if pos_notional > nav * self.config.position_limits.max_pos_pct_nav:
            reasons.append("position_limit")
        spread = self.last_spreads.get(intent.symbol, 0.0)
        if spread > self.config.volatility.max_spread_bps:
            reasons.append("wide_spread")
        if self.state.last_order_ts:
            delta = (utc_now() - self.state.last_order_ts).total_seconds()
            if delta < self.config.frequency.min_order_interval_seconds:
                reasons.append("min_order_interval")
        now = utc_now()
        if self.state.last_order_ts and self.state.last_order_ts.date() != now.date():
            self.state.reset_day()
        if self.state.trades_today >= self.config.frequency.max_trades_per_day:
            reasons.append("max_trades_day")
        if self.state.max_drawdown > self.config.drawdown.max_drawdown_pct:
            reasons.append("max_drawdown")
        if reasons:
            evaluation = RiskEvaluation(intent=intent, approved=False, reasons=reasons, tags=tags)
            return evaluation, None
        tags.extend(["pos_limit_ok", "daily_dd_ok"])
        signed_payload = {
            "ts": now.isoformat(),
            "broker": "IBKR" if symbol_info.venue != "BINANCE" else "BINANCE",
            "route": "SMART",
            "symbol": intent.symbol,
            "side": intent.side,
            "qty": intent.qty,
            "type": "MKT",
            "limit_price": None,
            "risk_tags": tags,
            "version": 1,
        }
        signature = signature_manager.sign_risk(signed_payload)
        order = ApprovedOrder(
            **signed_payload,
            risk_signature=signature,
            correlated_intent=intent,
        )
        evaluation = RiskEvaluation(intent=intent, approved=True, tags=tags, adjusted_qty=order.qty)
        return evaluation, order


__all__ = ["RiskEvaluator", "SymbolInfo"]
