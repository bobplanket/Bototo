from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from autollm_trader.config import get_settings


@dataclass
class PositionLimits:
    max_pos_pct_nav: float
    max_sector_pct_nav: float
    max_order_notional_pct_nav: float
    max_gross_exposure_pct_nav: float
    max_leverage: float


@dataclass
class FrequencyRules:
    min_order_interval_seconds: int
    max_trades_per_day: int


@dataclass
class DrawdownRules:
    daily_loss_limit_pct: float
    max_drawdown_pct: float


@dataclass
class VolatilityRules:
    atr_window: int
    atr_stop_loss_multiple: float
    atr_take_profit_multiple: float
    max_spread_bps: int


@dataclass
class RiskConfig:
    position_limits: PositionLimits
    frequency: FrequencyRules
    drawdown: DrawdownRules
    volatility: VolatilityRules
    calendars: dict[str, Any]
    kill_switch_file: Path


def load_config(path: Path | None = None) -> RiskConfig:
    settings = get_settings()
    cfg_path = path or settings.risk.risk_config_path
    raw = yaml.safe_load(cfg_path.read_text())
    risk = raw["risk_manager"]
    return RiskConfig(
        position_limits=PositionLimits(**risk["position_limits"]),
        frequency=FrequencyRules(**risk["frequency"]),
        drawdown=DrawdownRules(**risk["drawdown"]),
        volatility=VolatilityRules(**risk["volatility"]),
        calendars=risk.get("calendars", {}),
        kill_switch_file=Path(risk.get("kill_switch", {}).get("storage_file", settings.risk.kill_switch_file)),
    )


__all__ = ["RiskConfig", "load_config"]
