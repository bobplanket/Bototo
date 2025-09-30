from __future__ import annotations

import datetime as dt
from typing import Literal, Sequence

from pydantic import BaseModel, Field, HttpUrl, computed_field

Side = Literal["BUY", "SELL"]
TimeInForce = Literal["DAY", "GTC"]
OrderType = Literal["MKT", "LMT"]


class IntentReasoning(BaseModel):
    summary: str
    evidence_ids: list[str] = Field(default_factory=list)


class RiskParameters(BaseModel):
    max_slippage_bps: int = Field(ge=0, le=10_000)
    stop_loss: float | None = Field(default=None, gt=0)
    take_profit: float | None = Field(default=None, gt=0)


class TradeIntent(BaseModel):
    ts: dt.datetime = Field(default_factory=lambda: dt.datetime.now(tz=dt.timezone.utc))
    symbol: str
    venue: str | None = None
    side: Side
    qty: float = Field(gt=0)
    timeInForce: TimeInForce = Field(alias="timeInForce")
    reasoning: IntentReasoning
    risk: RiskParameters
    llm_signature: str
    version: int = Field(default=1, ge=1)

    model_config = {
        "populate_by_name": True,
        "json_schema_extra": {
            "example": {
                "ts": "2024-04-01T12:00:00Z",
                "symbol": "AAPL",
                "side": "BUY",
                "qty": 100,
                "timeInForce": "DAY",
                "reasoning": {"summary": "Momentum breakout", "evidence_ids": ["news:123"]},
                "risk": {"max_slippage_bps": 15, "stop_loss": 0.98, "take_profit": 1.02},
                "llm_signature": "base64sig",
                "version": 1,
            }
        },
    }


class RiskTag(BaseModel):
    tag: str
    details: str | None = None


class ApprovedOrder(BaseModel):
    ts: dt.datetime
    broker: Literal["IBKR", "BINANCE", "COINBASE", "KRAKEN", "PAPER"]
    route: str = Field(default="SMART")
    symbol: str
    side: Side
    qty: float = Field(gt=0)
    type: OrderType
    limit_price: float | None = Field(default=None, gt=0)
    risk_tags: list[str] = Field(default_factory=list)
    risk_signature: str
    version: int = Field(default=1, ge=1)
    correlated_intent: TradeIntent | None = None

    model_config = {
        "json_schema_extra": {
            "example": {
                "ts": "2024-04-01T12:00:02Z",
                "broker": "IBKR",
                "route": "SMART",
                "symbol": "AAPL",
                "side": "BUY",
                "qty": 100,
                "type": "MKT",
                "limit_price": None,
                "risk_tags": ["pos_limit_ok"],
                "risk_signature": "base64sig",
                "version": 1,
            }
        }
    }


class RejectedOrder(BaseModel):
    ts: dt.datetime
    symbol: str
    side: Side
    qty: float
    reason: str
    risk_tags: list[str] = Field(default_factory=list)
    version: int = Field(default=1, ge=1)


class ExecutionEvent(BaseModel):
    ts: dt.datetime
    symbol: str
    side: Side
    qty: float
    status: Literal["submitted", "filled", "partial", "canceled", "rejected"]
    broker: str
    fill_price: float | None = None
    intent_id: str | None = None
    order_id: str | None = None


class MarketTick(BaseModel):
    ts: dt.datetime
    venue: str
    symbol: str
    bid: float
    ask: float
    last: float
    volume: float

    @computed_field
    @property
    def mid(self) -> float:
        return (self.bid + self.ask) / 2


class MarketBar(BaseModel):
    ts: dt.datetime
    venue: str
    symbol: str
    timeframe: str
    open: float
    high: float
    low: float
    close: float
    volume: float


class NewsItem(BaseModel):
    id: str
    ts: dt.datetime
    title: str
    url: HttpUrl
    summary: str
    body: str
    tickers: list[str]
    source: str
    sentiment: Literal["positive", "neutral", "negative"]
    importance: float = Field(ge=0, le=1)


class FeatureSnapshot(BaseModel):
    ts: dt.datetime
    symbol: str
    features: dict[str, float]
    window: str


class PortfolioPosition(BaseModel):
    symbol: str
    qty: float
    avg_price: float
    realized_pnl: float
    unrealized_pnl: float


class RiskEvaluation(BaseModel):
    intent: TradeIntent
    approved: bool
    reasons: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    adjusted_qty: float | None = None
    adjusted_type: OrderType | None = None


class IntentTrace(BaseModel):
    intent: TradeIntent
    debate_transcript: Sequence[str]
    analyst_summaries: dict[str, str]
    memory_keys: list[str]
    latency_ms: float
    token_cost: float


__all__ = [
    "TradeIntent",
    "RiskParameters",
    "ApprovedOrder",
    "RejectedOrder",
    "ExecutionEvent",
    "MarketTick",
    "MarketBar",
    "NewsItem",
    "FeatureSnapshot",
    "RiskEvaluation",
    "IntentTrace",
    "PortfolioPosition",
]
