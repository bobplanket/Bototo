from __future__ import annotations

import datetime as dt
from typing import Literal

from pydantic import BaseModel, Field, HttpUrl

from autollm_trader.models import TradeIntent


class ManualIntentRequest(BaseModel):
    symbol: str
    side: Literal["BUY", "SELL"]
    qty: float = Field(gt=0)
    time_in_force: Literal["DAY", "GTC"] = Field(default="DAY")
    reasoning_summary: str
    evidence_ids: list[str] = Field(default_factory=list)
    max_slippage_bps: int = Field(default=20, ge=0, le=200)
    stop_loss: float | None = Field(default=None, gt=0)
    take_profit: float | None = Field(default=None, gt=0)

    def to_intent(self, signature: str) -> TradeIntent:
        return TradeIntent(
            symbol=self.symbol,
            side=self.side,
            qty=self.qty,
            timeInForce=self.time_in_force,
            reasoning={"summary": self.reasoning_summary, "evidence_ids": self.evidence_ids},
            risk={
                "max_slippage_bps": self.max_slippage_bps,
                "stop_loss": self.stop_loss,
                "take_profit": self.take_profit,
            },
            llm_signature=signature,
        )


class KillSwitchRequest(BaseModel):
    reason: str
    user: str


class WebhookNewsItem(BaseModel):
    id: str
    title: str
    url: HttpUrl
    summary: str
    published_at: dt.datetime
    categories: list[str] = Field(default_factory=list)
    content: str | None = None


class TradeIntentResponse(BaseModel):
    intent: TradeIntent
    published: bool


__all__ = [
    "ManualIntentRequest",
    "KillSwitchRequest",
    "WebhookNewsItem",
    "TradeIntentResponse",
]
