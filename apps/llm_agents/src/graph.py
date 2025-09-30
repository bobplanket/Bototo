from __future__ import annotations

import datetime as dt
import json
from typing import Any, TypedDict

from langgraph.graph import StateGraph

from autollm_trader.logger import get_logger

from .memory import LayeredMemory

logger = get_logger(__name__)


class AgentState(TypedDict, total=False):
    features: dict[str, float]
    news: list[str]
    symbol: str
    analyst_summary: dict[str, str]
    debate: dict[str, Any]
    decision: dict[str, Any]
    memory_keys: list[str]


def analyst_node(state: AgentState) -> AgentState:
    features = state.get("features", {})
    symbol = state.get("symbol", "")
    summary = {
        "momentum": "bullish" if features.get("sma_5", 0) > features.get("sma_20", 0) else "bearish",
        "volatility": f"ATR {features.get('atr', 0):.2f}",
    }
    logger.debug("Analyst summary", extra={"symbol": symbol, "summary": summary})
    return {"analyst_summary": summary}


def debate_node(state: AgentState) -> AgentState:
    summary = state.get("analyst_summary", {})
    news = state.get("news", [])
    bull = f"Momentum favorable: {summary.get('momentum', 'neutral')}"
    bear = "News risk low" if not news else f"Potential risk from {', '.join(news[:2])}"
    stance = "BUY" if "bullish" in summary.get("momentum", "") else "SELL"
    debate = {"bull": bull, "bear": bear, "stance": stance, "confidence": 0.6 if stance == "BUY" else 0.4}
    logger.debug("Debate outcome", extra=debate)
    return {"debate": debate}


def trader_node(state: AgentState) -> AgentState:
    debate = state.get("debate", {})
    symbol = state.get("symbol", "")
    qty = 10 if debate.get("stance") == "BUY" else -10
    decision = {
        "symbol": symbol,
        "side": "BUY" if qty > 0 else "SELL",
        "qty": abs(qty),
        "confidence": debate.get("confidence", 0.5),
        "summary": debate,
    }
    logger.debug("Trader decision", extra=decision)
    return {"decision": decision}


def build_graph() -> StateGraph:
    graph = StateGraph(AgentState)
    graph.add_node("analyst", analyst_node)
    graph.add_node("debate", debate_node)
    graph.add_node("trader", trader_node)

    graph.set_entry_point("analyst")
    graph.add_edge("analyst", "debate")
    graph.add_edge("debate", "trader")

    return graph.compile()


__all__ = ["build_graph", "AgentState"]
