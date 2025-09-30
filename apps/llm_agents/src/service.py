from __future__ import annotations

import asyncio
import json
import time

from autollm_trader.logger import get_logger
from autollm_trader.messaging.nats_client import nats_connection
from autollm_trader.metrics.prom import LLM_INTENTS_COUNTER
from autollm_trader.models import FeatureSnapshot, IntentTrace, NewsItem, TradeIntent
from autollm_trader.security.signature import signature_manager
from autollm_trader.utils.time import utc_now

from .graph import AgentState, build_graph
from .memory import LayeredMemory, MemoryRecord
from .llm_client import LLMClient

logger = get_logger(__name__)


class LLMAgentService:
    def __init__(self) -> None:
        self.graph = build_graph()
        self.memory = LayeredMemory()
        self._tasks: list[asyncio.Task[None]] = []
        self._lock = asyncio.Lock()
        try:
            self.llm_client: LLMClient | None = LLMClient()
            logger.info("LLM agents using OpenAI backend")
        except ValueError as exc:
            self.llm_client = None
            logger.warning("LLM backend disabled (%s); falling back to heuristic agents", exc)

    async def start(self) -> None:
        async with self._lock:
            if self._tasks:
                return
            logger.info("Starting LLM agents service")
            client = await nats_connection.connect()
            await client.subscribe("news.item.created", cb=self._handle_news)
            await client.subscribe("features.snapshot.>", cb=self._handle_feature)
            self._tasks.append(asyncio.create_task(self._prune_loop()))

    async def stop(self) -> None:
        async with self._lock:
            for task in self._tasks:
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
            self._tasks.clear()
            await nats_connection.close()

    async def _prune_loop(self) -> None:
        while True:
            await asyncio.sleep(3600)
            self.memory.prune()

    async def _handle_news(self, msg) -> None:  # type: ignore[no-untyped-def]
        news = NewsItem.model_validate_json(msg.data)
        layer = "shallow"
        if any(tag.lower() in news.title.lower() for tag in ("10q", "earnings")):
            layer = "intermediate"
        if any(tag.lower() in news.title.lower() for tag in ("10k", "annual")):
            layer = "deep"
        self.memory.add(
            key=news.id,
            text=f"{news.title} {news.summary}",
            layer=layer,
            metadata={"importance": str(news.importance), "sentiment": news.sentiment},
        )
        logger.info("News ingested", extra={"news_id": news.id, "layer": layer})

    async def _handle_feature(self, msg) -> None:  # type: ignore[no-untyped-def]
        snapshot = FeatureSnapshot.model_validate_json(msg.data)
        symbol = snapshot.symbol
        news_mem = self.memory.query(symbol, top_k=5)
        try:
            if self.llm_client is not None:
                result = await self._build_intent_with_llm(snapshot, news_mem)
            else:
                result = await self._build_intent_with_graph(snapshot, news_mem)
        except Exception as exc:  # noqa: BLE001
            logger.exception("Failed to generate intent", exc_info=exc)
            return
        if result is None:
            return
        intent, trace = result
        client = await nats_connection.connect()
        await client.publish("llm.intent.proposed", intent.model_dump_json().encode())
        await client.publish("llm.intent.trace", trace.model_dump_json().encode())
        LLM_INTENTS_COUNTER.labels(symbol=intent.symbol, side=intent.side, status="auto").inc()
        logger.info("Intent proposed", extra={"symbol": intent.symbol, "side": intent.side, "qty": intent.qty})

    async def _build_intent_with_llm(
        self,
        snapshot: FeatureSnapshot,
        news_mem: list[MemoryRecord],
    ):
        assert self.llm_client is not None
        analytics = self.llm_client.analytics()
        analytics.clear()
        news_texts = [mem.text for mem in news_mem]
        start = time.perf_counter()
        analyst, tokens_a = await self.llm_client.analyst(snapshot.symbol, snapshot.features, news_texts)
        debate, tokens_d = await self.llm_client.debate(snapshot.symbol, analyst, news_texts)
        trader, tokens_t = await self.llm_client.trader(snapshot.symbol, analyst, debate)
        latency_ms = (time.perf_counter() - start) * 1000
        total_tokens = tokens_a + tokens_d + tokens_t
        if trader.action == "HOLD" or trader.quantity <= 0:
            logger.info("LLM trader decided to hold", extra={"symbol": snapshot.symbol})
            return None
        qty = max(1.0, min(trader.quantity, 1000.0))
        stop_loss = None
        take_profit = None
        if trader.stop_loss_bps is not None:
            stop_loss = max(0.1, 1 - trader.stop_loss_bps / 10_000)
        if trader.take_profit_bps is not None:
            take_profit = 1 + trader.take_profit_bps / 10_000
        intent_payload = {
            "ts": utc_now().isoformat(),
            "symbol": snapshot.symbol,
            "side": trader.action,
            "qty": float(qty),
            "timeInForce": "DAY",
            "reasoning": {
                "summary": trader.summary,
                "evidence_ids": [mem.key for mem in news_mem],
            },
            "risk": {
                "max_slippage_bps": 20,
                "stop_loss": stop_loss,
                "take_profit": take_profit,
            },
            "version": 1,
        }
        signature = signature_manager.sign_llm(intent_payload)
        intent_payload["llm_signature"] = signature
        intent = TradeIntent.model_validate(intent_payload)
        trace = IntentTrace(
            intent=intent,
            debate_transcript=[debate.bull_case, debate.bear_case],
            analyst_summaries={
                "sentiment": analyst.sentiment,
                "summary": analyst.summary,
                "signals": ", ".join(analyst.key_signals),
            },
            memory_keys=[mem.key for mem in news_mem],
            latency_ms=latency_ms,
            token_cost=float(total_tokens),
        )
        return intent, trace

    async def _build_intent_with_graph(
        self,
        snapshot: FeatureSnapshot,
        news_mem: list[MemoryRecord],
    ):
        state: AgentState = {
            "features": snapshot.features,
            "news": [mem.text for mem in news_mem],
            "symbol": snapshot.symbol,
        }
        response: AgentState = self.graph.invoke(state)
        decision = response.get("decision", {})
        if not decision:
            logger.warning("Graph produced no decision", extra={"symbol": snapshot.symbol})
            return None
        side = decision.get("side", "HOLD")
        if side not in {"BUY", "SELL"}:
            logger.info("Decision not actionable", extra={"decision": decision})
            return None
        qty = float(decision.get("qty", 0))
        if qty <= 0:
            return None
        intent_payload = {
            "ts": utc_now().isoformat(),
            "symbol": snapshot.symbol,
            "side": side,
            "qty": qty,
            "timeInForce": "DAY",
            "reasoning": {
                "summary": decision.get("summary", {}).get("bull", ""),
                "evidence_ids": [mem.key for mem in news_mem],
            },
            "risk": {
                "max_slippage_bps": 20,
                "stop_loss": snapshot.features.get("atr", 0) * 0.5,
                "take_profit": snapshot.features.get("atr", 0) * 1.5,
            },
            "version": 1,
        }
        signature = signature_manager.sign_llm(intent_payload)
        intent_payload["llm_signature"] = signature
        intent = TradeIntent.model_validate(intent_payload)
        trace = IntentTrace(
            intent=intent,
            debate_transcript=[decision.get("summary", {}).get("bull", ""), decision.get("summary", {}).get("bear", "")],
            analyst_summaries=response.get("analyst_summary", {}),
            memory_keys=[mem.key for mem in news_mem],
            latency_ms=0.0,
            token_cost=0.0,
        )
        return intent, trace


service = LLMAgentService()


async def run_service() -> None:
    await service.start()
    while True:
        await asyncio.sleep(60)


__all__ = ["service", "run_service", "LLMAgentService"]
