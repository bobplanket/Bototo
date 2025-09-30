from __future__ import annotations

import json
import os
from typing import Any, Iterable, Literal, Tuple

from langchain.prompts import ChatPromptTemplate
from langchain_core.messages import BaseMessage
from langchain_openai import ChatOpenAI
from pydantic import BaseModel, Field

from autollm_trader.config import get_settings
from autollm_trader.logger import get_logger

logger = get_logger(__name__)


class AnalystOutput(BaseModel):
    sentiment: Literal["bullish", "bearish", "neutral"]
    summary: str
    key_signals: list[str] = Field(default_factory=list)
    confidence: float = Field(ge=0.0, le=1.0)


class DebateOutput(BaseModel):
    bull_case: str
    bear_case: str
    stance: Literal["BUY", "SELL", "HOLD"]
    uncertainty: float = Field(ge=0.0, le=1.0)


class TraderDecision(BaseModel):
    action: Literal["BUY", "SELL", "HOLD"]
    quantity: float = Field(ge=0.0)
    summary: str
    stop_loss_bps: int | None = Field(default=None, ge=0)
    take_profit_bps: int | None = Field(default=None, ge=0)


class LLMClient:
    def __init__(self) -> None:
        settings = get_settings().llm
        if settings.provider != "openai":
            raise ValueError("Only OpenAI provider is supported currently")
        api_key = os.getenv(settings.api_key_env)
        if not api_key:
            raise ValueError("OPENAI_API_KEY missing")
        self._model = ChatOpenAI(
            model=settings.model,
            temperature=settings.temperature,
            max_tokens=settings.max_output_tokens,
            api_key=api_key,
        )
        self._token_budget = settings.token_budget_per_intent
        self._analytics: dict[str, Any] = {}

    @property
    def token_budget(self) -> int:
        return self._token_budget

    def analytics(self) -> dict[str, Any]:
        return self._analytics

    async def analyst(
        self,
        symbol: str,
        features: dict[str, float],
        news: Iterable[str],
    ) -> Tuple[AnalystOutput, int]:
        feature_lines = "\n".join(f"- {k}: {v:.4f}" for k, v in features.items()) or "- (aucune donnée)"
        news_lines = "\n".join(f"- {snippet}" for snippet in news) or "- Aucun élément récent"
        prompt = ChatPromptTemplate.from_messages(
            [
                (
                    "system",
                    "Tu es un analyste actions senior. Analyse le titre {symbol} en t'appuyant sur les indicateurs "
                    "et les actualités fournies. Réponds uniquement en JSON strict.",
                ),
                (
                    "human",
                    "Indicateurs:\n{features}\nActualités:\n{news}\nRespecte strictement le schema: {schema}",
                ),
            ]
        )
        schema_hint = {
            "sentiment": "bullish|bearish|neutral",
            "summary": "string",
            "key_signals": ["string"],
            "confidence": 0.0,
        }
        messages = prompt.format_messages(
            symbol=symbol,
            features=feature_lines,
            news=news_lines,
            schema=json.dumps(schema_hint, ensure_ascii=False),
        )
        return await self._invoke(messages, AnalystOutput)

    async def debate(
        self,
        symbol: str,
        analyst: AnalystOutput,
        news: Iterable[str],
    ) -> Tuple[DebateOutput, int]:
        news_lines = "\n".join(f"- {snippet}" for snippet in news) or "- Aucun élément"
        prompt = ChatPromptTemplate.from_messages(
            [
                (
                    "system",
                    "Tu organises un débat bull vs bear sur {symbol}. Donne un JSON strict.",
                ),
                (
                    "human",
                    "Synthèse analyste: {summary}\nSentiment: {sentiment}\nSignaux: {signals}\nActualités:\n{news}\n"
                    "JSON attendu: {schema}",
                ),
            ]
        )
#
        schema_hint = {
            "bull_case": "string",
            "bear_case": "string",
            "stance": "BUY|SELL|HOLD",
            "uncertainty": 0.0,
        }
        messages = prompt.format_messages(
            symbol=symbol,
            summary=analyst.summary,
            sentiment=analyst.sentiment,
            signals=", ".join(analyst.key_signals) or "aucun",
            news=news_lines,
            schema=json.dumps(schema_hint, ensure_ascii=False),
        )
        return await self._invoke(messages, DebateOutput)

    async def trader(
        self,
        symbol: str,
        analyst: AnalystOutput,
        debate: DebateOutput,
    ) -> Tuple[TraderDecision, int]:
        prompt = ChatPromptTemplate.from_messages(
            [
                (
                    "system",
                    "Tu es un trader discrétionnaire. Tu dois décider d'une action sur {symbol}. Réponds en JSON strict.",
                ),
                (
                    "human",
                    "Analyse: {summary}\nSentiment: {sentiment}\nDébat bull: {bull}\nDébat bear: {bear}\n"
                    "Stance proposée: {stance}\nIncertitude: {uncertainty}\nJSON attendu: {schema}",
                ),
            ]
        )
        schema_hint = {
            "action": "BUY|SELL|HOLD",
            "quantity": 0.0,
            "summary": "string",
            "stop_loss_bps": "int|null",
            "take_profit_bps": "int|null",
        }
        messages = prompt.format_messages(
            symbol=symbol,
            summary=analyst.summary,
            sentiment=analyst.sentiment,
            bull=debate.bull_case,
            bear=debate.bear_case,
            stance=debate.stance,
            uncertainty=f"{debate.uncertainty:.2f}",
            schema=json.dumps(schema_hint, ensure_ascii=False),
        )
        return await self._invoke(messages, TraderDecision)

    async def _invoke(self, messages: list[BaseMessage], model: type[BaseModel]) -> Tuple[BaseModel, int]:
        remaining_budget = self._token_budget - int(self._analytics.get("tokens", 0))
        if remaining_budget <= 0:
            raise RuntimeError("Token budget épuisé pour cette intention")
        response = await self._model.ainvoke(messages)
        token_usage = response.response_metadata.get("token_usage", {}).get("total_tokens", 0)
        self._analytics.setdefault("tokens", 0)
        self._analytics["tokens"] += token_usage
        content = response.content if isinstance(response.content, str) else "".join(response.content)
        parsed = self._extract_json(content)
        return model.model_validate(parsed), token_usage

    @staticmethod
    def _extract_json(text: str) -> Any:
        start = text.find("{")
        end = text.rfind("}")
        if start == -1 or end == -1:
            raise ValueError("Réponse LLM sans JSON valide")
        snippet = text[start : end + 1]
        return json.loads(snippet)


__all__ = ["LLMClient", "AnalystOutput", "DebateOutput", "TraderDecision"]
