from __future__ import annotations

import importlib

import numpy as np
import pytest

from autollm_trader.config import get_settings
from autollm_trader.models import FeatureSnapshot
from autollm_trader.utils.time import utc_now


@pytest.fixture(autouse=True)
def clear_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    for var in ["OPENAI_API_KEY", "BROKERS__IB_ENABLED", "BROKERS__LIVE_FLAG"]:
        monkeypatch.delenv(var, raising=False)
    get_settings.cache_clear()


def test_llm_client_requires_key(monkeypatch: pytest.MonkeyPatch) -> None:
    from apps.llm_agents.src import llm_client as module

    importlib.reload(module)
    with pytest.raises(ValueError):
        module.LLMClient()


@pytest.mark.asyncio
async def test_build_intent_with_llm_stub(monkeypatch: pytest.MonkeyPatch) -> None:
    from apps.llm_agents.src import service as service_module
    importlib.reload(service_module)
    llm_service = service_module.LLMAgentService()

    class StubLLM:
        def __init__(self) -> None:
            self._analytics = {"tokens": 0}

        def analytics(self) -> dict[str, int]:
            return self._analytics

        async def analyst(self, symbol, features, news):  # noqa: ANN001
            from apps.llm_agents.src.llm_client import AnalystOutput

            return AnalystOutput(
                sentiment="bullish",
                summary="Momentum positif",
                key_signals=["SMA5>SMA20"],
                confidence=0.7,
            ), 100

        async def debate(self, symbol, analyst, news):  # noqa: ANN001
            from apps.llm_agents.src.llm_client import DebateOutput

            return DebateOutput(
                bull_case="Nouvelle favorable",
                bear_case="Risque macro",
                stance="BUY",
                uncertainty=0.3,
            ), 80

        async def trader(self, symbol, analyst, debate):  # noqa: ANN001
            from apps.llm_agents.src.llm_client import TraderDecision

            return TraderDecision(
                action="BUY",
                quantity=5,
                summary="Acheter sur breakout",
                stop_loss_bps=50,
                take_profit_bps=120,
            ), 60

    llm_service.llm_client = StubLLM()
    snapshot = FeatureSnapshot(
        ts=utc_now(),
        symbol="AAPL",
        features={"sma_5": 105.0, "sma_20": 100.0, "atr": 1.2},
        window="1h",
    )
    from apps.llm_agents.src.memory import MemoryRecord

    record = MemoryRecord(
        key="news:1",
        text="AAPL publie des résultats supérieurs aux attentes",
        ts=utc_now(),
        layer="shallow",
        embedding=np.zeros(64),
        importance=1.0,
    )
    from autollm_trader.security import signature

    monkeypatch.setattr(signature.signature_manager, "sign_llm", lambda payload: "sig")
    result = await llm_service._build_intent_with_llm(snapshot, [record])
    assert result is not None
    intent, trace = result
    assert intent.side == "BUY"
    assert intent.qty == 5
    assert intent.risk.stop_loss is not None
    assert trace.token_cost > 0
