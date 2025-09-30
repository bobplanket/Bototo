from __future__ import annotations

import asyncio
import base64
from pathlib import Path

import nacl.signing
import pytest

from apps.execution_ib.src.service import PaperBroker
from apps.llm_agents.src.graph import AgentState, build_graph
from apps.llm_agents.src.memory import LayeredMemory
from apps.risk_manager.src.rules import RiskEvaluator
from autollm_trader.config import get_settings
from autollm_trader.models import FeatureSnapshot, TradeIntent
from autollm_trader.security.signature import SignatureManager
from autollm_trader.utils.time import utc_now


class NullCalendar:
    def resolve_market(self, venue: str | None) -> None:
        return None

    def is_market_open(self, market: str, **_: object) -> bool:  # pragma: no cover - not invoked
        return True


@pytest.fixture(autouse=True)
def signing_keys(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    get_settings.cache_clear()
    secrets_dir = tmp_path / "secrets"
    secrets_dir.mkdir()
    llm_key = nacl.signing.SigningKey.generate()
    risk_key = nacl.signing.SigningKey.generate()
    (secrets_dir / "llm_signing_key.age").write_text(base64.b64encode(bytes(llm_key)).decode())
    (secrets_dir / "llm_pub.key").write_text(base64.b64encode(bytes(llm_key.verify_key)).decode())
    (secrets_dir / "risk_signing_key.age").write_text(base64.b64encode(bytes(risk_key)).decode())
    (secrets_dir / "risk_pub.key").write_text(base64.b64encode(bytes(risk_key.verify_key)).decode())
    monkeypatch.setenv("SECRETS__LLM_SIGNING_PRIVATE_KEY_PATH", str(secrets_dir / "llm_signing_key.age"))
    monkeypatch.setenv("SECRETS__LLM_PUBLIC_KEY_PATH", str(secrets_dir / "llm_pub.key"))
    monkeypatch.setenv("SECRETS__RISK_SIGNING_PRIVATE_KEY_PATH", str(secrets_dir / "risk_signing_key.age"))
    monkeypatch.setenv("SECRETS__RISK_PUBLIC_KEY_PATH", str(secrets_dir / "risk_pub.key"))


def test_end_to_end_flow(monkeypatch: pytest.MonkeyPatch) -> None:
    manager = SignatureManager()
    memory = LayeredMemory()
    memory.add("news:1", "AAPL releases strong earnings report", layer="shallow")
    snapshot = FeatureSnapshot(
        ts=utc_now(),
        symbol="AAPL",
        features={"sma_5": 102.0, "sma_20": 100.0, "atr": 1.2},
        window="1h",
    )
    state: AgentState = {
        "symbol": snapshot.symbol,
        "features": snapshot.features,
        "news": ["AAPL releases strong earnings report"],
    }
    graph = build_graph()
    result = graph.invoke(state)
    decision = result["decision"]
    payload = {
        "ts": utc_now().isoformat(),
        "symbol": snapshot.symbol,
        "side": decision["side"],
        "qty": float(decision["qty"]),
        "timeInForce": "DAY",
        "reasoning": {"summary": decision["summary"].get("bull", ""), "evidence_ids": ["news:1"]},
        "risk": {"max_slippage_bps": 20, "stop_loss": 0.99, "take_profit": 1.01},
        "version": 1,
    }
    payload["llm_signature"] = manager.sign_llm(payload)
    intent = TradeIntent.model_validate(payload)
    evaluator = RiskEvaluator(calendar=NullCalendar())
    evaluator.last_prices[intent.symbol] = 100.0
    evaluation, order = evaluator.evaluate(intent)
    assert evaluation.approved
    assert order is not None
    broker = PaperBroker()
    event = asyncio.run(broker.execute(order))
    assert event.status == "filled"
    assert event.symbol == intent.symbol
