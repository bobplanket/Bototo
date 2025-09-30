from __future__ import annotations

import base64
from pathlib import Path

import nacl.signing
import pytest

from autollm_trader.config import get_settings
from autollm_trader.models import TradeIntent
from autollm_trader.security.signature import SignatureManager
from apps.risk_manager.src.rules import RiskEvaluator


class NullCalendar:
    def resolve_market(self, venue: str | None) -> None:
        return None

    def is_market_open(self, market: str, **_: object) -> bool:  # pragma: no cover - not used
        return True


class ClosedCalendar(NullCalendar):
    def resolve_market(self, venue: str | None) -> str | None:  # noqa: D401 - documented by parent
        return "NASDAQ"

    def is_market_open(self, market: str, **_: object) -> bool:
        return False


@pytest.fixture(autouse=True)
def signing_keys(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    get_settings.cache_clear()
    secrets_dir = tmp_path / "secrets"
    secrets_dir.mkdir()
    llm_key = nacl.signing.SigningKey.generate()
    (secrets_dir / "llm_signing_key.age").write_text(base64.b64encode(bytes(llm_key)).decode())
    (secrets_dir / "llm_pub.key").write_text(base64.b64encode(bytes(llm_key.verify_key)).decode())
    monkeypatch.setenv("SECRETS__LLM_SIGNING_PRIVATE_KEY_PATH", str(secrets_dir / "llm_signing_key.age"))
    monkeypatch.setenv("SECRETS__LLM_PUBLIC_KEY_PATH", str(secrets_dir / "llm_pub.key"))
    risk_key = nacl.signing.SigningKey.generate()
    (secrets_dir / "risk_signing_key.age").write_text(base64.b64encode(bytes(risk_key)).decode())
    (secrets_dir / "risk_pub.key").write_text(base64.b64encode(bytes(risk_key.verify_key)).decode())
    monkeypatch.setenv("SECRETS__RISK_SIGNING_PRIVATE_KEY_PATH", str(secrets_dir / "risk_signing_key.age"))
    monkeypatch.setenv("SECRETS__RISK_PUBLIC_KEY_PATH", str(secrets_dir / "risk_pub.key"))


def build_intent(signature_manager: SignatureManager, symbol: str = "AAPL", qty: float = 10.0) -> TradeIntent:
    payload = {
        "ts": "2024-01-01T00:00:00Z",
        "symbol": symbol,
        "side": "BUY",
        "qty": qty,
        "timeInForce": "DAY",
        "reasoning": {"summary": "Test", "evidence_ids": []},
        "risk": {"max_slippage_bps": 10, "stop_loss": 0.95, "take_profit": 1.05},
        "version": 1,
    }
    signature = signature_manager.sign_llm(payload)
    payload["llm_signature"] = signature
    return TradeIntent.model_validate(payload)


def test_reject_exceeds_notional(monkeypatch: pytest.MonkeyPatch) -> None:
    manager = SignatureManager()
    intent = build_intent(manager, qty=1_000_000)
    evaluator = RiskEvaluator(calendar=NullCalendar())
    evaluator.last_prices[intent.symbol] = 100.0
    evaluation, order = evaluator.evaluate(intent)
    assert not evaluation.approved
    assert order is None
    assert "order_notional_limit" in evaluation.reasons


def test_approve_valid_intent(monkeypatch: pytest.MonkeyPatch) -> None:
    manager = SignatureManager()
    intent = build_intent(manager, qty=10)
    evaluator = RiskEvaluator(calendar=NullCalendar())
    evaluator.last_prices[intent.symbol] = 100.0
    evaluator.last_spreads[intent.symbol] = 5.0
    evaluation, order = evaluator.evaluate(intent)
    assert evaluation.approved
    assert order is not None
    assert order.symbol == intent.symbol


def test_reject_when_market_closed() -> None:
    manager = SignatureManager()
    intent = build_intent(manager, qty=10)
    evaluator = RiskEvaluator(calendar=ClosedCalendar())
    evaluator.last_prices[intent.symbol] = 100.0
    evaluation, order = evaluator.evaluate(intent)
    assert not evaluation.approved
    assert order is None
    assert "market_closed" in evaluation.reasons
