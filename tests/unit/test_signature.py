from __future__ import annotations

import base64
from pathlib import Path

import nacl.signing
import pytest

from autollm_trader.config import get_settings
from autollm_trader.security.signature import SignatureManager


@pytest.fixture(autouse=True)
def signing_keys(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    get_settings.cache_clear()
    secrets_dir = tmp_path / "secrets"
    secrets_dir.mkdir()
    llm_key = nacl.signing.SigningKey.generate()
    risk_key = nacl.signing.SigningKey.generate()
    (secrets_dir / "llm_signing_key.age").write_text(base64.b64encode(bytes(llm_key)).decode())
    (secrets_dir / "risk_signing_key.age").write_text(base64.b64encode(bytes(risk_key)).decode())
    (secrets_dir / "llm_pub.key").write_text(base64.b64encode(bytes(llm_key.verify_key)).decode())
    (secrets_dir / "risk_pub.key").write_text(base64.b64encode(bytes(risk_key.verify_key)).decode())
    monkeypatch.setenv("SECRETS__LLM_SIGNING_PRIVATE_KEY_PATH", str(secrets_dir / "llm_signing_key.age"))
    monkeypatch.setenv("SECRETS__RISK_SIGNING_PRIVATE_KEY_PATH", str(secrets_dir / "risk_signing_key.age"))
    monkeypatch.setenv("SECRETS__LLM_PUBLIC_KEY_PATH", str(secrets_dir / "llm_pub.key"))
    monkeypatch.setenv("SECRETS__RISK_PUBLIC_KEY_PATH", str(secrets_dir / "risk_pub.key"))


def test_sign_and_verify_intent(signing_keys: None) -> None:
    manager = SignatureManager()
    payload = {"symbol": "AAPL", "side": "BUY", "qty": 10, "version": 1}
    signature = manager.sign_llm(payload)
    assert manager.verify_llm(payload, signature)


def test_verify_risk_signature(signing_keys: None) -> None:
    manager = SignatureManager()
    payload = {"symbol": "AAPL", "qty": 5, "version": 1}
    signature = manager.sign_risk(payload)
    assert manager.verify_risk(payload, signature)
