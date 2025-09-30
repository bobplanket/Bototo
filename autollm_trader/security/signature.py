from __future__ import annotations

import base64
import json
import pathlib
from typing import Any

import nacl.signing
import nacl.encoding

from autollm_trader.config import get_settings
from autollm_trader.logger import get_logger

logger = get_logger(__name__)


class SignatureManager:
    def __init__(self) -> None:
        settings = get_settings()
        self._llm_private_path = settings.secrets.llm_signing_private_key_path
        self._risk_private_path = settings.secrets.risk_signing_private_key_path
        self._llm_public_path = settings.secrets.llm_public_key_path
        self._risk_public_path = settings.secrets.risk_public_key_path

    def _read_key(self, path: pathlib.Path) -> bytes:
        if not path.exists():
            raise FileNotFoundError(path)
        content = path.read_text().strip()
        try:
            if content.startswith("-----BEGIN"):
                lines = [line for line in content.splitlines() if not line.startswith("-")]
                return base64.b64decode("".join(lines))
            return base64.b64decode(content)
        except Exception as exc:  # noqa: BLE001
            raise ValueError(f"Invalid key at {path}") from exc

    def sign_llm(self, payload: dict[str, Any]) -> str:
        key_bytes = self._read_key(self._llm_private_path)
        signing_key = nacl.signing.SigningKey(key_bytes)
        data = json.dumps(payload, sort_keys=True).encode()
        signature = signing_key.sign(data).signature
        encoded = base64.b64encode(signature).decode()
        logger.debug("LLM payload signed")
        return encoded

    def verify_llm(self, payload: dict[str, Any], signature: str) -> bool:
        public_bytes = self._read_key(self._llm_public_path)
        verify_key = nacl.signing.VerifyKey(public_bytes)
        data = json.dumps(payload, sort_keys=True).encode()
        try:
            verify_key.verify(data, base64.b64decode(signature))
            return True
        except Exception:  # noqa: BLE001
            return False

    def sign_risk(self, payload: dict[str, Any]) -> str:
        key_bytes = self._read_key(self._risk_private_path)
        signing_key = nacl.signing.SigningKey(key_bytes)
        data = json.dumps(payload, sort_keys=True).encode()
        signature = signing_key.sign(data).signature
        encoded = base64.b64encode(signature).decode()
        logger.debug("Risk payload signed")
        return encoded

    def verify_risk(self, payload: dict[str, Any], signature: str) -> bool:
        public_bytes = self._read_key(self._risk_public_path)
        verify_key = nacl.signing.VerifyKey(public_bytes)
        data = json.dumps(payload, sort_keys=True).encode()
        try:
            verify_key.verify(data, base64.b64decode(signature))
            return True
        except Exception:  # noqa: BLE001
            return False


signature_manager = SignatureManager()

__all__ = ["signature_manager", "SignatureManager"]
