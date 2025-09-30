from __future__ import annotations

import base64
import json
import time
from pathlib import Path
from typing import Any, Dict, MutableMapping

import pyotp
from jose import JWTError, jwt
from pydantic import BaseModel, Field
from webauthn import (
    generate_registration_options,
    generate_authentication_options,
    verify_registration_response,
    verify_authentication_response,
)
from webauthn.helpers.options import (
    AuthenticationCredential,
    AuthenticationOptions,
    PublicKeyCredentialDescriptor,
    RegistrationCredential,
    RegistrationOptions,
)

from autollm_trader.config import get_settings
from autollm_trader.logger import get_logger

logger = get_logger(__name__)


class StoredCredential(BaseModel):
    credential_id: str
    public_key: str
    sign_count: int


class UserRecord(BaseModel):
    username: str
    display_name: str
    roles: list[str] = Field(default_factory=lambda: ["admin"])
    totp_secret: str | None = None
    credentials: list[StoredCredential] = Field(default_factory=list)

    model_config = {
        "arbitrary_types_allowed": True,
        "json_encoders": {StoredCredential: lambda c: c.__dict__},
    }


class FileAuthRepository:
    def __init__(self, path: Path | None = None) -> None:
        self._path = path or Path("data/users.json")
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._memcache: Dict[str, UserRecord] = {}
        self._load()

    def _load(self) -> None:
        if self._path.exists():
            payload = json.loads(self._path.read_text())
            for username, raw in payload.items():
                creds = [StoredCredential(**cred) for cred in raw.get("credentials", [])]
                self._memcache[username] = UserRecord(
                    username=raw["username"],
                    display_name=raw.get("display_name", username),
                    roles=raw.get("roles", ["admin"]),
                    totp_secret=raw.get("totp_secret"),
                    credentials=creds,
                )

    def _persist(self) -> None:
        serialised = {username: record.model_dump(mode="json") for username, record in self._memcache.items()}
        self._path.write_text(json.dumps(serialised, indent=2))

    def get(self, username: str) -> UserRecord | None:
        return self._memcache.get(username)

    def upsert(self, record: UserRecord) -> UserRecord:
        self._memcache[record.username] = record
        self._persist()
        return record

    def add_credential(self, username: str, credential: StoredCredential) -> None:
        record = self._memcache.setdefault(
            username,
            UserRecord(username=username, display_name=username),
        )
        record.credentials = [cred for cred in record.credentials if cred.credential_id != credential.credential_id]
        record.credentials.append(credential)
        self._persist()


class ChallengeStore:
    def __init__(self, ttl_seconds: int = 300) -> None:
        self._ttl = ttl_seconds
        self._store: MutableMapping[str, tuple[str, float]] = {}

    def save(self, key: str, challenge: str) -> None:
        self._store[key] = (challenge, time.time() + self._ttl)

    def pop(self, key: str) -> str | None:
        challenge, expiry = self._store.pop(key, ("", 0))
        if not challenge or expiry < time.time():
            return None
        return challenge


class TokenManager:
    def __init__(self) -> None:
        settings = get_settings()
        self._secret = settings.auth.jwt_secret
        self._algorithm = settings.auth.jwt_algorithm
        self._access_exp = settings.auth.access_token_expire_minutes * 60

    def create(self, username: str, roles: list[str]) -> str:
        now = int(time.time())
        payload = {"sub": username, "roles": roles, "iat": now, "exp": now + self._access_exp}
        token = jwt.encode(payload, self._secret, algorithm=self._algorithm)
        return token

    def decode(self, token: str) -> dict[str, Any]:
        try:
            return jwt.decode(token, self._secret, algorithms=[self._algorithm])
        except JWTError as exc:  # noqa: BLE001
            raise PermissionError("Invalid token") from exc


class AuthService:
    def __init__(self, repository: FileAuthRepository | None = None) -> None:
        settings = get_settings()
        self.repo = repository or FileAuthRepository()
        self.challenges = ChallengeStore()
        self.tokens = TokenManager()
        self.rp_id = settings.auth.webauthn_rp_id
        self.rp_name = settings.auth.webauthn_rp_name
        self.origin = settings.auth.webauthn_origin or f"https://{self.rp_id}"

    def registration_options(self, username: str, display_name: str) -> RegistrationOptions:
        record = self.repo.get(username)
        exclude = []
        if record:
            exclude = [
                PublicKeyCredentialDescriptor(id=bytes.fromhex(cred.credential_id))
                for cred in record.credentials
            ]
        options = generate_registration_options(
            rp_id=self.rp_id,
            rp_name=self.rp_name,
            user_id=username.encode(),
            user_name=username,
            user_display_name=display_name,
            exclude_credentials=exclude,
        )
        self.challenges.save(f"register:{username}", options.challenge)
        return options

    def verify_registration(self, username: str, credential: RegistrationCredential) -> StoredCredential:
        challenge = self.challenges.pop(f"register:{username}")
        if not challenge:
            raise ValueError("Registration challenge missing or expired")
        record = self.repo.get(username) or UserRecord(username=username, display_name=username)
        verification = verify_registration_response(
            credential=credential,
            expected_challenge=challenge,
            expected_rp_id=self.rp_id,
            expected_origin=self.origin,
        )
        stored = StoredCredential(
            credential_id=verification.credential_id.hex(),
            public_key=base64.b64encode(verification.credential_public_key).decode(),
            sign_count=verification.sign_count,
        )
        record.credentials.append(stored)
        self.repo.upsert(record)
        return stored

    def authentication_options(self, username: str) -> AuthenticationOptions:
        record = self.repo.get(username)
        allow_credentials = []
        if record:
            allow_credentials = [
                PublicKeyCredentialDescriptor(id=bytes.fromhex(cred.credential_id))
                for cred in record.credentials
            ]
        options = generate_authentication_options(rp_id=self.rp_id, allow_credentials=allow_credentials)
        self.challenges.save(f"auth:{username}", options.challenge)
        return options

    def verify_authentication(self, username: str, credential: AuthenticationCredential) -> str:
        challenge = self.challenges.pop(f"auth:{username}")
        if not challenge:
            raise ValueError("Authentication challenge missing or expired")
        record = self.repo.get(username)
        if not record:
            raise PermissionError("Unknown user")
        credential_data = {
            cred.credential_id: cred for cred in record.credentials
        }
        cred_id_hex = credential.raw_id.hex()
        stored = credential_data.get(cred_id_hex)
        if not stored:
            raise PermissionError("Credential not registered")
        verification = verify_authentication_response(
            credential=credential,
            expected_challenge=challenge,
            expected_rp_id=self.rp_id,
            expected_origin=self.origin,
            credential_current_sign_count=stored.sign_count,
            credential_public_key=base64.b64decode(stored.public_key),
        )
        stored.sign_count = verification.new_sign_count
        self.repo.upsert(record)
        token = self.tokens.create(username=username, roles=record.roles)
        return token

    def enable_totp(self, username: str) -> str:
        record = self.repo.get(username) or UserRecord(username=username, display_name=username)
        if record.totp_secret:
            return record.totp_secret
        secret = pyotp.random_base32()
        record.totp_secret = secret
        self.repo.upsert(record)
        return secret

    def verify_totp(self, username: str, code: str) -> str:
        record = self.repo.get(username)
        if not record or not record.totp_secret:
            raise PermissionError("TOTP not configured")
        totp = pyotp.TOTP(record.totp_secret)
        if not totp.verify(code, valid_window=get_settings().auth.totp_skew):
            raise PermissionError("Invalid TOTP code")
        token = self.tokens.create(username=username, roles=record.roles)
        return token


__all__ = [
    "AuthService",
    "FileAuthRepository",
    "UserRecord",
    "StoredCredential",
    "TokenManager",
]
