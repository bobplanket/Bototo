from __future__ import annotations

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from autollm_trader.logger import get_logger

from .auth import AuthService

logger = get_logger(__name__)


security = HTTPBearer(auto_error=False)
_auth_service: AuthService | None = None


def get_auth_service() -> AuthService:
    global _auth_service
    if _auth_service is None:
        _auth_service = AuthService()
    return _auth_service


def get_current_user(credentials: HTTPAuthorizationCredentials | None = Depends(security)) -> dict[str, str]:
    if credentials is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing credentials")
    auth_service = get_auth_service()
    try:
        payload = auth_service.tokens.decode(credentials.credentials)
    except PermissionError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc)) from exc
    return payload


def require_admin(payload: dict[str, str] = Depends(get_current_user)) -> dict[str, str]:
    roles = payload.get("roles", [])
    if "admin" not in roles:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
    return payload


__all__ = ["get_auth_service", "get_current_user", "require_admin"]
