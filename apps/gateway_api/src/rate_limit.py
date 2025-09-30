"""Rate limiting configuration for Gateway API using slowapi."""
from __future__ import annotations

import redis.asyncio as redis
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from fastapi import Request, Response
from typing import Callable

from autollm_trader.config import get_settings
from autollm_trader.logger import get_logger

logger = get_logger(__name__)
settings = get_settings()


# Custom key function that can use API key or IP
def get_client_identifier(request: Request) -> str:
    """
    Get client identifier for rate limiting.

    Priority:
    1. API key from Authorization header
    2. Username from JWT token (if authenticated)
    3. Client IP address
    """
    # Check for API key
    api_key = request.headers.get("X-API-Key")
    if api_key:
        return f"apikey:{api_key}"

    # Check for authenticated user
    if hasattr(request.state, "user") and request.state.user:
        username = request.state.user.get("username")
        if username:
            return f"user:{username}"

    # Fallback to IP address
    return get_remote_address(request)


# Initialize Redis connection for distributed rate limiting
redis_client: redis.Redis | None = None
storage_uri: str | None = None

try:
    redis_client = redis.from_url(
        settings.redis_url,
        encoding="utf-8",
        decode_responses=True,
    )
    storage_uri = settings.redis_url
    logger.info("Redis client initialised for rate limiting", extra={"url": storage_uri})
except Exception as exc:  # noqa: BLE001
    logger.warning("Redis not available for rate limiting, falling back to in-memory store", exc_info=exc)
    redis_client = None
    storage_uri = None


# Initialize slowapi limiter
limiter = Limiter(
    key_func=get_client_identifier,
    storage_uri=storage_uri,
    default_limits=["200/minute"],
    headers_enabled=True,
)


# Rate limit configurations by endpoint type
RATE_LIMITS = {
    # Public endpoints (no auth required)
    "public": "100/minute",

    # Health/monitoring endpoints
    "health": "500/minute",

    # Authentication endpoints
    "auth": "20/minute",

    # Authenticated user endpoints
    "user": "200/minute",

    # Admin endpoints
    "admin": "500/minute",

    # Trading endpoints (rate limited)
    "trading": "60/minute",

    # News webhook (high volume)
    "webhook": "300/minute",
}


def get_rate_limit(endpoint_type: str = "public") -> str:
    """Get rate limit string for endpoint type."""
    return RATE_LIMITS.get(endpoint_type, RATE_LIMITS["public"])


# Custom rate limit exceeded handler with logging
async def custom_rate_limit_handler(request: Request, exc: RateLimitExceeded) -> Response:
    """Custom handler for rate limit exceeded errors."""
    client_id = get_client_identifier(request)

    logger.warning(
        "Rate limit exceeded",
        client_id=client_id,
        path=request.url.path,
        method=request.method,
        limit=exc.detail,
    )

    try:
        from .observability import track_rate_limit_hit  # Local import to avoid cycle

        track_rate_limit_hit(request.url.path, client_id)
    except Exception:  # noqa: BLE001 - best-effort metric
        logger.debug("Failed to record rate limit metric", exc_info=True)

    return await _rate_limit_exceeded_handler(request, exc)
