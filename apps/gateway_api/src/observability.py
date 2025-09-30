"""Observability configuration for Gateway API."""
from __future__ import annotations

import time
from typing import Callable

from fastapi import FastAPI, Request, Response
from prometheus_client import Counter, Gauge, Histogram
from prometheus_fastapi_instrumentator import metrics

from autollm_trader.logger import get_logger
from autollm_trader.metrics.instrumentation import setup_instrumentation

logger = get_logger(__name__)

# Custom Prometheus metrics
REQUEST_COUNT = Counter(
    "gateway_http_requests_total",
    "Total HTTP requests",
    ["method", "endpoint", "status"],
)

REQUEST_LATENCY = Histogram(
    "gateway_http_request_duration_seconds",
    "HTTP request latency",
    ["method", "endpoint"],
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
)

ACTIVE_REQUESTS = Gauge(
    "gateway_http_requests_active",
    "Active HTTP requests",
    ["method", "endpoint"],
)

# Trading-specific metrics
MANUAL_ORDERS_CREATED = Counter(
    "gateway_manual_orders_created_total",
    "Total manual orders created",
    ["symbol", "side"],
)

KILL_SWITCH_ACTIVATIONS = Counter(
    "gateway_kill_switch_activations_total",
    "Total kill switch activations",
    ["user"],
)

WEBHOOKS_RECEIVED = Counter(
    "gateway_webhooks_received_total",
    "Total webhooks received",
    ["type"],
)

RATE_LIMIT_HITS = Counter(
    "gateway_rate_limit_hits_total",
    "Total rate limit hits",
    ["endpoint", "client_id"],
)

AUTH_ATTEMPTS = Counter(
    "gateway_auth_attempts_total",
    "Total authentication attempts",
    ["method", "status"],
)


def setup_observability(app: FastAPI) -> None:
    """
    Setup observability instrumentation for FastAPI app.

    Adds:
    - Prometheus metrics endpoint at /metrics
    - Automatic request instrumentation
    - Custom business metrics
    """
    def configure(inst):
        inst.add(
            metrics.request_size(
                should_include_handler=True,
                should_include_method=True,
                should_include_status=True,
                metric_name="gateway_request_size_bytes",
                metric_doc="Request size in bytes",
            )
        )
        inst.add(
            metrics.response_size(
                should_include_handler=True,
                should_include_method=True,
                should_include_status=True,
                metric_name="gateway_response_size_bytes",
                metric_doc="Response size in bytes",
            )
        )
        inst.add(
            metrics.latency(
                should_include_handler=True,
                should_include_method=True,
                should_include_status=True,
                metric_name="gateway_request_latency_seconds",
                metric_doc="Request latency in seconds",
                buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
            )
        )

    setup_instrumentation(
        app,
        service_name="gateway-api",
        version=app.version or "0",
        configure=configure,
    )

    logger.info("Observability instrumentation setup completed")


# Middleware for custom metrics
async def metrics_middleware(
    request: Request,
    call_next: Callable,
) -> Response:
    """Middleware to track custom metrics per request."""
    method = request.method
    endpoint = request.url.path

    # Track active requests
    ACTIVE_REQUESTS.labels(method=method, endpoint=endpoint).inc()

    start_time = time.time()

    try:
        response = await call_next(request)
        status = response.status_code

        # Track request count and latency
        REQUEST_COUNT.labels(method=method, endpoint=endpoint, status=status).inc()
        latency = time.time() - start_time
        REQUEST_LATENCY.labels(method=method, endpoint=endpoint).observe(latency)

        return response

    finally:
        # Always decrement active requests
        ACTIVE_REQUESTS.labels(method=method, endpoint=endpoint).dec()


def track_manual_order(symbol: str, side: str) -> None:
    """Track manual order creation."""
    MANUAL_ORDERS_CREATED.labels(symbol=symbol, side=side).inc()


def track_kill_switch(user: str) -> None:
    """Track kill switch activation."""
    KILL_SWITCH_ACTIVATIONS.labels(user=user).inc()


def track_webhook(webhook_type: str) -> None:
    """Track webhook reception."""
    WEBHOOKS_RECEIVED.labels(type=webhook_type).inc()


def track_rate_limit_hit(endpoint: str, client_id: str) -> None:
    """Track rate limit hit."""
    RATE_LIMIT_HITS.labels(endpoint=endpoint, client_id=client_id).inc()


def track_auth_attempt(method: str, status: str) -> None:
    """Track authentication attempt."""
    AUTH_ATTEMPTS.labels(method=method, status=status).inc()
