"""Shared Prometheus instrumentation helpers for FastAPI services."""
from __future__ import annotations

from typing import Callable

from fastapi import FastAPI
from prometheus_client import Counter, Gauge, Histogram, Info
from prometheus_fastapi_instrumentator import Instrumentator as BaseInstrumentator

SERVICE_INFO = Info("service_info", "Metadata about the running service")
NATS_MESSAGES_TOTAL = Counter(
    "nats_messages_total",
    "Number of NATS messages processed",
    ["subject", "status"],
)
DB_QUERY_DURATION = Histogram(
    "db_query_duration_seconds",
    "Database query duration in seconds",
    ["query_type"],
    buckets=(0.001, 0.005, 0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5),
)
ACTIVE_TASKS_GAUGE = Gauge(
    "service_active_tasks",
    "Current background tasks per service",
    ["task"],
)


ConfigHook = Callable[[BaseInstrumentator], None]


def setup_instrumentation(
    app: FastAPI,
    *,
    service_name: str,
    version: str,
    configure: ConfigHook | None = None,
) -> BaseInstrumentator:
    """Configure Prometheus instrumentation for a FastAPI application.

    Args:
        app: FastAPI application instance.
        service_name: Logical service name (used in metrics labels).
        version: Semantic version of the service.
        configure: Optional callback to mutate the instrumentator before it is registered.

    Returns:
        The configured :class:`Instrumentator` instance.
    """

    SERVICE_INFO.info({"service": service_name, "version": version})

    instrumentator = BaseInstrumentator(
        should_group_status_codes=True,
        should_ignore_untemplated=True,
        should_group_untemplated=True,
        excluded_handlers=["/health", "/metrics"],
    )

    if configure is not None:
        configure(instrumentator)

    instrumentator.instrument(app)
    instrumentator.expose(app, endpoint="/metrics", include_in_schema=False)
    app.state.instrumentator = instrumentator
    app.state.service_name = service_name
    return instrumentator


__all__ = [
    "setup_instrumentation",
    "SERVICE_INFO",
    "NATS_MESSAGES_TOTAL",
    "DB_QUERY_DURATION",
    "ACTIVE_TASKS_GAUGE",
]
