from __future__ import annotations

import time
from collections.abc import Callable
from contextlib import contextmanager
from typing import Any

from prometheus_client import Counter, Gauge, Histogram


LLM_INTENTS_COUNTER = Counter(
    "llm_intents_total",
    "Number of trade intents produced by LLM",
    ["symbol", "side", "status"],
)

RISK_REJECTIONS_COUNTER = Counter(
    "risk_rejections_total",
    "Number of intents rejected by risk manager",
    ["reason"],
)

EXECUTION_LATENCY = Histogram(
    "execution_latency_seconds",
    "Latency between order approval and execution",
    buckets=(0.1, 0.2, 0.5, 1, 2, 5, 10),
)

OPEN_POSITIONS_GAUGE = Gauge(
    "open_positions",
    "Number of open positions",
    ["symbol"],
)


@contextmanager
def observe_latency(histogram: Histogram, **labels: str) -> Callable[[None], None]:
    start = time.perf_counter()
    try:
        yield
    finally:
        elapsed = time.perf_counter() - start
        histogram.labels(**labels).observe(elapsed)


__all__ = [
    "LLM_INTENTS_COUNTER",
    "RISK_REJECTIONS_COUNTER",
    "EXECUTION_LATENCY",
    "OPEN_POSITIONS_GAUGE",
    "observe_latency",
]
