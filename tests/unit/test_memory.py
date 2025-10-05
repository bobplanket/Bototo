from __future__ import annotations

from apps.llm_agents.src.embedding_service import EmbeddingService
from apps.llm_agents.src.memory import LayeredMemory


def test_memory_add_and_query() -> None:
    memory = LayeredMemory(EmbeddingService())
    memory.add("news:1", "AAPL earnings beat expectations", layer="shallow")
    results = memory.query("AAPL earnings", top_k=1)
    assert results
    assert results[0].key == "news:1"
