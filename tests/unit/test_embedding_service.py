from __future__ import annotations

import numpy as np

from apps.llm_agents.src.embedding_service import EmbeddingService


def test_embedding_service_fallback_dimension() -> None:
    service = EmbeddingService(model_name="non-existent-model")
    vector = service.embed_text("Sample text for embedding")
    assert vector.shape[0] == service.embedding_dim
    assert np.isclose(np.linalg.norm(vector), 1, atol=1e-3) or np.linalg.norm(vector) == 0


def test_embedding_service_similarity() -> None:
    service = EmbeddingService()
    a = service.embed_text("positive signal with strong growth")
    b = service.embed_text("strong growth and positive outlook")
    c = service.embed_text("severe risks and negative outlook")
    assert service.similarity(a, b) > service.similarity(a, c)


def test_embedding_service_batch() -> None:
    service = EmbeddingService()
    vectors = service.embed_batch(["alpha", "beta", "gamma"])
    assert vectors.shape[0] == 3
    assert vectors.shape[1] == service.embedding_dim
