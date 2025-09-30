"""Abstraction over Qdrant vector store with in-memory fallback."""
from __future__ import annotations

import logging
from typing import Any, Iterable, List, Tuple

import numpy as np

logger = logging.getLogger(__name__)

try:  # pragma: no cover - optional dependency
    from qdrant_client import QdrantClient
    from qdrant_client.http import models as qmodels
except Exception:  # noqa: BLE001
    QdrantClient = None
    qmodels = None


class VectorStore:
    def __init__(
        self,
        collection: str,
        dim: int,
        *,
        url: str | None = None,
        api_key: str | None = None,
    ) -> None:
        self.collection = collection
        self.dim = dim
        self._client = None
        self._in_memory: dict[str, Tuple[np.ndarray, dict[str, Any]]] = {}
        if QdrantClient and url:
            try:
                self._client = QdrantClient(url=url, api_key=api_key)
                self._ensure_collection()
                logger.info("VectorStore using Qdrant collection '%s'", collection)
            except Exception as exc:  # noqa: BLE001
                logger.warning("Qdrant unavailable (%s); using in-memory store", exc)
                self._client = None
        else:
            logger.info("VectorStore running in in-memory mode for collection '%s'", collection)

    def upsert(self, point_id: str, vector: np.ndarray, payload: dict[str, Any] | None = None) -> None:
        payload = payload or {}
        if self._client is None:
            self._in_memory[point_id] = (vector.astype("float32"), payload)
            return
        assert qmodels is not None
        vector_list = vector.astype("float32").tolist()
        self._client.upsert(
            collection_name=self.collection,
            points=[qmodels.PointStruct(id=point_id, vector=vector_list, payload=payload)],
        )

    def delete(self, point_ids: Iterable[str]) -> None:
        ids = list(point_ids)
        if not ids:
            return
        if self._client is None:
            for pid in ids:
                self._in_memory.pop(pid, None)
            return
        assert qmodels is not None
        self._client.delete(collection_name=self.collection, points_selector=qmodels.PointIdsList(points=ids))

    def clear(self) -> None:
        if self._client is None:
            self._in_memory.clear()
            return
        assert qmodels is not None
        self._client.delete_collection(self.collection)
        self._ensure_collection()

    def search(self, vector: np.ndarray, limit: int = 5) -> List[Tuple[str, float]]:
        limit = max(limit, 1)
        if self._client is None:
            if not self._in_memory:
                return []
            vector_norm = np.linalg.norm(vector)
            if vector_norm == 0:
                return []
            norm_vec = vector / vector_norm
            candidates = []
            for key, (stored, _) in self._in_memory.items():
                score = float(np.dot(norm_vec, stored) / (np.linalg.norm(stored) + 1e-9))
                candidates.append((key, score))
            candidates.sort(key=lambda item: item[1], reverse=True)
            return candidates[:limit]
        assert qmodels is not None
        search_result = self._client.search(
            collection_name=self.collection,
            query_vector=vector.astype("float32").tolist(),
            limit=limit,
        )
        return [(hit.id, float(hit.score)) for hit in search_result]

    def payload(self, point_id: str) -> dict[str, Any] | None:
        if self._client is None:
            data = self._in_memory.get(point_id)
            return data[1] if data else None
        assert qmodels is not None
        result = self._client.retrieve(collection_name=self.collection, ids=[point_id])
        if not result:
            return None
        return result[0].payload or {}

    def _ensure_collection(self) -> None:  # pragma: no cover - requires qdrant
        assert QdrantClient is not None and qmodels is not None and self._client is not None
        try:
            self._client.get_collection(self.collection)
        except Exception:  # noqa: BLE001
            self._client.recreate_collection(
                collection_name=self.collection,
                vectors_config=qmodels.VectorParams(size=self.dim, distance=qmodels.Distance.COSINE),
            )


__all__ = ["VectorStore"]
