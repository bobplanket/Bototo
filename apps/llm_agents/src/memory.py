from __future__ import annotations

import datetime as dt
import math
from dataclasses import dataclass, field
from typing import Dict, Iterable

import numpy as np

from autollm_trader.logger import get_logger

from .embedding_service import EmbeddingService
from .vector_store import VectorStore

logger = get_logger(__name__)

LAYER_CONFIG = {
    "shallow": {"q": 14.0, "alpha": 0.95, "v": 1.0, "importance_threshold": 2.0},
    "intermediate": {"q": 90.0, "alpha": 0.97, "v": 2.0, "importance_threshold": 3.0},
    "deep": {"q": 365.0, "alpha": 0.99, "v": 3.0, "importance_threshold": 5.0},
}


@dataclass
class MemoryRecord:
    key: str
    text: str
    ts: dt.datetime
    layer: str
    embedding: np.ndarray
    importance: float
    metadata: dict[str, str] = field(default_factory=dict)


class LayerIndex:
    def __init__(self, layer: str, store: VectorStore) -> None:
        self.layer = layer
        self.store = store
        self.records: Dict[str, MemoryRecord] = {}

    def add(self, record: MemoryRecord) -> None:
        self.records[record.key] = record
        self.store.upsert(record.key, record.embedding, {"layer": record.layer})

    def search(self, embedding: np.ndarray, k: int) -> list[MemoryRecord]:
        hits = self.store.search(embedding, limit=k)
        results: list[MemoryRecord] = []
        for point_id, score in hits:
            record = self.records.get(point_id)
            if record is None:
                continue
            record.metadata["relevancy"] = f"{score:.4f}"
            results.append(record)
        return results

    def prune(self) -> None:
        if not self.records:
            return
        kept: Dict[str, MemoryRecord] = {}
        removable: list[str] = []
        for key, record in self.records.items():
            cfg = LAYER_CONFIG[record.layer]
            delta_days = (dt.datetime.now(tz=dt.timezone.utc) - record.ts).days
            s_recency = math.exp(-delta_days / cfg["q"])
            if s_recency < 0.05 or record.importance < cfg["importance_threshold"]:
                removable.append(key)
            else:
                kept[key] = record
        self.records = kept
        if removable:
            self.store.delete(removable)


class LayeredMemory:
    def __init__(
        self,
        embedding_service: EmbeddingService | None = None,
        *,
        store_url: str | None = None,
        store_api_key: str | None = None,
    ) -> None:
        self.embedding_service = embedding_service or EmbeddingService()
        # Warmup to ensure embedding dimension known
        _ = self.embedding_service.embed_text("warmup")
        self.layers: Dict[str, LayerIndex] = {
            layer: LayerIndex(layer, VectorStore(f"memory_{layer}", self.embedding_service.embedding_dim, url=store_url, api_key=store_api_key))
            for layer in LAYER_CONFIG
        }

    def embed(self, text: str) -> np.ndarray:
        return self.embedding_service.embed_text(text)

    def add(self, key: str, text: str, layer: str, metadata: dict[str, str] | None = None) -> None:
        if layer not in self.layers:
            raise ValueError(f"Unknown layer {layer}")
        embedding = self.embed(text)
        cfg = LAYER_CONFIG[layer]
        record = MemoryRecord(
            key=key,
            text=text,
            ts=dt.datetime.now(tz=dt.timezone.utc),
            layer=layer,
            embedding=embedding,
            importance=cfg["v"],
            metadata=metadata or {},
        )
        self.layers[layer].add(record)
        logger.debug("Memory stored", extra={"key": key, "layer": layer})

    def query(self, text: str, top_k: int = 5) -> list[MemoryRecord]:
        embedding = self.embed(text)
        candidates: list[MemoryRecord] = []
        for layer, index in self.layers.items():
            cfg = LAYER_CONFIG[layer]
            for record in index.search(embedding, top_k):
                delta_days = (dt.datetime.now(tz=dt.timezone.utc) - record.ts).days
                s_recency = math.exp(-delta_days / cfg["q"])
                relevancy = float(record.metadata.get("relevancy", "0"))
                importance = cfg["v"] * (cfg["alpha"] ** delta_days)
                total = s_recency + relevancy + importance
                record.metadata.update(
                    {
                        "recency": f"{s_recency:.4f}",
                        "importance_score": f"{importance:.4f}",
                        "total": f"{total:.4f}",
                    }
                )
                candidates.append(record)
        candidates.sort(key=lambda rec: float(rec.metadata.get("total", "0")), reverse=True)
        return candidates[:top_k]

    def prune(self) -> None:
        for index in self.layers.values():
            index.prune()


__all__ = ["LayeredMemory", "MemoryRecord"]
