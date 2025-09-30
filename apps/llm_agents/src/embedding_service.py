"""Sentence-transformer backed embedding utilities with graceful fallback."""
from __future__ import annotations

import hashlib
import logging
import threading
from typing import Iterable

import numpy as np

logger = logging.getLogger(__name__)

DEFAULT_MODEL = "sentence-transformers/all-MiniLM-L6-v2"
FALLBACK_DIM = 64


class EmbeddingService:
    """Produce embeddings for text using sentence-transformers when available."""

    def __init__(self, model_name: str = DEFAULT_MODEL) -> None:
        self.model_name = model_name
        self._lock = threading.Lock()
        self._model = None
        self._embed_dim = FALLBACK_DIM
        try:  # pragma: no cover - heavy dependency
            from sentence_transformers import SentenceTransformer  # type: ignore

            self._SentenceTransformer = SentenceTransformer
        except Exception as exc:  # noqa: BLE001
            logger.warning("SentenceTransformer not available (%s); using hashed fallback", exc)
            self._SentenceTransformer = None

    @property
    def embedding_dim(self) -> int:
        return self._embed_dim

    def embed_text(self, text: str) -> np.ndarray:
        if not text:
            return self._fallback_embed("")
        if self._SentenceTransformer is None:
            return self._fallback_embed(text)
        model = self._ensure_model()
        if model is None:
            return self._fallback_embed(text)
        vector = model.encode(text, convert_to_numpy=True, normalize_embeddings=True)
        self._embed_dim = vector.shape[0]
        return vector.astype("float32")

    def embed_batch(self, texts: Iterable[str], batch_size: int = 32) -> np.ndarray:
        texts = list(texts)
        if self._SentenceTransformer is None:
            return np.vstack([self._fallback_embed(text) for text in texts])
        model = self._ensure_model()
        if model is None:
            return np.vstack([self._fallback_embed(text) for text in texts])
        vectors = model.encode(
            texts,
            convert_to_numpy=True,
            batch_size=batch_size,
            normalize_embeddings=True,
        )
        self._embed_dim = vectors.shape[1]
        return vectors.astype("float32")

    def similarity(self, a: np.ndarray, b: np.ndarray) -> float:
        if a.shape != b.shape:
            raise ValueError("Embeddings must share the same dimension")
        denom = np.linalg.norm(a) * np.linalg.norm(b)
        if denom == 0:
            return 0.0
        return float(np.clip(np.dot(a, b) / denom, -1.0, 1.0))

    def _ensure_model(self):  # pragma: no cover - heavy dependency
        if self._SentenceTransformer is None:
            return None
        if self._model is not None:
            return self._model
        with self._lock:
            if self._model is not None:
                return self._model
            try:
                self._model = self._SentenceTransformer(self.model_name)
                self._embed_dim = self._model.get_sentence_embedding_dimension()
                logger.info("Loaded embedding model '%s' (dim=%s)", self.model_name, self._embed_dim)
            except Exception as exc:  # noqa: BLE001
                logger.warning("Failed to load model '%s' (%s); falling back to hashing", self.model_name, exc)
                self._model = None
            return self._model

    def _fallback_embed(self, text: str) -> np.ndarray:
        digest = hashlib.sha256(text.encode("utf-8")).digest()
        vec = np.frombuffer(digest[:FALLBACK_DIM * 2], dtype=np.uint8).astype(np.float32)
        vec = vec[:FALLBACK_DIM]
        norm = np.linalg.norm(vec)
        if norm == 0:
            return vec
        return (vec / norm).astype("float32")


__all__ = ["EmbeddingService", "DEFAULT_MODEL"]
