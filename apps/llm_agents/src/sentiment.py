"""Embedding-based sentiment scoring for financial text."""
from __future__ import annotations

from typing import Dict, Iterable, Tuple

import numpy as np

from .embedding_service import EmbeddingService

SENTIMENT_ANCHORS = {
    "very_bullish": "Exceptional upside, strong buy conviction, significant positive catalysts.",
    "bullish": "Positive outlook, moderate upside expected based on fundamentals.",
    "neutral": "Balanced view with limited conviction either way, monitoring developments.",
    "bearish": "Negative outlook, elevated risks outweigh potential upside.",
    "very_bearish": "Severe downside risk, strong sell recommendation due to critical issues.",
}


class SentimentAnalyzer:
    def __init__(self, embedding_service: EmbeddingService) -> None:
        self.embedding_service = embedding_service
        self._anchor_embeddings = self._build_anchor_embeddings()

    def analyze_sentiment(self, text: str) -> Dict[str, float]:
        if not text.strip():
            return {label: (1.0 if label == "neutral" else 0.0) for label in SENTIMENT_ANCHORS}
        vector = self.embedding_service.embed_text(text)
        scores = np.array([self.embedding_service.similarity(vector, anchor) for anchor in self._anchor_embeddings.values()])
        # Stabilise scores using softmax over similarities
        exp_scores = np.exp(scores - np.max(scores))
        probs = exp_scores / exp_scores.sum()
        return {label: float(prob) for label, prob in zip(self._anchor_embeddings.keys(), probs)}

    def get_dominant_sentiment(self, text: str) -> Tuple[str, float]:
        scores = self.analyze_sentiment(text)
        label = max(scores.items(), key=lambda item: item[1])[0]
        return label, scores[label]

    def _build_anchor_embeddings(self) -> Dict[str, np.ndarray]:
        return {
            label: self.embedding_service.embed_text(sentence)
            for label, sentence in SENTIMENT_ANCHORS.items()
        }


__all__ = ["SentimentAnalyzer", "SENTIMENT_ANCHORS"]
