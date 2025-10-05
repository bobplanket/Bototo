from __future__ import annotations

from apps.llm_agents.src.embedding_service import EmbeddingService
from apps.llm_agents.src.sentiment import SentimentAnalyzer


def test_sentiment_analyzer_returns_distribution() -> None:
    service = EmbeddingService()
    analyzer = SentimentAnalyzer(service)
    scores = analyzer.analyze_sentiment("The company reported record profits and guidance was raised")
    assert abs(sum(scores.values()) - 1.0) < 1e-6
    assert max(scores, key=scores.get) in scores


def test_sentiment_analyzer_handles_empty_text() -> None:
    analyzer = SentimentAnalyzer(EmbeddingService())
    sentiment, confidence = analyzer.get_dominant_sentiment("")
    assert sentiment == "neutral"
    assert confidence == 1.0
