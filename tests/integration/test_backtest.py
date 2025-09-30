from __future__ import annotations

import pandas as pd
import pytest

from apps.backtest_engine.src.cli import run_backtest


@pytest.mark.parametrize("strategy_return", [0.05])
def test_run_backtest(tmp_path, monkeypatch, strategy_return):
    data = pd.DataFrame(
        {
            "Open": [100, 101, 102, 103, 104, 105, 106, 107, 108, 109],
            "High": [101, 102, 103, 104, 105, 106, 107, 108, 109, 110],
            "Low": [99, 100, 101, 102, 103, 104, 105, 106, 107, 108],
            "Close": [100, 101, 102, 103, 104, 105, 106, 107, 108, 109],
            "Volume": [1_000] * 10,
        }
    )
    monkeypatch.setattr("yfinance.download", lambda *args, **kwargs: data)
    report = run_backtest("AAPL", "2024-01-01", "2024-01-10", tmp_path)
    assert report.exists()
