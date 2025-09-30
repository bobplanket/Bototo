from __future__ import annotations

import argparse
import datetime as dt
import json
from pathlib import Path

import pandas as pd
import yfinance as yf

from autollm_trader.logger import configure_logging, get_logger

configure_logging()
logger = get_logger(__name__)


def run_backtest(symbol: str, start: str, end: str, report_dir: Path) -> Path:
    start_dt = dt.datetime.fromisoformat(start)
    end_dt = dt.datetime.fromisoformat(end)
    logger.info("Downloading historical data", extra={"symbol": symbol, "start": start, "end": end})
    data = yf.download(symbol, start=start_dt, end=end_dt, progress=False)
    if data.empty:
        raise ValueError("No data downloaded")
    data["sma_fast"] = data["Close"].rolling(window=10).mean()
    data["sma_slow"] = data["Close"].rolling(window=30).mean()
    data["signal"] = 0
    data.loc[data["sma_fast"] > data["sma_slow"], "signal"] = 1
    data.loc[data["sma_fast"] < data["sma_slow"], "signal"] = -1
    data["returns"] = data["Close"].pct_change().fillna(0)
    data["strategy"] = data["signal"].shift(1) * data["returns"]
    cumulative = (1 + data[["returns", "strategy"]]).cumprod()
    report = {
        "symbol": symbol,
        "start": start,
        "end": end,
        "buy_and_hold": float(cumulative["returns"].iloc[-1] - 1),
        "strategy_return": float(cumulative["strategy"].iloc[-1] - 1),
        "max_drawdown": float((cumulative["strategy"].cummax() - cumulative["strategy"]).max()),
    }
    report_dir.mkdir(parents=True, exist_ok=True)
    report_file = report_dir / f"backtest_{symbol}_{start}_{end}.json"
    report_file.write_text(json.dumps(report, indent=2))
    logger.info("Backtest complete", extra={"report": str(report_file)})
    return report_file


def main() -> None:
    parser = argparse.ArgumentParser(description="Run simple SMA backtest")
    parser.add_argument("symbol")
    parser.add_argument("--start", required=True)
    parser.add_argument("--end", required=True)
    parser.add_argument("--report-dir", default="reports")
    args = parser.parse_args()
    run_backtest(args.symbol, args.start, args.end, Path(args.report_dir))


if __name__ == "__main__":
    main()
