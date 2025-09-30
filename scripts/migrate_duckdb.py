from __future__ import annotations

from autollm_trader.storage.duckdb import DuckDbFeatureStore


def main() -> None:
    store = DuckDbFeatureStore()
    store.close()


if __name__ == "__main__":
    main()
