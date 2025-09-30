from __future__ import annotations

import logging
import os
from typing import Any

from pythonjsonlogger import jsonlogger


class _JsonFormatter(jsonlogger.JsonFormatter):
    def add_fields(self, log_record: dict[str, Any], record: logging.LogRecord, message_dict: dict[str, Any]) -> None:
        super().add_fields(log_record, record, message_dict)
        log_record.setdefault("severity", record.levelname)
        log_record.setdefault("logger", record.name)
        log_record.setdefault("module", record.module)
        log_record.setdefault("line", record.lineno)


def configure_logging(level: str = "INFO") -> None:
    root = logging.getLogger()
    if root.handlers:
        for handler in root.handlers:
            root.removeHandler(handler)
    handler = logging.StreamHandler()
    formatter = _JsonFormatter("%(asctime)s %(name)s %(levelname)s %(message)s")
    handler.setFormatter(formatter)
    root.addHandler(handler)
    root.setLevel(level.upper())


def get_logger(name: str) -> logging.Logger:
    configure_logging(os.getenv("LOG_LEVEL", "INFO"))
    return logging.getLogger(name)


__all__ = ["configure_logging", "get_logger"]
