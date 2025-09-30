from __future__ import annotations

import datetime as dt
from typing import Any

from pydantic import BaseModel, HttpUrl


class MinifluxEntry(BaseModel):
    id: int
    title: str
    url: HttpUrl
    content: str | None = None
    summary: str | None = None
    published_at: dt.datetime
    categories: list[str] = []


class MinifluxWebhook(BaseModel):
    secret_token: str
    entry: MinifluxEntry

    @classmethod
    def from_payload(cls, payload: dict[str, Any]) -> "MinifluxWebhook":
        return cls.model_validate(payload)


__all__ = ["MinifluxWebhook", "MinifluxEntry"]
