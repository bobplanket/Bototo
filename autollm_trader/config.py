from __future__ import annotations

import pathlib
from functools import lru_cache
from typing import Literal

from pydantic import BaseModel, Field, HttpUrl
from pydantic_settings import BaseSettings, SettingsConfigDict


class AuthSettings(BaseModel):
    jwt_secret: str = Field(default="replace_me")
    jwt_algorithm: str = Field(default="HS256")
    access_token_expire_minutes: int = Field(default=15)
    refresh_token_expire_minutes: int = Field(default=60)
    webauthn_rp_id: str = Field(default="autollm.local")
    webauthn_rp_name: str = Field(default="AutoLLM Trader")
    webauthn_origin: HttpUrl | None = None
    totp_skew: int = Field(default=1)


class DatabaseSettings(BaseModel):
    host: str = Field(default="postgres")
    port: int = Field(default=5432)
    database: str = Field(default="autollm")
    user: str = Field(default="autollm")
    password: str = Field(default="changeme")

    @property
    def dsn(self) -> str:
        return (
            f"postgresql+asyncpg://{self.user}:{self.password}@{self.host}:{self.port}/{self.database}"
        )

    @property
    def async_dsn(self) -> str:
        return f"postgresql://{self.user}:{self.password}@{self.host}:{self.port}/{self.database}"


class DuckDbSettings(BaseModel):
    path: pathlib.Path = Field(default=pathlib.Path("data/storage/features.duckdb"))
    parquet_root: pathlib.Path = Field(default=pathlib.Path("data/storage/parquet"))


class MessagingSettings(BaseModel):
    nats_url: str = Field(default="nats://nats:4222")
    drain_timeout: int = 5
    intent_subject: str = "llm.intent.proposed"
    approved_subject: str = "risk.order.approved"
    rejected_subject: str = "risk.order.rejected"
    execution_events_subject: str = "exec.order"


class BrokerSettings(BaseModel):
    ib_enabled: bool = Field(default=False)
    ib_host: str = Field(default="ib-gateway")
    ib_port: int = Field(default=4002)
    ib_client_id: int = Field(default=17)
    ib_account: str = Field(default="DU0000000")
    live_flag: Literal[0, 1] = Field(default=0)
    freqtrade_host: HttpUrl | None = None
    freqtrade_token: str | None = None
    live_flag: Literal[0, 1] = Field(default=0)


class SecretsSettings(BaseModel):
    llm_signing_private_key_path: pathlib.Path = Field(default=pathlib.Path("secrets/llm_signing_key.age"))
    risk_signing_private_key_path: pathlib.Path = Field(default=pathlib.Path("secrets/risk_signing_key.age"))
    llm_public_key_path: pathlib.Path = Field(default=pathlib.Path("secrets/llm_pub.key"))
    risk_public_key_path: pathlib.Path = Field(default=pathlib.Path("secrets/risk_pub.key"))


class MonitoringSettings(BaseModel):
    prometheus_pushgateway_url: HttpUrl | None = None
    loki_http_url: HttpUrl | None = None
    grafana_url: HttpUrl | None = None


class ReporterSettings(BaseModel):
    smtp_host: str = Field(default="smtp.example.com")
    smtp_port: int = Field(default=587)
    smtp_username: str = Field(default="reporter")
    smtp_password: str = Field(default="changeme")
    report_recipients: list[str] = Field(default_factory=list)
    telegram_bot_token: str | None = None
    telegram_chat_id: str | None = None


class RiskSettings(BaseModel):
    risk_config_path: pathlib.Path = Field(default=pathlib.Path("configs/risk.yaml"))
    symbols_config_path: pathlib.Path = Field(default=pathlib.Path("configs/symbols.yaml"))
    feeds_config_path: pathlib.Path = Field(default=pathlib.Path("configs/feeds.yaml"))
    nav_initial_usd: float = Field(default=1_000_000.0)
    kill_switch_file: pathlib.Path = Field(default=pathlib.Path("data/kill_switch.flag"))


class LLMSettings(BaseModel):
    provider: Literal["openai", "mock"] = Field(default="openai")
    model: str = Field(default="gpt-4o-mini")
    temperature: float = Field(default=0.2, ge=0.0, le=1.0)
    max_output_tokens: int = Field(default=512, gt=0)
    token_budget_per_intent: int = Field(default=2000, gt=0)
    api_key_env: str = Field(default="OPENAI_API_KEY")


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="allow",
        populate_by_name=True,
    )

    environment: str = Field(default="development")
    log_level: str = Field(default="INFO")
    timezone: str = Field(default="UTC")
    redis_host: str = Field(default="redis")
    redis_port: int = Field(default=6379)
    redis_db: int = Field(default=0)
    redis_username: str | None = None
    redis_password: str | None = None
    redis_tls_enabled: bool = Field(default=False, alias="REDIS_TLS_ENABLED")
    redis_url_override: str | None = Field(default=None, alias="REDIS_URL")
    binance_api_key: str | None = Field(default=None, alias="BINANCE_API_KEY")
    binance_api_secret: str | None = Field(default=None, alias="BINANCE_API_SECRET")
    coinbase_api_key: str | None = Field(default=None, alias="COINBASE_API_KEY")
    coinbase_api_secret: str | None = Field(default=None, alias="COINBASE_API_SECRET")
    coinbase_api_passphrase: str | None = Field(default=None, alias="COINBASE_API_PASSPHRASE")
    kraken_api_key: str | None = Field(default=None, alias="KRAKEN_API_KEY")
    kraken_api_secret: str | None = Field(default=None, alias="KRAKEN_API_SECRET")

    auth: AuthSettings = Field(default_factory=AuthSettings)
    database: DatabaseSettings = Field(default_factory=DatabaseSettings)
    duckdb: DuckDbSettings = Field(default_factory=DuckDbSettings)
    messaging: MessagingSettings = Field(default_factory=MessagingSettings)
    brokers: BrokerSettings = Field(default_factory=BrokerSettings)
    secrets: SecretsSettings = Field(default_factory=SecretsSettings)
    monitoring: MonitoringSettings = Field(default_factory=MonitoringSettings)
    reporter: ReporterSettings = Field(default_factory=ReporterSettings)
    risk: RiskSettings = Field(default_factory=RiskSettings)
    llm: LLMSettings = Field(default_factory=LLMSettings)

    @property
    def redis_url(self) -> str:
        if self.redis_url_override:
            return self.redis_url_override

        protocol = "rediss" if self.redis_tls_enabled else "redis"

        auth = ""
        if self.redis_username and self.redis_password:
            auth = f"{self.redis_username}:{self.redis_password}@"
        elif self.redis_password:
            auth = f":{self.redis_password}@"
        elif self.redis_username:
            auth = f"{self.redis_username}@"

        return f"{protocol}://{auth}{self.redis_host}:{self.redis_port}/{self.redis_db}"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()


__all__ = ["Settings", "get_settings"]
