from __future__ import annotations

from functools import lru_cache
from os import getenv

from dotenv import load_dotenv
from pydantic import BaseModel, Field

load_dotenv()


class Settings(BaseModel):
    abuse_ch_auth_key: str | None = Field(default_factory=lambda: getenv("ABUSE_CH_AUTH_KEY"))
    database_url: str = Field(
        default_factory=lambda: getenv(
            "DATABASE_URL", "postgresql+psycopg://threat_ingest:change-me@localhost:5432/threat_ioc"
        )
    )
    timeout_seconds: float = Field(default_factory=lambda: float(getenv("COLLECTION_TIMEOUT_SECONDS", "20")))
    max_retries: int = Field(default_factory=lambda: int(getenv("COLLECTION_MAX_RETRIES", "3")))
    rate_limit_per_minute: int = Field(
        default_factory=lambda: int(getenv("COLLECTION_RATE_LIMIT_PER_MINUTE", "30"))
    )
    schedule_minutes: int = Field(default_factory=lambda: int(getenv("COLLECTION_SCHEDULE_MINUTES", "60")))


@lru_cache
def get_settings() -> Settings:
    return Settings()