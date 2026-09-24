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
    greynoise_api_key: str | None = Field(default_factory=lambda: getenv("GREYNOISE_API_KEY"))
    urlscan_api_key: str | None = Field(default_factory=lambda: getenv("URLSCAN_API_KEY"))
    enrichment_batch_limit: int = Field(default_factory=lambda: int(getenv("ENRICHMENT_BATCH_LIMIT", "25")))
    nvd_api_key: str | None = Field(default_factory=lambda: getenv("NVD_API_KEY"))
    epss_batch_size: int = Field(default_factory=lambda: int(getenv("EPSS_BATCH_SIZE", "100")))
    censys_personal_access_token: str | None = Field(
        default_factory=lambda: getenv("CENSYS_PERSONAL_ACCESS_TOKEN")
    )
    censys_organization_id: str | None = Field(default_factory=lambda: getenv("CENSYS_ORGANIZATION_ID"))
    censys_enable_cert_pivot: bool = Field(
        default_factory=lambda: getenv("CENSYS_ENABLE_CERT_PIVOT", "false").lower() == "true"
    )
    shodan_api_key: str | None = Field(default_factory=lambda: getenv("SHODAN_API_KEY"))
    otx_api_key: str | None = Field(default_factory=lambda: getenv("OTX_API_KEY"))
    abuseipdb_api_key: str | None = Field(default_factory=lambda: getenv("ABUSEIPDB_API_KEY"))


@lru_cache
def get_settings() -> Settings:
    return Settings()