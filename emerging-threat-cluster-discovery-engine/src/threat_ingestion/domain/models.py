from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, Field

SourceName = Literal["threatfox", "urlhaus", "malwarebazaar"]


class IocObservation(BaseModel):
    source: SourceName
    source_record_id: str
    indicator_type: str
    indicator_value: str
    observed_at: datetime
    tags: list[str] = Field(default_factory=list)
    confidence: int | None = None
    malware_family: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    @property
    def canonical_value(self) -> str:
        return self.indicator_value.strip().lower()


class SourceAttempt(BaseModel):
    source: SourceName
    fetched: int = 0
    accepted: int = 0
    inserted: int = 0
    updated: int = 0
    rejected: int = 0
    retries: int = 0
    status: Literal["success", "failed"]
    error: str | None = None


class CollectionRun(BaseModel):
    run_id: UUID = Field(default_factory=uuid4)
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    ended_at: datetime | None = None
    dry_run: bool = False
    attempts: list[SourceAttempt] = Field(default_factory=list)