from __future__ import annotations

from datetime import datetime, timezone
from typing import List, Literal, Optional

from pydantic import BaseModel, Field


SignalType = Literal[
    "repo_name",
    "keyword_match",
    "domain",
    "alias",
    "threat_chatter",
    "url",
    "infrastructure",
]

Severity = Literal["low", "medium", "high", "critical"]


class SignalRecord(BaseModel):
    id: str = Field(..., description="Stable identifier for the signal.")
    entity: str = Field(..., description="Normalized entity or relevant indicator.")
    signal_type: SignalType
    source: str
    source_type: str
    title: Optional[str] = None
    snippet: Optional[str] = None
    url: Optional[str] = None
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    severity: Severity = "low"
    tags: List[str] = Field(default_factory=list)
    discovered_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    raw_metadata: dict = Field(default_factory=dict)

    class Config:
        extra = "allow"
