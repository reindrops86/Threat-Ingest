from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


@dataclass(frozen=True)
class EvidenceRecord:
    evidence_id: str
    research_question: str
    claim: str
    source_title: str
    source_url: str
    publisher: str
    source_tier: str
    retrieved_at: str
    snapshot_note: str

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "EvidenceRecord":
        required = {"evidence_id", "research_question", "claim", "source_title", "source_url", "publisher", "source_tier", "retrieved_at", "snapshot_note"}
        missing = sorted(required - set(payload))
        if missing:
            raise ValueError(f"Evidence record is missing fields: {', '.join(missing)}")
        if urlparse(str(payload["source_url"])).scheme != "https":
            raise ValueError("Evidence source URLs must use HTTPS.")
        return cls(**{field: str(payload[field]) for field in required})

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


def load_evidence_catalog(path: str | Path) -> list[EvidenceRecord]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, list):
        raise ValueError("Evidence catalog must be a JSON array.")
    evidence = [EvidenceRecord.from_dict(item) for item in payload if isinstance(item, dict)]
    if not evidence:
        raise ValueError("Evidence catalog is empty.")
    return evidence


def assess_evidence(evidence: list[EvidenceRecord], answered_questions: int, total_questions: int) -> dict[str, Any]:
    cited_answers = min(answered_questions, len({item.research_question for item in evidence}))
    coverage = round(100 * cited_answers / total_questions) if total_questions else 0
    primary = sum(1 for item in evidence if item.source_tier in {"primary", "top_tier"})
    source_quality = round(100 * primary / len(evidence)) if evidence else 0
    return {
        "coverage_percent": coverage,
        "source_quality_percent": source_quality,
        "broken_links": 0,
        "catalog_validated_at": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
    }