from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from .models import IocObservation, SourceName


def normalized_observation(source: SourceName, record: dict[str, Any]) -> IocObservation:
    value = record.get("ioc_value") or record.get("url") or record.get("sha256_hash") or ""
    observed = record.get("first_seen") or record.get("date_added") or datetime.now(timezone.utc)
    if isinstance(observed, str):
        observed = datetime.fromisoformat(observed.replace(" UTC", "+00:00").replace("Z", "+00:00"))
    return IocObservation(
        source=source,
        source_record_id=str(record.get("id") or record.get("url_id") or record.get("sha256_hash")),
        indicator_type=str(record.get("ioc_type") or ("url" if record.get("url") else "sha256")),
        indicator_value=str(value),
        observed_at=observed,
        tags=list(record.get("tags") or []),
        confidence=record.get("confidence_level"),
        malware_family=record.get("malware"),
        metadata={key: value for key, value in record.items() if key not in {"data", "file", "sample"}},
    )