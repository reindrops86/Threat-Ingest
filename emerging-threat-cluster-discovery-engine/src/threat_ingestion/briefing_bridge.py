from __future__ import annotations

import json
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from threat_ingestion.application.kev_correlation import kev_exposure_matches
from threat_ingestion.persistence.models import (
    ClusterMemberRecord,
    IndicatorRecord,
    InfrastructureClusterRecord,
)

# Maps our confidence label onto the companion project's Admiralty-style
# source_reliability scale (A=fully reliable .. F=cannot be judged).
_RELIABILITY_BY_CONFIDENCE = {"high": "B", "medium": "C", "low": "D"}


def build_manual_signals(session: Session) -> list[dict[str, Any]]:
    """Builds a list of dicts matching the `Signal` schema consumed by
    Daily-Cyber-Threat-Intelligence-Briefing's `data/manual_signals.json`, so that
    project's live report can incorporate Threat-Ingest's independently
    discovered infrastructure clusters and directly observed KEV exposure —
    evidence its own live mode has no source for on its own."""
    today = date.today().isoformat()
    collected_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    signals: list[dict[str, Any]] = []

    clusters = session.scalars(select(InfrastructureClusterRecord)).all()
    for cluster in clusters:
        indicator_ids = [
            member.indicator_id
            for member in session.scalars(
                select(ClusterMemberRecord).where(ClusterMemberRecord.cluster_id == cluster.id)
            ).all()
        ]
        member_values = sorted(
            indicator.canonical_value
            for indicator in (
                session.scalars(select(IndicatorRecord).where(IndicatorRecord.id.in_(indicator_ids))).all()
                if indicator_ids
                else []
            )
        )
        reasons = "; ".join(f"{entry['kind']}: {entry['detail']}" for entry in (cluster.evidence_json or []))
        observed = cluster.first_observed or cluster.generated_at
        signals.append(
            {
                "signal_type": "multi_source_corroboration",
                "subject": cluster.cluster_key,
                "source": "threat-ingest-cluster",
                "source_reliability": _RELIABILITY_BY_CONFIDENCE.get(cluster.confidence_label, "C"),
                "confidence": round(min(max(cluster.confidence_score, 0.0), 1.0), 2),
                "detail": (
                    f"Threat-Ingest infrastructure cluster {cluster.cluster_key} "
                    f"({len(member_values)} indicators: {', '.join(member_values) or 'none'}). {reasons}"
                ),
                "observed_at": observed.date().isoformat(),
                "collected_at": collected_at,
                "upstream_id": f"threat-ingest-cluster:{cluster.cluster_key}",
            }
        )

    for indicator_value, cve_id, provider in kev_exposure_matches(session):
        signals.append(
            {
                "signal_type": "environment_reachable",
                "subject": cve_id,
                "source": f"threat-ingest-{provider}",
                "source_reliability": "B",
                "confidence": 0.75,
                "detail": (
                    f"{provider} observed {indicator_value} exposing {cve_id}, which is also in the "
                    "local CISA KEV catalog. This is direct scan evidence, not a self-declared "
                    "watchlist entry."
                ),
                "observed_at": today,
                "collected_at": collected_at,
                "upstream_id": f"threat-ingest-exposure:{indicator_value}:{cve_id}",
            }
        )

    return signals


def write_manual_signals(session: Session, output_path: Path) -> int:
    signals = build_manual_signals(session)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(signals, indent=2), encoding="utf-8")
    return len(signals)
