from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from threat_ingestion.briefing_bridge import build_manual_signals, write_manual_signals
from threat_ingestion.persistence.database import Base
from threat_ingestion.persistence.models import (
    ClusterMemberRecord,
    EnrichmentRecord,
    IndicatorRecord,
    InfrastructureClusterRecord,
    KevEntryRecord,
)


def _session() -> Session:
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return Session(engine)


def test_build_manual_signals_includes_cluster_and_kev_exposure(tmp_path: Path) -> None:
    session = _session()
    now = datetime.now(timezone.utc)

    domain_a = IndicatorRecord(indicator_type="domain", canonical_value="bad-one.test")
    domain_b = IndicatorRecord(indicator_type="domain", canonical_value="bad-two.test")
    exposed_ip = IndicatorRecord(indicator_type="ip", canonical_value="9.9.9.9")
    session.add_all([domain_a, domain_b, exposed_ip])
    session.flush()

    cluster = InfrastructureClusterRecord(
        cluster_key="TI-2026-0001",
        generated_at=now,
        first_observed=now,
        confidence_score=0.72,
        confidence_label="high",
        evidence_json=[{"kind": "cert_reuse", "detail": "shared TLS certificate abc123", "members": []}],
    )
    session.add(cluster)
    session.flush()
    session.add_all(
        [
            ClusterMemberRecord(cluster_id=cluster.id, indicator_id=domain_a.id),
            ClusterMemberRecord(cluster_id=cluster.id, indicator_id=domain_b.id),
        ]
    )

    session.add(
        KevEntryRecord(
            cve_id="CVE-2021-44228",
            vendor_project="Apache",
            product="Log4j2",
            vulnerability_name="Log4Shell",
            date_added=now,
            short_description="RCE",
            required_action="Patch",
            due_date=now,
            known_ransomware_use=True,
            cvss_score=10.0,
            epss_score=0.94,
            epss_percentile=0.99,
            synced_at=now,
        )
    )
    session.add(
        EnrichmentRecord(
            indicator_id=exposed_ip.id,
            provider="shodan",
            observed_at=now,
            asn=None,
            asn_name=None,
            country=None,
            resolved_ips=[],
            related_domains=[],
            cert_fingerprints=[],
            classification=None,
            tags=["CVE-2021-44228"],
            raw_json={},
            error=None,
        )
    )
    session.commit()

    signals = build_manual_signals(session)

    cluster_signals = [s for s in signals if s["signal_type"] == "multi_source_corroboration"]
    exposure_signals = [s for s in signals if s["signal_type"] == "environment_reachable"]

    assert len(cluster_signals) == 1
    assert cluster_signals[0]["subject"] == "TI-2026-0001"
    assert cluster_signals[0]["source_reliability"] == "B"
    assert "bad-one.test" in cluster_signals[0]["detail"]

    assert len(exposure_signals) == 1
    assert exposure_signals[0]["subject"] == "CVE-2021-44228"
    assert "9.9.9.9" in exposure_signals[0]["detail"]

    # Every emitted signal must be constructible by the companion project's
    # Signal(**entry) loader: only known fields, all required ones present.
    required = {"signal_type", "subject", "source", "source_reliability", "confidence", "detail", "observed_at", "collected_at"}
    for signal in signals:
        assert required <= signal.keys()

    output = tmp_path / "manual_signals.json"
    count = write_manual_signals(session, output)
    assert count == len(signals)
    assert json.loads(output.read_text(encoding="utf-8")) == signals
