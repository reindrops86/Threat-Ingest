from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from threat_ingestion.application.enrich_and_cluster import (
    load_indicator_facts,
    run_cluster_detection,
)
from threat_ingestion.persistence.database import Base
from threat_ingestion.persistence.models import EnrichmentRecord, IndicatorRecord, ObservationRecord
from threat_ingestion.persistence.repositories import IngestionRepository


def _session() -> Session:
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return Session(engine)


def test_ip_port_observation_merges_with_ip_enrichment_for_clustering() -> None:
    session = _session()
    ip_port_indicator = IndicatorRecord(indicator_type="ip:port", canonical_value="1.2.3.4:8080")
    ip_indicator = IndicatorRecord(indicator_type="ip", canonical_value="1.2.3.4")
    other_indicator = IndicatorRecord(indicator_type="ip", canonical_value="5.6.7.8")
    session.add_all([ip_port_indicator, ip_indicator, other_indicator])
    session.flush()

    now = datetime.now(timezone.utc)
    session.add(
        ObservationRecord(
            indicator_id=ip_port_indicator.id,
            source="threatfox",
            source_record_id="rec-1",
            observed_at=now,
            metadata_json={"malware": "redline"},
        )
    )
    session.add(
        EnrichmentRecord(
            indicator_id=ip_indicator.id,
            provider="rdap",
            observed_at=now,
            asn=64512,
            asn_name="Example",
            country="NL",
            resolved_ips=[],
            related_domains=[],
            cert_fingerprints=[],
            classification=None,
            tags=[],
            raw_json={},
            error=None,
        )
    )
    session.add(
        EnrichmentRecord(
            indicator_id=other_indicator.id,
            provider="rdap",
            observed_at=now,
            asn=64512,
            asn_name="Example",
            country="NL",
            resolved_ips=[],
            related_domains=[],
            cert_fingerprints=[],
            classification=None,
            tags=[],
            raw_json={},
            error=None,
        )
    )
    session.commit()

    facts, ids_by_key = load_indicator_facts(session)

    assert len(facts) == 2
    merged = next(f for f in facts if f.indicator_value == "1.2.3.4")
    assert merged.indicator_type == "ip"
    assert merged.asns == {64512}
    assert merged.malware_families == {"redline"}
    assert set(ids_by_key["ip:1.2.3.4"]) == {ip_port_indicator.id, ip_indicator.id}

    repository = IngestionRepository(session)
    clusters = run_cluster_detection(session, repository)

    assert len(clusters) == 1
    member_values = {member.indicator_value for member in clusters[0].members}
    assert member_values == {"1.2.3.4", "5.6.7.8"}
