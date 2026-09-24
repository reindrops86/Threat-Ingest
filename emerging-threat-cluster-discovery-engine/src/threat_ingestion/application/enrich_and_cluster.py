from __future__ import annotations

from collections import defaultdict

from sqlalchemy import select
from sqlalchemy.orm import Session

from threat_ingestion.clustering.graph import IndicatorFacts, detect_clusters
from threat_ingestion.domain.models import ClusterResult
from threat_ingestion.persistence.models import EnrichmentRecord, IndicatorRecord, ObservationRecord
from threat_ingestion.persistence.repositories import IngestionRepository

# ThreatFox reports "ip:port" for network indicators; URLhaus/MalwareBazaar report
# plain "domain". Both are enrichable once the port is stripped from the value.
_ENRICHABLE_TYPES = {"domain", "ip", "ip:port"}


def _as_enrichment_target(indicator_type: str, canonical_value: str) -> tuple[str, str]:
    if indicator_type == "ip:port":
        return "ip", canonical_value.split(":", 1)[0]
    return indicator_type, canonical_value


def load_indicator_facts(session: Session) -> tuple[list[IndicatorFacts], dict[str, list[int]]]:
    """Builds one IndicatorFacts per *canonical* indicator from every observation +
    enrichment event recorded so far. An "ip:port" observation (ThreatFox) and the
    plain "ip" enrichment record it produced are merged into a single node keyed by
    the bare IP, so ASN/cert overlap discovered via enrichment actually links back
    to the original observation instead of sitting on an orphaned node. Returns a
    key -> [indicator_id, ...] map (all underlying rows) for cluster persistence."""
    indicators = session.scalars(select(IndicatorRecord)).all()
    observations = session.scalars(select(ObservationRecord)).all()
    enrichments = session.scalars(select(EnrichmentRecord)).all()

    facts_by_key: dict[str, IndicatorFacts] = {}
    key_by_indicator_id: dict[int, str] = {}
    ids_by_key: dict[str, list[int]] = defaultdict(list)

    for indicator in indicators:
        canon_type, canon_value = _as_enrichment_target(indicator.indicator_type, indicator.canonical_value)
        key = f"{canon_type}:{canon_value}"
        if key not in facts_by_key:
            facts_by_key[key] = IndicatorFacts(indicator_type=canon_type, indicator_value=canon_value)
        key_by_indicator_id[indicator.id] = key
        ids_by_key[key].append(indicator.id)

    for observation in observations:
        key = key_by_indicator_id.get(observation.indicator_id)
        if key is None:
            continue
        fact = facts_by_key[key]
        metadata = observation.metadata_json or {}
        family = metadata.get("malware") or metadata.get("malware_family")
        if family:
            fact.malware_families.add(str(family))
        if fact.first_seen is None or observation.observed_at < fact.first_seen:
            fact.first_seen = observation.observed_at

    for enrichment in enrichments:
        key = key_by_indicator_id.get(enrichment.indicator_id)
        if key is None or enrichment.error:
            continue
        fact = facts_by_key[key]
        if enrichment.asn:
            fact.asns.add(enrichment.asn)
        fact.cert_fingerprints.update(enrichment.cert_fingerprints or [])
        fact.resolved_ips.update(enrichment.resolved_ips or [])
        fact.nameservers.update(enrichment.related_domains or [])

    return list(facts_by_key.values()), dict(ids_by_key)


def run_cluster_detection(session: Session, repository: IngestionRepository) -> list[ClusterResult]:
    facts, ids_by_key = load_indicator_facts(session)
    clusters = detect_clusters(facts)
    for cluster in clusters:
        indicator_ids: set[int] = set()
        for member in cluster.members:
            indicator_ids.update(ids_by_key.get(f"{member.indicator_type}:{member.indicator_value}", []))
        repository.save_cluster(cluster, sorted(indicator_ids))
    repository.session.commit()
    return clusters


def indicators_pending_enrichment(session: Session, limit: int) -> list[tuple[str, str]]:
    """Domain/IP indicators observed by feed collection, oldest-first, so the
    enrichment engine works through the whole indicator set over successive runs."""
    indicators = session.scalars(
        select(IndicatorRecord)
        .where(IndicatorRecord.indicator_type.in_(_ENRICHABLE_TYPES))
        .order_by(IndicatorRecord.id)
        .limit(limit)
    ).all()
    return [_as_enrichment_target(indicator.indicator_type, indicator.canonical_value) for indicator in indicators]
