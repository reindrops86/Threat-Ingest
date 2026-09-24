from __future__ import annotations

from datetime import datetime, timezone

from threat_ingestion.clustering.graph import IndicatorFacts, detect_clusters


def _fact(indicator_type: str, value: str, **kwargs) -> IndicatorFacts:
    return IndicatorFacts(indicator_type=indicator_type, indicator_value=value, **kwargs)


def test_shared_asn_and_cert_produce_high_confidence_cluster() -> None:
    facts = [
        _fact("domain", "bad-one.test", asns={64512}, cert_fingerprints={"aaaa1111"}),
        _fact("domain", "bad-two.test", asns={64512}, cert_fingerprints={"aaaa1111"}),
        _fact("domain", "unrelated.test", asns={99999}),
    ]

    clusters = detect_clusters(facts)

    assert len(clusters) == 1
    cluster = clusters[0]
    member_values = {member.indicator_value for member in cluster.members}
    assert member_values == {"bad-one.test", "bad-two.test"}
    assert cluster.confidence_label == "high"
    evidence_kinds = {evidence.kind for evidence in cluster.evidence}
    assert evidence_kinds == {"asn_overlap", "cert_reuse"}


def test_single_weak_signal_is_low_confidence() -> None:
    facts = [
        _fact("domain", "one.test", malware_families={"redline"}),
        _fact("domain", "two.test", malware_families={"redline"}),
    ]

    clusters = detect_clusters(facts)

    assert len(clusters) == 1
    assert clusters[0].confidence_label == "low"


def test_indicators_without_shared_signals_are_not_clustered() -> None:
    facts = [
        _fact("domain", "alpha.test", asns={1}),
        _fact("domain", "beta.test", asns={2}),
    ]

    assert detect_clusters(facts) == []


def test_first_observed_uses_earliest_member_timestamp() -> None:
    earlier = datetime(2026, 1, 1, tzinfo=timezone.utc)
    later = datetime(2026, 2, 1, tzinfo=timezone.utc)
    facts = [
        _fact("domain", "one.test", asns={10}, first_seen=later),
        _fact("domain", "two.test", asns={10}, first_seen=earlier),
    ]

    clusters = detect_clusters(facts)

    assert clusters[0].first_observed == earlier
