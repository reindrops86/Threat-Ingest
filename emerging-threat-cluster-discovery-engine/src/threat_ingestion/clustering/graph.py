from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime

import networkx as nx

from threat_ingestion.domain.models import ClusterEvidence, ClusterMember, ClusterResult

# Weight each signal contributes toward cluster confidence. Cert reuse and ASN
# overlap are strong operational-infrastructure signals; naming/tag overlap alone
# is weaker corroborating evidence.
_EVIDENCE_WEIGHTS: dict[str, float] = {
    "cert_reuse": 0.4,
    "asn_overlap": 0.25,
    "dns_overlap": 0.2,
    "malware_family_overlap": 0.15,
    "temporal_overlap": 0.1,
}
_HIGH_THRESHOLD = 0.6
_MEDIUM_THRESHOLD = 0.3


@dataclass
class IndicatorFacts:
    """The observed facts about one indicator, gathered from observations + enrichment,
    that the graph engine uses to decide whether two indicators are related infrastructure."""

    indicator_type: str
    indicator_value: str
    asns: set[int] = field(default_factory=set)
    cert_fingerprints: set[str] = field(default_factory=set)
    resolved_ips: set[str] = field(default_factory=set)
    nameservers: set[str] = field(default_factory=set)
    malware_families: set[str] = field(default_factory=set)
    first_seen: datetime | None = None

    @property
    def key(self) -> str:
        return f"{self.indicator_type}:{self.indicator_value}"


def _add_edge(graph: nx.Graph, a: str, b: str, kind: str, detail: str) -> None:
    if graph.has_edge(a, b):
        graph[a][b]["reasons"].append((kind, detail))
    else:
        graph.add_edge(a, b, reasons=[(kind, detail)])


def build_graph(facts: list[IndicatorFacts]) -> nx.Graph:
    """Connects indicators that share ASN, TLS certificate, resolved IP/DNS
    infrastructure, or a malware family label. Each edge records *why* it exists."""
    graph = nx.Graph()
    for indicator in facts:
        graph.add_node(indicator.key, facts=indicator)

    def _group_by(getter) -> dict:
        groups: dict = defaultdict(list)
        for indicator in facts:
            for value in getter(indicator):
                groups[value].append(indicator)
        return groups

    for asn, members in _group_by(lambda i: i.asns).items():
        for a, b in _pairs(members):
            _add_edge(graph, a.key, b.key, "asn_overlap", f"shared ASN {asn}")

    for fingerprint, members in _group_by(lambda i: i.cert_fingerprints).items():
        for a, b in _pairs(members):
            _add_edge(graph, a.key, b.key, "cert_reuse", f"shared TLS certificate {fingerprint[:12]}")

    for ip_or_ns, members in _group_by(lambda i: i.resolved_ips | i.nameservers).items():
        for a, b in _pairs(members):
            _add_edge(graph, a.key, b.key, "dns_overlap", f"shared DNS infrastructure {ip_or_ns}")

    for family, members in _group_by(lambda i: i.malware_families).items():
        for a, b in _pairs(members):
            _add_edge(graph, a.key, b.key, "malware_family_overlap", f"correlated malware family {family}")

    return graph


def _pairs(members: list[IndicatorFacts]):
    for i, a in enumerate(members):
        for b in members[i + 1 :]:
            yield a, b


def _score(evidence: list[ClusterEvidence]) -> tuple[float, str]:
    kinds = {item.kind for item in evidence}
    score = min(1.0, sum(_EVIDENCE_WEIGHTS.get(kind, 0.0) for kind in kinds))
    label = "high" if score >= _HIGH_THRESHOLD else "medium" if score >= _MEDIUM_THRESHOLD else "low"
    return score, label


def _collect_component_evidence(graph: nx.Graph, component: set[str]) -> list[ClusterEvidence]:
    grouped: dict[tuple[str, str], set[str]] = defaultdict(set)
    for a, b, data in graph.edges(data=True):
        if a not in component or b not in component:
            continue
        for kind, detail in data["reasons"]:
            grouped[(kind, detail)].update({a, b})
    return [
        ClusterEvidence(kind=kind, detail=detail, members=sorted(members))
        for (kind, detail), members in sorted(grouped.items())
    ]


def detect_clusters(facts: list[IndicatorFacts], key_prefix: str = "TI") -> list[ClusterResult]:
    """Groups indicators into connected infrastructure components and scores each
    cluster's confidence from the diversity of corroborating evidence, not just size."""
    graph = build_graph(facts)
    facts_by_key = {indicator.key: indicator for indicator in facts}
    clusters: list[ClusterResult] = []
    year = datetime.now().year
    sequence = 1
    for component in nx.connected_components(graph):
        if len(component) < 2:
            continue
        evidence = _collect_component_evidence(graph, component)
        score, label = _score(evidence)
        member_facts = [facts_by_key[key] for key in component]
        first_seen_candidates = [m.first_seen for m in member_facts if m.first_seen]
        clusters.append(
            ClusterResult(
                cluster_key=f"{key_prefix}-{year}-{sequence:04d}",
                members=[
                    ClusterMember(indicator_type=m.indicator_type, indicator_value=m.indicator_value)
                    for m in sorted(member_facts, key=lambda m: m.key)
                ],
                evidence=evidence,
                confidence_score=round(score, 2),
                confidence_label=label,
                first_observed=min(first_seen_candidates) if first_seen_candidates else None,
            )
        )
        sequence += 1
    return sorted(clusters, key=lambda c: c.confidence_score, reverse=True)
