"""Campaign clustering over time, infrastructure, behavior, and phrasing."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any, Dict, List, Sequence

from .entities import Edge, AccountProfile, LINK_THRESHOLD
from .schema import utc

WAVE_GAP = timedelta(hours=36)

CONFIDENCE_BANDS = (
    (0.80, "high"),
    (0.55, "moderate"),
    (0.30, "low"),
    (0.0, "insufficient"),
)


def confidence_band(value: float) -> str:
    for floor, label in CONFIDENCE_BANDS:
        if value >= floor:
            return label
    return "insufficient"


@dataclass
class Campaign:
    campaign_id: str
    account_ids: List[str]
    confidence: float
    band: str
    first_seen: str
    last_seen: str
    waves: List[Dict[str, Any]] = field(default_factory=list)
    shared_infrastructure: Dict[str, List[str]] = field(default_factory=dict)
    behaviors: List[str] = field(default_factory=list)
    artifacts: List[str] = field(default_factory=list)
    link_summary: List[Dict[str, Any]] = field(default_factory=list)
    temporal_coordination: float = 0.0
    strong_link_types: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "campaign_id": self.campaign_id,
            "account_ids": self.account_ids,
            "confidence": round(self.confidence, 3),
            "confidence_band": self.band,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "waves": self.waves,
            "shared_infrastructure": self.shared_infrastructure,
            "behaviors": self.behaviors,
            "artifacts": self.artifacts,
            "temporal_coordination": round(self.temporal_coordination, 3),
            "strong_link_types": self.strong_link_types,
            "link_summary": self.link_summary,
        }


class _UnionFind:
    def __init__(self) -> None:
        self.parent: Dict[str, str] = {}

    def find(self, item: str) -> str:
        self.parent.setdefault(item, item)
        while self.parent[item] != item:
            self.parent[item] = self.parent[self.parent[item]]
            item = self.parent[item]
        return item

    def union(self, a: str, b: str) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[rb] = ra


def _waves(members: Sequence[AccountProfile]) -> List[Dict[str, Any]]:
    ordered = sorted(members, key=lambda p: p.created_at)
    waves: List[Dict[str, Any]] = []
    current: List[AccountProfile] = []
    for profile in ordered:
        if current and utc(profile.created_at) - utc(current[-1].created_at) > WAVE_GAP:
            waves.append(_wave_record(len(waves) + 1, current))
            current = []
        current.append(profile)
    if current:
        waves.append(_wave_record(len(waves) + 1, current))
    return waves


def _wave_record(index: int, members: Sequence[AccountProfile]) -> Dict[str, Any]:
    prefixes = sorted({m.infrastructure.get("ip_prefix", "") for m in members if m.infrastructure.get("ip_prefix")})
    return {
        "wave": index,
        "account_ids": [m.account_id for m in members],
        "first_created": members[0].created_at,
        "last_created": members[-1].created_at,
        "ip_prefixes": prefixes,
        "statuses": sorted({m.status for m in members}),
    }


def _temporal_coordination(members: Sequence[AccountProfile]) -> float:
    """1.0 when creations are tightly bunched, decaying over a 24h window."""
    if len(members) < 2:
        return 0.0
    times = sorted(utc(m.created_at) for m in members)
    gaps = [(b - a).total_seconds() / 3600 for a, b in zip(times, times[1:])]
    tight = sum(1 for g in gaps if g <= 24)
    return tight / len(gaps)


def cluster(
    profiles: Dict[str, AccountProfile],
    edges: Sequence[Edge],
    threshold: float = LINK_THRESHOLD,
) -> List[Campaign]:
    uf = _UnionFind()
    kept = [e for e in edges if e.confidence >= threshold]
    for edge in kept:
        uf.union(edge.source, edge.target)

    groups: Dict[str, List[str]] = {}
    for edge in kept:
        for node in (edge.source, edge.target):
            groups.setdefault(uf.find(node), [])
            if node not in groups[uf.find(node)]:
                groups[uf.find(node)].append(node)

    campaigns: List[Campaign] = []
    for index, (root, account_ids) in enumerate(sorted(groups.items()), start=1):
        members = [profiles[a] for a in sorted(account_ids) if a in profiles]
        if len(members) < 2:
            continue
        member_ids = {m.account_id for m in members}
        internal = [e for e in kept if e.source in member_ids and e.target in member_ids]

        link_counter: Counter = Counter()
        strong_types: set = set()
        for edge in internal:
            for link in edge.links:
                link_counter[link.link_type] += 1
                if link.strength == "strong":
                    strong_types.add(link.link_type)

        shared: Dict[str, List[str]] = {}
        for key in ("client_fingerprint", "payment_fingerprint", "signup_domain", "ip_prefix", "asn"):
            values = sorted({m.infrastructure.get(key, "") for m in members if m.infrastructure.get(key)})
            if values:
                shared[key] = values

        behaviors = sorted({rule for m in members for rule in m.rules_fired})
        artifacts = sorted({a for m in members for a in m.artifacts})
        coordination = _temporal_coordination(members)

        mean_edge = sum(e.confidence for e in internal) / len(internal) if internal else 0.0
        confidence = min(0.90, 0.6 * mean_edge + 0.2 * coordination + 0.1 * min(1.0, len(strong_types) / 2) + 0.1 * min(1.0, len(behaviors) / 4))

        first_seen = min(m.first_activity or m.created_at for m in members)
        last_seen = max(m.last_activity or m.created_at for m in members)

        campaigns.append(
            Campaign(
                campaign_id=f"CAMP-2026-{index:03d}",
                account_ids=[m.account_id for m in members],
                confidence=confidence,
                band=confidence_band(confidence),
                first_seen=first_seen,
                last_seen=last_seen,
                waves=_waves(members),
                shared_infrastructure=shared,
                behaviors=behaviors,
                artifacts=artifacts,
                link_summary=[
                    {"link_type": name, "occurrences": count} for name, count in link_counter.most_common()
                ],
                temporal_coordination=coordination,
                strong_link_types=sorted(strong_types),
            )
        )

    campaigns.sort(key=lambda c: (-len(c.account_ids), -c.confidence))
    return campaigns
