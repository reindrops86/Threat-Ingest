"""Entity resolution across accounts, infrastructure, artifacts, and language use.

Every link carries a weight and a human-readable explanation. Weights combine
with a noisy-OR so that many weak signals never silently add up to certainty,
and each link records whether it is a strong identifier or a weak correlate.
"""

from __future__ import annotations

import math
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any, Dict, Iterable, List, Sequence, Tuple

from .detections import Signal
from .schema import Account, TelemetryEvent, utc

# Weight, strength tier, and analyst-facing wording for each link type.
LINK_TYPES: Dict[str, Dict[str, Any]] = {
    "client_fingerprint": {"weight": 0.45, "strength": "strong", "label": "identical client fingerprint"},
    "shared_artifact": {"weight": 0.40, "strength": "strong", "label": "same externally controlled artifact"},
    "payment_fingerprint": {"weight": 0.30, "strength": "strong", "label": "identical payment fingerprint"},
    "signup_domain": {"weight": 0.25, "strength": "moderate", "label": "same signup mail domain"},
    "style_similarity": {"weight": 0.30, "strength": "moderate", "label": "recurring rare phrasing"},
    "behavioral_fingerprint": {"weight": 0.22, "strength": "moderate", "label": "same detection rules fired"},
    "ip_prefix": {"weight": 0.15, "strength": "weak", "label": "same /24 network prefix"},
    "temporal_burst": {"weight": 0.12, "strength": "weak", "label": "accounts created in one burst"},
    "asn": {"weight": 0.05, "strength": "weak", "label": "same autonomous system"},
}

BURST_WINDOW = timedelta(hours=24)
STYLE_THRESHOLD = 0.22
LINK_THRESHOLD = 0.60


@dataclass
class AccountProfile:
    account_id: str
    created_at: str
    status: str
    infrastructure: Dict[str, Any] = field(default_factory=dict)
    artifacts: List[str] = field(default_factory=list)
    rules_fired: List[str] = field(default_factory=list)
    first_activity: str = ""
    last_activity: str = ""
    text: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "account_id": self.account_id,
            "created_at": self.created_at,
            "status": self.status,
            "infrastructure": self.infrastructure,
            "artifacts": self.artifacts,
            "rules_fired": self.rules_fired,
            "first_activity": self.first_activity,
            "last_activity": self.last_activity,
        }


@dataclass
class Link:
    source: str
    target: str
    link_type: str
    weight: float
    strength: str
    explanation: str
    shared_value: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source,
            "target": self.target,
            "link_type": self.link_type,
            "weight": round(self.weight, 3),
            "strength": self.strength,
            "explanation": self.explanation,
            "shared_value": self.shared_value,
        }


@dataclass
class Edge:
    source: str
    target: str
    confidence: float
    links: List[Link] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source,
            "target": self.target,
            "confidence": round(self.confidence, 3),
            "strong_link_count": sum(1 for l in self.links if l.strength == "strong"),
            "links": [l.to_dict() for l in self.links],
        }


def _ngrams(text: str) -> Counter:
    words = re.findall(r"[a-z']+", text.lower())
    grams = Counter(words)
    grams.update(f"{a} {b}" for a, b in zip(words, words[1:]))
    return grams


def _style_vectors(profiles: Sequence[AccountProfile]) -> Dict[str, Dict[str, float]]:
    """TF-IDF vectors so that rare phrasing dominates shared common wording."""
    docs = {p.account_id: _ngrams(p.text) for p in profiles}
    df: Counter = Counter()
    for grams in docs.values():
        df.update(set(grams))
    total = max(1, len(docs))

    vectors: Dict[str, Dict[str, float]] = {}
    for account_id, grams in docs.items():
        length = sum(grams.values()) or 1
        vector = {}
        for gram, count in grams.items():
            idf = math.log((total + 1) / (df[gram] + 1)) + 1.0
            vector[gram] = (count / length) * idf
        norm = math.sqrt(sum(v * v for v in vector.values())) or 1.0
        vectors[account_id] = {k: v / norm for k, v in vector.items()}
    return vectors


def _cosine(a: Dict[str, float], b: Dict[str, float]) -> float:
    if len(a) > len(b):
        a, b = b, a
    return sum(value * b.get(key, 0.0) for key, value in a.items())


def _top_shared_phrases(a: Dict[str, float], b: Dict[str, float], limit: int = 4) -> List[str]:
    shared = [(key, value * b[key]) for key, value in a.items() if key in b]
    shared.sort(key=lambda kv: kv[1], reverse=True)
    return [key for key, _ in shared[:limit] if " " in key or len(key) > 5]


def build_profiles(
    accounts: Sequence[Account],
    events: Sequence[TelemetryEvent],
    signals: Sequence[Signal],
) -> Dict[str, AccountProfile]:
    profiles: Dict[str, AccountProfile] = {
        a.account_id: AccountProfile(
            account_id=a.account_id,
            created_at=a.created_at,
            status=a.status,
            infrastructure=dict(a.infrastructure or {}),
        )
        for a in accounts
    }
    rules_by_account: Dict[str, set] = defaultdict(set)
    for signal in signals:
        rules_by_account[signal.account_id].add(signal.rule_id)

    for event in events:
        profile = profiles.get(event.account_id)
        if profile is None:
            continue
        if event.text and event.event_type == "prompt":
            profile.text += " " + event.text
        profile.artifacts.extend(event.artifacts)
        if event.infrastructure:
            for key in ("ip_prefix", "asn", "client_fingerprint", "payment_fingerprint", "signup_domain"):
                if event.infrastructure.get(key) and not profile.infrastructure.get(key):
                    profile.infrastructure[key] = event.infrastructure[key]
        if not profile.first_activity or event.timestamp < profile.first_activity:
            profile.first_activity = event.timestamp
        if event.timestamp > profile.last_activity:
            profile.last_activity = event.timestamp

    for account_id, profile in profiles.items():
        profile.artifacts = sorted(set(profile.artifacts))
        profile.rules_fired = sorted(rules_by_account.get(account_id, ()))
    return profiles


def _link(source: str, target: str, link_type: str, explanation: str, shared: str = "", scale: float = 1.0) -> Link:
    spec = LINK_TYPES[link_type]
    return Link(
        source=source,
        target=target,
        link_type=link_type,
        weight=spec["weight"] * scale,
        strength=spec["strength"],
        explanation=explanation,
        shared_value=shared,
    )


def _jaccard(a: Iterable[str], b: Iterable[str]) -> float:
    sa, sb = set(a), set(b)
    if not sa or not sb:
        return 0.0
    return len(sa & sb) / len(sa | sb)


def resolve(profiles: Dict[str, AccountProfile]) -> List[Edge]:
    """Produce confidence-weighted account-to-account edges with explanations."""
    ordered = sorted(profiles.values(), key=lambda p: p.account_id)
    vectors = _style_vectors(ordered)
    edges: List[Edge] = []

    for i, left in enumerate(ordered):
        for right in ordered[i + 1 :]:
            links: List[Link] = []

            for key in ("client_fingerprint", "payment_fingerprint", "signup_domain", "ip_prefix", "asn"):
                lv, rv = left.infrastructure.get(key), right.infrastructure.get(key)
                if lv and lv == rv:
                    links.append(
                        _link(
                            left.account_id,
                            right.account_id,
                            key,
                            f"Both accounts present {LINK_TYPES[key]['label']} ({lv}).",
                            shared=str(lv),
                        )
                    )

            shared_artifacts = sorted(set(left.artifacts) & set(right.artifacts))
            if shared_artifacts:
                links.append(
                    _link(
                        left.account_id,
                        right.account_id,
                        "shared_artifact",
                        "Both accounts directed tool calls at " + ", ".join(shared_artifacts[:2]) + ".",
                        shared=shared_artifacts[0],
                    )
                )

            similarity = _cosine(vectors[left.account_id], vectors[right.account_id])
            if similarity >= STYLE_THRESHOLD:
                phrases = _top_shared_phrases(vectors[left.account_id], vectors[right.account_id])
                links.append(
                    _link(
                        left.account_id,
                        right.account_id,
                        "style_similarity",
                        f"Rarity-weighted phrasing overlap {similarity:.2f}"
                        + (f"; distinctive shared phrases: {', '.join(phrases)}." if phrases else "."),
                        shared="|".join(phrases),
                        scale=min(1.0, similarity / 0.5),
                    )
                )

            behavior = _jaccard(left.rules_fired, right.rules_fired)
            if behavior >= 0.5 and left.rules_fired:
                links.append(
                    _link(
                        left.account_id,
                        right.account_id,
                        "behavioral_fingerprint",
                        "Same behavioral detections fired on both accounts: "
                        + ", ".join(sorted(set(left.rules_fired) & set(right.rules_fired)))
                        + ".",
                        scale=behavior,
                    )
                )

            if left.created_at and right.created_at:
                gap = abs(utc(left.created_at) - utc(right.created_at))
                if gap <= BURST_WINDOW and any(l.strength != "weak" for l in links):
                    links.append(
                        _link(
                            left.account_id,
                            right.account_id,
                            "temporal_burst",
                            f"Created {gap.total_seconds() / 3600:.1f}h apart.",
                            scale=1.0 - gap / BURST_WINDOW,
                        )
                    )

            if not links:
                continue
            product = 1.0
            for link in links:
                product *= 1.0 - min(0.95, link.weight)
            confidence = 1.0 - product
            # Weak correlates alone must not cross the linking threshold.
            if not any(l.strength == "strong" for l in links):
                confidence = min(confidence, 0.55)
            edges.append(Edge(left.account_id, right.account_id, confidence, links))

    return sorted(edges, key=lambda e: e.confidence, reverse=True)


def build_graph(profiles: Dict[str, AccountProfile], edges: Sequence[Edge]) -> Dict[str, Any]:
    """Account, infrastructure, and artifact nodes with confidence-weighted edges."""
    nodes: List[Dict[str, Any]] = []
    seen: set = set()

    def add(node_id: str, node_type: str, **attrs: Any) -> None:
        if node_id in seen:
            return
        seen.add(node_id)
        nodes.append({"id": node_id, "type": node_type, **attrs})

    graph_edges: List[Dict[str, Any]] = []
    for profile in profiles.values():
        add(profile.account_id, "account", status=profile.status, created_at=profile.created_at)
        infra = profile.infrastructure
        for key, node_type in (
            ("ip_prefix", "network"),
            ("asn", "asn"),
            ("client_fingerprint", "client_fingerprint"),
            ("signup_domain", "domain"),
            ("payment_fingerprint", "payment"),
        ):
            value = infra.get(key)
            if not value:
                continue
            node_id = f"{key}:{value}"
            add(node_id, node_type, value=value)
            graph_edges.append(
                {
                    "source": profile.account_id,
                    "target": node_id,
                    "relationship": "observed_from" if node_type in {"network", "asn"} else "presents",
                    "confidence": 1.0,
                    "explanation": "Directly observed in first-party telemetry.",
                }
            )
        for artifact in profile.artifacts:
            add(artifact, "artifact", value=artifact)
            graph_edges.append(
                {
                    "source": profile.account_id,
                    "target": artifact,
                    "relationship": "touched",
                    "confidence": 1.0,
                    "explanation": "Tool call referenced this artifact.",
                }
            )

    for edge in edges:
        graph_edges.append(
            {
                "source": edge.source,
                "target": edge.target,
                "relationship": "linked_to",
                "confidence": round(edge.confidence, 3),
                "explanation": " ".join(l.explanation for l in edge.links),
            }
        )

    return {"nodes": nodes, "edges": graph_edges, "node_count": len(nodes), "edge_count": len(graph_edges)}
