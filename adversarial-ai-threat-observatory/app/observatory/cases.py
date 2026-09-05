"""Investigation workspace: cases, timelines, evidence discipline, and actions.

The case object separates three claim types and never merges them:

* observation - something present in telemetry, with an event id.
* inference   - a conclusion drawn from observations, with stated confidence.
* attribution - a claim about who is responsible. This system does not make
                identity attributions; it produces operator-linkage hypotheses.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Sequence

from .campaigns import Campaign, confidence_band
from .detections import Signal
from .entities import AccountProfile, Edge
from .privacy import neutralize_untrusted
from .schema import ExternalReference, TelemetryEvent, utc

ENFORCEMENT_LADDER = [
    {
        "tier": 0,
        "action": "silent_monitoring",
        "reversible": True,
        "description": "Continue collection, add campaign watchlist, take no user-visible action.",
    },
    {
        "tier": 1,
        "action": "friction_and_rate_limit",
        "reversible": True,
        "description": "Apply signup friction and per-account rate limits on the affected surface.",
    },
    {
        "tier": 2,
        "action": "tool_restriction",
        "reversible": True,
        "description": "Withdraw outbound fetch and code-execution tools from linked accounts.",
    },
    {
        "tier": 3,
        "action": "account_suspension",
        "reversible": True,
        "description": "Suspend the accounts with direct high-severity evidence, with appeal path.",
    },
    {
        "tier": 4,
        "action": "campaign_wide_intervention",
        "reversible": False,
        "description": "Suspend all linked accounts and block the shared artifact platform-wide.",
    },
]


@dataclass
class Claim:
    claim_id: str
    kind: str  # observation | inference | attribution
    statement: str
    confidence: float
    provenance: List[str] = field(default_factory=list)
    basis: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "claim_id": self.claim_id,
            "kind": self.kind,
            "statement": self.statement,
            "confidence": round(self.confidence, 3),
            "provenance": self.provenance,
            "basis": self.basis,
        }


@dataclass
class Case:
    case_id: str
    title: str
    status: str
    campaign: Dict[str, Any]
    confidence: float
    band: str
    timeline: List[Dict[str, Any]] = field(default_factory=list)
    claims: List[Dict[str, Any]] = field(default_factory=list)
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    competing_explanations: List[Dict[str, Any]] = field(default_factory=list)
    evidence_gaps: List[str] = field(default_factory=list)
    corroboration: List[Dict[str, Any]] = field(default_factory=list)
    recommended_actions: List[Dict[str, Any]] = field(default_factory=list)
    analyst_notes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "case_id": self.case_id,
            "title": self.title,
            "status": self.status,
            "confidence": round(self.confidence, 3),
            "confidence_band": self.band,
            "campaign": self.campaign,
            "timeline": self.timeline,
            "claims": self.claims,
            "evidence": self.evidence,
            "competing_explanations": self.competing_explanations,
            "evidence_gaps": self.evidence_gaps,
            "corroboration": self.corroboration,
            "recommended_actions": self.recommended_actions,
            "analyst_notes": self.analyst_notes,
        }


def _timeline(
    campaign: Campaign,
    events: Sequence[TelemetryEvent],
    signals: Sequence[Signal],
) -> List[Dict[str, Any]]:
    members = set(campaign.account_ids)
    entries: List[Dict[str, Any]] = []

    for event in events:
        if event.account_id not in members:
            continue
        if event.event_type in {"account_create", "enforcement"}:
            entries.append(
                {
                    "timestamp": event.timestamp,
                    "account_id": event.account_id,
                    "type": event.event_type,
                    "summary": event.enforcement_action or "account created",
                    "event_id": event.event_id,
                }
            )
        elif event.event_type == "tool_call" and event.artifacts:
            entries.append(
                {
                    "timestamp": event.timestamp,
                    "account_id": event.account_id,
                    "type": "tool_call",
                    "summary": f"{event.tool_name} touched {', '.join(event.artifacts)}",
                    "event_id": event.event_id,
                }
            )

    for signal in signals:
        if signal.account_id not in members:
            continue
        entries.append(
            {
                "timestamp": signal.first_seen,
                "account_id": signal.account_id,
                "type": "detection",
                "summary": f"{signal.rule_id} {signal.name} (confidence {signal.confidence:.2f})",
                "event_id": signal.signal_id,
            }
        )

    entries.sort(key=lambda e: e["timestamp"])
    return entries


def _evidence(campaign: Campaign, signals: Sequence[Signal], edges: Sequence[Edge]) -> List[Dict[str, Any]]:
    members = set(campaign.account_ids)
    items: List[Dict[str, Any]] = []
    for signal in signals:
        if signal.account_id not in members:
            continue
        for item in signal.evidence:
            record = item.to_dict()
            record["supports"] = f"{signal.rule_id} ({signal.name})"
            record["excerpt"] = neutralize_untrusted(record["excerpt"])
            items.append(record)
    for edge in edges:
        if edge.source in members and edge.target in members:
            for link in edge.links:
                items.append(
                    {
                        "event_id": f"link:{edge.source}~{edge.target}:{link.link_type}",
                        "timestamp": campaign.first_seen,
                        "kind": "linkage",
                        "excerpt": link.shared_value or link.link_type,
                        "why": link.explanation,
                        "source": "entity_resolution",
                        "supports": f"account linkage ({link.strength})",
                    }
                )
    return items


def _claims(campaign: Campaign, signals: Sequence[Signal], profiles: Dict[str, AccountProfile]) -> List[Claim]:
    members = set(campaign.account_ids)
    relevant = [s for s in signals if s.account_id in members]
    claims: List[Claim] = []
    counter = 0

    def add(kind: str, statement: str, confidence: float, provenance: List[str], basis: List[str] | None = None) -> None:
        nonlocal counter
        counter += 1
        claims.append(
            Claim(
                claim_id=f"{campaign.campaign_id}-C{counter:02d}",
                kind=kind,
                statement=statement,
                confidence=confidence,
                provenance=provenance,
                basis=basis or [],
            )
        )

    creations = sorted(profiles[a].created_at for a in campaign.account_ids if a in profiles)
    add(
        "observation",
        f"{len(campaign.account_ids)} accounts were created between {creations[0]} and {creations[-1]}.",
        1.0,
        [f"account:{a}" for a in campaign.account_ids],
    )

    if campaign.artifacts:
        add(
            "observation",
            "Tool calls from multiple accounts referenced the same artifact(s): "
            + ", ".join(campaign.artifacts[:3])
            + ".",
            1.0,
            campaign.artifacts[:3],
        )

    for rule_id in campaign.behaviors:
        matching = [s for s in relevant if s.rule_id == rule_id]
        if not matching:
            continue
        add(
            "observation",
            f"{rule_id} ({matching[0].name}) fired on {len({m.account_id for m in matching})} account(s).",
            1.0,
            [m.signal_id for m in matching[:4]],
        )

    strong = campaign.strong_link_types
    add(
        "inference",
        "The linked accounts are more consistent with a single operator than with independent users.",
        campaign.confidence,
        [f"campaign:{campaign.campaign_id}"],
        basis=[f"strong link: {t}" for t in strong] or ["weak correlates only"],
    )

    if len(campaign.waves) > 1:
        add(
            "inference",
            "Activity resumed in a later wave from different network space after enforcement, "
            "with the same client fingerprint and reused artifact.",
            min(0.75, campaign.confidence),
            [f"wave:{w['wave']}" for w in campaign.waves],
            basis=["wave separation in creation times", "unchanged strong identifier across waves"],
        )

    add(
        "attribution",
        "No identity attribution is made. Linkage supports an operator hypothesis only; "
        "shared infrastructure and phrasing do not establish who the operator is.",
        0.0,
        [],
        basis=["policy: linkage != identity"],
    )
    return claims


def _competing_explanations(campaign: Campaign, profiles: Dict[str, AccountProfile]) -> List[Dict[str, Any]]:
    strong = set(campaign.strong_link_types)
    prefixes = campaign.shared_infrastructure.get("ip_prefix", [])
    explanations = [
        {
            "hypothesis": "Shared egress: unrelated users behind one VPN, campus, or office NAT.",
            "assessment": (
                "Weakened. Linkage does not rest on network prefix alone; "
                f"strong identifiers present: {', '.join(sorted(strong)) or 'none'}."
                if strong
                else "Not excluded. Linkage currently rests on weak correlates."
            ),
            "supported_by": ["ip_prefix"] if prefixes else [],
            "residual_probability": 0.10 if strong else 0.45,
        },
        {
            "hypothesis": "Authorised security-awareness team producing phishing-simulation material.",
            "assessment": (
                "Weakened. Sessions show refusal-driven reformulation and euphemistic relabelling, "
                "which authorised training work does not require."
                if "BEH-002" in campaign.behaviors or "BEH-004" in campaign.behaviors
                else "Not excluded. No boundary-probing sequence was observed."
            ),
            "supported_by": ["phishing vocabulary"],
            "residual_probability": 0.08 if "BEH-002" in campaign.behaviors else 0.35,
        },
        {
            "hypothesis": "Shared managed device pool, e.g. an agency using one browser image.",
            "assessment": (
                "Partially credible; a common browser image can duplicate a client fingerprint. "
                "It does not explain reuse of the same externally controlled artifact."
                if "shared_artifact" in strong
                else "Credible. Fingerprint reuse alone is not decisive."
            ),
            "supported_by": ["client_fingerprint"],
            "residual_probability": 0.12 if "shared_artifact" in strong else 0.4,
        },
        {
            "hypothesis": "Detection artefact: rules over-fire on the same benign template language.",
            "assessment": (
                "Weakened. Multiple independent rule families fired: "
                + ", ".join(campaign.behaviors)
                if len(campaign.behaviors) >= 3
                else "Not excluded. Few distinct rules fired."
            ),
            "supported_by": ["rule overlap"],
            "residual_probability": 0.05 if len(campaign.behaviors) >= 3 else 0.3,
        },
    ]
    return explanations


def _evidence_gaps(campaign: Campaign) -> List[str]:
    gaps = [
        "Ownership of the shared artifact is unconfirmed; no registrar or hosting evidence is available "
        "from first-party telemetry.",
        "No evidence shows that generated content was ever delivered to a recipient. Harm is potential, "
        "not observed.",
        "Client fingerprints can be duplicated by a common browser image; treat as strong-but-not-unique.",
    ]
    if "payment_fingerprint" not in campaign.shared_infrastructure:
        gaps.append("No payment linkage was observed across waves.")
    elif len(campaign.shared_infrastructure.get("payment_fingerprint", [])) > 1:
        gaps.append("Payment fingerprints differ between waves, so billing does not corroborate the link.")
    if len(campaign.waves) > 1:
        gaps.append(
            "The gap between waves is unexplained; the operator may have been active on surfaces "
            "outside this telemetry."
        )
    return gaps


def _corroboration(campaign: Campaign, references: Sequence[ExternalReference]) -> List[Dict[str, Any]]:
    results = []
    haystack = set(campaign.artifacts) | {
        f"{k}:{v}" for k, values in campaign.shared_infrastructure.items() for v in values
    }
    for reference in references:
        matched = [i for i in reference.indicators if i in haystack or i.split(":", 1)[-1] in " ".join(haystack)]
        if not matched and not reference.behaviors:
            continue
        results.append(
            {
                "reference_id": reference.reference_id,
                "title": reference.title,
                "publisher": reference.publisher,
                "trust_tier": reference.trust_tier,
                "admiralty": f"{reference.source_reliability}{reference.information_credibility}",
                "matched_indicators": matched,
                "matched_behaviors": reference.behaviors[:2],
                "weighting": (
                    "corroborating but not independent; external reporting may derive from the same "
                    "underlying observations"
                ),
            }
        )
    return results


def _recommend(campaign: Campaign, signals: Sequence[Signal]) -> List[Dict[str, Any]]:
    members = set(campaign.account_ids)
    relevant = [s for s in signals if s.account_id in members]
    high = {s.account_id for s in relevant if s.severity == "high"}

    if campaign.band == "high" and high:
        tier = 3
    elif campaign.band in {"high", "moderate"}:
        tier = 2
    elif campaign.band == "low":
        tier = 1
    else:
        tier = 0

    chosen = ENFORCEMENT_LADDER[tier]
    recommendations = [
        {
            **chosen,
            "scope": sorted(high) if tier >= 3 else sorted(members),
            "rationale": (
                f"Campaign confidence is {campaign.confidence:.2f} ({campaign.band}). "
                f"{len(high)} account(s) carry direct high-severity evidence, "
                f"{len(members) - len(high)} are linked by association only. "
                "Action is scoped to the evidence tier held for each account."
            ),
            "proportionality": "Accounts linked only by weak correlates receive monitoring, not suspension.",
            "requires_human_approval": tier >= 3,
        }
    ]
    if tier >= 3 and len(members - high) > 0:
        recommendations.append(
            {
                **ENFORCEMENT_LADDER[0],
                "scope": sorted(members - high),
                "rationale": "Association-only accounts remain under observation pending direct evidence.",
                "proportionality": "Avoids penalising users who may share infrastructure coincidentally.",
                "requires_human_approval": False,
            }
        )
    if campaign.artifacts:
        recommendations.append(
            {
                "tier": 2,
                "action": "artifact_watchlist",
                "reversible": True,
                "description": "Add reused artifacts to the outbound-fetch watchlist and alert on new touches.",
                "scope": campaign.artifacts,
                "rationale": "The reused artifact is the most durable pivot across waves.",
                "proportionality": "Detection-only; no user-visible impact.",
                "requires_human_approval": False,
            }
        )
    return recommendations


def build_case(
    campaign: Campaign,
    profiles: Dict[str, AccountProfile],
    events: Sequence[TelemetryEvent],
    signals: Sequence[Signal],
    edges: Sequence[Edge],
    references: Sequence[ExternalReference],
    case_index: int = 1,
) -> Case:
    claims = _claims(campaign, signals, profiles)
    competing = _competing_explanations(campaign, profiles)

    # Confidence is reduced by the strongest surviving alternative explanation.
    residual = max((c["residual_probability"] for c in competing), default=0.0)
    confidence = max(0.0, min(0.9, campaign.confidence * (1.0 - residual * 0.5)))

    return Case(
        case_id=f"CASE-2026-{case_index:03d}",
        title=f"Coordinated multi-account credential-phishing assistance ({campaign.campaign_id})",
        status="open",
        campaign=campaign.to_dict(),
        confidence=confidence,
        band=confidence_band(confidence),
        timeline=_timeline(campaign, events, signals),
        claims=[c.to_dict() for c in claims],
        evidence=_evidence(campaign, signals, edges),
        competing_explanations=competing,
        evidence_gaps=_evidence_gaps(campaign),
        corroboration=_corroboration(campaign, references),
        recommended_actions=_recommend(campaign, signals),
        analyst_notes=[],
    )
