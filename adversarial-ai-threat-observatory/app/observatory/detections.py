"""Abuse pattern rules, behavioral sequence detections, and anomaly scoring.

The message-level rules in :data:`CATEGORY_RULES` intentionally behave like a
naive keyword classifier. They are kept as an evaluation baseline so that the
session-level detections can be measured against them; the baseline over-fires
on legitimate security-awareness work, and the behavioral layer does not.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Sequence

from .privacy import neutralize_untrusted
from .schema import TelemetryEvent, utc

STOPWORDS = {
    "the", "a", "an", "and", "or", "to", "for", "of", "in", "on", "it", "is", "be", "with",
    "that", "this", "you", "me", "my", "our", "can", "please", "would", "just", "only",
    "now", "then", "same", "make", "give", "write", "add", "so", "as", "if", "was", "are",
}


def _tokens(text: str) -> List[str]:
    return [t for t in re.findall(r"[a-z']+", text.lower()) if t not in STOPWORDS and len(t) > 2]


def _jaccard(left: Iterable[str], right: Iterable[str]) -> float:
    a, b = set(left), set(right)
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


CATEGORY_RULES: Dict[str, Dict[str, Any]] = {
    "credential_phishing_assist": {
        "description": "Assistance producing content that induces a person to disclose credentials.",
        "severity": "high",
        "patterns": [
            r"(?i)confirm (their|your) (password|credentials|login)",
            r"(?i)enter(ing)? (their|your) (username|password)",
            r"(?i)(account|access) will be (locked|suspended|disabled)",
            r"(?i)(sign[- ]?on|login|sso) page that collects",
            r"(?i)(contrase|mot de passe|passwort)\w*",
            r"(?i)re-?confirmation (form|notice)",
            r"(?i)look like the (it|help ?desk|security team)",
        ],
    },
    "malware_iteration": {
        "description": "Repeated refinement of code whose purpose is evasion or mass delivery.",
        "severity": "high",
        "patterns": [
            r"(?i)iterate[s]? a template and swaps",
            r"(?i)(obfuscate|pack|crypt) (the )?(payload|binary|script)",
            r"(?i)avoid (detection|antivirus|edr)",
            r"(?i)template_variants?\(",
        ],
    },
    "bulk_account_creation": {
        "description": "Automated creation or enumeration of accounts and address lists.",
        "severity": "medium",
        "patterns": [
            r"(?i)\b\d{3,}\b[^.\n]{0,40}(email addresses|accounts|mailboxes)",
            r"(?i)generate .{0,30}(permutations|address list)",
            r"(?i)address_permutations",
        ],
    },
    "policy_evasion_probe": {
        "description": "Probing where enforcement boundaries sit rather than requesting a task.",
        "severity": "low",
        "patterns": [
            r"(?i)what .{0,30}(are you|aren't you|not allowed) .{0,30}(help|write|do)",
            r"(?i)would that change your answer",
            r"(?i)where exactly is the line",
            r"(?i)hypothetically[, ]",
            r"(?i)if I said it was for",
        ],
    },
    "recon_automation": {
        "description": "Tool-mediated reachability or availability checks against hosts.",
        "severity": "medium",
        "patterns": [
            r"(?i)(is|whether) this .{0,30}(portal|host ?name|address) is reachable",
            r"(?i)check availability of this host",
            r"(?i)reachable",
        ],
    },
}

# Contextual signals that a request is legitimate defensive or training work.
BENIGN_CONTEXT = re.compile(
    r"(?i)(authoris|authoriz)ed|awareness training|our own staff|report (a )?suspicious|"
    r"warning signs|click-through rate|training copy"
)

FRAGMENTATION_CUES = re.compile(
    r"(?i)(split it up|only the|just the|first only|one part at a time|then only)"
)

OBFUSCATION_CUES = re.compile(r"(?i)(base ?64|rot13|leet ?speak|encoded blob|decode it)")

EUPHEMISM_CUES = re.compile(
    r"(?i)(courtesy (access )?re-?confirmation|access re-?confirmation|verifcation|"
    r"reconfirm|field labels|form labels)"
)

STRONG_IDENTIFIERS = ("client_fingerprint", "payment_fingerprint", "signup_domain")


@dataclass
class EvidenceItem:
    event_id: str
    timestamp: str
    kind: str
    excerpt: str
    why: str
    source: str = "first_party_telemetry"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "kind": self.kind,
            "excerpt": self.excerpt,
            "why": self.why,
            "source": self.source,
        }


@dataclass
class Signal:
    signal_id: str
    rule_id: str
    name: str
    scope: str
    account_id: str
    session_id: str
    first_seen: str
    severity: str
    confidence: float
    rationale: str
    categories: List[str] = field(default_factory=list)
    evidence: List[EvidenceItem] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "signal_id": self.signal_id,
            "rule_id": self.rule_id,
            "name": self.name,
            "scope": self.scope,
            "account_id": self.account_id,
            "session_id": self.session_id,
            "first_seen": self.first_seen,
            "severity": self.severity,
            "confidence": round(self.confidence, 3),
            "rationale": self.rationale,
            "categories": self.categories,
            "evidence": [e.to_dict() for e in self.evidence],
        }


def match_categories(text: str) -> List[str]:
    hits = []
    for name, rule in CATEGORY_RULES.items():
        if any(re.search(pattern, text) for pattern in rule["patterns"]):
            hits.append(name)
    return hits


SEVERITY_WEIGHT = {"low": 0.2, "medium": 0.5, "high": 0.9}


def intent_score(text: str) -> float:
    """0-1 harm-intent estimate for a single message, with benign-context relief."""
    hits = match_categories(text)
    if not hits:
        return 0.0
    score = max(SEVERITY_WEIGHT[CATEGORY_RULES[h]["severity"]] for h in hits)
    score = min(1.0, score + 0.1 * (len(hits) - 1))
    if BENIGN_CONTEXT.search(text):
        score *= 0.25
    return round(score, 3)


def classify_message_baseline(events: Sequence[TelemetryEvent]) -> Dict[str, List[str]]:
    """Baseline: flag an account if any single message matches a keyword rule."""
    flagged: Dict[str, List[str]] = {}
    for event in events:
        if event.event_type != "prompt" or not event.text:
            continue
        hits = match_categories(event.text)
        if hits:
            flagged.setdefault(event.account_id, []).extend(hits)
    return flagged


class _SessionView:
    def __init__(self, session_id: str, events: List[TelemetryEvent]) -> None:
        self.session_id = session_id
        self.events = sorted(events, key=lambda e: e.timestamp)
        self.account_id = self.events[0].account_id if self.events else ""
        self.prompts = [e for e in self.events if e.event_type == "prompt" and e.text]
        self.outputs = [e for e in self.events if e.event_type == "model_output"]
        self.tools = [e for e in self.events if e.event_type == "tool_call"]

    @property
    def start(self) -> str:
        return self.events[0].timestamp if self.events else ""

    def refusal_turns(self) -> List[int]:
        return [o.turn_index for o in self.outputs if o.model_refusal]


def _evidence(event: TelemetryEvent, kind: str, why: str) -> EvidenceItem:
    excerpt = event.text or f"{event.tool_name}({event.tool_args})" or event.enforcement_action
    return EvidenceItem(
        event_id=event.event_id,
        timestamp=event.timestamp,
        kind=kind,
        excerpt=neutralize_untrusted(str(excerpt)),
        why=why,
        source=event.source,
    )


class BehavioralDetector:
    """Session-scoped detections that reason over ordered turns."""

    def __init__(self) -> None:
        self._counter = 0

    def _signal(self, **kwargs: Any) -> Signal:
        self._counter += 1
        return Signal(signal_id=f"sig-{self._counter:04d}", **kwargs)

    def run(self, events: Sequence[TelemetryEvent]) -> List[Signal]:
        by_session: Dict[str, List[TelemetryEvent]] = {}
        for event in events:
            if event.session_id:
                by_session.setdefault(event.session_id, []).append(event)

        signals: List[Signal] = []
        for session_id, session_events in by_session.items():
            view = _SessionView(session_id, session_events)
            for check in (
                self._escalation_gradient,
                self._refusal_reformulation,
                self._request_fragmentation,
                self._obfuscation_shift,
                self._tool_mediated_staging,
            ):
                found = check(view)
                if found:
                    signals.append(found)
        signals.extend(self._post_enforcement_return(events))
        return sorted(signals, key=lambda s: s.first_seen)

    # -- sequence detections -------------------------------------------------

    def _escalation_gradient(self, view: _SessionView) -> Signal | None:
        if len(view.prompts) < 3:
            return None
        scores = [intent_score(p.text) for p in view.prompts]
        head = max(scores[: max(1, len(scores) // 3)])
        tail = max(scores[len(scores) // 2 :])
        if head > 0.25 or tail < 0.5 or (tail - head) < 0.4:
            return None
        peak = view.prompts[scores.index(tail)] if tail in scores else view.prompts[-1]
        return self._signal(
            rule_id="BEH-001",
            name="Progressive intent escalation within a session",
            scope="session",
            account_id=view.account_id,
            session_id=view.session_id,
            first_seen=view.start,
            severity="high",
            confidence=min(0.9, 0.45 + (tail - head)),
            rationale=(
                f"Harm-intent estimate rose from {head:.2f} in the opening turns to "
                f"{tail:.2f} later in the same session. No single turn is decisive; the "
                "gradient is the observation."
            ),
            categories=sorted(set(sum((match_categories(p.text) for p in view.prompts), []))),
            evidence=[
                _evidence(view.prompts[0], "prompt", f"opening turn, intent {scores[0]:.2f}"),
                _evidence(peak, "prompt", f"peak turn, intent {tail:.2f}"),
            ],
        )

    def _refusal_reformulation(self, view: _SessionView) -> Signal | None:
        refusals = view.refusal_turns()
        if not refusals:
            return None
        pairs = []
        for turn in refusals:
            refused = next((p for p in view.prompts if p.turn_index == turn), None)
            follow = next((p for p in view.prompts if p.turn_index == turn + 1), None)
            if not refused or not follow:
                continue
            overlap = _jaccard(_tokens(refused.text), _tokens(follow.text))
            softened = intent_score(follow.text) < intent_score(refused.text)
            fragmented = bool(FRAGMENTATION_CUES.search(follow.text) and match_categories(refused.text))
            if overlap >= 0.10 or fragmented or (softened and EUPHEMISM_CUES.search(follow.text)):
                pairs.append((refused, follow, overlap))
        if len(pairs) < 1:
            return None
        confidence = min(0.88, 0.4 + 0.18 * len(pairs))
        evidence: List[EvidenceItem] = []
        for refused, follow, overlap in pairs:
            evidence.append(_evidence(refused, "prompt", "declined by the model"))
            evidence.append(
                _evidence(
                    follow,
                    "prompt",
                    f"next turn retains {overlap:.0%} of the declined topic with softened wording",
                )
            )
        return self._signal(
            rule_id="BEH-002",
            name="Reformulation immediately after refusal",
            scope="session",
            account_id=view.account_id,
            session_id=view.session_id,
            first_seen=view.start,
            severity="medium",
            confidence=confidence,
            rationale=(
                f"{len(pairs)} refusal(s) were each followed by a same-topic retry that reduced "
                "explicit harm wording while preserving the underlying objective."
            ),
            categories=["policy_evasion_probe"],
            evidence=evidence,
        )

    def _request_fragmentation(self, view: _SessionView) -> Signal | None:
        cues = [p for p in view.prompts if FRAGMENTATION_CUES.search(p.text)]
        if len(cues) < 2 or not view.refusal_turns():
            return None
        assembled = " ".join(p.text for p in view.prompts)
        if not match_categories(assembled):
            return None
        return self._signal(
            rule_id="BEH-003",
            name="Harmful workflow assembled from benign fragments",
            scope="session",
            account_id=view.account_id,
            session_id=view.session_id,
            first_seen=view.start,
            severity="high",
            confidence=0.72,
            rationale=(
                "Individually the fragment requests are innocuous. Concatenated, the session "
                "matches "
                + ", ".join(match_categories(assembled))
                + ", and the fragmentation begins only after a refusal."
            ),
            categories=match_categories(assembled),
            evidence=[_evidence(p, "prompt", "fragment request") for p in cues[:3]],
        )

    def _obfuscation_shift(self, view: _SessionView) -> Signal | None:
        languages = {p.text_language for p in view.prompts}
        encoded = [p for p in view.prompts if OBFUSCATION_CUES.search(p.text)]
        euphemistic = [p for p in view.prompts if EUPHEMISM_CUES.search(p.text)]
        indicators = []
        evidence: List[EvidenceItem] = []
        if len(languages) > 1:
            indicators.append("mid-session language switch")
            switched = next(p for p in view.prompts if p.text_language != view.prompts[0].text_language)
            evidence.append(_evidence(switched, "prompt", "language switch on a declined topic"))
        if encoded:
            indicators.append("encoded content handed to the model")
            evidence.append(_evidence(encoded[0], "prompt", "encoding used to carry the request"))
        if euphemistic:
            indicators.append("euphemistic relabelling of a declined request")
            evidence.append(_evidence(euphemistic[0], "prompt", "euphemism substituted for declined wording"))
        if len(indicators) < 2:
            return None
        return self._signal(
            rule_id="BEH-004",
            name="Obfuscation shift after boundary contact",
            scope="session",
            account_id=view.account_id,
            session_id=view.session_id,
            first_seen=view.start,
            severity="medium",
            confidence=min(0.85, 0.35 + 0.2 * len(indicators)),
            rationale="Concurrent obfuscation techniques observed: " + "; ".join(indicators) + ".",
            categories=["policy_evasion_probe"],
            evidence=evidence,
        )

    def _tool_mediated_staging(self, view: _SessionView) -> Signal | None:
        artifacts = [a for t in view.tools for a in t.artifacts]
        if not artifacts:
            return None
        risky = [t for t in view.tools if match_categories(str(t.tool_args))] or [
            t for t in view.tools if t.tool_name in {"web_fetch", "code_interpreter"} and t.artifacts
        ]
        if not risky:
            return None
        session_text = " ".join(p.text for p in view.prompts)
        if not match_categories(session_text):
            return None
        return self._signal(
            rule_id="BEH-005",
            name="Tool activity staging infrastructure alongside abusive content",
            scope="session",
            account_id=view.account_id,
            session_id=view.session_id,
            first_seen=view.start,
            severity="medium",
            confidence=0.65,
            rationale=(
                "Tool calls in this session touched externally controlled artifacts "
                f"({', '.join(sorted(set(artifacts))[:3])}) in the same session as content that "
                "matched an abuse rule."
            ),
            categories=match_categories(session_text) + ["recon_automation"],
            evidence=[_evidence(t, "tool_call", "artifact touched by tool call") for t in risky[:2]],
        )

    # -- cross-session detection ---------------------------------------------

    def _post_enforcement_return(self, events: Sequence[TelemetryEvent]) -> List[Signal]:
        enforcement = [e for e in events if e.event_type == "enforcement"]
        creations = [e for e in events if e.event_type == "account_create"]
        if not enforcement:
            return []

        signals: List[Signal] = []
        for created in creations:
            for action in enforcement:
                if action.account_id == created.account_id:
                    continue
                if utc(created.timestamp) <= utc(action.timestamp):
                    continue
                shared = [
                    key
                    for key in STRONG_IDENTIFIERS
                    if created.infrastructure.get(key)
                    and created.infrastructure.get(key) == action.infrastructure.get(key)
                ]
                if not shared:
                    continue
                delta_hours = (utc(created.timestamp) - utc(action.timestamp)).total_seconds() / 3600
                self._counter += 1
                signals.append(
                    Signal(
                        signal_id=f"sig-{self._counter:04d}",
                        rule_id="BEH-006",
                        name="Account re-registration after enforcement on a linked account",
                        scope="account",
                        account_id=created.account_id,
                        session_id="",
                        first_seen=created.timestamp,
                        severity="high",
                        confidence=0.7 if len(shared) > 1 else 0.55,
                        rationale=(
                            f"Created {delta_hours:.0f}h after enforcement against "
                            f"{action.account_id}, sharing {', '.join(shared)}. This is an "
                            "association, not proof of a shared operator."
                        ),
                        categories=["bulk_account_creation"],
                        evidence=[
                            _evidence(action, "enforcement", "prior enforcement event"),
                            _evidence(created, "account_create", "re-registration sharing identifiers"),
                        ],
                    )
                )
                break
        return signals


def score_accounts(
    events: Sequence[TelemetryEvent], signals: Sequence[Signal]
) -> Dict[str, Dict[str, Any]]:
    """Aggregate session signals into an account-level anomaly score."""
    by_account: Dict[str, Dict[str, Any]] = {}
    for event in events:
        entry = by_account.setdefault(
            event.account_id,
            {
                "account_id": event.account_id,
                "events": 0,
                "prompts": 0,
                "refusals": 0,
                "signals": [],
                "categories": set(),
                "score": 0.0,
            },
        )
        entry["events"] += 1
        if event.event_type == "prompt":
            entry["prompts"] += 1
        if event.event_type == "model_output" and event.model_refusal:
            entry["refusals"] += 1

    for signal in signals:
        entry = by_account.setdefault(
            signal.account_id,
            {
                "account_id": signal.account_id,
                "events": 0,
                "prompts": 0,
                "refusals": 0,
                "signals": [],
                "categories": set(),
                "score": 0.0,
            },
        )
        entry["signals"].append(signal.signal_id)
        entry["categories"].update(signal.categories)
        entry["score"] += SEVERITY_WEIGHT[signal.severity] * signal.confidence

    for entry in by_account.values():
        refusal_rate = entry["refusals"] / entry["prompts"] if entry["prompts"] else 0.0
        entry["refusal_rate"] = round(refusal_rate, 3)
        entry["score"] = round(min(1.0, entry["score"] / 3.0 + 0.2 * refusal_rate), 3)
        entry["categories"] = sorted(entry["categories"])
        entry["distinct_rules"] = len(set(entry["signals"]))
    return by_account
