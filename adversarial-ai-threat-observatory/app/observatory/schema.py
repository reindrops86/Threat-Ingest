"""Telemetry schema for the Adversarial AI Threat Observatory.

All records are synthetic. No production platform data, credentials, or
personally identifying information is represented here.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field, fields
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

SCHEMA_VERSION = "1.1.0"

EVENT_TYPES = (
    "account_create",
    "login",
    "prompt",
    "model_output",
    "tool_call",
    "enforcement",
)

TRUST_TIERS = ("first_party_telemetry", "vendor_feed", "osint", "analyst_assertion")


def utc(value: str) -> datetime:
    """Parse an ISO-8601 timestamp into an aware UTC datetime."""
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


class Record:
    """Serialization helpers shared by every schema object."""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)  # type: ignore[arg-type]

    @classmethod
    def from_dict(cls, payload: Dict[str, Any]):
        known = {f.name for f in fields(cls)}  # type: ignore[arg-type]
        return cls(**{k: v for k, v in payload.items() if k in known})  # type: ignore[call-arg]


@dataclass
class Infrastructure(Record):
    """Network and client provenance attached to an observation."""

    ip: str = ""
    ip_prefix: str = ""
    asn: str = ""
    country: str = ""
    user_agent: str = ""
    client_fingerprint: str = ""
    signup_domain: str = ""
    payment_fingerprint: str = ""


@dataclass
class Account(Record):
    account_id: str
    created_at: str
    tier: str = "free"
    status: str = "active"
    infrastructure: Dict[str, Any] = field(default_factory=dict)
    # Ground truth is present only because the corpus is simulated. Detection
    # code must never read this field; the evaluator is its only consumer.
    ground_truth_actor: Optional[str] = None


@dataclass
class Session(Record):
    session_id: str
    account_id: str
    started_at: str
    ended_at: str = ""
    surface: str = "chat"
    infrastructure: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TelemetryEvent(Record):
    """A single normalized observation.

    ``text`` holds prompt or model-output content, ``tool_name``/``tool_args``
    hold tool-call content, and ``enforcement_action`` holds platform actions.
    """

    event_id: str
    timestamp: str
    event_type: str
    account_id: str
    session_id: str = ""
    turn_index: int = 0
    text: str = ""
    text_language: str = "en"
    model_refusal: bool = False
    tool_name: str = ""
    tool_args: Dict[str, Any] = field(default_factory=dict)
    artifacts: List[str] = field(default_factory=list)
    enforcement_action: str = ""
    infrastructure: Dict[str, Any] = field(default_factory=dict)
    source: str = "first_party_telemetry"
    labels: List[str] = field(default_factory=list)


@dataclass
class ExternalReference(Record):
    """A public threat report or vendor feed entry used for corroboration."""

    reference_id: str
    title: str
    publisher: str
    published: str
    url: str = ""
    source_reliability: str = "B"  # Admiralty scale A-F
    information_credibility: str = "2"  # Admiralty scale 1-6
    behaviors: List[str] = field(default_factory=list)
    indicators: List[str] = field(default_factory=list)
    trust_tier: str = "osint"


@dataclass
class Corpus(Record):
    """The full normalized dataset handed to the detection stage."""

    schema_version: str = SCHEMA_VERSION
    generated_at: str = ""
    accounts: List[Dict[str, Any]] = field(default_factory=list)
    sessions: List[Dict[str, Any]] = field(default_factory=list)
    events: List[Dict[str, Any]] = field(default_factory=list)
    external_references: List[Dict[str, Any]] = field(default_factory=list)
    privacy: Dict[str, Any] = field(default_factory=dict)

    def account_objects(self) -> List[Account]:
        return [Account.from_dict(a) for a in self.accounts]

    def session_objects(self) -> List[Session]:
        return [Session.from_dict(s) for s in self.sessions]

    def event_objects(self) -> List[TelemetryEvent]:
        return [TelemetryEvent.from_dict(e) for e in self.events]

    def reference_objects(self) -> List[ExternalReference]:
        return [ExternalReference.from_dict(r) for r in self.external_references]


REQUIRED_EVENT_FIELDS = ("event_id", "timestamp", "event_type", "account_id")


def validate_corpus(corpus: Corpus) -> List[str]:
    """Return a list of schema violations; an empty list means the corpus is valid."""
    problems: List[str] = []
    account_ids = {a.get("account_id") for a in corpus.accounts}
    session_ids = {s.get("session_id") for s in corpus.sessions}

    for session in corpus.sessions:
        if session.get("account_id") not in account_ids:
            problems.append(f"session {session.get('session_id')} references unknown account")

    seen_events = set()
    for event in corpus.events:
        for required in REQUIRED_EVENT_FIELDS:
            if not event.get(required):
                problems.append(f"event {event.get('event_id', '?')} missing {required}")
        if event.get("event_type") not in EVENT_TYPES:
            problems.append(f"event {event.get('event_id')} has unknown type {event.get('event_type')}")
        if event.get("account_id") not in account_ids:
            problems.append(f"event {event.get('event_id')} references unknown account")
        sid = event.get("session_id")
        if sid and sid not in session_ids:
            problems.append(f"event {event.get('event_id')} references unknown session")
        eid = event.get("event_id")
        if eid in seen_events:
            problems.append(f"duplicate event_id {eid}")
        seen_events.add(eid)

    for reference in corpus.external_references:
        if reference.get("trust_tier") not in TRUST_TIERS:
            problems.append(f"reference {reference.get('reference_id')} has unknown trust tier")

    return problems
