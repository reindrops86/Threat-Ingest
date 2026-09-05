"""Normalization, privacy controls, and untrusted-content handling.

Two independent concerns live here:

1. Data minimization - pseudonymize identifiers, redact contact details, and
   enforce a retention window before any analysis runs.
2. Untrusted-content discipline - telemetry text is attacker-controlled. It is
   treated as data, never as instructions, whenever it is rendered into a
   report that a human or a model will later read.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any, Dict, List

from .schema import Corpus, iso, utc

PSEUDONYM_SALT = "observatory-demo-salt"

EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
PHONE_RE = re.compile(r"\b\+?\d[\d ()-]{7,}\d\b")
CARD_RE = re.compile(r"\b(?:\d[ -]?){13,19}\b")

# Directive phrasing that must never survive into a rendered report.
INJECTION_RE = re.compile(
    r"(?i)\b(ignore (all|any|previous|prior)[^.\n]*|disregard (the )?(above|previous)[^.\n]*|"
    r"system prompt|you are now|new instructions?:|act as (an? )?(admin|developer mode))"
)

RETENTION_DAYS = 90
CONTENT_RETENTION_DAYS = 30


def pseudonymize(value: str, prefix: str = "px") -> str:
    if not value:
        return ""
    digest = hashlib.sha256(f"{PSEUDONYM_SALT}:{value}".encode("utf-8")).hexdigest()
    return f"{prefix}_{digest[:12]}"


def redact(text: str) -> str:
    text = EMAIL_RE.sub("[redacted-email]", text)
    text = CARD_RE.sub("[redacted-number]", text)
    text = PHONE_RE.sub("[redacted-phone]", text)
    return text


def neutralize_untrusted(text: str, limit: int = 240) -> str:
    """Render attacker-controlled text safely for inclusion in a report."""
    cleaned = INJECTION_RE.sub("[directive-neutralized]", redact(text))
    cleaned = cleaned.replace("```", "'''").replace("\n", " ").strip()
    if len(cleaned) > limit:
        cleaned = cleaned[: limit - 1].rstrip() + "\u2026"
    return cleaned


def _mask_infrastructure(infra: Dict[str, Any]) -> Dict[str, Any]:
    if not infra:
        return {}
    masked = dict(infra)
    ip = masked.get("ip", "")
    if ip:
        masked["ip_prefix"] = masked.get("ip_prefix") or ".".join(ip.split(".")[:3]) + ".0/24"
        masked["ip"] = pseudonymize(ip, "ip")
    for key, prefix in (
        ("client_fingerprint", "fp"),
        ("payment_fingerprint", "pay"),
    ):
        if masked.get(key):
            masked[key] = pseudonymize(masked[key], prefix)
    return masked


@dataclass
class PrivacyReport:
    events_in: int = 0
    events_retained: int = 0
    events_dropped_by_retention: int = 0
    content_minimized: int = 0
    identifiers_pseudonymized: int = 0
    redactions: int = 0
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "events_in": self.events_in,
            "events_retained": self.events_retained,
            "events_dropped_by_retention": self.events_dropped_by_retention,
            "content_minimized": self.content_minimized,
            "identifiers_pseudonymized": self.identifiers_pseudonymized,
            "redactions": self.redactions,
            "retention_days": RETENTION_DAYS,
            "content_retention_days": CONTENT_RETENTION_DAYS,
            "notes": self.notes,
        }


def normalize(corpus: Corpus) -> tuple[Corpus, PrivacyReport]:
    """Apply retention, pseudonymization, and redaction to a raw corpus."""
    report = PrivacyReport(events_in=len(corpus.events))
    if not corpus.events:
        return corpus, report

    latest = max(utc(e["timestamp"]) for e in corpus.events)
    retention_cutoff = latest - timedelta(days=RETENTION_DAYS)
    content_cutoff = latest - timedelta(days=CONTENT_RETENTION_DAYS)

    events: List[Dict[str, Any]] = []
    for event in corpus.events:
        when = utc(event["timestamp"])
        if when < retention_cutoff:
            report.events_dropped_by_retention += 1
            continue

        clean = dict(event)
        original_text = clean.get("text", "")
        if original_text:
            redacted = redact(original_text)
            if redacted != original_text:
                report.redactions += 1
            clean["text"] = redacted
        if when < content_cutoff and clean.get("text"):
            # Past the content window only derived features survive.
            clean["text_length"] = len(clean["text"])
            clean["text"] = "[content-expired]"
            report.content_minimized += 1

        infra = clean.get("infrastructure") or {}
        if infra:
            clean["infrastructure"] = _mask_infrastructure(infra)
            report.identifiers_pseudonymized += 1
        events.append(clean)

    accounts = []
    for account in corpus.accounts:
        clean = dict(account)
        clean["infrastructure"] = _mask_infrastructure(clean.get("infrastructure") or {})
        accounts.append(clean)

    sessions = []
    for session in corpus.sessions:
        clean = dict(session)
        clean["infrastructure"] = _mask_infrastructure(clean.get("infrastructure") or {})
        sessions.append(clean)

    report.events_retained = len(events)
    report.notes.append(
        "IPs reduced to /24 prefix plus salted pseudonym; raw addresses are not stored."
    )
    report.notes.append(
        f"Prompt and output content is dropped after {CONTENT_RETENTION_DAYS} days; "
        f"derived detection features are kept for {RETENTION_DAYS} days."
    )
    report.notes.append(
        "Ground-truth actor labels exist only because the corpus is simulated and are "
        "readable solely by the evaluator."
    )

    normalized = Corpus(
        schema_version=corpus.schema_version,
        generated_at=iso(latest),
        accounts=accounts,
        sessions=sessions,
        events=events,
        external_references=list(corpus.external_references),
        privacy={"state": "normalized", **report.to_dict()},
    )
    return normalized, report
