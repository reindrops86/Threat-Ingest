"""Evaluation metrics and the analyst feedback loop.

Ground-truth actor labels exist only because the corpus is simulated. Nothing
in the detection path reads them; this module is their only consumer.
"""

from __future__ import annotations

import json
import statistics
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Sequence

from .campaigns import Campaign
from .detections import Signal
from .schema import Account, TelemetryEvent, utc

BEHAVIORAL_FLAG_THRESHOLD = 0.5


def _prf(tp: int, fp: int, fn: int) -> Dict[str, Any]:
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return {
        "true_positives": tp,
        "false_positives": fp,
        "false_negatives": fn,
        "precision": round(precision, 3),
        "recall": round(recall, 3),
        "f1": round(f1, 3),
    }


def _score(flagged: set, truth: set, universe: set) -> Dict[str, Any]:
    tp = len(flagged & truth)
    fp = len(flagged - truth)
    fn = len(truth - flagged)
    result = _prf(tp, fp, fn)
    result["false_positive_accounts"] = sorted(flagged - truth)
    result["missed_accounts"] = sorted(truth - flagged)
    result["flag_rate"] = round(len(flagged) / len(universe), 3) if universe else 0.0
    return result


def evaluate(
    accounts: Sequence[Account],
    events: Sequence[TelemetryEvent],
    signals: Sequence[Signal],
    campaigns: Sequence[Campaign],
    baseline_flags: Dict[str, List[str]],
) -> Dict[str, Any]:
    universe = {a.account_id for a in accounts}
    truth = {a.account_id for a in accounts if a.ground_truth_actor}

    behavioral_flagged = {
        s.account_id for s in signals if s.confidence >= BEHAVIORAL_FLAG_THRESHOLD and s.scope != "message"
    }
    baseline_flagged = set(baseline_flags)

    first_activity: Dict[str, str] = {}
    for event in events:
        current = first_activity.get(event.account_id)
        if current is None or event.timestamp < current:
            first_activity[event.account_id] = event.timestamp

    latencies: List[float] = []
    for account_id in sorted(truth):
        account_signals = [s for s in signals if s.account_id == account_id]
        if not account_signals or account_id not in first_activity:
            continue
        earliest = min(utc(s.first_seen) for s in account_signals)
        latencies.append((earliest - utc(first_activity[account_id])).total_seconds() / 3600)

    coverage = 0.0
    purity = 0.0
    best: Campaign | None = None
    for campaign in campaigns:
        members = set(campaign.account_ids)
        overlap = len(members & truth)
        if truth and overlap / len(truth) > coverage:
            coverage = overlap / len(truth)
            purity = overlap / len(members)
            best = campaign

    return {
        "corpus": {
            "accounts": len(universe),
            "events": len(events),
            "simulated_actor_accounts": sorted(truth),
        },
        "behavioral": _score(behavioral_flagged, truth, universe),
        "baseline": _score(baseline_flagged, truth, universe),
        "detection_latency_hours": round(statistics.median(latencies), 2) if latencies else None,
        "detection_latency_all_hours": [round(v, 2) for v in latencies],
        "campaign_coverage": round(coverage, 3),
        "campaign_purity": round(purity, 3),
        "best_campaign": best.campaign_id if best else None,
        "notes": [
            "Precision and recall are account-level on a synthetic corpus and do not transfer to "
            "production traffic.",
            "The baseline is a deliberately naive message-level keyword classifier, included to show "
            "the cost of ignoring sequence context.",
        ],
    }


@dataclass
class Disposition:
    """An analyst's verdict on one signal."""

    signal_id: str
    verdict: str  # confirmed | false_positive | inconclusive
    analyst: str = "analyst"
    note: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "signal_id": self.signal_id,
            "verdict": self.verdict,
            "analyst": self.analyst,
            "note": self.note,
        }


@dataclass
class FeedbackSummary:
    reviewed: int = 0
    agreement_rate: float = 0.0
    per_rule: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    proposed_adjustments: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "reviewed": self.reviewed,
            "agreement_rate": round(self.agreement_rate, 3),
            "per_rule": self.per_rule,
            "proposed_adjustments": self.proposed_adjustments,
        }


def apply_feedback(signals: Sequence[Signal], dispositions: Sequence[Disposition]) -> FeedbackSummary:
    """Turn analyst verdicts into per-rule precision and concrete tuning proposals."""
    by_id = {s.signal_id: s for s in signals}
    summary = FeedbackSummary()
    tallies: Dict[str, Dict[str, int]] = {}

    agreed = 0
    for disposition in dispositions:
        signal = by_id.get(disposition.signal_id)
        if signal is None:
            continue
        summary.reviewed += 1
        tally = tallies.setdefault(signal.rule_id, {"confirmed": 0, "false_positive": 0, "inconclusive": 0})
        tally[disposition.verdict] = tally.get(disposition.verdict, 0) + 1
        if disposition.verdict == "confirmed":
            agreed += 1

    summary.agreement_rate = agreed / summary.reviewed if summary.reviewed else 0.0

    for rule_id, tally in sorted(tallies.items()):
        judged = tally["confirmed"] + tally["false_positive"]
        precision = tally["confirmed"] / judged if judged else None
        summary.per_rule[rule_id] = {
            **tally,
            "analyst_precision": round(precision, 3) if precision is not None else None,
        }
        if precision is None:
            continue
        if precision < 0.6:
            summary.proposed_adjustments.append(
                {
                    "rule_id": rule_id,
                    "change": "raise_confidence_floor",
                    "detail": f"Analyst precision {precision:.2f}. Require a corroborating rule before "
                    "this detection can flag an account on its own.",
                    "requires_review": True,
                }
            )
        elif precision >= 0.9 and judged >= 3:
            summary.proposed_adjustments.append(
                {
                    "rule_id": rule_id,
                    "change": "promote_to_auto_case",
                    "detail": f"Analyst precision {precision:.2f} over {judged} reviews. Eligible for "
                    "automatic case creation, still human-approved for enforcement.",
                    "requires_review": True,
                }
            )
    return summary


def load_dispositions(path: Path) -> List[Disposition]:
    if not path.exists():
        return []
    payload = json.loads(path.read_text(encoding="utf-8"))
    return [Disposition(**item) for item in payload.get("dispositions", [])]
