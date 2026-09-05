"""End-to-end orchestration for the observatory."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List

from . import campaigns as campaign_mod
from . import cases as case_mod
from . import detections as detect_mod
from . import entities as entity_mod
from . import feedback as feedback_mod
from . import outputs as output_mod
from . import privacy as privacy_mod
from . import simulate as simulate_mod
from .schema import Corpus, validate_corpus


@dataclass
class PipelineResult:
    corpus: Corpus
    privacy: Dict[str, Any]
    schema_problems: List[str]
    signals: List[detect_mod.Signal]
    account_scores: Dict[str, Any]
    profiles: Dict[str, entity_mod.AccountProfile]
    edges: List[entity_mod.Edge]
    graph: Dict[str, Any]
    campaigns: List[campaign_mod.Campaign]
    cases: List[case_mod.Case]
    rule: Dict[str, Any] = field(default_factory=dict)
    metrics: Dict[str, Any] = field(default_factory=dict)
    feedback: Dict[str, Any] = field(default_factory=dict)


# A scripted analyst review queue. It stands in for a real triage backlog so the
# feedback loop can be demonstrated; verdicts are illustrative, not ground truth.
VERDICT_SCRIPT: Dict[str, List[str]] = {
    "BEH-001": ["confirmed", "confirmed", "confirmed"],
    "BEH-002": ["confirmed", "confirmed", "inconclusive"],
    "BEH-003": ["confirmed"],
    "BEH-004": ["confirmed", "confirmed"],
    "BEH-005": ["false_positive", "false_positive", "confirmed"],
    "BEH-006": ["confirmed", "inconclusive"],
}

VERDICT_NOTES = {
    "confirmed": "Sequence evidence holds up on review.",
    "inconclusive": "Plausible but not decisive without a corroborating rule.",
    "false_positive": "Tool call touched an artifact that was benign in context.",
}


def _sample_review(signals: List[detect_mod.Signal]) -> List[feedback_mod.Disposition]:
    by_rule: Dict[str, List[detect_mod.Signal]] = {}
    for signal in signals:
        by_rule.setdefault(signal.rule_id, []).append(signal)

    dispositions: List[feedback_mod.Disposition] = []
    for rule_id, group in sorted(by_rule.items()):
        verdicts = VERDICT_SCRIPT.get(rule_id, ["inconclusive"])
        for signal, verdict in zip(group, verdicts):
            dispositions.append(
                feedback_mod.Disposition(signal.signal_id, verdict, "a.mensah", VERDICT_NOTES[verdict])
            )
    return dispositions


def run(seed: int = 20260406, corpus: Corpus | None = None) -> PipelineResult:
    raw = corpus or simulate_mod.build_corpus(seed)
    problems = validate_corpus(raw)

    normalized, privacy_report = privacy_mod.normalize(raw)
    events = normalized.event_objects()
    accounts = normalized.account_objects()
    references = normalized.reference_objects()

    detector = detect_mod.BehavioralDetector()
    signals = detector.run(events)
    scores = detect_mod.score_accounts(events, signals)

    profiles = entity_mod.build_profiles(accounts, events, signals)
    edges = entity_mod.resolve(profiles)
    graph = entity_mod.build_graph(profiles, edges)
    clusters = campaign_mod.cluster(profiles, edges)

    cases = [
        case_mod.build_case(campaign, profiles, events, signals, edges, references, index)
        for index, campaign in enumerate(clusters, start=1)
    ]

    baseline = detect_mod.classify_message_baseline(events)
    metrics = feedback_mod.evaluate(accounts, events, signals, clusters, baseline)

    dispositions = _sample_review(signals)
    feedback_summary = feedback_mod.apply_feedback(signals, dispositions)

    rule = output_mod.generate_detection_rule(cases[0], clusters[0]) if cases else {}

    return PipelineResult(
        corpus=normalized,
        privacy=privacy_report.to_dict(),
        schema_problems=problems,
        signals=signals,
        account_scores=scores,
        profiles=profiles,
        edges=edges,
        graph=graph,
        campaigns=clusters,
        cases=cases,
        rule=rule,
        metrics=metrics,
        feedback=feedback_summary.to_dict(),
    )


def _write(path: Path, content: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def write_artifacts(result: PipelineResult, root: Path) -> List[Path]:
    data_dir = root / "data"
    reports_dir = root / "reports"
    rules_dir = root / "rules"
    written: List[Path] = []

    written.append(
        _write(data_dir / "telemetry_normalized.json", json.dumps(result.corpus.to_dict(), indent=2))
    )
    written.append(
        _write(
            data_dir / "signals.json",
            json.dumps({"signals": [s.to_dict() for s in result.signals]}, indent=2),
        )
    )
    written.append(
        _write(
            data_dir / "entity_graph.json",
            json.dumps(
                {
                    "graph": result.graph,
                    "account_links": [e.to_dict() for e in result.edges if e.confidence >= 0.4],
                },
                indent=2,
            ),
        )
    )
    written.append(
        _write(
            data_dir / "campaigns.json",
            json.dumps({"campaigns": [c.to_dict() for c in result.campaigns]}, indent=2),
        )
    )
    written.append(
        _write(
            data_dir / "cases.json",
            json.dumps({"cases": [c.to_dict() for c in result.cases]}, indent=2),
        )
    )
    written.append(_write(data_dir / "evaluation.json", json.dumps(result.metrics, indent=2)))
    written.append(_write(data_dir / "feedback_summary.json", json.dumps(result.feedback, indent=2)))

    if result.cases:
        case = result.cases[0]
        campaign = result.campaigns[0]
        written.append(
            _write(reports_dir / f"{case.case_id}-investigation.md", output_mod.investigation_report(case, result.metrics))
        )
        written.append(
            _write(reports_dir / f"{case.case_id}-enforcement.md", output_mod.enforcement_memo(case))
        )
        written.append(
            _write(reports_dir / f"{case.case_id}-threat-intel.md", output_mod.threat_intel_report(case, result.rule))
        )
        written.append(
            _write(reports_dir / f"{case.case_id}-executive-brief.md", output_mod.executive_brief(case, result.metrics))
        )
        written.append(
            _write(rules_dir / f"{result.rule['id']}.yml", output_mod.render_rule_yaml(result.rule))
        )
        del campaign
    return written
