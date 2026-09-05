"""Command-line interface for the Adversarial AI Threat Observatory.

    python -m app.main demo            full pipeline, prints the walkthrough
    python -m app.main run --write     full pipeline, writes data/ reports/ rules/
    python -m app.main generate        write the raw simulated corpus
    python -m app.main detect          list behavioral signals
    python -m app.main graph           print entity links and campaign clusters
    python -m app.main case            open the case workspace view
    python -m app.main evaluate        detection metrics and analyst feedback
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

if __package__ in (None, ""):  # allow `python app/main.py`
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.observatory import pipeline
from app.observatory import simulate
from app.observatory.feedback import Disposition, apply_feedback, load_dispositions

ROOT = Path(__file__).resolve().parent.parent
BANNER = "Adversarial AI Threat Observatory - simulated telemetry only"
BAR = "=" * 78


def _header(text: str) -> None:
    print(f"\n{BAR}\n{text}\n{BAR}")


def cmd_generate(args: argparse.Namespace) -> int:
    corpus = simulate.build_corpus(args.seed)
    target = Path(args.out or ROOT / "data" / "telemetry_raw.json")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(corpus.to_dict(), indent=2), encoding="utf-8")
    print(
        f"Wrote {len(corpus.events)} events across {len(corpus.accounts)} accounts "
        f"and {len(corpus.sessions)} sessions to {target}"
    )
    return 0


def cmd_detect(args: argparse.Namespace) -> int:
    result = pipeline.run(args.seed)
    _header("Behavioral signals")
    for signal in result.signals:
        print(f"\n[{signal.rule_id}] {signal.name}")
        print(f"  account={signal.account_id} session={signal.session_id or '-'} scope={signal.scope}")
        print(f"  severity={signal.severity} confidence={signal.confidence:.2f} first_seen={signal.first_seen}")
        print(f"  rationale: {signal.rationale}")
        for item in signal.evidence[:2]:
            print(f"    evidence {item.event_id}: {item.excerpt}")
            print(f"      why: {item.why}")
    print(f"\n{len(result.signals)} signals across {len({s.account_id for s in result.signals})} accounts.")
    return 0


def cmd_graph(args: argparse.Namespace) -> int:
    result = pipeline.run(args.seed)
    _header("Account linkage (confidence >= 0.40)")
    for edge in result.edges:
        if edge.confidence < 0.40:
            continue
        print(f"\n{edge.source} <-> {edge.target}  confidence={edge.confidence:.2f}")
        for link in edge.links:
            print(f"  [{link.strength:8}] {link.link_type}: {link.explanation}")

    _header("Campaign clusters")
    for campaign in result.campaigns:
        print(f"\n{campaign.campaign_id}  confidence={campaign.confidence:.2f} ({campaign.band})")
        print(f"  accounts: {', '.join(campaign.account_ids)}")
        print(f"  strong links: {', '.join(campaign.strong_link_types) or 'none'}")
        print(f"  behaviors: {', '.join(campaign.behaviors) or 'none'}")
        for wave in campaign.waves:
            print(
                f"  wave {wave['wave']}: {', '.join(wave['account_ids'])} "
                f"from {', '.join(wave['ip_prefixes']) or 'n/a'} at {wave['first_created']}"
            )
    print(f"\nGraph: {result.graph['node_count']} nodes, {result.graph['edge_count']} edges.")
    return 0


def cmd_case(args: argparse.Namespace) -> int:
    result = pipeline.run(args.seed)
    if not result.cases:
        print("No cases were opened; no cluster crossed the linking threshold.")
        return 1
    case = next((c for c in result.cases if c.case_id == args.case_id), result.cases[0])

    _header(f"{case.case_id}  {case.title}")
    print(f"status={case.status}  confidence={case.confidence:.2f} ({case.band})")
    print(f"accounts: {', '.join(case.campaign['account_ids'])}")

    print("\n-- Timeline " + "-" * 66)
    for entry in case.timeline:
        print(f"  {entry['timestamp']}  {entry['account_id']:<10} {entry['type']:<14} {entry['summary']}")

    for kind, label in (("observation", "Observations"), ("inference", "Inferences"), ("attribution", "Attribution")):
        print(f"\n-- {label} " + "-" * (74 - len(label)))
        for claim in [c for c in case.claims if c["kind"] == kind]:
            print(f"  [{claim['claim_id']}] conf={claim['confidence']:.2f}  {claim['statement']}")
            if claim["basis"]:
                print(f"      basis: {'; '.join(claim['basis'])}")
            if claim["provenance"]:
                print(f"      provenance: {', '.join(claim['provenance'][:4])}")

    print("\n-- Competing explanations " + "-" * 52)
    for alt in case.competing_explanations:
        print(f"  residual={alt['residual_probability']:.2f}  {alt['hypothesis']}")
        print(f"      {alt['assessment']}")

    print("\n-- Evidence gaps " + "-" * 61)
    for gap in case.evidence_gaps:
        print(f"  - {gap}")

    print("\n-- Recommended actions " + "-" * 55)
    for action in case.recommended_actions:
        approval = "HUMAN APPROVAL REQUIRED" if action["requires_human_approval"] else "auto-eligible"
        print(f"  tier {action['tier']} {action['action']} [{approval}]")
        print(f"      scope: {', '.join(action['scope'])}")
        print(f"      {action['rationale']}")
    return 0


def cmd_evaluate(args: argparse.Namespace) -> int:
    result = pipeline.run(args.seed)
    metrics = result.metrics
    _header("Detection evaluation")
    print(f"corpus: {metrics['corpus']['accounts']} accounts, {metrics['corpus']['events']} events")
    print(f"simulated actor accounts: {', '.join(metrics['corpus']['simulated_actor_accounts'])}")
    print(f"\n{'metric':<20}{'behavioral':>14}{'baseline':>14}")
    for key in ("precision", "recall", "f1", "true_positives", "false_positives", "false_negatives"):
        print(f"{key:<20}{metrics['behavioral'][key]:>14}{metrics['baseline'][key]:>14}")
    print(f"\nbaseline false positives: {', '.join(metrics['baseline']['false_positive_accounts']) or 'none'}")
    print(f"behavioral false positives: {', '.join(metrics['behavioral']['false_positive_accounts']) or 'none'}")
    print(f"median detection latency: {metrics['detection_latency_hours']} h")
    print(f"campaign coverage: {metrics['campaign_coverage']:.0%}  purity: {metrics['campaign_purity']:.0%}")

    dispositions = load_dispositions(Path(args.dispositions)) if args.dispositions else []
    summary = apply_feedback(result.signals, dispositions) if dispositions else None
    feedback = summary.to_dict() if summary else result.feedback

    _header("Analyst feedback loop")
    print(f"signals reviewed: {feedback['reviewed']}  agreement rate: {feedback['agreement_rate']:.0%}")
    for rule_id, stats in feedback["per_rule"].items():
        print(f"  {rule_id}: {stats}")
    for proposal in feedback["proposed_adjustments"]:
        print(f"  proposal for {proposal['rule_id']}: {proposal['change']} - {proposal['detail']}")
    if not feedback["proposed_adjustments"]:
        print("  no rule adjustments proposed at current review volume")
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    result = pipeline.run(args.seed)
    _header(BANNER)
    print(f"schema problems: {len(result.schema_problems)}")
    print(f"privacy: {result.privacy['events_retained']} events retained, "
          f"{result.privacy['identifiers_pseudonymized']} identifier sets pseudonymized")
    print(f"signals: {len(result.signals)}  campaigns: {len(result.campaigns)}  cases: {len(result.cases)}")
    if args.write:
        written = pipeline.write_artifacts(result, ROOT)
        print("\nartifacts written:")
        for path in written:
            print(f"  {path.relative_to(ROOT)}")
    return 0


def cmd_demo(args: argparse.Namespace) -> int:
    result = pipeline.run(args.seed)
    _header(BANNER)
    print("Stage 1  Telemetry + OSINT + vendor feeds")
    print(f"  {len(result.corpus.events)} events, {len(result.corpus.accounts)} accounts, "
          f"{len(result.corpus.external_references)} external references")
    print(f"  schema violations: {len(result.schema_problems)}")

    print("\nStage 2  Normalization and privacy controls")
    for note in result.privacy["notes"]:
        print(f"  - {note}")

    print("\nStage 3  Behavioral detections and anomaly scoring")
    rules = sorted({s.rule_id for s in result.signals})
    print(f"  {len(result.signals)} signals from rules {', '.join(rules)}")
    top = sorted(result.account_scores.values(), key=lambda a: a["score"], reverse=True)[:6]
    for entry in top:
        print(f"  {entry['account_id']:<10} score={entry['score']:.2f} "
              f"refusal_rate={entry['refusal_rate']:.2f} categories={','.join(entry['categories']) or '-'}")

    print("\nStage 4  Entity linking and campaign clustering")
    for campaign in result.campaigns:
        print(f"  {campaign.campaign_id}: {len(campaign.account_ids)} accounts, "
              f"confidence {campaign.confidence:.2f} ({campaign.band}), "
              f"{len(campaign.waves)} wave(s)")
        print(f"    strong links: {', '.join(campaign.strong_link_types) or 'none'}")

    print("\nStage 5  Evidence-backed investigation workspace")
    if result.cases:
        case = result.cases[0]
        print(f"  {case.case_id} confidence {case.confidence:.2f} ({case.band})")
        print(f"  {len(case.timeline)} timeline entries, {len(case.evidence)} evidence items, "
              f"{len(case.competing_explanations)} competing explanations, "
              f"{len(case.evidence_gaps)} stated evidence gaps")

    print("\nStage 6  Detection, enforcement, and executive outputs")
    if result.cases:
        for action in result.cases[0].recommended_actions:
            print(f"  tier {action['tier']} {action['action']} -> {len(action['scope'])} entities")
        print(f"  drafted rule {result.rule['id']} (status {result.rule['status']}, approver required)")

    print("\nStage 7  Analyst feedback and detection evaluation")
    metrics = result.metrics
    print(f"  behavioral precision {metrics['behavioral']['precision']:.2f} / recall {metrics['behavioral']['recall']:.2f}")
    print(f"  baseline   precision {metrics['baseline']['precision']:.2f} / recall {metrics['baseline']['recall']:.2f}")
    print(f"  baseline false positives: {', '.join(metrics['baseline']['false_positive_accounts']) or 'none'}")
    print(f"  median detection latency {metrics['detection_latency_hours']} h, "
          f"campaign coverage {metrics['campaign_coverage']:.0%}")
    print(f"  analyst agreement {result.feedback['agreement_rate']:.0%} over {result.feedback['reviewed']} reviews")

    if args.write:
        written = pipeline.write_artifacts(result, ROOT)
        print(f"\n  {len(written)} artifacts written under {ROOT.name}/")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="observatory", description=BANNER)
    parser.add_argument("--seed", type=int, default=20260406, help="simulation seed")
    sub = parser.add_subparsers(dest="command")

    p = sub.add_parser("generate", help="write the raw simulated corpus")
    p.add_argument("--out", help="output path")
    p.set_defaults(func=cmd_generate)

    p = sub.add_parser("detect", help="list behavioral signals")
    p.set_defaults(func=cmd_detect)

    p = sub.add_parser("graph", help="print entity links and campaign clusters")
    p.set_defaults(func=cmd_graph)

    p = sub.add_parser("case", help="open the case workspace view")
    p.add_argument("--case-id", default="CASE-2026-001")
    p.set_defaults(func=cmd_case)

    p = sub.add_parser("evaluate", help="detection metrics and analyst feedback")
    p.add_argument("--dispositions", help="path to an analyst dispositions JSON file")
    p.set_defaults(func=cmd_evaluate)

    p = sub.add_parser("run", help="run the full pipeline")
    p.add_argument("--write", action="store_true", help="write artifacts to disk")
    p.set_defaults(func=cmd_run)

    p = sub.add_parser("demo", help="narrated end-to-end walkthrough")
    p.add_argument("--write", action="store_true", help="write artifacts to disk")
    p.set_defaults(func=cmd_demo)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        args = parser.parse_args((argv or []) + ["demo"])
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
