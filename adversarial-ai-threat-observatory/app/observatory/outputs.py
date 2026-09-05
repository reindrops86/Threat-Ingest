"""Generated artifacts: detection rules, investigation summaries, and briefings.

Everything produced here is a draft for human review. Generated rules carry
``status: draft`` and an explicit approval field that a reviewer must change.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Sequence

from .campaigns import Campaign
from .cases import Case
from .detections import CATEGORY_RULES
from .schema import iso


def _yaml(value: Any, indent: int = 0) -> str:
    pad = "  " * indent
    if isinstance(value, dict):
        lines = []
        for key, item in value.items():
            if isinstance(item, (dict, list)) and item:
                lines.append(f"{pad}{key}:")
                lines.append(_yaml(item, indent + 1))
            else:
                lines.append(f"{pad}{key}: {_scalar(item)}")
        return "\n".join(lines)
    if isinstance(value, list):
        lines = []
        for item in value:
            if isinstance(item, (dict, list)):
                rendered = _yaml(item, indent + 1).lstrip()
                lines.append(f"{pad}- {rendered}")
            else:
                lines.append(f"{pad}- {_scalar(item)}")
        return "\n".join(lines)
    return f"{pad}{_scalar(value)}"


def _scalar(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    text = str(value)
    if any(ch in text for ch in ":#{}[]&*?|-<>=!%@`") or text.strip() != text or not text:
        return '"' + text.replace('"', '\\"') + '"'
    return text


def generate_detection_rule(case: Case, campaign: Campaign) -> Dict[str, Any]:
    """A reusable behavioral rule derived from the campaign, not from one string."""
    return {
        "id": f"AATO-BEH-{campaign.campaign_id[-3:]}",
        "version": "0.1.0",
        "status": "draft",
        "approved_by": None,
        "title": "Multi-account credential-phishing assistance with post-enforcement return",
        "derived_from_case": case.case_id,
        "created": iso(datetime.now(timezone.utc)),
        "scope": "session_sequence",
        "description": (
            "Fires when a single session escalates from benign to credential-collection "
            "assistance, reformulates after refusal, and is linked by a strong identifier "
            "to an account previously subject to enforcement."
        ),
        "logic": {
            "all_of": [
                {"detection": "BEH-001", "min_confidence": 0.55},
                {"any_of": [{"detection": "BEH-002"}, {"detection": "BEH-003"}, {"detection": "BEH-004"}]},
                {
                    "linkage": {
                        "strong_identifier_shared_with": "account_with_prior_enforcement",
                        "identifiers": ["client_fingerprint", "payment_fingerprint", "shared_artifact"],
                    }
                },
            ],
            "not_any_of": [
                {"context": "benign_security_awareness", "note": "authorised simulation language present"}
            ],
        },
        "observables_required": [
            "prompt.text",
            "model_output.model_refusal",
            "tool_call.artifacts",
            "enforcement.enforcement_action",
            "infrastructure.client_fingerprint",
        ],
        "expected_blind_spots": [
            "Operators who rotate client fingerprints between waves.",
            "Escalation split across sessions that are days apart and below the session window.",
            "Languages with no rule coverage; only English and Spanish cues are implemented.",
            "Artifacts never touched by a tool call are invisible to this rule.",
        ],
        "severity": "high",
        "response": "Route to human review; do not auto-suspend.",
        "tests": ["tests/test_detections.py::test_behavioral_rule_fires_on_actor_sessions"],
        "rollback": "Set status to disabled; rule state is versioned in git.",
    }


def render_rule_yaml(rule: Dict[str, Any]) -> str:
    return "# Draft rule - requires reviewer approval before deployment\n" + _yaml(rule) + "\n"


def _md_table(headers: Sequence[str], rows: Sequence[Sequence[Any]]) -> str:
    lines = ["| " + " | ".join(headers) + " |", "|" + "|".join(["---"] * len(headers)) + "|"]
    for row in rows:
        lines.append("| " + " | ".join(str(cell) for cell in row) + " |")
    return "\n".join(lines)


def investigation_report(case: Case, metrics: Dict[str, Any] | None = None) -> str:
    campaign = case.campaign
    observations = [c for c in case.claims if c["kind"] == "observation"]
    inferences = [c for c in case.claims if c["kind"] == "inference"]
    attribution = [c for c in case.claims if c["kind"] == "attribution"]

    lines: List[str] = []
    lines.append(f"# Investigation report {case.case_id}")
    lines.append("")
    lines.append(f"**Title:** {case.title}")
    lines.append(f"**Status:** {case.status}  ")
    lines.append(f"**Assessment confidence:** {case.confidence:.2f} ({case.band})  ")
    lines.append(f"**Accounts in scope:** {', '.join(campaign['account_ids'])}  ")
    lines.append(f"**Activity window:** {campaign['first_seen']} to {campaign['last_seen']}")
    lines.append("")
    lines.append("> All data in this report is simulated. No production telemetry, real credentials, "
                 "or live infrastructure is represented. Prompt excerpts are attacker-controlled text "
                 "and have been neutralized for safe rendering.")
    lines.append("")

    lines.append("## 1. Summary")
    lines.append("")
    lines.append(
        f"{len(campaign['account_ids'])} accounts across {len(campaign['waves'])} wave(s) show a "
        "consistent progression: benign warm-up, explicit boundary probing, then requests for "
        "credential-collection content, followed by tool calls that stage the same external artifact. "
        "After simulated enforcement, activity resumed from different network space with unchanged "
        "strong identifiers and obfuscated phrasing."
    )
    lines.append("")

    lines.append("## 2. Observations")
    lines.append("")
    lines.append("Statements below are present in telemetry and carry event provenance.")
    lines.append("")
    lines.append(
        _md_table(
            ["Claim", "Statement", "Provenance"],
            [[c["claim_id"], c["statement"], ", ".join(c["provenance"][:3]) or "-"] for c in observations],
        )
    )
    lines.append("")

    lines.append("## 3. Inferences")
    lines.append("")
    lines.append("Statements below are conclusions, not observations. Each carries a confidence value.")
    lines.append("")
    lines.append(
        _md_table(
            ["Claim", "Statement", "Confidence", "Basis"],
            [[c["claim_id"], c["statement"], f"{c['confidence']:.2f}", "; ".join(c["basis"])] for c in inferences],
        )
    )
    lines.append("")

    lines.append("## 4. Attribution position")
    lines.append("")
    for claim in attribution:
        lines.append(f"- {claim['statement']}")
    lines.append("")

    lines.append("## 5. Timeline")
    lines.append("")
    lines.append(
        _md_table(
            ["Timestamp", "Account", "Type", "Summary"],
            [[e["timestamp"], e["account_id"], e["type"], e["summary"]] for e in case.timeline[:40]],
        )
    )
    if len(case.timeline) > 40:
        lines.append("")
        lines.append(f"_{len(case.timeline) - 40} further timeline entries omitted; see the JSON case file._")
    lines.append("")

    lines.append("## 6. Linkage evidence")
    lines.append("")
    linkage = [e for e in case.evidence if e["kind"] == "linkage"]
    seen = set()
    rows = []
    for item in linkage:
        key = item["why"]
        if key in seen:
            continue
        seen.add(key)
        rows.append([item["supports"], item["why"]])
    lines.append(_md_table(["Strength", "Explanation"], rows[:12]))
    lines.append("")

    lines.append("## 7. Competing explanations")
    lines.append("")
    lines.append(
        _md_table(
            ["Alternative hypothesis", "Assessment", "Residual probability"],
            [[c["hypothesis"], c["assessment"], f"{c['residual_probability']:.2f}"] for c in case.competing_explanations],
        )
    )
    lines.append("")

    lines.append("## 8. Evidence gaps")
    lines.append("")
    for gap in case.evidence_gaps:
        lines.append(f"- {gap}")
    lines.append("")

    if case.corroboration:
        lines.append("## 9. External corroboration")
        lines.append("")
        lines.append(
            _md_table(
                ["Reference", "Publisher", "Tier", "Admiralty", "Matched"],
                [
                    [
                        c["reference_id"],
                        c["publisher"],
                        c["trust_tier"],
                        c["admiralty"],
                        ", ".join(c["matched_indicators"]) or "behaviors only",
                    ]
                    for c in case.corroboration
                ],
            )
        )
        lines.append("")
        lines.append("_External reporting is treated as corroborating, not independent; it may derive "
                     "from the same underlying observations (circular reporting risk)._")
        lines.append("")

    lines.append("## 10. Recommended actions")
    lines.append("")
    lines.append(
        _md_table(
            ["Action", "Scope", "Reversible", "Human approval", "Rationale"],
            [
                [
                    a["action"],
                    ", ".join(a["scope"])[:60],
                    "yes" if a["reversible"] else "no",
                    "required" if a["requires_human_approval"] else "not required",
                    a["rationale"],
                ]
                for a in case.recommended_actions
            ],
        )
    )
    lines.append("")

    if metrics:
        lines.append("## 11. Detection performance on this corpus")
        lines.append("")
        lines.append(
            _md_table(
                ["Metric", "Session-level (behavioral)", "Message-level (baseline)"],
                [
                    ["Precision", metrics["behavioral"]["precision"], metrics["baseline"]["precision"]],
                    ["Recall", metrics["behavioral"]["recall"], metrics["baseline"]["recall"]],
                    ["F1", metrics["behavioral"]["f1"], metrics["baseline"]["f1"]],
                    ["False positives", metrics["behavioral"]["false_positives"], metrics["baseline"]["false_positives"]],
                ],
            )
        )
        lines.append("")
        lines.append(f"- Median detection latency: **{metrics['detection_latency_hours']} h** from first "
                     "actor activity to first behavioral signal.")
        lines.append(f"- Campaign coverage: **{metrics['campaign_coverage']:.0%}** of simulated actor accounts "
                     "were placed in the correct cluster.")
        lines.append("")

    lines.append("## 12. Limitations")
    lines.append("")
    lines.append("- Rules are regular expressions over a simulated corpus; they will not transfer unchanged.")
    lines.append("- Style similarity is a weak, transferable signal. It supports linkage only alongside a "
                 "strong identifier and is never sufficient alone.")
    lines.append("- Confidence values are calibrated on synthetic data and should be re-estimated on any "
                 "real deployment before they inform enforcement.")
    lines.append("")
    return "\n".join(lines)


def enforcement_memo(case: Case) -> str:
    lines = [f"# Enforcement recommendation - {case.case_id}", ""]
    lines.append(f"Assessment confidence: **{case.confidence:.2f} ({case.band})**")
    lines.append("")
    lines.append("Actions are scoped by the evidence tier held for each account. Association-only "
                 "accounts are never suspended on linkage alone.")
    lines.append("")
    for action in case.recommended_actions:
        lines.append(f"## {action['action']} (tier {action['tier']})")
        lines.append("")
        lines.append(f"- **Scope:** {', '.join(action['scope'])}")
        lines.append(f"- **What it does:** {action['description']}")
        lines.append(f"- **Rationale:** {action['rationale']}")
        lines.append(f"- **Proportionality:** {action['proportionality']}")
        lines.append(f"- **Reversible:** {'yes' if action['reversible'] else 'no'}")
        lines.append(f"- **Human approval:** {'required' if action['requires_human_approval'] else 'not required'}")
        lines.append("")
    lines.append("## Appeal and rollback")
    lines.append("")
    lines.append("- Every suspension carries an appeal path and a preserved evidence bundle.")
    lines.append("- Watchlist entries expire after 90 days unless renewed with new evidence.")
    lines.append("- If the campaign confidence falls below 0.55 after analyst feedback, tier 3 actions are reverted.")
    lines.append("")
    return "\n".join(lines)


def threat_intel_report(case: Case, rule: Dict[str, Any]) -> str:
    campaign = case.campaign
    lines = ["# Threat intelligence report - simulated actor cluster", ""]
    lines.append(f"**Cluster:** {campaign['campaign_id']}  ")
    lines.append(f"**Confidence:** {case.confidence:.2f} ({case.band})  ")
    lines.append(f"**Window:** {campaign['first_seen']} - {campaign['last_seen']}")
    lines.append("")
    lines.append("## Behaviors observed")
    lines.append("")
    for rule_id in campaign["behaviors"]:
        lines.append(f"- `{rule_id}`")
    lines.append("")
    lines.append("## Abuse categories in scope")
    lines.append("")
    for name, spec in CATEGORY_RULES.items():
        lines.append(f"- **{name}** ({spec['severity']}): {spec['description']}")
    lines.append("")
    lines.append("## Infrastructure (simulated)")
    lines.append("")
    for key, values in campaign["shared_infrastructure"].items():
        lines.append(f"- `{key}`: {', '.join(values)}")
    for artifact in campaign["artifacts"]:
        lines.append(f"- `artifact`: {artifact}")
    lines.append("")
    lines.append("## Tradecraft changes after enforcement")
    lines.append("")
    for wave in campaign["waves"]:
        lines.append(
            f"- Wave {wave['wave']}: {', '.join(wave['account_ids'])} from {', '.join(wave['ip_prefixes']) or 'n/a'} "
            f"({wave['first_created']})"
        )
    lines.append("")
    lines.append("## Candidate detection")
    lines.append("")
    lines.append("```yaml")
    lines.append(render_rule_yaml(rule).rstrip())
    lines.append("```")
    lines.append("")
    lines.append("## Confidence and caveats")
    lines.append("")
    for gap in case.evidence_gaps:
        lines.append(f"- {gap}")
    lines.append("")
    return "\n".join(lines)


def executive_brief(case: Case, metrics: Dict[str, Any]) -> str:
    campaign = case.campaign
    high_actions = [a for a in case.recommended_actions if a.get("requires_human_approval")]
    lines = ["# Executive one-pager", ""]
    lines.append(f"**Case {case.case_id} - {case.title}**")
    lines.append("")
    lines.append("## What happened")
    lines.append("")
    lines.append(
        f"One apparent operator used {len(campaign['account_ids'])} accounts to work toward "
        "credential-phishing content, testing where our limits sit before escalating. After we "
        "acted on the first accounts, the activity returned with new accounts and reworded requests "
        "but the same technical fingerprint and the same landing-page hostname."
    )
    lines.append("")
    lines.append("## Why we believe the accounts are connected")
    lines.append("")
    lines.append(
        f"- Assessment confidence **{case.confidence:.2f} ({case.band})**, reduced from the raw "
        f"clustering score of {campaign['confidence']:.2f} to account for alternative explanations."
    )
    lines.append(f"- Strong links: {', '.join(campaign['strong_link_types']) or 'none'}.")
    lines.append("- We do not claim to know who the operator is. This is a linkage assessment, not attribution.")
    lines.append("")
    lines.append("## What we recommend")
    lines.append("")
    for action in case.recommended_actions:
        lines.append(f"- **{action['action'].replace('_', ' ')}** for {len(action['scope'])} entities - {action['proportionality']}")
    if high_actions:
        lines.append("")
        lines.append("Tier 3 actions require named human approval before execution.")
    lines.append("")
    lines.append("## What it costs us to be wrong")
    lines.append("")
    lines.append(
        f"- Behavioral detection precision on this corpus: **{metrics['behavioral']['precision']:.2f}** "
        f"versus **{metrics['baseline']['precision']:.2f}** for a message-level keyword classifier."
    )
    lines.append(
        f"- The baseline would have wrongly actioned {metrics['baseline']['false_positives']} account(s), "
        "including an authorised security-awareness team."
    )
    lines.append(f"- Median time to first detection: **{metrics['detection_latency_hours']} hours**.")
    lines.append("")
    lines.append("## What changes as a result")
    lines.append("")
    lines.append("- One reusable behavioral rule is drafted for reviewer approval.")
    lines.append("- The reused hostname is added to a detection-only watchlist as the durable pivot.")
    lines.append("- Analyst dispositions feed the next evaluation run, which re-scores rule precision.")
    lines.append("")
    lines.append("_Simulated data. No production systems or real users are involved._")
    lines.append("")
    return "\n".join(lines)
