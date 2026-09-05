"""Entity resolution, clustering, case construction, outputs, and evaluation."""

from __future__ import annotations

import pytest

from app.observatory import feedback as feedback_mod
from app.observatory import outputs, pipeline
from app.observatory.campaigns import confidence_band
from app.observatory.entities import LINK_THRESHOLD

ACTOR_ACCOUNTS = {"acct-a1", "acct-a2", "acct-a3", "acct-b1", "acct-b2"}
LOOKALIKE_ACCOUNTS = {"acct-sec1", "acct-sec2", "acct-sec3"}


@pytest.fixture(scope="module")
def result() -> pipeline.PipelineResult:
    return pipeline.run()


def _edge(result: pipeline.PipelineResult, a: str, b: str):
    return next((e for e in result.edges if {e.source, e.target} == {a, b}), None)


def test_waves_are_linked_by_a_strong_identifier(result: pipeline.PipelineResult) -> None:
    edge = _edge(result, "acct-a1", "acct-b1")
    assert edge is not None
    assert edge.confidence >= LINK_THRESHOLD
    assert any(link.strength == "strong" for link in edge.links)


def test_every_link_carries_an_explanation(result: pipeline.PipelineResult) -> None:
    for edge in result.edges:
        assert edge.links
        for link in edge.links:
            assert link.explanation.strip()


def test_weak_correlates_alone_never_cross_the_linking_threshold(result: pipeline.PipelineResult) -> None:
    for edge in result.edges:
        if not any(link.strength == "strong" for link in edge.links):
            assert edge.confidence < LINK_THRESHOLD


def test_authorised_training_team_is_not_clustered_with_the_actor(result: pipeline.PipelineResult) -> None:
    for campaign in result.campaigns:
        members = set(campaign.account_ids)
        assert not (members & ACTOR_ACCOUNTS and members & LOOKALIKE_ACCOUNTS)


def test_campaign_contains_both_waves(result: pipeline.PipelineResult) -> None:
    campaign = result.campaigns[0]
    assert set(campaign.account_ids) == ACTOR_ACCOUNTS
    assert len(campaign.waves) == 2
    assert campaign.waves[0]["ip_prefixes"] != campaign.waves[1]["ip_prefixes"]
    assert campaign.band in {"moderate", "high"}


def test_confidence_is_capped_below_certainty(result: pipeline.PipelineResult) -> None:
    assert all(c.confidence <= 0.9 for c in result.campaigns)
    assert all(c.confidence <= 0.9 for c in result.cases)


def test_confidence_bands_are_ordered() -> None:
    assert confidence_band(0.95) == "high"
    assert confidence_band(0.6) == "moderate"
    assert confidence_band(0.4) == "low"
    assert confidence_band(0.1) == "insufficient"


def test_graph_contains_account_infrastructure_and_artifact_nodes(result: pipeline.PipelineResult) -> None:
    types = {node["type"] for node in result.graph["nodes"]}
    assert {"account", "network", "client_fingerprint", "artifact"} <= types


def test_case_separates_observation_inference_and_attribution(result: pipeline.PipelineResult) -> None:
    case = result.cases[0]
    kinds = {claim["kind"] for claim in case.claims}
    assert kinds == {"observation", "inference", "attribution"}
    for claim in case.claims:
        if claim["kind"] == "observation":
            assert claim["confidence"] == 1.0
        if claim["kind"] == "attribution":
            assert claim["confidence"] == 0.0


def test_case_states_competing_explanations_and_gaps(result: pipeline.PipelineResult) -> None:
    case = result.cases[0]
    assert len(case.competing_explanations) >= 3
    assert all(0.0 <= alt["residual_probability"] <= 1.0 for alt in case.competing_explanations)
    assert case.evidence_gaps


def test_case_confidence_is_discounted_by_alternatives(result: pipeline.PipelineResult) -> None:
    case = result.cases[0]
    assert case.confidence <= case.campaign["confidence"]


def test_evidence_excerpts_are_neutralized(result: pipeline.PipelineResult) -> None:
    for item in result.cases[0].evidence:
        assert "```" not in item["excerpt"]
        assert "\n" not in item["excerpt"]


def test_enforcement_is_proportional_and_gated(result: pipeline.PipelineResult) -> None:
    actions = result.cases[0].recommended_actions
    assert actions
    for action in actions:
        assert action["scope"]
        assert action["rationale"]
        if action["tier"] >= 3:
            assert action["requires_human_approval"] is True


def test_generated_rule_is_a_draft_needing_approval(result: pipeline.PipelineResult) -> None:
    rule = result.rule
    assert rule["status"] == "draft"
    assert rule["approved_by"] is None
    assert rule["expected_blind_spots"]
    assert rule["rollback"]
    rendered = outputs.render_rule_yaml(rule)
    assert "status: draft" in rendered
    assert rendered.startswith("# Draft rule")


def test_investigation_report_has_the_required_sections(result: pipeline.PipelineResult) -> None:
    report = outputs.investigation_report(result.cases[0], result.metrics)
    for heading in (
        "## 2. Observations",
        "## 3. Inferences",
        "## 4. Attribution position",
        "## 5. Timeline",
        "## 7. Competing explanations",
        "## 8. Evidence gaps",
        "## 10. Recommended actions",
        "## 12. Limitations",
    ):
        assert heading in report
    assert "simulated" in report.lower()


def test_executive_brief_reports_the_cost_of_being_wrong(result: pipeline.PipelineResult) -> None:
    brief = outputs.executive_brief(result.cases[0], result.metrics)
    assert "attribution" in brief.lower()
    assert "precision" in brief.lower()


def test_evaluation_reports_latency_and_coverage(result: pipeline.PipelineResult) -> None:
    metrics = result.metrics
    assert metrics["campaign_coverage"] == 1.0
    assert metrics["campaign_purity"] == 1.0
    assert metrics["detection_latency_hours"] is not None
    assert metrics["detection_latency_hours"] > 0


def test_feedback_computes_per_rule_precision_and_proposals() -> None:
    from app.observatory.detections import Signal

    signals = [
        Signal(f"sig-{i:04d}", "BEH-009", "test", "session", "acct-x", "ses-x", "2026-04-06T09:00:00Z", "low", 0.5, "r")
        for i in range(4)
    ]
    dispositions = [
        feedback_mod.Disposition("sig-0000", "false_positive"),
        feedback_mod.Disposition("sig-0001", "false_positive"),
        feedback_mod.Disposition("sig-0002", "false_positive"),
        feedback_mod.Disposition("sig-0003", "confirmed"),
    ]
    summary = feedback_mod.apply_feedback(signals, dispositions)
    assert summary.reviewed == 4
    assert summary.per_rule["BEH-009"]["analyst_precision"] == 0.25
    assert summary.proposed_adjustments[0]["change"] == "raise_confidence_floor"
    assert summary.proposed_adjustments[0]["requires_review"] is True


def test_pipeline_is_deterministic() -> None:
    first = pipeline.run(seed=1234)
    second = pipeline.run(seed=1234)
    assert [s.to_dict() for s in first.signals] == [s.to_dict() for s in second.signals]
    assert first.metrics["behavioral"] == second.metrics["behavioral"]


def test_artifacts_are_written(tmp_path, result: pipeline.PipelineResult) -> None:
    written = pipeline.write_artifacts(result, tmp_path)
    names = {path.name for path in written}
    assert "cases.json" in names
    assert "evaluation.json" in names
    assert any(name.endswith("-executive-brief.md") for name in names)
    assert all(path.exists() and path.stat().st_size > 0 for path in written)
