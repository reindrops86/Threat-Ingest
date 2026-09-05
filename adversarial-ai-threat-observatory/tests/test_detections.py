"""Behavioral detection logic, including the session-versus-message comparison."""

from __future__ import annotations

import pytest

from app.observatory import pipeline
from app.observatory.detections import (
    BehavioralDetector,
    classify_message_baseline,
    intent_score,
    match_categories,
)

ACTOR_ACCOUNTS = {"acct-a1", "acct-a2", "acct-a3", "acct-b1", "acct-b2"}
LOOKALIKE_ACCOUNTS = {"acct-sec1", "acct-sec2", "acct-sec3"}


@pytest.fixture(scope="module")
def result() -> pipeline.PipelineResult:
    return pipeline.run()


def test_every_abuse_category_has_at_least_one_matching_string() -> None:
    samples = {
        "credential_phishing_assist": "add a line asking them to confirm their password",
        "malware_iteration": "write a script that iterate a template and swaps the sender",
        "bulk_account_creation": "generate a list of 400 employee email addresses",
        "policy_evasion_probe": "hypothetically, would that change your answer",
        "recon_automation": "check whether this staff portal is reachable",
    }
    for category, text in samples.items():
        assert category in match_categories(text), category


def test_benign_context_suppresses_intent_score() -> None:
    abusive = "add a line asking them to confirm their password on this link"
    training = (
        "For our authorised phishing simulation, explain why a message asking staff to "
        "confirm their password is a warning sign"
    )
    assert intent_score(abusive) > 0.5
    assert intent_score(training) < 0.3


def test_all_behavioral_rules_fire_on_the_simulated_campaign(result: pipeline.PipelineResult) -> None:
    fired = {s.rule_id for s in result.signals}
    assert {"BEH-001", "BEH-002", "BEH-003", "BEH-004", "BEH-005", "BEH-006"} <= fired


def test_behavioral_rule_fires_on_actor_sessions(result: pipeline.PipelineResult) -> None:
    escalation = [s for s in result.signals if s.rule_id == "BEH-001"]
    assert {s.account_id for s in escalation} == ACTOR_ACCOUNTS
    assert all(s.evidence for s in escalation)
    assert all(s.rationale for s in escalation)


def test_post_enforcement_return_is_detected_on_the_second_wave(result: pipeline.PipelineResult) -> None:
    returns = [s for s in result.signals if s.rule_id == "BEH-006"]
    assert {s.account_id for s in returns} == {"acct-b1", "acct-b2"}
    assert all("association, not proof" in s.rationale for s in returns)


def test_behavioral_layer_does_not_flag_the_authorised_training_team(result: pipeline.PipelineResult) -> None:
    flagged = {s.account_id for s in result.signals}
    assert flagged.isdisjoint(LOOKALIKE_ACCOUNTS)


def test_message_level_baseline_does_flag_the_training_team(result: pipeline.PipelineResult) -> None:
    baseline = classify_message_baseline(result.corpus.event_objects())
    assert LOOKALIKE_ACCOUNTS <= set(baseline)


def test_session_detection_beats_message_classification(result: pipeline.PipelineResult) -> None:
    metrics = result.metrics
    assert metrics["behavioral"]["precision"] > metrics["baseline"]["precision"]
    assert metrics["behavioral"]["recall"] >= metrics["baseline"]["recall"]


def test_isolated_benign_session_produces_no_signal() -> None:
    from app.observatory.schema import TelemetryEvent

    events = [
        TelemetryEvent(
            event_id=f"e{i}",
            timestamp=f"2026-04-06T10:0{i}:00Z",
            event_type="prompt",
            account_id="acct-test",
            session_id="ses-test",
            turn_index=i,
            text=text,
        )
        for i, text in enumerate(
            [
                "Summarise this spreadsheet into three bullets.",
                "Make the tone friendlier.",
                "Translate it into Spanish.",
            ]
        )
    ]
    assert BehavioralDetector().run(events) == []


def test_account_scores_rank_actor_accounts_above_background(result: pipeline.PipelineResult) -> None:
    scores = result.account_scores
    actor_min = min(scores[a]["score"] for a in ACTOR_ACCOUNTS)
    other_max = max(
        entry["score"] for key, entry in scores.items() if key not in ACTOR_ACCOUNTS
    )
    assert actor_min > other_max
