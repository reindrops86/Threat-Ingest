# Threat intelligence report - simulated actor cluster

**Cluster:** CAMP-2026-001  
**Confidence:** 0.82 (high)  
**Window:** 2026-04-06T09:00:00Z - 2026-04-11T00:07:20Z

## Behaviors observed

- `BEH-001`
- `BEH-002`
- `BEH-003`
- `BEH-004`
- `BEH-005`
- `BEH-006`

## Abuse categories in scope

- **credential_phishing_assist** (high): Assistance producing content that induces a person to disclose credentials.
- **malware_iteration** (high): Repeated refinement of code whose purpose is evasion or mass delivery.
- **bulk_account_creation** (medium): Automated creation or enumeration of accounts and address lists.
- **policy_evasion_probe** (low): Probing where enforcement boundaries sit rather than requesting a task.
- **recon_automation** (medium): Tool-mediated reachability or availability checks against hosts.

## Infrastructure (simulated)

- `client_fingerprint`: fp_a4a7375171f0
- `payment_fingerprint`: pay_5e3c5449786b, pay_f0213aa6e4f3
- `signup_domain`: mailbox-drop.example
- `ip_prefix`: 198.51.100.0/24, 203.0.113.0/24
- `asn`: AS64500 SIMHOST-BV, AS64510 SIMVPN-LTD
- `artifact`: domain:payroll-verify-portal.example
- `artifact`: url:https://payroll-verify-portal.example/sso

## Tradecraft changes after enforcement

- Wave 1: acct-a1, acct-a2, acct-a3 from 203.0.113.0/24 (2026-04-06T09:00:00Z)
- Wave 2: acct-b1, acct-b2 from 198.51.100.0/24 (2026-04-10T09:00:00Z)

## Candidate detection

```yaml
# Draft rule - requires reviewer approval before deployment
id: "AATO-BEH-001"
version: 0.1.0
status: draft
approved_by: null
title: "Multi-account credential-phishing assistance with post-enforcement return"
derived_from_case: "CASE-2026-001"
created: "2026-09-05T20:39:47.508156Z"
scope: session_sequence
description: "Fires when a single session escalates from benign to credential-collection assistance, reformulates after refusal, and is linked by a strong identifier to an account previously subject to enforcement."
logic:
  all_of:
    - detection: "BEH-001"
      min_confidence: 0.55
    - any_of:
        - detection: "BEH-002"
        - detection: "BEH-003"
        - detection: "BEH-004"
    - linkage:
        strong_identifier_shared_with: account_with_prior_enforcement
        identifiers:
          - client_fingerprint
          - payment_fingerprint
          - shared_artifact
  not_any_of:
    - context: benign_security_awareness
      note: authorised simulation language present
observables_required:
  - prompt.text
  - model_output.model_refusal
  - tool_call.artifacts
  - enforcement.enforcement_action
  - infrastructure.client_fingerprint
expected_blind_spots:
  - Operators who rotate client fingerprints between waves.
  - Escalation split across sessions that are days apart and below the session window.
  - Languages with no rule coverage; only English and Spanish cues are implemented.
  - Artifacts never touched by a tool call are invisible to this rule.
severity: high
response: "Route to human review; do not auto-suspend."
tests:
  - "tests/test_detections.py::test_behavioral_rule_fires_on_actor_sessions"
rollback: Set status to disabled; rule state is versioned in git.
```

## Confidence and caveats

- Ownership of the shared artifact is unconfirmed; no registrar or hosting evidence is available from first-party telemetry.
- No evidence shows that generated content was ever delivered to a recipient. Harm is potential, not observed.
- Client fingerprints can be duplicated by a common browser image; treat as strong-but-not-unique.
- Payment fingerprints differ between waves, so billing does not corroborate the link.
- The gap between waves is unexplained; the operator may have been active on surfaces outside this telemetry.
