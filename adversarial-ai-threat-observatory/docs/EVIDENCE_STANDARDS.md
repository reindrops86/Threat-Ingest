# Observation, inference, and attribution

Most abuse-investigation mistakes are category errors: an inference gets written down as if it
were an observation, and three reports later it is treated as attribution. This system keeps
the three apart structurally, in the `Claim` type, and never merges them.

## The three claim kinds

### Observation

Something present in telemetry. Carries an `event_id`. Confidence is always `1.00`, because
the claim is only that the record exists - not that it means anything.

> `CAMP-2026-001-C02` Tool calls from multiple accounts referenced the same artifact(s):
> `domain:payroll-verify-portal.example`. Provenance: the tool-call event ids.

An observation is falsifiable by looking at one record.

### Inference

A conclusion drawn from observations. Carries an explicit confidence and a stated basis.
Never carries an event id, because no single record contains it.

> `CAMP-2026-001-C09` The linked accounts are more consistent with a single operator than with
> independent users. Confidence 0.87. Basis: strong link client_fingerprint; strong link
> payment_fingerprint; strong link shared_artifact.

An inference is falsifiable by a competing explanation. Every case therefore records
alternatives with residual probabilities, and the strongest surviving alternative discounts
the case confidence below the raw clustering score.

### Attribution

A claim about who is responsible. **This system does not make them.** The attribution claim on
every case states the limit explicitly and carries confidence `0.00`:

> No identity attribution is made. Linkage supports an operator hypothesis only; shared
> infrastructure and phrasing do not establish who the operator is.

## Why linkage is not identity

| Signal | What it actually supports | What it does not support |
|---|---|---|
| Identical client fingerprint | Same browser build and configuration | Same person; a corporate image duplicates it across thousands of users |
| Shared `/24` prefix | Same network egress | Same household; VPNs, campuses, and carrier NAT all collapse users |
| Reused hostname | Same operational infrastructure | Ownership; we have no registrar evidence from first-party telemetry |
| Recurring rare phrasing | Similar writing habits | Authorship; phrasing is imitable and shared within teams |
| Same rules firing | Similar behaviour | Coordination; independent users converge on similar tactics |

Individually each is a correlate. The system requires at least one **strong** link before it
will cluster accounts at all, and it caps weak-only edges below the linking threshold so that
a pile of weak signals can never manufacture confidence.

## Confidence bands

| Band | Range | Meaning |
|---|---|---|
| high | >= 0.80 | Multiple independent strong links plus behavioural corroboration |
| moderate | 0.55 - 0.79 | At least one strong link, alternatives not fully excluded |
| low | 0.30 - 0.54 | Suggestive only; monitoring, never enforcement |
| insufficient | < 0.30 | Not actionable |

Confidence is capped at **0.90**. Nothing in this system is certain.

## How this constrains action

Enforcement is scoped to the evidence tier held for each account, not to the cluster:

- Accounts with direct high-severity evidence can reach tier 3 (suspension), with named human
  approval.
- Accounts linked by association only stay at tier 0 (monitoring) regardless of how confident
  the cluster assessment is.
- Artifact watchlisting is detection-only and has no user-visible impact, so it is the default
  durable action.

## Evidence gaps are part of the record

Every case states what is missing, not only what is present - for example, that no evidence
shows generated content was ever delivered to a recipient, so harm is **potential rather than
observed**. Gaps are printed in the case workspace and in section 8 of the investigation report.
