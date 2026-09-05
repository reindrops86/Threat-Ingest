# Executive one-pager

**Case CASE-2026-001 - Coordinated multi-account credential-phishing assistance (CAMP-2026-001)**

## What happened

One apparent operator used 5 accounts to work toward credential-phishing content, testing where our limits sit before escalating. After we acted on the first accounts, the activity returned with new accounts and reworded requests but the same technical fingerprint and the same landing-page hostname.

## Why we believe the accounts are connected

- Assessment confidence **0.82 (high)**, reduced from the raw clustering score of 0.87 to account for alternative explanations.
- Strong links: client_fingerprint, payment_fingerprint, shared_artifact.
- We do not claim to know who the operator is. This is a linkage assessment, not attribution.

## What we recommend

- **account suspension** for 5 entities - Accounts linked only by weak correlates receive monitoring, not suspension.
- **artifact watchlist** for 2 entities - Detection-only; no user-visible impact.

Tier 3 actions require named human approval before execution.

## What it costs us to be wrong

- Behavioral detection precision on this corpus: **1.00** versus **0.62** for a message-level keyword classifier.
- The baseline would have wrongly actioned 3 account(s), including an authorised security-awareness team.
- Median time to first detection: **5.0 hours**.

## What changes as a result

- One reusable behavioral rule is drafted for reviewer approval.
- The reused hostname is added to a detection-only watchlist as the durable pivot.
- Analyst dispositions feed the next evaluation run, which re-scores rule precision.

_Simulated data. No production systems or real users are involved._
