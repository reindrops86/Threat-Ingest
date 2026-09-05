# Enforcement recommendation - CASE-2026-001

Assessment confidence: **0.82 (high)**

Actions are scoped by the evidence tier held for each account. Association-only accounts are never suspended on linkage alone.

## account_suspension (tier 3)

- **Scope:** acct-a1, acct-a2, acct-a3, acct-b1, acct-b2
- **What it does:** Suspend the accounts with direct high-severity evidence, with appeal path.
- **Rationale:** Campaign confidence is 0.87 (high). 5 account(s) carry direct high-severity evidence, 0 are linked by association only. Action is scoped to the evidence tier held for each account.
- **Proportionality:** Accounts linked only by weak correlates receive monitoring, not suspension.
- **Reversible:** yes
- **Human approval:** required

## artifact_watchlist (tier 2)

- **Scope:** domain:payroll-verify-portal.example, url:https://payroll-verify-portal.example/sso
- **What it does:** Add reused artifacts to the outbound-fetch watchlist and alert on new touches.
- **Rationale:** The reused artifact is the most durable pivot across waves.
- **Proportionality:** Detection-only; no user-visible impact.
- **Reversible:** yes
- **Human approval:** not required

## Appeal and rollback

- Every suspension carries an appeal path and a preserved evidence bundle.
- Watchlist entries expire after 90 days unless renewed with new evidence.
- If the campaign confidence falls below 0.55 after analyst feedback, tier 3 actions are reverted.
