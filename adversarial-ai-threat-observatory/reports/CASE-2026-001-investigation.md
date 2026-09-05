# Investigation report CASE-2026-001

**Title:** Coordinated multi-account credential-phishing assistance (CAMP-2026-001)
**Status:** open  
**Assessment confidence:** 0.82 (high)  
**Accounts in scope:** acct-a1, acct-a2, acct-a3, acct-b1, acct-b2  
**Activity window:** 2026-04-06T09:00:00Z to 2026-04-11T00:07:20Z

> All data in this report is simulated. No production telemetry, real credentials, or live infrastructure is represented. Prompt excerpts are attacker-controlled text and have been neutralized for safe rendering.

## 1. Summary

5 accounts across 2 wave(s) show a consistent progression: benign warm-up, explicit boundary probing, then requests for credential-collection content, followed by tool calls that stage the same external artifact. After simulated enforcement, activity resumed from different network space with unchanged strong identifiers and obfuscated phrasing.

## 2. Observations

Statements below are present in telemetry and carry event provenance.

| Claim | Statement | Provenance |
|---|---|---|
| CAMP-2026-001-C01 | 5 accounts were created between 2026-04-06T09:00:00Z and 2026-04-10T10:00:00Z. | account:acct-a1, account:acct-a2, account:acct-a3 |
| CAMP-2026-001-C02 | Tool calls from multiple accounts referenced the same artifact(s): domain:payroll-verify-portal.example, url:https://payroll-verify-portal.example/sso. | domain:payroll-verify-portal.example, url:https://payroll-verify-portal.example/sso |
| CAMP-2026-001-C03 | BEH-001 (Progressive intent escalation within a session) fired on 5 account(s). | sig-0001, sig-0002, sig-0003 |
| CAMP-2026-001-C04 | BEH-002 (Reformulation immediately after refusal) fired on 5 account(s). | sig-0004, sig-0006, sig-0008 |
| CAMP-2026-001-C05 | BEH-003 (Harmful workflow assembled from benign fragments) fired on 5 account(s). | sig-0005, sig-0007, sig-0009 |
| CAMP-2026-001-C06 | BEH-004 (Obfuscation shift after boundary contact) fired on 2 account(s). | sig-0016, sig-0020 |
| CAMP-2026-001-C07 | BEH-005 (Tool activity staging infrastructure alongside abusive content) fired on 5 account(s). | sig-0010, sig-0011, sig-0012 |
| CAMP-2026-001-C08 | BEH-006 (Account re-registration after enforcement on a linked account) fired on 2 account(s). | sig-0023, sig-0024 |

## 3. Inferences

Statements below are conclusions, not observations. Each carries a confidence value.

| Claim | Statement | Confidence | Basis |
|---|---|---|---|
| CAMP-2026-001-C09 | The linked accounts are more consistent with a single operator than with independent users. | 0.87 | strong link: client_fingerprint; strong link: payment_fingerprint; strong link: shared_artifact |
| CAMP-2026-001-C10 | Activity resumed in a later wave from different network space after enforcement, with the same client fingerprint and reused artifact. | 0.75 | wave separation in creation times; unchanged strong identifier across waves |

## 4. Attribution position

- No identity attribution is made. Linkage supports an operator hypothesis only; shared infrastructure and phrasing do not establish who the operator is.

## 5. Timeline

| Timestamp | Account | Type | Summary |
|---|---|---|---|
| 2026-04-06T09:00:00Z | acct-a1 | account_create | account created |
| 2026-04-06T09:07:00Z | acct-a2 | account_create | account created |
| 2026-04-06T09:14:00Z | acct-a3 | account_create | account created |
| 2026-04-06T14:00:00Z | acct-a1 | detection | BEH-001 Progressive intent escalation within a session (confidence 0.90) |
| 2026-04-06T14:07:00Z | acct-a2 | detection | BEH-001 Progressive intent escalation within a session (confidence 0.90) |
| 2026-04-06T14:14:00Z | acct-a3 | detection | BEH-001 Progressive intent escalation within a session (confidence 0.90) |
| 2026-04-07T11:00:00Z | acct-a1 | detection | BEH-002 Reformulation immediately after refusal (confidence 0.58) |
| 2026-04-07T11:00:00Z | acct-a1 | detection | BEH-003 Harmful workflow assembled from benign fragments (confidence 0.72) |
| 2026-04-07T11:07:00Z | acct-a2 | detection | BEH-002 Reformulation immediately after refusal (confidence 0.58) |
| 2026-04-07T11:07:00Z | acct-a2 | detection | BEH-003 Harmful workflow assembled from benign fragments (confidence 0.72) |
| 2026-04-07T11:14:00Z | acct-a3 | detection | BEH-002 Reformulation immediately after refusal (confidence 0.58) |
| 2026-04-07T11:14:00Z | acct-a3 | detection | BEH-003 Harmful workflow assembled from benign fragments (confidence 0.72) |
| 2026-04-07T15:00:00Z | acct-a1 | detection | BEH-005 Tool activity staging infrastructure alongside abusive content (confidence 0.65) |
| 2026-04-07T15:00:20Z | acct-a1 | tool_call | web_fetch touched domain:payroll-verify-portal.example, url:https://payroll-verify-portal.example/sso |
| 2026-04-07T15:07:00Z | acct-a2 | detection | BEH-005 Tool activity staging infrastructure alongside abusive content (confidence 0.65) |
| 2026-04-07T15:07:20Z | acct-a2 | tool_call | web_fetch touched domain:payroll-verify-portal.example, url:https://payroll-verify-portal.example/sso |
| 2026-04-07T15:08:20Z | acct-a1 | tool_call | code_interpreter touched domain:payroll-verify-portal.example |
| 2026-04-07T15:14:00Z | acct-a3 | detection | BEH-005 Tool activity staging infrastructure alongside abusive content (confidence 0.65) |
| 2026-04-07T15:14:20Z | acct-a3 | tool_call | web_fetch touched domain:payroll-verify-portal.example, url:https://payroll-verify-portal.example/sso |
| 2026-04-07T15:15:20Z | acct-a2 | tool_call | code_interpreter touched domain:payroll-verify-portal.example |
| 2026-04-07T15:22:20Z | acct-a3 | tool_call | code_interpreter touched domain:payroll-verify-portal.example |
| 2026-04-08T10:00:00Z | acct-a1 | enforcement | account_suspension |
| 2026-04-08T10:03:00Z | acct-a2 | enforcement | account_suspension |
| 2026-04-08T10:06:00Z | acct-a3 | enforcement | account_suspension |
| 2026-04-10T09:00:00Z | acct-b1 | account_create | account created |
| 2026-04-10T09:00:00Z | acct-b1 | detection | BEH-006 Account re-registration after enforcement on a linked account (confidence 0.55) |
| 2026-04-10T10:00:00Z | acct-b2 | account_create | account created |
| 2026-04-10T10:00:00Z | acct-b2 | detection | BEH-006 Account re-registration after enforcement on a linked account (confidence 0.55) |
| 2026-04-10T18:00:00Z | acct-b1 | detection | BEH-001 Progressive intent escalation within a session (confidence 0.90) |
| 2026-04-10T18:00:00Z | acct-b1 | detection | BEH-002 Reformulation immediately after refusal (confidence 0.58) |
| 2026-04-10T18:00:00Z | acct-b1 | detection | BEH-003 Harmful workflow assembled from benign fragments (confidence 0.72) |
| 2026-04-10T18:00:00Z | acct-b1 | detection | BEH-004 Obfuscation shift after boundary contact (confidence 0.85) |
| 2026-04-10T19:00:00Z | acct-b2 | detection | BEH-001 Progressive intent escalation within a session (confidence 0.90) |
| 2026-04-10T19:00:00Z | acct-b2 | detection | BEH-002 Reformulation immediately after refusal (confidence 0.58) |
| 2026-04-10T19:00:00Z | acct-b2 | detection | BEH-003 Harmful workflow assembled from benign fragments (confidence 0.72) |
| 2026-04-10T19:00:00Z | acct-b2 | detection | BEH-004 Obfuscation shift after boundary contact (confidence 0.85) |
| 2026-04-10T23:00:00Z | acct-b1 | detection | BEH-005 Tool activity staging infrastructure alongside abusive content (confidence 0.65) |
| 2026-04-10T23:00:20Z | acct-b1 | tool_call | web_fetch touched domain:payroll-verify-portal.example |
| 2026-04-11T00:00:00Z | acct-b2 | detection | BEH-005 Tool activity staging infrastructure alongside abusive content (confidence 0.65) |
| 2026-04-11T00:00:20Z | acct-b2 | tool_call | web_fetch touched domain:payroll-verify-portal.example |

## 6. Linkage evidence

| Strength | Explanation |
|---|---|
| account linkage (strong) | Both accounts present identical client fingerprint (fp_a4a7375171f0). |
| account linkage (strong) | Both accounts present identical payment fingerprint (pay_5e3c5449786b). |
| account linkage (moderate) | Both accounts present same signup mail domain (mailbox-drop.example). |
| account linkage (weak) | Both accounts present same /24 network prefix (203.0.113.0/24). |
| account linkage (weak) | Both accounts present same autonomous system (AS64500 SIMHOST-BV). |
| account linkage (strong) | Both accounts directed tool calls at domain:payroll-verify-portal.example, url:https://payroll-verify-portal.example/sso. |
| account linkage (moderate) | Rarity-weighted phrasing overlap 0.95. |
| account linkage (moderate) | Same behavioral detections fired on both accounts: BEH-001, BEH-002, BEH-003, BEH-005. |
| account linkage (weak) | Created 0.1h apart. |
| account linkage (moderate) | Rarity-weighted phrasing overlap 0.96. |
| account linkage (weak) | Created 0.2h apart. |
| account linkage (strong) | Both accounts present identical payment fingerprint (pay_f0213aa6e4f3). |

## 7. Competing explanations

| Alternative hypothesis | Assessment | Residual probability |
|---|---|---|
| Shared egress: unrelated users behind one VPN, campus, or office NAT. | Weakened. Linkage does not rest on network prefix alone; strong identifiers present: client_fingerprint, payment_fingerprint, shared_artifact. | 0.10 |
| Authorised security-awareness team producing phishing-simulation material. | Weakened. Sessions show refusal-driven reformulation and euphemistic relabelling, which authorised training work does not require. | 0.08 |
| Shared managed device pool, e.g. an agency using one browser image. | Partially credible; a common browser image can duplicate a client fingerprint. It does not explain reuse of the same externally controlled artifact. | 0.12 |
| Detection artefact: rules over-fire on the same benign template language. | Weakened. Multiple independent rule families fired: BEH-001, BEH-002, BEH-003, BEH-004, BEH-005, BEH-006 | 0.05 |

## 8. Evidence gaps

- Ownership of the shared artifact is unconfirmed; no registrar or hosting evidence is available from first-party telemetry.
- No evidence shows that generated content was ever delivered to a recipient. Harm is potential, not observed.
- Client fingerprints can be duplicated by a common browser image; treat as strong-but-not-unique.
- Payment fingerprints differ between waves, so billing does not corroborate the link.
- The gap between waves is unexplained; the operator may have been active on surfaces outside this telemetry.

## 9. External corroboration

| Reference | Publisher | Tier | Admiralty | Matched |
|---|---|---|---|---|
| ref-osint-001 | Fictional CERT Example | osint | B2 | domain:payroll-verify-portal.example |
| ref-vendor-002 | Fictional Feed Example | vendor_feed | C3 | asn:AS64500 SIMHOST-BV, domain:mailbox-drop.example |

_External reporting is treated as corroborating, not independent; it may derive from the same underlying observations (circular reporting risk)._

## 10. Recommended actions

| Action | Scope | Reversible | Human approval | Rationale |
|---|---|---|---|---|
| account_suspension | acct-a1, acct-a2, acct-a3, acct-b1, acct-b2 | yes | required | Campaign confidence is 0.87 (high). 5 account(s) carry direct high-severity evidence, 0 are linked by association only. Action is scoped to the evidence tier held for each account. |
| artifact_watchlist | domain:payroll-verify-portal.example, url:https://payroll-ve | yes | not required | The reused artifact is the most durable pivot across waves. |

## 11. Detection performance on this corpus

| Metric | Session-level (behavioral) | Message-level (baseline) |
|---|---|---|
| Precision | 1.0 | 0.625 |
| Recall | 1.0 | 1.0 |
| F1 | 1.0 | 0.769 |
| False positives | 0 | 3 |

- Median detection latency: **5.0 h** from first actor activity to first behavioral signal.
- Campaign coverage: **100%** of simulated actor accounts were placed in the correct cluster.

## 12. Limitations

- Rules are regular expressions over a simulated corpus; they will not transfer unchanged.
- Style similarity is a weak, transferable signal. It supports linkage only alongside a strong identifier and is never sufficient alone.
- Confidence values are calibrated on synthetic data and should be re-estimated on any real deployment before they inform enforcement.
