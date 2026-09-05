# Investigation walkthrough

A full run of the demonstration scenario, from ambiguous signal to a reusable detection.
Every command below is reproducible: `python -m app.main <command>`.

---

## The scenario

One simulated actor, `SIM-ACTOR-ALPHA`, does six things:

1. Creates three accounts in a seven-minute burst from one hosting range.
2. Warms up with benign writing help, then asks explicitly where the limits are.
3. Drifts toward a notice asking staff to confirm their password, is refused, and reformulates.
4. Points tool calls at the same hostname from all three accounts.
5. Is suspended.
6. Returns four days later with two new accounts, a different network, Spanish and base64
   framing - and the same client fingerprint and the same hostname.

Alongside it: an authorised security-awareness team whose prompts are full of phishing
vocabulary and who share an ASN with the actor's first wave, plus fourteen ordinary users.
The look-alike team exists so that precision is measured against a realistic competing
explanation rather than against obviously benign traffic.

---

## Stage 1-2: intake, normalization, privacy

```
$ python -m app.main run
Stage 1  Telemetry + OSINT + vendor feeds
  320 events, 22 accounts, 2 external references
  schema violations: 0

Stage 2  Normalization and privacy controls
  - IPs reduced to /24 prefix plus salted pseudonym; raw addresses are not stored.
  - Prompt and output content is dropped after 30 days; derived detection features are kept for 90 days.
  - Ground-truth actor labels exist only because the corpus is simulated and are readable solely by the evaluator.
```

No detection code sees a raw identifier. Pseudonyms are stable, so equality-based linkage still
works; the mapping is one-way, so re-identification does not.

---

## Stage 3: behavioral detections

```
$ python -m app.main detect

[BEH-001] Progressive intent escalation within a session
  account=acct-a1 session=ses-00003 scope=session
  severity=high confidence=0.90 first_seen=2026-04-06T14:00:00Z
  rationale: Harm-intent estimate rose from 0.20 in the opening turns to 0.90 later in the
             same session. No single turn is decisive; the gradient is the observation.
```

Six rules fire, none of which look at a message in isolation:

| Rule | What it examines |
|---|---|
| `BEH-001` | Intent gradient across turns in one session |
| `BEH-002` | Refusal followed by a same-topic retry with softened wording |
| `BEH-003` | A harmful workflow assembled from individually innocuous fragments |
| `BEH-004` | Two or more obfuscation techniques appearing after boundary contact |
| `BEH-005` | Tool calls staging artifacts in a session that also matched an abuse rule |
| `BEH-006` | Re-registration after enforcement, sharing a strong identifier |

Account scores rank the actor accounts above everything else, and the authorised training team
scores zero behavioural signals.

---

## Stage 4: entity linking and clustering

```
$ python -m app.main graph

acct-a1 <-> acct-b1  confidence=0.79
  [strong  ] client_fingerprint: Both accounts present identical client fingerprint (fp_a4a7375171f0).
  [moderate] signup_domain: Both accounts present same signup mail domain (mailbox-drop.example).
  [strong  ] shared_artifact: Both accounts directed tool calls at domain:payroll-verify-portal.example.
  [moderate] style_similarity: Rarity-weighted phrasing overlap 0.25.

acct-sec1 <-> acct-sec2  confidence=0.55
  [moderate] signup_domain: Both accounts present same signup mail domain (northwind-training.example).
  [weak    ] ip_prefix: Both accounts present same /24 network prefix (203.0.113.0/24).
  [weak    ] asn: Both accounts present same autonomous system (AS64500 SIMHOST-BV).
```

The second block is the important one. The training team shares a network prefix with the
actor's first wave and writes about phishing all day, but has **no strong link**, so their edge
is capped at 0.55 and never reaches the 0.60 clustering threshold. Weak signals cannot
manufacture a campaign.

```
CAMP-2026-001  confidence=0.87 (high)
  accounts: acct-a1, acct-a2, acct-a3, acct-b1, acct-b2
  strong links: client_fingerprint, payment_fingerprint, shared_artifact
  wave 1: acct-a1, acct-a2, acct-a3 from 203.0.113.0/24 at 2026-04-06T09:00:00Z
  wave 2: acct-b1, acct-b2         from 198.51.100.0/24 at 2026-04-10T09:00:00Z
```

The wave split is what the operator was trying to hide: new accounts, new network space, but
the payment fingerprint changed while the client fingerprint did not.

---

## Stage 5: the case workspace

```
$ python -m app.main case

CASE-2026-001  Coordinated multi-account credential-phishing assistance (CAMP-2026-001)
status=open  confidence=0.82 (high)
accounts: acct-a1, acct-a2, acct-a3, acct-b1, acct-b2

-- Timeline ------------------------------------------------------------------
  2026-04-06T09:00:00Z  acct-a1    account_create account created
  2026-04-06T14:00:00Z  acct-a1    detection      BEH-001 Progressive intent escalation (0.90)
  2026-04-07T11:00:00Z  acct-a1    detection      BEH-003 Harmful workflow from fragments (0.72)
  2026-04-07T15:00:20Z  acct-a1    tool_call      web_fetch touched domain:payroll-verify-portal.example
  2026-04-08T10:00:00Z  acct-a1    enforcement    account_suspension
  2026-04-10T09:00:00Z  acct-b1    account_create account created
  2026-04-10T09:00:00Z  acct-b1    detection      BEH-006 Re-registration after enforcement (0.55)
  2026-04-10T18:00:00Z  acct-b1    detection      BEH-004 Obfuscation shift after boundary contact (0.85)

-- Competing explanations ----------------------------------------------------
  residual=0.12  Shared managed device pool, e.g. an agency using one browser image.
      Partially credible; a common browser image can duplicate a client fingerprint.
      It does not explain reuse of the same externally controlled artifact.
  residual=0.10  Shared egress: unrelated users behind one VPN, campus, or office NAT.
  residual=0.08  Authorised security-awareness team producing phishing-simulation material.
  residual=0.05  Detection artefact: rules over-fire on the same benign template language.

-- Recommended actions -------------------------------------------------------
  tier 3 account_suspension [HUMAN APPROVAL REQUIRED]
  tier 2 artifact_watchlist [auto-eligible]
```

Case confidence (0.82) is deliberately lower than the clustering confidence (0.87): the
strongest surviving alternative explanation discounts it. Claims are typed - observations carry
event ids and confidence 1.00, inferences carry a basis and a confidence, and the attribution
claim states that no identity attribution is made.

---

## Stage 6: outputs

Four documents and one rule are generated from the same case object, so they cannot disagree:

| Artifact | Audience |
|---|---|
| [`reports/CASE-2026-001-investigation.md`](../reports/CASE-2026-001-investigation.md) | Investigating analyst |
| [`reports/CASE-2026-001-enforcement.md`](../reports/CASE-2026-001-enforcement.md) | Approver |
| [`reports/CASE-2026-001-threat-intel.md`](../reports/CASE-2026-001-threat-intel.md) | Intel consumers |
| [`reports/CASE-2026-001-executive-brief.md`](../reports/CASE-2026-001-executive-brief.md) | Leadership |
| [`rules/AATO-BEH-001.yml`](../rules/AATO-BEH-001.yml) | Detection engineering |

The rule ships as `status: draft` with `approved_by: null` and a declared list of blind spots.
Nothing deploys itself.

---

## Stage 7: evaluation and feedback

```
$ python -m app.main evaluate

metric                  behavioral      baseline
precision                      1.0         0.625
recall                         1.0           1.0
false_positives                  0             3

baseline false positives: acct-sec1, acct-sec2, acct-sec3
median detection latency: 5.0 h
campaign coverage: 100%  purity: 100%
```

A message-level keyword classifier finds the actor - and also suspends the authorised
security-awareness team. That is the argument for behavioural context, stated as a number
rather than as an opinion.

The analyst queue then feeds back:

```
  BEH-001: {'confirmed': 3, 'false_positive': 0, 'analyst_precision': 1.0}
  BEH-005: {'confirmed': 1, 'false_positive': 2, 'analyst_precision': 0.333}
  proposal for BEH-001: promote_to_auto_case
  proposal for BEH-005: raise_confidence_floor - Require a corroborating rule before this
                        detection can flag an account on its own.
```

Both proposals are marked `requires_review: true`. The loop tunes rules; it does not deploy them.
