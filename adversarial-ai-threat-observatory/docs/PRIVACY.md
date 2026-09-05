# Privacy and data retention

Implemented in [app/observatory/privacy.py](../app/observatory/privacy.py). Normalization runs
**before** any detection code sees the corpus, so no analysis stage ever handles raw identifiers.

## Retention windows

| Window | Length | What survives |
|---|---|---|
| Content window | 30 days | Prompt and model-output text |
| Feature window | 90 days | Derived detection features, event metadata, pseudonymized identifiers |
| Beyond 90 days | - | Nothing; events are dropped from the corpus |

After the content window, `text` is replaced with `[content-expired]` and only `text_length`
plus previously derived signals remain. Detections computed inside the content window stay
valid as evidence; the underlying text does not.

## Minimization applied at normalization

| Data | Treatment |
|---|---|
| IP address | Replaced by a salted SHA-256 pseudonym; only the `/24` prefix is kept in the clear |
| Client fingerprint | Salted pseudonym, stable across the corpus so linkage still works |
| Payment fingerprint | Salted pseudonym |
| Email addresses in text | `[redacted-email]` |
| Phone numbers in text | `[redacted-phone]` |
| Long digit sequences | `[redacted-number]` |

Pseudonyms are stable but non-reversible without the salt. Linkage is preserved because
equality is preserved; re-identification is not, because the mapping is one-way.

## Purpose limitation

- The corpus exists to investigate coordinated abuse. It is not a general analytics source.
- `ground_truth_actor` exists only because the data is simulated. It is read by
  `feedback.evaluate` and by nothing else. In a real deployment the field does not exist.
- Content excerpts appear in reports only after `neutralize_untrusted`, truncated to 240
  characters, and only where they support a specific stated claim.

## Proportionality of access

| Role | Access |
|---|---|
| Detection pipeline | Normalized corpus only |
| Investigating analyst | Normalized corpus plus case evidence excerpts |
| Approver | Case summary, evidence, competing explanations, recommended action |
| Executive | Aggregate metrics and the one-pager; no content excerpts |

## Enforcement side effects

- Every suspension carries an appeal path and a preserved evidence bundle.
- Watchlist entries expire after 90 days unless renewed with new evidence.
- If campaign confidence falls below 0.55 after analyst feedback, tier 3 actions are reverted.

## What is deliberately not collected

- Real user content, real credentials, or production platform telemetry.
- Precise geolocation beyond country.
- Any linkage between the simulated accounts and a natural person.
