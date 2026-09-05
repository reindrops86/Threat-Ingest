# Telemetry schema

Version `1.1.0`. Defined in [app/observatory/schema.py](../app/observatory/schema.py) and
validated by `validate_corpus`.

All timestamps are ISO-8601 UTC with a `Z` suffix.

## Object model

```
Corpus
 ├── Account[]              one row per registered identity
 ├── Session[]              one row per conversation, belongs to an Account
 ├── TelemetryEvent[]       every observation, belongs to an Account and usually a Session
 └── ExternalReference[]    public reports and vendor feeds used for corroboration
```

## Account

| Field | Type | Notes |
|---|---|---|
| `account_id` | str | Primary key |
| `created_at` | str | Registration time |
| `tier` | str | `free`, `pro`, `enterprise` |
| `status` | str | `active`, `suspended` |
| `infrastructure` | object | See Infrastructure below |
| `ground_truth_actor` | str/null | **Simulation only.** Read exclusively by `feedback.evaluate`; no detection code may consume it. |

## Session

| Field | Type | Notes |
|---|---|---|
| `session_id` | str | Primary key |
| `account_id` | str | Foreign key |
| `started_at` / `ended_at` | str | Session bounds |
| `surface` | str | Product surface, e.g. `chat` |
| `infrastructure` | object | Observed at session start |

## TelemetryEvent

One table for every observation type, discriminated by `event_type`.

| Field | Type | Applies to |
|---|---|---|
| `event_id` | str | all |
| `timestamp` | str | all |
| `event_type` | enum | `account_create`, `login`, `prompt`, `model_output`, `tool_call`, `enforcement` |
| `account_id` | str | all |
| `session_id` | str | conversation events |
| `turn_index` | int | conversation events; ordering within a session |
| `text` | str | `prompt`, `model_output` |
| `text_language` | str | `prompt` |
| `model_refusal` | bool | `model_output` |
| `tool_name` | str | `tool_call` |
| `tool_args` | object | `tool_call` |
| `artifacts` | str[] | `tool_call`; typed pivots such as `domain:example.test` |
| `enforcement_action` | str | `enforcement` |
| `infrastructure` | object | all |
| `source` | str | trust tier of the observation |
| `labels` | str[] | free-form analyst tags |

## Infrastructure

| Field | Notes |
|---|---|
| `ip` | Salted pseudonym after normalization; the raw value is never persisted |
| `ip_prefix` | `/24` prefix, retained for analysis |
| `asn` | Autonomous system, treated as a **weak** correlate |
| `country` | Coarse geography |
| `user_agent` | Client string |
| `client_fingerprint` | Pseudonymized; **strong** but not unique - a shared browser image duplicates it |
| `signup_domain` | Mail domain used at registration; **moderate** |
| `payment_fingerprint` | Pseudonymized billing token; **strong** |

## ExternalReference

| Field | Notes |
|---|---|
| `reference_id`, `title`, `publisher`, `published`, `url` | Provenance |
| `source_reliability` | Admiralty A-F |
| `information_credibility` | Admiralty 1-6 |
| `behaviors`, `indicators` | Extracted claims |
| `trust_tier` | `first_party_telemetry`, `vendor_feed`, `osint`, `analyst_assertion` |

## Validation rules

`validate_corpus` returns a list of violations. It rejects:

- missing `event_id`, `timestamp`, `event_type`, or `account_id`
- an `event_type` outside the enum
- events or sessions referencing an unknown account
- events referencing an unknown session
- duplicate `event_id`
- external references with an unknown trust tier

## Signal-strength policy

Link strength is a schema-level commitment, not a per-case judgement:

| Strength | Link types | Effect |
|---|---|---|
| strong | `client_fingerprint`, `payment_fingerprint`, `shared_artifact` | Can support clustering |
| moderate | `signup_domain`, `style_similarity`, `behavioral_fingerprint` | Contributes, cannot carry a cluster |
| weak | `ip_prefix`, `asn`, `temporal_burst` | Capped; weak-only edges are forced below the linking threshold |
