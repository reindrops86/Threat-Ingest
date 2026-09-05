# Threat model

## What this system protects

The integrity of an AI platform against **coordinated misuse** - not isolated bad prompts,
but an operator who runs a campaign across accounts, adapts to enforcement, and returns.

## Who we are defending against

| Actor | Capability | Goal | Why they are hard |
|---|---|---|---|
| Opportunistic user | Single account, no tooling | Get one refused answer | Trivial; message-level rules suffice |
| Persistent hobbyist | A few accounts, manual retries | Wear down refusals | Escalation looks like normal curiosity turn by turn |
| **Coordinated operator (in scope)** | Many accounts, shared infrastructure, adapts after enforcement | Produce credential-phishing material at scale | Every individual request is deniable; linkage is the only durable signal |
| Resourced group | Rotates all identifiers, distributes across surfaces | Sustained operations | Out of scope for this build; see blind spots |

## Assets

- Model capability that can be repurposed to produce credential-harvesting content.
- Tool surfaces (outbound fetch, code execution) that let an operator stage infrastructure.
- The account-creation surface, which determines how cheap a fresh identity is.
- The investigation record itself, which must remain trustworthy enough to justify enforcement.

## Attacker techniques this system is built to see

1. **Boundary mapping** - asking where the limits are rather than asking for the harmful thing.
2. **Progressive escalation** - starting benign and drifting, so no single turn is decisive.
3. **Post-refusal reformulation** - keeping the objective, changing the words.
4. **Decomposition** - splitting a harmful workflow into individually innocuous fragments.
5. **Obfuscation** - encoding, translation, and euphemism applied after boundary contact.
6. **Infrastructure reuse** - the same landing-page hostname across accounts and waves.
7. **Enforcement adaptation** - new accounts, new network space, unchanged tradecraft.

## Attacks against the observatory itself

| Attack | Mitigation in this repo |
|---|---|
| Indirect prompt injection through telemetry text into reports or downstream models | `privacy.neutralize_untrusted` strips directive phrasing, collapses newlines, and breaks code fences before any excerpt is rendered. Tested in `tests/test_schema_and_privacy.py`. |
| Poisoning linkage by deliberately sharing a benign user's fingerprint | Weak correlates are capped below the linking threshold; a strong identifier is required to cluster. Competing explanations are recorded on every case. |
| Circular reporting - external feeds echoing our own observations | External references are labelled `corroborating but not independent` and carry Admiralty reliability grades. |
| Over-enforcement driven by a noisy rule | Tier 3+ actions require named human approval; per-rule analyst precision feeds proposals to raise the confidence floor. |
| Analyst anchoring on the first hypothesis | Competing explanations with residual probabilities are generated for every case and discount the final confidence. |

## Trust boundaries

```
untrusted ──────────────────────────────► trusted
prompt text, tool args, model output  │  event ids, timestamps, infrastructure
external feeds, OSINT reports         │  enforcement records
                                      │
      neutralize before rendering ────┘  never executed, never used as instructions
```

## Explicit non-goals

- **Identity attribution.** The system produces operator-linkage hypotheses. It never claims
  to know who a person is.
- **Automated punishment.** No path in this repo suspends an account without a human approver.
- **Content moderation of single messages.** A message-level classifier is included only as an
  evaluation baseline, to show what it costs.
- **Offensive capability.** No payloads, no live infrastructure, no real credentials.

## Known blind spots

- Operators who rotate client fingerprints between waves lose the strongest link this build uses.
- Escalation spread across sessions days apart falls outside the session window.
- Only English and Spanish cues are implemented; other languages are uncovered.
- Artifacts never touched by a tool call are invisible.
- Precision figures are measured on synthetic data and will not transfer unchanged.
