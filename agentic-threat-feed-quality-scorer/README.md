# Agentic Threat Feed Quality Scorer

An explainable quality gate for incoming STIX threat-intelligence feeds. Specialist agents score each feed on completeness, accuracy, enrichment depth, STIX compliance, redundancy, and timeliness before an intake workflow decides whether it should enter a collection.

## Decisions

- `Accept` - the feed meets automated thresholds across all quality dimensions.
- `Reject` - the feed is empty, structurally unreliable, or has invalid indicator patterns.
- `Enrich before ingest` - the core feed is usable, but it lacks metadata, confidence, labels, or provenance needed for analyst use.
- `Quarantine for manual review` - stale or duplicate-heavy intelligence needs analyst review before it changes collection quality.

Each decision includes a rationale and the underlying evidence. This makes the policy reviewable by analysts and easy to tune as an organization changes its intake standards.

## Agents and Signals

| Agent | Score | Evidence used |
| --- | --- | --- |
| `CompletenessAgent` | Required STIX fields | Missing type, id, dates, pattern, or valid-from values |
| `AccuracyAgent` | Indicator syntax | Recognizable STIX pattern structure |
| `EnrichmentAgent` | Analyst context | Labels, confidence, and source provenance |
| `STIXComplianceAgent` | STIX 2.1 shape | Bundle, indicator IDs, and specification version |
| `RedundancyAgent` | Indicator uniqueness | Duplicate STIX patterns |
| `TimelinessAgent` | Freshness | Indicators updated within 30 days |
| `DecisionAgent` | Intake recommendation | Transparent threshold-based policy |

## Run the Demo

The project uses the Python standard library only.

```powershell
python app/main.py --input data/sample_feed.json --output data/feed_quality_report.json
```

The included feed is structurally valid and timely, but one indicator lacks labels and provenance. It is therefore routed to `Enrich before ingest` with a detailed report.

## Layout

- `app/main.py` - CLI and report writer
- `app/feed_quality/workflow.py` - scoring agents and recommendation policy
- `data/sample_feed.json` - representative STIX 2.1 bundle with an enrichment gap

## Portfolio Value

This project demonstrates automated CTI intake control: quantifying feed reliability, protecting downstream analysts from stale or duplicated intelligence, and retaining a traceable explanation for every automated decision.