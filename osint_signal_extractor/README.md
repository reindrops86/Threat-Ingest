# OSINT Signal Extractor

A small cyber-focused OSINT pipeline that ingests public sources, extracts suspicious signals, scores them, and exports structured intelligence.

## Purpose
This project is the first anchor project in a cyber-focused portfolio. It is designed to turn noisy public-source signals into ranked threat observations that can later be enriched with attribution, agentic workflows, and correlation.

## Core workflow
1. Collect public-source data from GitHub and other open sources.
2. Extract suspicious indicators, aliases, or malicious patterns.
3. Normalize entity names and metadata.
4. Score the signal using a lightweight heuristic model.
5. Export a JSON intelligence report for downstream use.

## Repository layout
- app/collectors: data collection modules
- app/extractors: text and metadata extraction logic
- app/scorers: confidence and severity calculation
- app/exporters: reporting and serialization
- app/models.py: shared signal schema
- app/main.py: CLI entrypoint
- data/: sample data and example outputs

## Example usage
```bash
python -m app.main --query "ransomware" --source github --limit 10
```

The command returns a JSON report with ranked signals, confidence, and reasons.

## Example output
```json
[
  {
    "id": "sig-001",
    "entity": "ransomware-team",
    "signal_type": "repo_name",
    "source": "https://github.com/example/ransomware-team",
    "confidence": 0.82,
    "severity": "medium",
    "tags": ["malware", "repo"]
  }
]
```

## Review guide

1. `README.md` — overview and workflow
2. `app/collectors/` — source ingestion
3. `app/extractors/` — signal extraction
4. `app/normalizers/` — entity cleanup
5. `app/scorers/` — risk and confidence scoring
6. `app/exporters/` — output generation
7. `data/sample_signals.json` — sample export

## Why this matters
This project shows practical cyber threat-intelligence engineering because it converts open-source signals into a structured, analyst-usable report.

## Planned extensions
- domain and URL enrichment
- deduplication and clustering
- dashboard view
- CSV / JSON export improvements
- correlation with threat intel feeds
- LLM-assisted summarization

## Notes
This is intentionally scoped as an MVP project: simple, useful, and easy to demo in under a week.
