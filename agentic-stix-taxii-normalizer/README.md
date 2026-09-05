# Agentic STIX/TAXII Feed Normalizer

A compact, auditable multi-agent workflow that turns heterogeneous cyber-threat-intelligence feeds into validated STIX 2.1 indicator bundles. It is built around the part of CTI engineering that is usually difficult in practice: deciding what an unfamiliar feed contains, repairing defensively formatted values, and retaining the reasoning trail.

## Workflow

1. `FeedDetectionAgent` identifies CSV, MISP event exports, OpenCTI GraphQL responses, vendor JSON, or generic JSON API records.
2. `FieldMappingAgent` maps source-specific fields into a common indicator representation and repairs common defanging mistakes such as `[.]` and `hxxps`.
3. `SchemaValidationAgent` emits STIX 2.1 indicator objects and checks their required fields and pattern envelopes before any publication attempt.
4. The CLI writes the STIX bundle locally, or posts it to a caller-supplied TAXII 2.1 collection URL.

The implementation is deterministic by design. This makes each autonomous decision inspectable in the printed agent trace and keeps an analyst in control of deployment and publication.

## Run the demo

The project uses only the Python standard library.

```powershell
python app/main.py --input data/vendor_indicators.csv --output data/normalized_vendor_bundle.json
python app/main.py --input data/misp_export.json --output data/normalized_misp_bundle.json
python app/main.py --input data/opencti_response.json --output data/normalized_opencti_bundle.json
```

For a real TAXII 2.1 server, add the collection endpoint explicitly:

```powershell
python app/main.py --input data/vendor_indicators.csv --taxii-collection-url https://taxii.example/collections/collection-id
```

The endpoint is intentionally not stored in code or configuration. Production use should add authentication, retry/backoff, TLS policy, and an analyst approval gate before publication.

## Supported Shapes

| Feed type | Detection cue | Example fields |
| --- | --- | --- |
| CSV | `.csv` extension | `indicator_type`, `ioc`, `confidence`, `timestamp` |
| MISP | `Event.Attribute` | `type`, `value`, `timestamp`, `Tag` |
| OpenCTI | `data` GraphQL array | `node.observable_value`, `node.indicator_type` |
| Vendor JSON | `indicators` array | `indicator`, `type`, `tags` |
| JSON API | top-level record array | `value`, `type`, `confidence` |

## Output

Each output is a STIX bundle containing `indicator` objects with a STIX pattern, confidence, labels, timestamps, and a source reference. The CLI prints the input count, correction log, skip count, and validation outcome. Sample successful bundles are generated locally and ignored by version control.

## Layout

- `app/main.py` - CLI and optional TAXII 2.1 publication adapter
- `app/stix_normalizer/workflow.py` - detection, mapping, repair, STIX generation, and validation agents
- `data/` - deliberately messy vendor, MISP, and OpenCTI-style fixtures

## Portfolio Value

This project demonstrates practical CTI data engineering: schema inference, defensive normalization, STIX 2.1 production, controlled TAXII delivery, and transparent agent orchestration rather than opaque automation.