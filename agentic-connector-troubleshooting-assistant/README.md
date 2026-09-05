# Agentic Connector Troubleshooting Assistant

An evidence-driven multi-agent assistant for diagnosing threat-intelligence and SOC connector failures. It tests an optional configured API endpoint, replays captured ingestion attempts without resending them, classifies failures, and generates a report with specific remediation steps.

## What It Diagnoses

- API reachability, HTTP endpoint failures, and network errors
- Authentication rejections such as `401` and `403`
- Incorrect or unavailable TAXII collection identifiers
- STIX or connector payload schema gaps
- Remote `5xx` service failures that should be retried only after payload verification

The assistant does not change connector configuration, retry against remote systems, or transmit tokens. Replay mode is local and safe to run against captured failed requests.

## Agent Workflow

1. `ConnectivityAgent` calls an explicitly configured endpoint with a five-second timeout and records HTTP or network evidence.
2. `AuthenticationAgent` identifies credential-related replay responses.
3. `CollectionRoutingAgent` compares the expected collection ID to the captured request URL and identifies collection `404` responses.
4. `SchemaAgent` compares each replayed object with the connector's declared required fields.
5. `ReplayAgent` preserves an operator-readable trace of the attempts examined.

## Run the Offline Demo

The project has no external dependencies and defaults to replay-only operation.

```powershell
python app/main.py --connector data/connector_config.json --attempts data/captured_attempts.json --output data/diagnostic_report.json
```

The included report identifies an invalid token, a wrong collection ID, an object missing `spec_version`, and an object missing `id`.

## Optional Connectivity Probe

Add an `endpoint` property to the connector JSON only when you intend to test a specific service endpoint:

```json
{
  "name": "Production TAXII connector",
  "endpoint": "https://taxii.example/health",
  "collection_id": "collection-id",
  "required_fields": ["type", "id", "spec_version"]
}
```

The probe sends a simple unauthenticated `GET`. It does not send your configured payload or any credentials. Keep tokens in a secret store; do not place them in connector files or captured replay data.

## Layout

- `app/main.py` - CLI and diagnostic report writer
- `app/connector_troubleshooter/workflow.py` - connectivity probing, replay, classification, and recommendations
- `data/connector_config.json` - sample TAXII connector contract
- `data/captured_attempts.json` - captured failure scenarios

## Portfolio Value

This project targets the operational reality of CTI integrations: an analyst gets explainable evidence and next actions for connector failures instead of only a failed job notification.