# Autonomous CTI Pipeline Simulator

A reproducible, agent-driven simulation of an end-to-end cyber-threat-intelligence pipeline. It models feed ingestion, enrichment, connector failures, STIX 2.1 generation, TAXII transport, and a dashboard of pipeline health without contacting a real intelligence platform.

## Pipeline Agents

1. `IngestionAgent` validates incoming records and records malformed feed entries.
2. `EnrichmentAgent` adds deterministic passive-DNS and reputation context.
3. `ConnectorAgent` simulates successful delivery, token rejection, collection failure, and schema mismatch outcomes.
4. `STIXTransportAgent` creates STIX 2.1 indicator objects for connector-approved records and delivers them to a simulated TAXII collection.
5. `PipelineHealthAgent` calculates stage health and overall pipeline status.

## Run the Simulation

The scenario is fully local and reproducible:

```powershell
python app/main.py --scenario data/degraded_pipeline_scenario.json --output data/pipeline_health_report.json
```

The included scenario produces:

- One malformed feed record rejected during ingestion.
- Three records enriched.
- One successful connector pass and STIX/TAXII delivery.
- One simulated `401` authentication error and one `422` schema mismatch.
- A degraded overall pipeline score with a critical connector stage.

## View Pipeline Health

Install the dashboard dependencies, then point Streamlit at the generated report:

```powershell
pip install -r requirements.txt
streamlit run app/dashboard.py -- --report data/pipeline_health_report.json
```

The dashboard displays overall and per-stage health, filters pipeline events, shows the agent trace, and exposes simulated STIX objects delivered to TAXII.

## Cloud & AI Security Risk Graph

An interactive toxic-combination simulator that models how cloud and AI risks intersect:

```powershell
streamlit run app/risk_graph_app.py --server.port 8503
```

Toggle risks in the sidebar to see the attack graph change in real time:

- Individual risks rarely matter; combinations of exposure, vulnerability, identity, and data risk create the critical path.
- AI-specific risks include plaintext LLM provider keys, unencrypted training buckets, vector-store leakage, and shadow AI deployments.
- Remediation is ranked by how many toxic paths a single fix eliminates rather than by raw alert volume.

## Behavioral Cloud IOC Hunter

Detects cloud attackers from CloudTrail-style activity rather than from atomic indicators alone:

```powershell
streamlit run app/behavioral_ioc_app.py --server.port 8504 -- --events data/cloudtrail_activity.json
```

- Sequence signatures match ordered API calls within a time window per credential and source IP.
- Parameter-level IOCs extract attacker-controlled values such as `clusterName`, `keyName`, and `publicKeyMaterial`.
- A parameter value reused across separate credentials links otherwise unrelated incidents to one operator.
- Actor clustering groups activity by ASN, country, and API call set, mirroring the honeypot pivot method.
- Contextual signals flag scripted user agents, unusual geography, multi-region repetition, and permission probing.

## Cloud Threat Actor Tracker

Turns one-off detections into tracked adversaries with persistent profiles:

```powershell
streamlit run app/actor_tracker_app.py --server.port 8506 -- --registry data/actor_registry.json
```

- Ingests behavioral hunt results and links new activity to known actors using weighted evidence.
- Evidence is ranked: a reused parameter fingerprint outweighs source IP, behavior, and shared hosting.
- Tracks infrastructure rotation over time, so an actor stays linked after changing IP, ASN, and country.
- Confidence decays on a 90-day half-life, because a dormant cluster is weaker evidence than fresh activity.
- Analysts can promote a candidate to a named actor, add notes, merge clusters, and split them when evidence contradicts.

Ingesting both waves demonstrates the core idea. The second wave shares no IP address with the first, yet links to the same actor through the reused SSH public key:

```powershell
streamlit run app/actor_tracker_app.py --server.port 8506
# Ingest data/cloudtrail_activity.json as wave-1, then data/cloudtrail_activity_wave2.json as wave-2
```

## Layout

- `app/main.py` - simulation CLI and health-report writer
- `app/cti_pipeline/workflow.py` - pipeline agent orchestration and deterministic failure simulation
- `app/dashboard.py` - Streamlit pipeline-health dashboard
- `app/risk_graph/graph.py` - attack-path, toxic-combination, and remediation-priority engine
- `app/risk_graph_app.py` - interactive cloud and AI security risk graph
- `app/behavioral_ioc/hunter.py` - behavioral IOC detection, clustering, and hunt-query generation
- `app/behavioral_ioc_app.py` - behavioral cloud IOC hunting interface
- `app/actor_tracker/tracker.py` - persistent actor profiles, evidence linking, and confidence decay
- `app/actor_tracker_app.py` - cloud threat actor tracking interface
- `data/degraded_pipeline_scenario.json` - feed and connector outcome scenario
- `data/cloudtrail_activity.json` - synthetic cloud activity log for behavioral hunting
- `data/cloudtrail_activity_wave2.json` - later activity with rotated infrastructure

## Portfolio Value

This project demonstrates how a CTI integration behaves as a complete system: malformed data, enrichment, connector reliability, standards-based transport, and operational telemetry are visible in one repeatable model.