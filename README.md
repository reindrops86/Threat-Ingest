# Cybersecurity Portfolio

A curated portfolio of cybersecurity projects focused on threat intelligence, OSINT workflows, detection engineering, malware analysis, attribution, and AI misuse research.

This portfolio is built to show practical engineering, analytical thinking, and intentional growth across modern security domains.

## Focus areas

- Threat intelligence
- OSINT collection and enrichment
- Detection engineering
- Malware behavior analysis
- Actor attribution
- AI threat surfaces and misuse patterns
- Cybercrime ecosystem research

## Featured projects

### Cloud Campaign Evidence Graph ⭐ [Centerpiece Project]
An agentic cloud threat investigation pipeline that builds time-bounded evidence graphs, performs ATT&CK Cloud mappings, executes Skeptic audit reviews, generates STIX 2.1 bundles, and exports Sigma/KQL detection rules—validated against a 20-case evaluation benchmark.
- Repo: [cloud-campaign-evidence-graph](cloud-campaign-evidence-graph)
- Strength: Agentic pipeline design, defensible CTI judgments, cloud IAM/container threat intelligence, STIX 2.1 validation, and quantitative evaluation.

### OSINT Signal Extractor
Collects public-source signals, extracts suspicious entities, scores them, and exports structured intelligence.
- Repo: [osint_signal_extractor](osint_signal_extractor)
- Strength: OSINT pipeline design and signal scoring

### Threat Actor Knowledge Graph
Models actors, infrastructure, TTPs, and campaigns as a graph for attribution-oriented analysis.
- Repo: [threat-actor-knowledge-graph](threat-actor-knowledge-graph)
- Strength: relationship mapping and attribution reasoning

### LLM Abuse Detection Lab
Classifies adversarial prompts and misuse patterns using an agentic workflow.
- Repo: [llm-abuse-detection-lab](llm-abuse-detection-lab)
- Strength: AI threat-surface awareness and triage logic

### Detection Engineering Lab
Demonstrates Sigma/YARA-style detection thinking, log parsing, enrichment, and triage reporting.
- Repo: [detection-engineering-lab](detection-engineering-lab)
- Strength: operational detection and SOC relevance

### CTI Dashboard
An analyst-facing dashboard for IOC lookup, actor profiles, OSINT signals, enrichment, and ATT&CK mapping.
- Repo: [cti-dashboard](cti-dashboard)
- Strength: practical tool building and usability

### CTI Toolkit
A collection of scripts, wrappers, and notes for common threat-intelligence services and workflows.
- Repo: [cti-toolkit](cti-toolkit)
- Strength: ecosystem knowledge and practical CTI workflow awareness

### Agentic STIX/TAXII Feed Normalizer
Detects heterogeneous threat feeds, repairs malformed indicators, maps them to STIX 2.1, validates the result, and optionally publishes to a TAXII 2.1 collection.
- Repo: [agentic-stix-taxii-normalizer](agentic-stix-taxii-normalizer)
- Strength: CTI data normalization, STIX/TAXII interoperability, and auditable agent orchestration

### Agentic Connector Troubleshooting Assistant
Replays failed connector attempts, diagnoses connectivity, authentication, collection-routing, and schema problems, then generates evidence-driven remediation guidance.
- Repo: [agentic-connector-troubleshooting-assistant](agentic-connector-troubleshooting-assistant)
- Strength: CTI integration reliability, connector diagnostics, and operator-focused automation

### Agentic Threat Feed Quality Scorer
Evaluates STIX feeds for completeness, accuracy, enrichment, compliance, redundancy, and freshness, then recommends a transparent intake decision.
- Repo: [agentic-threat-feed-quality-scorer](agentic-threat-feed-quality-scorer)
- Strength: CTI quality control, explainable automation, and intake governance

### Autonomous CTI Pipeline Simulator
Simulates feed ingestion, enrichment, connector failures, STIX/TAXII transport, and pipeline health in one repeatable agentic workflow.
- Repo: [autonomous-cti-pipeline-simulator](autonomous-cti-pipeline-simulator)
- Strength: end-to-end CTI pipeline modeling, operational telemetry, and agent orchestration

### Malware Analysis Lab
Parses sandbox-like logs, extracts behaviors, maps to ATT&CK, and summarizes findings.
- Repo: [malware-analysis-lab](malware-analysis-lab)
- Strength: technical depth in malware behavior analysis

### Threat Actor Encyclopedia
Actor profiles, TTP notes, campaign timelines, and attribution writing.
- Repo: [threat-actor-encyclopedia](threat-actor-encyclopedia)
- Strength: intelligence writing and analysis discipline

### Cybercrime Ecosystem Research
Research-style analysis of the ransomware affiliate ecosystem, including TTPs, infrastructure, and trends.
- Repo: [cybercrime-ecosystem-research](cybercrime-ecosystem-research)
- Strength: research depth and strategic threat analysis

### Cybersecurity Roadmap 2026
Public learning plan, research goals, reading list, and portfolio roadmap.
- Repo: [cybersecurity-roadmap-2026](cybersecurity-roadmap-2026)
- Strength: intentional growth and direction

## Suggested reading order

1. [cybersecurity-roadmap-2026](cybersecurity-roadmap-2026)
2. [cti-toolkit](cti-toolkit)
3. [osint_signal_extractor](osint_signal_extractor)
4. [threat-actor-knowledge-graph](threat-actor-knowledge-graph)
5. [cti-dashboard](cti-dashboard)
6. [agentic-stix-taxii-normalizer](agentic-stix-taxii-normalizer)
7. [agentic-connector-troubleshooting-assistant](agentic-connector-troubleshooting-assistant)
8. [agentic-threat-feed-quality-scorer](agentic-threat-feed-quality-scorer)
9. [autonomous-cti-pipeline-simulator](autonomous-cti-pipeline-simulator)
10. [detection-engineering-lab](detection-engineering-lab)
11. [malware-analysis-lab](malware-analysis-lab)
12. [llm-abuse-detection-lab](llm-abuse-detection-lab)
13. [threat-actor-encyclopedia](threat-actor-encyclopedia)
14. [cybercrime-ecosystem-research](cybercrime-ecosystem-research)

## What this portfolio demonstrates

- Python development for security workflows
- IOC and infrastructure analysis
- ATT&CK-aware detection and mapping
- STIX/TAXII interoperability and feed normalization
- connector troubleshooting and integration reliability
- threat-feed quality scoring and intake governance
- end-to-end CTI pipeline simulation and health monitoring
- actor attribution and campaign analysis
- AI misuse and adversarial prompt classification
- analyst-facing research and reporting

## Publishing note

This README works best as the landing page for a dedicated portfolio repository that links out to each project repo.