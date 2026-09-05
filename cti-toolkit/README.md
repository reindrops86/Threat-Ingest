# CTI Toolkit

A practical threat-intelligence toolkit featuring modular API wrappers, multi-source enrichment scripts, CLI examples, and ecosystem documentation for SOC & CTI analyst workflows.

## Included Wrappers & Integration Scope

- **VirusTotal / Hybrid Analysis**: File hash, URL, domain, and IP reputation reports.
- **AbuseIPDB / GreyNoise**: IP threat confidence scoring, mass-scanner noise filtration, and threat actor context.
- **Shodan / Censys**: Host fingerprinting, open port/banner inspection, and SSL/TLS certificate discovery.
- **AlienVault OTX / MISP**: Open Threat Exchange pulse lookups and MISP event/attribute queries.

## Key Features

- **Modular Python Wrappers**: `wrappers/` folder containing isolated, easy-to-use API clients.
- **Unified Multi-Source Enricher**: `scripts/unified_enrichment.py` auto-detects indicator type and queries relevant threat intel services.
- **Offline Fallback Execution**: All wrappers return structured mock intelligence when API keys are absent, ensuring offline reproducibility.

## Repo Layout

- `wrappers/` — Service clients for VirusTotal, Hybrid Analysis, AbuseIPDB, GreyNoise, Shodan, Censys, OTX, and MISP
- `scripts/` — Utility scripts including `unified_enrichment.py` and `ioc_normalizer.py`
- `notes/` — OSINT and service notes
- `cli_examples.md` — Command line and Python API usage examples

## Example use cases

- normalize indicators from raw text
- prototype enrichment against common CTI services
- document tool usage for investigations
- build repeatable analyst workflows

## Review guide

1. `README.md` — overview
2. `scripts/` — utility scripts
3. `wrappers/` — service wrappers
4. `notes/` — ecosystem notes
5. `cli_examples.md` — commands to try

## Portfolio value

This repo shows you know the CTI ecosystem well enough to build around it, not just talk about it.
