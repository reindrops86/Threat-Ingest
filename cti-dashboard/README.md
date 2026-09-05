# CTI Dashboard

A practical Streamlit dashboard for cyber threat intelligence workflows. It demonstrates IOC lookup, actor profiles, OSINT signal viewing, enrichment, and ATT&CK mapping in one place.

## What it includes

- IOC lookup
- Actor profiles
- OSINT signal viewer
- Enrichment results
- ATT&CK mapping
- Severity breakdown and filtering
- A small enrichment engine backed by example indicators
- Wiz CTI interview lab with cloud, supply-chain, and infrastructure scenarios

## Run it

```bash
streamlit run app/main.py -- --signals data/sample_signals.json
```

## Inputs

The dashboard expects a signal JSON file shaped like the OSINT extractor output, with fields such as:

- entity
- signal_type
- source
- confidence
- severity
- tags

## Wiz interview lab

Choose `Wiz CTI interview lab` in the sidebar to practice a four-stage scenario covering:

- Cloud identity and control-plane investigation
- Supply-chain compromise hypotheses
- Adversary infrastructure clustering
- Actionable reporting with calibrated confidence

The lab runs offline and provides scored feedback plus high-probability interview prompts.

## Analyst views

- Signal table with severity badges
- Severity breakdown chart
- IOC lookup and enrichment index
- Actor profile browser
- ATT&CK technique mapping

## Why this matters

This project shows practical engineering because it moves beyond scripts and provides an analyst-facing interface for threat-intelligence workflows.
