# Threat Actor Knowledge Graph

A lightweight threat intelligence graph built with NetworkX to model how actors, infrastructure, tactics, and campaigns connect. This demonstrates attribution by showing which infrastructure and TTPs support a campaign and which actor appears most likely responsible.

## What is included

- Actors
- Infrastructure
- TTPs
- Campaigns
- Relationship edges with labels such as `uses`, `controls`, `conducts`, and `supports`
- A Python graph builder and visualization export
- A Jupyter notebook for graph queries and visual analytics

## Example actor profiles

### APT29
- Alias: Cozy Bear / IRON HEMLOCK
- Region: Russia
- Focus: cyber espionage
- High-confidence indicator set tied to phishing and credential theft
- Infrastructure: `mail-verify[.]com`
- Campaign: `Operation Ghost`

### FIN7
- Alias: Carbon Spider
- Focus: financial theft and point-of-sale compromise
- Infrastructure: `invoice-update[.]cloud`
- TTPs: PowerShell Loader, malicious web infrastructure, credential theft patterns
- Campaign: `Trident Finance`

### Lazarus Group
- Alias: Hidden Cobra
- Region: North Korea
- Focus: strategic disruption and financial theft
- Infrastructure: `webmail-security[.]net`
- TTPs: living-off-the-land and stealthy execution patterns
- Campaign: `Moonlight Incursion`

## Graph schema

Nodes are typed as:
- `actor`
- `infrastructure`
- `ttp`
- `campaign`

Edges use relationship labels like:
- `uses`
- `controls`
- `conducts`
- `supports`

## Run the graph

```bash
python threat_actor_graph.py
```

This builds the graph, prints a summary, and saves a visualization as `threat_actor_graph.png`.

## Notebook usage

Open the Notebook in the `notebooks` folder to query the graph and inspect actor-to-campaign connections.

## Review guide

1. `README.md` — overview and actor model
2. `threat_actor_graph.py` — graph construction and query logic
3. `notebooks/threat_actor_graph_analysis.ipynb` — graph exploration
4. `threat_actor_graph.png` — visual output

## Why this matters
This project shows attribution skill because it connects the actor, infrastructure, TTPs, and campaign into a single explainable picture.
