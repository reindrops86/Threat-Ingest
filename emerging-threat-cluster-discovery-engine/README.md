# Emerging Threat Cluster Discovery Engine

Local-first, metadata-only ingestion of IOC observations from ThreatFox, URLhaus, and MalwareBazaar.

The worker never downloads malware samples, archives, or binary payloads. It only requests documented metadata endpoints.

## Local setup

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
Copy-Item .env.example .env
# Edit .env and set ABUSE_CH_AUTH_KEY from https://auth.abuse.ch/
docker compose up -d
alembic upgrade head
threat-ingest collect
pytest
```

The same `ABUSE_CH_AUTH_KEY` is used for the ThreatFox, URLhaus, and MalwareBazaar
community APIs. Keep `.env` local and never commit the key. Use
`threat-ingest collect-source threatfox` (or `urlhaus` / `malwarebazaar`) for one
source, `--dry-run` to fetch and normalize without persistence, or
`threat-ingest schedule` for the hourly job.

Generate a Markdown report from the PostgreSQL data collected so far:

```powershell
threat-ingest report
```

Use `--output reports/custom-report.md` to choose a path and
`--recent-limit 50` to include more recent observations.

## OSINT enrichment and infrastructure clustering (v2)

Collection alone only answers "what indicators are feeds reporting?". The
enrichment + clustering pipeline pivots each collected domain/IP through
independent OSINT signals and groups infrastructure that shares real
operational overlap, so the report can answer "what previously unconnected
infrastructure is emerging?" instead.

```
Feed collectors → indicators → enrichment providers → graph engine → clusters → report
```

Enrichment providers (`src/threat_ingestion/enrichment/providers/`):

- **RDAP** (`rdap.py`) — ASN/geo for IPs via ip-api.com, registrar/nameservers for
  domains via the RDAP bootstrap service. No API key required.
- **DNS** (`dns.py`) — passive-DNS-style A/NS resolution over Cloudflare
  DNS-over-HTTPS. No API key required.
- **urlscan** (`urlscan.py`) — pivots a domain into co-hosted IPs, related
  domains, and TLS certificate fingerprints via the public search API.
  `URLSCAN_API_KEY` is optional and only raises the rate limit.
- **GreyNoise** (`greynoise.py`) — classifies an IP as scanner noise vs.
  worth investigating. Requires `GREYNOISE_API_KEY`; skipped (not an error)
  if unset.
- **Censys** (`censys.py`) — ASN, geolocation, and embedded GreyNoise/threat/
  privacy labels for a host via the Censys Platform's free, high-volume
  enrichment endpoint (no credits consumed). Requires
  `CENSYS_PERSONAL_ACCESS_TOKEN`. Setting `CENSYS_ENABLE_CERT_PIVOT=true`
  additionally asks Censys which other hosts have presented a TLS certificate
  discovered by urlscan — a strong "shared infrastructure" signal for the
  graph engine — but requires the paid Adversary Investigation module.
- **Shodan** (`shodan.py`) — open ports/services, TLS certificate
  fingerprints, and any CVEs Shodan has flagged as exposed on the host.
  Requires `SHODAN_API_KEY`. Reported CVEs are surfaced as tags and
  cross-referenced against the local KEV catalog in the report.
- **OTX** (`otx.py`) — how many AlienVault OTX community threat-intel pulses
  reference this IP/domain, and under what tags/malware families. Requires
  `OTX_API_KEY`.
- **AbuseIPDB** (`abuseipdb.py`) — community-reported abuse confidence score
  for an IP. Requires `ABUSEIPDB_API_KEY`.

Each provider's evidence is stored separately per source rather than collapsed
into a single malicious/not-malicious verdict, per the "store evidence from
each source separately" principle — the report and graph engine decide what
to do with disagreement between sources.

An `ip:port` observation (ThreatFox) and the plain `ip` node its enrichment
produces are resolved to the same graph node by canonical IP, so ASN/cert
overlap discovered via enrichment links back to the original observation
instead of sitting on an orphaned node (see `application/enrich_and_cluster.py`).

Every enrichment call is stored as a new row (`enrichments` table) rather than
overwriting the previous state, so ASN moves, new certificate reuse, or newly
observed co-hosted domains stay queryable as a timeline.

The graph engine (`src/threat_ingestion/clustering/graph.py`) connects
indicators that share an ASN, TLS certificate, DNS/IP infrastructure, or a
malware family label, then scores each connected component's confidence from
the *diversity* of corroborating evidence — not just cluster size. Every
cluster records *why* it was grouped (e.g. `cert_reuse: shared TLS
certificate ...`), so findings are explainable rather than an AI asserting
two things "look related".

```powershell
threat-ingest enrich --limit 25   # pivot the next batch of domains/IPs through OSINT providers
threat-ingest cluster             # detect and persist infrastructure clusters
threat-ingest report              # includes an "Emerging Infrastructure Clusters" section
```

## Vulnerability/exploitation intelligence (v2)

`src/threat_ingestion/vulnerability_intel/` mirrors the CISA Known Exploited
Vulnerabilities (KEV) catalog locally and enriches every entry with a FIRST.org
EPSS exploitation-probability score, so the report can rank CVEs by real-world
exploitation risk instead of just severity:

- **KEV** (`kev_client.py`) — the full catalog, free and keyless.
- **EPSS** (`epss_client.py`) — batched exploitation-probability + percentile
  lookups, free and keyless.
- **NVD** (`nvd_client.py`) — on-demand CVSS score/vector + description for a
  single CVE. Works keyless at a low rate limit; `NVD_API_KEY` raises it.

```powershell
threat-ingest vuln-sync                  # refresh the local KEV catalog + EPSS scores
threat-ingest vuln-lookup CVE-2021-44228 # combined KEV + EPSS + NVD view for one CVE
threat-ingest report                     # includes a "Known Exploited Vulnerabilities" section
                                          # and an "Infrastructure Exposing Known Exploited
                                          # Vulnerabilities" section (Shodan CVE tags x KEV)
```

**Known gap**: the cross-reference is tag-based (CVE IDs Shodan already
flagged), not full CPE/version matching against NVD — a host running a
vulnerable product that Shodan hasn't tagged with a CVE won't show up.
Full CPE-based matching is the natural next step.

## ATT&CK mapping and OSINT reporting (v2)

`src/threat_ingestion/attack_mapping/mapping.py` is a curated, dependency-free
lookup from malware family name (matched case/punctuation-insensitively) to
MITRE ATT&CK Enterprise techniques. The report's "MITRE ATT&CK Techniques
Observed" section aggregates techniques across every correlated malware
family, so a finding reads as "this activity exhibits credential-access and
C2 behaviors" instead of just a family name. It's a curated subset, not a full
mitre/cti STIX ingestion — extend `_FAMILY_TECHNIQUES` for more coverage.

`src/threat_ingestion/osint_reports/` pulls Unit 42, The DFIR Report, and CISA
advisories (RSS/Atom, no API key) and flags which posts mention a malware
family already observed in this dataset:

```powershell
threat-ingest osint-sync   # pull latest posts from the configured feeds
threat-ingest report       # includes a "Recent OSINT Reporting" section with a Mentions column
```

## Bridging into Daily-Cyber-Threat-Intelligence-Briefing

[Daily-Cyber-Threat-Intelligence-Briefing](https://github.com/reindrops86/Daily-Cyber-Threat-Intelligence-Briefing)
is a companion project that scores and tracks findings through an
evidence-backed lifecycle, but its live mode has no source for actor-campaign,
dark-web, or multi-source-indicator signals — it explicitly reads those from a
`data/manual_signals.json` file the analyst supplies. `threat-ingest
export-signals` writes exactly that file, so Threat-Ingest becomes that
project's live source for two signal types it otherwise cannot get on its own:

- **`multi_source_corroboration`** — one signal per detected infrastructure
  cluster, subject set to the cluster key, confidence/reliability derived from
  the cluster's own confidence score, detail listing members and *why* they
  clustered (ASN/cert/DNS overlap).
- **`environment_reachable`** — one signal per indicator where host enrichment
  (e.g. Shodan) directly observed a CVE that is also in the local KEV catalog —
  real scan evidence of exposure, not a self-declared watchlist entry.

```powershell
threat-ingest export-signals --output ..\Daily-Cyber-Threat-Intelligence-Briefing\data\manual_signals.json
cd ..\Daily-Cyber-Threat-Intelligence-Briefing
python -m app.main live
```

The exported JSON matches that project's `Signal` dataclass exactly (verified
directly against its schema, not just informally) — `Signal(**entry)` for each
emitted dict succeeds with no adaptation needed on the other side.