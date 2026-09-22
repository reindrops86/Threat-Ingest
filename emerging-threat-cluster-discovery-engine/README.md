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