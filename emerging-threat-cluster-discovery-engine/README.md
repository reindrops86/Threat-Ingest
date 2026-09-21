# Emerging Threat Cluster Discovery Engine

Local-first, metadata-only ingestion of IOC observations from ThreatFox, URLhaus, and MalwareBazaar.

The worker never downloads malware samples, archives, or binary payloads. It only requests documented metadata endpoints.

## Local setup

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
Copy-Item .env.example .env
docker compose up -d
alembic upgrade head
threat-ingest collect --dry-run
pytest
```

Use `threat-ingest collect-source threatfox --dry-run` for a single source, or `threat-ingest schedule` for the hourly job.