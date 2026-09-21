# Project Plan

**Status**: Integrated
**Created**: 2026-09-21
**Mode**: NEW

---

## 1. Project Overview

**Goal**: Build V1 of the Emerging Threat Cluster Discovery Engine as a local-first Python ingestion worker that collects metadata-only IOC observations from ThreatFox, URLhaus, and MalwareBazaar and persists normalized, idempotent records with collection-run provenance in PostgreSQL. The project is designed so that every module is independently testable. Clustering, analyst UI, API, reporting, and AI enrichment are explicitly deferred to later stages.

**App Type**: Background worker

**API Login**: No

**Mode**: NEW

**Deployment Plan**: No deployment plan found

---

## 2. IOC Ingestion Worker — worker

| Component | Technology |
|-----------|-----------|
| **Language** | Python |
| **Runtime** | CPython 3.12 |
| **Framework** | APScheduler worker with Typer CLI |
| **Package Manager** | pip |
| **Database Access** | SQLAlchemy 2 + Alembic + psycopg |
| **Validation** | Pydantic v2 |
| **HTTP Client** | HTTPX |
| **Test Runner** | pytest |
| **Mocking Library** | unittest.mock + respx |
| **Test Command** | pytest |
| **Orchestration** | docker-compose |

**Immediate Scaffold Scope**:

- Define one shared source-adapter contract with source identity, cursor/checkpoint input, metadata-only fetch, normalization, and structured result/error output.
- Implement ThreatFox, URLhaus, and MalwareBazaar adapters using documented metadata endpoints only. Reject, ignore, and never download malware samples, archives, or binary payloads.
- Normalize source records into typed IOC observations while retaining source record identifiers, timestamps, tags, confidence, malware family references, and a JSON metadata envelope.
- Persist sources, indicators, observations, collection runs, run-source attempts, and checkpoints in PostgreSQL. Enforce deterministic canonical values and unique constraints/upserts so replaying the same fixture or source page is idempotent.
- Record run provenance including run ID, source, requested window/cursor, start/end times, counts fetched/accepted/inserted/updated/rejected, retry count, terminal status, and sanitized error details.
- Apply per-source configurable rate limits, request timeouts, bounded exponential backoff with jitter, `Retry-After` handling, and retry only for transient failures. Never log secrets or full sensitive payloads.
- Provide `collect`, `collect-source`, and `schedule` CLI entry points. Support one-shot local execution and a single-instance hourly APScheduler job with overlap prevention and graceful shutdown.
- Supply Docker Compose PostgreSQL with health checks, environment-driven configuration, Alembic migrations, and deterministic local setup commands.
- Add fixture-based contract, normalization, idempotency, retry/rate-limit, provenance, CLI, and PostgreSQL integration tests. Tests must run without live threat-feed access and must assert that no binary download path exists.

**Acceptance Criteria**:

1. All three collectors satisfy the same adapter contract and pass identical contract tests against checked-in metadata fixtures.
2. Two imports of the same fixture produce one canonical indicator/observation set while recording two distinct collection runs and their per-source outcomes.
3. Transient `429` and `5xx` responses honor bounds and `Retry-After`; permanent `4xx` responses fail without unsafe retries; source quotas are configurable.
4. A fresh Docker PostgreSQL instance can be migrated and populated through the CLI, and the hourly scheduler invokes the same idempotent application service used by one-shot commands.
5. Repository code, tests, and fixtures contain no malware binaries and no code path that requests or writes MalwareBazaar samples.

---

## 3. Services Required

| Azure Service | Role in App | Environment Variable | Default Value (Local) | Classification |
|---------------|------------|---------------------|----------------------|----------------|
| PostgreSQL | Primary store for normalized IOCs, observations, collection runs, source attempts, and checkpoints | DATABASE_URL | postgresql://${POSTGRES_USER}:${POSTGRES_PASSWORD}@localhost:5432/threat_ioc | Essential |

---

## 4. Prerequisites

### Run

| Tool | Service(s) | Installed | Version |
|------|------------|-----------|---------|
| Python | IOC Ingestion Worker | ✅ | 3.12.10 |
| pip | IOC Ingestion Worker | ✅ | 25.0.1 |

### Debug

| Tool | Service(s) | Installed | Version |
|------|------------|-----------|---------|
| Docker | PostgreSQL local dependency | ✅ | 29.6.2 |
| Docker Compose | PostgreSQL local dependency | ✅ | 5.3.1 |
| Python VS Code extension (`ms-python.python`) | IOC Ingestion Worker | ✅ | 2026.4.0 |

---

## 5. Project Structure

```text
emerging-threat-cluster-discovery-engine/
├── .azure/
│   └── project-plan.md
├── .env.example
├── .gitignore
├── README.md
├── compose.yaml
├── pyproject.toml
├── alembic.ini
├── migrations/
│   └── versions/
├── src/
│   └── threat_ingestion/
│       ├── __init__.py
│       ├── cli.py
│       ├── config.py
│       ├── scheduler.py
│       ├── application/
│       │   └── collect.py
│       ├── collectors/
│       │   ├── base.py
│       │   ├── threatfox.py
│       │   ├── urlhaus.py
│       │   └── malwarebazaar.py
│       ├── domain/
│       │   ├── models.py
│       │   └── normalization.py
│       └── persistence/
│           ├── database.py
│           ├── models.py
│           └── repositories.py
└── tests/
    ├── fixtures/
    │   ├── threatfox/
    │   ├── urlhaus/
    │   └── malwarebazaar/
    ├── contract/
    ├── integration/
    └── unit/
```

---

## 6. Route Definitions

V1 exposes no HTTP routes. Its command surface is intentionally limited to local CLI and scheduler entry points.

| # | Method | Path | Description | Request Body | Response Body | Status Codes |
|---|--------|------|-------------|-------------|--------------|-------------|
| 1 | CLI | `threat-ingest collect` | Run all enabled metadata collectors once | CLI options for time window and dry-run | Structured run summary with source counts and run ID | 0 success, nonzero failure |
| 2 | CLI | `threat-ingest collect-source <source>` | Run one metadata collector once | Source name plus optional cursor/window | Structured source-attempt summary and run ID | 0 success, 2 validation, nonzero failure |
| 3 | CLI | `threat-ingest schedule` | Start the single-instance hourly collector scheduler | Interval and overlap policy from environment | Structured lifecycle and run logs | 0 clean shutdown, nonzero failure |

---

## 7. Next Steps

1. Run **azure-project-scaffold** to execute this approved V1 ingestion plan
2. Run **azure-project-integrate** to create and apply migrations, connect the CLI to PostgreSQL, and execute fixture-backed smoke tests
3. Run **azure-debug-plan** → **azure-debug-generate** for Docker PostgreSQL and VS Code debugging
4. Stage deterministic correlation/clustering, FastAPI, Streamlit analyst workflows, Markdown reports, Blob Storage, and optional local Ollama enrichment only after V1 ingestion acceptance criteria pass
5. Run the **azure-deploy** agent only when a later phase requires Azure hosting; it uses **azure-app-onboard** for architecture, cost estimation, IaC generation, provisioning, and health verification