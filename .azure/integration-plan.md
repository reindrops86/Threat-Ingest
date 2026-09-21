# Integration Plan

## Backend

- Folder: `emerging-threat-cluster-discovery-engine`
- Runtime: Python 3.12 worker (no HTTP server or health endpoint)
- Install/build: `python -m pip install -e ".[dev]"`; `python -m compileall -q src migrations`
- Run: `threat-ingest collect --dry-run`, `threat-ingest collect-source <source> --dry-run`, `threat-ingest schedule`
- Test: `python -m pytest -q`

## Frontend

- None. This is a background worker; no frontend API seam or mock files exist.

## CLI Routes

- `CLI threat-ingest collect`: collect all enabled metadata sources once; options include `--dry-run`.
- `CLI threat-ingest collect-source <source>`: collect one of `threatfox`, `urlhaus`, or `malwarebazaar`; options include `--dry-run`.
- `CLI threat-ingest schedule`: start the single-instance APScheduler interval job.

## Database

- Type: PostgreSQL 16 via `compose.yaml`
- Connection variable: `DATABASE_URL`
- Supporting variables: `POSTGRES_USER`, `POSTGRES_PASSWORD`, `POSTGRES_DB`
- Migration tool: Alembic; directory: `emerging-threat-cluster-discovery-engine/migrations/versions`
- Create the initial schema migration for `indicators`, `observations`, `collection_runs`, `run_source_attempts`, and `checkpoints`; apply it to Docker PostgreSQL.
- NO seed data is to be created.

## Types

- Shared typed contracts live in `src/threat_ingestion/domain/models.py`; there is no separate shared package or import alias.

## Services

- Essential: PostgreSQL for normalized indicators, observations, runs, attempts, and checkpoints.
- No Enhancement services.

## Integration Tasks

- Create and apply an Alembic initial migration without seed data.
- Smoke-test the metadata-only CLI against fixture-backed tests; do not request or write samples, archives, or binaries.
- Validate idempotent replay, collection-run provenance, retry handling, and Docker PostgreSQL wiring.

## Integration Results

- Created `migrations/versions/20260921_0001_initial_schema.py` with schema-only tables for indicators, observations, collection runs, source attempts, and checkpoints, including foreign keys, uniqueness constraints, checks, and indexes. No seed data was created.
- Backend validation passed: package source compiled, the existing fixture-backed tests passed (`2 passed`), and all CLI command/help routes responded. The all-source and per-source dry-run commands exited without process errors; the upstream metadata services returned `401 Unauthorized` responses.
- Frontend integration is not applicable: this project is intentionally a background worker with no frontend, HTTP server, API routes, mock client, or mock data layer.
- PostgreSQL integration completed after Docker Desktop became available: `alembic upgrade head` applied revision `20260921_0001` successfully, and the database contains all five required tables plus `alembic_version`.
- Persistence smoke test passed against the empty schema: `threat-ingest collect` exited successfully, recorded one collection run and three failed source attempts for upstream `401 Unauthorized` responses, and created zero indicator or observation rows. No seed data was created.