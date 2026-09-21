from __future__ import annotations

from datetime import datetime, timezone

from threat_ingestion.collectors.base import MetadataCollector
from threat_ingestion.domain.models import CollectionRun, SourceAttempt
from threat_ingestion.persistence.repositories import IngestionRepository


async def collect_once(
    collectors: list[MetadataCollector], repository: IngestionRepository | None, dry_run: bool
) -> CollectionRun:
    run = CollectionRun(dry_run=dry_run)
    if repository and not dry_run:
        repository.record_run(run)
    for collector in collectors:
        try:
            observations = await collector.collect()
            attempt = SourceAttempt(source=collector.source, fetched=len(observations), accepted=len(observations), status="success")
            if repository and not dry_run:
                for observation in observations:
                    outcome = repository.upsert_observation(observation)
                    setattr(attempt, outcome, getattr(attempt, outcome) + 1)
                repository.record_attempt(run, attempt)
            run.attempts.append(attempt)
        except Exception as error:
            sanitized = f"{type(error).__name__}: {str(error)[:200]}"
            attempt = SourceAttempt(source=collector.source, status="failed", error=sanitized)
            if repository and not dry_run:
                repository.record_attempt(run, attempt)
            run.attempts.append(attempt)
    run.ended_at = datetime.now(timezone.utc)
    if repository and not dry_run:
        repository.session.commit()
    return run