from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from threat_ingestion.domain.models import CollectionRun, IocObservation, SourceAttempt

from .models import CollectionRunRecord, IndicatorRecord, ObservationRecord, RunSourceAttemptRecord


class IngestionRepository:
    def __init__(self, session: Session) -> None:
        self.session = session

    def record_run(self, run: CollectionRun) -> None:
        self.session.add(CollectionRunRecord(id=run.run_id, started_at=run.started_at, ended_at=run.ended_at))

    def upsert_observation(self, observation: IocObservation) -> str:
        indicator = self.session.scalar(
            select(IndicatorRecord).where(
                IndicatorRecord.indicator_type == observation.indicator_type,
                IndicatorRecord.canonical_value == observation.canonical_value,
            )
        )
        if indicator is None:
            indicator = IndicatorRecord(
                indicator_type=observation.indicator_type, canonical_value=observation.canonical_value
            )
            self.session.add(indicator)
            self.session.flush()
        existing = self.session.scalar(
            select(ObservationRecord).where(
                ObservationRecord.source == observation.source,
                ObservationRecord.source_record_id == observation.source_record_id,
            )
        )
        if existing is None:
            self.session.add(
                ObservationRecord(
                    indicator_id=indicator.id,
                    source=observation.source,
                    source_record_id=observation.source_record_id,
                    observed_at=observation.observed_at,
                    metadata_json=observation.metadata,
                )
            )
            return "inserted"
        existing.indicator_id = indicator.id
        existing.observed_at = observation.observed_at
        existing.metadata_json = observation.metadata
        return "updated"

    def record_attempt(self, run: CollectionRun, attempt: SourceAttempt) -> None:
        self.session.add(
            RunSourceAttemptRecord(run_id=run.run_id, **attempt.model_dump())
        )