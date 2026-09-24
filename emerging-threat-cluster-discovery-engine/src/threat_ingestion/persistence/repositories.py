from __future__ import annotations

from sqlalchemy import nulls_last, select
from sqlalchemy.orm import Session

from threat_ingestion.domain.models import (
    ClusterResult,
    CollectionRun,
    EnrichmentResult,
    IocObservation,
    KevEntry,
    OsintReportItem,
    SourceAttempt,
)

from .models import (
    ClusterMemberRecord,
    CollectionRunRecord,
    EnrichmentRecord,
    IndicatorRecord,
    InfrastructureClusterRecord,
    KevEntryRecord,
    ObservationRecord,
    OsintReportRecord,
    RunSourceAttemptRecord,
)


class IngestionRepository:
    def __init__(self, session: Session) -> None:
        self.session = session

    def record_run(self, run: CollectionRun) -> None:
        self.session.add(CollectionRunRecord(id=run.run_id, started_at=run.started_at, ended_at=run.ended_at))

    def _get_or_create_indicator(self, indicator_type: str, canonical_value: str) -> IndicatorRecord:
        indicator = self.session.scalar(
            select(IndicatorRecord).where(
                IndicatorRecord.indicator_type == indicator_type,
                IndicatorRecord.canonical_value == canonical_value,
            )
        )
        if indicator is None:
            indicator = IndicatorRecord(indicator_type=indicator_type, canonical_value=canonical_value)
            self.session.add(indicator)
            self.session.flush()
        return indicator

    def upsert_observation(self, observation: IocObservation) -> str:
        indicator = self._get_or_create_indicator(observation.indicator_type, observation.canonical_value)
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

    def add_enrichment(self, result: EnrichmentResult) -> None:
        """Always inserts a new row; enrichment history is append-only by design."""
        indicator = self._get_or_create_indicator(result.indicator_type, result.canonical_value)
        self.session.add(
            EnrichmentRecord(
                indicator_id=indicator.id,
                provider=result.provider,
                observed_at=result.observed_at,
                asn=result.asn,
                asn_name=result.asn_name,
                country=result.country,
                resolved_ips=result.resolved_ips,
                related_domains=result.related_domains,
                cert_fingerprints=result.cert_fingerprints,
                classification=result.classification,
                tags=result.tags,
                raw_json=result.raw,
                error=result.error,
            )
        )

    def indicators_by_type(self, indicator_types: set[str]) -> list[IndicatorRecord]:
        return list(
            self.session.scalars(
                select(IndicatorRecord).where(IndicatorRecord.indicator_type.in_(indicator_types))
            ).all()
        )

    def save_cluster(self, cluster: ClusterResult, indicator_ids: list[int]) -> None:
        existing = self.session.scalar(
            select(InfrastructureClusterRecord).where(
                InfrastructureClusterRecord.cluster_key == cluster.cluster_key
            )
        )
        if existing is not None:
            self.session.delete(existing)
            self.session.flush()
        record = InfrastructureClusterRecord(
            cluster_key=cluster.cluster_key,
            generated_at=cluster.generated_at,
            first_observed=cluster.first_observed,
            confidence_score=cluster.confidence_score,
            confidence_label=cluster.confidence_label,
            evidence_json=[evidence.model_dump(mode="json") for evidence in cluster.evidence],
        )
        self.session.add(record)
        self.session.flush()
        for indicator_id in indicator_ids:
            self.session.add(ClusterMemberRecord(cluster_id=record.id, indicator_id=indicator_id))

    def upsert_kev_entry(self, entry: KevEntry) -> None:
        record = self.session.get(KevEntryRecord, entry.cve_id)
        fields = entry.model_dump(exclude={"cve_id"})
        if record is None:
            self.session.add(KevEntryRecord(cve_id=entry.cve_id, **fields))
            return
        for key, value in fields.items():
            setattr(record, key, value)

    def get_kev_entry(self, cve_id: str) -> KevEntryRecord | None:
        return self.session.get(KevEntryRecord, cve_id)

    def list_kev_entries(self, limit: int = 15) -> list[KevEntryRecord]:
        return list(
            self.session.scalars(
                select(KevEntryRecord)
                .order_by(nulls_last(KevEntryRecord.epss_score.desc()))
                .limit(limit)
            ).all()
        )

    def upsert_osint_report(self, item: OsintReportItem) -> str:
        existing = self.session.scalar(select(OsintReportRecord).where(OsintReportRecord.link == item.link))
        if existing is None:
            self.session.add(
                OsintReportRecord(
                    source=item.source,
                    title=item.title,
                    link=item.link,
                    published_at=item.published_at,
                    summary=item.summary,
                    fetched_at=item.fetched_at,
                )
            )
            return "inserted"
        existing.title = item.title
        existing.summary = item.summary
        existing.fetched_at = item.fetched_at
        return "updated"

    def list_recent_osint_reports(self, limit: int = 15) -> list[OsintReportRecord]:
        return list(
            self.session.scalars(
                select(OsintReportRecord).order_by(OsintReportRecord.published_at.desc()).limit(limit)
            ).all()
        )