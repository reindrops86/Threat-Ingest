from __future__ import annotations

from datetime import datetime
from uuid import UUID

from sqlalchemy import JSON, Boolean, DateTime, Float, ForeignKey, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from .database import Base


class IndicatorRecord(Base):
    __tablename__ = "indicators"
    __table_args__ = (UniqueConstraint("indicator_type", "canonical_value", name="uq_indicator_canonical"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    indicator_type: Mapped[str] = mapped_column(String(64))
    canonical_value: Mapped[str] = mapped_column(String(2048))


class ObservationRecord(Base):
    __tablename__ = "observations"
    __table_args__ = (UniqueConstraint("source", "source_record_id", name="uq_observation_source_record"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    indicator_id: Mapped[int] = mapped_column(ForeignKey("indicators.id"))
    source: Mapped[str] = mapped_column(String(64))
    source_record_id: Mapped[str] = mapped_column(String(256))
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    metadata_json: Mapped[dict] = mapped_column(JSON)


class CollectionRunRecord(Base):
    __tablename__ = "collection_runs"

    id: Mapped[UUID] = mapped_column(primary_key=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class RunSourceAttemptRecord(Base):
    __tablename__ = "run_source_attempts"

    id: Mapped[int] = mapped_column(primary_key=True)
    run_id: Mapped[UUID] = mapped_column(ForeignKey("collection_runs.id"))
    source: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(16))
    fetched: Mapped[int] = mapped_column(Integer)
    accepted: Mapped[int] = mapped_column(Integer)
    inserted: Mapped[int] = mapped_column(Integer)
    updated: Mapped[int] = mapped_column(Integer)
    rejected: Mapped[int] = mapped_column(Integer)
    retries: Mapped[int] = mapped_column(Integer)
    error: Mapped[str | None] = mapped_column(String(512))


class CheckpointRecord(Base):
    __tablename__ = "checkpoints"

    source: Mapped[str] = mapped_column(String(64), primary_key=True)
    cursor: Mapped[str | None] = mapped_column(String(512))


class EnrichmentRecord(Base):
    """Append-only enrichment observation. Every provider call inserts a new row so
    infrastructure history (ASN moves, cert reuse, new resolutions) can be replayed."""

    __tablename__ = "enrichments"

    id: Mapped[int] = mapped_column(primary_key=True)
    indicator_id: Mapped[int] = mapped_column(ForeignKey("indicators.id"))
    provider: Mapped[str] = mapped_column(String(32))
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    asn: Mapped[int | None] = mapped_column(Integer)
    asn_name: Mapped[str | None] = mapped_column(String(256))
    country: Mapped[str | None] = mapped_column(String(8))
    resolved_ips: Mapped[list] = mapped_column(JSON)
    related_domains: Mapped[list] = mapped_column(JSON)
    cert_fingerprints: Mapped[list] = mapped_column(JSON)
    classification: Mapped[str | None] = mapped_column(String(64))
    tags: Mapped[list] = mapped_column(JSON)
    raw_json: Mapped[dict] = mapped_column(JSON)
    error: Mapped[str | None] = mapped_column(String(512))


class InfrastructureClusterRecord(Base):
    __tablename__ = "infrastructure_clusters"
    __table_args__ = (UniqueConstraint("cluster_key", name="uq_cluster_key"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    cluster_key: Mapped[str] = mapped_column(String(64))
    generated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    first_observed: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    confidence_score: Mapped[float] = mapped_column(Float)
    confidence_label: Mapped[str] = mapped_column(String(16))
    evidence_json: Mapped[list] = mapped_column(JSON)


class ClusterMemberRecord(Base):
    __tablename__ = "cluster_members"
    __table_args__ = (UniqueConstraint("cluster_id", "indicator_id", name="uq_cluster_member"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    cluster_id: Mapped[int] = mapped_column(ForeignKey("infrastructure_clusters.id"))
    indicator_id: Mapped[int] = mapped_column(ForeignKey("indicators.id"))


class KevEntryRecord(Base):
    """Local mirror of the CISA KEV catalog, refreshed by `threat-ingest vuln-sync`.
    Upserted by cve_id rather than append-only: this is a canonical government
    catalog, not an independent OSINT observation about our own indicators."""

    __tablename__ = "known_exploited_vulnerabilities"

    cve_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    vendor_project: Mapped[str] = mapped_column(String(256))
    product: Mapped[str] = mapped_column(String(256))
    vulnerability_name: Mapped[str] = mapped_column(String(512))
    date_added: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    short_description: Mapped[str] = mapped_column(String(4096))
    required_action: Mapped[str] = mapped_column(String(2048))
    due_date: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    known_ransomware_use: Mapped[bool] = mapped_column(Boolean)
    cvss_score: Mapped[float | None] = mapped_column(Float)
    epss_score: Mapped[float | None] = mapped_column(Float)
    epss_percentile: Mapped[float | None] = mapped_column(Float)
    synced_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class OsintReportRecord(Base):
    """A single item pulled from an OSINT research feed. Upserted by link so
    re-running the sync doesn't duplicate rows, but title/summary edits are
    picked up if a publisher updates a post."""

    __tablename__ = "osint_reports"
    __table_args__ = (UniqueConstraint("link", name="uq_osint_report_link"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    source: Mapped[str] = mapped_column(String(64))
    title: Mapped[str] = mapped_column(String(512))
    link: Mapped[str] = mapped_column(String(2048))
    published_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    summary: Mapped[str] = mapped_column(String(2048))
    fetched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))