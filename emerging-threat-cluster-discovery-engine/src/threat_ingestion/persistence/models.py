from __future__ import annotations

from datetime import datetime
from uuid import UUID

from sqlalchemy import DateTime, ForeignKey, Integer, JSON, String, UniqueConstraint
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