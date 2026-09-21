"""Create the initial ingestion schema.

Revision ID: 20260921_0001
Revises:
Create Date: 2026-09-21
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "20260921_0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "indicators",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("indicator_type", sa.String(length=64), nullable=False),
        sa.Column("canonical_value", sa.String(length=2048), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("indicator_type", "canonical_value", name="uq_indicator_canonical"),
    )

    op.create_table(
        "observations",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("indicator_id", sa.Integer(), nullable=False),
        sa.Column("source", sa.String(length=64), nullable=False),
        sa.Column("source_record_id", sa.String(length=256), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("metadata_json", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.ForeignKeyConstraint(["indicator_id"], ["indicators.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("source", "source_record_id", name="uq_observation_source_record"),
    )
    op.create_index("ix_observations_indicator_id", "observations", ["indicator_id"])
    op.create_index("ix_observations_observed_at", "observations", ["observed_at"])

    op.create_table(
        "collection_runs",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("ended_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_collection_runs_started_at", "collection_runs", ["started_at"])

    op.create_table(
        "run_source_attempts",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("run_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("source", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("fetched", sa.Integer(), nullable=False),
        sa.Column("accepted", sa.Integer(), nullable=False),
        sa.Column("inserted", sa.Integer(), nullable=False),
        sa.Column("updated", sa.Integer(), nullable=False),
        sa.Column("rejected", sa.Integer(), nullable=False),
        sa.Column("retries", sa.Integer(), nullable=False),
        sa.Column("error", sa.String(length=512), nullable=True),
        sa.ForeignKeyConstraint(["run_id"], ["collection_runs.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.CheckConstraint("status IN ('success', 'failed')", name="ck_run_source_attempt_status"),
    )
    op.create_index("ix_run_source_attempts_run_id", "run_source_attempts", ["run_id"])

    op.create_table(
        "checkpoints",
        sa.Column("source", sa.String(length=64), nullable=False),
        sa.Column("cursor", sa.String(length=512), nullable=True),
        sa.PrimaryKeyConstraint("source"),
    )


def downgrade() -> None:
    op.drop_table("checkpoints")
    op.drop_index("ix_run_source_attempts_run_id", table_name="run_source_attempts")
    op.drop_table("run_source_attempts")
    op.drop_index("ix_collection_runs_started_at", table_name="collection_runs")
    op.drop_table("collection_runs")
    op.drop_index("ix_observations_observed_at", table_name="observations")
    op.drop_index("ix_observations_indicator_id", table_name="observations")
    op.drop_table("observations")
    op.drop_table("indicators")
