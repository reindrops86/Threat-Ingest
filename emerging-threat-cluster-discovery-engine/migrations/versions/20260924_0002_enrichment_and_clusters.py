"""Add enrichment (append-only) and infrastructure cluster tables.

Revision ID: 20260924_0002
Revises: 20260921_0001
Create Date: 2026-09-24
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "20260924_0002"
down_revision: str | None = "20260921_0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "enrichments",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("indicator_id", sa.Integer(), nullable=False),
        sa.Column("provider", sa.String(length=32), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("asn", sa.Integer(), nullable=True),
        sa.Column("asn_name", sa.String(length=256), nullable=True),
        sa.Column("country", sa.String(length=8), nullable=True),
        sa.Column("resolved_ips", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("related_domains", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("cert_fingerprints", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("classification", sa.String(length=64), nullable=True),
        sa.Column("tags", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("raw_json", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("error", sa.String(length=512), nullable=True),
        sa.ForeignKeyConstraint(["indicator_id"], ["indicators.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_enrichments_indicator_id", "enrichments", ["indicator_id"])
    op.create_index("ix_enrichments_provider", "enrichments", ["provider"])
    op.create_index("ix_enrichments_observed_at", "enrichments", ["observed_at"])

    op.create_table(
        "infrastructure_clusters",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("cluster_key", sa.String(length=64), nullable=False),
        sa.Column("generated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("first_observed", sa.DateTime(timezone=True), nullable=True),
        sa.Column("confidence_score", sa.Float(), nullable=False),
        sa.Column("confidence_label", sa.String(length=16), nullable=False),
        sa.Column("evidence_json", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("cluster_key", name="uq_cluster_key"),
    )

    op.create_table(
        "cluster_members",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("cluster_id", sa.Integer(), nullable=False),
        sa.Column("indicator_id", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(["cluster_id"], ["infrastructure_clusters.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["indicator_id"], ["indicators.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("cluster_id", "indicator_id", name="uq_cluster_member"),
    )
    op.create_index("ix_cluster_members_cluster_id", "cluster_members", ["cluster_id"])


def downgrade() -> None:
    op.drop_index("ix_cluster_members_cluster_id", table_name="cluster_members")
    op.drop_table("cluster_members")
    op.drop_table("infrastructure_clusters")
    op.drop_index("ix_enrichments_observed_at", table_name="enrichments")
    op.drop_index("ix_enrichments_provider", table_name="enrichments")
    op.drop_index("ix_enrichments_indicator_id", table_name="enrichments")
    op.drop_table("enrichments")
