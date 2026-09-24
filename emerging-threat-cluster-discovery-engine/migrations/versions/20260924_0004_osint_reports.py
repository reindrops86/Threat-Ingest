"""Add the osint_reports table for OSINT research feed ingestion.

Revision ID: 20260924_0004
Revises: 20260924_0003
Create Date: 2026-09-24
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "20260924_0004"
down_revision: str | None = "20260924_0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "osint_reports",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("source", sa.String(length=64), nullable=False),
        sa.Column("title", sa.String(length=512), nullable=False),
        sa.Column("link", sa.String(length=2048), nullable=False),
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("summary", sa.String(length=2048), nullable=False),
        sa.Column("fetched_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("link", name="uq_osint_report_link"),
    )
    op.create_index("ix_osint_reports_published_at", "osint_reports", ["published_at"])
    op.create_index("ix_osint_reports_source", "osint_reports", ["source"])


def downgrade() -> None:
    op.drop_index("ix_osint_reports_source", table_name="osint_reports")
    op.drop_index("ix_osint_reports_published_at", table_name="osint_reports")
    op.drop_table("osint_reports")
