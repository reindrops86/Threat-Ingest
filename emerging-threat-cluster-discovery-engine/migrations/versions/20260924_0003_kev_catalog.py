"""Add the known_exploited_vulnerabilities catalog (CISA KEV + EPSS + NVD CVSS).

Revision ID: 20260924_0003
Revises: 20260924_0002
Create Date: 2026-09-24
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "20260924_0003"
down_revision: str | None = "20260924_0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "known_exploited_vulnerabilities",
        sa.Column("cve_id", sa.String(length=32), nullable=False),
        sa.Column("vendor_project", sa.String(length=256), nullable=False),
        sa.Column("product", sa.String(length=256), nullable=False),
        sa.Column("vulnerability_name", sa.String(length=512), nullable=False),
        sa.Column("date_added", sa.DateTime(timezone=True), nullable=False),
        sa.Column("short_description", sa.String(length=4096), nullable=False),
        sa.Column("required_action", sa.String(length=2048), nullable=False),
        sa.Column("due_date", sa.DateTime(timezone=True), nullable=False),
        sa.Column("known_ransomware_use", sa.Boolean(), nullable=False),
        sa.Column("cvss_score", sa.Float(), nullable=True),
        sa.Column("epss_score", sa.Float(), nullable=True),
        sa.Column("epss_percentile", sa.Float(), nullable=True),
        sa.Column("synced_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("cve_id"),
    )
    op.create_index(
        "ix_known_exploited_vulnerabilities_epss_score", "known_exploited_vulnerabilities", ["epss_score"]
    )
    op.create_index(
        "ix_known_exploited_vulnerabilities_due_date", "known_exploited_vulnerabilities", ["due_date"]
    )


def downgrade() -> None:
    op.drop_index("ix_known_exploited_vulnerabilities_due_date", table_name="known_exploited_vulnerabilities")
    op.drop_index("ix_known_exploited_vulnerabilities_epss_score", table_name="known_exploited_vulnerabilities")
    op.drop_table("known_exploited_vulnerabilities")
