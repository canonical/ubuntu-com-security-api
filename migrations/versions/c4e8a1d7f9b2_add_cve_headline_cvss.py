"""add headline_cvss column to cve

Stores the single, source-tagged CVSS score ({version, source, baseScore,
baseSeverity}) chosen by the security team to be shown as the CVE's headline
score. It lives alongside the legacy cvss3 column until that is retired.

Revision ID: c4e8a1d7f9b2
Revises: b7d9e1f3a2c4
Create Date: 2026-11-09 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "c4e8a1d7f9b2"
down_revision = "b7d9e1f3a2c4"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        "cve", sa.Column("headline_cvss", sa.JSON(), nullable=True)
    )


def downgrade():
    op.drop_column("cve", "headline_cvss")
