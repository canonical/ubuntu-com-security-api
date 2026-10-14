"""add ordered_packages column to cve

Stores a CVE's package names in the source "order of interest" (the order the
import JSON lists them in) as a single JSON value on the CVE row, so the API
can return packages in that order without writing an ordering key onto every
status row on every import (which previously caused bulk-upsert timeouts).

Revision ID: b7d9e1f3a2c4
Revises: a7c31e9f4b28
Create Date: 2026-10-14 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "b7d9e1f3a2c4"
down_revision = "a7c31e9f4b28"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        "cve", sa.Column("ordered_packages", sa.JSON(), nullable=True)
    )


def downgrade():
    op.drop_column("cve", "ordered_packages")
