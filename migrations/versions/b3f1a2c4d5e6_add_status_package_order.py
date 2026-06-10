"""add package_order column to status

Stores the position of each package within a CVE as supplied by the source
JSON, so that the API can return packages in the original "order of interest"
(e.g. linux before linux-hwe) instead of an arbitrary database order.

Revision ID: b3f1a2c4d5e6
Revises: 0e647dd16ef6
Create Date: 2026-06-09 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "b3f1a2c4d5e6"
down_revision = "0e647dd16ef6"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        "status", sa.Column("package_order", sa.Integer(), nullable=True)
    )


def downgrade():
    op.drop_column("status", "package_order")
