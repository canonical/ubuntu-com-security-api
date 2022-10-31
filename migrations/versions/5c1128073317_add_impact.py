"""add_impact

Revision ID: 5c1128073317
Revises: 8008e46e6ea8
Create Date: 2022-10-27 17:11:02.654110

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '5c1128073317'
down_revision = '8008e46e6ea8'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        "cve",
        sa.Column(
            "impact",
            sa.JSON(),
            nullable=True,
        ),
    )


def downgrade():
    op.drop_column("cve", "impact")
