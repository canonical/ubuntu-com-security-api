"""empty message

Revision ID: f18a0bd8a809
Revises: d1b71925b9e3
Create Date: 2023-04-25 17:07:19.259029

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'f18a0bd8a809'
down_revision = 'd1b71925b9e3'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('cve', sa.Column('updated_at', sa.DateTime(timezone=True), server_default=None, nullable=True))


def downgrade():
    op.drop_column('cve', 'updated_at')
