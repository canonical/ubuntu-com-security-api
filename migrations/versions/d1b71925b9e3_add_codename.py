"""empty message

Revision ID: d1b71925b9e3
Revises: 0320de7481ac
Create Date: 2023-04-12 18:12:13.413661

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'd1b71925b9e3'
down_revision = '0320de7481ac'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('cve', sa.Column('codename', sa.String(), nullable=True))


def downgrade():
    op.drop_column('cve', 'codename')
