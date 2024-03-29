"""empty message

Revision ID: 0320de7481ac
Revises: 1e0a9c001320
Create Date: 2023-03-28 18:27:02.492780

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '0320de7481ac'
down_revision = '1e0a9c001320'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.alter_column('release', 'codename',
               existing_type=sa.VARCHAR(),
               nullable=False)
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.alter_column('release', 'codename',
               existing_type=sa.VARCHAR(),
               nullable=True)
    # ### end Alembic commands ###
