"""empty message

Revision ID: 1e0a9c001320
Revises: 5c1128073317
Create Date: 2023-03-28 17:09:04.546775

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '1e0a9c001320'
down_revision = '5c1128073317'
branch_labels = None
depends_on = None

# Enum 'type' for PostgreSQL
enum_name = 'pockets'
# Set temporary enum 'type' for PostgreSQL
tmp_enum_name = 'tmp_' + enum_name

# Options for Enum
old_options = ('security', 'updates', 'esm-infra', 'esm-apps')
new_options = ('security', 'updates', 'esm-infra', 'esm-apps', 'soss', 'fips', 'fips-updates', 'ros-esm')

# Create enum fields
old_type = sa.Enum(*old_options, name=enum_name)
new_type = sa.Enum(*new_options, name=enum_name)


def upgrade():
    # Rename current enum type to tmp_
    op.execute('ALTER TYPE ' + enum_name + ' RENAME TO ' + tmp_enum_name)
    # Create new enum type in db
    new_type.create(op.get_bind())
    # Update column to use new enum type
    op.execute('ALTER TABLE status ALTER COLUMN pocket TYPE ' + enum_name + ' USING pocket::text::' + enum_name)
    # Drop old enum type
    op.execute('DROP TYPE ' + tmp_enum_name)


def downgrade():
    # Instantiate db query
    status = sa.sql.table('status', sa.Column('pocket', new_type, nullable=False))
    # Rename enum type to tmp_
    op.execute('ALTER TYPE ' + enum_name + ' RENAME TO ' + tmp_enum_name)
    # Create enum type using old values
    old_type.create(op.get_bind())
    # Set enum type as type for pocket column
    op.execute('ALTER TABLE status ALTER COLUMN pocket TYPE ' + enum_name + ' USING pocket::text::' + enum_name)
    # Drop temp enum type
    op.execute('DROP TYPE ' + tmp_enum_name)
