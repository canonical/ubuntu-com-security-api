"""empty message

Revision ID: 645c9424286e
Revises: 5df43dc932dd
Create Date: 2024-08-27 08:30:26.043013

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '645c9424286e'
down_revision = '5df43dc932dd'
branch_labels = None
depends_on = None

# Enum 'type' for PostgreSQL
enum_name = 'pockets'
# Set temporary enum 'type' for PostgreSQL
tmp_enum_name = 'tmp_' + enum_name

# Options for Enum
old_options = ('security', 'updates', 'esm-infra', 'esm-apps', 'soss', 'fips', 'fips-updates', 'ros-esm')
new_options = ('security', "updates", "esm-infra", "esm-infra-legacy", "esm-apps", "fips", "fips-updates", "ros-esm", "soss", "realtime",)

#Create enum fields
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
