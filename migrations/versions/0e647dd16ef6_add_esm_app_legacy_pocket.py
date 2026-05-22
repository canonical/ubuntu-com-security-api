"""empty message

Revision ID: 0e647dd16ef6
Revises: fc4b8f31d182
Create Date: 2026-05-22 12:02:19.267122

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '0e647dd16ef6'
down_revision = 'fc4b8f31d182'
branch_labels = None
depends_on = None

# Enum 'type' for PostgreSQL
enum_name = 'pockets'
# Set temporary enum 'type' for PostgreSQL
tmp_enum_name = 'tmp_' + enum_name

# Options for Enum
old_options = (
    'security',
    'updates',
    'esm-infra',
    'esm-infra-legacy',
    'esm-apps',
    'fips',
    'fips-updates',
    'ros-esm',
    'soss',
    'realtime',
)
new_options = (
    'security',
    'updates',
    'esm-infra',
    'esm-infra-legacy',
    'esm-apps',
    'esm-apps-legacy',
    'fips',
    'fips-updates',
    'ros-esm',
    'soss',
    'realtime',
)

# Create enum fields
old_type = sa.Enum(*old_options, name=enum_name)
new_type = sa.Enum(*new_options, name=enum_name)


def upgrade():
    # Rename current enum type to tmp_
    op.execute('ALTER TYPE ' + enum_name + ' RENAME TO ' + tmp_enum_name)
    # Create new enum type in db
    new_type.create(op.get_bind())
    # Update column to use new enum type
    op.execute(
        'ALTER TABLE status ALTER COLUMN pocket TYPE '
        + enum_name
        + ' USING pocket::text::'
        + enum_name
    )
    # Drop old enum type
    op.execute('DROP TYPE ' + tmp_enum_name)


def downgrade():
    # Downgrade safety: map removed value to a compatible one.
    op.execute(
        "UPDATE status SET pocket = 'esm-apps' WHERE pocket = 'esm-apps-legacy'"
    )
    # Rename enum type to tmp_
    op.execute('ALTER TYPE ' + enum_name + ' RENAME TO ' + tmp_enum_name)
    # Create enum type using old values
    old_type.create(op.get_bind())
    # Set enum type as type for pocket column
    op.execute(
        'ALTER TABLE status ALTER COLUMN pocket TYPE '
        + enum_name
        + ' USING pocket::text::'
        + enum_name
    )
    # Drop temp enum type
    op.execute('DROP TYPE ' + tmp_enum_name)
