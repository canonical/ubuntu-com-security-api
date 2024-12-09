"""empty message

Revision ID: 654254322cd3
Revises: 645c9424286e
Create Date: 2024-12-05 15:16:32.511623

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '654254322cd3'
down_revision = '645c9424286e'
branch_labels = None
depends_on = None


# Enum 'type' for PostgreSQL
enum_name = 'cve_statuses'
# Set temporary enum 'type' for PostgreSQL
tmp_enum_name = 'tmp_' + enum_name

# Options for Enum
old_options = ("not-in-ubuntu", "active", "rejected")
new_options = ("not-in-ubuntu", "in-progress", "rejected")

# Create enum fields
old_type = sa.Enum(*old_options, name=enum_name)
new_type = sa.Enum(*new_options, name=enum_name)

def upgrade():
    # Rename current enum type to tmp_
    op.execute('ALTER TYPE ' + enum_name + ' RENAME TO ' + tmp_enum_name)
    # Create new enum type in db
    new_type.create(op.get_bind())
    # Update column to use new enum type
    op.execute('ALTER TABLE cve ALTER COLUMN status TYPE ' + enum_name + ' USING status::text::' + enum_name)
    # Drop old enum type
    op.execute('DROP TYPE ' + tmp_enum_name)

def downgrade():
    # Instantiate db query
    status = sa.sql.table('cve', sa.Column('status', new_type, nullable=False))
    # Rename enum type to tmp_
    op.execute('ALTER TYPE ' + enum_name + ' RENAME TO ' + tmp_enum_name)
    # Create enum type using old values
    old_type.create(op.get_bind())
    # Set enum type as type for status column
    op.execute('ALTER TABLE cve ALTER COLUMN status TYPE ' + enum_name + ' USING status::text::' + enum_name)
    # Drop temp enum type
    op.execute('DROP TYPE ' + tmp_enum_name)