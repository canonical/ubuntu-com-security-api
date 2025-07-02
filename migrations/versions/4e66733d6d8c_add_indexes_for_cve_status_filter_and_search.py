"""add indexes for CVE status filtering and search

Revision ID: 4e66733d6d8c
Revises: 085878f314e9
Create Date: 2025-06-18 21:54:21.547540

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '4e66733d6d8c'
down_revision = '085878f314e9'
branch_labels = None
depends_on = None


def upgrade():
    # Enable pg_trgm
    op.execute("CREATE EXTENSION IF NOT EXISTS pg_trgm")

    # B-tree indexes for common join and filter operations
    op.execute("CREATE INDEX idx_status_cve_id ON status (cve_id)")
    op.execute("CREATE INDEX idx_status_status ON status (status)")
    op.execute("CREATE INDEX idx_status_release_codename ON status (release_codename)")
    op.execute("CREATE INDEX idx_status_component ON status (component)")

    # Composite index for multi-condition filter efficiency
    op.execute("CREATE INDEX idx_status_multi ON status (cve_id, status, release_codename, component)")

    # GIN index for fuzzy package_name search
    op.execute("CREATE INDEX idx_status_package_trgm ON status USING gin (package_name gin_trgm_ops)")


def downgrade():
    # Drop indexes in reverse order
    op.execute("DROP INDEX IF EXISTS idx_status_package_trgm")
    op.execute("DROP INDEX IF EXISTS idx_status_multi")
    op.execute("DROP INDEX IF EXISTS idx_status_component")
    op.execute("DROP INDEX IF EXISTS idx_status_release_codename")
    op.execute("DROP INDEX IF EXISTS idx_status_status")
    op.execute("DROP INDEX IF EXISTS idx_status_cve_id")