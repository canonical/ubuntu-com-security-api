"""add indexes for CVE search

Revision ID: 5ad36b3ca4ba
Revises: 645c9424286e
Create Date: 2025-07-23 10:33:13.590820

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '5ad36b3ca4ba'
down_revision = '645c9424286e'
branch_labels = None
depends_on = None


def upgrade():
    # Create GIN indexes with pg_trgm ops on cve table (assumes extension already exists)
    op.execute("CREATE INDEX idx_cve_description_trgm ON cve USING gin (description gin_trgm_ops)")
    op.execute("CREATE INDEX idx_cve_ubuntu_description_trgm ON cve USING gin (ubuntu_description gin_trgm_ops)")
    op.execute("CREATE INDEX idx_cve_codename_trgm ON cve USING gin (codename gin_trgm_ops)")
    op.execute("CREATE INDEX idx_cve_mitigation_trgm ON cve USING gin (mitigation gin_trgm_ops)")
    op.execute("CREATE INDEX idx_cve_id_trgm ON cve USING gin (id gin_trgm_ops)")
    
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
    # Drop all created indexes in reverse order
    op.execute("DROP INDEX IF EXISTS idx_status_package_trgm")
    op.execute("DROP INDEX IF EXISTS idx_status_multi")
    op.execute("DROP INDEX IF EXISTS idx_status_component")
    op.execute("DROP INDEX IF EXISTS idx_status_release_codename")
    op.execute("DROP INDEX IF EXISTS idx_status_status")
    op.execute("DROP INDEX IF EXISTS idx_status_cve_id")

    op.execute("DROP INDEX IF EXISTS idx_cve_id_trgm")
    op.execute("DROP INDEX IF EXISTS idx_cve_mitigation_trgm")
    op.execute("DROP INDEX IF EXISTS idx_cve_codename_trgm")
    op.execute("DROP INDEX IF EXISTS idx_cve_ubuntu_description_trgm")
    op.execute("DROP INDEX IF EXISTS idx_cve_description_trgm")
