"""Add indexes for notice search optimization

Revision ID: fc4b8f31d182
Revises: 5ad36b3ca4ba
Create Date: 2025-08-18 09:56:49.713094

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'fc4b8f31d182'
down_revision = '5ad36b3ca4ba'
branch_labels = None
depends_on = None


def upgrade():
    # Create GIN indexes for full-text search
    # assumes pg_trgm already exists
    
    # Trigram indexes for full-text search
    op.execute("CREATE INDEX IF NOT EXISTS idx_notice_id_trgm ON notice USING gin (id gin_trgm_ops)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_notice_title_trgm ON notice USING gin (title gin_trgm_ops)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_notice_details_trgm ON notice USING gin (details gin_trgm_ops)")

    # B-tree indexes on notice_cves for fast joins
    op.execute("CREATE INDEX IF NOT EXISTS idx_notice_cves_notice_id ON notice_cves (notice_id)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_notice_cves_cve_id ON notice_cves (cve_id)")

    # B-tree index on release.codename for filtering
    op.execute("CREATE INDEX IF NOT EXISTS idx_release_codename ON release (codename)")

def downgrade():
    op.execute("DROP INDEX IF EXISTS idx_release_codename")
    op.execute("DROP INDEX IF EXISTS idx_notice_cves_cve_id")
    op.execute("DROP INDEX IF EXISTS idx_notice_cves_notice_id")
    op.execute("DROP INDEX IF EXISTS idx_notice_details_trgm")
    op.execute("DROP INDEX IF EXISTS idx_notice_title_trgm")
    op.execute("DROP INDEX IF EXISTS idx_notice_id_trgm")