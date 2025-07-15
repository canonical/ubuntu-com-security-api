"""add trigram indexes for CVE search

Revision ID: 085878f314e9
Revises: 645c9424286e
Create Date: 2025-06-13 12:56:49.834647

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '085878f314e9'
down_revision = '645c9424286e'
branch_labels = None
depends_on = None


def upgrade():
    # Enable pg_trgm
    op.execute("CREATE EXTENSION IF NOT EXISTS pg_trgm")

    # Create trigram indexes on cve table
    op.execute("CREATE INDEX idx_cve_description_trgm ON cve USING gin (description gin_trgm_ops)")
    op.execute("CREATE INDEX idx_cve_ubuntu_description_trgm ON cve USING gin (ubuntu_description gin_trgm_ops)")
    op.execute("CREATE INDEX idx_cve_codename_trgm ON cve USING gin (codename gin_trgm_ops)")
    op.execute("CREATE INDEX idx_cve_mitigation_trgm ON cve USING gin (mitigation gin_trgm_ops)")
    op.execute("CREATE INDEX idx_cve_id_trgm ON cve USING gin (id gin_trgm_ops)")

def downgrade():
    # Drop the trigram indexes
    op.execute("DROP INDEX IF EXISTS idx_cve_description_trgm")
    op.execute("DROP INDEX IF EXISTS idx_cve_ubuntu_description_trgm")
    op.execute("DROP INDEX IF EXISTS idx_cve_codename_trgm")
    op.execute("DROP INDEX IF EXISTS idx_cve_mitigation_trgm")
    op.execute("DROP INDEX IF EXISTS idx_cve_id_trgm")