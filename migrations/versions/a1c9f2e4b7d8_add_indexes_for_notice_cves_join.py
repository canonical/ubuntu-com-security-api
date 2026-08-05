"""add indexes for notice_cves / notice_releases join tables

The many-to-many association tables ``notice_cves`` and ``notice_releases``
were created with foreign key constraints but WITHOUT indexes on their
columns. PostgreSQL does not create indexes for foreign keys automatically,
so every query that resolves the CVE<->Notice relationship (selectinload of
notices for a CVE list, loading the CVEs of a notice, etc.) performed a full
sequential scan of the join table. As the table grew this pushed those
queries past ``statement_timeout``, producing 503s on /security/cves.json,
/security/cves/<id>.json and /security/page/notices.json.

Adding B-tree indexes on both columns of each join table lets PostgreSQL use
index lookups instead of sequential scans.

Revision ID: a1c9f2e4b7d8
Revises: b3f1a2c4d5e6
Create Date: 2026-08-05 00:00:00.000000

"""
from alembic import op


# revision identifiers, used by Alembic.
revision = "a1c9f2e4b7d8"
down_revision = "b3f1a2c4d5e6"
branch_labels = None
depends_on = None


def upgrade():
    # notice_cves is the CVE <-> Notice association table.
    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_notice_cves_cve_id "
        "ON notice_cves (cve_id)"
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_notice_cves_notice_id "
        "ON notice_cves (notice_id)"
    )

    # notice_releases is the Release <-> Notice association table and has the
    # same missing-index problem.
    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_notice_releases_notice_id "
        "ON notice_releases (notice_id)"
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_notice_releases_release_codename "
        "ON notice_releases (release_codename)"
    )


def downgrade():
    op.execute("DROP INDEX IF EXISTS idx_notice_releases_release_codename")
    op.execute("DROP INDEX IF EXISTS idx_notice_releases_notice_id")
    op.execute("DROP INDEX IF EXISTS idx_notice_cves_notice_id")
    op.execute("DROP INDEX IF EXISTS idx_notice_cves_cve_id")
