"""add composite indexes for the CVE list ordering

get_cves() filters on cve.status and orders by published/updated_at with
NULLs last, tie-broken on id. Without an index matching that shape the
planner sorts the whole matched set on every request, which took ~28s and
exceeded the statement timeout.

Both indexes already exist in production, created by hand during the
incident. IF NOT EXISTS makes this a no-op there while creating them in
dev, CI and staging, which have never had them.

CONCURRENTLY is required: a plain CREATE INDEX takes an ACCESS EXCLUSIVE
lock on cve for the duration, blocking all reads and writes. It cannot run
inside a transaction, hence the autocommit block.

Revision ID: a7c31e9f4b28
Revises: b3f1a2c4d5e6
Create Date: 2026-08-05 00:00:00.000000

"""
from alembic import op


# revision identifiers, used by Alembic.
revision = "a7c31e9f4b28"
down_revision = "b3f1a2c4d5e6"
branch_labels = None
depends_on = None


INDEXES = {
    "idx_cve_status_published_id": (
        "status, published DESC NULLS LAST, id DESC"
    ),
    "idx_cve_status_updated_id": (
        "status, updated_at DESC NULLS LAST, id DESC"
    ),
}

# A cancelled CONCURRENTLY build leaves an index of the same name behind with
# indisvalid = false. It is unusable, and CREATE INDEX IF NOT EXISTS would
# skip over it, so a retry would silently do nothing. Drop those first.
DROP_IF_INVALID = """
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_index i
        JOIN pg_class c ON c.oid = i.indexrelid
        WHERE c.relname = '{name}' AND NOT i.indisvalid
    ) THEN
        EXECUTE 'DROP INDEX {name}';
    END IF;
END $$;
"""


def upgrade():
    with op.get_context().autocommit_block():
        for name, columns in INDEXES.items():
            op.execute(DROP_IF_INVALID.format(name=name))
            op.execute(
                f"CREATE INDEX CONCURRENTLY IF NOT EXISTS {name} "
                f"ON cve USING btree ({columns})"
            )


def downgrade():
    with op.get_context().autocommit_block():
        for name in INDEXES:
            op.execute(f"DROP INDEX CONCURRENTLY IF EXISTS {name}")
