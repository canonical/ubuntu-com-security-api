"""The session timeouts are set with SET on connect, not with the libpq
`options` startup parameter, because poolers such as PgBouncer drop it.
"""

import unittest

from sqlalchemy import text

from tests import BaseTestCase
from webapp.database import (
    ENGINE_OPTIONS,
    PRIMARY_IDLE_IN_TRANSACTION_TIMEOUT_MS,
    READ_IDLE_IN_TRANSACTION_TIMEOUT_MS,
    READ_STATEMENT_TIMEOUT_MS,
    engines,
    primary_engine,
    REPLICA_ONE,
)


def setting_ms(engine, name):
    with engine.connect() as connection:
        value = connection.execute(
            text("SELECT setting::int FROM pg_settings WHERE name = :name"),
            {"name": name},
        ).scalar()
    return value


def idle_timeout_ms(engine):
    return setting_ms(engine, "idle_in_transaction_session_timeout")


class DatabaseSessionSettings(BaseTestCase):
    def test_no_startup_options(self):
        # PgBouncer drops `options` with no error, and these tests connect
        # without PgBouncer. So guard against adding it back.
        self.assertNotIn("options", ENGINE_OPTIONS["connect_args"])

    def test_primary_engine_sets_timeout(self):
        self.assertEqual(
            idle_timeout_ms(primary_engine),
            PRIMARY_IDLE_IN_TRANSACTION_TIMEOUT_MS,
        )

    def test_read_engine_sets_timeout(self):
        self.assertEqual(
            idle_timeout_ms(engines[REPLICA_ONE]),
            READ_IDLE_IN_TRANSACTION_TIMEOUT_MS,
        )

    def test_read_engine_caps_statements(self):
        self.assertEqual(
            setting_ms(engines[REPLICA_ONE], "statement_timeout"),
            READ_STATEMENT_TIMEOUT_MS,
        )

    def test_primary_engine_does_not_cap_statements(self):
        # Publishes run long statements on the primary.
        self.assertEqual(setting_ms(primary_engine, "statement_timeout"), 0)

    def test_timeout_survives_rollback_on_return(self):
        # The pool rolls back on return; the SET must not be undone.
        primary_engine.dispose()
        idle_timeout_ms(primary_engine)
        self.assertEqual(
            idle_timeout_ms(primary_engine),
            PRIMARY_IDLE_IN_TRANSACTION_TIMEOUT_MS,
        )


if __name__ == "__main__":
    unittest.main()
