"""The idle-in-transaction timeout is set with SET on connect, not with the
libpq `options` startup parameter, because poolers such as PgBouncer drop it.
"""

import unittest

from sqlalchemy import text

from tests import BaseTestCase
from webapp.database import (
    ENGINE_OPTIONS,
    PRIMARY_IDLE_IN_TRANSACTION_TIMEOUT_MS,
    READ_IDLE_IN_TRANSACTION_TIMEOUT_MS,
    engines,
    primary_engine,
    REPLICA_ONE,
)


def idle_timeout_ms(engine):
    with engine.connect() as connection:
        value = connection.execute(
            text(
                "SELECT setting::int FROM pg_settings"
                " WHERE name = 'idle_in_transaction_session_timeout'"
            )
        ).scalar()
    return value


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
