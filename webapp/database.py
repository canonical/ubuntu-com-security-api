"""Why keep the database object here?
===

The basic implementation of flask-sqlalchemy illustrates creating the
db object inside the `app.py` file, which allows you to use the simpler
syntax:

    db = SQLAlchemy(app)

(See https://flask-sqlalchemy.palletsprojects.com/en/2.x/quickstart/)


The reason we can't do it that way is because it creates a circular
dependency error. This is because we keep our models in `models.py`
(rather than directly in `app.py` as in the quickstart example).
`models.py` of course needs to do `from webapp.app import db`, which
is a problem:

> app.py --imports> views.py --imports> models.py --imports> app.py

So instead, we create the db object here, which can be imported by
both `app.py` and `models.py`, and then inside `app.py` we do:

    db.init_app(app)

To add the application context
"""

from flask import jsonify, make_response
from flask_migrate import Migrate
from canonicalwebteam.flask_base.env import get_flask_env
from flask_sqlalchemy import SQLAlchemy
from flask_sqlalchemy.session import Session
from sqlalchemy import create_engine
from sqlalchemy import exc
from sqlalchemy.sql import Update, Delete, Insert
import os


PRIMARY_DATABASE_URL = get_flask_env("DATABASE_URL", error=True)
# Use the primary as the default
REPLICA_ONE_DATABASE_URL = get_flask_env(
    "REPLICA_ONE_DATABASE_URL",
    PRIMARY_DATABASE_URL,
)
REPLICA_TWO_DATABASE_URL = get_flask_env(
    "REPLICA_TWO_DATABASE_URL",
    PRIMARY_DATABASE_URL,
)

# libpq hardening for every engine. connect_timeout bounds the handshake: a
# failed-over host can accept packets but never complete one, blocking for the
# OS TCP timeout. Keepalives let the server reap backends stranded "idle in
# transaction" when gunicorn SIGKILLs their worker.
BASE_CONNECT_ARGS = {
    "connect_timeout": 5,
    "keepalives": 1,
    "keepalives_idle": 30,
    "keepalives_interval": 10,
    "keepalives_count": 3,
}

# Server-side backstop for the same stranded backends. Both sit well above
# gunicorn's --timeout, so they abort only abandoned transactions.
#
# NOTE: CLI imports use the primary engine. One that does >5min of Python
# between statements in a transaction will be aborted; raise PRIMARY_PG_OPTIONS.
READ_PG_OPTIONS = (
    "-c statement_timeout=10000 -c idle_in_transaction_session_timeout=60000"
)
PRIMARY_PG_OPTIONS = "-c idle_in_transaction_session_timeout=300000"

# Sized against the server, not the app: max_connections is 100 and the fleet
# is 18 pods x 5 workers = 90 processes, so pool_size 1 is at its floor and
# cannot absorb another worker increase. Connections open lazily, so the real
# figure is far below the ceiling (27/100 observed at 3 workers). If headroom
# runs out, the levers are max_overflow or setting REPLICA_ONE/TWO_DATABASE_URL
# so reads stop landing on one server.
#
# pool_size caps idle retention, not concurrency; max_overflow covers a request
# touching both a replica and the primary. pool_timeout is short so an
# exhausted pool fails fast instead of blocking until gunicorn's --timeout and
# turning a slow query into a WORKER TIMEOUT cascade.
SQLALCHEMY_ENGINE_OPTIONS = {
    "pool_recycle": 3600,
    "pool_pre_ping": True,
    "pool_size": 1,
    "max_overflow": 2,
    "pool_timeout": 5,
    "connect_args": {**BASE_CONNECT_ARGS, "options": PRIMARY_PG_OPTIONS},
}

# Replicas also cap query runtime in the database: a slow read is aborted at
# 10s, releasing its worker and connection rather than pinning both until
# gunicorn SIGKILLs the worker. The primary has no statement_timeout on
# purpose - bulk CVE imports legitimately run long.
READ_ENGINE_OPTIONS = {
    **SQLALCHEMY_ENGINE_OPTIONS,
    "connect_args": {**BASE_CONNECT_ARGS, "options": READ_PG_OPTIONS},
}

# Bind names
REPLICA_ONE = "replicaone"
REPLICA_TWO = "replicatwo"

_replica_one_engine = create_engine(
    url=REPLICA_ONE_DATABASE_URL,
    **READ_ENGINE_OPTIONS,
)

# The replica URLs are unset in konf/, so both fall back to DATABASE_URL. Two
# pools against the same URL would double the connection count for nothing, so
# share the engine while they match; configuring the URLs splits them again.
if REPLICA_TWO_DATABASE_URL == REPLICA_ONE_DATABASE_URL:
    _replica_two_engine = _replica_one_engine
else:
    _replica_two_engine = create_engine(
        url=REPLICA_TWO_DATABASE_URL,
        **READ_ENGINE_OPTIONS,
    )

engines = {
    REPLICA_ONE: _replica_one_engine,
    REPLICA_TWO: _replica_two_engine,
}

primary_engine = create_engine(
    url=PRIMARY_DATABASE_URL,
    **SQLALCHEMY_ENGINE_OPTIONS,
)


class RoutedSession(Session):
    """A session to selectively return replica binds"""

    def get_bind(  # pyright: ignore
        self, mapper=None, clause=None, bind=None, **kwargs
    ):
        """Return a replica engine depending on available connections"""
        # For destructive operations, return the primary bind
        if self._flushing or isinstance(clause, (Insert, Delete, Update)):
            return primary_engine
        # Return the primary always for single threaded tests.
        # We need this to prevent deadlocks when multiple
        # sessions are created by test cases
        if os.getenv("TEST_MODE"):
            return primary_engine
        # Otherwise, choose a replica with the fewest
        # available connections
        current_engine = engines[REPLICA_ONE]
        for name, engine in engines.items():
            if engine.pool.checkedout() < current_engine.pool.checkedout():
                current_engine = engines[name]
        return current_engine


db = SQLAlchemy(
    session_options={
        "autoflush": False,
        "class_": RoutedSession,
    },
)


def init_db(app):
    db.init_app(app)
    Migrate(app, db)

    # These handlers must RETURN a response: returning None makes Flask raise
    # a TypeError blaming the view, which hides the database error that
    # actually occurred. Routine now that reads carry a statement_timeout -
    # a cancelled query raises OperationalError, a SQLAlchemyError.
    def _database_unavailable(error):
        app.logger.error(error)
        db.session.rollback()
        response = make_response(
            jsonify(
                {
                    "message": (
                        "The database is temporarily unavailable. "
                        "Please retry shortly."
                    )
                }
            ),
            503,
        )
        response.headers["Retry-After"] = "5"
        return response

    app.register_error_handler(exc.PendingRollbackError, _database_unavailable)
    app.register_error_handler(exc.SQLAlchemyError, _database_unavailable)
