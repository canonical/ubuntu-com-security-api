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

# Give up on a dead host in 5s and let the server reap dead workers' backends.
BASE_CONNECT_ARGS = {
    "connect_timeout": 5,
    "keepalives": 1,
    "keepalives_idle": 30,
    "keepalives_interval": 10,
    "keepalives_count": 3,
}

# Above gunicorn's 30s timeout, so only abandoned transactions are reaped.
READ_PG_OPTIONS = "-c idle_in_transaction_session_timeout=60000"
PRIMARY_PG_OPTIONS = "-c idle_in_transaction_session_timeout=300000"

# 90 workers share max_connections=100, so pool_size 1 is the ceiling.
PRIMARY_ENGINE_OPTIONS = {
    "pool_recycle": 3600,
    "pool_pre_ping": True,
    "pool_size": 1,
    "max_overflow": 2,
    "pool_timeout": 5,
    "connect_args": {**BASE_CONNECT_ARGS, "options": PRIMARY_PG_OPTIONS},
}

READ_ENGINE_OPTIONS = {
    **PRIMARY_ENGINE_OPTIONS,
    "connect_args": {**BASE_CONNECT_ARGS, "options": READ_PG_OPTIONS},
}

# Bind names
REPLICA_ONE = "replicaone"
REPLICA_TWO = "replicatwo"

_read_engines_by_url = {}


# Replicas that resolve to the same URL share one engine.
def _read_engine(url):
    if url not in _read_engines_by_url:
        _read_engines_by_url[url] = create_engine(
            url=url, **READ_ENGINE_OPTIONS
        )
    return _read_engines_by_url[url]


engines = {
    REPLICA_ONE: _read_engine(REPLICA_ONE_DATABASE_URL),
    REPLICA_TWO: _read_engine(REPLICA_TWO_DATABASE_URL),
}

primary_engine = create_engine(
    url=PRIMARY_DATABASE_URL,
    **PRIMARY_ENGINE_OPTIONS,
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


# Errors a retry can clear; the rest under SQLAlchemyError are permanent.
TRANSIENT_DB_ERRORS = (
    exc.DisconnectionError,
    exc.InterfaceError,
    exc.OperationalError,
    exc.PendingRollbackError,
    exc.TimeoutError,
)


def init_db(app):
    # Size Flask-SQLAlchemy's own engine like the others.
    app.config.setdefault(
        "SQLALCHEMY_ENGINE_OPTIONS", dict(PRIMARY_ENGINE_OPTIONS)
    )

    db.init_app(app)
    Migrate(app, db)

    # Returning None makes Flask raise a TypeError that hides the real error.
    def _log_and_rollback(error):
        app.logger.error(error)
        db.session.rollback()

    def _database_unavailable(error):
        _log_and_rollback(error)
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

    def _database_error(error):
        _log_and_rollback(error)
        return make_response(
            jsonify({"message": "A database error occurred."}), 500
        )

    for error_type in TRANSIENT_DB_ERRORS:
        app.register_error_handler(error_type, _database_unavailable)

    # Catch-all so every other SQLAlchemyError still gets a response.
    app.register_error_handler(exc.SQLAlchemyError, _database_error)
