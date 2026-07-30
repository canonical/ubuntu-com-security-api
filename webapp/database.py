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

# Explicit pool sizing keeps the total connection count predictable across
# the fleet (8 pods x 3 gunicorn workers x 3 engines). Validate against the
# replicas' `max_connections` before raising these.
#
# pool_timeout is deliberately short: when the pool is exhausted a request
# now fails fast instead of blocking on the default 30s, which previously
# lined up with gunicorn's --timeout 30 and turned a slow query into a
# WORKER TIMEOUT cascade (every worker stuck waiting for a connection).
# libpq-level hardening applied to every engine.
#
# connect_timeout: after a primary failover the old host can accept packets but
# never complete a handshake. Without this, psycopg2 blocks for the OS TCP
# timeout (minutes) and pins a gunicorn worker for the whole time.
#
# keepalives: when gunicorn SIGKILLs a worker at --timeout, the server side of
# its connections is stranded as "idle in transaction" and keeps holding a
# connection slot. Keepalives let the server notice the dead peer and reap it.
BASE_CONNECT_ARGS = {
    "connect_timeout": 5,
    "keepalives": 1,
    "keepalives_idle": 30,
    "keepalives_interval": 10,
    "keepalives_count": 3,
}

# idle_in_transaction_session_timeout is the server-side backstop for the same
# stranded-backend problem. Both values sit well above gunicorn's --timeout 30,
# so they can never abort a live HTTP request - only abandoned ones.
#
# NOTE: long-running CLI import commands also use the primary engine. If one
# does Python work for more than 5 minutes between statements inside a single
# transaction, it will be aborted. Raise PRIMARY_PG_OPTIONS if that happens.
READ_PG_OPTIONS = (
    "-c statement_timeout=10000 -c idle_in_transaction_session_timeout=60000"
)
PRIMARY_PG_OPTIONS = "-c idle_in_transaction_session_timeout=300000"

# Pool sizing is constrained by the server, not by the app: max_connections on
# these instances is 100, and `usndbreplica` is shared with the
# raw-site-updates deployment. With 8 pods x 3 gunicorn workers there are 24
# processes, so each engine can afford roughly one persistent connection.
#
# pool_size caps *idle retention*, not concurrency. Sync workers serve one
# request at a time, so a process never needs more than a couple of connections
# at once; max_overflow covers the brief case where a request touches both a
# replica and the primary.
#
# pool_timeout is deliberately short: when the pool is exhausted a request now
# fails fast instead of blocking on the default 30s, which previously lined up
# with gunicorn's --timeout 30 and turned a slow query into a WORKER TIMEOUT
# cascade (every worker stuck waiting for a connection).
SQLALCHEMY_ENGINE_OPTIONS = {
    "pool_recycle": 3600,
    "pool_pre_ping": True,
    "pool_size": 1,
    "max_overflow": 2,
    "pool_timeout": 5,
    "connect_args": {**BASE_CONNECT_ARGS, "options": PRIMARY_PG_OPTIONS},
}

# Read replicas additionally cap query runtime at the database level. A slow
# CVE query (e.g. an unindexed ILIKE scan) is aborted by Postgres after 10s,
# releasing its worker and connection, instead of pinning both until gunicorn
# SIGKILLs the worker at 30s. Writes (bulk CVE imports) use the primary and
# are intentionally left without a statement_timeout since they run long.
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

# REPLICA_ONE/TWO_DATABASE_URL are currently unset in konf/, so both fall back
# to DATABASE_URL (see above) and all reads land on one server. Building two
# separate pools against the same URL just doubles the connection count for no
# benefit, so share the engine when the URLs match. Once the replica URLs are
# actually configured this transparently becomes two engines again.
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

    @app.errorhandler(exc.PendingRollbackError)
    def handle_db_exceptions(error):
        # log the error:
        app.logger.error(error)
        db.session.rollback()

    @app.errorhandler(exc.SQLAlchemyError)
    def rollback_failed_transactoins(error):
        app.logger.error(error)
        db.session.rollback()
