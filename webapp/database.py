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


PRIMARY_DATABASE_URL = get_flask_env(
    "DATABASE_URL", "POSTGRESQL_DB_CONNECT_STRING", error=True
)
# Use the primary as the default
REPLICA_ONE_DATABASE_URL = get_flask_env(
    "REPLICA_ONE_DATABASE_URL",
    PRIMARY_DATABASE_URL,
)
REPLICA_TWO_DATABASE_URL = get_flask_env(
    "REPLICA_TWO_DATABASE_URL",
    PRIMARY_DATABASE_URL,
)

SQLALCHEMY_ENGINE_OPTIONS = {
    "pool_recycle": 3600,
    "pool_pre_ping": True,
}

# Bind names
REPLICA_ONE = "replicaone"
REPLICA_TWO = "replicatwo"

engines = {
    REPLICA_ONE: create_engine(
        url=REPLICA_ONE_DATABASE_URL,
        **SQLALCHEMY_ENGINE_OPTIONS,
    ),
    REPLICA_TWO: create_engine(
        url=REPLICA_TWO_DATABASE_URL,
        **SQLALCHEMY_ENGINE_OPTIONS,
    ),
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
