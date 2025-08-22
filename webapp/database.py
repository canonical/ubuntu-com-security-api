"""
Why keep the database object here?
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
from flask_sqlalchemy import SQLAlchemy  # noqa: E402
from sqlalchemy import exc

db = SQLAlchemy(session_options={"autoflush": False}, engine_options={"pool_pre_ping": True})


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
