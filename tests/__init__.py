# Standard library
from contextlib import redirect_stderr
import io
import os
import unittest
import warnings

# Packages
from sqlalchemy_utils import database_exists, create_database
import flask_migrate


# Local
from tests.fixtures.models import make_models

"""
Monkey-patching before importing the main application
===

Get the database connection string from the TEST_DATABASE_URL environment
variable. This variabel is required, as it's important not to accidentally
wipe out a real database.

Replace the authorization_required view decorator with a transparent function
to disable authorization checks for testing privileged views.
This is not ideal, as it means we're not testing the actual authorization
functionality, but I don't know of a good way to do that right now.
"""

from webapp import auth
from tests.helpers import transparent_decorator

auth.authorization_required = transparent_decorator
os.environ["DATABASE_URL"] = os.environ["TEST_DATABASE_URL"]

from webapp.app import app, db  # noqa: E402


# Create database if it doesn't exist
with app.app_context():
    if not database_exists(db.engine.url):
        create_database(db.engine.url)


# Suppress annoying ResourceWarnings
warnings.filterwarnings(action="ignore", category=ResourceWarning)


class BaseTestCase(unittest.TestCase):
    db = db

    def setUp(self):
        app.testing = True

        # Set up app context
        self.context = app.app_context()
        self.context.push()

        # Clear DB
        self.db.drop_all()
        with redirect_stderr(io.StringIO()):
            flask_migrate.stamp(revision="base")

        # Prepare DB
        with redirect_stderr(io.StringIO()):
            flask_migrate.upgrade()

        # Import data
        self.models = make_models()
        self.db.session.add(self.models["cve"])
        self.db.session.add(self.models["notice"])
        self.db.session.add(self.models["release"])
        self.db.session.add(self.models["package"])
        self.db.session.add(self.models["status"])
        self.db.session.commit()

        self.client = app.test_client()
        return super().setUp()

    def tearDown(self):
        self.db.session.close()

        self.context.pop()

        return super().tearDown()
