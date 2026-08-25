"""The SQLAlchemy error handlers must return a response, not None.

Returning None makes Flask raise:

    TypeError: The view function for '<view>' did not return a valid
    response. The function either returned None or ended without a return
    statement.

which blames the view and hides the database error that actually happened.
This matters routinely now that the read engines carry a statement_timeout -
Postgres cancelling a slow query raises OperationalError, which is a
SQLAlchemyError, so this path is reached under load rather than only in
exceptional cases.
"""

from unittest import mock

from sqlalchemy import exc

from tests import BaseTestCase


class DatabaseErrorHandler(BaseTestCase):
    def test_sqlalchemy_error_returns_503_not_none(self):
        cve_id = self.models["cve"].id
        boom = exc.OperationalError(
            "SELECT 1", {}, Exception("canceling statement due to timeout")
        )

        with mock.patch(
            "webapp.views.db.session.query", side_effect=boom
        ):
            response = self.client.get(f"/security/cves/{cve_id}.json")

        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.headers.get("Retry-After"), "5")
        self.assertIn(
            "temporarily unavailable", response.get_json()["message"]
        )

    def test_pending_rollback_error_returns_503_not_none(self):
        cve_id = self.models["cve"].id
        boom = exc.PendingRollbackError("rollback required", None, None)

        with mock.patch(
            "webapp.views.db.session.query", side_effect=boom
        ):
            response = self.client.get(f"/security/cves/{cve_id}.json")

        self.assertEqual(response.status_code, 503)

    def test_normal_requests_are_unaffected(self):
        cve_id = self.models["cve"].id
        response = self.client.get(f"/security/cves/{cve_id}.json")
        self.assertEqual(response.status_code, 200)
