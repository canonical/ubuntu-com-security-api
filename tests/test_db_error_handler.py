"""The SQLAlchemy error handlers must return a response, not None.

Returning None makes Flask raise a TypeError blaming the view, which hides
the database error. The read engines carry a statement_timeout, so Postgres
cancelling a slow query reaches this path under load, not just in edge cases.

The handlers must also separate transient failures from permanent ones. A 503
with Retry-After is right for a lost connection and wrong for schema drift:
the CVE importer retries, so a failure that cannot clear becomes a loop.
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

        with mock.patch("webapp.views.db.session.query", side_effect=boom):
            response = self.client.get(f"/security/cves/{cve_id}.json")

        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.headers.get("Retry-After"), "5")
        self.assertIn(
            "temporarily unavailable", response.get_json()["message"]
        )

    def test_pending_rollback_error_returns_503_not_none(self):
        cve_id = self.models["cve"].id
        boom = exc.PendingRollbackError("rollback required", None, None)

        with mock.patch("webapp.views.db.session.query", side_effect=boom):
            response = self.client.get(f"/security/cves/{cve_id}.json")

        self.assertEqual(response.status_code, 503)

    def test_programming_error_is_not_advertised_as_retryable(self):
        """Schema drift is permanent: 500, and no Retry-After."""
        cve_id = self.models["cve"].id
        boom = exc.ProgrammingError(
            "SELECT 1", {}, Exception('column "nope" does not exist')
        )

        with mock.patch("webapp.views.db.session.query", side_effect=boom):
            response = self.client.get(f"/security/cves/{cve_id}.json")

        self.assertEqual(response.status_code, 500)
        self.assertIsNone(response.headers.get("Retry-After"))

    def test_integrity_error_is_not_advertised_as_retryable(self):
        """A constraint violation will not clear on retry either."""
        cve_id = self.models["cve"].id
        boom = exc.IntegrityError(
            "INSERT", {}, Exception("violates foreign key constraint")
        )

        with mock.patch("webapp.views.db.session.query", side_effect=boom):
            response = self.client.get(f"/security/cves/{cve_id}.json")

        self.assertEqual(response.status_code, 500)
        self.assertIsNone(response.headers.get("Retry-After"))

    def test_normal_requests_are_unaffected(self):
        cve_id = self.models["cve"].id
        response = self.client.get(f"/security/cves/{cve_id}.json")
        self.assertEqual(response.status_code, 200)
