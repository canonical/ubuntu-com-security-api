"""Database error handlers must return a response, and only advertise
Retry-After for failures a retry can clear.

Returning None makes Flask raise a TypeError that hides the real error. A
Retry-After on schema drift makes the retrying CVE importer loop forever.
"""

from unittest import mock

from sqlalchemy import exc

from tests import BaseTestCase


class DatabaseErrorHandler(BaseTestCase):
    def test_sqlalchemy_error_returns_503_not_none(self):
        cve_id = self.models["cve"].id
        boom = exc.OperationalError(
            "SELECT 1",
            {},
            Exception("SSL connection has been closed unexpectedly"),
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
