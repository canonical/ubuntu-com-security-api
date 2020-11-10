import unittest
from unittest.mock import patch

from webapp.app import app
from webapp.models import CVE, Notice


class TestRoutes(unittest.TestCase):
    def setUp(self):
        app.testing = True

        self.client = app.test_client()
        return super().setUp()

    def test_spec(self):
        response = self.client.get("/spec")

        assert response.status_code == 200

    def test_docs(self):
        response = self.client.get("/docs")

        assert response.status_code == 200

    @patch("webapp.views.db_session")
    def test_cve_not_exists(self, db_session):
        mocked_query = db_session.query.return_value
        mocked_filter = mocked_query.filter.return_value
        mocked_filter.one_or_none.return_value = None

        response = self.client.get("/cves/CVE-TEST")

        assert response.status_code == 404

    @patch("webapp.views.db_session")
    def test_cve(self, db_session):
        mocked_query = db_session.query.return_value
        mocked_filter = mocked_query.filter.return_value
        mocked_filter.one_or_none.return_value = CVE(id="CVE-TEST-1")

        response = self.client.get("/cves/CVE-TEST-1")

        assert response.status_code == 200

    @patch("webapp.views.db_session")
    def test_usn_not_exists(self, db_session):
        mocked_query = db_session.query.return_value
        mocked_filter = mocked_query.filter.return_value
        mocked_filter.one_or_none.return_value = None

        response = self.client.get("/usn/USN-TEST")

        assert response.status_code == 404

    @patch("webapp.views.db_session")
    def test_usn(self, db_session):
        mocked_query = db_session.query.return_value
        mocked_filter = mocked_query.filter.return_value
        mocked_filter.one_or_none.return_value = Notice(id="USN-TEST-1")

        response = self.client.get("/notices/USN-TEST-1")

        assert response.status_code == 200


if __name__ == "__main__":
    unittest.main()
