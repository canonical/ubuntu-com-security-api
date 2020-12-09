import unittest
from unittest.mock import patch

from webapp.app import app
from webapp.models import CVE, Notice, Status


class TestRoutes(unittest.TestCase):
    def setUp(self):
        app.testing = True

        self.client = app.test_client()
        return super().setUp()

    def test_spec(self):
        response = self.client.get("/security/api/spec.json")

        assert response.status_code == 200

    def test_docs(self):
        response = self.client.get("/security/api/docs")

        assert response.status_code == 200

    @patch("webapp.views.db_session")
    def test_cve_not_exists(self, db_session):
        mocked_query = db_session.query.return_value
        mocked_filter = mocked_query.filter.return_value
        mocked_filter.one_or_none.return_value = None

        response = self.client.get("/security/cves/CVE-TEST.json")

        assert response.status_code == 404

    @patch("webapp.views.db_session")
    def test_cve(self, db_session):
        cve = CVE(
            id="CVE-TEST-1",
            notices=[Notice(id="USN-TEST-1"), Notice(id="USN-TEST-2")],
            statuses=[
                Status(
                    cve_id="CVE-TEST-1",
                    release_codename="focal",
                    package_name="test_package",
                    status="ignored",
                ),
                Status(
                    cve_id="CVE-TEST-1",
                    release_codename="bionic",
                    package_name="test_package",
                    status="released",
                ),
            ],
        )

        mocked_query = db_session.query.return_value
        mocked_filter = mocked_query.filter.return_value
        mocked_filter.one_or_none.return_value = cve

        response = self.client.get("/security/cves/CVE-TEST-1.json")

        assert response.status_code == 200

        expected_cve_packages = [
            {
                "debian": "https://tracker.debian.org/pkg/test_package",
                "name": "test_package",
                "source": (
                    "https://ubuntu.com/security/cve?" "package=test_package"
                ),
                "statuses": [
                    {
                        "component": None,
                        "description": None,
                        "pocket": None,
                        "release_codename": "focal",
                        "status": "ignored",
                    },
                    {
                        "component": None,
                        "description": None,
                        "pocket": None,
                        "release_codename": "bionic",
                        "status": "released",
                    },
                ],
                "ubuntu": (
                    "https://packages.ubuntu.com/search?"
                    "suite=all&section=all&arch=any&"
                    "searchon=sourcenames&keywords=test_package"
                ),
            }
        ]
        assert response.json["packages"] == expected_cve_packages

        expected_cve_notices = ["USN-TEST-1", "USN-TEST-2"]

        assert response.json["notices"] == expected_cve_notices

    @patch("webapp.views.db_session")
    def test_usn_not_exists(self, db_session):
        mocked_query = db_session.query.return_value
        mocked_filter = mocked_query.filter.return_value
        mocked_filter.one_or_none.return_value = None

        response = self.client.get("/security/notices/USN-TEST.json")

        assert response.status_code == 404

    @patch("webapp.views.db_session")
    def test_usn(self, db_session):
        notice = Notice(
            id="USN-TEST-1",
            cves=[CVE(id="CVE-TEST-1"), CVE(id="CVE-TEST-2")],
        )

        mocked_query = db_session.query.return_value
        mocked_filter = mocked_query.filter.return_value
        mocked_filter.one_or_none.return_value = notice

        response = self.client.get("/security/notices/USN-TEST-1.json")

        assert response.status_code == 200

        expected_cves = ["CVE-TEST-1", "CVE-TEST-2"]

        assert response.json["cves"] == expected_cves


if __name__ == "__main__":
    unittest.main()
