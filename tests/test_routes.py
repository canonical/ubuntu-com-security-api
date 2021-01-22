import unittest

from alchemy_mock.mocking import UnifiedAlchemyMagicMock

from tests.auth_mock import mock_auth_decorator
from tests.db_mock import data
from tests.inspector_mock import mocked_inspector
from webapp import auth, database

auth.authorization_required = mock_auth_decorator()
database.inspector = mocked_inspector
database.db_session = UnifiedAlchemyMagicMock(data=data)

from webapp.app import app  # noqa


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

    def test_cve_not_exists(self):
        response = self.client.get("/security/cves/CVE-TEST.json")

        assert response.status_code == 404

    def test_cve(self):
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

    def test_cves_returns_422_for_wrong_package_name(self):
        response = self.client.get("/security/cves.json?package=no-exist")

        assert response.status_code == 422
        assert "No CVEs with package" in response.json["errors"]

    def test_cves_returns_422_for_non_existing_version(self):
        response = self.client.get("/security/cves.json?version=no-exist")

        assert response.status_code == 422
        assert "Cannot find a release with codename" in response.json["errors"]

    def test_cves_returns_422_for_non_existing_status(self):
        response = self.client.get("/security/cves.json?status=no-exist")

        assert response.status_code == 422
        assert "Cannot find a status" in response.json["errors"]

    def test_usn_not_exists(self):
        response = self.client.get("/security/notices/USN-TEST.json")

        assert response.status_code == 404

    def test_usn(self):
        response = self.client.get("/security/notices/USN-TEST-1.json")

        assert response.status_code == 200

        expected_cves = ["CVE-TEST-1", "CVE-TEST-2"]

        assert response.json["cves"] == expected_cves

    def test_usns_returns_422_for_non_existing_release(self):
        response = self.client.get("/security/notices.json?release=no-exist")

        assert response.status_code == 422
        assert "Cannot find a release with codename" in response.json["errors"]


if __name__ == "__main__":
    unittest.main()
