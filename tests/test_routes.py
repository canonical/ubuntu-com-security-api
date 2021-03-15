import pathlib
import unittest

from alchemy_mock.mocking import UnifiedAlchemyMagicMock
from flask import json

from tests.auth_mock import mock_auth_decorator
from tests.alchemy_mock_data import data
from tests.database_mock import (
    mocked_inspector,
    mocked_release_codenames,
    mocked_status_statuses,
)
from webapp import auth, database

auth.authorization_required = mock_auth_decorator()
database.db_session = UnifiedAlchemyMagicMock(data=data)
database.inspector = mocked_inspector
database.release_codenames = mocked_release_codenames
database.status_statuses = mocked_status_statuses

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
        response = self.client.get("/security/cves/CVE-0000-0000.json")

        assert response.status_code == 404

    def test_cve(self):
        response = self.client.get("/security/cves/CVE-0000-0001.json")
        expected_cve = get_fixture("CVE-0000-0001")

        assert response.status_code == 200
        assert response.json["packages"] == expected_cve["packages"]
        assert response.json["notices_ids"] == expected_cve["notices_ids"]

    def test_cves_returns_422_for_non_existing_package_name(self):
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
        response = self.client.get("/security/notices/USN-0000-00.json")

        assert response.status_code == 404

    def test_usn(self):
        response = self.client.get("/security/notices/USN-0000-01.json")
        expected_notice = get_fixture("USN-0000-01")

        assert response.status_code == 200
        assert response.json["cves_ids"] == expected_notice["cves_ids"]

    def test_usns_returns_422_for_non_existing_release(self):
        response = self.client.get("/security/notices.json?release=no-exist")

        assert response.status_code == 422
        assert "Cannot find a release with codename" in response.json["errors"]

    def test_create_usn(self):
        notice = get_fixture("USN-0000-02")
        response = self.client.post("/security/notices.json", json=notice)

        assert response.status_code == 200

    def test_create_usn_returns_422_for_non_unique_id(self):
        notice = get_fixture("USN-0000-01")
        response = self.client.post("/security/notices.json", json=notice)

        assert response.status_code == 422
        assert "'USN-0000-01' already exists" in response.json["errors"]

    def test_create_usn_returns_422_for_unknown_field(self):
        notice = get_fixture("USN-0000-02")
        notice["unknown"] = "field"

        response = self.client.post("/security/notices.json", json=notice)

        assert response.status_code == 422
        assert "Unknown field." in response.json["errors"]

    def test_update_usn(self):
        notice = get_fixture("USN-0000-03")
        notice["instructions"] = "Instructions were updated!"

        response = self.client.put(
            "/security/notices/USN-0000-03.json", json=notice
        )

        assert response.status_code == 200

    def test_update_usn_returns_404_for_non_existing_id(self):
        notice = get_fixture("USN-0000-03")

        response = self.client.put(
            "/security/notices/USN-0000-02.json", json=notice
        )

        assert response.status_code == 404

    def test_update_usn_returns_422_for_unknown_field(self):
        notice = get_fixture("USN-0000-03")
        notice["unknown"] = "field"

        response = self.client.put(
            "/security/notices/USN-0000-03.json", json=notice
        )

        assert response.status_code == 422
        assert "Unknown field." in response.json["errors"]

    def test_delete_usn_returns_404_for_non_existing_usn(self):
        response = self.client.delete("/security/notices/USN-0000-02.json")

        assert response.status_code == 404

    def test_delete_usn(self):
        response = self.client.delete("/security/notices/USN-0000-04.json")

        assert response.status_code == 200

    def test_bulk_upsert_cves_returns_422_for_invalid_cve(self):
        cve = get_fixture("CVE-9999-0000")
        cve["hello"] = "world"
        response = self.client.put("/security/cves.json", json=[cve])

        assert response.status_code == 422
        assert "Unknown field." in response.json["errors"]

    def test_bulk_upsert_cves(self):
        response = self.client.get("/security/cves/CVE-9999-0000.json")
        assert response.status_code == 200

        response = self.client.get("/security/cves/CVE-9999-0001.json")
        assert response.status_code == 200

        response = self.client.get("/security/cves/CVE-9999-0002.json")
        assert response.status_code == 404

        response = self.client.put(
            "/security/cves.json",
            json=[
                get_fixture("CVE-9999-0000"),
                get_fixture("CVE-9999-0001"),
                get_fixture("CVE-9999-0002"),
            ],
        )
        assert response.status_code == 200

    def test_delete_non_existing_cve_returns_404(self):
        response = self.client.delete("/security/cves/CVE-9999-0002.json")

        assert response.status_code == 404

    def test_delete_cve(self):
        response = self.client.delete("/security/cves/CVE-9999-0000.json")
        assert response.status_code == 200

        response = self.client.delete("/security/cves/CVE-9999-0001.json")
        assert response.status_code == 200

    def test_create_release(self):
        release = get_fixture("new-release")
        response = self.client.post("/security/releases.json", json=release)

        assert response.status_code == 200

    def test_create_existing_release_returns_422(self):
        release = get_fixture("hirsute")
        response = self.client.post("/security/releases.json", json=release)

        assert response.status_code == 422
        assert (
            "Release with codename 'hirsute' already exists"
            in response.json["errors"]
        )
        assert (
            "Release with version '21.04' already exists"
            in response.json["errors"]
        )
        assert (
            "Release with name 'Hirsute Hippo' already exists"
            in response.json["errors"]
        )

    def test_delete_non_existing_release_returns_404(self):
        response = self.client.delete("/security/releases/no-exist.json")

        assert response.status_code == 404

    def test_delete_release(self):
        response = self.client.delete("/security/releases/hirsute.json")

        assert response.status_code == 200


def get_fixture(file):
    current_path = pathlib.Path(__file__).parent.absolute()
    with open(f"{current_path}/./fixtures/{file}.json") as json_data:
        file_data = json_data.read()
        json_data.close()

    return json.loads(file_data)


if __name__ == "__main__":
    unittest.main()
