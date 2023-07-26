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
from tests.fixtures import payloads

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


class TestRoutes(unittest.TestCase):
    def setUp(self):
        app.testing = True

        # Set up app context
        self.context = app.app_context()
        self.context.push()

        # Clear DB
        db.drop_all()
        with redirect_stderr(io.StringIO()):
            flask_migrate.stamp(revision="base")

        # Prepare DB
        with redirect_stderr(io.StringIO()):
            flask_migrate.upgrade()

        # Import data
        self.models = make_models()
        db.session.add(self.models["cve"])
        db.session.add(self.models["notice"])
        db.session.add(self.models["release"])
        db.session.add(self.models["package"])
        db.session.add(self.models["status"])
        db.session.commit()

        self.client = app.test_client()
        return super().setUp()

    def tearDown(self):
        db.session.close()

        self.context.pop()

        return super().tearDown()

    def test_spec(self):
        response = self.client.get("/security/api/spec.json")

        assert response.status_code == 200

    def test_docs(self):
        response = self.client.get("/security/api/docs")

        assert response.status_code == 200

    def test_cves(self):
        """
        Check /security/cves.json returns a list with the expected CVE
        """

        response = self.client.get("/security/cves.json")

        assert response.status_code == 200
        assert len(response.json["cves"]) == 1
        assert response.json["cves"][0]["id"] == "CVE-1111-0001"

    def test_cve_not_exists(self):
        response = self.client.get("/security/cves/CVE-0000-0000.json")

        assert response.status_code == 404

    def test_cve(self):
        response = self.client.get(
            f"/security/cves/{self.models['cve'].id}.json"
        )

        assert response.status_code == 200
        assert (
            response.json["packages"][0]["name"]
            == list(self.models["cve"].packages)[0]
        )
        assert response.json["notices_ids"] == self.models["cve"].notices_ids

    def test_cves_query_no_500(self):
        response = self.client.get("/security/cves.json?q=firefox")

        assert response.status_code == 200

    def test_cves_returns_200_for_non_existing_package_name(self):
        response = self.client.get("/security/cves.json?package=no-exist")

        assert response.status_code == 200
        assert "No CVEs with package" not in response.json.get("errors", [])

    def test_cves_returns_200_for_non_existing_version(self):
        response = self.client.get("/security/cves.json?version=no-exist")

        assert response.status_code == 200
        assert "Cannot find a release with codename" not in response.json.get(
            "errors", []
        )

    def test_cves_returns_422_for_non_existing_package_status(self):
        response = self.client.get("/security/cves.json?status=no-exist")

        assert response.status_code == 422
        assert "Cannot find a status" in response.json["errors"]

    def test_cve_updated_at_column(self):
        """
        Tests that updated_at is created automatically when a new CVE is added
        and that it is changed on update.
        """

        # Create and add new CVE
        cve_payload = payloads.cve1.copy()

        add_cve_response = self.client.put(
            "/security/cves.json",
            json=[cve_payload],
        )

        assert add_cve_response.status_code == 200

        cve = self.client.get(f"/security/cves/{cve_payload['id']}.json").json

        # Check that value exists and is populated
        assert cve["updated_at"] is not None

        # Pass an update to the CVE
        update_cve_response = self.client.put(
            "/security/cves.json",
            json=[{"id": "CVE-9999-0001", "codename": "new_codename"}],
        )

        assert update_cve_response.status_code == 200

        updated_cve = self.client.get(
            f"/security/cves/{cve_payload['id']}.json"
        ).json

        # Check that field value is updated on update
        assert updated_cve["updated_at"]

    def test_cve_updated_at_column_unchaged_data(self):
        """
        Tests that update_at is unchaged if no changes
        were passed in the payload.
        """

        # Create and add new CVE
        cve_payload = payloads.cve1.copy()

        add_cve_response = self.client.put(
            "/security/cves.json",
            json=[cve_payload],
        )

        assert add_cve_response.status_code == 200

        cve = self.client.get(f"/security/cves/{cve_payload['id']}.json").json

        # Pass an update to the CVE
        update_cve_response = self.client.put(
            "/security/cves.json",
            json=[cve_payload],
        )

        assert update_cve_response.status_code == 200

        updated_cve = self.client.get(
            f"/security/cves/{cve_payload['id']}.json"
        ).json

        old_updated_at = cve["updated_at"]
        new_updated_at = updated_cve["updated_at"]

        # Check that field value did not change
        assert old_updated_at == new_updated_at

    def test_cve_updated_at_column_populated_value(self):
        """
        Tests that 422 is returned when trying update field directly.
        """
        # Create and add new CVE
        cve_payload = payloads.cve1.copy()

        add_cve_response = self.client.put(
            "/security/cves.json",
            json=[cve_payload],
        )

        assert add_cve_response.status_code == 200

        # Try to update updated_at field
        update_cve_response = self.client.put(
            "/security/cves.json",
            json=[{"updated_at": "2023-03-26T13:59:23.966558+00:00"}],
        )

        assert update_cve_response.status_code == 422

    def test_cve_group_by_functionality(self):
        """
        Tests that CVEs are correctly grouped by priority
        and ordered by publish date.
        """
        # Check that there is one CVE in the db with an active status
        # and a critical priority
        initial_cves = self.client.get("/security/cves.json")

        assert initial_cves.status_code == 200
        assert initial_cves.json["cves"][0]["priority"] == "critical"

        # Add CVEs of varying priority, including one without
        # a status field (cve1)
        add_cves_response = self.client.put(
            "/security/cves.json",
            json=[
                payloads.cve1,
                payloads.cve2,
                payloads.cve3,
                payloads.cve4,
                payloads.cve5,
                payloads.cve6,
            ],
        )

        assert add_cves_response.status_code == 200

        grouped_cves = self.client.get(
            "/security/cves.json?group_by=priority"
        ).json

        # Check that they are grouped by desc priority (critical -> unknown)
        assert grouped_cves["cves"][0]["priority"] == "critical"
        assert grouped_cves["cves"][1]["priority"] == "high"
        assert grouped_cves["cves"][2]["priority"] == "medium"
        assert grouped_cves["cves"][3]["priority"] == "medium"
        assert grouped_cves["cves"][4]["priority"] == "low"
        assert grouped_cves["cves"][5]["priority"] == "negligible"

        # Check that CVEs with same priority are ordered by publication date
        assert (
            grouped_cves["cves"][2]["published"]
            > grouped_cves["cves"][3]["published"]
        )

        # Check that CVE with a missing status is excluded from the payload
        for cve in grouped_cves["cves"]:
            is_present = "CVE-9999-0001" in cve.values()

        assert is_present is False

        # Check that grouped CVEs of same priority can be ordered by
        # asc publication date
        grouped_cves_asc = self.client.get(
            "/security/cves.json?group_by=priority&order=ascending"
        ).json

        assert (
            grouped_cves_asc["cves"][2]["published"]
            < grouped_cves_asc["cves"][3]["published"]
        )

    def test_cve_sort_by_functionality(self):
        """
        Tests that CVEs can be sorted by updated_at or published field
        and can be ordered by descending or ascending values.
        """

        # Add CVEs at different intervals to create separate publish dates
        add_cves_response1 = self.client.put(
            "/security/cves.json",
            json=[
                payloads.cve2,
            ],
        )

        add_cves_response2 = self.client.put(
            "/security/cves.json",
            json=[
                payloads.cve3,
            ],
        )

        add_cves_response3 = self.client.put(
            "/security/cves.json",
            json=[
                payloads.cve4,
            ],
        )

        assert add_cves_response1.status_code == 200
        assert add_cves_response2.status_code == 200
        assert add_cves_response3.status_code == 200

        # Sorting by publish date is the default and should not
        # need to be explicitly passed
        sorted_cves1_desc = self.client.get("/security/cves.json").json
        sorted_cves1_desc_with_param = self.client.get(
            "/security/cves.json?sort_by=published"
        ).json

        # Check that behavior is the same with or without param
        assert sorted_cves1_desc == sorted_cves1_desc_with_param

        # Check sorting by publish date (desc)
        assert (
            sorted_cves1_desc["cves"][0]["published"]
            > sorted_cves1_desc["cves"][1]["published"]
        )
        assert (
            sorted_cves1_desc["cves"][1]["published"]
            > sorted_cves1_desc["cves"][2]["published"]
        )

        # Check ordering by asc value
        sorted_cves1_asc = self.client.get(
            "/security/cves.json?sort_by=published&order=ascending"
        ).json

        assert (
            sorted_cves1_asc["cves"][0]["published"]
            < sorted_cves1_asc["cves"][1]["published"]
        )
        assert (
            sorted_cves1_asc["cves"][1]["published"]
            < sorted_cves1_asc["cves"][2]["published"]
        )

        # Make updates to existing CVEs to update updated_at field
        payloads.cve2["codename"] = "new_name2"
        payloads.cve3["codename"] = "new_name3"
        payloads.cve4["codename"] = "new_name4"

        update_cves_response1 = self.client.put(
            "/security/cves.json",
            json=[payloads.cve2],
        )

        update_cves_response2 = self.client.put(
            "/security/cves.json",
            json=[payloads.cve3],
        )

        update_cves_response3 = self.client.put(
            "/security/cves.json",
            json=[payloads.cve4],
        )

        assert update_cves_response1.status_code == 200
        assert update_cves_response2.status_code == 200
        assert update_cves_response3.status_code == 200

        # Check sorting by updated_at field (desc)
        sorted_cves2_desc = self.client.get(
            "/security/cves.json?sort_by=updated"
        ).json

        assert (
            sorted_cves2_desc["cves"][0]["updated_at"]
            > sorted_cves2_desc["cves"][1]["updated_at"]
        )
        assert (
            sorted_cves2_desc["cves"][1]["updated_at"]
            > sorted_cves2_desc["cves"][2]["updated_at"]
        )

        # Check ordering by asc value
        sorted_cves2_asc = self.client.get(
            "/security/cves.json?sort_by=updated&order=ascending"
        ).json

        assert (
            sorted_cves2_asc["cves"][0]["updated_at"]
            < sorted_cves2_asc["cves"][1]["updated_at"]
        )
        assert (
            sorted_cves2_asc["cves"][1]["updated_at"]
            < sorted_cves2_asc["cves"][2]["updated_at"]
        )

    def test_bulk_upsert_cves_returns_422_for_invalid_cve(self):
        cve = payloads.cve1.copy()
        cve["hello"] = "world"

        response = self.client.put("/security/cves.json", json=[cve])

        assert response.status_code == 422
        assert "Unknown field." in response.json["errors"]

    def test_bulk_upsert_cves(self):
        response_1 = self.client.get(
            f"/security/cves/{self.models['cve'].id}.json"
        )
        assert response_1.status_code == 200

        response_2 = self.client.get(
            f"/security/cves/{payloads.cve1['id']}.json"
        )
        assert response_2.status_code == 404

        response_3 = self.client.put(
            "/security/cves.json",
            json=[
                payloads.cve1,
                payloads.cve2,
            ],
        )
        assert response_3.status_code == 200

        response = self.client.get(
            f"/security/cves/{payloads.cve1['id']}.json"
        )
        assert response.status_code == 200

        response = self.client.get(
            f"/security/cves/{payloads.cve2['id']}.json"
        )
        assert response.status_code == 200

    def test_delete_non_existing_cve_returns_404(self):
        response = self.client.delete(
            f"/security/cves/{payloads.cve1['id']}.json"
        )

        assert response.status_code == 404

    def test_delete_cve(self):
        response = self.client.delete(
            f"/security/cves/{self.models['cve'].id}.json"
        )
        assert response.status_code == 200

    def test_usn_not_exists(self):
        response = self.client.get("/security/notices/USN-0000-00.json")

        assert response.status_code == 404

    def test_usn(self):
        response = self.client.get(
            f"/security/notices/{self.models['notice'].id}.json"
        )

        assert response.status_code == 200
        assert response.json["cves_ids"] == self.models["notice"].cves_ids

    def test_usns_returns_200_for_non_existing_release(self):
        response = self.client.get("/security/notices.json?release=no-exist")

        assert response.status_code == 200
        assert "Cannot find a release with codename" not in response.json.get(
            "errors", []
        )

    def test_create_usn(self):
        response = self.client.post(
            "/security/notices.json", json=payloads.notice
        )

        assert response.status_code == 200

    def test_create_ssn_usn(self):
        response = self.client.post(
            "/security/notices.json", json=payloads.ssn_notice
        )

        assert response.status_code == 200

    def test_create_usn_returns_422_for_non_unique_id(self):
        # Create USN
        response_1 = self.client.post(
            "/security/notices.json", json=payloads.notice
        )
        assert response_1.status_code == 200

        # Create again
        response_2 = self.client.post(
            "/security/notices.json", json=payloads.notice
        )
        assert response_2.status_code == 422
        assert (
            f"'{payloads.notice['id']}' already exists"
            in response_2.json["errors"]
        )

    def test_create_usn_returns_422_for_unknown_field(self):
        notice = payloads.notice.copy()
        notice["unknown"] = "field"

        response = self.client.post("/security/notices.json", json=notice)

        assert response.status_code == 422
        assert "Unknown field." in response.json["errors"]

    def test_update_usn(self):
        instructions = "Instructions were updated!"

        # Create first
        notice = payloads.notice.copy()
        response_1 = self.client.post("/security/notices.json", json=notice)
        assert response_1.status_code == 200

        # Update
        notice["instructions"] = instructions
        response_2 = self.client.put(
            f"/security/notices/{notice['id']}.json", json=notice
        )
        assert response_2.status_code == 200

        # Get
        response_3 = self.client.get(f"/security/notices/{notice['id']}.json")
        assert response_3.json["instructions"] == instructions

    def test_update_usn_returns_404_for_non_existing_id(self):
        response = self.client.put(
            f"/security/notices/{payloads.notice['id']}.json",
            json=payloads.notice,
        )

        assert response.status_code == 404

    def test_update_usn_returns_422_for_unknown_field(self):
        notice = payloads.notice.copy()
        notice["unknown"] = "field"

        response = self.client.put(
            f"/security/notices/{notice['id']}.json", json=notice
        )

        assert response.status_code == 422
        assert "Unknown field." in response.json["errors"]

    def test_delete_usn_returns_404_for_non_existing_usn(self):
        response = self.client.delete(
            f"/security/notices/{payloads.notice['id']}.json"
        )

        assert response.status_code == 404

    def test_delete_usn(self):
        # Create USN first
        response = self.client.post(
            "/security/notices.json", json=payloads.notice
        )
        assert response.status_code == 200

        # Now delete it
        response = self.client.delete(
            f"/security/notices/{payloads.notice['id']}.json"
        )
        assert response.status_code == 200

    def test_create_release(self):
        response = self.client.post(
            "/security/releases.json", json=payloads.release
        )

        assert response.status_code == 200

    def test_create_existing_release_returns_422(self):
        # Create release
        response_1 = self.client.post(
            "/security/releases.json", json=payloads.release
        )
        assert response_1.status_code == 200

        # Create release again
        response_2 = self.client.post(
            "/security/releases.json", json=payloads.release
        )
        assert response_2.status_code == 422
        assert (
            f"Release with codename '{payloads.release['codename']}'"
            " already exists"
        ) in response_2.json["errors"]

    def test_delete_non_existing_release_returns_404(self):
        response = self.client.delete("/security/releases/no-exist.json")

        assert response.status_code == 404

    def test_delete_release(self):
        # Create release first
        response_1 = self.client.post(
            "/security/releases.json", json=payloads.release
        )
        assert response_1.status_code == 200

        # Delete release
        response = self.client.delete(
            f"/security/releases/{payloads.release['codename']}.json"
        )
        assert response.status_code == 200


if __name__ == "__main__":
    unittest.main()
