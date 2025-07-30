import unittest
from tests import BaseTestCase
from tests.fixtures import payloads
from tests.fixtures.models import make_cve, make_notice, make_release
from collections import defaultdict
from datetime import datetime


class TestRoutes(BaseTestCase):
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

    def test_cves_filtered_by_existing_version(self):
        # Add releases because the DB only
        # includes 1 release upon initialization
        add_release_response = self.client.post(
            "/security/updates/releases.json", json=payloads.release
        )
        add_release2_response = self.client.post(
            "/security/updates/releases.json", json=payloads.release2
        )
        add_release3_response = self.client.post(
            "/security/updates/releases.json", json=payloads.release3
        )

        assert add_release_response.status_code == 200
        assert add_release2_response.status_code == 200
        assert add_release3_response.status_code == 200

        # Add cves with different statuses because the
        # DB only includes 1 cve upon initialization
        add_cves_response = self.client.put(
            "/security/updates/cves.json",
            json=[
                payloads.cve2,
                payloads.cve3,
                payloads.cve4,
                payloads.cve5,
                payloads.cve6,
                payloads.cve7,
                payloads.cve8,
            ],
        )
        assert add_cves_response.status_code == 200

        filtered_cves_response = self.client.get(
            "/security/cves.json?version=testrelease"
        )

        assert filtered_cves_response.status_code == 200
        assert filtered_cves_response.json["total_results"] == 5

    def text_cves_filtered_by_existing_status(self):
        # Add cves with different statuses because the
        # DB only includes 1 cve upon initialization
        add_cves_response = self.client.put(
            "/security/updates/cves.json",
            json=[
                payloads.cve2,
                payloads.cve3,
                payloads.cve4,
                payloads.cve5,
                payloads.cve6,
                payloads.cve7,
                payloads.cve8,
            ],
        )
        assert add_cves_response.status_code == 200

        filtered_cves_response = self.client.get(
            "/security/cves.json?status=released"
        )

        assert filtered_cves_response.status_code == 200
        assert filtered_cves_response.json["total_results"] == 6

    def test_cves_filtered_by_multiple_statuses(self):
        # Add releases because the DB only includes
        # 1 release upon initialization
        add_release_response = self.client.post(
            "/security/updates/releases.json", json=payloads.release
        )
        add_release2_response = self.client.post(
            "/security/updates/releases.json", json=payloads.release2
        )
        add_release3_response = self.client.post(
            "/security/updates/releases.json", json=payloads.release3
        )

        assert add_release_response.status_code == 200
        assert add_release2_response.status_code == 200
        assert add_release3_response.status_code == 200

        # Add cves with different statuses because the
        # DB only includes 1 cve upon initialization
        add_cves_response = self.client.put(
            "/security/updates/cves.json",
            json=[
                payloads.cve2,
                payloads.cve3,
                payloads.cve4,
                payloads.cve5,
                payloads.cve6,
                payloads.cve7,
                payloads.cve8,
            ],
        )

        assert add_cves_response.status_code == 200

        filtered_cves_response = self.client.get(
            "/security/cves.json?status=needed&status=needs-triage"
        )

        assert filtered_cves_response.status_code == 200
        assert filtered_cves_response.json["total_results"] == 2

    def test_cves_filtered_by_multiple_versions(self):
        # Add releases because the DB only includes
        # 1 release upon initialization
        add_release_response = self.client.post(
            "/security/updates/releases.json", json=payloads.release
        )
        add_release2_response = self.client.post(
            "/security/updates/releases.json", json=payloads.release2
        )
        add_release3_response = self.client.post(
            "/security/updates/releases.json", json=payloads.release3
        )

        assert add_release_response.status_code == 200
        assert add_release2_response.status_code == 200
        assert add_release3_response.status_code == 200

        # Add cves with different statuses because the
        # DB only includes 1 cve upon initialization
        add_cves_response = self.client.put(
            "/security/updates/cves.json",
            json=[
                payloads.cve2,
                payloads.cve3,
                payloads.cve4,
                payloads.cve5,
                payloads.cve6,
                payloads.cve7,
                payloads.cve8,
            ],
        )

        assert add_cves_response.status_code == 200

        filtered_cves_response = self.client.get(
            "/security/cves.json?version=testrelease3&version=testrelease2"
        )

        assert filtered_cves_response.status_code == 200
        assert filtered_cves_response.json["total_results"] == 3

    def test_cves_filtered_by_multiple_priorities(self):
        # Add releases because the DB only includes
        # 1 release upon initialization
        add_release_response = self.client.post(
            "/security/updates/releases.json", json=payloads.release
        )
        add_release2_response = self.client.post(
            "/security/updates/releases.json", json=payloads.release2
        )
        add_release3_response = self.client.post(
            "/security/updates/releases.json", json=payloads.release3
        )

        assert add_release_response.status_code == 200
        assert add_release2_response.status_code == 200
        assert add_release3_response.status_code == 200

        # Add cves with different statuses because the
        # DB only includes 1 cve upon initialization
        add_cves_response = self.client.put(
            "/security/updates/cves.json",
            json=[
                payloads.cve2,
                payloads.cve3,
                payloads.cve4,
                payloads.cve5,
                payloads.cve6,
                payloads.cve7,
                payloads.cve8,
            ],
        )

        assert add_cves_response.status_code == 200
        filtered_cves_response = self.client.get(
            "/security/cves.json?priority=high&priority=medium"
        )

        assert filtered_cves_response.status_code == 200
        assert filtered_cves_response.json["total_results"] == 3

    def test_cves_filtered_by_status_and_version(self):
        # Add releases because the DB only includes
        # 1 release upon initialization
        add_release_response = self.client.post(
            "/security/updates/releases.json", json=payloads.release
        )
        add_release2_response = self.client.post(
            "/security/updates/releases.json", json=payloads.release2
        )
        add_release3_response = self.client.post(
            "/security/updates/releases.json", json=payloads.release3
        )

        assert add_release_response.status_code == 200
        assert add_release2_response.status_code == 200
        assert add_release3_response.status_code == 200

        # Add cves with different statuses because the
        # DB only includes 1 cve upon initialization
        add_cves_response = self.client.put(
            "/security/updates/cves.json",
            json=[
                payloads.cve2,
                payloads.cve3,
                payloads.cve4,
                payloads.cve5,
                payloads.cve6,
                payloads.cve7,
                payloads.cve8,
            ],
        )

        assert add_cves_response.status_code == 200

        filtered_cves_response = self.client.get(
            "/security/cves.json?status=needs-triage&version=testrelease2"
        )

        assert filtered_cves_response.status_code == 200
        assert filtered_cves_response.json["total_results"] == 1

    def test_cves_filtered_by_version_and_priority(self):
        # Add releases because the DB only includes
        # 1 release upon initialization
        add_release_response = self.client.post(
            "/security/updates/releases.json", json=payloads.release
        )
        add_release2_response = self.client.post(
            "/security/updates/releases.json", json=payloads.release2
        )
        add_release3_response = self.client.post(
            "/security/updates/releases.json", json=payloads.release3
        )

        assert add_release_response.status_code == 200
        assert add_release2_response.status_code == 200
        assert add_release3_response.status_code == 200

        # Add cves with different statuses because the
        # DB only includes 1 cve upon initialization
        add_cves_response = self.client.put(
            "/security/updates/cves.json",
            json=[
                payloads.cve2,
                payloads.cve3,
                payloads.cve4,
                payloads.cve5,
                payloads.cve6,
                payloads.cve7,
                payloads.cve8,
            ],
        )

        assert add_cves_response.status_code == 200

        filtered_cves_response = self.client.get(
            "/security/cves.json?version=testrelease&priority=medium"
        )

        assert filtered_cves_response.status_code == 200
        assert filtered_cves_response.json["total_results"] == 2

    def test_cves_filtered_by_priority_and_status(self):
        # Add releases because the DB only includes
        # 1 release upon initialization
        add_release_response = self.client.post(
            "/security/updates/releases.json", json=payloads.release
        )
        add_release2_response = self.client.post(
            "/security/updates/releases.json", json=payloads.release2
        )
        add_release3_response = self.client.post(
            "/security/updates/releases.json", json=payloads.release3
        )

        assert add_release_response.status_code == 200
        assert add_release2_response.status_code == 200
        assert add_release3_response.status_code == 200

        # Add cves with different statuses because the
        # DB only includes 1 cve upon initialization
        add_cves_response = self.client.put(
            "/security/updates/cves.json",
            json=[
                payloads.cve2,
                payloads.cve3,
                payloads.cve4,
                payloads.cve5,
                payloads.cve6,
                payloads.cve7,
                payloads.cve8,
            ],
        )

        assert add_cves_response.status_code == 200

        filtered_cves_response = self.client.get(
            "/security/cves.json?status=released&priority=negligible"
        )

        assert filtered_cves_response.status_code == 200
        assert filtered_cves_response.json["total_results"] == 1

    def test_cves_filtered_by_version_and_package(self):
        # Add releases because the DB only includes
        # 1 release upon initialization
        add_release_response = self.client.post(
            "/security/updates/releases.json", json=payloads.release
        )
        add_release2_response = self.client.post(
            "/security/updates/releases.json", json=payloads.release2
        )
        add_release3_response = self.client.post(
            "/security/updates/releases.json", json=payloads.release3
        )

        assert add_release_response.status_code == 200
        assert add_release2_response.status_code == 200
        assert add_release3_response.status_code == 200

        # Add cves with different statuses because the
        # DB only includes 1 cve upon initialization
        add_cves_response = self.client.put(
            "/security/updates/cves.json",
            json=[
                payloads.cve2,
                payloads.cve3,
                payloads.cve4,
                payloads.cve5,
                payloads.cve6,
                payloads.cve7,
                payloads.cve8,
            ],
        )

        assert add_cves_response.status_code == 200

        filtered_cves_response = self.client.get(
            "/security/cves.json?package=sql&version=testrelease"
        )

        assert filtered_cves_response.status_code == 200
        assert filtered_cves_response.json["total_results"] == 2

    def test_cves_filtered_by_package_and_status(self):
        # Add releases because the DB only includes
        # 1 release upon initialization
        add_release_response = self.client.post(
            "/security/updates/releases.json", json=payloads.release
        )
        add_release2_response = self.client.post(
            "/security/updates/releases.json", json=payloads.release2
        )
        add_release3_response = self.client.post(
            "/security/updates/releases.json", json=payloads.release3
        )

        assert add_release_response.status_code == 200
        assert add_release2_response.status_code == 200
        assert add_release3_response.status_code == 200

        # Add cves with different statuses because the
        # DB only includes 1 cve upon initialization
        add_cves_response = self.client.put(
            "/security/updates/cves.json",
            json=[
                payloads.cve2,
                payloads.cve3,
                payloads.cve4,
                payloads.cve5,
                payloads.cve6,
                payloads.cve7,
                payloads.cve8,
            ],
        )

        assert add_cves_response.status_code == 200

        filtered_cves_response = self.client.get(
            "/security/cves.json?package=mysql&status=released"
        )

        assert filtered_cves_response.status_code == 200
        assert filtered_cves_response.json["total_results"] == 1

    def test_cves_filtered_by_multiple_statuses_and_versions(self):
        # Add releases because the DB only includes
        # 1 release upon initialization
        add_release_response = self.client.post(
            "/security/updates/releases.json", json=payloads.release
        )
        add_release2_response = self.client.post(
            "/security/updates/releases.json", json=payloads.release2
        )
        add_release3_response = self.client.post(
            "/security/updates/releases.json", json=payloads.release3
        )

        assert add_release_response.status_code == 200
        assert add_release2_response.status_code == 200
        assert add_release3_response.status_code == 200

        # Add cves with different statuses because the
        # DB only includes 1 cve upon initialization
        add_cves_response = self.client.put(
            "/security/updates/cves.json",
            json=[
                payloads.cve2,
                payloads.cve3,
                payloads.cve4,
                payloads.cve5,
                payloads.cve6,
                payloads.cve7,
                payloads.cve8,
            ],
        )

        assert add_cves_response.status_code == 200

        # Formated so as to comply with line length
        base_url = "/security/cves.json?"
        params = "status=needs-triage&version=testrelease2&status=released"
        filtered_cves_response = self.client.get(f"{base_url}{params}")

        assert filtered_cves_response.status_code == 200
        assert filtered_cves_response.json["total_results"] == 2

    def test_cves_filtered_by_status_version_and_package(self):
        # Add releases because the DB only includes
        # 1 release upon initialization
        add_release_response = self.client.post(
            "/security/updates/releases.json", json=payloads.release
        )
        add_release2_response = self.client.post(
            "/security/updates/releases.json", json=payloads.release2
        )
        add_release3_response = self.client.post(
            "/security/updates/releases.json", json=payloads.release3
        )

        assert add_release_response.status_code == 200
        assert add_release2_response.status_code == 200
        assert add_release3_response.status_code == 200

        # Add cves with different statuses because the
        # DB only includes 1 cve upon initialization
        add_cves_response = self.client.put(
            "/security/updates/cves.json",
            json=[
                payloads.cve2,
                payloads.cve3,
                payloads.cve4,
                payloads.cve5,
                payloads.cve6,
                payloads.cve7,
                payloads.cve8,
            ],
        )

        assert add_cves_response.status_code == 200

        base_url = "/security/cves.json?"
        params = "status=released&package=test_package_3&version=testrelease"
        filtered_cves_response = self.client.get(f"{base_url}{params}")

        assert filtered_cves_response.status_code == 200
        assert filtered_cves_response.json["total_results"] == 1

    def test_cves_filtered_by_empty_status(self):
        # Add releases because the DB only includes
        # 1 release upon initialization
        add_release_response = self.client.post(
            "/security/updates/releases.json", json=payloads.release
        )
        add_release2_response = self.client.post(
            "/security/updates/releases.json", json=payloads.release2
        )
        add_release3_response = self.client.post(
            "/security/updates/releases.json", json=payloads.release3
        )

        assert add_release_response.status_code == 200
        assert add_release2_response.status_code == 200
        assert add_release3_response.status_code == 200

        # Add cves with different statuses because the
        # DB only includes 1 cve upon initialization
        add_cves_response = self.client.put(
            "/security/updates/cves.json",
            json=[
                payloads.cve2,
                payloads.cve3,
                payloads.cve4,
                payloads.cve5,
                payloads.cve6,
                payloads.cve7,
                payloads.cve8,
            ],
        )

        assert add_cves_response.status_code == 200

        filtered_cves_response_1 = self.client.get(
            "/security/cves.json?package=mysql&version=testrelease&status="
        )

        filtered_cves_response_2 = self.client.get(
            "/security/cves.json?version=testrelease&status=&status="
        )

        assert filtered_cves_response_1.status_code == 200
        assert filtered_cves_response_1.json["total_results"] == 1

        assert filtered_cves_response_2.status_code == 200
        assert filtered_cves_response_2.json["total_results"] == 5

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
            "/security/updates/cves.json",
            json=[cve_payload],
        )

        assert add_cve_response.status_code == 200

        cve = self.client.get(f"/security/cves/{cve_payload['id']}.json").json

        # Check that value exists and is populated
        assert cve["updated_at"] is not None

        # Pass an update to the CVE
        update_cve_response = self.client.put(
            "/security/updates/cves.json",
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
            "/security/updates/cves.json",
            json=[cve_payload],
        )

        assert add_cve_response.status_code == 200

        cve = self.client.get(f"/security/cves/{cve_payload['id']}.json").json

        # Pass an update to the CVE
        update_cve_response = self.client.put(
            "/security/updates/cves.json",
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
            "/security/updates/cves.json",
            json=[cve_payload],
        )

        assert add_cve_response.status_code == 200

        # Try to update updated_at field
        update_cve_response = self.client.put(
            "/security/updates/cves.json",
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

        # Add releases because the DB only includes
        # 1 release upon initialization
        add_release_response = self.client.post(
            "/security/updates/releases.json", json=payloads.release
        )
        add_release2_response = self.client.post(
            "/security/updates/releases.json", json=payloads.release2
        )
        add_release3_response = self.client.post(
            "/security/updates/releases.json", json=payloads.release3
        )

        assert add_release_response.status_code == 200
        assert add_release2_response.status_code == 200
        assert add_release3_response.status_code == 200

        # Add CVEs of varying priority, including one without
        # a status field (cve1)
        add_cves_response = self.client.put(
            "/security/updates/cves.json",
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

        PRIORITY_ORDER = {
            "critical": 5,
            "high": 4,
            "medium": 3,
            "low": 2,
            "negligible": 1,
            "unknown": 0,
        }

        priorities = [cve["priority"] for cve in grouped_cves["cves"]]

        # Check that they are grouped by desc priority (critical -> unknown)
        numeric_priorities = [PRIORITY_ORDER[p] for p in priorities]
        assert numeric_priorities == sorted(
            numeric_priorities, reverse=True
        ), f"CVEs are not sorted from highest to lowest priority: {priorities}"

        # Check that CVEs with same priority are ordered by publication date
        priority_buckets = defaultdict(list)
        for cve in grouped_cves["cves"]:
            dt = datetime.fromisoformat(cve["published"])
            priority_buckets[cve["priority"]].append(dt)

        for priority, dates in priority_buckets.items():
            assert dates == sorted(dates, reverse=True), (
                f"CVEs with priority '{priority}' are not in descending "
                f"publish order: {dates}"
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
        cves_asc = grouped_cves_asc["cves"]

        # Rebuild priority buckets
        priority_buckets_asc = defaultdict(list)
        for cve in cves_asc:
            dt = datetime.fromisoformat(cve["published"])
            priority_buckets_asc[cve["priority"]].append(dt)

        for priority, dates in priority_buckets_asc.items():
            assert dates == sorted(dates), (
                f"CVEs with priority '{priority}' are not in ascending "
                f"publish order: {dates}"
            )

    def test_cve_sort_by_functionality(self):
        """
        Tests that CVEs can be sorted by updated_at or published field
        and can be ordered by descending or ascending values.
        """

        # Add CVEs at different intervals to create separate publish dates
        add_cves_response1 = self.client.put(
            "/security/updates/cves.json",
            json=[
                payloads.cve2,
            ],
        )

        add_cves_response2 = self.client.put(
            "/security/updates/cves.json",
            json=[
                payloads.cve3,
            ],
        )

        add_cves_response3 = self.client.put(
            "/security/updates/cves.json",
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
            "/security/updates/cves.json",
            json=[payloads.cve2],
        )

        update_cves_response2 = self.client.put(
            "/security/updates/cves.json",
            json=[payloads.cve3],
        )

        update_cves_response3 = self.client.put(
            "/security/updates/cves.json",
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

        response = self.client.put("/security/updates/cves.json", json=[cve])

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
            "/security/updates/cves.json",
            json=[
                payloads.cve1,
                payloads.cve2,
                payloads.cve3,
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

        response = self.client.get(
            f"/security/cves/{payloads.cve3['id']}.json"
        )
        assert response.status_code == 200

    def test_delete_non_existing_cve_returns_404(self):
        response = self.client.delete(
            f"/security/updates/cves/{payloads.cve1['id']}.json"
        )

        assert response.status_code == 404

    def test_delete_cve(self):
        response = self.client.delete(
            f"/security/updates/cves/{self.models['cve'].id}.json"
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
        assert (
            response.json["cves"][0]["id"] == self.models["notice"].cves[0].id
        )
        assert response.json["cves"][0]["notices_ids"] == [
            self.models["notice"].id
        ]

        # related_notices in payload
        assert response.json["related_notices"] == []

        # Test request limit
        response = self.client.get("/security/notices.json?limit=21")
        assert response.status_code == 422

        # Test cves field
        cve_id = self.models["notice"].cves[0].id

        test_cve = make_cve("CVE-9999-0001")
        test_notice = make_notice("USN-9999-0001", cves=[test_cve])
        self.db.session.add(test_cve)
        self.db.session.add(test_notice)
        self.db.session.commit()

        response = self.client.get(f"/security/notices.json?cves={cve_id}")
        assert response.status_code == 200
        assert cve_id in response.json["notices"][0]["cves_ids"]
        assert (
            response.json["notices"][0]["cves"][0]["id"]
            == self.models["notice"].cves[0].id
        )
        assert response.json["notices"][0]["cves"][0]["notices_ids"] == [
            self.models["notice"].id
        ]

        # related_notices in payload
        assert response.json["notices"][0]["related_notices"] == []

        response = self.client.get(
            f"/security/notices.json?cves={cve_id},{test_cve.id}"
        )

        assert response.status_code == 200
        assert len(response.json["notices"]) == 2
        # Check for either cve_id in the returned notices
        assert (
            cve_id in response.json["notices"][0]["cves_ids"]
            or test_cve.id in response.json["notices"][0]["cves_ids"]
        )
        assert (
            test_cve.id in response.json["notices"][0]["cves_ids"]
            or cve_id in response.json["notices"][0]["cves_ids"]
        )

    def test_multiple_usn(self):
        response = self.client.get("/security/notices.json")

        assert response.status_code == 200
        # Should include cve
        assert (
            self.models["notice"].id
            in response.json["notices"][0]["cves"][0]["notices_ids"]
        )

    def test_page_notice(self):
        response = self.client.get("/security/page/notices.json")

        assert response.status_code == 200
        assert (
            response.json["notices"][0]["cves_ids"]
            == self.models["notice"].cves_ids
        )
        # Should not include cves
        assert response.json["notices"][0].get("cves") is None

        # Test details field
        response = self.client.get(
            (
                "/security/page/notices.json?"
                f"details={self.models['notice'].id[:3]}"
            )
        )

        assert response.status_code == 200
        assert response.json["notices"][0]["id"] == self.models["notice"].id

        # Test cve_id field
        response = self.client.get(
            (
                "/security/page/notices.json"
                f"?cve_id={self.models['notice'].cves[0].id}"
            )
        )

        assert response.status_code == 200
        assert response.json["notices"][0]["id"] == self.models["notice"].id

        response = self.client.get(
            (
                "/security/page/notices.json?"
                f"release={self.models['notice'].releases[0].codename}"
            )
        )

        assert response.status_code == 200
        assert (
            response.json["notices"][0]["releases"][0]["codename"]
            == self.models["notice"].releases[0].codename
        )

    def test_flat_notices(self):
        # Build test releases and notices
        test_cve = make_cve("CVE-1111-0002")
        test_release = make_release(
            codename="test_release",
            version="00.06",
            name="Ubuntu Testrelease 00.06 LTS",
        )
        test_release2 = make_release(
            codename="test_release2",
            version="00.07",
            name="Ubuntu Testrelease 00.07 LTS",
        )
        test_release3 = make_release(
            codename="test_release3",
            version="00.08",
            name="Ubuntu Testrelease 00.08 LTS",
        )
        test_notice = make_notice(
            "USN-9999-0003",
            releases=[test_release, test_release2],
            cves=[test_cve],
            details="Test release details Linux-1",
        )
        test_notice2 = make_notice(
            "USN-9999-0004",
            releases=[test_release],
            cves=[test_cve],
            details="Test release details Linux-2",
        )
        test_notice3 = make_notice(
            "USN-9999-0005",
            releases=[test_release3],
            cves=[test_cve],
            details="Test release details Firefox",
        )

        self.db.session.add(test_cve)
        self.db.session.add(test_release)
        self.db.session.add(test_release2)
        self.db.session.add(test_release3)
        self.db.session.add(test_notice)
        self.db.session.add(test_notice2)
        self.db.session.add(test_notice3)

        self.db.session.commit()

        response = self.client.get("/security/flat/notices.json")
        assert response.status_code == 200

        assert response.json["total_results"] == 4

        expected_ids_base = {
            "USN-9999-0005",
            "USN-9999-0004",
            "USN-9999-0003",
            "USN-1111-01",
        }

        for notice in response.json["notices"]:
            notice_id = notice.get("id")
            assert notice_id in expected_ids_base, (
                f"Unexpected notice ID in response: '{notice_id}'\n"
                f"Expected one of: {expected_ids_base}"
            )

        # Test details query parameter
        response_details = self.client.get(
            ("/security/flat/notices.json?details=linux")
        )

        assert response_details.status_code == 200

        expected_ids_details = {
            "USN-9999-0004",
            "USN-9999-0003",
        }

        for notice in response_details.json["notices"]:
            notice_id = notice.get("id")
            assert notice_id in expected_ids_details, (
                f"Unexpected notice ID in response: '{notice_id}'\n"
                f"Expected one of: {expected_ids_details}"
            )
        assert response_details.json["total_results"] == 2

        # Test releases query parameter
        response_releases = self.client.get(
            ("/security/flat/notices.json?release=test_release2")
        )
        assert response_releases.status_code == 200
        assert response_releases.json["total_results"] == 1
        assert response_releases.json["notices"][0]["id"] == "USN-9999-0003"

    def test_page_usns_multiple_releases_filter(self):
        # Build test releases and notices
        test_cve = make_cve("CVE-1111-0002")
        test_release = make_release(
            codename="test_release",
            version="00.06",
            name="Ubuntu Testrelease 00.06 LTS",
        )
        test_release2 = make_release(
            codename="test_release2",
            version="00.07",
            name="Ubuntu Testrelease 00.07 LTS",
        )
        test_release3 = make_release(
            codename="test_release3",
            version="00.08",
            name="Ubuntu Testrelease 00.08 LTS",
        )
        test_notice = make_notice(
            "USN-9999-0003",
            releases=[test_release, test_release2],
            cves=[test_cve],
        )
        test_notice2 = make_notice(
            "USN-9999-0004", releases=[test_release], cves=[test_cve]
        )
        test_notice3 = make_notice(
            "USN-9999-0005", releases=[test_release3], cves=[test_cve]
        )

        self.db.session.add(test_cve)
        self.db.session.add(test_release)
        self.db.session.add(test_release2)
        self.db.session.add(test_release3)
        self.db.session.add(test_notice)
        self.db.session.add(test_notice2)
        self.db.session.add(test_notice3)

        self.db.session.commit()

        multiple_releases_response = self.client.get(
            "/security/page/notices.json?"
            "release=test_release2&release=test_release3"
        )
        # Check that the response is succesful and contains expected notices
        valid_ids = {"USN-9999-0005", "USN-9999-0003"}

        assert multiple_releases_response.status_code == 200
        assert multiple_releases_response.json["total_results"] == 2
        for notice in multiple_releases_response.json["notices"]:
            assert notice["id"] in valid_ids

    def test_usns_returns_200_for_non_existing_release(self):
        response = self.client.get("/security/notices.json?release=no-exist")

        assert response.status_code == 200
        assert "Cannot find a release with codename" not in response.json.get(
            "errors", []
        )

    def test_create_usn(self):
        response = self.client.post(
            "/security/updates/notices.json", json=payloads.notice
        )

        assert response.status_code == 200

    def test_create_ssn_usn(self):
        response = self.client.post(
            "/security/updates/notices.json", json=payloads.ssn_notice
        )

        assert response.status_code == 200

    def test_create_usn_returns_422_for_non_unique_id(self):
        # Create USN
        response_1 = self.client.post(
            "/security/updates/notices.json", json=payloads.notice
        )
        assert response_1.status_code == 200

        # Create again
        response_2 = self.client.post(
            "/security/updates/notices.json", json=payloads.notice
        )
        assert response_2.status_code == 422
        assert (
            f"'{payloads.notice['id']}' already exists"
            in response_2.json["errors"]
        )

    def test_create_usn_returns_422_for_unknown_field(self):
        notice = payloads.notice.copy()
        notice["unknown"] = "field"

        response = self.client.post(
            "/security/updates/notices.json", json=notice
        )

        assert response.status_code == 422
        assert "Unknown field." in response.json["errors"]

    def test_update_usn(self):
        instructions = "Instructions were updated!"

        # Create first
        notice = payloads.notice.copy()
        response_1 = self.client.post(
            "/security/updates/notices.json", json=notice
        )
        assert response_1.status_code == 200

        # Update
        notice["instructions"] = instructions
        response_2 = self.client.put(
            f"/security/updates/notices/{notice['id']}.json", json=notice
        )
        assert response_2.status_code == 200

        # Get
        response_3 = self.client.get(f"/security/notices/{notice['id']}.json")
        assert response_3.json["instructions"] == instructions

    def test_update_usn_returns_404_for_non_existing_id(self):
        response = self.client.put(
            f"/security/updates/notices/{payloads.notice['id']}.json",
            json=payloads.notice,
        )

        assert response.status_code == 404

    def test_update_usn_returns_422_for_unknown_field(self):
        notice = payloads.notice.copy()
        notice["unknown"] = "field"

        response = self.client.put(
            f"/security/updates/notices/{notice['id']}.json", json=notice
        )

        assert response.status_code == 422
        assert "Unknown field." in response.json["errors"]

    def test_delete_usn_returns_404_for_non_existing_usn(self):
        response = self.client.delete(
            f"/security/updates/notices/{payloads.notice['id']}.json"
        )

        assert response.status_code == 404

    def test_delete_usn(self):
        # Create USN first
        response = self.client.post(
            "/security/updates/notices.json", json=payloads.notice
        )
        assert response.status_code == 200

        # Now delete it
        response = self.client.delete(
            f"/security/updates/notices/{payloads.notice['id']}.json"
        )
        assert response.status_code == 200

    def test_create_release(self):
        response = self.client.post(
            "/security/updates/releases.json", json=payloads.release
        )

        assert response.status_code == 200

    def test_create_existing_release_returns_422(self):
        # Create release
        response_1 = self.client.post(
            "/security/updates/releases.json", json=payloads.release
        )
        assert response_1.status_code == 200

        # Create release again
        response_2 = self.client.post(
            "/security/updates/releases.json", json=payloads.release
        )
        assert response_2.status_code == 422
        assert (
            f"Release with codename '{payloads.release['codename']}'"
            " already exists"
        ) in response_2.json["errors"]

    def test_delete_non_existing_release_returns_404(self):
        response = self.client.delete(
            "/security/updates/releases/no-exist.json"
        )

        assert response.status_code == 404

    def test_delete_release(self):
        # Create release first
        response_1 = self.client.post(
            "/security/updates/releases.json", json=payloads.release
        )
        assert response_1.status_code == 200

        # Delete release
        response = self.client.delete(
            f"/security/updates/releases/{payloads.release['codename']}.json"
        )
        assert response.status_code == 200

    def test_cves_query_notes(self):
        """
        Query text field should include notes
        """
        # Act
        response = self.client.get("/security/cves.json?q=sql")

        # Assert
        assert response.status_code == 200
        assert response.json["total_results"] == 1
        assert len(response.json["cves"]) == 1


if __name__ == "__main__":
    unittest.main()
