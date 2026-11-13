"""Endpoints that used the 60 second default now cache for longer."""

from tests import BaseTestCase


class CacheHeaders(BaseTestCase):
    def max_age(self, url):
        response = self.client.get(url)
        return response.status_code, response.cache_control.max_age

    def test_single_cve_is_cached_for_five_minutes(self):
        cve_id = self.models["cve"].id

        self.assertEqual(
            self.max_age(f"/security/cves/{cve_id}.json"), (200, 300)
        )

    def test_notice_lists_and_releases_are_cached_for_ten_minutes(self):
        codename = self.models["release"].codename

        for url in (
            "/security/page/notices.json",
            "/security/flat/notices.json",
            "/security/releases.json",
            f"/security/releases/{codename}.json",
        ):
            self.assertEqual(self.max_age(url), (200, 600), url)

    def test_missing_cve_is_not_cached_for_longer(self):
        status, max_age = self.max_age("/security/cves/CVE-0000-0000.json")

        self.assertEqual(status, 404)
        self.assertNotEqual(max_age, 300)
