"""The temporary scraper block only answers 429 for CVE-ID searches on
cves.json from the blocked user agent. Everyone else is served as normal.
"""

from tests import BaseTestCase

SCRAPER_UA = {"User-Agent": "python-urllib3/1.26.19"}


class ScraperBlock(BaseTestCase):
    def test_blocks_cve_id_search_from_scraper(self):
        for q in ("CVE-2026-89465", "cve-2026-89465", "%20CVE-2026-1"):
            response = self.client.get(
                f"/security/cves.json?q={q}&order=descending"
                "&sort_by=published",
                headers=SCRAPER_UA,
            )
            self.assertEqual(response.status_code, 429, q)
            self.assertEqual(response.headers["Retry-After"], "3600")

    def test_allows_everything_else(self):
        allowed = [
            # Other clients doing the same search
            ("/security/cves.json?q=CVE-2026-89465", {}),
            (
                "/security/cves.json?q=CVE-2026-89465",
                {"User-Agent": "python-requests/2.33.0"},
            ),
            (
                "/security/cves.json?q=CVE-2026-89465",
                {"User-Agent": "UA-Client/37.2ubuntu~22.04.1"},
            ),
            # The scraper's UA on other queries and endpoints
            ("/security/cves.json?q=firefox", SCRAPER_UA),
            ("/security/cves.json?limit=10", SCRAPER_UA),
            ("/security/cves/CVE-2026-89465.json", SCRAPER_UA),
        ]
        for url, headers in allowed:
            response = self.client.get(url, headers=headers)
            self.assertNotEqual(response.status_code, 429, (url, headers))
