"""Regression test for the Notice.cves_ids bulk preload.

NoticeAPISchema serialises `cves_ids` for every notice. The model property
builds that list by walking the `cves` relationship, which hydrates one ORM
object per related CVE - and notices like USN-8606-1 reference over 1200 of
them. views.preload_notice_cve_ids replaces that with a single query against
the association table.

This test pins the behaviour: both routes must produce identical output.
"""

import json

from tests import BaseTestCase
from tests.fixtures.models import make_cve
from webapp import views
from webapp.database import db
from webapp.models import Notice

EXTRA_CVES = 25


class CvesIdsEquivalence(BaseTestCase):
    def _seed_wide_notice(self):
        """Attach many CVEs to the fixture notice, mimicking a large USN."""
        notice = db.session.query(Notice).first()
        self.assertIsNotNone(notice, "fixture notice missing")
        for n in range(EXTRA_CVES):
            cve = make_cve(id=f"CVE-1999-{2000 + n}", status="active")
            db.session.add(cve)
            notice.cves.append(cve)
        db.session.commit()
        db.session.expire_all()
        return notice.id

    def _fetch(self):
        response = self.client.get("/security/cves.json?limit=10")
        self.assertEqual(response.status_code, 200)
        return json.loads(response.data)

    def test_preload_matches_relationship_walk(self):
        self._seed_wide_notice()

        with_preload = self._fetch()
        db.session.expire_all()

        # Stub the preload out, so cves_ids falls back to walking `cves`.
        original = views.preload_notice_cve_ids
        views.preload_notice_cve_ids = lambda cves: None
        try:
            without_preload = self._fetch()
        finally:
            views.preload_notice_cve_ids = original

        self.assertEqual(
            json.dumps(with_preload, sort_keys=True),
            json.dumps(without_preload, sort_keys=True),
            "bulk preload and relationship walk disagree - the optimisation "
            "is not behaviour-preserving",
        )

    def test_cves_ids_are_actually_populated(self):
        """Guard against the preload silently yielding empty lists."""
        notice_id = self._seed_wide_notice()
        payload = self._fetch()

        notices = [
            notice
            for cve in payload["cves"]
            for notice in cve.get("notices", [])
            if notice["id"] == notice_id
        ]
        self.assertTrue(notices, f"notice {notice_id} absent from response")
        for notice in notices:
            self.assertGreaterEqual(len(notice["cves_ids"]), EXTRA_CVES)
