"""Tests for the NESTED_NOTICE_CVE_IDS kill-switch.

Notices nested inside a CVE response carry `cves_ids` - every CVE that notice
covers. For a large USN that is 1200+ ids, which is what makes CVE responses
reach 1MB (detail) and 24MB (list). Dropping the field cuts those payloads by
~95%, at the cost of an API contract change.

The switch defaults to on, so these tests assert the default preserves the
contract, and that turning it off actually removes the field.
"""

import json

from marshmallow.fields import List, Nested

from tests import BaseTestCase
from tests.fixtures.models import make_cve
from webapp import schemas
from webapp.database import db
from webapp.models import Notice

EXTRA_CVES = 25


class LeanCVESchema(schemas.CVEAPISchema):
    """CVEAPIDetailedSchema as it renders with the switch off."""

    notices = List(Nested(schemas.NoticeAPISchema, exclude=("cves_ids",)))


class NestedCveIds(BaseTestCase):
    def _seed_wide_notice(self):
        notice = db.session.query(Notice).first()
        for n in range(EXTRA_CVES):
            cve = make_cve(id=f"CVE-1999-{3000 + n}", status="active")
            db.session.add(cve)
            notice.cves.append(cve)
        db.session.commit()
        db.session.expire_all()

    def test_default_keeps_cves_ids(self):
        """The contract must not change unless deliberately switched off."""
        self.assertTrue(
            schemas.NESTED_NOTICE_CVE_IDS,
            "NESTED_NOTICE_CVE_IDS should default to true",
        )
        self.assertEqual(schemas._NESTED_NOTICE_EXCLUDE, ())

        self._seed_wide_notice()
        cve_id = self.models["cve"].id
        response = self.client.get(f"/security/cves/{cve_id}.json")
        self.assertEqual(response.status_code, 200)

        payload = json.loads(response.data)
        self.assertTrue(payload["notices"], "expected nested notices")
        for notice in payload["notices"]:
            self.assertIn("cves_ids", notice)

    def test_excluding_removes_field_and_shrinks_payload(self):
        self._seed_wide_notice()
        cve = db.session.query(schemas.Notice).first().cves[0]

        full = schemas.CVEAPIDetailedSchema().dumps(cve)
        lean = LeanCVESchema().dumps(cve)

        for notice in json.loads(lean)["notices"]:
            self.assertNotIn("cves_ids", notice)
        for notice in json.loads(full)["notices"]:
            self.assertIn("cves_ids", notice)

        self.assertLess(
            len(lean),
            len(full),
            "excluding cves_ids should shrink the payload",
        )
