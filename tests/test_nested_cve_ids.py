"""Tests for the NESTED_NOTICE_EXCLUDE kill-switch.

Nested notices dominate CVE responses. Measured on CVE-2026-23412 (852KB),
`notices` was 77% of the payload across only 13 notices - roughly 50KB each -
carried mainly by release_packages and cves_ids.

The switch defaults to empty, so these tests assert the default preserves the
API contract, and that listing a field actually removes it and shrinks the
payload.
"""

import json

from marshmallow.fields import List, Nested

from tests import BaseTestCase
from tests.fixtures.models import make_cve
from webapp import schemas
from webapp.database import db
from webapp.models import Notice

EXTRA_CVES = 25
EXCLUDABLE = ("cves_ids", "release_packages")


class LeanCVESchema(schemas.CVEAPISchema):
    """CVEAPIDetailedSchema as it renders with the switch enabled."""

    notices = List(Nested(schemas.NoticeAPISchema, exclude=EXCLUDABLE))


class NestedNoticeExclude(BaseTestCase):
    def _seed_wide_notice(self):
        notice = db.session.query(Notice).first()
        for n in range(EXTRA_CVES):
            cve = make_cve(id=f"CVE-1999-{3000 + n}", status="active")
            db.session.add(cve)
            notice.cves.append(cve)
        db.session.commit()
        db.session.expire_all()

    def test_default_excludes_nothing(self):
        """The contract must not change unless deliberately switched on."""
        self.assertEqual(
            schemas.NESTED_NOTICE_EXCLUDE,
            (),
            "NESTED_NOTICE_EXCLUDE should default to empty",
        )

        self._seed_wide_notice()
        cve_id = self.models["cve"].id
        response = self.client.get(f"/security/cves/{cve_id}.json")
        self.assertEqual(response.status_code, 200)

        payload = json.loads(response.data)
        self.assertTrue(payload["notices"], "expected nested notices")
        for notice in payload["notices"]:
            for field in EXCLUDABLE:
                self.assertIn(field, notice)

    def test_excluded_fields_are_removed_and_payload_shrinks(self):
        self._seed_wide_notice()
        cve = db.session.query(Notice).first().cves[0]

        full = schemas.CVEAPIDetailedSchema().dumps(cve)
        lean = LeanCVESchema().dumps(cve)

        for notice in json.loads(lean)["notices"]:
            for field in EXCLUDABLE:
                self.assertNotIn(field, notice)
        for notice in json.loads(full)["notices"]:
            for field in EXCLUDABLE:
                self.assertIn(field, notice)

        self.assertLess(
            len(lean),
            len(full),
            "excluding notice fields should shrink the payload",
        )

    def test_every_excludable_field_exists_on_the_schema(self):
        """Marshmallow raises if `exclude` names a field that isn't there."""
        fields = schemas.NoticeAPISchema().fields
        for field in EXCLUDABLE:
            self.assertIn(field, fields)
