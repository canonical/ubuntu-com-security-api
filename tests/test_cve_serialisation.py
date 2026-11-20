"""A single CVE response is encoded once, by orjson."""

import json
from unittest.mock import patch

from tests import BaseTestCase
from webapp.models import CVE
from webapp.schemas import CVEAPIDetailedSchema


class SingleCVESerialisation(BaseTestCase):
    def test_body_matches_schema_dump_without_flask_json_encoding(self):
        cve_id = self.models["cve"].id
        expected = CVEAPIDetailedSchema().dump(
            CVE.query.filter(CVE.id == cve_id).one()
        )

        with patch(
            "flask.json.provider.DefaultJSONProvider.response",
            side_effect=AssertionError("encoded by flask.json"),
        ):
            response = self.client.get(f"/security/cves/{cve_id}.json")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.mimetype, "application/json")
        self.assertEqual(response.cache_control.max_age, 300)
        self.assertEqual(
            json.loads(response.data), json.loads(json.dumps(expected))
        )
