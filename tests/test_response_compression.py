"""JSON responses are compressed when the client accepts it, except for the
Ubuntu Pro client, which reads the raw body as UTF-8 (WD-23733).

A client that sends no Accept-Encoding gets the plain body, so the contract
is unchanged.
"""

import gzip
import json

from tests import BaseTestCase


class ResponseCompression(BaseTestCase):
    # flask-compress leaves anything under COMPRESS_MIN_SIZE (500) alone.
    URL = "/security/cves.json?limit=10"

    def test_json_is_gzipped_when_accepted(self):
        response = self.client.get(
            self.URL, headers={"Accept-Encoding": "gzip"}
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers.get("Content-Encoding"), "gzip")

    def test_body_survives_a_round_trip(self):
        plain = self.client.get(self.URL)
        packed = self.client.get(self.URL, headers={"Accept-Encoding": "gzip"})
        self.assertEqual(gzip.decompress(packed.data), plain.data)

    def test_pro_client_is_never_compressed(self):
        response = self.client.get(
            self.URL,
            headers={
                "Accept-Encoding": "gzip",
                "User-Agent": "UA-Client/37.2ubuntu~22.04.1",
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertIsNone(response.headers.get("Content-Encoding"))
        # Mirrors what pro fix does with the body.
        json.loads(response.data.decode("utf-8"))

    def test_client_without_accept_encoding_gets_plain_json(self):
        response = self.client.get(self.URL)
        self.assertEqual(response.status_code, 200)
        self.assertIsNone(response.headers.get("Content-Encoding"))
