"""JSON responses must be compressed when the client accepts it.

webapp/app.py used to pass flask-compress a mimetype list that was the
library's own default with application/json deleted, so every response this
API serves went out uncompressed. These pin the behaviour back.

Compression is negotiated: a client that sends no Accept-Encoding still gets
the plain body, so the API contract is unchanged either way.
"""

import gzip

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
        packed = self.client.get(
            self.URL, headers={"Accept-Encoding": "gzip"}
        )
        self.assertEqual(gzip.decompress(packed.data), plain.data)

    def test_client_without_accept_encoding_gets_plain_json(self):
        response = self.client.get(self.URL)
        self.assertEqual(response.status_code, 200)
        self.assertIsNone(response.headers.get("Content-Encoding"))
