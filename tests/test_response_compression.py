"""JSON responses must be compressed when the client accepts it.

webapp/app.py used to pass flask-compress a mimetype list that was the
library's own default with application/json deleted, so every response this
API serves went out uncompressed. These pin the behaviour back.

Compression is negotiated: a client that sends no Accept-Encoding still gets
the plain body, so the API contract is unchanged either way.

The Ubuntu Pro client is the one known exception. It reads the raw body as
UTF-8 without honouring Content-Encoding, which is why compression was
disabled in the first place (WD-23733). It is exempted by User-Agent.
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
        packed = self.client.get(
            self.URL, headers={"Accept-Encoding": "gzip"}
        )
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
        # What `pro fix` does with the body: decode it as UTF-8 directly.
        json.loads(response.data.decode("utf-8"))

    def test_client_without_accept_encoding_gets_plain_json(self):
        response = self.client.get(self.URL)
        self.assertEqual(response.status_code, 200)
        self.assertIsNone(response.headers.get("Content-Encoding"))
