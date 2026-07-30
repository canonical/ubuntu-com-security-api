"""Tests for the CVE list endpoint's concurrency gate.

/security/cves.json can emit 12-24MB of JSON. With sync gunicorn workers,
three of those in flight starve every other request on the pod - including
/_status/check, which gets the pod removed from the Service. The gate caps
how many run at once and rejects the excess with 429 instead of queuing.
"""

import fcntl
import os

from tests import BaseTestCase
from webapp import views


class ConcurrencyGate(BaseTestCase):
    def _slot_paths(self):
        return [
            os.path.join(views.CVE_LIST_SLOT_DIR, f"cve-list-{slot}.lock")
            for slot in range(views.CVE_LIST_SLOTS)
        ]

    def test_rejects_with_429_when_all_slots_held(self):
        handles = []
        try:
            for path in self._slot_paths():
                handle = open(path, "w")
                fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
                handles.append(handle)

            response = self.client.get("/security/cves.json?limit=10")
            self.assertEqual(response.status_code, 429)
            self.assertEqual(response.headers.get("Retry-After"), "5")
        finally:
            for handle in handles:
                fcntl.flock(handle, fcntl.LOCK_UN)
                handle.close()

    def test_slot_is_released_after_each_request(self):
        """A leaked slot would 429 every subsequent request."""
        for _ in range(3):
            response = self.client.get("/security/cves.json?limit=10")
            self.assertEqual(response.status_code, 200)

    def test_detail_endpoint_is_not_gated(self):
        """get_cve must keep serving while the list endpoint is saturated."""
        cve_id = self.models["cve"].id
        handles = []
        try:
            for path in self._slot_paths():
                handle = open(path, "w")
                fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
                handles.append(handle)

            response = self.client.get(f"/security/cves/{cve_id}.json")
            self.assertEqual(response.status_code, 200)

            status = self.client.get("/_status/check")
            self.assertEqual(status.status_code, 200)
        finally:
            for handle in handles:
                fcntl.flock(handle, fcntl.LOCK_UN)
                handle.close()
