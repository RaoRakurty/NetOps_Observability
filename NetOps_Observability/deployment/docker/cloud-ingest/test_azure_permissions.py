"""Azure permission-adapter tests (azure_permissions.py) — the harness invokes the
ACTUAL ARM paths (mocked here) and grades them, never inferring from a role name.

Run: python3 -m pytest test_azure_permissions.py
"""
import json
import unittest
import urllib.error

import azure_permissions as ap
import capabilities as cap


class TestAzureAdapter(unittest.TestCase):
    def test_reader_only_grants_inventory_denies_metrics(self):
        # A read-only principal: inventory answers 200; metric definitions 403.
        def get_fn(url: str):
            if "Microsoft.Insights/metricDefinitions" in url or "eventtypes" in url:
                body = json.dumps({"error": {"code": "AuthorizationFailed",
                                             "message": "not authorized to perform action"}}).encode()
                return 403, body
            return 200, b'{"value":[]}'
        rep = ap.report(get_fn, "sub-123")
        by = {s.cap_id: s.status for s in rep.statuses}
        self.assertEqual(by["inventory_read"], cap.AVAILABLE)
        self.assertEqual(by["metric_read"], cap.MISSING_PERMISSION)
        self.assertEqual(by["activity_event_read"], cap.MISSING_PERMISSION)
        self.assertFalse(rep.required_ok)  # metric_read is required

    def test_provider_not_registered_is_api_disabled(self):
        def get_fn(url: str):
            if "ResourceGraph" in url:
                body = json.dumps({"error": {"code": "SubscriptionNotRegistered",
                                             "message": "RP not registered"}}).encode()
                return 409, body
            return 200, b'{"value":[]}'
        rep = ap.report(get_fn, "sub-123")
        by = {s.cap_id: s.status for s in rep.statuses}
        self.assertEqual(by["resource_graph_query"], cap.API_DISABLED)

    def test_httperror_is_captured_not_raised(self):
        # The real transport raises HTTPError — the adapter must convert, not crash.
        def get_fn(url: str):
            raise urllib.error.HTTPError(url, 403, "Forbidden", {},
                                         _FakeBody(json.dumps({"error": {"code": "AuthorizationFailed"}}).encode()))
        rep = ap.report(get_fn, "sub-123")
        self.assertTrue(all(s.status == cap.MISSING_PERMISSION for s in rep.statuses))

    def test_probe_urls_are_reads_on_the_subscription(self):
        seen: list[str] = []

        def get_fn(url: str):
            seen.append(url)
            return 200, b'{"value":[]}'
        ap.report(get_fn, "sub-XYZ")
        # Every probed URL targets ARM and the given subscription (or the global
        # ResourceGraph endpoint) — and none is a POST/PUT (this is a GET seam).
        self.assertTrue(seen)
        for u in seen:
            self.assertTrue(u.startswith("https://management.azure.com"))
        self.assertTrue(any("subscriptions/sub-XYZ" in u for u in seen))


class _FakeBody:
    def __init__(self, data: bytes):
        self._data = data

    def read(self) -> bytes:
        return self._data

    def close(self) -> None:
        pass


if __name__ == "__main__":
    unittest.main()
