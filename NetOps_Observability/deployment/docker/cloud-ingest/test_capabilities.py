"""Permission-test harness tests (capabilities.py) — the read-only, least-privilege
guarantee, exercised against CANNED provider responses (no live cloud, no creds).

Scenarios the mission requires: Reader-only, Monitoring-Reader-only, scope-limited,
and write-denied. Each is a mock probe_fn returning the ProbeResult that Azure's
ARM layer would return for that grant; we assert the per-capability classification
and that a partial grant is a set of coverage GAPS, never a total failure.

Run: python3 -m pytest test_capabilities.py
"""
import unittest

import capabilities as cap
from capabilities import (AZURE_CAPABILITIES, Capability, ProbeResult,
                          classify_probe, coverage_report)

# Which built-in roles grant which capability action (mirrors the catalog) — the
# mock uses this to answer "would THIS grant authorize THIS action?".
_ROLE_GRANTS = {
    "Reader": {"Reader"},
    "Monitoring Reader": {"Monitoring Reader"},
    # A subscription Reader also covers Monitoring-Reader reads in practice, but we
    # model them distinctly so a monitoring-only principal shows inventory gaps.
}


def grant_probe(*roles: str):
    """A mock probe_fn: AVAILABLE when the caller holds the capability's role,
    else a 403 AuthorizationFailed (exactly what ARM returns)."""
    held = set(roles)

    def fn(c: Capability) -> ProbeResult:
        if c.role in held:
            return ProbeResult(200)
        return ProbeResult(403, "AuthorizationFailed",
                           f"does not have authorization to perform action '{c.action}'")
    return fn


class TestClassify(unittest.TestCase):
    def test_status_mapping(self):
        self.assertEqual(classify_probe(ProbeResult(200)), cap.AVAILABLE)
        self.assertEqual(classify_probe(ProbeResult(204)), cap.AVAILABLE)
        self.assertEqual(classify_probe(ProbeResult(403, "AuthorizationFailed")), cap.MISSING_PERMISSION)
        self.assertEqual(classify_probe(ProbeResult(401)), cap.MISSING_PERMISSION)
        self.assertEqual(classify_probe(ProbeResult(409, "SubscriptionNotRegistered")), cap.API_DISABLED)
        self.assertEqual(classify_probe(ProbeResult(404, "ResourceNotFound")), cap.NOT_CONFIGURED)
        self.assertEqual(classify_probe(ProbeResult(500, "InternalError")), cap.ERROR)

    def test_scope_complaint_is_distinct_from_missing(self):
        pr = ProbeResult(403, "AuthorizationFailed",
                         "not authorized to perform action over scope '/subscriptions/x/rg/y'")
        self.assertEqual(classify_probe(pr), cap.SCOPE_NOT_GRANTED)


class TestReaderOnly(unittest.TestCase):
    def test_reader_only_covers_reader_caps_gaps_monitoring(self):
        rep = coverage_report(AZURE_CAPABILITIES, grant_probe("Reader"))
        by = {s.cap_id: s.status for s in rep.statuses}
        # Reader covers inventory + health + topology.
        self.assertEqual(by["inventory_read"], cap.AVAILABLE)
        self.assertEqual(by["resource_health_read"], cap.AVAILABLE)
        self.assertEqual(by["topology_read"], cap.AVAILABLE)
        # But NOT the Monitoring-Reader lanes.
        self.assertEqual(by["metric_read"], cap.MISSING_PERMISSION)
        self.assertEqual(by["activity_event_read"], cap.MISSING_PERMISSION)
        # A required capability (metric_read) is missing → required_ok is False,
        # but the harness still reports every other capability's real status.
        self.assertFalse(rep.required_ok)
        self.assertTrue(len(rep.gaps) >= 2)


class TestReaderPlusMonitoring(unittest.TestCase):
    def test_both_core_roles_satisfy_required(self):
        rep = coverage_report(AZURE_CAPABILITIES, grant_probe("Reader", "Monitoring Reader"))
        # Both required capabilities present → required_ok True.
        self.assertTrue(rep.required_ok)
        by = {s.cap_id: s.status for s in rep.statuses}
        self.assertEqual(by["inventory_read"], cap.AVAILABLE)
        self.assertEqual(by["metric_read"], cap.AVAILABLE)
        # Cost is a separate role — still an honest gap, not a failure.
        self.assertEqual(by["cost_read"], cap.MISSING_PERMISSION)
        # Optional gaps do not flip required_ok.
        self.assertTrue(rep.required_ok)


class TestMonitoringOnly(unittest.TestCase):
    def test_monitoring_only_gaps_inventory(self):
        rep = coverage_report(AZURE_CAPABILITIES, grant_probe("Monitoring Reader"))
        by = {s.cap_id: s.status for s in rep.statuses}
        self.assertEqual(by["metric_read"], cap.AVAILABLE)
        self.assertEqual(by["inventory_read"], cap.MISSING_PERMISSION)  # required gap
        self.assertFalse(rep.required_ok)


class TestScopeLimited(unittest.TestCase):
    def test_scope_limited_reports_scope_not_granted(self):
        # A principal scoped to one RG probing a subscription-level action.
        def fn(c: Capability) -> ProbeResult:
            return ProbeResult(403, "AuthorizationFailed",
                               "not authorized to perform action over scope '/subscriptions/x'")
        rep = coverage_report(AZURE_CAPABILITIES, fn)
        self.assertTrue(all(s.status == cap.SCOPE_NOT_GRANTED for s in rep.statuses))
        self.assertFalse(rep.required_ok)


class TestWriteDenied(unittest.TestCase):
    def test_catalog_is_read_only(self):
        # No capability in the catalog is a write action — least privilege.
        for c in AZURE_CAPABILITIES:
            self.assertIn("/read", c.action.lower(),
                          f"{c.cap_id} action {c.action!r} is not a read")
        for forbidden in cap.FORBIDDEN_WRITE_ACTIONS:
            self.assertNotIn(forbidden, [c.action for c in AZURE_CAPABILITIES])

    def test_never_auto_broadens(self):
        # The harness must never turn a denial into an attempt at a broader grant —
        # a denied probe stays denied in the report (no retry with more scope).
        calls: list[str] = []

        def fn(c: Capability) -> ProbeResult:
            calls.append(c.cap_id)
            return ProbeResult(403, "AuthorizationFailed", "denied")
        rep = coverage_report(AZURE_CAPABILITIES, fn)
        # Exactly one probe per capability — no escalation loop.
        self.assertEqual(len(calls), len(AZURE_CAPABILITIES))
        self.assertTrue(all(s.status == cap.MISSING_PERMISSION for s in rep.statuses))


if __name__ == "__main__":
    unittest.main()
