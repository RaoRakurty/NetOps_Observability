"""Teardown ordering: the telemetry purge must run only AFTER the consumer
drain gate (the late-insert residue race the mini-ladder fixed on 2026-08-16),
and every step reports its failure instead of raising past the rest."""
import lifecycle


class FakeStack:
    def __init__(self, lag_sequence):
        self.calls = []
        self.lag_sequence = list(lag_sequence)
        self.devices = {"twx-r1-edge-a1", "twx-r1-rtr-c1"}

    # -- API ---------------------------------------------------------------
    def api(self, method, path, body=None):
        if method == "DELETE" and path.startswith("/api/devices/"):
            self.calls.append("delete_device")
            self.devices.discard(path.rsplit("/", 1)[1])
            return 204, {}
        if method == "GET" and path.startswith("/api/devices"):
            self.calls.append("verify_devices")
            return 200, {"devices": [{"id": d} for d in sorted(self.devices)],
                         "complete": True}
        if method == "PATCH" and path.startswith("/api/seams/"):
            self.calls.append("retire_seam")
            return 200, {}
        if method == "DELETE" and path.startswith("/api/tenants/"):
            self.calls.append("delete_tenant")
            return 204, {}
        if method == "DELETE" and path.startswith("/api/orgs/"):
            self.calls.append("delete_org")
            return 204, {}
        raise AssertionError(f"unexpected api call {method} {path}")

    # -- bus/stores ----------------------------------------------------------
    def group_lag_total(self, group):
        self.calls.append("drain_poll")
        lag = self.lag_sequence.pop(0) if self.lag_sequence else 0
        return lag, 2

    def ch_mutation(self, query):
        assert "DELETE" in query
        self.calls.append("purge_ch")
        return True, ""

    def ch(self, query):
        self.calls.append("verify_ch")
        return True, "0"

    def os_req(self, role, user, path, body=None, timeout=25):
        self.calls.append("purge_os")
        return True, {"deleted": 42}

    def os_count(self, index, field, prefix):
        self.calls.append("verify_os")
        return 0


STATE = {
    "runid": "r1", "prefix": "twx-r1-",
    "devices": ["twx-r1-edge-a1", "twx-r1-rtr-c1"],
    "seam_mode": "api", "seams": ["twx-r1-dal-dx-1"],
    "tenants": {"acme": {"tenant_id": "tA", "name": "twx-r1-acme"}},
    "orgs": [{"id": "oA", "name": "twx-r1-acme-corp"}],
}


def test_purge_runs_only_after_drain_gate(monkeypatch):
    monkeypatch.setattr(lifecycle.time, "sleep", lambda s: None)
    stack = FakeStack(lag_sequence=[500, 120, 0])  # drains on 3rd poll
    problems = lifecycle.teardown(stack, dict(STATE), "/nonexistent")
    assert problems == []
    order = stack.calls
    # every drain poll precedes the ClickHouse purge
    assert order.index("purge_ch") > max(
        i for i, c in enumerate(order) if c == "drain_poll")
    # gross phase ordering: devices → seams → drain → CH → OS → tenants
    assert order.index("delete_device") < order.index("retire_seam")
    assert order.index("retire_seam") < order.index("drain_poll")
    assert order.index("purge_ch") < order.index("verify_ch")
    assert order.index("verify_ch") < order.index("purge_os")
    assert order.index("purge_os") < order.index("verify_os")
    assert order.index("verify_os") < order.index("delete_tenant")
    assert order.index("delete_tenant") < order.index("delete_org")


def test_stuck_drain_is_reported_but_purge_still_runs(monkeypatch):
    monkeypatch.setattr(lifecycle.time, "sleep", lambda s: None)
    monkeypatch.setattr(lifecycle, "DRAIN_WAIT_TIMEOUT_S", 0.0)
    stack = FakeStack(lag_sequence=[9999] * 100)
    problems = lifecycle.teardown(stack, dict(STATE), "/nonexistent")
    assert any("purge may race late inserts" in p for p in problems)
    # the purge is NOT skipped — the whole point is to purge after the last
    # insert, and a bounded wait failure still purges + reports.
    assert "purge_ch" in stack.calls
    assert "purge_os" in stack.calls


def test_leftover_devices_are_reported(monkeypatch):
    monkeypatch.setattr(lifecycle.time, "sleep", lambda s: None)

    class Sticky(FakeStack):
        def api(self, method, path, body=None):
            if method == "DELETE" and path.startswith("/api/devices/"):
                self.calls.append("delete_device")
                return 204, {}  # lies: device stays
            return super().api(method, path, body)

    stack = Sticky(lag_sequence=[0])
    problems = lifecycle.teardown(stack, dict(STATE), "/nonexistent")
    assert any("still present after delete" in p for p in problems)
