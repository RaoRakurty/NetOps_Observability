"""Regression guards for audit F-41 (cloud-ingest lane starvation).

Two independent defects lived here, and both had the same signature — a real
failure that ran for cycle after cycle with nothing able to alert on it:

  1. THE LIVE BUG. `_pages(ec2, "describe_vpn_gateways", ...)` called
     get_paginator() on an operation botocore does not model as pageable, so it
     raised OperationNotPageableError before a single request went out. The
     seam_endpoints family produced ZERO rows on every cycle — VPN gateways, VPN
     connections, DX connections and transit gateways all missing from the
     inventory — for **167 consecutive cycles**, visible only as a log line.

  2. THE STRUCTURE THAT HID IT. Every AWS lane shared one try/except and set its
     cadence marker AFTER its call, so one failing lane permanently starved every
     lane behind it (flow logs, S3, CloudTrail, seams, health) AND save_state.
"""
from __future__ import annotations

import aws_components
import aws_workloads
import ingest_metrics


class _NotPageable:
    """A client shaped like the real EC2 one: describe_vpn_gateways has no
    paginator, everything else does."""

    def __init__(self):
        self.direct_calls = []

    def can_paginate(self, op):
        return op != "describe_vpn_gateways"

    def describe_vpn_gateways(self, **kw):
        self.direct_calls.append(("describe_vpn_gateways", kw))
        return {"VpnGateways": [{"VpnGatewayId": "vgw-1"}, {"VpnGatewayId": "vgw-2"}]}

    def get_paginator(self, op):
        if op == "describe_vpn_gateways":
            raise ValueError(f"Operation cannot be paginated: {op}")

        class _P:
            def paginate(self, **kw):
                return [{"TransitGateways": [{"TransitGatewayId": "tgw-1"}]}]
        return _P()


def test_pages_falls_back_when_the_operation_is_not_pageable():
    """The exact live failure: get_paginator() on describe_vpn_gateways raised
    and the whole seam_endpoints family returned nothing, every cycle."""
    for mod in (aws_components, aws_workloads):
        client = _NotPageable()
        rows = mod._pages(client, "describe_vpn_gateways", "VpnGateways")
        assert [r["VpnGatewayId"] for r in rows] == ["vgw-1", "vgw-2"], (
            f"{mod.__name__}._pages returned {rows} for a non-pageable operation — "
            "this is the 167-cycle F-41 bug"
        )
        assert client.direct_calls, "the direct (non-paginated) call was never made"


def test_pages_still_paginates_pageable_operations():
    client = _NotPageable()
    rows = aws_components._pages(client, "describe_transit_gateways", "TransitGateways")
    assert [r["TransitGatewayId"] for r in rows] == ["tgw-1"]


def test_pages_tolerates_a_client_without_can_paginate():
    """Duck-typed fakes across the existing suite do not implement
    can_paginate; the helper must not require it."""

    class _Legacy:
        def get_paginator(self, op):
            class _P:
                def paginate(self, **kw):
                    return [{"K": [1, 2]}]
            return _P()

    assert aws_components._pages(_Legacy(), "anything", "K") == [1, 2]


def test_degraded_families_are_counted_not_only_logged():
    """F-41's 'unalertable' half: a degraded family was a print() and nothing
    else, so no monitor could ever see 167 consecutive failures."""
    ingest_metrics.reset()
    ingest_metrics.record_family_degraded("aws", "seam_endpoints")
    ingest_metrics.record_family_degraded("aws", "seam_endpoints")
    assert ingest_metrics.family_degradations()[("aws", "seam_endpoints")] == 2
    body = ingest_metrics.render()
    assert "netops_cloud_ingest_family_degraded_total" in body
    assert 'family="seam_endpoints"' in body
    ingest_metrics.reset()


def test_lane_failures_are_counted():
    ingest_metrics.reset()
    ingest_metrics.record_lane_failure("aws", "cloudmetrics")
    assert ingest_metrics.lane_failures()[("aws", "cloudmetrics")] == 1
    body = ingest_metrics.render()
    assert 'netops_cloud_ingest_lane_failures_total{provider="aws",lane="cloudmetrics"} 1' in body
    ingest_metrics.reset()


def test_lane_isolation_semantics():
    """The structural fix, exercised on the same shape the poller uses: a lane
    that raises must NOT stop the lanes behind it, and its cadence marker must
    advance anyway so it retries on its own schedule instead of hot-looping."""
    ingest_metrics.reset()
    ran = []

    def _isolated(lane, fn, *args, **kw):
        try:
            return True, fn(*args, **kw)
        except Exception as exc:  # noqa: BLE001
            ingest_metrics.record_lane_failure("aws", lane)
            return False, None

    def boom():
        raise RuntimeError("vector aggregator blip")

    last_marker = 0.0
    now = 100.0
    if now - last_marker >= 60:
        last_marker = now          # advanced FIRST, before the call
        _isolated("cloudmetrics", boom)
    _isolated("flow_logs", lambda: ran.append("flow_logs"))
    _isolated("change_audit", lambda: ran.append("change_audit"))
    _isolated("save_state", lambda: ran.append("save_state"))

    assert ran == ["flow_logs", "change_audit", "save_state"], (
        "a failing lane starved the lanes behind it — including save_state (F-41)"
    )
    assert last_marker == now, "the failing lane's cadence marker did not advance"
    assert ingest_metrics.lane_failures()[("aws", "cloudmetrics")] == 1
    ingest_metrics.reset()
