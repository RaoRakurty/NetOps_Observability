"""Seam-lane tests (#105 P0/P1) — run with: python3 -m pytest test_seams.py

Covers the prompt's regression demands that live in this layer:
  * AWS per-tunnel state comes from VgwTelemetry — the aggregate fractional
    TunnelState metric is structurally never read, and redundant tunnels are
    distinct keys (one down ≠ VPN down).
  * TGW blackhole vs no-route drops remain DISTINCT kinds.
  * A stale "up" becomes unknown, never an eternal up.
  * Repeated identical samples emit nothing (idempotent); transitions dedup.
  * Counter resets never fabricate negative/spike deltas.
  * Route-count materiality uses expected context (1000→900 and 3→2 both
    material; 1000→995 not).
"""
from __future__ import annotations

import seam_aws
from seam_state import SeamStateTracker, counter_delta, material_route_drop

T0 = "2026-07-14T22:00:00Z"
T1 = "2026-07-14T22:02:00Z"
T2 = "2026-07-14T22:04:00Z"


def test_tracker_emits_transitions_not_repeats():
    tr = SeamStateTracker()
    assert tr.observe("k", "up", T0, 0.0) == []          # first sight: baseline, silent
    assert tr.observe("k", "up", T1, 120.0) == []        # repeat: nothing
    evs = tr.observe("k", "down", T2, 240.0)
    assert len(evs) == 1 and evs[0]["from"] == "up" and evs[0]["to"] == "down"
    assert evs[0]["observed_at"] == T2                    # provider observation time


def test_tracker_flap_detection():
    tr = SeamStateTracker()
    tr.observe("k", "up", T0, 0.0)
    tr.observe("k", "down", T0, 10.0)
    tr.observe("k", "up", T0, 20.0)
    evs = tr.observe("k", "down", T0, 30.0)
    assert any(e.get("flap") for e in evs)                # 3 transitions in window


def test_stale_up_becomes_unknown():
    tr = SeamStateTracker()
    tr.observe("k", "up", T0, 0.0)
    evs = tr.expire(freshness_s=300, now=301.0)
    assert len(evs) == 1 and evs[0]["to"] == "unknown" and evs[0]["from"] == "up"
    assert tr.current("k") == "unknown"
    assert tr.expire(freshness_s=300, now=700.0) == []    # only once per episode


def test_tracker_survives_persistence_roundtrip():
    tr = SeamStateTracker()
    tr.observe("k", "up", T0, 0.0)
    tr2 = SeamStateTracker.from_state(tr.to_state())
    assert tr2.observe("k", "up", T1, 60.0) == []         # no re-announce after restart
    assert len(tr2.observe("k", "down", T2, 120.0)) == 1


def test_counter_delta_reset_handling():
    assert counter_delta(None, 5) == 5
    assert counter_delta(5, 9) == 4
    assert counter_delta(9, 3) == 3                       # reset → absolute, never negative


def test_material_route_drop_uses_expected_context():
    assert material_route_drop(1000, 900)                 # 10% loss
    assert not material_route_drop(1000, 995)             # noise
    assert material_route_drop(3, 2)                      # small-table loss matters
    assert material_route_drop(7, 0)                      # to zero always material
    assert not material_route_drop(None, 5)               # no baseline → no claim
    assert not material_route_drop(5, 9)


# ── AWS lane ──────────────────────────────────────────────────────────────────

SEAMS = {
    "vpn": [{
        "vpn_id": "vpn-0abc", "tgw_id": "tgw-1", "vgw_id": "", "cgw_id": "cgw-9",
        "tunnels": [
            {"outside_ip": "52.0.0.1", "status": "up", "status_message": "", "accepted_routes": 4},
            {"outside_ip": "52.0.0.2", "status": "down", "status_message": "IPSEC IS DOWN", "accepted_routes": 0},
        ],
    }],
    "dx_vifs": [{
        "vif_id": "dxvif-7", "connection_id": "dxcon-3", "vif_state": "available",
        "peers": [{"peer_id": "p1", "address_family": "ipv4", "bgp_status": "up", "peer_address": "169.254.0.1"}],
    }],
    "dx_connections": [{"connection_id": "dxcon-3", "state": "available", "bandwidth": "1Gbps", "hosted": False}],
    "tgws": [{"tgw_id": "tgw-1"}], "nats": [{"nat_id": "nat-5"}],
}


def test_vpn_tunnels_are_distinct_keys_never_aggregate():
    tr = SeamStateTracker()
    seam_aws.seam_state_events(SEAMS, tr, 0.0, T0)  # baseline
    # tunnel 2 recovers; tunnel 1 stays up — exactly ONE transition, for the
    # right tunnel key. The fractional-aggregate trap cannot occur: keys are
    # per-outside-ip and the aggregate metric is never consulted.
    seams2 = {**SEAMS, "vpn": [{**SEAMS["vpn"][0], "tunnels": [
        {"outside_ip": "52.0.0.1", "status": "up", "status_message": "", "accepted_routes": 4},
        {"outside_ip": "52.0.0.2", "status": "up", "status_message": "", "accepted_routes": 4},
    ]}]}
    evs = seam_aws.seam_state_events(seams2, tr, 120.0, T1)
    assert len(evs) == 1
    assert evs[0]["kind"] == "cloud_vpn_tunnel_up"
    assert evs[0]["attrs"]["tunnel_ip"] == "52.0.0.2"
    assert evs[0]["attrs"]["vpn_id"] == "vpn-0abc"


def test_route_collapse_while_tunnel_up_is_route_change_not_outage():
    tr = SeamStateTracker()
    prev, cur = {}, {}
    seam_aws.seam_state_events(SEAMS, tr, 0.0, T0, prev, cur)   # baseline: t1 up w/ 4 routes
    assert cur["vpnroutes:vpn-0abc:52.0.0.1"] == 4
    seams2 = {**SEAMS, "vpn": [{**SEAMS["vpn"][0], "tunnels": [
        {"outside_ip": "52.0.0.1", "status": "up", "status_message": "", "accepted_routes": 0},
        SEAMS["vpn"][0]["tunnels"][1],
    ]}]}
    evs = seam_aws.seam_state_events(seams2, tr, 120.0, T1, cur, {})
    drops = [e for e in evs if e["kind"] == "cloud_route_count_drop"]
    assert len(drops) == 1
    assert drops[0]["attrs"]["evidence_class"] == "route_change"
    assert drops[0]["attrs"]["tunnel_ip"] == "52.0.0.1"
    assert drops[0]["attrs"]["previous"] == "4"
    # and no tunnel-down was fabricated: the session stayed up
    assert not [e for e in evs if e["kind"] == "cloud_vpn_tunnel_down"]


def test_route_drop_on_down_tunnel_stays_silent():
    # tunnel 2 is DOWN with 0 routes; collapse must not double-report as a
    # route fault (the down transition owns that story), and no-baseline → no claim.
    tr = SeamStateTracker()
    prev, cur = {}, {}
    seam_aws.seam_state_events(SEAMS, tr, 0.0, T0, prev, cur)
    evs = seam_aws.seam_state_events(SEAMS, tr, 120.0, T1, cur, {})
    assert [e for e in evs if e["kind"] == "cloud_route_count_drop"] == []


def test_dx_bgp_down_transition_carries_native_ids():
    tr = SeamStateTracker()
    seam_aws.seam_state_events(SEAMS, tr, 0.0, T0)
    seams2 = {**SEAMS, "dx_vifs": [{**SEAMS["dx_vifs"][0], "peers": [
        {"peer_id": "p1", "address_family": "ipv4", "bgp_status": "down", "peer_address": "169.254.0.1"}]}]}
    evs = seam_aws.seam_state_events(seams2, tr, 120.0, T1)
    kinds = {e["kind"] for e in evs}
    assert "cloud_bgp_session_down" in kinds
    ev = [e for e in evs if e["kind"] == "cloud_bgp_session_down"][0]
    assert ev["attrs"]["vif_id"] == "dxvif-7"
    assert ev["attrs"]["connection_id"] == "dxcon-3"
    assert ev["attrs"]["address_family"] == "ipv4"
    assert ev["severity"] == "crit"


class _FakeCW:
    """GetMetricData fake: blackhole and no-route on the same TGW."""
    def get_metric_data(self, MetricDataQueries, StartTime, EndTime, ScanBy):
        import datetime as dt
        ts = dt.datetime(2026, 7, 14, 22, 0, tzinfo=dt.timezone.utc)
        out = []
        for q in MetricDataQueries:
            name = q["MetricStat"]["Metric"]["MetricName"]
            if name == "PacketDropCountBlackhole":
                out.append({"Id": q["Id"], "Values": [12.0], "Timestamps": [ts]})
            elif name == "PacketDropCountNoRoute":
                out.append({"Id": q["Id"], "Values": [3.0], "Timestamps": [ts]})
            else:
                out.append({"Id": q["Id"], "Values": [], "Timestamps": []})
        return {"MetricDataResults": out}


def test_blackhole_and_noroute_stay_distinct_kinds():
    _, signals, _ = seam_aws.poll_seam_metrics(_FakeCW(), SEAMS, {})
    kinds = {s["kind"]: s for s in signals}
    assert "cloud_gateway_blackhole_drop" in kinds and "cloud_gateway_no_route_drop" in kinds
    assert kinds["cloud_gateway_blackhole_drop"]["value"] == 12.0
    assert kinds["cloud_gateway_no_route_drop"]["value"] == 3.0
    assert kinds["cloud_gateway_blackhole_drop"]["attrs"]["evidence_class"] == "forwarding_drop"


def test_absent_metric_values_emit_nothing():
    seams = {"tgws": [], "nats": [{"nat_id": "nat-5"}], "dx_connections": []}
    events, signals, _ = seam_aws.poll_seam_metrics(_FakeCW(), seams, {})
    assert events == [] and signals == []                 # absence ≠ zero
