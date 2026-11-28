# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""ENGINE_SEMVER 3.9.0 — owner decisions 2026-11-25, items 7–10.

  [1] controller-relayed CPU / memory thresholds join the resource dwell, on EVENT
      time (resource_dwell.py §3; nms/vmanage_kinds.go maps them).
  [3] the storm backlog-age arm ignores evidence old on arrival (main.backlog_age_s).
  [4] the path-hop hub cap (path_graph.CORR_PATH_HOP_HUB_CAP).
  [6] sig.ent.wan-edge.sdwan-controller-resource-sustained.

Lab shapes (7 days, 2026-11-25): vManage polls every 5 min (events arrive 280 s
late on average); its cpu-usage events flap raise → "back to normal" in ~4 s; vBond
(10.255.255.3) stood above its threshold for 976 s once; the prober reaches every
edge through vEdge-20 (7 of 8 path observations).
"""
from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

import engine as E
import main
import path_graph as PG
from catalog import SDWAN_CONTROLLER_RESOURCE_TEMPLATE_ID, builtin_catalog
from controller_events import controller_event_to_signal
from engine import EngineConfig, run_window
from path_graph import PathGraphView, PathIndex, hub_hops
from resource_dwell import HOLD, PASS, ResourceDwell, threshold_resource
from signals import (
    CLAUSE_ATTR_KEYS,
    EntityType,
    ModalityClass,
    Observer,
    ObserverType,
    Severity,
    Signal,
    Source,
)

T0 = datetime(2026, 11, 25, 5, 43, 6, tzinfo=timezone.utc)
TENANT = "t_lab"
VBOND = "10.255.255.3"
VMANAGE_OBS = "vmanage:nmsi-668f5b96d5ce7857"
RAISE, CLEAR = "device_resource_anomaly", "device_resource_anomaly_clear"


class Clock:
    def __init__(self) -> None:
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t


def _ctl(kind: str, off: float, *, sev: Severity = Severity.HIGH, eid: str = VBOND,
         resource: str = "cpu", role: str = "controller", n: int = 0,
         obs: str = VMANAGE_OBS, tenant: str = TENANT) -> Signal:
    attrs: dict = {"event_type": "cpu-usage"}
    if resource:
        attrs["resource"] = resource
    if role:
        attrs["node_role"] = role
    return Signal(
        tenant_id=tenant, ts=T0 + timedelta(seconds=off), source=Source.CONTROLLER, kind=kind,
        observer=Observer(observer_id=obs, observer_type=ObserverType.CONTROLLER,
                          collection_path="via_controller"),
        modality_class=ModalityClass.MANAGEMENT_PLANE, entity_type=EntityType.DEVICE,
        entity_id=eid, severity=Severity.INFO if kind == CLEAR else sev,
        native_id=f"39|{eid}|{kind}|{off}|{n}", entity_tokens=(eid,), attrs=attrs)


def _tick(dwell: ResourceDwell, other_off: float, n: int = 0) -> None:
    """Another device's event in the same poll: advances the lane watermark."""
    dwell.observe(_ctl("controller_alarm", other_off, eid="10.255.255.1", resource="", n=n))


def _feed(dwell: ResourceDwell, sig: Signal) -> str:
    dwell.observe(sig)
    return dwell.admit(sig, sig.entity_id)


# ── [1] stage-[1] lift of the connector's hints ──────────────────────────────

def _event(kind: str, hints: dict) -> dict:
    return {"tenant_id": TENANT, "normalized_event_type": kind, "source_system": "vmanage",
            "integration_id": "nmsi-1", "device_id": VBOND, "severity": "high",
            "event_type": "cpu-usage", "event_id": "e1", "event_time": T0.isoformat(),
            "correlation_hints": hints}


def test_controller_event_lifts_resource_and_node_role_closed_vocabulary():
    s = controller_event_to_signal(_event(RAISE, {"resource": "CPU", "node_role": "controller"}), T0)
    assert s is not None and s.attrs["resource"] == "cpu" and s.attrs["node_role"] == "controller"
    assert threshold_resource(s) == "cpu"
    clr = controller_event_to_signal(_event(CLEAR, {"resource": "memory", "node_role": "edge"}), T0)
    assert clr is not None and clr.attrs["resource"] == "memory" and clr.attrs["node_role"] == "edge"
    # Out of vocabulary states nothing (fail-closed): no threshold, no role.
    bad = controller_event_to_signal(_event(RAISE, {"resource": "disk", "node_role": "router"}), T0)
    assert bad is not None and "resource" not in bad.attrs and "node_role" not in bad.attrs
    assert threshold_resource(bad) is None
    # `resource` only for the resource kind; node_role for any kind.
    other = controller_event_to_signal(_event("controller_alarm", {"resource": "cpu", "node_role": "edge"}), T0)
    assert other is not None and "resource" not in other.attrs and other.attrs["node_role"] == "edge"
    assert "node_role" in CLAUSE_ATTR_KEYS


# ── [1] the polled dwell on event time ───────────────────────────────────────

def test_a_controller_flap_split_across_two_polls_is_suppressed():
    # Raise at the end of one poll, its clear 4 s later in the NEXT poll, 300 s of
    # arrival apart: the arrival clock would release it; event time suppresses it.
    clk = Clock()
    g = ResourceDwell(dwell_s=300, clock=clk, polled=True, poll_margin_s=120)
    assert _feed(g, _ctl(RAISE, 0)) == HOLD
    clk.t += 300
    assert g.due() == []
    assert _feed(g, _ctl(CLEAR, 4)) == PASS
    _tick(g, 900)
    clk.t += 1000
    assert g.due() == [] and g.polled_suppressed == 1


def test_the_arrival_clock_would_have_released_that_flap():
    # The 3.8.0 arrival dwell on the same delivery (the defect 3.9.0 removes).
    clk = Clock()
    g = ResourceDwell(dwell_s=300, clock=clk)
    trap_like = replace(_ctl(RAISE, 0), source=Source.TRAP)
    assert g.admit(trap_like, VBOND) == HOLD
    clk.t += 301
    assert len(g.due()) == 1


def test_a_clear_delivered_before_its_raise_still_suppresses_it():
    # vManage returns a poll newest-first: the clear can arrive before its raise.
    clk = Clock()
    g = ResourceDwell(dwell_s=300, clock=clk, polled=True, poll_margin_s=120)
    assert _feed(g, _ctl(CLEAR, 4)) == PASS
    assert _feed(g, _ctl(RAISE, 0)) == HOLD
    _tick(g, 900)
    clk.t += 1000
    assert g.due() == [] and g.polled_suppressed == 1 and g.pending_count() == 0


def test_a_lab_shaped_poll_of_flaps_releases_nothing():
    # vBond's real rhythm: a raise and its clear every ~66 s, a whole poll at once.
    clk = Clock()
    g = ResourceDwell(dwell_s=300, clock=clk, polled=True, poll_margin_s=120)
    for i in range(30):
        _feed(g, _ctl(CLEAR, i * 66 + 4, n=i))      # newest-first within the poll
        _feed(g, _ctl(RAISE, i * 66, sev=Severity.CRIT, n=i))
    _tick(g, 30 * 66 + 600)
    clk.t += 2000
    assert g.due() == [] and g.polled_suppressed == 30


def _sustained_976s(g: ResourceDwell, clk: Clock) -> list[Signal]:
    """vBond, 2026-11-25 05:43:06: high raise, no clear for 976 s (then a crit
    re-raise at 972 s and the clear at 976 s), delivered across polls."""
    out: list[Signal] = []
    assert _feed(g, _ctl(RAISE, 0, sev=Severity.HIGH, n=1)) == HOLD
    for poll in range(1, 4):                       # three later polls, other devices only
        clk.t += 300
        _tick(g, poll * 300 - 20, n=poll)
        out += g.due()
    return out


def test_a_976s_sustained_vbond_raise_is_released_once_at_its_proof_time():
    clk = Clock()
    g = ResourceDwell(dwell_s=300, clock=clk, polled=True, poll_margin_s=120)
    out = _sustained_976s(g, clk)
    assert len(out) == 1 and g.polled_released == 1
    rel = out[0]
    raw = _ctl(RAISE, 0, sev=Severity.HIGH, n=1)
    assert rel.signal_id == raw.signal_id                 # stored identity kept
    assert rel.attrs["dwell_onset"] == T0.isoformat()     # its own onset named
    # Stamped no earlier than onset + dwell, no later than the lane proves.
    assert T0 + timedelta(seconds=300) <= rel.ts <= T0 + timedelta(seconds=580 - 120)
    # The condition stands: the crit re-raise at 972 s passes; the clear ends it.
    assert _feed(g, _ctl(RAISE, 972, sev=Severity.CRIT, n=2)) == PASS
    assert _feed(g, _ctl(CLEAR, 976)) == PASS
    assert _feed(g, _ctl(RAISE, 1004, n=3)) == HOLD       # a fresh condition waits again


def test_a_clear_past_the_dwell_proves_it_stood_even_in_one_poll():
    clk = Clock()
    g = ResourceDwell(dwell_s=300, clock=clk, polled=True, poll_margin_s=120)
    assert _feed(g, _ctl(CLEAR, 976)) == PASS             # newest-first
    assert _feed(g, _ctl(RAISE, 0)) == HOLD
    assert g.due() == []                                   # settle: same poll still arriving
    clk.t += 31
    out = g.due()
    assert len(out) == 1 and g.polled_stood_released == 1
    assert T0 + timedelta(seconds=300) <= out[0].ts <= T0 + timedelta(seconds=976)


def test_a_silent_lane_releases_fail_open_and_counts_it():
    clk = Clock()
    g = ResourceDwell(dwell_s=300, clock=clk, polled=True, poll_margin_s=120)
    _feed(g, _ctl(RAISE, 0))
    clk.t += 300 + 120 + 599
    assert g.due() == []
    clk.t += 2
    assert len(g.due()) == 1 and g.polled_stall_released == 1


def test_lanes_and_tenants_never_share_a_watermark():
    clk = Clock()
    g = ResourceDwell(dwell_s=300, clock=clk, polled=True, poll_margin_s=120)
    _feed(g, _ctl(RAISE, 0))
    # Another integration's and another tenant's clocks race ahead: not ours.
    g.observe(_ctl("controller_alarm", 5000, eid="x", resource="", obs="vmanage:other"))
    g.observe(_ctl("controller_alarm", 5000, eid="x", resource="", tenant="t_other"))
    clk.t += 100
    assert g.due() == []
    _tick(g, 421)
    assert len(g.due()) == 1


def test_polled_kill_switch_is_3_8_0(monkeypatch):
    monkeypatch.setenv("CORR_RESOURCE_DWELL_POLLED", "0")
    g = ResourceDwell(dwell_s=300, clock=Clock())
    assert g.polled is False
    assert _feed(g, _ctl(RAISE, 0)) == PASS and g.pending_count() == 0
    assert threshold_resource(_ctl(RAISE, 0), polled=False) is None


def test_trap_and_syslog_keep_the_arrival_clock():
    clk = Clock()
    g = ResourceDwell(dwell_s=300, clock=clk, polled=True)
    trap = replace(_ctl(RAISE, 0), source=Source.TRAP,
                   observer=Observer(observer_id=VBOND, observer_type=ObserverType.DEVICE))
    assert g.admit(trap, VBOND) == HOLD
    clk.t += 301
    out = g.due()
    assert out == [trap] and out[0].ts == trap.ts          # 3.8.0 path: own ts, untouched


def test_polled_metric_lines_and_health():
    g = ResourceDwell(dwell_s=300, clock=Clock(), polled=True)
    assert 'corr_resource_dwell_polled_total{outcome="suppressed"} 0' in g.metric_lines()
    h = g.health()
    assert h["polled"] is True and h["poll_margin_s"] == 120 and h["polled_pending"] == 0


def test_polled_state_is_bounded():
    clk = Clock()
    g = ResourceDwell(dwell_s=300, max_groups=3, clock=clk, polled=True)
    for i in range(10):
        _feed(g, _ctl(CLEAR, i, eid=f"c{i}", n=i))
        _feed(g, _ctl(RAISE, 100 + i, eid=f"d{i}", n=i))
        g.observe(_ctl("controller_alarm", i, eid="x", resource="", obs=f"o{i}"))
    assert len(g._ppending) <= 3 and len(g._clears) <= 3 and len(g._lane_wm) <= 3
    assert g.overflow_released == 7                        # released early, never dropped
    assert len(g.due()) == 7


# ── [1] wired at the window entry ────────────────────────────────────────────

@pytest.fixture
def wired(monkeypatch):
    clk = Clock()
    monkeypatch.setattr(main, "RESOURCE_DWELL",
                        ResourceDwell(dwell_s=300, clock=clk, polled=True, poll_margin_s=120))
    main.WINDOW_BUFFER.clear()
    main._BUFFERED_IDS.clear()
    main._BUFFERED_ID_ORDER.clear()
    yield clk
    main.WINDOW_BUFFER.clear()
    main._BUFFERED_IDS.clear()
    main._BUFFERED_ID_ORDER.clear()


def _now_ctl(kind: str, off: float, **kw) -> Signal:
    s = _ctl(kind, 0, **kw)
    return replace(s, ts=datetime.now(timezone.utc) + timedelta(seconds=off - 600))


def test_buffer_signal_holds_a_controller_raise_and_releases_it_on_the_lane_clock(wired):
    clk = wired
    raise_ = _now_ctl(RAISE, 0, n=1)
    main.buffer_signal(raise_)
    assert list(main.WINDOW_BUFFER) == []
    main.buffer_signal(_now_ctl("controller_alarm", 430, eid="10.255.255.1", resource="", n=2))
    clk.t += 31
    assert main.release_resource_dwell() == 1
    out = main.WINDOW_BUFFER[-1]
    assert out.kind == RAISE and out.signal_id == raise_.signal_id
    assert out.ts >= raise_.ts + timedelta(seconds=300)


# ── [6] the controller-resource template ─────────────────────────────────────

def test_a_released_sustained_controller_raise_opens_one_object_topped_by_the_template():
    clk = Clock()
    g = ResourceDwell(dwell_s=300, clock=clk, polled=True, poll_margin_s=120)
    rel = _sustained_976s(g, clk)
    snaps = run_window(rel, builtin_catalog(), (), EngineConfig())
    assert len(snaps) == 1
    top = snaps[0].ranking.hypotheses[0]
    assert top.template_id == SDWAN_CONTROLLER_RESOURCE_TEMPLATE_ID
    assert snaps[0].ranking.top_hypothesis == SDWAN_CONTROLLER_RESOURCE_TEMPLATE_ID


def test_an_edges_sustained_cpu_never_reads_as_the_controller_template():
    edge = _ctl(RAISE, 0, eid="cedge-40-fdf7b64f", role="edge")
    snaps = run_window([edge], builtin_catalog(), (), EngineConfig())
    ids = {h.template_id for s in snaps for h in s.ranking.hypotheses}
    assert SDWAN_CONTROLLER_RESOURCE_TEMPLATE_ID not in ids
    unstated = _ctl(RAISE, 0, eid="cedge-40-fdf7b64f", role="")
    ids = {h.template_id for s in run_window([unstated], builtin_catalog(), (), EngineConfig())
           for h in s.ranking.hypotheses}
    assert SDWAN_CONTROLLER_RESOURCE_TEMPLATE_ID not in ids


def test_a_controller_flap_opens_nothing_end_to_end():
    clk = Clock()
    g = ResourceDwell(dwell_s=300, clock=clk, polled=True, poll_margin_s=120)
    window: list[Signal] = []
    for i in range(10):
        for s in (_ctl(CLEAR, i * 66 + 4, n=i), _ctl(RAISE, i * 66, sev=Severity.CRIT, n=i)):
            if _feed(g, s) == PASS:
                window.append(s)
    _tick(g, 2000)
    clk.t += 3000
    window += g.due()
    assert all(s.kind == CLEAR for s in window)
    assert run_window(window, builtin_catalog(), (), EngineConfig()) == []


# ── [3] the storm backlog arm ignores evidence old on arrival ────────────────

def _syslog(off: float, n: int = 0) -> Signal:
    return Signal(
        tenant_id=TENANT, ts=T0 + timedelta(seconds=off), source=Source.SYSLOG,
        kind="link_state_change",
        observer=Observer(observer_id="vEdge-20", observer_type=ObserverType.DEVICE),
        modality_class=ModalityClass.CONTROL_PLANE, entity_type=EntityType.INTERFACE,
        entity_id="vedge-20:ge0/1", severity=Severity.HIGH, native_id=f"39|sys|{off}|{n}",
        entity_tokens=("vedge-20",))


def _onset_episode(off: float) -> Signal:
    s = _syslog(off)
    return replace(s, source=Source.METRIC, kind="if_errors",
                   native_id=f"39|ep|{off}", attrs={"phase": "onset"})


def test_backlog_age_ignores_polled_and_onset_evidence(monkeypatch):
    monkeypatch.setattr(main, "CORR_STORM_BACKLOG_EXCLUDE_LAGGING", True)
    live = _syslog(600)
    polled = _ctl(RAISE, 300)                 # a vManage event 300 s old on arrival
    onset = _onset_episode(200)                # an episode stamped at its CUSUM onset
    window = [polled, onset, live]
    assert main.backlog_age_s([polled, onset, live], window) == 0.0
    assert main.backlog_age_s([polled, onset], window) == 0.0
    behind = _syslog(400, n=1)                 # a live signal the engine is behind on
    assert main.backlog_age_s([polled, behind], window + [behind]) == 200.0
    assert main._storm_state.__name__          # the arm's consumer is unchanged


def test_backlog_age_kill_switch_is_3_8_0(monkeypatch):
    monkeypatch.setattr(main, "CORR_STORM_BACKLOG_EXCLUDE_LAGGING", False)
    live, polled = _syslog(600), _ctl(RAISE, 300)
    assert main.backlog_age_s([polled, live], [polled, live]) == 300.0


def test_a_syslog_only_backlog_is_measured_exactly_as_before(monkeypatch):
    # The t-storm-2.5k rig is SYSLOG-ONLY (scripts/scale-miniladder.py injects into
    # netops.syslog): no signal it produces is polled or onset-stamped, so the arm's
    # input — and the storm declaration — is the 3.8.0 formula, value for value.
    monkeypatch.setattr(main, "CORR_STORM_BACKLOG_EXCLUDE_LAGGING", True)
    sigs = [_syslog(i * 7.5, n=i) for i in range(200)]
    pend = sigs[:150]
    newest = max(s.ts.timestamp() for s in sigs)
    old = max(0.0, newest - min(s.ts.timestamp() for s in pend))
    assert main.backlog_age_s(pend, sigs) == old
    assert not any(main.lagging_on_arrival(s) for s in sigs)


def test_lagging_on_arrival_reads_instance_suffixed_paths():
    s = _ctl(RAISE, 0)
    inst = replace(s, observer=Observer(
        observer_id="aws:1", observer_type=ObserverType.CLOUD_API, collection_path="via_cloud_api:i-1"))
    assert main.lagging_on_arrival(s) and main.lagging_on_arrival(inst)
    assert not main.lagging_on_arrival(_syslog(0))


# ── [4] the path-hop hub cap ─────────────────────────────────────────────────

EDGES = ("cedge-80-b0afc197", "cedge-60-07ae8615", "cedge-40-fdf7b64f", "vedge-52-bf77ee2c",
         "vedge-51-79fbba30", "vedge-100-3efc4148", "cedge-81-dde8d64d")
HUB = "vedge-20-02efdcad"


def _hop(i: int, ref: str, addr: str) -> dict:
    return {"hop_index": i, "state": "responding", "observed_address": addr,
            "resolved_entity_ref": ref, "resolution_method": "hop_inventory" if ref else "unresolved",
            "confidence": "authoritative" if ref else "unknown", "transformation": "none",
            "evidence_ref": f"pv-{i}-{ref or addr}", "observed_at": T0.isoformat(), "tenant_id": TENANT}


def _lab_paths(tenant: str = TENANT) -> PathGraphView:
    """The lab prober's 8 observations (path_graph.json, 2026-11-25): every edge
    through the docker gateway and vEdge-20; one path ends AT vEdge-20."""
    obs = []
    for k, dst in enumerate((*EDGES, None)):
        hops = [_hop(1, "", "172.18.0.1"), _hop(2, HUB, "192.168.172.2")]
        if dst:
            hops.append(_hop(3, dst, f"10.0.{k}.1"))
        obs.append({"observation_id": f"ob-{k}", "path_id": f"pd-{k}", "tenant_id": tenant,
                    "observed_at": T0.isoformat(), "method": "traceroute_icmp",
                    "vantage_id": "prober", "status": "complete", "hops": hops,
                    "definition": {"path_id": f"pd-{k}", "tenant_id": tenant,
                                   "dst_endpoint_ref": f"ep-{k}", "vantage_id": "prober",
                                   "network_context": "default"}})
    return PathGraphView.from_dict({"observations": obs, "freshness_s": 900})


def _dev(kind: str, eid: str, off: float, *, sev: Severity = Severity.HIGH,
         path_id: str | None = None, src: Source = Source.TRAP) -> Signal:
    return Signal(
        tenant_id=TENANT, ts=T0 + timedelta(seconds=off), source=src, kind=kind,
        observer=Observer(observer_id=eid.split(":")[0], observer_type=ObserverType.DEVICE),
        modality_class=ModalityClass.CONTROL_PLANE, entity_type=EntityType.DEVICE,
        entity_id=eid, severity=sev, native_id=f"39|{kind}|{eid}|{off}",
        entity_tokens=(f"tok-{eid}",), path_id=path_id)


def test_the_lab_gateway_hop_is_a_hub_and_no_destination_is():
    view = _lab_paths()
    hubs = hub_hops(view.observations, 3)
    # vEdge-20 is transit on 7 paths to 7 distinct destinations; the unresolved
    # docker gateway on all 8. Destinations are never hubs (they are last hops).
    assert {oid: idx for oid, idx in hubs.items()} == {
        f"ob-{k}": frozenset({1, 2}) for k in range(7)} | {"ob-7": frozenset({1})}
    assert hub_hops(view.observations, 7) == {f"ob-{k}": frozenset({1}) for k in range(8)}
    assert hub_hops(view.observations, 0) == {}


def test_re_observations_and_protocols_count_one_destination():
    view = _lab_paths()
    one = [o for o in view.observations if o.observation_id in ("ob-0", "ob-1")]
    # The same two destinations re-observed 5 times: still a fan-out of 2.
    again = [replace(o, observation_id=f"{o.observation_id}-{i}")
             for o in one for i in range(5)]
    assert hub_hops(again, 2) == {}
    assert hub_hops(again, 1) != {}


def _relate(idx: PathIndex, a: Signal, b: Signal):
    na, nb = (E.build_nodes([s])[0] for s in (a, b))
    return idx.relate(na.identity_refs(), nb.identity_refs(), na.window(), nb.window(),
                      na.declared_path_ids(), nb.declared_path_ids())


def test_the_hub_no_longer_relates_to_everything_behind_it():
    view = _lab_paths()
    cpu = _dev(RAISE, HUB, 0)
    bgp = _dev("bgp_adjacency_change", "cedge-81-dde8d64d:10.255.255.2", 30)
    assert _relate(PathIndex(view, TENANT, hub_cap=0), cpu, bgp) is not None    # 3.8.0: welded
    before = PG.path_hop_hub_skipped_total()
    assert _relate(PathIndex(view, TENANT, hub_cap=3), cpu, bgp) is None
    assert PG.path_hop_hub_skipped_total() > before


def test_a_signal_about_the_path_still_grounds_to_the_hub():
    view = _lab_paths()
    cpu = _dev(RAISE, HUB, 0)
    probe = Signal(
        tenant_id=TENANT, ts=T0 + timedelta(seconds=20), source=Source.PROBE, kind="probe_loss",
        observer=Observer(observer_id="prober", observer_type=ObserverType.VANTAGE_AGENT),
        modality_class=ModalityClass.ACTIVE_PROBE, entity_type=EntityType.PATH,
        entity_id="prober->cedge-81-dde8d64d", severity=Severity.HIGH, native_id="39|probe",
        entity_tokens=("cedge-81-dde8d64d",), path_id="pd-6")
    rel = _relate(PathIndex(view, TENANT, hub_cap=3), cpu, probe)
    assert rel is not None and rel.ref == "ob-6"


def test_hops_below_the_hub_still_relate():
    # Two nodes on one observation, neither at the hub hop: unchanged.
    view = _lab_paths()
    idx = PathIndex(view, TENANT, hub_cap=3)
    edge = _dev(RAISE, "cedge-81-dde8d64d", 0)
    gw = _dev(RAISE, "172.18.0.1", 10)
    # the gateway is a hub too (unresolved, all 8): only declared paths reach it
    assert _relate(idx, edge, gw) is None
    view2 = _lab_paths()
    lone = PathIndex(PathGraphView(observations=tuple(
        o for o in view2.observations if o.observation_id == "ob-6")), TENANT, hub_cap=3)
    assert _relate(lone, _dev(RAISE, HUB, 0), edge) is not None   # one path: no hub


def test_the_rolling_blob_splits_end_to_end():
    view = _lab_paths()
    window = [
        _dev(RAISE, HUB, 0, sev=Severity.CRIT),
        _dev("bgp_adjacency_change", "cedge-81-dde8d64d:10.255.255.2", 30),
        _dev("link_state_change", "cedge-40-fdf7b64f:GigabitEthernet1", 60),
        _dev("bgp_adjacency_change", "vedge-51-79fbba30:10.255.255.1", 90),
    ]
    saved = PG.CORR_PATH_HOP_HUB_CAP
    try:
        PG.CORR_PATH_HOP_HUB_CAP = 0
        off = run_window(window, builtin_catalog(), (), EngineConfig(), paths=view)
        PG.CORR_PATH_HOP_HUB_CAP = 3
        on = run_window(window, builtin_catalog(), (), EngineConfig(), paths=view)
    finally:
        PG.CORR_PATH_HOP_HUB_CAP = saved
    assert len(off) == 1 and len(off[0].nodes) == 4          # 3.8.0: one rolling object
    assert len(on) == 4 and all(len(s.nodes) == 1 for s in on)


def test_hub_cap_off_is_byte_identical():
    view = _lab_paths()
    window = [_dev(RAISE, HUB, 0, sev=Severity.CRIT),
              _dev("bgp_adjacency_change", "cedge-81-dde8d64d:10.255.255.2", 30)]
    saved = PG.CORR_PATH_HOP_HUB_CAP
    try:
        PG.CORR_PATH_HOP_HUB_CAP = 0
        a = [s.content_hash() for s in run_window(window, builtin_catalog(), (), EngineConfig(), paths=view)]
        # 0 never computes a hub, so memberships carry no flag: the 3.8.0 path.
        assert PathIndex(view, TENANT)._hub_hops == {}
        b = [s.content_hash() for s in run_window(window, builtin_catalog(), (), EngineConfig(), paths=view)]
    finally:
        PG.CORR_PATH_HOP_HUB_CAP = saved
    assert a == b


def test_hubs_are_counted_per_tenant():
    mine = _lab_paths()
    theirs = _lab_paths("t_other")
    both = PathGraphView(observations=mine.observations + theirs.observations, freshness_s=900)
    assert PathIndex(both, TENANT, hub_cap=3)._hub_hops == PathIndex(mine, TENANT, hub_cap=3)._hub_hops
    # A tenant with only two paths through the same hop has no hub, whatever another has.
    two = PathGraphView(observations=tuple(o for o in theirs.observations
                                           if o.observation_id in ("ob-0", "ob-1")) + mine.observations)
    assert PathIndex(two, "t_other", hub_cap=3)._hub_hops == {}


def test_hub_metric_lines():
    lines = PG.path_hop_hub_metric_lines()
    assert lines[1] == "# TYPE corr_path_hop_hub_skipped_total counter"
    assert f"corr_path_hop_hub_cap {PG.CORR_PATH_HOP_HUB_CAP}" in lines


# ── one semver ───────────────────────────────────────────────────────────────

def test_engine_semver():
    assert E.ENGINE_SEMVER == "3.9.0"
