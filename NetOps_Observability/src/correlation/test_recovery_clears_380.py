# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Tracker 380 PR 3 — device-lane recoveries are clears (stage [1] only).

Controller lanes, and the SD-WAN/resource trap rows, reported a recovery as
`<kind>_clear`, which `build_nodes` skips. The device lanes reported the FAULT
kind with `state=up` at warn — a live node. Templates key on kind only
(CLAUSE_ATTR_KEYS is `{link_cause}`), so a recovery alone satisfied fault
templates: an up beside a CPU episode CONFIRMED "BGP peer flap", a linkUp after a
reboot headlined "local link fault" on the lab (2026-11-18, cEDGE-40).

Now the 32 device-lane link/adjacency rows declare `emit.clear_when` and an up is
`<kind>_clear` at info: same entity, tokens, native_id and attrs, so the same
signal_id. No catalog, gate or constant moved; ENGINE_SEMVER stays 3.6.0.
"""
from __future__ import annotations

import importlib.util
import pathlib
from datetime import datetime, timedelta, timezone

import pytest

import aggregation
import engine as E
import producers as P
from catalog import builtin_catalog
from engine import run_window
from proactive import ProactiveMonitor

TENANT = "t1"
T0 = datetime(2026, 11, 22, 12, 0, tzinfo=timezone.utc)
SIX = ("link_state_change", "bgp_adjacency_change", "ospf_adjacency_change",
       "isis_adjacency_change", "routing_adjacency_change", "vtep_state_change")
HERE = pathlib.Path(__file__).resolve().parent


def _syslog(message: str, *, at: int = 0, host: str = "edge-1"):
    tag = message.split(":", 1)[0].lstrip("%")
    ts = (T0 + timedelta(seconds=at)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    return P.syslog_control_signal({"appname": tag, "facility": "local7", "hostname": host,
                                    "message": message, "timestamp": ts}, TENANT, T0)


# ── stage [1]: the emission ───────────────────────────────────────────────────

@pytest.mark.parametrize("down,up,kind", [
    ("%LINK-3-UPDOWN: Interface GigabitEthernet2, changed state to down",
     "%LINK-3-UPDOWN: Interface GigabitEthernet2, changed state to up", "link_state_change"),
    ("%BGP-5-ADJCHANGE: neighbor 10.0.0.9 Down Interface flap",
     "%BGP-5-ADJCHANGE: neighbor 10.0.0.9 Up", "bgp_adjacency_change"),
    ("%OSPF-5-ADJCHG: Process 1, Nbr 10.0.0.2 on Gi1 from FULL to DOWN, Neighbor Down: Dead timer expired",
     "%OSPF-5-ADJCHG: Process 1, Nbr 10.0.0.2 on Gi1 from LOADING to FULL, Loading Done",
     "ospf_adjacency_change"),
])
def test_an_up_is_a_clear_on_the_same_entity_as_its_down(down, up, kind):
    d, u = _syslog(down), _syslog(up)
    assert (d.kind, d.severity.value, d.attrs["state"]) == (kind, "high", "down")
    assert (u.kind, u.severity.value, u.attrs["state"]) == (f"{kind}_clear", "info", "up")
    assert u.entity_id == d.entity_id
    assert u.entity_tokens == d.entity_tokens


def test_the_clear_keeps_the_up_lines_native_id_and_signal_id():
    """The only fields that move are kind and severity: native_id (and therefore
    signal_id = uuid5(source|native_id|ts)) is the one the up line always had."""
    u = _syslog("%LINK-3-UPDOWN: Interface GigabitEthernet2, changed state to up")
    assert "|up|" in u.native_id
    rebuilt = P.Signal(
        tenant_id=u.tenant_id, ts=u.ts, source=u.source, kind="link_state_change",
        observer=u.observer, modality_class=u.modality_class, entity_type=u.entity_type,
        entity_id=u.entity_id, severity=P.Severity.WARN, native_id=u.native_id,
        entity_tokens=u.entity_tokens, metric_name=u.metric_name, attrs=dict(u.attrs))
    assert rebuilt.signal_id == u.signal_id


def test_every_device_lane_row_that_can_say_up_declares_the_clear():
    """The ratchet: no rule emitting one of the six kinds may let an `up` out as the
    fault kind. A new row without `clear_when` fails here."""
    missing = sorted(r.rule_id for r in P.RULES
                     if r.emit is not None and r.emit.kind in SIX
                     and r.state != "down" and r.emit.clear_when is None)
    assert not missing, f"rows that would emit an up as a live fault node: {missing}"


def test_no_corpus_output_is_a_fault_kind_with_state_up():
    import json
    corpus = HERE / "fixtures" / "parser_golden_corpus.jsonl"
    bad = []
    for line in corpus.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        for out in json.loads(line)["out"].values():
            if out and out.get("kind") in SIX and out.get("state") == "up":
                bad.append(out["kind"])
    assert not bad, f"{len(bad)} recorded up outputs are still fault kinds"


# ── stages [5]–[7]: what the engine now concludes ─────────────────────────────

def test_a_lone_recovery_opens_nothing():
    up = _syslog("%LINK-3-UPDOWN: Interface GigabitEthernet2, changed state to up")
    assert run_window([up], builtin_catalog(), ()) == []


def test_a_recovery_no_longer_props_up_a_below_floor_alarm():
    """The lab's 85aabaf7 shape: one link up (warn) grounded to two below-floor
    device alarms opened an object headlined local-link-fault. The up is a clear
    now, so there is no node to ground and nothing opens."""
    up = _syslog("%LINK-3-UPDOWN: Interface GigabitEthernet2, changed state to up", at=0)
    objs = run_window([up], builtin_catalog(), ())
    assert objs == []
    assert all(n.kind != "link_state_change"
               for o in objs for n in o.nodes)


def test_a_reboot_followed_by_link_ups_has_no_link_fault_headline():
    """The 2026-11-18 cEDGE-40 shape: links coming back after a restart, with no
    link down at all. Before 380 the ups made `local-link-fault` the headline."""
    sigs = [_syslog(f"%LINK-3-UPDOWN: Interface Tunnel{i}, changed state to up", at=i)
            for i in (1, 2)]
    sigs.append(_syslog("%LINEPROTO-5-UPDOWN: Line protocol on Interface GigabitEthernet1, "
                        "changed state to up", at=3))
    for o in run_window(sigs, builtin_catalog(), ()):
        assert o.ranking.top_hypothesis != "sig.ent.access.local-link-fault"
        assert all(n.kind != "link_state_change" for n in o.nodes)


def test_a_flap_is_still_read_from_its_downs():
    """down → up → down → up: the downs carry the flap. One node, two downs; the
    ups never become evidence."""
    lines = [("%BGP-5-ADJCHANGE: neighbor 10.0.0.9 Down Interface flap", 0),
             ("%BGP-5-ADJCHANGE: neighbor 10.0.0.9 Up", 20),
             ("%BGP-5-ADJCHANGE: neighbor 10.0.0.9 Down Interface flap", 40),
             ("%BGP-5-ADJCHANGE: neighbor 10.0.0.9 Up", 60)]
    sigs = [_syslog(m, at=t) for m, t in lines]
    nodes = E.build_nodes(sigs)
    bgp = [n for n in nodes if n.kind == "bgp_adjacency_change"]
    assert len(bgp) == 1
    assert [s.attrs["state"] for s in bgp[0].signals] == ["down", "down"]
    assert not [n for n in nodes if n.kind.endswith("_clear")]


# ── the wiring that keyed on the kind ─────────────────────────────────────────

def test_the_aggregation_identity_folds_a_clear_onto_its_base_kind():
    d = _syslog("%LINK-3-UPDOWN: Interface GigabitEthernet2, changed state to down")
    u = _syslog("%LINK-3-UPDOWN: Interface GigabitEthernet2, changed state to up", at=5)
    assert aggregation.ident_key(u) == aggregation.ident_key(d)
    # Only the six: another lane's clear keeps its own identity.
    assert aggregation.identity_kind("if_metric_anomaly_clear") == "if_metric_anomaly_clear"
    assert aggregation.AGG_POLICY_VERSION == "p3.k3.v2"


def test_the_outage_chain_harness_folds_the_same_six():
    path = HERE.parent.parent / "scripts" / "enterprise_outage_chain.py"
    spec = importlib.util.spec_from_file_location("eoc380", path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    assert mod.RECOVERY_CLEAR_BASE == aggregation.RECOVERY_CLEAR_BASE


def test_a_recovery_clear_still_clears_the_proactive_watch():
    """The dwell watch is keyed on the base kind; main passes `kind` with the
    `_clear` suffix removed, and the up resets the watch."""
    plane = ProactiveMonitor()
    kw = {"tenant": TENANT, "entity_id": "edge-1", "observer_id": "edge-1", "peer": "10.0.0.9"}
    plane.observe_signal(kind="bgp_adjacency_change", state="down", ts=T0, **kw)
    plane.observe_signal(kind="bgp_adjacency_change_clear".removesuffix("_clear"),
                         state="up", ts=T0 + timedelta(seconds=30), **kw)
    # Long after the dwell, nothing fires: the up cleared the watch.
    fired = plane.observe_signal(kind="bgp_adjacency_change", state="up",
                                 ts=T0 + timedelta(hours=2), **kw)
    assert all(ev.phase != "onset" for ev in fired)


def test_main_reads_the_base_kind_where_it_keyed_on_the_fault_kind():
    src = (HERE / "main.py").read_text(encoding="utf-8")
    assert 'sig.kind.removesuffix("_clear") == "bgp_adjacency_change"' in src
    assert 'kind=sig.kind.removesuffix("_clear")' in src
    assert 'kind=cp_sig.kind.removesuffix("_clear")' in src


def test_the_engine_did_not_move():
    # Tracker 380 moved no engine constant; 3.7.0 (2026-11-24) is a later change.
    assert E.ENGINE_SEMVER == "3.7.0"
