# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Tracker 397: SD-WAN control-session direction (stage [1], owner 2026-11-28).

The cEDGE-80 drill (2026-11-25 23:23:32Z, `clear sdwan control connections`)
recorded what vManage really sends: the CONTROLLERS report the lost sessions
(system_ip = vSmart 10.255.255.2 / vManage 10.255.255.1) and name the EDGE as the
peer. Read as-is, the two controllers counted as two "edges" that lost
"controller 10.255.255.80", the stage [6] fan-in fired, and the engine headlined
`sdwan-controller-unreachable` for one edge's own outage.

The fix is a stage [1] delta in the Go connector (nms/control_session.go): a
controller-reported session is emitted edge-centred — ON the edge, naming the
controller it lost. No engine code changes. What is pinned here, on the golden
the production Go transform + runtime produced from the recorded events
(nms/source_parity_golden_test.go keeps it current):

* the recorded drill replays to an object headlined by the EDGE-side reading,
  located on the edge, with no controller-unreachable headline;
* the shape the connector used to emit (controllers as the entities) is what
  produced the misattribution — kept as a regression witness;
* a real controller outage — many edges each losing the SAME controller, in the
  connector's new shape — still headlines `sdwan-controller-unreachable`.
"""
from __future__ import annotations

import copy
import json
import os
from datetime import datetime, timedelta

from catalog import SDWAN_CONTROLLER_UNREACHABLE_TEMPLATE_ID, builtin_catalog
from controller_events import controller_event_to_signal
from engine import EngineConfig, run_window
from signals import controller_peer

HERE = os.path.dirname(os.path.abspath(__file__))
GOLDEN = os.path.join(HERE, "..", "backend", "nms", "testdata", "source_parity",
                      "vmanage_20.6.control_connection_drill.controller_events.json")
CAT = builtin_catalog()
CONTROLLER = SDWAN_CONTROLLER_UNREACHABLE_TEMPLATE_ID
LOCAL = "sig.ent.wan-edge.sdwan-control-connection-loss"
EDGE = "cedge-80-b0afc197"
VSMART, VMANAGE = "10.255.255.2", "10.255.255.1"


def recorded() -> list[dict]:
    with open(GOLDEN, encoding="utf-8") as fh:
        return json.load(fh)


def _signals(events: list[dict]):
    out = []
    for ev in events:
        ts = datetime.fromisoformat(ev["event_time"].replace("Z", "+00:00"))
        sig = controller_event_to_signal(ev, ts + timedelta(seconds=5))
        assert sig is not None, ev["event_id"]
        out.append(sig)
    return out


def _headlines(events: list[dict]):
    snaps = run_window(_signals(events), CAT, (), EngineConfig())
    return snaps, [s.ranking.top_hypothesis for s in snaps]


def _as_reported(ev: dict) -> dict:
    """The shape the connector emitted before the fix: the reporting controller
    as the entity, the edge as its peer, peer_type = the edge's word."""
    old = copy.deepcopy(ev)
    hints = old["correlation_hints"]
    ctrl = hints["reported_by"]
    old["device_id"] = ctrl
    old["peer_id"] = "10.255.255.80"
    for k in ("controller_device_id", "controller_peer_id", "reported_by", "session_direction"):
        hints.pop(k, None)
    hints["system_ip"] = ctrl
    hints["peer_type"] = "vedge"
    return old


def test_the_golden_is_edge_centred():
    evs = recorded()
    assert len(evs) == 4
    for ev in evs:
        assert ev["device_id"] == EDGE
        assert ev["correlation_hints"]["session_direction"] == "edge_lost_controller"
    peers = {controller_peer(s) for s in _signals(evs)
             if s.kind == "controller_control_connection_loss"}
    assert peers == {(VSMART, "vsmart"), (VMANAGE, "vmanage")}, \
        "the edge names each controller it lost by its system-ip and role"


def test_the_recorded_drill_headlines_the_edge_side_reading():
    snaps, heads = _headlines(recorded())
    assert CONTROLLER not in heads, heads
    obj = next(s for s in snaps if s.ranking.top_hypothesis == LOCAL)
    entities = {n.entity_id for n in obj.nodes}
    assert entities == {EDGE}, f"the fault location is the edge, got {entities}"


def test_the_old_shape_was_the_misattribution():
    """Regression witness: the pre-fix shape (controllers as entities) is what
    made two controllers look like two edges losing one controller."""
    _snaps, heads = _headlines([_as_reported(ev) for ev in recorded()])
    assert CONTROLLER in heads, heads


def test_a_real_controller_outage_still_headlines_controller_unreachable():
    """Five edges each lose the SAME vSmart, emitted in the connector's
    edge-centred shape (the drill's own rows, re-addressed per edge)."""
    base = next(ev for ev in recorded()
                if ev["normalized_event_type"] == "controller_control_connection_loss"
                and ev["correlation_hints"]["reported_by"] == VSMART)
    t0 = datetime.fromisoformat(base["event_time"].replace("Z", "+00:00"))
    evs = []
    for i in range(5):
        ev = copy.deepcopy(base)
        native = f"10.255.255.{20 + i}"
        ev["device_id"] = f"vedge-{20 + i}-0000{i}"
        ev["event_id"] = f"outage-{i}"
        ev["dedupe_key"] = f"i-parity:outage-{i}"
        ev["event_time"] = (t0 + timedelta(seconds=2 * i)).isoformat()
        ev["correlation_hints"]["controller_device_id"] = native
        ev["correlation_hints"]["system_ip"] = native
        evs.append(ev)
    _snaps, heads = _headlines(evs)
    assert CONTROLLER in heads, heads
