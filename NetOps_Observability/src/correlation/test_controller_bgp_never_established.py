# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Tracker 387 on the controller lane (P-424934, 2026-11-11).

Owner rule: only an ESTABLISHED session going down is a session failure. The trap
lane already obeys it (producers.trap_control_signal, test_trap_semantics_387.py).
The controller lane did not: vManage's `bgp-peer-state-change` to idle/active for
a neighbour that never came up (`peer-routerid=0.0.0.0`) became seven `high`
`bgp_adjacency_change` signals on cEDGE-81, and the exposure story used them as
its corroborating network fault (P-424934, test_exposure_story_cap_p424934.py).

Stage [1] now: the connector stamps the transition's class with the trap
receiver's own classifier (internal/bgpfsm, pinned to
collectors/testdata/bgp_transition_classes.json) into
`correlation_hints.bgp_transition_class`; `handle_controller_event` still writes
the corr_signals row, and a never_established / progressing down never enters
the window and is counted (`corr_controller_bgp_not_session_failure_total`).
Absent, "unknown" or session_lost leaves the reading as it was.
"""
from __future__ import annotations

import asyncio
import json
import os
from datetime import datetime, timezone

import pytest

import controller_events as CE
import main
import producers as P
from catalog import builtin_catalog
from controller_events import bgp_not_a_session_failure, controller_event_to_signal
from scoring import rank
from verdicts import VerdictTier

HERE = os.path.dirname(os.path.abspath(__file__))
GOLDEN = os.path.join(HERE, "..", "backend", "nms", "testdata", "source_parity",
                      "vmanage_20.6.controller_events.json")
INGEST = datetime(2026, 11, 1, 17, 5, 0, tzinfo=timezone.utc)
DEVICE = "ctl-vmanage-bfa81d722501"
PEER = "192.168.200.34"


def run(coro):
    return asyncio.run(coro)


async def _noop():
    return None


def recorded() -> list[dict]:
    """The lab's recorded vManage reports, through the production Go transform
    (nms/source_parity_golden_test.go keeps this file current)."""
    with open(GOLDEN, encoding="utf-8") as fh:
        return json.load(fh)


def event(state: str, cls: str | None, *, rid: str = "0.0.0.0", eid: str = "e-1",
          tenant: str = "RETAIL-WALMART") -> dict:
    hints = {"component": "VPN", "system_ip": "10.255.255.81"}
    if cls is not None:
        hints["bgp_transition_class"] = cls
        hints["bgp_transition_basis"] = "peer_routerid_unset"
    return {
        "tenant_id": tenant, "integration_id": "i-lab", "source_system": "vmanage",
        "vendor": "cisco", "event_id": eid, "event_time": "2026-11-11T09:00:00Z",
        "event_type": "bgp-peer-state-change",
        "normalized_event_type": "bgp_adjacency_change", "severity": "high",
        "device_id": DEVICE, "device_name": "cEDGE-81", "peer_id": PEER,
        "message": (f"bgp-peer-state-change host-name=cEDGE-81; peer={PEER}; "
                    f"bgp-new-state={state}; peer-routerid={rid}; vpn-id=200"),
        "correlation_hints": hints,
    }


@pytest.fixture
def lane(monkeypatch):
    """handle_controller_event with corr_signals and the window captured, the
    controller counter zeroed, and an empty registry (an API-only device keeps
    the producer's claim)."""
    rows: list[dict] = []
    window: list = []
    monkeypatch.setattr(main, "ch", object())
    monkeypatch.setattr(main, "CORR_SIGNALS_ENABLED", True)
    monkeypatch.setattr(main, "_tenant_registry", dict)

    async def _batch(row):
        rows.append(row)

    monkeypatch.setattr(main, "batch_signal", _batch)
    monkeypatch.setattr(main, "buffer_signal", window.append)
    monkeypatch.setattr(CE, "BGP_NOT_A_SESSION_FAILURE", {k: 0 for k in CE.BGP_NOT_A_SESSION_FAILURE})
    return rows, window


def test_the_classes_are_the_trap_lanes():
    assert set(CE.BGP_NOT_A_SESSION_FAILURE) == set(P.BGP_NOT_A_SESSION_FAILURE)
    assert set(CE.BGP_NOT_A_SESSION_FAILURE) < P.BGP_TRANSITION_CLASSES


def test_the_recorded_reports_follow_the_peer_history_not_the_router_id():
    """One poll of the lab's idle <-> active neighbour, with no memory from an
    earlier poll. The FIRST report has no prior report: peer-routerid 0.0.0.0
    decides nothing (IOS clears it on teardown, so a real drop looks the same),
    so it is unknown and reads as a down. Every later report follows a
    below-established one and is never_established."""
    evs = sorted((e for e in recorded() if e["normalized_event_type"] == "bgp_adjacency_change"),
                 key=lambda e: e["event_time"])
    assert len(evs) == 4
    got = []
    for ev in evs:
        assert "peer-routerid=0.0.0.0" in ev["message"]
        assert ev["correlation_hints"]["bgp_peer_routerid"] == "unset"
        sig = controller_event_to_signal(ev, INGEST)
        assert sig is not None and sig.kind == "bgp_adjacency_change"
        got.append(bgp_not_a_session_failure(sig))
    assert got == ["", "never_established", "never_established", "never_established"], \
        [e["correlation_hints"] for e in evs]


@pytest.mark.parametrize("cls", ["never_established", "progressing"])
def test_a_never_established_down_is_kept_counted_and_never_windowed(lane, cls):
    rows, window = lane
    run(main.handle_controller_event(event("idle", cls)))
    assert window == [], "a session that never came up is not a session failure"
    assert len(rows) == 1 and rows[0]["kind"] == "bgp_adjacency_change", \
        "raw evidence is never dropped: corr_signals keeps the report"
    assert CE.BGP_NOT_A_SESSION_FAILURE[cls] == 1
    assert (f'corr_controller_bgp_not_session_failure_total{{class="{cls}"}} 1'
            in main._metrics_text())


@pytest.mark.parametrize("cls", [None, "", "unknown", "session_lost", "bogus"])
def test_anything_else_reads_as_before(lane, cls):
    """A genuine drop (session_lost), a report that cannot tell (unknown), an
    older connector (no hint) and an out-of-vocabulary value all still reach
    the window."""
    rows, window = lane
    run(main.handle_controller_event(event("idle", cls, rid="10.9.9.9")))
    assert len(rows) == 1 and len(window) == 1
    assert window[0].kind == "bgp_adjacency_change"
    assert window[0].entity_id == f"{DEVICE}:{PEER}"
    assert sum(CE.BGP_NOT_A_SESSION_FAILURE.values()) == 0


def test_only_bgp_reads_the_hint(lane):
    _rows, window = lane
    ev = {**event("down", "never_established"), "normalized_event_type": "ospf_adjacency_change"}
    run(main.handle_controller_event(ev))
    assert len(window) == 1 and window[0].kind == "ospf_adjacency_change"


def test_a_clear_is_untouched(lane):
    _rows, window = lane
    ev = {**event("established", "session_up", rid="10.9.9.9"),
          "normalized_event_type": "bgp_adjacency_change_clear", "severity": "info"}
    run(main.handle_controller_event(ev))
    assert len(window) == 1 and window[0].kind == "bgp_adjacency_change_clear"


def test_the_incident_window_carries_no_bgp_session_failure(lane):
    """P-424934's seven reports, as the connector now stamps them: none reaches
    the window, so nothing there can be read as the exposure story's fault."""
    rows, window = lane
    for i, st in enumerate(("idle", "active", "idle", "active", "idle", "active", "idle")):
        run(main.handle_controller_event(event(st, "never_established", eid=f"e-{i}")))
    assert window == [] and len(rows) == 7
    assert CE.BGP_NOT_A_SESSION_FAILURE["never_established"] == 7


def test_the_suppressed_reports_were_what_the_story_leaned_on():
    """Without the BGP reports the exposure story keeps only the interface
    anomaly as its network clause, and is still capped (belt and braces: the two
    fixes are independent)."""
    from test_exposure_story_cap_p424934 import incident
    sigs = [s for s in incident() if s.kind != "bgp_adjacency_change"]
    res = rank(builtin_catalog(), sigs)
    assert res.verdict_tier is not VerdictTier.CONFIRMED
