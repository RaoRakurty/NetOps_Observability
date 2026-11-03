# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""BGP traps name their session by the bgpPeerTable INDEX (2026-11-03).

The original RFC 4273 notifications (bgpBackwardTransition, bgpEstablished)
carry only bgpPeerLastError.<peer> and bgpPeerState.<peer> — the peer is the
row index, not a varbind value. IOS-XE sends exactly that (recorded from the
lab's cEDGE-81, 2026-11-01, below). The rule used to read bgpPeerRemoteAddr
only, so the trap bound the bare device while the controller bound
`device:peer` — the same session as two unrelated nodes (E7, tracker 374).
"""
from __future__ import annotations

from datetime import datetime, timezone

import producers as P

T0 = datetime(2026, 11, 1, 17, 1, tzinfo=timezone.utc)
DEVICE = "cedge-81-11060ae2"
PEER = "192.168.200.34"


def lab_backward_transition(**over) -> dict:
    """cEDGE-81's real bgpBackwardTransition (community and storage fields dropped)."""
    ev = {
        "_signal": "snmptrap", "timestamp": "2026-11-01T17:00:09.997Z",
        "host": "192.168.200.33", "device": DEVICE, "snmp_version": "v2c",
        "authenticated": False, "trap_oid": "1.3.6.1.2.1.15.7.2",
        "trap_name": "bgpBackwardTransition", "event_type": "bgp_backward_transition",
        "severity": "warning",
        "varbinds": [
            {"name": "sysUpTime", "oid": "1.3.6.1.2.1.1.3.0", "value": "70193062"},
            {"name": "bgpPeerLastError", "oid": f"1.3.6.1.2.1.15.3.1.14.{PEER}", "value": "0x0000"},
            {"name": "bgpPeerState", "oid": f"1.3.6.1.2.1.15.3.1.2.{PEER}", "value": "idle(1)"},
        ],
    }
    ev.update(over)
    return ev


def classify(ev: dict):
    return P.trap_control_signal(dict(ev), "t_lab", T0)


def test_the_recorded_trap_binds_the_session_like_the_controller() -> None:
    sig = classify(lab_backward_transition())
    assert sig.kind == "bgp_adjacency_change"
    assert sig.entity_id == f"{DEVICE}:{PEER}", "the same id the controller's bgp-peer-state-change binds"
    assert sig.attrs["peer"] == PEER and sig.attrs["state"] == "down"
    assert f"|{PEER}|" in sig.native_id
    assert PEER in sig.entity_tokens


def test_bgp_peer_remote_addr_still_wins_when_sent() -> None:
    vbs = lab_backward_transition()["varbinds"] + [
        {"name": "bgpPeerRemoteAddr", "oid": "1.3.6.1.2.1.15.3.1.7.10.9.9.9", "value": "10.9.9.9"}]
    assert classify(lab_backward_transition(varbinds=vbs)).attrs["peer"] == "10.9.9.9"


def test_a_non_ipv4_index_is_never_used_as_a_peer() -> None:
    """The index is raw device text: anything but a dotted quad stays out of the
    entity id (the trap then binds the device, as before)."""
    vbs = [{"name": "bgpPeerState", "oid": "1.3.6.1.2.1.15.3.1.2.1.4.10.0.0.1.7", "value": "idle(1)"}]
    sig = classify(lab_backward_transition(varbinds=vbs))
    assert sig.attrs["peer"] == ""
    assert sig.entity_id == DEVICE


def test_the_event_type_rule_never_takes_the_state_value_as_the_peer() -> None:
    """A vendor BGP trap classified off its event_type, carrying the same
    index-only varbinds: `vbname: peer` alone would match bgpPeerState and
    take "idle(1)" as the peer."""
    sig = classify(lab_backward_transition(
        trap_oid="1.3.6.1.4.1.99999.0.1", trap_name="vendorBgpBackwardTransition",
        event_type="vendor_bgp_backward_transition"))
    assert sig.attrs["rule_id"] == "trap.bgp.adjacency_change.event_type"
    assert sig.attrs["peer"] == PEER
    assert sig.entity_id == f"{DEVICE}:{PEER}"
