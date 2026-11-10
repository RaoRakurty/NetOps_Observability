# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Tracker 387 trap semantics, in the catalog (events.yaml): only an ESTABLISHED BGP
session going down is a session failure, and the event_type row names its peer from
the receiver's `bgp.peer_address`.

Values, not presence: each case states the signal it must or must not build.
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

import producers as P

NOW = datetime(2026, 11, 10, 10, 0, tzinfo=timezone.utc)
CBGP = "1.3.6.1.4.1.9.9.187"
PEER2_STATE = f"{CBGP}.1.2.5.1.3.10.0.0.5"      # cbgpPeer2State.<10.0.0.5>
PEER2_PREV = f"{CBGP}.1.2.5.1.29.10.0.0.5"      # cbgpPeer2PrevState.<10.0.0.5>


def _trap(oid: str, varbinds: list[dict], **kw) -> dict:
    return {"device": "leaf1", "trap_oid": oid, "trap_name": "enterpriseSpecific",
            "event_type": "enterprise_specific", "timestamp": "2026-11-10T09:59:00Z",
            "authenticated": False, "varbinds": varbinds, **kw}


def _sig(ev: dict):
    return P.trap_control_signal(ev, "t1", NOW)


def _cbgp(oid_suffix: str, frm: str | None, to: str | None, **kw) -> dict:
    vbs = []
    if to is not None:
        vbs.append({"oid": PEER2_STATE, "value": to})
    if frm is not None:
        vbs.append({"oid": PEER2_PREV, "value": frm})
    return _trap(f"{CBGP}.0.{oid_suffix}", vbs, **kw)


@pytest.mark.parametrize(("suffix", "frm", "to", "extra", "want"), [
    # cbgpPeer2FsmStateChange (.0.7): only a move OUT of established is backward.
    ("7", "6", "1", {}, "down"),
    ("7", "5", "4", {}, None),          # never established: a named alarm, no down
    ("7", "3", "1", {}, None),
    ("7", "5", "6", {}, "up"),
    # backward notifications (.0.8 / .0.6 / .0.2): need no prior state or established...
    ("8", None, "1", {}, "down"),
    ("8", "6", "1", {}, "down"),
    ("8", "3", "1", {}, None),
    ("6", "4", "3", {}, None),
    # ...and the receiver must not class the session as never up or progressing.
    ("8", None, "1", {"bgp": {"transition_class": "never_established"}}, None),
    ("8", None, "1", {"bgp": {"transition_class": "progressing"}}, None),
    ("8", None, "1", {"bgp": {"transition_class": "session_lost"}}, "down"),
    ("2", None, None, {}, "down"),
])
def test_cisco_bgp4_downs_only_an_established_session(suffix, frm, to, extra, want):
    sig = _sig(_cbgp(suffix, frm, to, **extra))
    if want is None:
        assert sig is None or sig.kind != "bgp_adjacency_change", sig and sig.attrs
        return
    assert sig is not None and sig.kind == "bgp_adjacency_change"
    assert sig.attrs["state"] == want


SDWAN_BGP = "1.3.6.1.4.1.41916.100.2.54"


@pytest.mark.parametrize(("event_state", "tclass", "want"), [
    ("raise", "", "down"),
    ("raise", "session_lost", "down"),
    ("raise", "never_established", None),
    ("raise", "progressing", None),
    ("clear", "never_established", "up"),
])
def test_sdwan_bgp_peer_is_gated_on_the_transition_class(event_state, tclass, want):
    ev = _trap(SDWAN_BGP, [{"oid": "1.3.6.1.4.1.41916.100.1.68", "value": "192.0.2.9"}],
               event_state=event_state)
    if tclass:
        ev["bgp"] = {"transition_class": tclass}
    sig = _sig(ev)
    if want is None:
        assert sig is None or sig.kind != "bgp_adjacency_change", sig and sig.attrs
        return
    assert sig is not None and sig.kind == "bgp_adjacency_change"
    assert (sig.attrs["state"], sig.attrs["peer"]) == (want, "192.0.2.9")


ARISTA_BACKWARD = "1.3.6.1.4.1.30065.3.1"


def _vendor_bgp(varbinds: list[dict], **kw) -> dict:
    ev = _trap(ARISTA_BACKWARD, varbinds, **kw)
    ev["event_type"] = "arista_bgp4_v2_backward_transition"
    return ev


def test_the_event_type_row_names_the_peer_the_receiver_named():
    ev = _vendor_bgp([{"oid": "1.3.6.1.4.1.30065.3.1.1.2.1.13.1.1.4.10.0.0.9",
                       "name": "aristaBgp4V2PeerState", "value": "idle(1)"}],
                     bgp={"peer_address": "10.0.0.9"})
    sig = _sig(ev)
    assert sig.kind == "bgp_adjacency_change"
    assert (sig.entity_id, sig.attrs["peer"]) == ("leaf1:10.0.0.9", "10.0.0.9")


def test_a_varbind_merely_named_peer_is_never_the_peer():
    """The bare `peer` substring scan is gone: a state value is not an address."""
    ev = _vendor_bgp([{"oid": "1.3.6.1.4.1.30065.3.1.1.2.1.13.1.1.4.10.0.0.9",
                       "name": "aristaBgp4V2PeerState", "value": "idle(1)"}])
    sig = _sig(ev)
    assert sig.kind == "bgp_adjacency_change"
    assert sig.entity_id == "leaf1" and not sig.attrs.get("peer"), sig.attrs


def test_a_peer_address_column_still_names_the_peer_meanwhile():
    """Until every receiver stamps bgp.peer_address, an address-named column holds."""
    ev = _vendor_bgp([{"oid": "1.3.6.1.4.1.30065.3.1.1.2.1.6", "name": "srlPeerAddr",
                       "value": "10.0.0.9"}])
    assert _sig(ev).entity_id == "leaf1:10.0.0.9"


def test_a_dotted_ev_path_that_is_not_an_object_answers_nothing():
    ev = _vendor_bgp([], bgp="not-an-object")
    assert _sig(ev).entity_id == "leaf1"
