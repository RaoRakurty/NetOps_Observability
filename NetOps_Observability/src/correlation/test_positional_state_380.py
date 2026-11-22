# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Tracker 380 PR 2 — `up` is a POSITIONAL claim (stage [1], parser only).

The OSPF, generic routing, link and VTEP syslog rows used to scan the WHOLE
message for an up/down word, so "%OSPF-5-ADJCHG ... from FULL to EXSTART" read
as `up` (it contains FULL): an adjacency LOSS reached the engine as a recovery.
They now classify the state a transition goes TO; a line with no transition
phrase keeps the whole-message scan. The rows whose `up` was the else-branch
now match up explicitly and default to `unknown`.

Line shapes are the vendors' documented formats (synthetic, labelled), plus the
lab's recorded IOS link lines.
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

import producers as P

TENANT = "t_lab"
INGEST = datetime(2026, 11, 22, 12, 0, tzinfo=timezone.utc)


def _syslog(message: str, appname: str | None = None, host: str = "10.0.0.1"):
    tag = appname or message.split(":", 1)[0]
    return P.syslog_control_signal({"appname": tag, "facility": "local7", "hostname": host,
                                    "message": message, "timestamp": "2026-11-22T11:59:00Z"},
                                   TENANT, INGEST)


def _state(message: str, appname: str | None = None) -> tuple[str, str]:
    """(base kind, state). This file pins the STATE a line reads; since tracker 380
    PR 3 an up is reported as `<kind>_clear`, which test_recovery_clears_380 pins."""
    sig = _syslog(message, appname)
    assert sig is not None, message
    return sig.kind.removesuffix("_clear"), sig.attrs.get("state", "")


# (line, appname, kind, state)
OSPF = [
    # Cisco IOS / IOS-XE: the documented ADJCHG shape, every transition target.
    ("%OSPF-5-ADJCHG: Process 1, Nbr 10.0.0.2 on GigabitEthernet1 from FULL to DOWN, Neighbor Down: Dead timer expired",
     None, "down"),
    ("%OSPF-5-ADJCHG: Process 1, Nbr 10.0.0.2 on GigabitEthernet1 from LOADING to FULL, Loading Done",
     None, "up"),
    # The defect: a pre-Full target was read as up because the line contains FULL.
    ("%OSPF-5-ADJCHG: Process 1, Nbr 10.0.0.2 on GigabitEthernet1 from FULL to EXSTART, SeqNumberMismatch",
     None, "down"),
    ("%OSPF-5-ADJCHG: Process 1, Nbr 10.0.0.2 on GigabitEthernet1 from FULL to EXCHANGE, BadLSReq",
     None, "down"),
    ("%OSPF-5-ADJCHG: Process 1, Nbr 10.0.0.2 on GigabitEthernet1 from FULL to LOADING, Exchange Done",
     None, "down"),
    ("%OSPF-5-ADJCHG: Process 1, Nbr 10.0.0.2 on GigabitEthernet1 from FULL to INIT, 1-Way",
     None, "down"),
    # 2WAY: the steady state between two DROTHERs — claims neither loss nor recovery.
    ("%OSPF-5-ADJCHG: Process 1, Nbr 10.0.0.2 on GigabitEthernet1 from FULL to 2WAY, Neighbor Down: Adjacency forced to reset",
     None, "unknown"),
    # IOS XR
    ("%ROUTING-OSPF-5-ADJCHG : Process 1, Nbr 10.0.0.2 on GigabitEthernet0/0/0/0 in area 0 from FULL to DOWN, Neighbor Down: interface down or detached",
     "ROUTING-OSPF-5-ADJCHG", "down"),
    # NX-OS
    ("%OSPF-5-ADJCHANGE: ospf-1 [5678] Nbr 10.0.0.2 on Ethernet1/1 went DOWN", None, "down"),
    ("%OSPF-5-ADJCHANGE: ospf-1 [5678] Nbr 10.0.0.2 on Ethernet1/1 went FULL", None, "up"),
]


@pytest.mark.parametrize("line,app,want", OSPF)
def test_ospf_reads_the_state_the_neighbour_went_to(line, app, want):
    kind, state = _state(line, app)
    assert kind == "ospf_adjacency_change"
    assert state == want, line


LINK = [
    # Cisco IOS (lab-recorded shapes)
    ("%LINK-3-UPDOWN: Interface GigabitEthernet2, changed state to down", None, "down"),
    ("%LINK-3-UPDOWN: Interface GigabitEthernet2, changed state to up", None, "up"),
    ("%LINEPROTO-5-UPDOWN: Line protocol on Interface GigabitEthernet2, changed state to down", None, "down"),
    ("%LINK-5-CHANGED: Interface GigabitEthernet2, changed state to administratively down", None, "down"),
    # A description that says "up" no longer decides a down line.
    ("%LINK-3-UPDOWN: Interface GigabitEthernet2 (uplink-to-core), changed state to down", None, "down"),
    # An unclassifiable target claims nothing.
    ("%LINK-3-UPDOWN: Interface GigabitEthernet2, changed state to testing", None, "unknown"),
]


@pytest.mark.parametrize("line,app,want", LINK)
def test_link_reads_the_state_the_port_changed_to(line, app, want):
    kind, state = _state(line, app)
    assert kind == "link_state_change"
    assert state == want, line


def test_the_generic_routing_row_reads_its_target_too():
    kind, state = _state("%RIB-5-ADJCHANGE: neighbor 10.0.0.2 from ESTABLISHED to IDLE, reset by peer")
    assert (kind, state) == ("routing_adjacency_change", "down")
    kind, state = _state("%RIB-5-ADJCHANGE: neighbor 10.0.0.2 from IDLE to ESTABLISHED")
    assert (kind, state) == ("routing_adjacency_change", "up")


def test_a_line_with_no_transition_phrase_keeps_the_whole_scan():
    # The documented IOS BGP-like shape with no "to": unchanged behaviour.
    kind, state = _state("%RIB-5-ADJCHANGE: neighbor 10.0.0.2 Down")
    assert (kind, state) == ("routing_adjacency_change", "down")


def test_the_isis_row_is_unchanged():
    kind, state = _state("%CLNS-5-ADJCHANGE: ISIS: Adjacency to R2 (GigabitEthernet1) Up, new adjacency")
    assert kind == "isis_adjacency_change"  # base kind (380: the up itself is a clear)
    assert state == "up"


def test_stp_lldp_fhrp_rows_are_not_touched():
    # Pinned unchanged: STP forwarding and LLDP neighbour adds are not recoveries,
    # and these rows still read exactly what they read before.
    sig = _syslog("%SPANTREE-2-ROOTGUARD_BLOCK: Root guard blocking port GigabitEthernet1/0/1 on VLAN0010.")
    assert sig is None or sig.kind != "link_state_change"
