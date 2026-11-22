# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Tracker 382: a syslog BGP line that names an IPv6 neighbour carries its peer.

The syslog BGP rows read the peer as the first IPv4 address in the message, so an
IPv6 session had no peer and P6 D1 left it device-level, never meeting the trap
and controller reports of the same session. An ORDERED second alternative now
reads an IPv6 literal anchored on the vendor's keyword; the IPv4 alternative stays
first, so every IPv4 line reads exactly what it read before.

The lines are SYNTHETIC, run through the production parser: each vendor's
documented IPv4 shape (events.yaml header notes, test_canon_identity_p6.py) with
an IPv6 literal. There is no IPv6 BGP session on the lab."""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

import producers as P
from canon import REWRITTEN, canonicalize
from test_canon_identity_p6 import CEDGE81_MGMT, DEVICE, TENANT, _lab

INGEST = datetime(2026, 11, 21, 12, 0, 0, tzinfo=timezone.utc)


def _syslog(message: str, appname: str | None = None, host: str = CEDGE81_MGMT):
    tag = appname or message.split(":", 1)[0]
    return P.syslog_control_signal({"appname": tag, "facility": "local7", "hostname": host,
                                    "message": message, "timestamp": "2026-11-21T11:59:00Z"},
                                   TENANT, INGEST)


# (line, appname override, peer as written, canonical peer, state)
IPV6_LINES = [
    # Cisco IOS / IOS-XE
    ("%BGP-5-ADJCHANGE: neighbor 2001:DB8:0:CC00::1 Down Interface flap", None,
     "2001:DB8:0:CC00::1", "2001:db8:0:cc00::1", "down"),
    ("%BGP-5-ADJCHANGE: neighbor 2001:DB8::2 vpn vrf CUST-A Up", None,
     "2001:DB8::2", "2001:db8::2", "up"),
    # IOS XR
    (("%ROUTING-BGP-5-ADJCHANGE : neighbor 2001:db8::2 Down - Peer closing down the session"
      " (VRF: default) (AS: 65001)"), None, "2001:db8::2", "2001:db8::2", "down"),
    # NX-OS
    ("%BGP-5-ADJCHANGE: bgp-65000 [4321] (default) neighbor 2001:db8:10::5 Up", None,
     "2001:db8:10::5", "2001:db8:10::5", "up"),
    # Arista EOS
    (("%BGP-5-ADJCHANGE: peer 2001:db8::9 (VRF default AS 65001) old state Established"
      " event RecvNotify new state Idle"), None, "2001:db8::9", "2001:db8::9", "down"),
]


@pytest.mark.parametrize("line,app,raw,canon_peer,state", IPV6_LINES)
def test_ipv6_adjacency_line_carries_its_peer(line, app, raw, canon_peer, state):
    sig = _syslog(line, app)
    assert sig is not None, line
    # Tracker 380: an up line is the recovery clear; the peer it names is the same.
    assert sig.kind == ("bgp_adjacency_change_clear" if state == "up" else "bgp_adjacency_change")
    assert sig.attrs.get("peer") == raw
    assert sig.attrs.get("state") == state


@pytest.mark.parametrize("line,app,raw,canon_peer,state", IPV6_LINES)
def test_ipv6_session_binds_the_session_node(line, app, raw, canon_peer, state):
    """P6 D1 now binds `<device>:<compressed peer>`: the node the trap and the
    controller report the same session on."""
    out, outcome = canonicalize(_syslog(line, app), _lab())
    assert outcome == REWRITTEN
    assert out.entity_id == f"{DEVICE}:{canon_peer}"


def test_ipv4_line_reads_exactly_what_it_read_before():
    """The IPv4 alternative is first: a line naming both families keeps the IPv4."""
    sig = _syslog("%BGP-5-ADJCHANGE: neighbor 10.0.0.1 Down Interface flap")
    assert sig.attrs.get("peer") == "10.0.0.1"
    mixed = _syslog("%BGP-5-ADJCHANGE: neighbor 2001:db8::1 Down, router-id 10.9.9.9")
    assert mixed.attrs.get("peer") == "10.9.9.9"


@pytest.mark.parametrize("line", [
    # A notification teardown (tracker 184 shape), Cisco and Junos.
    "%BGP-3-NOTIFICATION: sent to neighbor 2001:db8::7 4/0 (hold time expired) 0 bytes",
    "%BGP-3-NOTIFICATION: received from neighbor 2001:db8::7 6/4 (Administrative Reset) 0 bytes",
])
def test_ipv6_notification_carries_its_peer(line):
    sig = _syslog(line)
    assert sig is not None and sig.attrs.get("peer") == "2001:db8::7", line


@pytest.mark.parametrize("line", [
    # No keyword-anchored address: a time, a bare hex run, an AS path — no peer.
    "%BGP-5-ADJCHANGE: neighbor Down at 12:34:56",
    "%BGP-5-ADJCHANGE: session dead:beef:cafe Down",
    "%BGP-5-ADJCHANGE: peer group EDGE Down",
])
def test_unanchored_hex_is_not_a_peer(line):
    sig = _syslog(line)
    assert sig is not None
    assert not sig.attrs.get("peer"), (line, sig.attrs.get("peer"))


def test_a_non_address_after_the_keyword_stays_host_level():
    """`neighbor ::::` matches the shape but is no address: canon abstains on the
    peer and the signal keeps its device binding, as any unparseable peer did."""
    sig = _syslog("%BGP-5-ADJCHANGE: neighbor :::::: Down")
    out, _outcome = canonicalize(sig, _lab())
    assert out.entity_id == DEVICE
