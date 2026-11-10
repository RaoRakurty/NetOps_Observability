# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Tracker 387 §6a wave 1 (Nokia SR OS, Cisco IOS XR / IOS / NX-OS, Junos) and the
tracker 388 syslog link causes, through the engine's real stage [5].

The pack fixtures (telemetry-catalog/test_vendor_packs.py) pin each line's parse and
signal. This file pins what those signals OPEN: a shutdown is a change and opens
nothing, a fault opens, and a cause is stated only where the line states it.
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

import catalog
import engine
import producers as P

NOW = datetime(2026, 11, 9, 10, 0, tzinfo=timezone.utc)


def _signals(docs: list[dict]) -> list:
    sigs = []
    for i, doc in enumerate(docs):
        ev = {"severity": "notice", "appname": "unknown", **doc,
              "timestamp": f"2026-11-09T09:59:{i:02d}Z"}
        ev = {**ev, **P._PACKS.parse(ev)}
        sig = P.syslog_control_signal(ev, "t1", NOW)
        if sig is not None:
            sigs.append(sig)
    return sorted(sigs, key=lambda s: (s.ts, s.signal_id))


def _opened(docs: list[dict]) -> int:
    return len(engine.run_window(tuple(_signals(docs)), catalog.builtin_catalog(), ()))


def _ios(msg: str, **kw: str) -> dict:
    # Stage B's ios_style.v1 fields, which the classic three-part form gets in vector.yaml.
    fac, _sev, mnem = msg[1:msg.index(":")].split("-", 2)
    return {"hostname": "r1", "message": msg, "facility": fac, "event_type": mnem.lower(), **kw}


IOS_SHUTDOWN = [
    _ios("%LINK-5-CHANGED: Interface Gi1, changed state to administratively down"),
    _ios("%LINEPROTO-5-UPDOWN: Line protocol on Interface Gi1, changed state to down"),
]
IOS_FAULT = [
    _ios("%LINK-3-UPDOWN: Interface Gi1, changed state to down", severity="err"),
    _ios("%LINEPROTO-5-UPDOWN: Line protocol on Interface Gi1, changed state to down"),
]


def test_an_ios_shutdown_carries_the_admin_cause_and_opens_nothing():
    sigs = _signals(IOS_SHUTDOWN)
    assert [(s.kind, s.attrs.get("link_cause")) for s in sigs] == [
        ("link_state_change", "admin"), ("link_state_change", None)]
    assert {s.entity_id for s in sigs} == {"r1:Gi1"}, "both lines are one interface node"
    assert _opened(IOS_SHUTDOWN) == 0


def test_an_ios_fault_still_opens_one_object():
    assert _opened(IOS_FAULT) == 1


def test_a_fault_after_a_shutdown_still_opens():
    """Fail-closed (tracker 385): the admin line cannot hide a fault on the same port."""
    assert _opened(IOS_SHUTDOWN + IOS_FAULT) == 1


# IOS XR: the four-part grammar files `CATEGORY-GROUP` as the facility. The fault line
# is napalm-logs' documented one. The protocol line is the IOS text in the XR envelope:
# no XR document shows it, so this is a guard on the severity rule, not a fixture.
XR_FAULT = {"hostname": "gw2", "appname": "ifmgr", "severity": "err",
            "message": "%PKT_INFRA-LINK-3-UPDOWN : Interface TenGigE0/2/0/4, changed state to Down"}
XR_PROTO_DOWN = {"hostname": "gw2", "appname": "ifmgr",
                 "message": "%PKT_INFRA-LINEPROTO-5-UPDOWN : Line protocol on Interface "
                            "TenGigE0/2/0/4, changed state to Down"}
XR_ADMIN = {"hostname": "gw2", "appname": "ifmgr",
            "message": "%PKT_INFRA-LINK-5-CHANGED : Interface TenGigE0/2/0/4, changed state "
                       "to Administratively Down"}


def test_an_xr_link_fault_opens_like_the_ios_one():
    (sig,) = _signals([XR_FAULT])
    assert (sig.kind, sig.severity.value, sig.entity_id) == (
        "link_state_change", "high", "gw2:TenGigE0/2/0/4")
    assert _opened([XR_FAULT]) == 1


def test_an_xr_protocol_line_alone_stays_below_the_floor():
    (sig,) = _signals([XR_PROTO_DOWN])
    assert (sig.kind, sig.severity.value) == ("link_state_change", "warn")


def test_an_xr_shutdown_opens_nothing():
    sigs = _signals([XR_ADMIN, XR_PROTO_DOWN])
    assert sigs[0].attrs["link_cause"] == "admin"
    assert _opened([XR_ADMIN, XR_PROTO_DOWN]) == 0


@pytest.mark.parametrize(("reason", "cause"), [
    ("Administratively down", "admin"),
    ("Link failure", "fault"),
    ("No operational members", "unknown"),
    ("Initializing", "unknown"),
])
def test_nxos_states_its_cause_in_its_own_words(reason, cause):
    msg = f"%ETHPORT-5-IF_DOWN_X: Interface Ethernet1/5 is down ({reason})"
    (sig,) = _signals([_ios(msg, hostname="sw1")])
    assert sig.attrs["link_cause"] == cause
    assert sig.attrs["link_reason"] == reason
    assert sig.severity.value == "warn", "D3: a pack row does not open alone"


@pytest.mark.parametrize(("admin", "cause"), [("down(2)", "admin"), ("up(1)", "unknown"),
                                              ("testing(3)", "unknown")])
def test_junos_reads_the_cause_from_ifadminstatus(admin, cause):
    doc = {"hostname": "vmx01", "appname": "mib2d", "severity": "warning",
           "message": f"SNMP_TRAP_LINK_DOWN: ifIndex 502, ifAdminStatus {admin}, "
                      "ifOperStatus down(2), ifName xe-0/0/0"}
    (sig,) = _signals([doc])
    assert (sig.kind, sig.entity_id, sig.attrs["link_cause"]) == (
        "link_state_change", "vmx01:xe-0/0/0", cause)


def test_a_junos_link_up_states_no_cause():
    doc = {"hostname": "vmx01", "appname": "mib2d", "severity": "info",
           "message": "SNMP_TRAP_LINK_UP: ifIndex 502, ifAdminStatus up(1), "
                      "ifOperStatus up(1), ifName xe-0/0/0"}
    (sig,) = _signals([doc])
    assert sig.attrs["state"] == "up" and "link_cause" not in sig.attrs


def test_a_nokia_link_line_states_no_cause():
    """SR OS linkDown does not say why (Nokia: check ifAdminStatus): no cause invented."""
    doc = {"hostname": "10.0.0.1", "appname": "TMNX", "severity": "warning",
           "message": "25 Base SNMP-WARNING-linkDown-2004 [to-core]: Interface to-core is not operational"}
    (sig,) = _signals([doc])
    assert sig.kind == "link_state_change" and "link_cause" not in sig.attrs


def test_a_junos_structured_data_frame_without_its_msgid_is_not_parsed():
    """`with_msgid` reads the tag from MSGID; the message alone carries none."""
    ev = {"hostname": "router1", "appname": "mgd", "severity": "notice",
          "message": "User 'regress' exiting configuration mode"}
    assert "parser_id" not in P._PACKS.parse(ev)
    assert P._PACKS.parse({**ev, "msgid": "UI_DBASE_LOGOUT_EVENT"})["event_type"] == \
        "ui_dbase_logout_event"
    assert "parser_id" not in P._PACKS.parse({**ev, "msgid": "-"}), "`-` is RFC 5424 nil"


def test_a_nokia_major_line_with_no_row_may_alarm_and_a_minor_one_may_not():
    """The alarm floor at the canonical critical line: MAJOR (crit) passes, MINOR (err)
    is withheld from the generic net and needs a row."""
    major = {"hostname": "10.0.0.1", "appname": "TMNX", "severity": "notice",
             "message": "40 Base FOO-MAJOR-fooEvent-9999 []: text"}
    minor = {**major, "message": "41 Base FOO-MINOR-fooEvent-9998 []: text"}
    assert P.syslog_alarm_num(major, "TMNX") == 2
    assert P.syslog_alarm_num(minor, "TMNX") is None
    assert P.syslog_severity_num(minor, "TMNX") == 3, "read, not hidden"


def test_an_xr_error_no_row_types_reaches_the_engine_below_the_floor():
    """Rule 1: XR's err and warning lines are withheld from the generic net by the alarm
    floor, so the pack's own net carries them at `warn`. The four-part shape is the
    documented one; the mnemonic is illustrative, since no citable XR line at err sits
    outside the vendor-neutral rows."""
    doc = {"hostname": "gw2", "appname": "envmon", "severity": "err",
           "message": "%PLATFORM-ENVMON-3-EXAMPLE : an illustrative error text"}
    assert P.syslog_alarm_num(doc, "ENVMON") is None
    (sig,) = _signals([doc])
    assert (sig.kind, sig.severity.value, sig.attrs["rule_id"]) == (
        "device_alarm", "warn", "syslog.iosxr.below_floor")
    assert sig.attrs["facility"] == "PLATFORM-ENVMON"
    assert P.syslog_promotable({**doc, **P._PACKS.parse(doc)})


def test_eos_isis_adjchg_reaches_the_isis_row():
    """The vendor-neutral IS-IS row's third arm (napalm-logs ISIS_NEIGHBOR_DOWN, EOS)."""
    (sig,) = _signals([_ios("%ISIS-4-ISIS_ADJCHG: L1 Neighbor State Change for SystemID "
                            "1920.0000.2006 on et7 to DOWN: interface went down or no IP "
                            "address on interface", hostname="eos1", appname="Isis")])
    assert (sig.kind, sig.attrs["peer"], sig.attrs["state"]) == (
        "isis_adjacency_change", "1920.0000.2006", "down")


@pytest.mark.parametrize(("frm", "to", "state", "sev"), [
    ("Established", "Idle", "down", "warn"),
    ("OpenConfirm", "Established", "up", "warn"),
    ("Connect", "Active", "unknown", "info"),
])
def test_junos_bgp_direction_comes_from_the_transition(frm, to, state, sev):
    """The documented line with its states varied (the fixtures carry the documented
    down and churn cases; no citable line shows a session coming up)."""
    doc = {"hostname": "vmx01", "appname": "rpd", "severity": "warning",
           "message": f"RPD_BGP_NEIGHBOR_STATE_CHANGED: BGP peer 1.1.1.1 (External AS 2222) "
                      f"changed state from {frm} to {to} (event RecvOpen) (instance master)"}
    (sig,) = _signals([doc])
    assert (sig.attrs["state"], sig.severity.value) == (state, sev)
