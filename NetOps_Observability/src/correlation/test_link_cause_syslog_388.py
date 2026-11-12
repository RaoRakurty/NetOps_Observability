# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Tracker 388 (a) — a SYSLOG admin link change reaches stages [5] and [6] the way the
trap one does (tracker 385), for the vendors whose syslog gained a cause here: Nokia SR
Linux (chassis portDown/subinterfaceDown with the device's oper-down-reason), SONiC
(portmgrd `Configure <port> admin status to down`) and the IOS XR wording of
%PKT_INFRA-LINK-5-CHANGED.

The pack fixtures (telemetry-catalog/test_vendor_packs.py) pin each line's parse and its
signal by value. This file pins what the engine DOES with those signals, built through
the real parse and the real syslog rule walk:

* [5] a shutdown opens nothing; a non-admin down still opens when anything on the node
  is at the open floor (fail-closed: unknown and fault are not admin);
* [6] an admin syslog line is the anchor of `sig.ent.access.admin-link-change-induced`
  and contradicts `local-link-fault` and `lastmile-circuit-flap` exactly as the admin
  trap does; a fault or unknown syslog line leaves them scoring as they did.

Stage [1] only: no template, gate or constant moved, so ENGINE_SEMVER does not move.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

import catalog
import engine
import producers as P
from scoring import CONFIDENCE_FLOOR, rank
from signals import (
    EntityType,
    ModalityClass,
    Observer,
    ObserverType,
    Severity,
    Signal,
    Source,
)

NOW = datetime(2026, 11, 12, 10, 0, tzinfo=timezone.utc)
T0 = NOW - timedelta(seconds=60)
SIBLING = "sig.ent.access.admin-link-change-induced"
LOCAL = "sig.ent.access.local-link-fault"
LASTMILE = "sig.ent.middle-mile.lastmile-circuit-flap"
ADMIN_TAG = "link_state_change[link_cause=admin]"

# The pack fixtures' lines (doc_claimed; sources on each fixture in the packs).
SRL_ADMIN = {"hostname": "leaf1", "appname": "-", "severity": "warning",
             "message": "chassis|1580|1580|00031|EV|portDown|W: Interface ethernet-1/1 is now "
                        "down for reason: port-admin-disabled"}
SRL_SUBIF_ADMIN = {"hostname": "leaf1", "appname": "-", "severity": "warning",
                   "message": "chassis|1580|1580|00034|EV|subinterfaceDown|W: The subinterface "
                              "ethernet-1/1.0 is now down for reason: admin-disabled"}
SRL_FAULT = {"hostname": "leaf1", "appname": "-", "severity": "warning",
             "message": "chassis|1580|1580|00032|EV|portDown|W: Interface ethernet-1/1 is now "
                        "down for reason: transceiver-oper-down"}
SRL_UNKNOWN = {"hostname": "leaf1", "appname": "-", "severity": "warning",
               "message": "chassis|1580|1580|00033|EV|portDown|W: Interface ethernet-1/1 is now "
                          "down for reason: lower-layer-down"}
SONIC_ADMIN = {"hostname": "sonic1", "appname": "swss#portmgrd", "severity": "notice",
               "message": ":- doTask: Configure Ethernet184 admin status to down"}
SONIC_OPER = {"hostname": "sonic1", "appname": "swss#orchagent", "severity": "notice",
              "message": ":- setHostIntfsOperStatus: Set operation status DOWN to host "
                         "interface Ethernet184"}
XR_ADMIN = {"hostname": "spine2", "appname": "ifmgr", "severity": "notice",
            "message": "%PKT_INFRA-LINK-5-CHANGED : Interface HundredGigE0/0/0/8, changed "
                       "state to Administratively Down"}
XR_NOT_ADMIN = {"hostname": "ncs1", "appname": "ifmgr", "severity": "notice",
                "message": "%PKT_INFRA-LINK-5-CHANGED : Interface Optics0/3/0/28, changed "
                           "state to Down"}

ADMIN_LINES = {"srlinux": SRL_ADMIN, "srlinux-subinterface": SRL_SUBIF_ADMIN,
               "sonic": SONIC_ADMIN, "iosxr": XR_ADMIN}


def _signals(docs: list[dict]) -> list[Signal]:
    sigs = []
    for i, doc in enumerate(docs):
        ev = {**doc, "timestamp": (T0 + timedelta(seconds=i)).isoformat()}
        ev = {**ev, **P._PACKS.parse(ev)}
        sig = P.syslog_control_signal(ev, "t1", NOW)
        if sig is not None:
            sigs.append(sig)
    return sorted(sigs, key=lambda s: (s.ts, s.signal_id))


def _one(doc: dict) -> Signal:
    sigs = _signals([doc])
    assert len(sigs) == 1, sigs
    return sigs[0]


def _trap_link(entity_id: str, observer: str, cause: str | None, off: float = 5.0) -> Signal:
    """The device's RFC 2863 linkDown as the trap rows emit it: high, cause from
    ifAdminStatus (events.yaml `trap_link_cause`)."""
    attrs = {"state": "down"} | ({"link_cause": cause} if cause is not None else {})
    return Signal(
        tenant_id="t1", ts=T0 + timedelta(seconds=off), source=Source.TRAP,
        kind="link_state_change",
        observer=Observer(observer_id=observer, observer_type=ObserverType.DEVICE),
        modality_class=ModalityClass.CONTROL_PLANE, entity_type=EntityType.INTERFACE,
        entity_id=entity_id, severity=Severity.HIGH,
        native_id=f"t388|trap|{entity_id}|{cause}|{off}", attrs=attrs)


def _if_metric(entity_id: str, observer: str, off: float = 30.0) -> Signal:
    return Signal(
        tenant_id="t1", ts=T0 + timedelta(seconds=off), source=Source.METRIC,
        kind="if_metric_anomaly",
        observer=Observer(observer_id=observer + "-snmp", observer_type=ObserverType.DEVICE),
        modality_class=ModalityClass.DEVICE_TELEMETRY, entity_type=EntityType.INTERFACE,
        entity_id=entity_id, severity=Severity.HIGH, native_id=f"t388|if|{entity_id}|{off}")


def _bgp(device: str, off: float = 20.0) -> Signal:
    return Signal(
        tenant_id="t1", ts=T0 + timedelta(seconds=off), source=Source.SYSLOG,
        kind="bgp_adjacency_change",
        observer=Observer(observer_id=device, observer_type=ObserverType.DEVICE),
        modality_class=ModalityClass.CONTROL_PLANE, entity_type=EntityType.DEVICE,
        entity_id=device, severity=Severity.HIGH, native_id=f"t388|bgp|{device}|{off}")


def _opened(sigs: list[Signal]) -> int:
    ordered = tuple(sorted(sigs, key=lambda s: (s.ts, s.signal_id)))
    return len(engine.run_window(ordered, catalog.builtin_catalog(), ()))


def _hyp(result, template_id: str):
    return next(h for h in result.hypotheses if h.template_id == template_id)


def _row(result, template_id: str) -> tuple:
    h = _hyp(result, template_id)
    return (h.confidence_rank, h.coverage, h.contradicted, h.contradictions,
            h.forced_competitors)


# ══ stage [1]: the cause is the line's, and only the line's ═════════════════


@pytest.mark.parametrize("name", sorted(ADMIN_LINES))
def test_every_admin_line_carries_the_admin_cause_at_warn(name):
    sig = _one(ADMIN_LINES[name])
    assert (sig.kind, sig.severity.value, sig.attrs["state"], sig.attrs["link_cause"]) == (
        "link_state_change", "warn", "down", "admin")


@pytest.mark.parametrize(("doc", "cause"), [(SRL_FAULT, "fault"), (SRL_UNKNOWN, "unknown")])
def test_a_down_that_is_not_a_shutdown_never_reads_admin(doc, cause):
    assert _one(doc).attrs["link_cause"] == cause


def test_lines_that_state_no_cause_carry_none():
    """Fail-closed: the oper-state line and the XR CHANGED-to-Down line say nothing
    about a shutdown, so no cause is invented (and the XR one emits nothing)."""
    assert "link_cause" not in _one(SONIC_OPER).attrs
    assert _signals([XR_NOT_ADMIN]) == []


# ══ stage [5]: the singleton exemption ══════════════════════════════════════


@pytest.mark.parametrize("name", sorted(ADMIN_LINES))
def test_a_syslog_shutdown_alone_opens_nothing(name):
    assert _opened(_signals([ADMIN_LINES[name]])) == 0


def test_a_sonic_shutdown_and_its_oper_down_open_nothing():
    sigs = _signals([SONIC_ADMIN, SONIC_OPER])
    assert {s.entity_id for s in sigs} == {"sonic1:Ethernet184"}, "one interface node"
    assert _opened(sigs) == 0


def test_a_syslog_shutdown_beside_the_admin_trap_opens_nothing():
    """The device's two records of one shutdown agree: no object."""
    sigs = _signals([SRL_ADMIN]) + [_trap_link("leaf1:ethernet-1/1", "leaf1", "admin")]
    assert _opened(sigs) == 0


def test_a_syslog_shutdown_cannot_hide_a_trap_with_no_cause():
    """Fail-closed (tracker 385): an opening-severity signal on the node without
    link_cause=admin opens, whatever the warn syslog line beside it says."""
    sigs = _signals([SRL_ADMIN]) + [_trap_link("leaf1:ethernet-1/1", "leaf1", None)]
    assert _opened(sigs) == 1


@pytest.mark.parametrize("doc", [SRL_FAULT, SRL_UNKNOWN])
def test_a_non_admin_down_still_opens_beside_its_trap(doc):
    sigs = _signals([doc]) + [_trap_link("leaf1:ethernet-1/1", "leaf1", None)]
    assert _opened(sigs) == 1


# ══ stage [6]: scoring ══════════════════════════════════════════════════════


@pytest.mark.parametrize("name", sorted(ADMIN_LINES))
def test_a_syslog_shutdown_scores_like_the_admin_trap(name):
    sig = _one(ADMIN_LINES[name])
    host = sig.entity_id.split(":", 1)[0]
    trap = _trap_link(sig.entity_id, host, "admin")
    metric = _if_metric(sig.entity_id, host)
    cat = catalog.builtin_catalog()
    via_syslog, via_trap = rank(cat, (sig, metric)), rank(cat, (trap, metric))
    assert via_syslog.top_hypothesis == via_trap.top_hypothesis == SIBLING
    for tid in (SIBLING, LOCAL):
        assert _row(via_syslog, tid) == _row(via_trap, tid), tid
    local = _hyp(via_syslog, LOCAL)
    assert local.contradicted and local.contradictions == (ADMIN_TAG,)
    assert local.confidence_rank <= 0.2 < CONFIDENCE_FLOOR
    assert local.forced_competitors == (SIBLING,)


def test_a_syslog_shutdown_then_bgp_takes_lastmile_out_of_contention():
    sig = _one(SRL_ADMIN)
    result = rank(catalog.builtin_catalog(), (sig, _bgp("leaf1")))
    last = _hyp(result, LASTMILE)
    assert last.contradicted and last.contradictions == (ADMIN_TAG,)
    assert last.forced_competitors == (SIBLING,)


@pytest.mark.parametrize("doc", [SRL_FAULT, SRL_UNKNOWN, SONIC_OPER])
def test_a_non_admin_syslog_down_leaves_the_fault_templates_scoring(doc):
    sig = _one(doc)
    host = sig.entity_id.split(":", 1)[0]
    result = rank(catalog.builtin_catalog(), (sig, _if_metric(sig.entity_id, host)))
    assert SIBLING not in {h.template_id for h in result.hypotheses}, "no anchor, no sibling"
    assert not _hyp(result, LOCAL).contradicted
    assert result.top_hypothesis == LOCAL
    assert not _hyp(rank(catalog.builtin_catalog(), (sig, _bgp(host))), LASTMILE).contradicted
