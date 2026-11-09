# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""E7 source parity — one RECORDED real event, two sources, the same evidence?

Plan of record: docs/design/NMS_DEVICE_IDENTITY_2026-11-01.md (E7). E0 proves
statically which kinds each source CAN supply; this proves at runtime what the
engine actually receives for the same event through the device path and the
controller path, inside one tenant.

The event (captured read-only from the lab, 2026-11-01 ~17:00Z): cEDGE-81's
BGP session to 192.168.200.34 in VPN 200 goes idle, then active.
  * device path: the router's own SNMP traps — the RFC 4273
    `bgpBackwardTransition` and the CISCO-BGP4-MIB `cbgp*` notifications —
    fixtures/source_parity/traps_cedge81_bgp_20261101.jsonl (community and
    storage-side enrichment dropped; otherwise as received).
  * device path, syslog: everything cEDGE-81 logged from 16:59:00Z to
    17:01:30Z — fixtures/source_parity/syslog_cedge81_20261101.jsonl, ten
    lines with consecutive sequence numbers, read from the lab OpenSearch
    (tenant enrichment and Kafka/storage metadata dropped; otherwise as
    indexed). The box logs under its management address, 192.168.222.106,
    not its hostname. None of the ten is about the session (all are netconf
    logins). Likely why: the session never reached Established (every
    controller report has peer-routerid 0.0.0.0) and IOS-XE logs
    %BGP-5-ADJCHANGE only on entering or leaving Established; no device's
    syslog in the retained days (2026-10-25..11-07) holds one. So
    syslog contributes NOTHING to this event, which the harness pins; the
    syslog binding divergences (tracker 374 D1 host-level BGP, D2 hostname
    entity) need a recorded syslog transition and are NOT covered here.
  * controller path: vManage `bgp-peer-state-change` events for the same
    seconds, through the production Go transform + runtime with the lab's
    inventory join — the golden ../backend/nms/testdata/source_parity/
    (nms/source_parity_golden_test.go keeps it current). A second golden
    joins the same events against an inventory that also owns the peer's
    address, which is where nms/identity.go rewrites the peer (D5).

Not covered by a RECORDED event: D1/D2 (above; synthetic messages below), D3
recoveries (tracker 380; the controller lane here relays no recovery), D4
interface spellings (no recorded interface event; synthetic below), D6 severity
(tracker 381; not compared).

KNOWN_DIVERGENCES is a ratchet: every divergence the harness observes must be
declared with its owner, and a declared one that no longer reproduces fails
too (delete it). So a regression on either side of the language boundary, or
a fix nobody recorded, is a red test — never silence.

P6 PR-E split the ratchet by stage [1] identity canonicalisation
(CORR_IDENTITY_CANON): KNOWN_DIVERGENCES is what the engine receives with the
flag OFF (unchanged), KNOWN_DIVERGENCES_ON what it receives with the flag ON —
every signal pushed through the live window entry (`main.buffer_signal`) with
the lab's tenant-only inventory. D5 heals on the recorded GOLDEN_PEER events;
trap_unattributed stays (the sender is in no registry: tracker 371).

IDENTITY_DIVERGENCES / IDENTITY_DIVERGENCES_ON cover D1/D2/D4, which the
recorded event cannot (its syslog carries no evidence, above). Each case is the
box's RECORDED syslog hostname (its management address) with a SYNTHETIC
message through the production parser — the PR-D vectors — set against the
recorded trap (D1) and the SNMP ifName IOS-XE reports for the same port (D4).
A recorded transition, when one is captured, replaces the synthetic message.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone

import pytest

import main
import producers as P
import signals
from canon import canonicalize_series, tenant_key
from controller_events import controller_event_to_signal
from engine import build_nodes
from entity_resolver import EntityResolver, identity_resolver_for
from signals import (
    ORIGIN_DEVICE_ATTR,
    ModalityClass,
    set_identity_canon,
    set_origin_observer,
    set_series_admission,
)
from trap_collapse import TransitionCollapser
from verdicts import VerdictTier, assess

HERE = os.path.dirname(os.path.abspath(__file__))
GOLDEN = os.path.join(HERE, "..", "backend", "nms", "testdata", "source_parity",
                      "vmanage_20.6.controller_events.json")
GOLDEN_PEER = os.path.join(HERE, "..", "backend", "nms", "testdata", "source_parity",
                           "vmanage_20.6.controller_events_peer_in_inventory.json")
TRAPS = os.path.join(HERE, "fixtures", "source_parity", "traps_cedge81_bgp_20261101.jsonl")
SYSLOG = os.path.join(HERE, "fixtures", "source_parity", "syslog_cedge81_20261101.jsonl")

TENANT = "t_lab"
DEVICE = "cedge-81-11060ae2"       # the lab's inventory id for cEDGE-81
PEER = "192.168.200.34"
PEER_INVENTORY_ID = "pe-vpn200-parity"  # the peer's inventory id in GOLDEN_PEER only
CEDGE81_MGMT = "192.168.222.106"   # cEDGE-81's inventory address = its syslog hostname
RFC_BACKWARD = "1.3.6.1.2.1.15.7.2"
CISCO_BGP4 = "1.3.6.1.4.1.9.9.187.0."
INGEST = datetime(2026, 11, 1, 17, 5, tzinfo=timezone.utc)  # after every recorded event
MAX_SKEW_S = 5.0  # controller and device clocks for the same transition

KNOWN_DIVERGENCES = {
    "trap_unattributed": (
        "the trap's sender (cEDGE-81's VPN-200 interface 192.168.200.33) is in no address "
        "registry, so the record's device is '' and the producer emits nothing — tracker 371 "
        "(and 373: after a recreate the sender became the bridge gateway)"),
    "controller_peer_is_inventory_id": (
        "D5 (tracker 374): once the peer's address is in inventory, nms/identity.go rewrites "
        "the controller's PeerID to the peer's inventory id (the IP survives only in "
        "correlation_hints.controller_peer_id) while the router's own trap keeps the IP — "
        "one session, two nodes. P6 PR-E canonicalisation, "
        "docs/design/P6_CANONICALISATION_PLAN_2026-11-07.md"),
}

# CORR_IDENTITY_CANON on (with its prerequisites E1 + series admission): D5 heals.
KNOWN_DIVERGENCES_ON = {
    "trap_unattributed": KNOWN_DIVERGENCES["trap_unattributed"],
}

IDENTITY_DIVERGENCES = {
    "syslog_bgp_binds_the_host": (
        "D1 (tracker 374): a syslog BGP adjacency binds the HOST while the router's own trap "
        "binds the session `{device}:{peer}` — one session, two nodes. P6 PR-E"),
    "syslog_names_the_box_by_its_address": (
        "D2 (tracker 374): cEDGE-81 logs under its management address 192.168.222.106, the "
        "trap and the controller name it by inventory id. P6 PR-E"),
    "interface_spelling_differs": (
        "D4 (tracker 374): syslog says `GigabitEthernet1`, IF-MIB ifName says `Gi1` — one "
        "port, two series/nodes. P6 PR-E"),
}
IDENTITY_DIVERGENCES_ON: dict[str, str] = {}

# The lab inventory as the Go API exports it for t_lab (entity_resolver.json):
# cEDGE-81 by id, name and management address, its ports by ifIndex, and the
# GOLDEN_PEER case's peer box owning the session's remote address.
LAB_INVENTORY = {
    "devices": {TENANT: [
        {"tenant_id": TENANT, "device": DEVICE, "name": "cEDGE-81", "mgmt_ip": CEDGE81_MGMT},
        {"tenant_id": TENANT, "device": PEER_INVENTORY_ID, "name": "pe-vpn200", "mgmt_ip": PEER},
    ]},
    "interface_ips": {},
    "ifindex": {TENANT: [
        {"tenant_id": TENANT, "device": DEVICE, "ifindex": "1", "ifname": "Gi1"},
        {"tenant_id": TENANT, "device": DEVICE, "ifindex": "2", "ifname": "Gi2"},
    ]},
}


@pytest.fixture(autouse=True)
def _restore():
    prev = (signals.origin_observer_enabled(), signals.series_admission_enabled(),
            signals.identity_canon_requested())
    yield
    set_origin_observer(prev[0])
    set_series_admission(prev[1])
    set_identity_canon(prev[2])


@pytest.fixture
def lab_inventory(monkeypatch):
    res = identity_resolver_for(LAB_INVENTORY, TENANT)
    monkeypatch.setattr(main, "cached_identity_resolver_for",
                        lambda tenant: res if tenant_key(tenant) == TENANT else
                        identity_resolver_for({}, tenant))
    monkeypatch.setattr(main, "IDENTITY_CANON_COUNTS", {})


def engine_view(canon: bool):
    """What the engine's window holds for a lane's signal: `main.buffer_signal`
    with stage [1] on (its prerequisites too) or off. None stays None."""
    set_origin_observer(canon)
    set_series_admission(canon)
    set_identity_canon(canon)
    assert main.identity_canon_enabled() is canon

    def view(sig):
        if sig is None:
            return None
        main.WINDOW_BUFFER.clear()
        main._BUFFERED_ID_ORDER.clear()
        main._BUFFERED_IDS.clear()
        main.buffer_signal(sig)
        return main.WINDOW_BUFFER[-1]
    return view


def controller_events(golden: str = GOLDEN) -> list[dict]:
    with open(golden, encoding="utf-8") as fh:
        return json.load(fh)


def traps() -> list[dict]:
    with open(TRAPS, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def syslog_lines() -> list[dict]:
    with open(SYSLOG, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def joined(trap: dict) -> dict:
    """The record as the identity join would leave it: device = the inventory id."""
    return {**trap, "device": DEVICE}


def first_rfc_trap() -> dict:
    return next(t for t in traps() if t["trap_oid"] == RFC_BACKWARD)


def first_controller_signal():
    return controller_event_to_signal(controller_events()[0], INGEST)


def ts(raw: str) -> datetime:
    return datetime.fromisoformat(raw.replace("Z", "+00:00"))


def _as_received(sig):
    return sig


def observed_divergences(view=_as_received) -> set[str]:
    """`view` maps a lane's signal to what the engine holds for it: as produced
    (default), or through the live window entry with stage [1] on/off
    (`engine_view`)."""
    seen: set[str] = set()
    ctl = view(first_controller_signal())
    if view(P.trap_control_signal(dict(first_rfc_trap()), TENANT, INGEST)) is None:
        seen.add("trap_unattributed")
    trap_sig = view(P.trap_control_signal(joined(first_rfc_trap()), TENANT, INGEST))
    if trap_sig is not None and trap_sig.entity_id != ctl.entity_id:
        seen.add("trap_bgp_peer_from_index")
    # tracker 376: every CISCO-BGP4-MIB report of the transition the RFC trap
    # reports (same sysUpTime second) must be the SAME evidence — and the trap
    # lane must fold all the families into ONE signal.
    if trap_sig is not None:
        rfc_up = uptime_cs(first_rfc_trap())
        same = [t for t in traps() if t["trap_oid"].startswith(CISCO_BGP4)
                and abs(uptime_cs(t) - rfc_up) <= 100]
        family = [view(P.trap_control_signal(joined(t), TENANT, INGEST)) for t in same]
        want = (trap_sig.entity_id, trap_sig.attrs.get("state"))
        if not same or any(s is None or (s.entity_id, s.attrs.get("state")) != want
                           for s in family):
            seen.add("cisco_bgp4_mib_unclassified")
        col = TransitionCollapser()
        kept = [s for s in [trap_sig, *family] if s is not None
                and col.admit(TENANT, s.entity_id, str(s.attrs.get("state") or ""), s.ts)]
        if len(kept) != 1:
            seen.add("trap_families_multiply_one_transition")
    # D5: the same recorded controller events, joined against an inventory that
    # owns the peer's address. One session must stay one node with the trap's.
    ctl_peer = view(controller_event_to_signal(controller_events(GOLDEN_PEER)[0], INGEST))
    if trap_sig is not None and ctl_peer.entity_id != trap_sig.entity_id:
        seen.add("controller_peer_is_inventory_id")
    return seen


SYSLOG_BGP = f"%BGP-5-ADJCHANGE: neighbor {PEER} vpn vrf 200 Down BGP Notification sent"
SYSLOG_LINK = "%LINEPROTO-5-UPDOWN: Line protocol on Interface GigabitEthernet1, changed state to down"


def recorded_host_syslog(message: str):
    """A synthetic message under the box's RECORDED syslog hostname, through the
    production parser (the recorded lines promote nothing — see the docstring)."""
    host = syslog_lines()[0]["hostname"]
    sig = P.syslog_control_signal({"appname": message.split(":", 1)[0], "facility": "local7",
                                   "hostname": host, "message": message,
                                   "timestamp": "2026-11-01T17:00:01Z"}, TENANT, INGEST)
    assert sig is not None, message
    return sig


def snmp_series_key(if_name: str, canon: bool) -> str:
    """The metric lane's series key for an IOS-XE IF-MIB sample of cEDGE-81's port
    (ifName is the SHORT form there), as `main.handle_metric` keys it."""
    ev = {"device": DEVICE, "signal_family": "interface", "if_name": if_name, "index": "1",
          "metric": "device_if_oper_status"}
    entity_id, _etype, _kp, tokens = main.metric_identity(ev)
    if not canon:
        return entity_id
    return canonicalize_series(ev, entity_id, tokens, main.cached_identity_resolver_for(TENANT),
                               TENANT).entity_id


def observed_identity_divergences(view, canon: bool) -> set[str]:
    seen: set[str] = set()
    trap = view(P.trap_control_signal(joined(first_rfc_trap()), TENANT, INGEST))
    bgp = view(recorded_host_syslog(SYSLOG_BGP))
    link = view(recorded_host_syslog(SYSLOG_LINK))
    if bgp.entity_id != trap.entity_id:
        seen.add("syslog_bgp_binds_the_host")
    if link.entity_id.split(":", 1)[0] != DEVICE:
        seen.add("syslog_names_the_box_by_its_address")
    if link.entity_id.split(":", 1)[1] != snmp_series_key("Gi1", canon).split(":", 1)[1]:
        seen.add("interface_spelling_differs")
    return seen


def uptime_cs(trap: dict) -> int:
    """The trap's sysUpTime.0 (centiseconds) — one transition shares it across families."""
    for vb in trap["varbinds"]:
        if vb["oid"] == "1.3.6.1.2.1.1.3.0":
            return int(vb["value"])
    raise AssertionError("recorded trap without sysUpTime")


# ── the fixtures are what they claim to be ───────────────────────────────────

def test_both_sides_record_the_same_transition() -> None:
    evs = controller_events()
    assert evs and all(e["device_id"] == DEVICE and e["peer_id"] == PEER for e in evs)
    rfc = first_rfc_trap()
    assert any(PEER in vb["oid"] for vb in rfc["varbinds"]), "the trap must name the same peer"
    skew = abs((ts(rfc["timestamp"]) - ts(evs[0]["event_time"])).total_seconds())
    assert skew <= MAX_SKEW_S, f"{skew}s apart — not the same transition"


def _without_peer_join(ev: dict) -> dict:
    hints = {k: v for k, v in ev["correlation_hints"].items() if k != "controller_peer_id"}
    return {**ev, "peer_id": None, "correlation_hints": hints}


def test_the_peer_in_inventory_golden_is_the_same_recorded_events() -> None:
    """GOLDEN_PEER differs from GOLDEN only by the peer join (D5's precondition)."""
    base, peer = controller_events(), controller_events(GOLDEN_PEER)
    assert len(peer) == len(base)
    for b, p in zip(base, peer):
        assert p["peer_id"] == PEER_INVENTORY_ID
        assert p["correlation_hints"].get("controller_peer_id") == b["peer_id"] == PEER
        assert _without_peer_join(p) == _without_peer_join(b)


def test_the_syslog_fixture_is_everything_cedge81_logged_across_the_transition() -> None:
    lines = syslog_lines()
    assert lines and all(e["hostname"] == CEDGE81_MGMT for e in lines)
    times = [ts(e["timestamp"]) for e in lines]
    ctl = [ts(e["event_time"]) for e in controller_events()]
    assert times == sorted(times) and times[0] < min(ctl) and times[-1] > max(ctl), \
        "the recorded syslog must bracket every controller report of the transition"
    seq = [int(e["meta"]["sequenceId"]) for e in lines]
    assert seq == list(range(seq[0], seq[0] + len(seq))), \
        "consecutive sequence numbers: no line from the box is missing in between"


def test_the_device_syslog_lane_carries_no_evidence_for_the_transition() -> None:
    """The recorded event's syslog promotes nothing through either syslog
    producer. If this fails, a line now becomes evidence: compare its binding
    with the trap/controller session id in observed_divergences (D1/D2) and
    declare what differs."""
    for ev in syslog_lines():
        assert P.syslog_control_signal(dict(ev), TENANT, INGEST) is None, ev["message"]
        assert P.port_event_signal(dict(ev), TENANT, INGEST) is None, ev["message"]


# ── the ratchet ──────────────────────────────────────────────────────────────

def _ratchet(seen: set[str], declared: dict[str, str]) -> None:
    undeclared = seen - set(declared)
    healed = set(declared) - seen
    assert not undeclared, f"new divergence between the device and controller paths: {undeclared}"
    assert not healed, f"declared divergence no longer reproduces — delete it: {healed}"


def test_every_divergence_is_declared_and_every_declaration_still_holds() -> None:
    _ratchet(observed_divergences(), KNOWN_DIVERGENCES)


@pytest.mark.parametrize("canon,declared", [(False, KNOWN_DIVERGENCES), (True, KNOWN_DIVERGENCES_ON)],
                         ids=["canon_off", "canon_on"])
def test_the_ratchet_through_the_window_entry(canon, declared, lab_inventory) -> None:
    """The same recorded events as the engine's window holds them, stage [1]
    off (unchanged from the producer view) and on (D5 healed)."""
    _ratchet(observed_divergences(engine_view(canon)), declared)


@pytest.mark.parametrize("canon,declared",
                         [(False, IDENTITY_DIVERGENCES), (True, IDENTITY_DIVERGENCES_ON)],
                         ids=["canon_off", "canon_on"])
def test_the_identity_ratchet_d1_d2_d4(canon, declared, lab_inventory) -> None:
    _ratchet(observed_identity_divergences(engine_view(canon), canon), declared)


def test_with_canon_on_the_session_is_one_node_across_three_lanes(lab_inventory) -> None:
    """D1 + D2 + D5: the box's syslog (recorded hostname), its own trap and the
    controller whose peer was rewritten to an inventory id meet on ONE node — and
    stay ONE witness under E1 (the prerequisite), never a confirmation."""
    view = engine_view(True)
    sigs = [view(recorded_host_syslog(SYSLOG_BGP)),
            view(P.trap_control_signal(joined(first_rfc_trap()), TENANT, INGEST)),
            view(controller_event_to_signal(controller_events(GOLDEN_PEER)[0], INGEST))]
    assert {s.entity_id for s in sigs} == {f"{DEVICE}:{PEER}"}
    assert len(build_nodes(tuple(sigs))) == 1
    assert {s.attrs[ORIGIN_DEVICE_ATTR] for s in sigs} == {DEVICE}
    assert assess(sigs).tier is not VerdictTier.CONFIRMED


# ── what must hold today ─────────────────────────────────────────────────────

def test_the_controller_path_carries_the_recorded_time_and_the_session() -> None:
    sig = first_controller_signal()
    assert sig.kind == "bgp_adjacency_change"
    assert sig.entity_id == f"{DEVICE}:{PEER}"
    assert sig.modality_class is ModalityClass.MANAGEMENT_PLANE
    assert sig.ts == ts(controller_events()[0]["event_time"]), "the event time, never the ingest time"


def test_the_joined_device_path_agrees_on_kind_type_and_time() -> None:
    ctl = first_controller_signal()
    rfc = first_rfc_trap()
    trap = P.trap_control_signal(joined(rfc), TENANT, INGEST)
    assert trap is not None
    assert trap.kind == ctl.kind
    assert trap.entity_type == ctl.entity_type
    assert trap.modality_class is ModalityClass.CONTROL_PLANE  # the box speaking for itself
    assert trap.ts == ts(rfc["timestamp"])
    assert abs((trap.ts - ctl.ts).total_seconds()) <= MAX_SKEW_S
    assert trap.signal_id != ctl.signal_id, "two lanes are two pieces of evidence"


def test_one_node_exactly_when_the_session_ids_agree() -> None:
    ctl = first_controller_signal()
    trap = P.trap_control_signal(joined(first_rfc_trap()), TENANT, INGEST)
    nodes = build_nodes((trap, ctl))
    same_entity = trap.entity_id == ctl.entity_id
    assert len(nodes) == (1 if same_entity else 2)


def test_the_two_lanes_are_never_independent_witnesses(monkeypatch) -> None:
    """E1: the router's own trap and the controller relaying the same session
    are one device's state — never the independent pair a confirmation needs."""
    set_origin_observer(True)
    res = EntityResolver.from_rows(devices=[{"device": DEVICE, "name": "cEDGE-81"}],
                                   interface_ips=[], ifindex=[])
    monkeypatch.setattr(main, "cached_entity_resolver_for", lambda tenant: res)
    ctl = main._stamp_origin_device(first_controller_signal())
    trap = main._stamp_origin_device(P.trap_control_signal(joined(first_rfc_trap()), TENANT, INGEST))
    assert ctl.attrs[ORIGIN_DEVICE_ATTR] == trap.attrs[ORIGIN_DEVICE_ATTR] == DEVICE
    assert assess([trap, ctl]).tier is not VerdictTier.CONFIRMED
