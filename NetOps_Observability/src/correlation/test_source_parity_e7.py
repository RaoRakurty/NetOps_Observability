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
  * controller path: vManage `bgp-peer-state-change` events for the same
    seconds, through the production Go transform + runtime with the lab's
    inventory join — the golden ../backend/nms/testdata/source_parity/
    (nms/source_parity_golden_test.go keeps it current).

KNOWN_DIVERGENCES is a ratchet: every divergence the harness observes must be
declared with its owner, and a declared one that no longer reproduces fails
too (delete it). So a regression on either side of the language boundary, or
a fix nobody recorded, is a red test — never silence.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone

import pytest

import main
import producers as P
from controller_events import controller_event_to_signal
from engine import build_nodes
from entity_resolver import EntityResolver
from signals import ORIGIN_DEVICE_ATTR, ModalityClass, set_origin_observer
from verdicts import VerdictTier, assess

HERE = os.path.dirname(os.path.abspath(__file__))
GOLDEN = os.path.join(HERE, "..", "backend", "nms", "testdata", "source_parity",
                      "vmanage_20.6.controller_events.json")
TRAPS = os.path.join(HERE, "fixtures", "source_parity", "traps_cedge81_bgp_20261101.jsonl")

TENANT = "t_lab"
DEVICE = "cedge-81-11060ae2"       # the lab's inventory id for cEDGE-81
PEER = "192.168.200.34"
RFC_BACKWARD = "1.3.6.1.2.1.15.7.2"
CISCO_BGP4 = "1.3.6.1.4.1.9.9.187.0."
INGEST = datetime(2026, 11, 1, 17, 5, tzinfo=timezone.utc)  # after every recorded event
MAX_SKEW_S = 5.0  # controller and device clocks for the same transition

KNOWN_DIVERGENCES = {
    "trap_unattributed": (
        "the trap's sender (cEDGE-81's VPN-200 interface 192.168.200.33) is in no address "
        "registry, so the record's device is '' and the producer emits nothing — tracker 371 "
        "(and 373: after a recreate the sender became the bridge gateway)"),
    "cisco_bgp4_mib_unclassified": (
        "CISCO-BGP4-MIB (1.3.6.1.4.1.9.9.187) is not in the vendored index: the cbgp* "
        "notifications arrive enterpriseSpecific and emit nothing, and the idle→active "
        "transition arrives only there — tracker 374"),
}


@pytest.fixture(autouse=True)
def _restore():
    yield
    set_origin_observer(False)


def controller_events() -> list[dict]:
    with open(GOLDEN, encoding="utf-8") as fh:
        return json.load(fh)


def traps() -> list[dict]:
    with open(TRAPS, encoding="utf-8") as fh:
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


def observed_divergences() -> set[str]:
    seen: set[str] = set()
    ctl = first_controller_signal()
    if P.trap_control_signal(dict(first_rfc_trap()), TENANT, INGEST) is None:
        seen.add("trap_unattributed")
    trap_sig = P.trap_control_signal(joined(first_rfc_trap()), TENANT, INGEST)
    if trap_sig is not None and trap_sig.entity_id != ctl.entity_id:
        seen.add("trap_bgp_peer_from_index")
    if any(P.trap_control_signal(joined(t), TENANT, INGEST) is None
           for t in traps() if t["trap_oid"].startswith(CISCO_BGP4)):
        seen.add("cisco_bgp4_mib_unclassified")
    return seen


# ── the fixtures are what they claim to be ───────────────────────────────────

def test_both_sides_record_the_same_transition() -> None:
    evs = controller_events()
    assert evs and all(e["device_id"] == DEVICE and e["peer_id"] == PEER for e in evs)
    rfc = first_rfc_trap()
    assert any(PEER in vb["oid"] for vb in rfc["varbinds"]), "the trap must name the same peer"
    skew = abs((ts(rfc["timestamp"]) - ts(evs[0]["event_time"])).total_seconds())
    assert skew <= MAX_SKEW_S, f"{skew}s apart — not the same transition"


# ── the ratchet ──────────────────────────────────────────────────────────────

def test_every_divergence_is_declared_and_every_declaration_still_holds() -> None:
    seen = observed_divergences()
    undeclared = seen - set(KNOWN_DIVERGENCES)
    healed = set(KNOWN_DIVERGENCES) - seen
    assert not undeclared, f"new divergence between the device and controller paths: {undeclared}"
    assert not healed, f"declared divergence no longer reproduces — delete it: {healed}"


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
