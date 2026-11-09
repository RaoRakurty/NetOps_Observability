# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Tracker 387: decoded vendor traps reach the engine as evidence, not incidents.

Stage [1] only. What this holds:

  * the trap recorded on the lab (vedge-52's CPU recovery) classifies as a clear,
    bound to the device, and opens nothing;
  * owner rule "ingestion is not incident creation" and D3: a lone warn opens no
    object, a lone qualifying critical does, and a warn still joins a component;
  * the rows use the kinds and the entity shapes the controller lane and the
    templates use, so a device's report and vManage's can meet;
  * a retry leg, an unknown state or a notification nobody reviewed never turns
    into a fault, however the MIB now names it;
  * every OID a row names resolves in the index, under the name the pack states.

The event shape is the Go receiver's: collectors/trap_semantics_test.go decodes
the same fixture from the wire, so the two sides cannot drift apart unnoticed.
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import replace
from datetime import datetime, timezone

import pytest

import canon
import producers as P
from catalog import builtin_catalog
from controller_events import controller_event_to_signal
from engine import EngineConfig, build_nodes, run_window
from entity_resolver import identity_resolver_for
from parser_rules import RULES
from signals import EntityType, ModalityClass, Severity

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURE = os.path.join(HERE, "fixtures", "source_parity", "trap_vedge52_cpu_recovery_20261109.json")
BACKEND = os.path.join(HERE, "..", "backend", "collectors", "mibs")
INDEX = os.path.join(BACKEND, "index", "oididx.json")
PACKS = os.path.join(BACKEND, "packs")

TENANT = "t_lab"
DEVICE = "vedge-52-749b1687"
INGEST = datetime(2026, 11, 9, 1, 35, 5, tzinfo=timezone.utc)
TS = "2026-11-09T01:35:01.212Z"
VF = "1.3.6.1.4.1.41916.100.1."
VT = "1.3.6.1.4.1.41916.100.2."
SEC_F = "1.3.6.1.4.1.9.9.1006.2."
SEC_T = "1.3.6.1.4.1.9.9.1006.0."
OMP_F = "1.3.6.1.4.1.9.9.1003.2."
OMP_T = "1.3.6.1.4.1.9.9.1003.0."

CAT = builtin_catalog()


def _index() -> dict:
    with open(INDEX, encoding="utf-8") as fh:
        return json.load(fh)["nodes"]


def _packs() -> list[dict]:
    out = []
    for fn in sorted(os.listdir(PACKS)):
        with open(os.path.join(PACKS, fn), encoding="utf-8") as fh:
            out.append(json.load(fh))
    return out


def vb(oid: str, value: str) -> dict:
    return {"oid": oid + ".0", "value": value}


def trap(oid: str, name: str, *varbinds: dict, state: str = "point", native: str = "",
         device: str = DEVICE, severity: str = "notice", tenant_field: str | None = None) -> dict:
    ev = {
        "_signal": "snmptrap", "timestamp": TS, "device": device, "trap_oid": oid, "trap_name": name,
        "event_type": re.sub(r"([A-Z])", lambda m: "_" + m.group(1).lower(), name),
        "severity": severity, "event_state": state, "varbinds": list(varbinds),
    }
    if native:
        ev["severity_native_text"] = native
    if tenant_field is not None:
        ev["tenant_id"] = tenant_field
    return ev


def classify(ev: dict, tenant: str = TENANT):
    return P.trap_control_signal(ev, tenant, INGEST)


def cpu(state: str, native: str, warning: str) -> dict:
    return trap(VT + "114", "viptelaSystemCpuUsage", vb(VF + "54", warning), state=state, native=native)


def bfd(state: str, native: str = "major", reverse: bool = False) -> dict:
    a, b = ("10.255.255.52", "biz-internet"), ("10.255.255.20", "mpls")
    if reverse:
        a, b = b, a
    return trap(VT + "4", "viptelaBfdBfdStateChange", vb(VF + "9", a[0]), vb(VF + "10", a[1]),
                vb(VF + "11", b[0]), vb(VF + "12", b[1]),
                vb(VF + "13", "down(1)" if state == "raise" else "up(0)"), state=state, native=native)


# ── the recorded trap ────────────────────────────────────────────────────────


def test_the_recorded_lab_recovery_is_a_clear_on_the_device():
    with open(FIXTURE, encoding="utf-8") as fh:
        ev = json.load(fh)
    sig = classify(ev)
    assert sig.kind == "device_resource_anomaly_clear"
    assert sig.entity_type is EntityType.DEVICE and sig.entity_id == DEVICE
    assert sig.severity is Severity.INFO
    assert sig.modality_class is ModalityClass.DEVICE_TELEMETRY
    assert sig.attrs["rule_id"] == "trap.sdwan.cpu_threshold.clear"
    assert sig.attrs["fidelity"] == "lab_validated"
    assert sig.attrs["severity_native"] == "minor"
    assert sig.attrs["cpu_idle_percent"] == "79.79"
    assert sig.attrs["warning"] == "System cpu usage back to normal level"
    assert not build_nodes([sig])


def test_the_recorded_lab_recovery_opens_nothing():
    with open(FIXTURE, encoding="utf-8") as fh:
        ev = json.load(fh)
    assert run_window([classify(ev)], CAT, (), EngineConfig()) == []


# ── D3: ingestion is not incident creation ───────────────────────────────────


def test_a_lone_warn_opens_no_object():
    sig = classify(cpu("raise", "minor", "System cpu usage is above 75%"))
    assert sig.kind == "device_resource_anomaly" and sig.severity is Severity.WARN
    assert run_window([sig], CAT, (), EngineConfig()) == []


def test_a_lone_qualifying_critical_opens_one():
    sig = classify(cpu("raise", "critical", "System cpu usage is above 90% (critically high)"))
    assert sig.kind == "device_resource_anomaly" and sig.severity is Severity.CRIT
    assert len(run_window([sig], CAT, (), EngineConfig())) == 1


def test_vendor_major_stays_below_the_open_floor():
    """vManage reports BGP transitions as `major`; D3 keeps them from opening alone."""
    sig = classify(trap(VT + "54", "viptelaVpnBgpPeerStateChange", vb(VF + "68", "192.168.200.34"),
                        vb(VF + "69", "active(2)"), state="raise", native="major"))
    assert sig.severity is Severity.WARN
    assert run_window([sig], CAT, (), EngineConfig()) == []


def test_a_warn_still_joins_the_component_a_critical_opened():
    """The other half: below the floor is not out of the evidence."""
    crit = classify(trap(VT + "27", "viptelaSecurityControlNoActiveVsmart", state="raise", native="critical"))
    warn = classify(cpu("raise", "minor", "System cpu usage is above 75%"))
    snaps = run_window([crit, warn], CAT, (), EngineConfig())
    assert len(snaps) == 1
    kinds = {s.kind for n in snaps[0].nodes for s in n.signals}
    assert kinds == {"controller_control_connection_loss", "device_resource_anomaly"}


def test_a_clear_is_no_node_and_opens_nothing():
    clear = classify(bfd("clear"))
    assert clear.kind == "controller_bfd_down_clear" and clear.severity is Severity.INFO
    assert not build_nodes([clear])
    assert run_window([clear], CAT, (), EngineConfig()) == []


@pytest.mark.parametrize("ev", [
    bfd("raise", "minor"),
    trap(VT + "20", "viptelaOmpOmpPeerStateChange", vb(VF + "27", "10.0.0.1"), vb(VF + "28", "down(4)"),
         state="raise", native="minor"),
    trap(VT + "55", "viptelaVpnInterfaceStateChange", vb(VF + "73", "ge0/0"), vb(VF + "74", "down(1)"),
         state="raise", native="major"),
    trap(VT + "23", "viptelaSecurityControlConnectionStateChange", vb(VF + "39", "down(1)"),
         state="raise", native="major"),
], ids=["bfd", "omp", "interface", "control"])
def test_every_row_below_critical_arrives_below_the_floor(ev):
    sig = classify(ev)
    assert sig.severity is Severity.WARN, sig.attrs["rule_id"]
    assert run_window([sig], CAT, (), EngineConfig()) == []


@pytest.mark.parametrize("ev,rule", [
    (bfd("raise", "critical"), "trap.sdwan.bfd"),
    (trap(VT + "20", "viptelaOmpOmpPeerStateChange", vb(VF + "27", "10.0.0.1"), vb(VF + "28", "down(4)"),
          state="raise", native="critical"), "trap.sdwan.omp"),
    (trap(VT + "55", "viptelaVpnInterfaceStateChange", vb(VF + "73", "ge0/0"), vb(VF + "74", "down(1)"),
          state="raise", native="critical"), "trap.sdwan.interface"),
    (trap(VT + "54", "viptelaVpnBgpPeerStateChange", vb(VF + "68", "10.0.0.2"), vb(VF + "69", "idle(0)"),
          state="raise", native="critical"), "trap.sdwan.bgp_peer"),
    (trap(VT + "28", "viptelaSecurityControlNoActiveVbond", state="raise", native="critical"),
     "trap.sdwan.control_connection"),
    (trap(VT + "44", "viptelaSystemMemoryUsage", vb(VF + "54", "System memory usage is above 90%"),
          state="raise", native="critical"), "trap.sdwan.memory_threshold"),
])
def test_a_native_critical_raise_is_crit(ev, rule):
    sig = classify(ev)
    assert sig.severity is Severity.CRIT and sig.attrs["rule_id"] == rule


@pytest.mark.parametrize("ev", [
    trap(VT + "55", "viptelaVpnInterfaceStateChange", vb(VF + "73", "ge0/0"), vb(VF + "74", "up(0)"),
         state="clear", native="critical"),
    trap(VT + "54", "viptelaVpnBgpPeerStateChange", vb(VF + "68", "10.0.0.2"),
         vb(VF + "69", "established(5)"), state="clear", native="critical"),
], ids=["interface", "bgp"])
def test_a_recovery_natively_critical_is_never_crit(ev):
    """Severity and lifecycle are separate facts, and a recovery opens nothing."""
    sig = classify(ev)
    assert sig.severity is Severity.WARN and sig.attrs["state"] == "up"


# ── binding: where the device's report meets the controller's ────────────────


def test_bfd_binds_the_tunnel_both_ends_share():
    a, b = classify(bfd("raise")), classify(bfd("raise", reverse=True))
    assert a.entity_type is EntityType.PATH
    assert a.entity_id == b.entity_id == "10.255.255.20/mpls|10.255.255.52/biz-internet"
    assert a.attrs["tunnel_scheme"] == "tloc_pair"


def test_the_tunnel_id_is_the_controller_lanes_spelling():
    """nms/sdwan_tunnel_test.go pins the same pair on the Go side."""
    ev = bfd("raise")
    ev["varbinds"] = [vb(VF + "9", "10.0.0.2"), vb(VF + "10", "MPLS"),
                      vb(VF + "11", "10.0.0.1"), vb(VF + "12", "biz-internet")]
    assert classify(ev).entity_id == "10.0.0.1/biz-internet|10.0.0.2/mpls"


@pytest.mark.parametrize("varbinds", [
    [],
    [vb(VF + "9", "not-an-address"), vb(VF + "10", "mpls"), vb(VF + "11", "10.0.0.1"), vb(VF + "12", "mpls")],
    [vb(VF + "9", "999.0.0.1"), vb(VF + "10", "mpls"), vb(VF + "11", "10.0.0.1"), vb(VF + "12", "mpls")],
    [vb(VF + "9", "10.0.0.1"), vb(VF + "10", "bad color!"), vb(VF + "11", "10.0.0.2"), vb(VF + "12", "mpls")],
    [vb(VF + "9", "10.0.0.1"), vb(VF + "10", "mpls"), vb(VF + "11", "10.0.0.1"), vb(VF + "12", "mpls")],
], ids=["absent", "not an address", "octet out of range", "hostile color", "tunnel to itself"])
def test_half_an_identity_binds_the_device_never_a_made_up_tunnel(varbinds):
    ev = bfd("raise")
    ev["varbinds"] = varbinds
    sig = classify(ev)
    assert sig.entity_type is EntityType.DEVICE and sig.entity_id == DEVICE
    assert "tunnel_id" not in sig.attrs and "tunnel_scheme" not in sig.attrs


@pytest.mark.parametrize("kind,ev", [
    ("controller_control_connection_loss",
     trap(VT + "23", "viptelaSecurityControlConnectionStateChange", vb(VF + "33", "10.0.0.9"),
          vb(VF + "39", "down(1)"), state="raise")),
    ("controller_control_connection_loss",
     trap(VT + "20", "viptelaOmpOmpPeerStateChange", vb(VF + "27", "10.0.0.9"), vb(VF + "28", "down(4)"),
          state="raise")),
    ("link_state_change",
     trap(VT + "55", "viptelaVpnInterfaceStateChange", vb(VF + "73", "ge0/1"), vb(VF + "74", "down(1)"),
          state="raise")),
    ("bgp_adjacency_change",
     trap(VT + "54", "viptelaVpnBgpPeerStateChange", vb(VF + "68", "10.0.0.9"), vb(VF + "69", "idle(0)"),
          state="raise")),
], ids=["control", "omp", "interface", "bgp"])
def test_device_and_controller_reports_land_on_one_node(kind, ev):
    """The same symptom from vManage, bound by the controller lane."""
    ctl = {"tenant_id": TENANT, "normalized_event_type": kind, "source_system": "vmanage",
           "integration_id": "i1", "device_id": DEVICE, "severity": "major", "event_id": "e1",
           "event_time": TS, "interface_name": "ge0/1", "peer_id": "10.0.0.9"}
    device, relayed = classify(ev), controller_event_to_signal(ctl, INGEST)
    assert device.kind == relayed.kind == kind
    assert (device.entity_type, device.entity_id) == (relayed.entity_type, relayed.entity_id)
    nodes = build_nodes([device, relayed])
    assert len(nodes) == 1, [n.key for n in nodes]


def test_the_cpu_trap_lands_on_the_metric_lanes_node():
    """main.py metric_identity binds a CPU episode to the bare device, same kind."""
    sig = classify(cpu("raise", "minor", "System cpu usage is above 75%"))
    assert (sig.kind, sig.entity_type, sig.entity_id) == ("device_resource_anomaly", EntityType.DEVICE, DEVICE)


def test_recovery_binds_the_faults_entity():
    down, up = classify(bfd("raise")), classify(bfd("clear"))
    assert down.entity_id == up.entity_id and up.kind == down.kind + "_clear"


def test_stage_one_canonicalisation_leaves_these_rows_coherent():
    """P6 canon.py, read not edited: the session and port keys are the shapes it
    canonicalises, and a tunnel id is left alone."""
    raw = {"devices": {TENANT: [{"tenant_id": TENANT, "id": DEVICE, "name": "vEdge-52",
                                 "address": "192.168.222.102"}]},
           "interface_ips": {TENANT: []},
           "ifindex": {TENANT: [{"tenant_id": TENANT, "device": DEVICE, "ifindex": "3", "ifname": "ge0/1"}]}}
    res = identity_resolver_for(raw, TENANT)
    iface = classify(trap(VT + "55", "viptelaVpnInterfaceStateChange", vb(VF + "73", "ge0/1"),
                          vb(VF + "74", "down(1)"), state="raise"))
    out = canon.canonicalize_detailed(iface, res).signal
    assert out.entity_id == f"{DEVICE}:{canon.canon_iface_key('ge0/1')}"
    assert out.native_id == iface.native_id and out.signal_id == iface.signal_id
    tunnel = classify(bfd("raise"))
    assert canon.canonicalize_detailed(tunnel, res).signal.entity_id == tunnel.entity_id
    bgp = classify(trap(VT + "54", "viptelaVpnBgpPeerStateChange", vb(VF + "68", "2001:DB8::1"),
                        vb(VF + "69", "idle(0)"), state="raise"))
    assert canon.canonicalize_detailed(bgp, res).signal.entity_id == f"{DEVICE}:2001:db8::1"


# ── what must NOT become evidence ────────────────────────────────────────────


@pytest.mark.parametrize("state", ["point", "", None])
@pytest.mark.parametrize("oid,name,varbinds", [
    (VT + "54", "viptelaVpnBgpPeerStateChange", [vb(VF + "68", "10.0.0.9"), vb(VF + "69", "connect(1)")]),
    (VT + "55", "viptelaVpnInterfaceStateChange", [vb(VF + "73", "ge0/1")]),
    (VT + "4", "viptelaBfdBfdStateChange", []),
    (VT + "20", "viptelaOmpOmpPeerStateChange", [vb(VF + "28", "handshake(2)")]),
    (VT + "23", "viptelaSecurityControlConnectionStateChange", []),
    (VT + "114", "viptelaSystemCpuUsage", [vb(VF + "54", "cpu feels odd")]),
], ids=["bgp retry leg", "interface", "bfd", "omp handshake", "control", "cpu wording"])
def test_no_state_no_fault(oid, name, varbinds, state):
    """A state the receiver could not evidence stays searchable and claims nothing.
    In particular the BGP retry leg must not fall to the event_type rule, whose
    name scan would read it as a session down."""
    ev = trap(oid, name, *varbinds, state="point", native="critical")
    if state is None:
        del ev["event_state"]
    else:
        ev["event_state"] = state
    assert classify(ev) is None


def test_a_notification_nobody_reviewed_stays_out_however_it_is_named():
    """Now they decode by name, the name-scanning rules must not mistake any other
    Cisco SD-WAN notification for a symptom. A match would be a guess with no state
    evidence behind it; the VRRP one did, as a takeover at `high`, until excluded."""
    typed = {oid for pack in _packs() for oid in pack["notifications"]}
    roots = (VT, OMP_T, SEC_T, "1.3.6.1.4.1.9.9.1002.0.")
    matched, seen = {}, 0
    for oid, node in _index().items():
        if not oid.startswith(roots) or node["kind"] != "notification" or oid in typed:
            continue
        seen += 1
        for state in ("point", "raise"):
            sig = classify(trap(oid, node["name"], state=state, native="critical"))
            if sig is not None:
                matched[node["name"]] = sig.attrs["rule_id"]
    assert seen > 100, "the sweep stopped looking at the notifications"
    assert not matched, matched


def test_a_cedge_bfd_notification_is_named_and_claims_nothing():
    """Its varbind arcs move between releases, so it gets no row until captured."""
    assert classify(trap("1.3.6.1.4.1.9.9.1002.0.1", "ciscoSdwanBfdStateChange", native="critical")) is None


# ── cEdge and the multi-vendor rows ──────────────────────────────────────────


@pytest.mark.parametrize("ev,rule,kind,severity,entity", [
    (trap(SEC_T + "1", "ciscoSdwanSecurityControlConnectionStateChange", vb(SEC_F + "5", "10.0.0.9"),
          vb(SEC_F + "12", "down(1)"), state="raise", native="major"),
     "trap.sdwan.control_connection", "controller_control_connection_loss", Severity.WARN, DEVICE),
    (trap(SEC_T + "1", "ciscoSdwanSecurityControlConnectionStateChange", vb(SEC_F + "12", "up(0)"),
          state="clear", native="minor"),
     "trap.sdwan.control_connection.clear", "controller_control_connection_loss_clear", Severity.INFO, DEVICE),
    (trap(SEC_T + "5", "ciscoSdwanSecurityControlNoActiveVsmart", state="raise", native="critical"),
     "trap.sdwan.control_connection", "controller_control_connection_loss", Severity.CRIT, DEVICE),
    (trap(OMP_T + "3", "ciscoSdwanOmpOmpPeerStateChange", vb(OMP_F + "5", "10.0.0.9"),
          vb(OMP_F + "6", "down(4)"), state="raise", native="major"),
     "trap.sdwan.omp", "controller_control_connection_loss", Severity.WARN, DEVICE),
    (trap("1.3.6.1.4.1.9.9.109.2.0.1", "cpmCPURisingThreshold"),
     "trap.resource.cpu_threshold", "device_resource_anomaly", Severity.WARN, DEVICE),
    (trap("1.3.6.1.4.1.9.9.109.2.0.2", "cpmCPUFallingThreshold"),
     "trap.resource.cpu_threshold.clear", "device_resource_anomaly_clear", Severity.INFO, DEVICE),
    (trap("1.3.6.1.2.1.222.0.2", "bfdSessDown", {"oid": "1.3.6.1.2.1.222.1.2.1.13.4", "value": "1"}),
     "trap.bfd.session", "bfd_session_flap", Severity.WARN, f"{DEVICE}:bfd-4"),
    (trap("1.3.6.1.2.1.222.0.1", "bfdSessUp", {"oid": "1.3.6.1.2.1.222.1.2.1.13.4", "value": "4"}),
     "trap.bfd.session.clear", "bfd_session_flap_clear", Severity.INFO, f"{DEVICE}:bfd-4"),
    (trap("1.3.6.1.2.1.222.0.2", "bfdSessDown"),
     "trap.bfd.session", "bfd_session_flap", Severity.WARN, DEVICE),
    (trap(VT + "21", "viptelaOmpOmpTlocStateChange", vb(VF + "29", "ipv4(1)"), native="critical"),
     "trap.sdwan.omp_tloc_change", "device_alarm", Severity.WARN, DEVICE),
])
def test_each_row(ev, rule, kind, severity, entity):
    sig = classify(ev)
    assert sig.attrs["rule_id"] == rule
    assert sig.kind == kind and sig.severity is severity and sig.entity_id == entity
    assert sig.attrs["fidelity"] == "doc_claimed"


def test_the_standard_bfd_kind_is_the_one_a_template_names():
    """The template ships disabled; its kind is reused, not invented."""
    named = {k for t in CAT.templates for c in t.requires for k in c.kind.split("|")}
    assert "bfd_session_flap" in named


# ── the catalogue's claims ───────────────────────────────────────────────────


NEW_RULES = sorted(r.rule_id for r in RULES
                   if r.rule_id.startswith(("trap.sdwan.", "trap.bfd.", "trap.resource.")))


def _oids_in(node) -> set[str]:
    out: set[str] = set()
    if isinstance(node, str):
        if re.fullmatch(r"1\.[0-9.]+", node):
            out.add(node)
    elif isinstance(node, dict):
        for v in node.values():
            out |= _oids_in(v)
    elif isinstance(node, (list, tuple)):
        for v in node:
            out |= _oids_in(v)
    return out


def _rows() -> list[dict]:
    import parser_rules
    return [r for r in parser_rules._ROWS if r["rule_id"] in NEW_RULES]


def test_a_rule_names_only_oids_that_resolve_in_the_index():
    nodes = _index()
    rows = _rows()
    assert len(rows) == 17
    for row in rows:
        for oid in _oids_in(row["guard"]) | _oids_in(row.get("extract")):
            assert oid in nodes, f"{row['rule_id']}: {oid} is not in the MIB index"


def test_only_the_captured_row_claims_more_than_doc_claimed():
    claims = {r["rule_id"]: r["fidelity_status"] for r in _rows()}
    captured = {k for k, v in claims.items() if v != "doc_claimed"}
    assert captured == {"trap.sdwan.cpu_threshold.clear"}
    assert claims["trap.sdwan.cpu_threshold.clear"] == "lab_validated"


def test_every_pack_state_has_a_typed_row():
    """A listed notification's normalized severity follows the vendor's, so it must
    never fall to the generic alarm, where a `crit` would open an object unreviewed."""
    typed_rules = set(NEW_RULES) | {"trap.link.state_change", "trap.bgp.adjacency_change"}
    for pack in _packs():
        for oid, row in pack["notifications"].items():
            for state in ("raise", "clear"):
                can = (row.get("event_state") == state or row.get(state)
                       or any(t["state"] == state for t in row.get("text", ())))
                if not can:
                    continue
                sig = classify(trap(oid, row["name"], state=state, native="critical", severity="crit"))
                assert sig is not None and sig.attrs["rule_id"] in typed_rules, (oid, state)


def test_the_row_kinds_are_registered():
    for r in _rows():
        assert r["kind"] in P.EMITTED_KINDS, r["rule_id"]


def test_redelivery_keeps_its_identity_and_a_new_transition_does_not():
    a = classify(bfd("raise"))
    assert a.signal_id == classify(bfd("raise")).signal_id
    assert a.signal_id != classify(bfd("clear")).signal_id


# ── §3a unchanged ────────────────────────────────────────────────────────────


def test_tenant_comes_from_the_caller_never_the_trap():
    ev = trap(VT + "27", "viptelaSecurityControlNoActiveVsmart", state="raise", native="critical",
              tenant_field="someone_else")
    assert classify(ev, "t_a").tenant_id == "t_a"


def test_a_window_stays_single_tenant():
    a = classify(trap(VT + "27", "viptelaSecurityControlNoActiveVsmart", state="raise", native="critical"), "t_a")
    b = replace(a, tenant_id="t_b")
    with pytest.raises(ValueError):
        run_window([a, b], CAT, (), EngineConfig())


def test_one_tenants_critical_opens_only_its_own_object():
    a = classify(trap(VT + "27", "viptelaSecurityControlNoActiveVsmart", state="raise", native="critical"), "t_a")
    snaps = run_window([a], CAT, (), EngineConfig())
    assert [s.tenant_id for s in snaps] == ["t_a"]
