# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""SD-WAN controller unreachable — stage [6] structural fan-in (2026-11-11).

The outage (lab, 2026-11-10, proven with read-only vEdge CLI): the vSmart was shut
down. Every edge lost its control connection to it, so OMP, centralized policy (and
the cflowd flow-export config it carries) and BFD went with it. The engine saw N
unrelated symptoms because nothing could tell "many edges lost the SAME controller"
from "one edge lost its controllers".

What this pins:

* stage [1]: the syslog control-connection rows now emit the lost controller as a
  token (as the trap rows did), and `signals.controller_peer` reads the controller
  every lane names (syslog/trap `peer`, the controller's `peer_id` or the address
  nms/identity.go kept in `correlation_hints.controller_peer_id`);
* stage [6]: the `controller_fan_in` structure (>=2 distinct edges, per lane, lost
  the same controller) admits `sig.ent.wan-edge.sdwan-controller-unreachable`, names
  the controller in a hypothesis note, and — through a structure-conditioned
  discriminator — rules out the edge-local reading;
* the tier stays suspected ("possibly because of X"): the edges meet only on the
  shared controller address, a rank-7 token, never authoritative;
* negatives: one edge losing its control connection, one edge's WAN going down
  while the controller is up, flows going quiet with control connections up, one
  edge seen through three lanes, two edges losing two different controllers;
* evidence with no control-connection loss is byte-identical with and without the
  change; the rank memo keys what the gate reads.
"""
from __future__ import annotations

import json
from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

import catalog as C
import scoring
from catalog import (
    SDWAN_CONTROLLER_UNREACHABLE_TEMPLATE_ID,
    builtin_catalog,
    load_catalog,
)
from controller_events import controller_event_to_signal
from engine import ENGINE_SEMVER, EngineConfig, run_window
from producers import syslog_control_signal, syslog_promotable, trap_control_signal
from rank_memo import rank_key, signal_projection
from scoring import (
    controller_fan_in,
    controller_fan_in_note,
    evidence_kinds,
    evidence_structure,
    rank,
)
from signals import (
    EntityType,
    ModalityClass,
    Observer,
    ObserverType,
    Severity,
    Signal,
    Source,
    controller_peer,
)
from test_fixtures import fixture_files, signal_from_fixture
from verdicts import VerdictTier

T0 = datetime(2026, 11, 10, 9, 0, 0, tzinfo=timezone.utc)
TENANT = "t1"
CAT = builtin_catalog()
CONTROLLER = SDWAN_CONTROLLER_UNREACHABLE_TEMPLATE_ID
LOCAL = "sig.ent.wan-edge.sdwan-control-connection-loss"
VSMART = "10.255.255.2"
VMANAGE = "10.255.255.1"
EDGES = ("vEdge-20", "vEdge-21", "vEdge-22")
FAN_IN_TAG = "sdwan_control_down|controller_control_connection_loss@controller_fan_in"


# ── stage [1] producers: the shapes the lanes really emit ────────────────────


def _syslog(message: str, app: str, host: str, off: float):
    ts = T0 + timedelta(seconds=off)
    ev = {"hostname": host, "appname": app, "severity": "notice", "message": message,
          "timestamp": ts.isoformat()}
    assert syslog_promotable(ev)
    return syslog_control_signal(ev, TENANT, ts)


def control_down(host: str, off: float, peer: str = VSMART, ptype: str = "vsmart"):
    """The pack's documented VDAEMON control-connection line (cisco_sdwan.yaml)."""
    return _syslog(
        f"%Viptela-{host}-VDAEMON_0-5-NTCE-1000001: control-connection-state-change "
        f"new-state:down peer-type:{ptype} peer-system-ip:{peer} public-ip:192.0.2.3 "
        f"public-port:12346 domain-id:1 site-id:1005", "VDAEMON", host, off)


def control_up(host: str, off: float, peer: str = VSMART):
    return _syslog(
        f"%Viptela-{host}-VDAEMON_0-5-NTCE-1000001: control-connection-state-change "
        f"new-state:up peer-type:vsmart peer-system-ip:{peer} public-ip:192.0.2.3 "
        f"public-port:12346 domain-id:1 site-id:1005", "VDAEMON", host, off)


def bfd_down(host: str, off: float):
    """The pack's documented FTMD BFD line."""
    return _syslog(
        f'%Viptela-{host}-ftmd-6-INFO-1400002: Notification: bfd-state-change '
        f'severity-level:major host-name:"{host}" system-ip:192.0.2.1 local-color:"mpls" '
        f'remote-color:"biz-internet" new-state:down deleted:"false" flap-reason:timeout',
        "FTMD", host, off)


VF = "1.3.6.1.4.1.41916.100.1."
VT = "1.3.6.1.4.1.41916.100.2."


def trap_control_down(device: str, off: float, peer: str = VSMART):
    """viptelaSecurityControlConnectionStateChange, the Go receiver's event shape
    (test_trap_packs_387)."""
    ts = T0 + timedelta(seconds=off)
    ev = {"_signal": "snmptrap", "timestamp": ts.isoformat(), "device": device,
          "trap_oid": VT + "23", "trap_name": "viptelaSecurityControlConnectionStateChange",
          "event_type": "viptela_security_control_connection_state_change",
          "severity": "notice", "event_state": "raise", "severity_native_text": "major",
          "varbinds": [{"oid": VF + "32.0", "value": "vsmart(3)"},
                       {"oid": VF + "33.0", "value": peer},
                       {"oid": VF + "39.0", "value": "down(1)"}]}
    return trap_control_signal(ev, TENANT, ts)


def vmanage_control_down(system_ip: str, off: float, peer: str = VSMART, *,
                         rewritten_to: str = "", site: str = ""):
    """A normalized vManage control-connection transition (nms/vmanage_events.go).
    `rewritten_to` mimics nms/identity.go replacing the peer with an inventory id."""
    hints = {"component": "Control", "system_ip": system_ip, "peer_type": "vsmart"}
    peer_id = peer
    if rewritten_to:
        hints["controller_peer_id"] = peer
        peer_id = rewritten_to
    ev = {"tenant_id": TENANT, "normalized_event_type": "controller_control_connection_loss",
          "source_system": "vmanage", "integration_id": "vm1", "device_id": system_ip,
          "site_id": site, "peer_id": peer_id, "severity": "high",
          "event_time": (T0 + timedelta(seconds=off)).isoformat(),
          "event_id": f"cc-{system_ip}-{off}", "correlation_hints": hints}
    sig = controller_event_to_signal(ev, T0 + timedelta(seconds=off))
    assert sig is not None
    return sig


def flow_drop(sampler: str, off: float, sev: Severity = Severity.HIGH) -> Signal:
    """A flow_volume_anomaly drop as main._flush_flow_aggregator emits it: an
    INTERFACE entity grounded on the exporter address only."""
    return Signal(
        tenant_id=TENANT, ts=T0 + timedelta(seconds=off), source=Source.FLOW,
        kind="flow_volume_anomaly",
        observer=Observer(observer_id=sampler, observer_type=ObserverType.FLOW_EXPORTER,
                          collection_path="flow_export"),
        modality_class=ModalityClass.PASSIVE_FLOW, entity_type=EntityType.INTERFACE,
        entity_id=f"{sampler}:if3", severity=sev, native_id=f"flow|{sampler}|{off}",
        entity_tokens=(sampler,), deviation=-9.0)


def link_down(host: str, iface: str, off: float) -> Signal:
    return Signal(
        tenant_id=TENANT, ts=T0 + timedelta(seconds=off), source=Source.TRAP,
        kind="link_state_change",
        observer=Observer(observer_id=host, observer_type=ObserverType.DEVICE),
        modality_class=ModalityClass.CONTROL_PLANE, entity_type=EntityType.INTERFACE,
        entity_id=f"{host}:{iface}", severity=Severity.HIGH,
        native_id=f"link|{host}|{iface}|{off}", entity_tokens=(host,),
        attrs={"state": "down", "link_cause": "fault"})


def outage() -> list[Signal]:
    """2026-11-10: three edges lose the vSmart within seconds, then their BFD
    sessions; flows from their exporters drop."""
    win: list[Signal] = []
    for i, host in enumerate(EDGES):
        win.append(control_down(host, 2.0 * i))
        win.append(bfd_down(host, 20.0 + 2.0 * i))
    win += [flow_drop(f"192.168.20.{i}", 90.0 + i) for i in range(3)]
    return win


def _objects(win):
    return run_window(win, CAT, (), EngineConfig())


def _hyp(ranking, template_id):
    return next(h for h in ranking.hypotheses if h.template_id == template_id)


def _controller_objects(snaps):
    return [s for s in snaps if s.ranking.top_hypothesis == CONTROLLER]


# ══ stage [1]: the controller each lane names ═══════════════════════════════


def test_the_syslog_row_emits_the_lost_controller_as_a_token():
    sig = control_down("vEdge-20", 0)
    assert sig.kind == "controller_control_connection_loss"
    assert sig.severity is Severity.WARN, "ingestion is not incident creation (D3)"
    assert set(sig.entity_tokens) == {"vEdge-20", VSMART}
    assert controller_peer(sig) == (VSMART, "vsmart")


def test_the_syslog_clear_carries_the_same_token():
    sig = control_up("vEdge-20", 0)
    assert sig.kind == "controller_control_connection_loss_clear"
    assert VSMART in sig.entity_tokens


def test_the_trap_names_the_controller_and_its_role():
    sig = trap_control_down("vedge-20-1e95f00f", 0)
    assert sig.kind == "controller_control_connection_loss"
    assert controller_peer(sig) == (VSMART, "vsmart"), "the enum `vsmart(3)` reads as vsmart"


def test_the_controller_relay_prefers_the_address_identity_rewrote():
    sig = vmanage_control_down("10.255.255.20", 0, rewritten_to="vsmart-1-abc")
    assert sig.attrs["peer_id"] == "vsmart-1-abc"
    assert controller_peer(sig) == (VSMART, "vsmart"), \
        "all three lanes must spell one controller by its system-ip"
    plain = vmanage_control_down("10.255.255.21", 0)
    assert controller_peer(plain) == (VSMART, "vsmart")


@pytest.mark.parametrize("attrs", [
    {}, {"peer": ""}, {"peer": "   "}, {"peer": 7}, {"peer": "a b"}, {"peer": "x" * 65},
    {"peer": "{peer}"}, {"peer": "<script>"}, {"peer": "vEdge-20"},   # itself
    {"peer_id": None}, {"correlation_hints": "10.255.255.2"},
], ids=lambda a: repr(a)[:40])
def test_a_malformed_or_self_peer_names_no_controller(attrs):
    sig = replace(control_down("vEdge-20", 0), attrs=attrs)
    assert controller_peer(sig) == ("", "")


def test_another_kind_names_no_controller_even_with_a_peer():
    sig = replace(bfd_down("vEdge-20", 0), attrs={"peer": VSMART})
    assert controller_peer(sig) == ("", "")


@pytest.mark.parametrize("raw,want", [
    ("vsmart", "vsmart"), ("VSMART", "vsmart"), ("vsmart(3)", "vsmart"), ("3", ""),
    ("v smart", ""), ("", ""), (5, ""),
])
def test_peer_type_is_one_short_word(raw, want):
    sig = replace(control_down("vEdge-20", 0), attrs={"peer": VSMART, "peer_type": raw})
    assert controller_peer(sig) == (VSMART, want)


# ══ stage [6]: the fan-in count ═════════════════════════════════════════════


def test_three_edges_one_controller_is_a_fan_in():
    ev = tuple(control_down(h, i) for i, h in enumerate(EDGES))
    assert controller_fan_in(ev) == ((VSMART, "vsmart", 3),)
    assert "controller_fan_in" in evidence_structure(ev, evidence_kinds(ev))


def test_one_edge_is_not_a_fan_in():
    ev = (control_down("vEdge-20", 0), control_down("vEdge-20", 5))
    assert controller_fan_in(ev) == ()
    assert "controller_fan_in" not in evidence_structure(ev, evidence_kinds(ev))


def test_one_edge_through_three_lanes_is_not_a_fan_in():
    """Hostname, inventory id and system-ip are three spellings of ONE box until
    identity canonicalisation is on; counting across lanes would let it fan in
    on its own."""
    ev = (control_down("vEdge-20", 0), trap_control_down("vedge-20-1e95f00f", 1),
          vmanage_control_down("10.255.255.20", 2))
    assert controller_fan_in(ev) == ()


def test_two_edges_two_controllers_is_not_a_fan_in():
    ev = (control_down("vEdge-20", 0, peer=VSMART), control_down("vEdge-21", 1, peer=VMANAGE))
    assert controller_fan_in(ev) == ()


def test_the_fan_in_counts_per_lane_and_takes_the_widest():
    ev = (control_down("vEdge-20", 0), control_down("vEdge-21", 1),
          vmanage_control_down("10.255.255.20", 2), vmanage_control_down("10.255.255.21", 3),
          vmanage_control_down("10.255.255.22", 4))
    assert controller_fan_in(ev) == ((VSMART, "vsmart", 3),)


def test_an_interface_entity_or_a_debug_signal_is_not_an_edge():
    a, b = control_down("vEdge-20", 0), control_down("vEdge-21", 1)
    iface = replace(b, entity_type=EntityType.INTERFACE)
    assert controller_fan_in((a, iface)) == ()
    debug = replace(b, attrs={**b.attrs, "probe_authority": "debug_only"},
                    modality_class=ModalityClass.ACTIVE_PROBE)
    assert controller_fan_in((a, debug)) == ()


def test_the_note_names_the_controller():
    note = controller_fan_in_note(((VSMART, "vsmart", 3), ("10.9.9.9", "", 2)))
    assert note == (f"controller fan-in: 3 edges lost their control connection to controller "
                    f"{VSMART} (vSmart); 2 edges lost their control connection to controller 10.9.9.9")
    many = tuple((f"10.0.0.{i}", "", 2) for i in range(6))
    assert controller_fan_in_note(many).endswith("; and 2 more controller(s)")


# ══ the outage, end to end ══════════════════════════════════════════════════


def test_the_outage_is_one_incident_whose_cause_is_the_controller():
    snaps = _objects(outage())
    ctl = _controller_objects(snaps)
    assert len(ctl) == 1, [(s.ranking.top_hypothesis, [n.key for n in s.nodes]) for s in snaps]
    obj = ctl[0]
    kinds_by_entity = {(n.entity_id, n.kind) for n in obj.nodes}
    for host in EDGES:
        assert (host, "controller_control_connection_loss") in kinds_by_entity
        assert (host, "controller_bfd_down") in kinds_by_entity
    # Every control-loss node and BFD node is in THIS object: no per-edge
    # incident is left over for the same outage.
    others = [s for s in snaps if s is not obj]
    for s in others:
        assert not {n.kind for n in s.nodes} & {"controller_control_connection_loss",
                                                 "controller_bfd_down"}


def test_the_outage_reads_possibly_because_of_the_controller():
    obj = _controller_objects(_objects(outage()))[0]
    top = _hyp(obj.ranking, CONTROLLER)
    # "possibly because of X" until confirmed: the edges meet only on the shared
    # controller address (rank 7), so the tier is capped at suspected.
    assert obj.ranking.verdict_tier is VerdictTier.SUSPECTED
    assert top.confidence_label() != "confirmed"
    assert top.operator_phrase.startswith("Possibly an SD-WAN controller outage")
    assert "flow export" in top.operator_phrase
    assert top.seams == ("WAN_SDWAN",)
    assert top.owner == "sdwan_vendor"
    assert any(n == (f"controller fan-in: 3 edges lost their control connection to "
                     f"controller {VSMART} (vSmart)") for n in top.notes), top.notes
    chain = {st["stage"]: st["witnessed"] for st in top.causal_chain}
    assert chain == {"SD-WAN controller": False,
                     "Edge control connections to the controller": True,
                     "Overlay tunnels (BFD)": True}


def test_the_edge_local_reading_is_ruled_out_and_shown():
    ranking = _controller_objects(_objects(outage()))[0].ranking
    local = _hyp(ranking, LOCAL)
    assert local.contradicted and FAN_IN_TAG in local.contradictions
    assert CONTROLLER in local.forced_competitors
    assert local.confidence_rank < _hyp(ranking, CONTROLLER).confidence_rank


def test_the_outage_with_the_trap_and_controller_lanes():
    """NMS-first: vManage relaying every edge's transition plus two edges' own
    traps; all three spell the controller by its system-ip."""
    win = [vmanage_control_down(f"10.255.255.{20 + i}", i) for i in range(3)]
    win += [trap_control_down(f"vedge-{20 + i}-x", 5 + i) for i in range(2)]
    snaps = _objects(win)
    ctl = _controller_objects(snaps)
    assert len(ctl) == 1
    assert len({n.entity_id for n in ctl[0].nodes}) == 5
    # Two planes (the edges' traps, the manager's relay) agree the sessions died;
    # the gate would confirm that, and the template caps it: that the controller
    # itself failed is still "possibly".
    top = _hyp(ctl[0].ranking, CONTROLLER)
    assert ctl[0].ranking.verdict_tier is VerdictTier.SUSPECTED
    assert any("allow_root_cause_confirmed=false" in r for r in top.verdict_gate.reasons), \
        top.verdict_gate.reasons


def test_the_controllers_own_unreachability_witnesses_the_root_rung():
    win = outage() + [vmanage_unreachable(VSMART, 30.0)]
    obj = _controller_objects(_objects(win))[0]
    top = _hyp(obj.ranking, CONTROLLER)
    assert {st["stage"]: st["witnessed"] for st in top.causal_chain}["SD-WAN controller"]
    assert "controller_device_unreachable" in top.satisfied


def vmanage_unreachable(system_ip: str, off: float) -> Signal:
    ev = {"tenant_id": TENANT, "normalized_event_type": "controller_device_unreachable",
          "source_system": "vmanage", "integration_id": "vm1", "device_id": system_ip,
          "severity": "high", "event_time": (T0 + timedelta(seconds=off)).isoformat(),
          "event_id": f"unreach-{system_ip}"}
    sig = controller_event_to_signal(ev, T0 + timedelta(seconds=off))
    assert sig is not None
    return sig


# ══ negatives ═══════════════════════════════════════════════════════════════


def test_one_edge_losing_its_control_connection_is_a_local_cause():
    snaps = _objects([control_down("vEdge-20", 0), bfd_down("vEdge-20", 15)])
    assert len(snaps) == 1
    ranking = snaps[0].ranking
    assert ranking.top_hypothesis == LOCAL
    assert not _hyp(ranking, LOCAL).contradicted
    ctl = [h for h in ranking.hypotheses if h.template_id == CONTROLLER]
    assert all(h.confidence_rank == 0.0 for h in ctl), "no fan-in, no controller verdict"


def test_controller_up_but_one_edges_wan_down_is_not_the_controller():
    """The edge's transport fails: it loses the vSmart AND the vManage, its BFD
    and its WAN link. Only one edge — no fan-in."""
    win = [link_down("vEdge-20", "ge0/0", 0),
           control_down("vEdge-20", 3, peer=VSMART),
           control_down("vEdge-20", 4, peer=VMANAGE, ptype="vmanage"),
           bfd_down("vEdge-20", 15)]
    snaps = _objects(win)
    assert snaps
    for s in snaps:
        assert s.ranking.top_hypothesis != CONTROLLER
        assert all(h.confidence_rank == 0.0 for h in s.ranking.hypotheses
                   if h.template_id == CONTROLLER)


def test_flows_silent_with_control_connections_up_is_not_this_cause():
    win = [flow_drop(f"192.168.20.{i}", float(i)) for i in range(3)]
    win += [control_up(h, 30.0 + i) for i, h in enumerate(EDGES)]   # clears: up, not down
    for s in _objects(win):
        assert s.ranking.top_hypothesis != CONTROLLER
        assert all(h.confidence_rank == 0.0 for h in s.ranking.hypotheses
                   if h.template_id == CONTROLLER)


def test_two_edges_losing_different_controllers_are_not_one_controller():
    ranking = rank(CAT, (control_down("vEdge-20", 0, peer=VSMART),
                         control_down("vEdge-21", 1, peer=VMANAGE, ptype="vmanage")))
    assert ranking.top_hypothesis == LOCAL


def test_three_lanes_of_one_edge_are_not_a_controller_outage():
    ranking = rank(CAT, (control_down("vEdge-20", 0), trap_control_down("vedge-20-1e95f00f", 1),
                         vmanage_control_down("10.255.255.20", 2)))
    assert ranking.top_hypothesis == LOCAL


def test_the_recovery_opens_nothing():
    assert _objects([control_up(h, i) for i, h in enumerate(EDGES)]) == []


# ══ rank memo: the key carries what the gate reads ══════════════════════════


def test_the_lane_moves_rank_so_it_is_keyed():
    """Two edges in ONE lane fan in; the same two ids split across two lanes do
    not. `source` therefore reaches `rank` for these kinds and is in the key."""
    a, b = control_down("vEdge-20", 0), control_down("vEdge-21", 1)
    split = replace(b, source=Source.TRAP)
    assert rank(CAT, (a, b)).top_hypothesis == CONTROLLER
    assert rank(CAT, (a, split)).top_hypothesis == LOCAL
    catv = CAT.version_hash()
    assert rank_key(TENANT, catv, (a, b)) != rank_key(TENANT, catv, (a, split))


def test_the_controller_and_its_role_are_keyed():
    a = control_down("vEdge-20", 0)
    assert signal_projection(a) != signal_projection(
        replace(a, attrs={**a.attrs, "peer": VMANAGE}))
    assert signal_projection(a) != signal_projection(
        replace(a, attrs={**a.attrs, "peer_type": "vbond"}))


def test_other_kinds_project_as_before():
    """The new element is () for every kind outside CONTROL_LOSS_KINDS, and the
    lane never reaches their key."""
    b = bfd_down("vEdge-20", 0)
    assert signal_projection(b)[-2] == ()
    assert signal_projection(b) == signal_projection(replace(b, source=Source.TRAP))


# ══ byte identity for evidence with no control-connection loss ══════════════


def _catalog_before() -> C.Catalog:
    """The shipped catalog minus this change: no controller template, and the
    edge-local template as it was (producer-less mandatory kind, optional relay
    clause, one discriminator)."""
    raw = []
    for t in C.BUILTIN_TEMPLATES:
        if t["id"] == CONTROLLER:
            continue
        if t["id"] == LOCAL:
            t = dict(t)
            t["requires"] = [
                {"kind": "sdwan_control_down", "entity_type": "device"},
                {"kind": "tunnel_flap|path_change", "optional": True},
                {"kind": "cert_expiry_warning", "optional": True},
                {"kind": "controller_control_connection_loss", "entity_type": "device",
                 "optional": True},
            ]
            t["discriminators"] = [d for d in t["discriminators"] if "attested" not in d]
        raw.append(t)
    return load_catalog(raw)


def _strip(blob: str) -> dict:
    data = json.loads(blob)
    data.pop("engine", None)
    data.pop("catalog_version", None)
    data.get("ranking", {}).pop("catalog_version", None)
    return data


NEW_LOCAL_CLAUSE = "sdwan_control_down|controller_control_connection_loss"


def _old_label(data: dict) -> dict:
    """The ONE expected difference: the edge-local template's row names its own
    mandatory clause, and that clause's text changed. Restored to the old text."""
    for h in data.get("ranking", {}).get("hypotheses", []):
        if h.get("id") == LOCAL:
            h["missing"] = ["sdwan_control_down" if m == NEW_LOCAL_CLAUSE else m
                            for m in h.get("missing", [])]
    return data


def _corpus_blobs(cat, relabel: bool = False) -> dict[str, list[dict]]:
    out: dict[str, list[dict]] = {}
    for path in fixture_files():
        raw = path.read_text()
        if "controller_control_connection_loss" in raw or "sdwan_control_down" in raw:
            continue
        ev = [signal_from_fixture(s, i) for i, s in enumerate(json.loads(raw)["signals"])]
        blobs = [_strip(o.hypotheses_blob()) for o in run_window(ev, cat, ())]
        out[path.stem] = [_old_label(b) for b in blobs] if relabel else blobs
    return out


def test_no_control_loss_evidence_is_byte_identical_with_and_without_the_change():
    before, after = _corpus_blobs(_catalog_before()), _corpus_blobs(CAT, relabel=True)
    assert len(after) > 100, "the corpus must actually be exercised"
    assert after == before
    # ...and the relabel is not hiding anything else: it moved only that leaf.
    moved = {k for k, v in _corpus_blobs(CAT).items() if v != before[k]}
    assert moved == {"dem-b-network-degradation-backend-healthy", "mtu-blackhole-fires",
                     "mtu-blackhole-same-controller-suspected", "sdwan-tunnel-degraded-confirmed"}


def test_the_flow_drops_alone_are_byte_identical():
    win = [flow_drop(f"192.168.20.{i}", float(i)) for i in range(3)]
    assert [_strip(o.hypotheses_blob()) for o in run_window(win, CAT, ())] == \
           [_strip(o.hypotheses_blob()) for o in run_window(win, _catalog_before(), ())]


def test_before_the_change_the_outage_had_no_name():
    """The regression this fixes, kept as a fact: on the old catalog the same
    evidence ranks no SD-WAN control-plane template at all."""
    old = run_window(outage(), _catalog_before(), ())
    assert old
    assert all(s.ranking.top_hypothesis not in (CONTROLLER, LOCAL) for s in old)


def test_engine_semver_moved():
    assert ENGINE_SEMVER == "3.4.0"


def test_the_structure_gate_refuses_without_fan_in():
    """The template is excluded from ranking, with the refusal on the record."""
    ranking = rank(CAT, (control_down("vEdge-20", 0),))
    row = next((h for h in ranking.hypotheses if h.template_id == CONTROLLER), None)
    assert row is None or (row.confidence_rank == 0.0 and row.notes
                           and "controller_fan_in" in row.notes[0])
    assert scoring.STRUCTURE_FAN_IN_ATTESTED == frozenset({"controller_fan_in"})
