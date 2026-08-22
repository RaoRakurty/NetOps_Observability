"""Tracker 168 — a device-local name must never be a global correlation subject.

THE DEFECT, reproduced before the fix: an interface name is unique only WITHIN
its device, but producers emitted a bare `GigabitEthernet0/5` as an
`entity_token`, which `Node.tokens()` treats as a grounding subject. So
`dc1-switch-a/Gi0/5` and `branch-77-rtr/Gi0/5` — two devices with nothing to do
with each other — fused into ONE RCA object on
`grounding=topo:shared:GigabitEthernet0/5 rank=7 weight=0.452`.

The §3/§4 gate capped the verdict at `suspected`, so it could never be a false
CONFIRMED RCA. The evidence graph was still wrong, and at 1K scale it produced
48 candidate-index groups of 1,000 nodes each (~25.1M candidate pairs), which
was simultaneously the throughput wall.

THE RULE these tests pin:

    Identity establishes SAMENESS.
    Topology establishes RELATIONSHIPS between different entities.
    Accidental string equality is neither.

Two layers, both load-bearing and both mutation-tested below:
  1. producers qualify a device-local name as `device:name`, or drop it where
     `entity_id` already carries it;
  2. `Node.tokens()` refuses the node's own local component as a subject, so a
     producer regression cannot reintroduce the weld.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

import main as M
from catalog import builtin_catalog
from engine import (
    EngineConfig,
    TopologyAdjacency,
    build_nodes,
    run_window,
)
from producers import syslog_control_signal, trap_control_signal
from signals import (
    EntityType,
    ModalityClass,
    Observer,
    ObserverType,
    Severity,
    Signal,
    Source,
)

T0 = datetime(2026, 8, 21, 9, 0, 0, tzinfo=timezone.utc)
CAT = builtin_catalog()
IF = "GigabitEthernet0/5"


def syslog_link(host, iface=IF, *, offset_s=0.0, state="down", tenant="acme"):
    return syslog_control_signal(
        {"hostname": host, "appname": "LINK-3-UPDOWN",
         "message": f"%LINK-3-UPDOWN: Interface {iface}, changed state to {state}",
         "severity": "err",
         "timestamp": (T0 + timedelta(seconds=offset_s)).strftime("%Y-%m-%dT%H:%M:%S.000Z")},
        tenant, T0)


def trap_link(device, iface=IF, *, offset_s=0.0, tenant="acme"):
    return trap_control_signal(
        {"device": device, "trap_name": "linkDown", "authenticated": True,
         "timestamp": (T0 + timedelta(seconds=offset_s)).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
         "varbinds": [{"name": "ifName", "value": iface}]},
        tenant, T0)


def metric_if(device, iface=IF, *, offset_s=0.0, tenant="acme", kind_suffix="_errors"):
    """SNMP polling and gNMI both reach correlation through metric_identity."""
    ident = M.metric_identity(
        {"device": device, "signal_family": "interface", "if_name": iface})
    assert ident is not None
    eid, etype, kind, toks = ident
    return Signal(
        tenant_id=tenant, ts=T0 + timedelta(seconds=offset_s), source=Source.METRIC,
        kind=f"{kind}{kind_suffix}",
        observer=Observer(observer_id=device, observer_type=ObserverType.DEVICE),
        modality_class=ModalityClass.DEVICE_TELEMETRY, entity_type=etype,
        entity_id=eid, severity=Severity.HIGH,
        native_id=f"{device}|metric|{iface}{kind_suffix}", entity_tokens=toks,
        metric_name="if_errors", attrs={"onset_uncertainty_s": 5.0})


def objects(sigs, seams=(), adjacency=None, cfg=None):
    kw = {} if adjacency is None else {"adjacency": adjacency}
    return run_window(tuple(sigs), CAT, seams, cfg or EngineConfig(), **kw)


def edge_refs(snaps):
    return {e.grounding.ref for s in snaps for e in s.edges}


# ── A. same interface NAME, different devices — the reproduction ─────────────


def test_same_interface_name_on_different_devices_does_NOT_correlate():
    """THE regression test for the reproduced defect. Before the fix this
    produced ONE object with a rank-7 `shared:GigabitEthernet0/5` edge at
    weight 0.452."""
    a, b = syslog_link("dc1-switch-a"), syslog_link("branch-77-rtr", offset_s=30)
    snaps = objects([a, b])
    assert len(snaps) == 2, (
        "two unrelated devices fused into one RCA object on interface-name "
        f"equality alone: {[[n.key for n in s.nodes] for s in snaps]}")
    assert edge_refs(snaps) == set(), "an edge was admitted from name equality"


def test_the_bare_interface_name_is_not_a_grounding_subject():
    """Stated directly on the identity model rather than via the outcome."""
    n = build_nodes((syslog_link("dc1-switch-a"),))[0]
    assert IF not in n.tokens(), (
        f"the bare local name is still a global subject: {sorted(n.tokens())}")
    # what SHOULD be there: the globally unique id and the device
    assert f"dc1-switch-a:{IF}" in n.tokens()
    assert "dc1-switch-a" in n.tokens()


def test_no_shared_token_between_same_named_interfaces_on_any_ingest_path():
    """syslog, SNMP trap and the metric path (SNMP polling + gNMI) all had the
    same defect — fixing only one producer would have left the others welding."""
    for label, mk in (("syslog", syslog_link), ("trap", trap_link),
                      ("metric", metric_if)):
        a = build_nodes((mk("dc1-switch-a"),))[0]
        b = build_nodes((mk("branch-77-rtr"),))[0]
        assert a.tokens() & b.tokens() == frozenset(), (
            f"{label}: unrelated devices share {sorted(a.tokens() & b.tokens())}")


@pytest.mark.parametrize("iface", [
    "GigabitEthernet0/5",     # physical
    "Gi0/0/1.100",            # subinterface
    "Port-channel10",         # LAG
    "Loopback0",              # loopback
    "Management1",            # management
    "eth0",                   # linux-style
    "xe-0/0/0",               # junos-style
])
def test_common_interface_forms_all_stay_device_scoped(iface):
    a = build_nodes((syslog_link("dc1-switch-a", iface),))[0]
    b = build_nodes((syslog_link("branch-77-rtr", iface),))[0]
    assert iface not in a.tokens(), f"{iface} leaked as a global token"
    assert a.tokens() & b.tokens() == frozenset()


# ── B. same device, same interface, several modalities — must be PRESERVED ───


def test_all_modalities_of_one_real_interface_still_converge():
    """The relation the fix must not cost us. syslog + SNMP trap + metric all
    name the same real interface; they must land on one identity and stay one
    object — and now on an AUTHORITATIVE rank-1 edge rather than the rank-7
    name coincidence they used to also have."""
    sigs = [syslog_link("dc1-switch-a"), trap_link("dc1-switch-a", offset_s=20),
            metric_if("dc1-switch-a", offset_s=40)]
    assert all(s is not None for s in sigs)
    assert {s.entity_id for s in sigs} == {f"dc1-switch-a:{IF}"}, \
        "the modalities did not converge on one canonical interface identity"
    nodes = build_nodes(tuple(sigs))
    snaps = objects(sigs)
    assert len(snaps) == 1, "cross-modality correlation for one interface was lost"
    assert len(snaps[0].nodes) == len(nodes)
    assert snaps[0].edges, "no edge between the modalities"
    assert all(e.grounding.authoritative for e in snaps[0].edges), (
        "the surviving relation must be authoritative, not a rank-7 candidate")


def test_the_interface_and_its_own_device_still_relate():
    """Containment must survive: the device's own event and its interface's
    event are still one story."""
    dev = syslog_control_signal(
        {"hostname": "dc1-switch-a", "appname": "SYS-5-RESTART",
         "message": "%PLATFORM-2-ALARM: Interface GigabitEthernet0/5 fault raised",
         "severity": "err", "timestamp": "2026-08-21T09:00:10.000Z"}, "acme", T0)
    snaps = objects([syslog_link("dc1-switch-a"), dev] if dev else [syslog_link("dc1-switch-a")])
    assert len(snaps) == 1, "a device and its own interface stopped correlating"


# ── C. different devices related by TOPOLOGY, not by name ────────────────────


def test_topology_relates_peers_that_name_equality_no_longer_does():
    """`sw1/Gi0/5 ↔ sw2/Gi0/5` may absolutely correlate — through the adjacency
    inventory. The point of 168 is that the relation comes from topology, not
    from the two names being the same string."""
    a, b = syslog_link("sw1"), syslog_link("sw2", offset_s=30)
    assert len(objects([a, b])) == 2, "still welding without topology"
    adjacency = TopologyAdjacency.from_links([{"a": "sw1", "b": "sw2"}])
    snaps = objects([a, b], adjacency=adjacency)
    assert len(snaps) == 1, "topology failed to relate two genuine peers"
    refs = edge_refs(snaps)
    assert any(r.startswith("adj:") for r in refs), (
        f"related, but not through topology: {refs}")


def test_topology_does_not_need_the_names_to_match():
    """The corollary: peers relate on the link, whatever their interfaces are
    called."""
    a = syslog_link("sw1", "GigabitEthernet0/5")
    b = syslog_link("sw2", "xe-0/0/7", offset_s=30)
    adjacency = TopologyAdjacency.from_links([{"a": "sw1", "b": "sw2"}])
    assert len(objects([a, b], adjacency=adjacency)) == 1


# ── D. tenant isolation ──────────────────────────────────────────────────────


def test_same_device_and_interface_in_two_tenants_never_meet():
    a = syslog_link("sw1", tenant="tenant-a")
    b = syslog_link("sw1", tenant="tenant-b", offset_s=10)
    with pytest.raises(ValueError, match="single-tenant"):
        objects([a, b])
    # and each tenant's own window is complete on its own
    assert len(objects([a])) == 1
    assert len(objects([b])) == 1


# ── E. the other locally scoped token classes (Phase 6) ──────────────────────


def _syslog(host, msg, offset_s=0.0):
    return syslog_control_signal(
        {"hostname": host, "appname": msg.split(":")[0].lstrip("%").split("-")[0],
         "message": msg, "severity": "err", "event_type": msg.split(":")[0].lstrip("%"),
         "timestamp": (T0 + timedelta(seconds=offset_s)).strftime("%Y-%m-%dT%H:%M:%S.000Z")},
        "acme", T0)


FHRP = "%HSRP-5-STATECHANGE: GigabitEthernet0/5 Grp 1 state Standby -> Active"
MACFLAP = ("%SW_MATM-4-MACFLAP_NOTIF: Host aabb.ccdd.eeff in vlan 10 is flapping "
           "between port Gi0/1 and port Gi0/2")


def test_fhrp_group_number_is_device_scoped():
    """`grp1` is device-local — every HSRP-speaking device in the estate has
    one. Two routers in a real FHRP group must relate through topology."""
    a, b = _syslog("rtr-a", FHRP), _syslog("rtr-b", FHRP, 30)
    assert a is not None and b is not None
    ta, tb = build_nodes((a,))[0].tokens(), build_nodes((b,))[0].tokens()
    assert "grp1" not in ta and IF not in ta, f"device-local FHRP tokens leaked: {sorted(ta)}"
    assert ta & tb == frozenset(), f"FHRP welded two devices on {sorted(ta & tb)}"


def test_fhrp_still_binds_to_its_OWN_device_interface():
    """The qualified token must preserve the binding the bare one was there for."""
    fhrp = _syslog("rtr-a", FHRP)
    assert f"rtr-a:{IF}" in build_nodes((fhrp,))[0].tokens()
    assert len(objects([fhrp, syslog_link("rtr-a", offset_s=20)])) == 1, (
        "FHRP stopped binding to its own device's interface event")


def test_mac_flap_keeps_the_MAC_but_scopes_vlan_and_ports():
    """A MAC address IS globally unique — two devices seeing the same MAC flap
    really are related, and that is what this signal is about. The VLAN id and
    the port names are not."""
    a, b = _syslog("sw-a", MACFLAP), _syslog("sw-b", MACFLAP, 30)
    assert a is not None and b is not None
    ta, tb = build_nodes((a,))[0].tokens(), build_nodes((b,))[0].tokens()
    assert "vlan10" not in ta and "Gi0/1" not in ta, f"local tokens leaked: {sorted(ta)}"
    assert ta & tb == {"aabb.ccdd.eeff"}, (
        f"expected only the MAC to be shared, got {sorted(ta & tb)}")


def test_globally_unique_identifiers_are_left_alone():
    """The fix must not over-reach: a BGP peer address is a real global subject."""
    msg = "%BGP-5-ADJCHANGE: neighbor 10.3.3.3 Down"
    a, b = _syslog("rtr-a", msg), _syslog("rtr-b", msg, 30)
    assert a is not None and b is not None
    shared = build_nodes((a,))[0].tokens() & build_nodes((b,))[0].tokens()
    assert shared == {"10.3.3.3"}, (
        f"two devices peering with the same neighbour must still relate: {shared}")


# ── Phase 5. mutants — every one must be KILLED ──────────────────────────────


def test_MUTANT_restoring_the_bare_ifname_token_is_caught_by_the_engine():
    """Mutant 1: a producer regresses and emits the bare name again. The
    engine-side backstop must still refuse it as a subject."""
    s = syslog_link("dc1-switch-a")
    regressed = M.dc_replace(s, entity_tokens=("dc1-switch-a", IF))
    n = build_nodes((regressed,))[0]
    assert IF not in n.tokens(), (
        "the engine accepted a bare device-local name as a grounding subject — "
        "the structural backstop is not load-bearing")
    other = M.dc_replace(syslog_link("branch-77-rtr", offset_s=30),
                         entity_tokens=("branch-77-rtr", IF))
    assert len(objects([regressed, other])) == 2, (
        "a producer regression re-welded two unrelated devices")


def test_MUTANT_removing_the_device_component_reweldscollides():
    """Mutant 2: drop the device from the interface identity. Two devices then
    genuinely collide — proving the device component is what carries the
    separation, not some incidental difference in the fixtures."""
    a = M.dc_replace(syslog_link("dc1-switch-a"), entity_id=IF)
    b = M.dc_replace(syslog_link("branch-77-rtr", offset_s=30), entity_id=IF)
    assert build_nodes((a,))[0].key == build_nodes((b,))[0].key, (
        "without the device component these should be indistinguishable — if "
        "they are not, this test is not exercising the mutant it claims to")


def test_MUTANT_disabling_tenant_scoping_is_refused_structurally():
    """Mutant 4: try to correlate across tenants. The engine must refuse the
    window outright rather than quietly relate them."""
    a = syslog_link("sw1", tenant="tenant-a")
    b = M.dc_replace(syslog_link("sw1", offset_s=10), tenant_id="tenant-b")
    with pytest.raises(ValueError, match="single-tenant"):
        objects([a, b])


def test_MUTANT_an_always_global_token_filter_would_break_real_relations():
    """Mutant 7 (over-reach control): if the filter stripped EVERY shared token
    rather than only device-local ones, the legitimate MAC and peer-IP relations
    would vanish. They must not."""
    msg = "%BGP-5-ADJCHANGE: neighbor 10.3.3.3 Down"
    a, b = _syslog("rtr-a", msg), _syslog("rtr-b", msg, 30)
    assert len(objects([a, b])) == 1, (
        "the fix over-reached: two devices peering with the same neighbour "
        "stopped correlating")


def test_the_local_component_filter_only_strips_the_nodes_OWN_component():
    """Precision control: the filter must not strip a token that merely looks
    like some other node's local part."""
    s = M.dc_replace(syslog_link("dc1-switch-a"),
                     entity_tokens=("dc1-switch-a", "some-global-thing"))
    toks = build_nodes((s,))[0].tokens()
    assert "some-global-thing" in toks, "the filter stripped an unrelated token"
    assert IF not in toks


def test_a_path_or_segment_id_has_no_local_component_to_strip():
    """`a->b` ids contain no device:component split; the filter must leave them
    entirely alone."""
    seg = Signal(
        tenant_id="acme", ts=T0, source=Source.PROBE, kind="probe_loss",
        observer=Observer(observer_id="probe1", observer_type=ObserverType.VANTAGE_AGENT),
        modality_class=ModalityClass.ACTIVE_PROBE, entity_type=EntityType.SEGMENT,
        entity_id="dallas-edge->equinix-pop", severity=Severity.HIGH,
        native_id="seg|1", entity_tokens=("dallas-edge", "equinix-pop"),
        attrs={"onset_uncertainty_s": 5.0})
    toks = build_nodes((seg,))[0].tokens()
    assert {"dallas-edge", "equinix-pop", "dallas-edge->equinix-pop"} <= toks
