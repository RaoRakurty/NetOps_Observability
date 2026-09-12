# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Contract tests for path_assembly (path-causality RCA P1: discovery / assembly).

Holds the assembler to the blueprint's P1 requirements + the honesty rules:

  * assembly from EACH source type (measured / flow / inventory) → correct typed path
  * PRECEDENCE — a measured edge supersedes a flow-inferred one for the same adjacency,
    the superseded evidence kept as `supporting_refs`
  * COLLAPSE — consecutive same-type hops become one typed segment, KEY devices preserved
  * OPACITY — an opaque/unresponsive run → an `unknown` segment WITH a reason and
    `unknown_hops`, never a fabricated device
  * ECMP — a pair seen in both orders stays AMBIGUOUS, never a false single path
  * ISOLATION (§3a) — a path never contains another tenant's hop

Offline + pure: uses only the bundled provider snapshot (via the P0 classifier), no
network, no wall clock.
"""

from __future__ import annotations

import json
import os

import pytest

from path_assembly import (
    DiscoveredEdge,
    DiscoverySources,
    DnsHead,
    HopNode,
    HopState,
    MeasuredRun,
    PathAssembler,
    SourceKind,
    flow_edges_from_pairs,
    inventory_edges_from_topology,
    measured_run_from_observation,
)
from segment_classifier import DeviceRole, SegmentType

A = PathAssembler()

# Public AWS address (inside 52.216.0.0/15, S3 us-east-1) → classifies CLOUD/aws.
AWS_1 = "52.216.100.5"
AWS_2 = "52.216.100.6"
AWS_3 = "52.216.100.7"
LAN_1 = "10.20.30.40"
LAN_2 = "10.20.30.41"


def _seg_types(path) -> list[str]:
    return [s.segment_type for s in path.segments]


# ── assembly from a MEASURED source (rank 1) ─────────────────────────────────


def test_measured_source_assembles_typed_path():
    run = MeasuredRun("acme", evidence_ref="tr-1", hops=(
        HopNode(LAN_1, device_role_hint="client"),
        HopNode(AWS_1, device_role_hint="waf", key_device="web-acl-1"),
        HopNode(AWS_2, device_role_hint="lb", key_device="alb-1"),
        HopNode(AWS_3, device_role_hint="host", key_device="app-host-01"),
    ))
    p = A.assemble("acme", LAN_1, AWS_3, DiscoverySources(measured=(run,)))
    # LAN head, then ONE collapsed cloud segment (the essence, not 3 hops).
    assert _seg_types(p) == [SegmentType.LAN.value, SegmentType.CLOUD.value]
    cloud = p.segments[1]
    assert cloud.provider == "aws"
    assert cloud.boundary == "CLOUD"
    assert cloud.authoritative_source == SourceKind.MEASURED.value


def test_flow_source_assembles_typed_path():
    edges = (
        DiscoveredEdge("acme", HopNode(LAN_1, device_role_hint="router"),
                       HopNode(LAN_2, device_role_hint="router"),
                       source=SourceKind.FLOW.value, evidence_ref="flow-1"),
        DiscoveredEdge("acme", HopNode(LAN_2, device_role_hint="router"),
                       HopNode(AWS_1, device_role_hint="host"),
                       source=SourceKind.FLOW.value, evidence_ref="flow-2"),
    )
    p = A.assemble("acme", LAN_1, AWS_1, DiscoverySources(edges=edges))
    assert _seg_types(p) == [SegmentType.LAN.value, SegmentType.CLOUD.value]
    assert all(s.authoritative_source == SourceKind.FLOW.value for s in p.segments)


def test_inventory_source_assembles_typed_path():
    # cloud-inventory edge: app subnet → NVA (declared next hop), NVA → app host.
    edges = (
        DiscoveredEdge("acme", HopNode("10.60.10.10", device_role_hint="host"),
                       HopNode("10.60.1.10", device_role_hint="nva"),
                       source=SourceKind.INVENTORY.value, evidence_ref="inv-1"),
    )
    p = A.assemble("acme", "10.60.10.10", "10.60.1.10", DiscoverySources(edges=edges))
    # both private → LAN essence; the NVA hop is a tunnel-gw key device.
    assert p.segments[0].segment_type == SegmentType.LAN.value
    roles = {k.role for s in p.segments for k in s.key_devices}
    assert DeviceRole.TUNNEL_GW.value in roles       # the NVA is retained as a key device


def test_inventory_adapter_on_real_topology_fixture():
    path = os.path.join(os.path.dirname(__file__), "..", "..", "deployment",
                        "docker", "cloud-fixtures", "aws-topology.json")
    with open(path, encoding="utf-8") as f:
        topo = json.load(f)
    inv = inventory_edges_from_topology("acme", topo, "aws-topo")
    assert inv, "real topology fixture should yield inventory edges"
    # every emitted edge carries evidence (§5) and its downstream role hint.
    assert all(e.evidence_ref and e.source == SourceKind.INVENTORY.value for e in inv)
    assert all(e.downstream.device_role_hint for e in inv)


# ── PRECEDENCE — measured supersedes flow for the same adjacency ─────────────


def test_measured_supersedes_flow_same_adjacency():
    run = MeasuredRun("acme", evidence_ref="tr", hops=(HopNode(LAN_1), HopNode(AWS_1)))
    flow = (DiscoveredEdge("acme", HopNode(LAN_1), HopNode(AWS_1),
                           source=SourceKind.FLOW.value, evidence_ref="flow-x"),)
    src = DiscoverySources(measured=(run,), edges=flow)
    p = A.assemble("acme", LAN_1, AWS_1, src)
    rels = A.relations(p, src)
    assert len(rels) == 1
    r = rels[0]
    assert r.observation_method == SourceKind.MEASURED.value   # measured wins
    assert "flow-x" in r.supporting_refs                       # flow kept as supporting
    assert r.evidence_ref == "tr"


def test_flow_supersedes_route_same_adjacency():
    flow = DiscoveredEdge("acme", HopNode(LAN_1), HopNode(AWS_1),
                          source=SourceKind.FLOW.value, evidence_ref="flow-a")
    route = DiscoveredEdge("acme", HopNode(LAN_1), HopNode(AWS_1),
                           source=SourceKind.ROUTE.value, evidence_ref="route-a")
    src = DiscoverySources(edges=(route, flow))
    p = A.assemble("acme", LAN_1, AWS_1, src)
    rels = A.relations(p, src)
    assert rels[0].observation_method == SourceKind.FLOW.value
    assert "route-a" in rels[0].supporting_refs


# ── COLLAPSE — same-type hops → one segment, key devices preserved ───────────


def test_same_type_collapse_preserves_key_devices():
    run = MeasuredRun("acme", evidence_ref="tr", hops=(
        HopNode(AWS_1, device_role_hint="dns", key_device="route53"),
        HopNode(AWS_2, device_role_hint="waf", key_device="web-acl"),
        HopNode(AWS_3, device_role_hint="lb", key_device="alb"),
        HopNode("52.216.100.8", device_role_hint="firewall", key_device="fw-1"),
        HopNode("52.216.100.9", device_role_hint="host", key_device="app"),
    ))
    p = A.assemble("acme", AWS_1, "52.216.100.9", DiscoverySources(measured=(run,)))
    # five same-type cloud hops collapse to ONE segment...
    assert len(p.segments) == 1
    seg = p.segments[0]
    assert seg.segment_type == SegmentType.CLOUD.value
    # ...but every KEY service device is retained by role.
    roles = {k.role for k in seg.key_devices}
    assert roles == {DeviceRole.DNS_RESOLVER.value, DeviceRole.WAF.value,
                     DeviceRole.LOAD_BALANCER.value, DeviceRole.FIREWALL.value,
                     DeviceRole.HOST.value}
    labels = {k.label for k in seg.key_devices}
    assert labels == {"route53", "web-acl", "alb", "fw-1", "app"}


def test_lan_dc_fabric_role_retained():
    run = MeasuredRun("acme", evidence_ref="tr", hops=(
        HopNode(LAN_1, device_role_hint="switch", key_device="leaf-1"),
        HopNode(LAN_2, device_role_hint="router", key_device="core-1"),
    ))
    p = A.assemble("acme", LAN_1, LAN_2, DiscoverySources(measured=(run,)))
    roles = {k.role for s in p.segments for k in s.key_devices}
    assert DeviceRole.SWITCH.value in roles and DeviceRole.ROUTER.value in roles


# ── OPACITY — opaque run → unknown segment + reason, no fabricated hop ────────


def test_opaque_run_becomes_unknown_segment_with_reason():
    run = MeasuredRun("acme", evidence_ref="tr", hops=(
        HopNode(LAN_1, device_role_hint="client"),
        HopNode("", state=HopState.MISSING.value),
        HopNode("", state=HopState.FILTERED.value),
        HopNode(AWS_1, device_role_hint="host"),
    ))
    p = A.assemble("acme", LAN_1, AWS_1, DiscoverySources(measured=(run,)))
    unknown = [s for s in p.segments if s.segment_type == SegmentType.UNKNOWN.value]
    assert len(unknown) == 1
    u = unknown[0]
    assert u.unknown_hops == (1, 2)          # both opaque hop indices preserved
    assert u.reason                          # a human reason, not silence
    assert u.member_addresses == ()          # NO fabricated device
    assert u.key_devices == ()


def test_no_evidence_yields_unknown_not_invented_path():
    p = A.assemble("acme", LAN_1, AWS_1, DiscoverySources())
    assert _seg_types(p) == [SegmentType.UNKNOWN.value]
    assert p.segments[0].reason
    assert p.segments[0].member_addresses == ()


# ── ECMP — a pair seen both orders stays AMBIGUOUS ───────────────────────────


def test_ecmp_stays_ambiguous_not_false_single_path():
    r1 = MeasuredRun("acme", evidence_ref="r1",
                     hops=(HopNode(LAN_1), HopNode(LAN_2), HopNode("10.20.30.42"),
                           HopNode(AWS_1)))
    r2 = MeasuredRun("acme", evidence_ref="r2",
                     hops=(HopNode(LAN_1), HopNode("10.20.30.42"), HopNode(LAN_2),
                           HopNode(AWS_1)))
    p = A.assemble("acme", LAN_1, AWS_1, DiscoverySources(measured=(r1, r2)))
    assert p.ambiguous
    assert (LAN_2, "10.20.30.42") in p.ecmp_pairs
    # the segment containing the ECMP branch is flagged — order is NOT asserted as truth.
    assert any(s.ambiguous for s in p.segments)


def test_ecmp_relation_is_supporting_not_directed_hop():
    from path_graph import EdgeType
    r1 = MeasuredRun("acme", evidence_ref="r1",
                     hops=(HopNode(LAN_1), HopNode(LAN_2), HopNode(AWS_1)))
    r2 = MeasuredRun("acme", evidence_ref="r2",
                     hops=(HopNode(AWS_1), HopNode(LAN_2), HopNode(LAN_1)))
    src = DiscoverySources(measured=(r1, r2))
    p = A.assemble("acme", LAN_1, AWS_1, src)
    assert p.ambiguous
    rels = A.relations(p, src)
    # an adjacency inside the diamond is emitted as EVIDENCE_SUPPORTS, never PATH_HAS_HOP.
    ecmp_rels = [r for r in rels if r.ref.startswith("path:")]
    assert any(r.edge_type == EdgeType.EVIDENCE_SUPPORTS.value for r in ecmp_rels)


# ── DNS head capture ─────────────────────────────────────────────────────────


def test_dns_resolved_frontend_is_path_head():
    head = DnsHead("acme", query_name="app.example.com", resolved_address=AWS_1,
                   cname_chain=("app.example.com", "app.elb.amazonaws.com"),
                   evidence_ref="dns-1")
    run = MeasuredRun("acme", evidence_ref="tr", hops=(HopNode(LAN_1), HopNode(AWS_1)))
    p = A.assemble("acme", LAN_1, AWS_1, DiscoverySources(measured=(run,), dns_head=head))
    assert p.head is not None
    assert p.head.query_name == "app.example.com"
    assert p.head.resolved_address == AWS_1


# ── TENANT ISOLATION (§3a) — a path never contains another tenant's hop ──────


def test_isolation_other_tenant_run_dropped():
    mine = MeasuredRun("acme", evidence_ref="tr", hops=(HopNode(LAN_1), HopNode(AWS_1)))
    evil = MeasuredRun("evil", evidence_ref="x", hops=(HopNode("10.9.9.9"),
                                                       HopNode("8.8.8.8")))
    p = A.assemble("acme", LAN_1, AWS_1, DiscoverySources(measured=(mine, evil)))
    addrs = {a for s in p.segments for a in s.member_addresses}
    assert "10.9.9.9" not in addrs and "8.8.8.8" not in addrs
    assert addrs == {LAN_1, AWS_1}


def test_isolation_other_tenant_edges_dropped():
    evil_edge = DiscoveredEdge("evil", HopNode("10.9.9.9"), HopNode("8.8.8.8"),
                               source=SourceKind.FLOW.value, evidence_ref="evil-flow")
    mine = MeasuredRun("acme", evidence_ref="tr", hops=(HopNode(LAN_1), HopNode(AWS_1)))
    src = DiscoverySources(measured=(mine,), edges=(evil_edge,))
    p = A.assemble("acme", LAN_1, AWS_1, src)
    addrs = {a for s in p.segments for a in s.member_addresses}
    assert "10.9.9.9" not in addrs and "8.8.8.8" not in addrs
    # and the evil edge contributes NO relation / supporting evidence
    rels = A.relations(p, src)
    assert all("evil-flow" not in r.supporting_refs for r in rels)


def test_isolation_dns_head_from_other_tenant_dropped():
    evil_head = DnsHead("evil", query_name="x", resolved_address=AWS_1)
    run = MeasuredRun("acme", evidence_ref="tr", hops=(HopNode(LAN_1), HopNode(AWS_1)))
    p = A.assemble("acme", LAN_1, AWS_1,
                   DiscoverySources(measured=(run,), dns_head=evil_head))
    assert p.head is None                    # cross-tenant DNS head fails closed


def test_empty_tenant_object_fails_closed():
    # a run carrying an EMPTY tenant_id is dropped (no 'global' path evidence).
    run = MeasuredRun("", evidence_ref="tr", hops=(HopNode(LAN_1), HopNode(AWS_1)))
    p = A.assemble("acme", LAN_1, AWS_1, DiscoverySources(measured=(run,)))
    assert _seg_types(p) == [SegmentType.UNKNOWN.value]   # nothing observed for acme


def test_assemble_requires_tenant():
    with pytest.raises(ValueError):
        A.assemble("", LAN_1, AWS_1, DiscoverySources())


# ── determinism (replay contract) ────────────────────────────────────────────


def test_assembly_is_deterministic():
    run = MeasuredRun("acme", evidence_ref="tr", hops=(
        HopNode(LAN_1, device_role_hint="client"),
        HopNode(AWS_1, device_role_hint="lb", key_device="alb"),
        HopNode(AWS_2, device_role_hint="host", key_device="app"),
    ))
    src = DiscoverySources(measured=(run,))
    a = A.assemble("acme", LAN_1, AWS_2, src).to_dict()
    b = A.assemble("acme", LAN_1, AWS_2, src).to_dict()
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)


# ── adapter: measured run from a path_graph PathObservation ──────────────────


def test_measured_run_from_observation_adapter():
    from datetime import datetime, timezone

    from path_graph import PathHop, PathObservation, Provenance

    prov = Provenance(tenant_id="acme", producer_id="prober", provenance_id="obs-ev")
    obs = PathObservation(
        observation_id="obs-1", path_id="p1", tenant_id="acme",
        observed_at=datetime(2026, 7, 16, tzinfo=timezone.utc),
        method="traceroute_icmp", prov=prov,
        hops=(
            PathHop(hop_index=1, observed_address=LAN_1, evidence_ref="h1"),
            PathHop(hop_index=2, state="missing", evidence_ref="h2"),
            PathHop(hop_index=3, observed_address=AWS_1, evidence_ref="h3"),
        ),
    )
    run = measured_run_from_observation(obs)
    assert run.tenant_id == "acme"
    assert run.evidence_ref == "obs-ev"
    assert [h.address for h in run.hops] == [LAN_1, "", AWS_1]
    assert run.hops[1].state == HopState.MISSING.value
    # assembling it preserves the opaque middle hop as an unknown segment.
    p = A.assemble("acme", LAN_1, AWS_1, DiscoverySources(measured=(run,)))
    assert any(s.unknown_hops for s in p.segments)


def test_flow_edges_from_pairs_adapter():
    edges = flow_edges_from_pairs("acme", [(LAN_1, AWS_1), (AWS_1, AWS_1)], "flow-ev")
    assert len(edges) == 1                   # self-pair dropped
    assert edges[0].tenant_id == "acme"
    assert edges[0].source == SourceKind.FLOW.value
