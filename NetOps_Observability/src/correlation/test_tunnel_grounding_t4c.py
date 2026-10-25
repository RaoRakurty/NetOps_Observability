# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""NMS-first T4c — a controller tunnel grounds to its edge devices at rank 3.

Stage [4] grounding. Before T4c a tunnel node (`<tloc pair>@<instance>`) and a
signal on one of its endpoint devices met only through a rank-7 shared token:
non-authoritative, so the component carried the "no authoritative edge" cap, and
a DC device's token shared by more than the hub cap of tunnel nodes grounded
nothing at all. The API now exports tunnel↔endpoint rows into
topology_links.json; Node.adjacency_key lets the adjacency rung find them.
"""
from datetime import datetime, timezone

from controller_events import controller_event_to_signal
from engine import NO_ADJACENCY, TopologyAdjacency, build_nodes, resolve_grounding

INGEST = datetime(2026, 7, 3, 12, 0, 0, tzinfo=timezone.utc)
TID = "10.255.255.20/mpls|10.255.255.51/mpls"   # nms.CanonicalTunnelID shape
CI = "ci-aaaaaaaaaaaaaaaa"
NODE = f"{TID}@{CI}"


def _ev(kind, device, *, tunnel="", peer="", event_id="e", tenant="t-w"):
    ev = {
        "tenant_id": tenant, "integration_id": "nmsi-1", "source_system": "vmanage", "vendor": "cisco",
        "normalized_event_type": kind, "severity": "high", "device_id": device, "peer_id": peer,
        "site_id": "", "tunnel_id": tunnel, "event_id": event_id, "event_time": "2026-07-03T11:59:00Z",
        "controller_instance": CI,
    }
    if tunnel:
        ev["correlation_hints"] = {"tunnel_scheme": "tloc_pair", "controller_instance_basis": "host"}
    return ev


def _nodes():
    tun = controller_event_to_signal(_ev("controller_bfd_down", "ctl-a", tunnel=TID, peer="ctl-b"), INGEST)
    dev = controller_event_to_signal(_ev("controller_device_unreachable", "ctl-a", event_id="d"), INGEST)
    nodes = {n.entity_id: n for n in build_nodes((tun, dev))}
    return nodes[NODE], nodes["ctl-a"]


# The exact rows topology_links_enrichment.go writes for this tunnel.
ROWS = [{"tenant_id": "t-w", "a": NODE, "b": "ctl-a", "proto": "sdwan_bfd"},
        {"tenant_id": "t-w", "a": NODE, "b": "ctl-b", "proto": "sdwan_bfd"}]


def test_the_tunnel_node_is_looked_up_by_its_own_id():
    tun, dev = _nodes()
    assert tun.device_part() is None, "a tunnel has no single device"
    assert tun.adjacency_key() == NODE
    assert dev.adjacency_key() == dev.device_part() == "ctl-a"


def test_with_the_exported_rows_a_tunnel_grounds_to_its_device_at_rank_3():
    tun, dev = _nodes()
    g = resolve_grounding(tun, dev, (), TopologyAdjacency.from_links(ROWS))
    assert g is not None and g.rank == 3 and g.authoritative, g
    assert g.ref == f"adj:{min(NODE, 'ctl-a')}--{max(NODE, 'ctl-a')}"


def test_without_the_rows_nothing_changes():
    tun, dev = _nodes()
    g = resolve_grounding(tun, dev, (), NO_ADJACENCY)
    assert g is not None and g.rank == 7 and not g.authoritative, (
        "pre-T4c behaviour: only the shared device token joins them")


def test_rows_never_ground_a_tunnel_to_a_device_it_does_not_run_to():
    tun, _ = _nodes()
    other = build_nodes((controller_event_to_signal(
        _ev("controller_device_unreachable", "ctl-z", event_id="z"), INGEST),))[0]
    g = resolve_grounding(tun, other, (), TopologyAdjacency.from_links(ROWS))
    assert g is None or not g.authoritative


def test_an_unscoped_tunnel_id_is_not_an_adjacency_key():
    # A pre-T0 opaque tunnel id (no "@instance") keeps its old behaviour.
    legacy = build_nodes((controller_event_to_signal(
        {**_ev("controller_bfd_down", "ctl-a", tunnel="mpls-biz"), "correlation_hints": {}}, INGEST),))[0]
    assert legacy.entity_id == "mpls-biz" and legacy.adjacency_key() is None
