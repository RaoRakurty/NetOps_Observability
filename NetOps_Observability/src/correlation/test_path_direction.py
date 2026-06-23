"""Active-path-trace direction source (C7.4) — the precedence-1 directed-topology
source (measured forwarding path; hop order = direction).

Properties: hop order directs a pair; an endpoint that doesn't resolve abstains;
both-orders-seen (ECMP/loop) → AMBIGUOUS; traceroute OUTRANKS NetFlow when they
agree and CONFLICTS safely (conservative v1 fusion → abstain); and a path-directed
edge replays deterministically from the embedded orientation.
"""
from datetime import datetime, timedelta, timezone

from catalog import builtin_catalog
from directed_topology import DirectedTopology, Verdict, frozen_oracle
from engine import TopologyAdjacency, run_window
from entity_resolver import EntityResolver
from flow_direction import netflow_direction_source
from path_direction import resolve_path_order, traceroute_direction_source
from signals import (
    EntityType, ModalityClass, Observer, ObserverType, Severity, Signal, Source,
)

T0 = datetime(2026, 6, 23, 11, 0, 0, tzinfo=timezone.utc)


def _resolver():
    return EntityResolver.from_rows(
        devices=[
            {"device": "leaf1", "mgmt_ip": "10.0.0.1"},
            {"device": "spine1", "mgmt_ip": "10.0.0.2"},
            {"device": "edge1", "mgmt_ip": "10.0.0.3"},
        ],
        interface_ips=[], ifindex=[],
    )


# ── resolve_path_order + the source ─────────────────────────────────────────────

def test_hop_order_becomes_directed_pairs_transitively():
    # leaf1 → spine1 → edge1: every earlier→later pair is ordered (incl. transitive).
    before = resolve_path_order([{"hops": ["10.0.0.1", "10.0.0.2", "10.0.0.3"]}], _resolver())
    assert ("leaf1", "spine1") in before
    assert ("spine1", "edge1") in before
    assert ("leaf1", "edge1") in before          # transitive
    assert ("spine1", "leaf1") not in before
    s = traceroute_direction_source(before)
    assert s("leaf1", "edge1").verdict is Verdict.A_UPSTREAM
    assert s("edge1", "leaf1").verdict is Verdict.B_UPSTREAM
    assert s("leaf1", "edge1").source == "traceroute"


def test_unresolved_hops_are_dropped_order_of_the_rest_preserved():
    # the middle hop is an unknown transit IP → dropped; leaf1 before edge1 still holds.
    before = resolve_path_order([{"hops": ["10.0.0.1", "203.0.113.9", "10.0.0.3"]}], _resolver())
    assert ("leaf1", "edge1") in before
    s = traceroute_direction_source(before)
    assert s("leaf1", "edge1").verdict is Verdict.A_UPSTREAM
    # a pair where one endpoint never resolves → not covered → abstain.
    assert s("leaf1", "spine1") is None


def test_both_orders_seen_is_ambiguous_never_assumed():
    before = resolve_path_order([
        {"hops": ["10.0.0.1", "10.0.0.2"]},   # leaf1 → spine1
        {"hops": ["10.0.0.2", "10.0.0.1"]},   # spine1 → leaf1 (ECMP asymmetry)
    ], _resolver())
    assert traceroute_direction_source(before)("leaf1", "spine1").verdict is Verdict.AMBIGUOUS


# ── end-to-end + precedence + replay ────────────────────────────────────────────

def _dev_sig(kind, dev, off):
    return Signal(
        tenant_id="", ts=T0 + timedelta(seconds=off), source=Source.SYSLOG, kind=kind,
        observer=Observer(observer_id=dev, observer_type=ObserverType.DEVICE),
        modality_class=ModalityClass.CONTROL_PLANE, entity_type=EntityType.DEVICE,
        entity_id=dev, severity=Severity.HIGH, native_id=f"{dev}|{kind}|{off}",
        entity_tokens=(dev,), attrs={"onset_uncertainty_s": 1.0})


_WINDOW = [_dev_sig("bgp_adjacency_change", "leaf1", 0),
           _dev_sig("bgp_adjacency_change", "spine1", 20)]
_ADJ = TopologyAdjacency.from_links([{"a": "leaf1", "b": "spine1"}])


def test_traceroute_directs_fabric_pair_and_embeds_traceroute_source():
    before = resolve_path_order([{"hops": ["10.0.0.1", "10.0.0.2"]}], _resolver())
    directed = DirectedTopology(sources=(("traceroute", traceroute_direction_source(before)),))
    snap = run_window(_WINDOW, builtin_catalog(), (), adjacency=_ADJ, directed=directed)[0]
    e = snap.edges[0]
    assert e.direction_conf > 0 and "topo_updown" in e.direction_basis
    assert snap.orientations == (("leaf1", "spine1", "a_upstream", "traceroute"),)
    # replay reconstructs the same direction from the embedded orientation.
    replayed = run_window(_WINDOW, builtin_catalog(), (), adjacency=_ADJ,
                          directed=frozen_oracle(snap.orientations))[0]
    assert replayed.content_hash() == snap.content_hash()


def test_conservative_fusion_abstains_when_traceroute_and_netflow_conflict():
    # traceroute says leaf1→spine1, NetFlow says spine1→leaf1 dominant: v1 fusion is
    # conservative → covering sources disagree → AMBIGUOUS → vote #2 abstains. The
    # 2-of-3 safety means a contradiction can never manufacture a false direction.
    before = resolve_path_order([{"hops": ["10.0.0.1", "10.0.0.2"]}], _resolver())
    vol = {("spine1", "leaf1"): 1000.0, ("leaf1", "spine1"): 10.0}
    directed = DirectedTopology(sources=(
        ("traceroute", traceroute_direction_source(before)),
        ("netflow", netflow_direction_source(vol)),
    ))
    assert directed.orient("leaf1", "spine1").verdict is Verdict.AMBIGUOUS
    snap = run_window(_WINDOW, builtin_catalog(), (), adjacency=_ADJ, directed=directed)[0]
    assert snap.edges[0].direction_basis == "none"   # abstained → undirected
    assert snap.orientations == ()


def test_sources_agree_directs_with_highest_precedence_source():
    # both agree leaf1→spine1 → directed; the recorded source is the FIRST (traceroute).
    before = resolve_path_order([{"hops": ["10.0.0.1", "10.0.0.2"]}], _resolver())
    vol = {("leaf1", "spine1"): 1000.0, ("spine1", "leaf1"): 10.0}
    directed = DirectedTopology(sources=(
        ("traceroute", traceroute_direction_source(before)),
        ("netflow", netflow_direction_source(vol)),
    ))
    snap = run_window(_WINDOW, builtin_catalog(), (), adjacency=_ADJ, directed=directed)[0]
    assert snap.orientations == (("leaf1", "spine1", "a_upstream", "traceroute"),)
