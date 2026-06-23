"""NetFlow direction source (C7.3) — the precedence-2 directed-topology source.

Properties: dominant flow → a directed verdict, balanced → AMBIGUOUS (never an
assumed direction), no flow → UNKNOWN; a flow contributes only when BOTH endpoints
resolve to devices; the vote DIRECTS a same-layer fabric pair the engine couldn't
direct before; and a directed edge REPLAYS deterministically from the embedded
orientation (never recomputed from live volume).
"""
from datetime import datetime, timedelta, timezone

from catalog import builtin_catalog
from directed_topology import DirectedTopology, Verdict, frozen_oracle
from engine import TopologyAdjacency, run_window
from entity_resolver import EntityResolver
from flow_direction import flow_direction_sample, netflow_direction_source
from signals import (
    EntityType, ModalityClass, Observer, ObserverType, Severity, Signal, Source,
)

T0 = datetime(2026, 6, 23, 10, 0, 0, tzinfo=timezone.utc)


def _src(verdict_pair):
    return netflow_direction_source(verdict_pair)


# ── the source ─────────────────────────────────────────────────────────────────

def test_dominant_direction_wins_balanced_is_ambiguous_absent_is_unknown():
    s = _src({("a", "b"): 1000.0, ("b", "a"): 50.0})
    assert s("a", "b").verdict is Verdict.A_UPSTREAM        # a→b dominant
    assert s("b", "a").verdict is Verdict.B_UPSTREAM        # symmetric question
    assert _src({("a", "b"): 100.0, ("b", "a"): 100.0})("a", "b").verdict is Verdict.AMBIGUOUS
    assert _src({})("a", "b") is None                       # no flow → UNKNOWN (abstain)
    # confidence reports the winning share.
    assert abs(s("a", "b").confidence - 1000 / 1050) < 1e-9
    assert s("a", "b").source == "netflow"


def test_dominance_threshold_is_respected():
    # 0.6 default: 60/40 is dominant, 55/45 is balanced.
    assert netflow_direction_source({("a", "b"): 60.0, ("b", "a"): 40.0})("a", "b").verdict is Verdict.A_UPSTREAM
    assert netflow_direction_source({("a", "b"): 55.0, ("b", "a"): 45.0})("a", "b").verdict is Verdict.AMBIGUOUS


# ── the sample resolver ─────────────────────────────────────────────────────────

def _resolver():
    return EntityResolver.from_rows(
        devices=[
            {"device": "leaf1", "mgmt_ip": "10.0.0.1"},
            {"device": "spine1", "mgmt_ip": "10.0.0.2"},
        ],
        interface_ips=[], ifindex=[],
    )


def test_flow_direction_sample_resolves_both_endpoints_or_abstains():
    r = _resolver()
    ev = {"SrcAddr": "10.0.0.1", "DstAddr": "10.0.0.2", "Bytes": "500", "SamplingRate": "10"}
    assert flow_direction_sample(ev, r) == ("leaf1", "spine1", 5000.0)   # ×rate
    # an unknown endpoint → abstain (None), never a guessed device
    assert flow_direction_sample({"SrcAddr": "10.0.0.1", "DstAddr": "203.0.113.9", "Bytes": "1"}, r) is None
    # same device (intra-device) → None
    assert flow_direction_sample({"SrcAddr": "10.0.0.1", "DstAddr": "10.0.0.1", "Bytes": "1"}, r) is None
    # no bytes → None
    assert flow_direction_sample({"SrcAddr": "10.0.0.1", "DstAddr": "10.0.0.2", "Bytes": "0"}, r) is None


# ── end-to-end: the vote directs a same-layer fabric pair ───────────────────────

def _dev_sig(kind, dev, off):
    return Signal(
        tenant_id="", ts=T0 + timedelta(seconds=off), source=Source.SYSLOG, kind=kind,
        observer=Observer(observer_id=dev, observer_type=ObserverType.DEVICE),
        modality_class=ModalityClass.CONTROL_PLANE, entity_type=EntityType.DEVICE,
        entity_id=dev, severity=Severity.HIGH, native_id=f"{dev}|{kind}|{off}",
        entity_tokens=(dev,), attrs={"onset_uncertainty_s": 1.0},
    )


def _fabric_window():
    # two NETWORK-layer (bgp) events on adjacent devices — SAME layer, so the layer
    # vote abstains; without a topo vote only onset remains (1 of 2) → no direction.
    return [_dev_sig("bgp_adjacency_change", "leaf1", 0),
            _dev_sig("bgp_adjacency_change", "spine1", 20)]


_ADJ = TopologyAdjacency.from_links([{"a": "leaf1", "b": "spine1"}])


def test_same_layer_fabric_pair_undirected_without_oracle():
    snaps = run_window(_fabric_window(), builtin_catalog(), (), adjacency=_ADJ)
    edges = [e for s in snaps for e in s.edges]
    assert len(edges) == 1
    assert edges[0].direction_basis == "none"   # onset alone (1 vote) → undirected
    assert all(s.orientations == () for s in snaps)


def test_netflow_vote_directs_the_fabric_pair_and_embeds_the_orientation():
    vol = {("leaf1", "spine1"): 1000.0, ("spine1", "leaf1"): 50.0}  # leaf1 upstream
    directed = DirectedTopology(sources=(("netflow", netflow_direction_source(vol)),))
    snaps = run_window(_fabric_window(), builtin_catalog(), (), adjacency=_ADJ, directed=directed)
    assert len(snaps) == 1
    snap = snaps[0]
    e = snap.edges[0]
    # from_node = earlier-onset = leaf1; oracle says leaf1 upstream → agrees → 2 votes.
    assert e.from_node.startswith("device:leaf1") and e.direction_conf > 0
    assert "onset_order" in e.direction_basis and "topo_updown" in e.direction_basis
    # the orientation is embedded for replay (from, to, verdict, source), sorted.
    assert snap.orientations == (("leaf1", "spine1", "a_upstream", "netflow"),)


def test_directed_edge_replays_deterministically_from_embedded_orientation():
    vol = {("leaf1", "spine1"): 1000.0, ("spine1", "leaf1"): 50.0}
    directed = DirectedTopology(sources=(("netflow", netflow_direction_source(vol)),))
    cat = builtin_catalog()
    live = run_window(_fabric_window(), cat, (), adjacency=_ADJ, directed=directed)[0]

    # Replay: reconstruct ONLY from the embedded orientations (no live volume), exactly
    # like replay.py does via StoredObject.directed(). Direction + content hash must match.
    replay_oracle = frozen_oracle(live.orientations)
    replayed = run_window(_fabric_window(), cat, (), adjacency=_ADJ, directed=replay_oracle)[0]
    assert replayed.edges[0].direction_basis == live.edges[0].direction_basis
    assert replayed.orientations == live.orientations
    assert replayed.content_hash() == live.content_hash()


def test_undirected_object_blob_is_byte_identical_to_pre_c7():
    # An object that used NO orientation embeds nothing → its hypotheses blob (hence
    # content_hash + replay pin) is unchanged from before C7 (no churn for the common case).
    no_oracle = run_window(_fabric_window(), builtin_catalog(), (), adjacency=_ADJ)[0]
    assert "orientations" not in no_oracle.hypotheses_blob()
