# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""build_edges complexity regression (perf defect #1) — deterministic
OPERATION-COUNT assertions, never wall-clock.

The naive form scored every pair (C(n,2) resolve_grounding calls, each
recomputing tokens()/identity_refs()/path memberships and re-sorting the
seams — benchmarked ~100µs/pair ⇒ ~48s synchronous at 1k nodes). The fix
precomputes per-node views ONCE and scores only pairs the inverted
token/identity/seam/adjacency/observation index admits.

Two properties are pinned here:

  1. SOUNDNESS/EQUIVALENCE — build_edges output (edges INCLUDING grounding
     refs/ranks, and the gap-hint total) is byte-identical to a brute-force
     reference that replays the original O(n²) loop through the public
     resolve_grounding. Pruning may only skip pairs that ground to None.
  2. COMPLEXITY — exact candidate-pair counts on synthetic windows: 0 for a
     1k-node all-disjoint window (naive: 499_500 scored pairs), and exactly
     Σ C(k,2) for clustered windows. Per-node precomputation is pinned by
     counting Node.tokens() invocations (n, not 2·C(n,2)).
"""

from __future__ import annotations

import math
from datetime import datetime, timedelta, timezone

from engine import (
    CORR_TOKEN_HUB_CAP,
    NO_ADJACENCY,
    Edge,
    EngineConfig,
    SeamView,
    TopologyAdjacency,
    _candidate_pairs,
    _direction,
    build_edges,
    build_nodes,
    resolve_grounding,
)
from engine import (
    Node as EngineNode,
)
from path_graph import PathIndex
from signals import (
    EntityType,
    ModalityClass,
    Observer,
    ObserverType,
    Severity,
    Signal,
    Source,
)
from test_path_graph import lab_path_view, lab_signals

T0 = datetime(2026, 6, 12, 9, 42, 0, tzinfo=timezone.utc)


def sig(kind: str, entity_type: EntityType, entity_id: str, *, offset_s: float = 0,
        observer: str = "obs1", modality: ModalityClass = ModalityClass.DEVICE_TELEMETRY,
        severity: Severity = Severity.HIGH, tokens: tuple[str, ...] = (),
        tenant: str = "t1") -> Signal:
    return Signal(
        tenant_id=tenant,
        ts=T0 + timedelta(seconds=offset_s),
        source=Source.METRIC,
        kind=kind,
        observer=Observer(observer_id=observer, observer_type=ObserverType.DEVICE),
        modality_class=modality,
        entity_type=entity_type,
        entity_id=entity_id,
        severity=severity,
        native_id=f"t|{kind}|{entity_id}|{offset_s}",
        entity_tokens=tokens,
        attrs={"onset_uncertainty_s": 5.0},
    )


def _hub_tokens(nodes, cap=None):
    """The window's rank-7 HUB tokens — shared by > cap nodes (#168 Stage-2
    Lever 1). The brute-force reference applies the SAME cap the engine does: a
    hub token no longer grounds, so the naive loop must also skip it, or the
    fast path (which drops the hub mesh at generation) would not match. A pure
    function of the node set, exactly like the engine's index."""
    if cap is None:
        cap = CORR_TOKEN_HUB_CAP
    counts: dict[str, int] = {}
    for nd in nodes:
        for t in nd.tokens():
            counts[t] = counts.get(t, 0) + 1
    return frozenset(t for t, c in counts.items() if c > cap)


def brute_force_edges(nodes, seams, cfg, adjacency=NO_ADJACENCY,
                      topology_stale=False, directed=None, paths=None):
    """The ORIGINAL O(n²) loop, kept verbatim as the behavioral reference —
    every pair through the public resolve_grounding, same weight/direction math.
    Updated for #168 Stage-2 Lever 1: it applies the SAME hub-token cap the
    engine's candidate index does (hub tokens do not ground), so the pruned fast
    path still matches the reference byte-for-byte at every window shape."""
    edges: list[Edge] = []
    gap_hints = 0
    hub = _hub_tokens(nodes)
    for i in range(len(nodes)):
        for j in range(i + 1, len(nodes)):
            a, b = nodes[i], nodes[j]
            if b.onset < a.onset or (b.onset == a.onset and b.key < a.key):
                a, b = b, a
            grounding = resolve_grounding(a, b, seams, adjacency, paths, hub)
            if grounding is None:
                gap_hints += 1
                continue
            a_last, b_last = a.signals[-1].ts, b.signals[-1].ts
            gap = max(0.0, (max(a.onset, b.onset) - min(a_last, b_last)).total_seconds())
            w_t = math.exp(-gap / cfg.tau_s)
            rel = grounding.relation
            if rel is not None and rel.rank == 7:
                w_topo = cfg.w_topo_candidate  # §3 rank 7 candidate (mirrors engine._score_edges)
            elif grounding.ref.startswith("path:"):
                w_topo = cfg.w_topo_path
            elif grounding.ref.startswith("route:"):
                w_topo = cfg.w_topo_inferred
            elif grounding.kind == "seam":
                w_topo = cfg.w_topo_seam
            elif grounding.ref.startswith("adj:"):
                w_topo = cfg.w_topo_adjacency
            else:
                w_topo = cfg.w_topo_containment
            if topology_stale:
                w_topo = min(w_topo, cfg.w_topo_stale_cap)
            cross = a.signals[0].modality_class is not b.signals[0].modality_class
            w_r = cfg.reinforce_cross_modality if cross else 1.0
            weight = min(w_t * w_topo * w_r, 1.0)
            if weight < cfg.attach_threshold:
                continue
            conf, basis = _direction(a, b, cfg, directed)
            edges.append(Edge(a.key, b.key, grounding, weight, w_t, w_topo, w_r,
                              conf, basis))
    return tuple(sorted(edges, key=lambda e: (e.from_node, e.to_node))), gap_hints


def mixed_window() -> tuple:
    """Every grounding rung in one window: seam, containment, adjacency,
    shared-token clusters, cross-modality, plus disjoint singletons."""
    sigs = []
    # seam-grounded pair
    sigs.append(sig("if_util_high", EntityType.INTERFACE, "dallas-edge:Gi0/1"))
    sigs.append(sig("probe_loss", EntityType.SEGMENT, "dallas-edge->equinix-pop",
                    offset_s=30, observer="probe1",
                    modality=ModalityClass.ACTIVE_PROBE))
    # containment cluster (device + 3 interfaces)
    sigs.append(sig("device_cpu_high", EntityType.DEVICE, "core-9", offset_s=5))
    for k in range(3):
        sigs.append(sig("if_errors", EntityType.INTERFACE, f"core-9:Et{k}",
                        offset_s=10 + k))
    # adjacency-grounded pair (two different devices, inventoried link)
    sigs.append(sig("device_cpu_high", EntityType.DEVICE, "leafA", offset_s=2))
    sigs.append(sig("device_mem_high", EntityType.DEVICE, "leafB", offset_s=40))
    # shared-token cluster (site token)
    for k in range(4):
        sigs.append(sig("metric_anomaly", EntityType.DEVICE, f"dev-tok-{k}",
                        offset_s=3 * k, tokens=("site-dfw",)))
    # disjoint singletons (no shared anything → gap hints only)
    for k in range(30):
        sigs.append(sig("metric_anomaly", EntityType.DEVICE, f"lone-{k}",
                        offset_s=k))
    seams = (SeamView(
        seam_id="dallas-dx-equinix", tenant_id="t1", seam_type="DX",
        endpoints=(("on_prem", "dallas-edge"), ("provider_edge", "equinix-pop")),
    ),)
    adjacency = TopologyAdjacency.from_links([{"a": "leafA", "b": "leafB"}])
    return build_nodes(tuple(sigs)), seams, adjacency


# ── 1. soundness / equivalence ───────────────────────────────────────────────


def test_build_edges_equals_brute_force_on_mixed_window():
    nodes, seams, adjacency = mixed_window()
    cfg = EngineConfig()
    fast = build_edges(nodes, seams, cfg, adjacency=adjacency)
    ref = brute_force_edges(nodes, seams, cfg, adjacency=adjacency)
    assert fast == ref
    edges, gap_hints = fast
    # sanity: every rung actually exercised, and honest gaps counted
    kinds = {e.grounding.ref.split(":")[0] if ":" in e.grounding.ref else e.grounding.kind
             for e in edges}
    assert edges and gap_hints > 0
    assert any(e.grounding.kind == "seam" for e in edges)
    assert any(e.grounding.ref.startswith("adj:") for e in edges)
    assert any(e.grounding.ref.startswith("shared:") for e in edges)
    assert kinds  # non-empty variety


def test_build_edges_equals_brute_force_with_stale_topology():
    nodes, seams, adjacency = mixed_window()
    cfg = EngineConfig()
    assert build_edges(nodes, seams, cfg, adjacency=adjacency, topology_stale=True) \
        == brute_force_edges(nodes, seams, cfg, adjacency=adjacency, topology_stale=True)


def test_build_edges_equals_brute_force_with_path_graph():
    """Path-relation pruning (shared observation membership + route refs) must
    not lose a single rank-1..6 relation: the §10 lab path view relates a cloud
    app symptom to an on-prem WAN-edge fault with ZERO shared tokens."""
    app, wan = lab_signals("acme")
    extras = [sig("metric_anomaly", EntityType.DEVICE, f"noise-{k}", offset_s=k,
                  tenant="acme") for k in range(10)]
    nodes = build_nodes((app, wan, *extras))
    paths = PathIndex(lab_path_view("acme"), "acme")
    cfg = EngineConfig()
    fast = build_edges(nodes, (), cfg, paths=paths)
    ref = brute_force_edges(nodes, (), cfg, paths=paths)
    assert fast == ref
    assert any(e.grounding.ref.startswith("path:") for e in fast[0]), \
        "the rank-4 app→endpoint path relation must survive pruning"


def test_build_edges_deterministic_across_runs():
    nodes, seams, adjacency = mixed_window()
    cfg = EngineConfig()
    a = build_edges(nodes, seams, cfg, adjacency=adjacency)
    b = build_edges(nodes, seams, cfg, adjacency=adjacency)
    assert a == b


# ── 2. complexity: exact operation counts ────────────────────────────────────


def _disjoint_nodes(n: int):
    """n nodes sharing NOTHING: unique ids, no tokens, no seams, no adjacency."""
    return build_nodes(tuple(
        sig("metric_anomaly", EntityType.SERVICE, f"svc-{k:04d}", offset_s=float(k % 300))
        for k in range(n)
    ))


def test_disjoint_1k_node_window_scores_zero_pairs():
    """The 1k-node storm shape: 499_500 naive pair evaluations collapse to 0
    scored candidates; the gap-hint total stays exactly C(n,2)."""
    nodes = _disjoint_nodes(1000)
    assert len(nodes) == 1000
    toks = [nd.tokens() for nd in nodes]
    refs = [nd.identity_refs() for nd in nodes]
    devs = [nd.device_part() for nd in nodes]
    cand = _candidate_pairs(len(nodes), toks, refs, [], devs, NO_ADJACENCY, None, None)
    assert cand == set(), "disjoint nodes must produce ZERO scored candidates"
    edges, gap_hints = build_edges(nodes, (), EngineConfig())
    assert edges == ()
    assert gap_hints == 1000 * 999 // 2  # honest gap count is NOT pruned away


def test_clustered_window_scores_exactly_sum_of_cluster_pairs():
    """100 disjoint clusters of 10 token-sharing nodes: candidates == 100·C(10,2)
    == 4_500 — proportional to real relations, not to C(1000,2) == 499_500."""
    sigs = []
    for c in range(100):
        for k in range(10):
            sigs.append(sig("metric_anomaly", EntityType.SERVICE, f"c{c:03d}-m{k}",
                            offset_s=float(k), tokens=(f"cluster-{c:03d}",)))
    nodes = build_nodes(tuple(sigs))
    assert len(nodes) == 1000
    toks = [nd.tokens() for nd in nodes]
    refs = [nd.identity_refs() for nd in nodes]
    devs = [nd.device_part() for nd in nodes]
    cand = _candidate_pairs(len(nodes), toks, refs, [], devs, NO_ADJACENCY, None, None)
    assert len(cand) == 100 * (10 * 9 // 2)
    # and the scored result still matches brute force exactly
    cfg = EngineConfig()
    assert build_edges(nodes, (), cfg) == brute_force_edges(nodes, (), cfg)


def test_concentrated_hub_token_storm_collapses_to_zero_candidates():
    """#168 Stage-2 Lever 1 — the concentrated storm shape. One token shared by
    1_000 nodes is a non-specific HUB: its C(1000,2) == 499_500 all-pairs mesh is
    pure rank-7 noise and is EXCLUDED from candidate generation, collapsing the
    quadratic to zero. build_edges still matches the (capped) brute-force
    reference byte-for-byte, and the honest gap count stays C(n,2)."""
    sigs = [sig("metric_anomaly", EntityType.SERVICE, f"hub-m{k:04d}",
                offset_s=float(k % 300), tokens=("everyones-token",))
            for k in range(1000)]
    nodes = build_nodes(tuple(sigs))
    assert len(nodes) == 1000
    toks = [nd.tokens() for nd in nodes]
    refs = [nd.identity_refs() for nd in nodes]
    devs = [nd.device_part() for nd in nodes]
    # "everyones-token" is shared by 1000 > CORR_TOKEN_HUB_CAP nodes → hub → no mesh.
    cand = _candidate_pairs(len(nodes), toks, refs, [], devs, NO_ADJACENCY, None, None)
    assert cand == set(), "a hub-token group must generate ZERO candidate pairs"
    cfg = EngineConfig()
    edges, gap_hints = build_edges(nodes, (), cfg)
    assert edges == ()
    assert gap_hints == 1000 * 999 // 2
    assert build_edges(nodes, (), cfg) == brute_force_edges(nodes, (), cfg)


def test_at_cap_token_group_fully_meshes_but_above_cap_drops():
    """The cap boundary is exact: a token shared by EXACTLY cap nodes keeps its
    full C(cap,2) mesh; one more node makes it a hub and the mesh vanishes. Proves
    the cut is `> cap`, not `>= cap`, and that realistic small groups are intact."""
    cap = CORR_TOKEN_HUB_CAP

    def _cand_for(count):
        sigs = [sig("metric_anomaly", EntityType.SERVICE, f"g-m{k:04d}",
                    offset_s=float(k), tokens=("grp",)) for k in range(count)]
        nodes = build_nodes(tuple(sigs))
        toks = [nd.tokens() for nd in nodes]
        refs = [nd.identity_refs() for nd in nodes]
        devs = [nd.device_part() for nd in nodes]
        return _candidate_pairs(len(nodes), toks, refs, [], devs, NO_ADJACENCY,
                                None, None)

    assert len(_cand_for(cap)) == cap * (cap - 1) // 2      # at cap: full mesh
    assert _cand_for(cap + 1) == set()                       # above cap: dropped


def test_per_node_views_computed_once_not_per_pair(monkeypatch):
    """tokens() was recomputed for BOTH sides of every pair (2·C(n,2) calls at
    ~200 nodes = 39_800). The precompute pins it to exactly n calls."""
    nodes, seams, adjacency = mixed_window()
    n = len(nodes)
    calls = {"tokens": 0, "identity_refs": 0}
    orig_tokens, orig_refs = EngineNode.tokens, EngineNode.identity_refs

    def counting_tokens(self):
        calls["tokens"] += 1
        return orig_tokens(self)

    def counting_refs(self):
        calls["identity_refs"] += 1
        return orig_refs(self)

    monkeypatch.setattr(EngineNode, "tokens", counting_tokens)
    monkeypatch.setattr(EngineNode, "identity_refs", counting_refs)
    build_edges(nodes, seams, EngineConfig(), adjacency=adjacency)
    assert calls["tokens"] == n
    assert calls["identity_refs"] == n
