# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Tracker 185 residual — `reconcile.find_continuation` must not hold the loop.

WHAT HAPPENED. Storm run `storm-s04-08300637` took a 29,974 ms event-loop stall
of which **27,844 ms was measured SYNCHRONOUS time** at the site
`reconcile.find_continuation` (`corr_sync_stretch_max_ms`, 16 overruns of the
500 ms budget, 14 of them at that site). The profile said it was a handful of
objects, not a broad regression: 8,444 calls, p50 0.06 ms, p99 0.66 ms, max
27,844 ms. The run passed stability only because the same commit widened the
Kafka session timeout 30 s → 60 s — the block was never bounded.

THE ROOT CAUSE, and it is a complexity defect, not a scheduling one. Admission
is `jac >= min_overlap OR _seam_bridged(probe, candidate)`, so a probe whose
entity set is huge (a storm aggregate: 900+ nodes, ~95k signals, ZERO edges)
scores a near-zero Jaccard against every candidate and therefore reaches
`_seam_bridged` for ALL of them. `_seam_bridged` then re-derived, once per
candidate pair:

  * `_snap_touches_seam(probe, view)` as `any(n.identity_refs() & ev ...)` —
    and `Node.identity_refs()` is itself O(|node.signals|) (it derives the
    observer set from the signals), so ONE such test walks the probe's entire
    signal population. **O(candidates x Σ|signals|).**
  * the seam-id → view map, by scanning `(*a.seams, *b.seams)` — and
    `run_window` stamps the WHOLE tenant seam inventory into every snapshot it
    emits, so that is O(|inventory|) per pair of pure re-derivation of a
    constant. (The same "the inventory is not per-object" shape tracker 162's
    grounded re-keying removed from `ContinuationIndex`.)
  * plus `find_continuation`'s own `ce | se` union SET, built and discarded
    once per candidate — O(|probe entities|) per candidate.

THE FIX is algebraic, not a yield: REFS(x) = ∪ node.identity_refs is cached on
the snapshot and `any(n.identity_refs() & ev)` becomes `REFS(x) & ev` (a union
meets `ev` iff some member does); G(x) is cached the same way; the seam map is
built once per inventory; and the Jaccard uses |A∪B| = |A|+|B|-|A∩B|. The
probe's cost stops depending on the candidate count altogether.

WHAT THIS FILE PINS.
  * THE BOUND, counted not timed: probing a live-shaped storm aggregate touches
    each of its signals a CONSTANT number of times, whatever the candidate
    population — and the pre-fix algorithm, reproduced here from first
    principles, touches them tens of times more on the same fixture (so the
    fixture is proven pathological rather than merely small).
  * EQUIVALENCE: over randomized corpora the shipped `find_continuation` and
    `_seam_bridged` return exactly what the pre-fix implementations return.
    The continuation decision is the object's IDENTITY — it may not move.
  * The cache rules that make instance caching safe (recompute on copy).
"""
from __future__ import annotations

import dataclasses
import random
from collections.abc import Callable
from datetime import timedelta
from typing import ClassVar, Literal

import pytest

import engine
from catalog import builtin_catalog
from engine import (
    ContinuationIndex,
    Edge,
    EngineConfig,
    Grounding,
    Node,
    ObjectSnapshot,
    SeamView,
    _entity_ids,
    _seam_bridged,
    _seam_view_index,
    _windows_overlap,
    build_nodes,
    find_continuation,
    run_window,
)
from path_graph import seam_relation
from signals import EntityType, ModalityClass, Severity
from test_engine import sig

CAT = builtin_catalog()
CFG = EngineConfig()

# Live-shaped: the storm aggregate on `storm-s04` carried 900+ nodes and ~95k
# signals with no edges. Node count is kept at the live figure because it is the
# dimension the defect multiplied by the candidate count; signals per node are
# scaled down so the fixture builds in well under a second (the per-signal cost
# is linear in BOTH implementations, so it changes the ratio not at all).
AGG_NODES = 900
AGG_SIGS_PER_NODE = 6
POP_OBJECTS = 400


# ── the pre-fix implementation, reproduced from first principles ─────────────
#
# Deliberately NOT imported from engine: it is the ORACLE this change is judged
# against, so it has to keep working after the shipped code changes. It goes
# through `Node.identity_refs()` (uncached, per node) exactly as the shipped
# code did before this commit.

def _ref_grounded(snap: ObjectSnapshot) -> frozenset[str]:
    return frozenset(e.grounding.ref for e in snap.edges
                     if e.grounding.kind == "seam" and e.grounding.authoritative)


def _ref_touches(snap: ObjectSnapshot, view: SeamView) -> bool:
    ev = view.endpoint_values() | {view.seam_id}
    return any(n.identity_refs() & ev for n in snap.nodes)


def _ref_seam_bridged(a: ObjectSnapshot, b: ObjectSnapshot) -> bool:
    if a.tenant_id != b.tenant_id:
        return False
    grounded = _ref_grounded(a) | _ref_grounded(b)
    if not grounded:
        return False
    views: dict[str, SeamView] = {}
    for v in (*a.seams, *b.seams):
        if v.seam_id in grounded and v.tenant_id in ("", a.tenant_id):
            views.setdefault(v.seam_id, v)
    return any(_ref_touches(a, views[sid]) and _ref_touches(b, views[sid])
               for sid in sorted(views))


def _ref_find_continuation(snap, open_snaps, min_overlap: float = 0.4, *,
                           exclude=(), entity_cache=None) -> str:
    ce = _entity_ids(snap)
    if not ce:
        return ""
    best: tuple | None = None
    best_cid = ""
    for s in open_snaps:
        if s.correlation_id in exclude:
            continue
        if (s.tenant_id != snap.tenant_id
                or s.correlation_id == snap.correlation_id
                or not _windows_overlap(snap, s)):
            continue
        if entity_cache is None:
            se = _entity_ids(s)
        else:
            cached = entity_cache.get(s.correlation_id)
            if cached is None:
                cached = entity_cache[s.correlation_id] = _entity_ids(s)
            se = cached
        union = ce | se
        jac = len(ce & se) / len(union) if union else 0.0
        if jac < min_overlap and not _ref_seam_bridged(snap, s):
            continue
        if (best is None or jac > best[0]
                or (jac == best[0]
                    and (s.window_start, s.correlation_id) < (best[1], best[2]))):
            best, best_cid = (jac, s.window_start, s.correlation_id), s.correlation_id
    return best_cid


# ── the signal-touch counter (an OPERATION count, never a wall clock) ────────

class _Touches:
    """Counts `Node.identity_refs()` calls and the signals each one walks.

    `identity_refs` is O(|node.signals|) — it derives the observer set from the
    signals — so "signals walked" is the honest unit of the defect, and it is
    deterministic: the same fixture yields the same number on any machine."""

    def __init__(self) -> None:
        self.calls = 0
        self.signals = 0
        self._orig: Callable[[Node], frozenset[str]] = Node.identity_refs

    def __enter__(self) -> _Touches:  # noqa: PYI034 — no typing.Self on py3.10
        orig, outer = self._orig, self

        def counting(node: Node) -> frozenset[str]:
            outer.calls += 1
            outer.signals += len(node.signals)
            return orig(node)

        Node.identity_refs = counting          # type: ignore[method-assign, assignment]
        return self

    def __exit__(self, *exc: object) -> Literal[False]:
        Node.identity_refs = self._orig        # type: ignore[method-assign, assignment]
        return False


class _CountingSeams(tuple):
    """A seam inventory that counts how many VIEWS get scanned out of it.

    The second half of the defect is not about signals at all: `_seam_bridged`
    rebuilt its seam_id → view map by walking `(*a.seams, *b.seams)` on every
    candidate pair, and `run_window` stamps the whole tenant inventory into
    every snapshot — so the scan is O(|inventory|) per pair for a map that is a
    constant of the cycle. Counting iteration is the deterministic witness."""

    __slots__ = ()
    _n: ClassVar[list[int]] = [0]

    def __iter__(self):
        for v in tuple.__iter__(self):
            _CountingSeams._n[0] += 1
            yield v

    @staticmethod
    def reset() -> None:
        _CountingSeams._n[0] = 0

    @staticmethod
    def scanned() -> int:
        return _CountingSeams._n[0]


# ── fixtures: a live-shaped storm aggregate over a seam-dense estate ─────────

def _inventory(n: int) -> tuple[SeamView, ...]:
    """One seam per device — every device in the estate is a seam ENDPOINT.
    Tenant-constant (untenanted/platform), the live shape."""
    return tuple(
        SeamView(seam_id=f"seam-{i}", tenant_id="", seam_type="DX",
                 endpoints=(("member_edge", f"dev-{i}"),
                            ("provider_resource", f"dxcon-{i}/vif")))
        for i in range(n))


def _base() -> ObjectSnapshot:
    """One genuine engine snapshot to clone window/ranking/version fields from."""
    return run_window(
        [sig("device_cpu_high", EntityType.DEVICE, "seed-dev"),
         sig("if_errors", EntityType.INTERFACE, "seed-dev:Gi0/1", offset_s=5)],
        CAT, (), CFG)[0]


BASE = _base()


def _open_object(i: int, seams: tuple[SeamView, ...],
                 tenant: str = "") -> ObjectSnapshot:
    """One open object on `dev-i`, holding an AUTHORITATIVE seam-grounded edge
    on `seam-i` — the shape that puts a candidate into the bridge clause."""
    nodes = build_nodes((
        sig("bgp_adjacency_change", EntityType.DEVICE, f"dev-{i}",
            modality=ModalityClass.CONTROL_PLANE, severity=Severity.CRIT),
        sig("probe_loss", EntityType.PATH, f"vantage-1->dev-{i}", offset_s=10,
            observer="probe1", modality=ModalityClass.ACTIVE_PROBE,
            severity=Severity.CRIT),
    ))
    edge = Edge(
        from_node=nodes[0].key, to_node=nodes[-1].key,
        grounding=Grounding("seam", f"seam-{i}", seam_relation(f"seam-{i}", True)),
        weight=0.8, w_temporal=1.0, w_topo=0.8, w_reinforce=1.0,
        direction_conf=0.0, direction_basis="none")
    return dataclasses.replace(
        BASE, correlation_id=f"open-{i:05d}", tenant_id=tenant,
        nodes=nodes, edges=(edge,), seams=seams)


def _aggregate(nodes_n: int, sigs_per_node: int, seams: tuple[SeamView, ...],
               tenant: str = "") -> ObjectSnapshot:
    """The storm-noise aggregate: many nodes, ZERO edges, a large signal count,
    the tenant's whole seam inventory embedded (`storm-s04`'s `bb1e46d6…`)."""
    window = tuple(
        sig("device_cpu_high", EntityType.DEVICE, f"dev-{d}", offset_s=k * 0.01)
        for d in range(nodes_n) for k in range(sigs_per_node))
    return dataclasses.replace(
        BASE, correlation_id="bb1e46d6-storm-aggregate", tenant_id=tenant,
        nodes=build_nodes(window), edges=(), seams=seams, storm_aggregate=True)


@pytest.fixture(scope="module")
def estate():
    seams = _inventory(AGG_NODES)
    pop = [_open_object(i, seams) for i in range(POP_OBJECTS)]
    agg = _aggregate(AGG_NODES, AGG_SIGS_PER_NODE, seams)
    return seams, pop, agg


def _probe_reaches(agg: ObjectSnapshot, cands) -> int:
    """How many candidates get past the cheap guards into the admission test —
    the fixture's own premise, asserted rather than assumed."""
    return sum(1 for s in cands
               if s.tenant_id == agg.tenant_id
               and s.correlation_id != agg.correlation_id
               and _windows_overlap(agg, s))


# ── 1. THE BOUND ─────────────────────────────────────────────────────────────

def test_aggregate_probe_touches_each_signal_a_constant_number_of_times(estate):
    """The reproduction. Pre-fix this was O(candidates x Σ|signals|)."""
    _seams, pop, agg = estate
    idx = ContinuationIndex(pop)                      # index build: not measured
    cands = idx.candidates(agg)
    reaching = _probe_reaches(agg, cands)
    assert reaching >= POP_OBJECTS // 2, (
        f"premise broken: only {reaching} candidates reach the admission test, "
        "so this fixture no longer exercises the defect")

    fresh = dataclasses.replace(agg)      # drop the caches the probe above filled
    with _Touches() as t:
        winner = find_continuation(fresh, cands, entity_cache={})
    with _Touches() as ref:
        ref_winner = _ref_find_continuation(fresh, cands, entity_cache={})

    assert winner == ref_winner, "the fix moved the continuation decision"
    # The probe walks its own signal population ONCE. The `<= 2x` slack is for
    # the union build inside `identity_refs` itself, never for a second sweep.
    assert t.signals <= 2 * fresh.signal_count(), (
        f"probe walked {t.signals:,} signals for an object holding "
        f"{fresh.signal_count():,} — the cost is still per-candidate")
    # …and the pre-fix algorithm, on the SAME inputs, walks vastly more. This is
    # what proves the fixture is pathological rather than merely small.
    assert ref.signals >= 20 * t.signals, (
        f"reference walked {ref.signals:,} vs {t.signals:,} — the fixture no "
        "longer reproduces the super-linear cost, so the bound above is vacuous")


def test_probe_cost_does_not_grow_with_the_candidate_population(estate):
    """The complexity statement, stated as an invariant: O(1) in |candidates|.

    Pre-fix this number was proportional to the candidate count — which is
    exactly why a storm (many open objects) turned a 0.66 ms p99 into 27.8 s."""
    _seams, pop, agg = estate
    small, large = pop[:POP_OBJECTS // 4], pop
    assert len(large) >= 4 * len(small) - 3

    counts = []
    for population in (small, large):
        idx = ContinuationIndex(population)
        cands = idx.candidates(agg)
        fresh = dataclasses.replace(agg)
        with _Touches() as t:
            find_continuation(fresh, cands, entity_cache={})
        counts.append(t.signals)
    assert counts[0] == counts[1], (
        f"probe cost moved with the population: {counts[0]:,} signals against "
        f"{len(small)} candidates, {counts[1]:,} against {len(large)}")


def test_index_candidate_retrieval_is_also_bounded(estate):
    """`ContinuationIndex.candidates()` sits inside the SAME `sync_span`, so it
    is part of the block tracker 185 bounds — it must share the cached union."""
    _seams, pop, agg = estate
    idx = ContinuationIndex(pop)
    fresh = dataclasses.replace(agg)
    with _Touches() as t:
        idx.candidates(fresh)
    assert t.signals <= 2 * fresh.signal_count()


def test_seam_view_map_is_built_once_per_inventory_not_once_per_pair():
    """The other super-linear term: the inventory scan inside `_seam_bridged`."""
    seams = _CountingSeams(_inventory(400))
    pop = [_open_object(i, seams) for i in range(60)]
    agg = _aggregate(60, 2, seams)
    idx = ContinuationIndex(pop)
    cands = idx.candidates(agg)
    assert _probe_reaches(agg, cands) >= 30, "premise: candidates reach the test"

    _CountingSeams.reset()
    find_continuation(dataclasses.replace(agg), cands, entity_cache={})
    shipped = _CountingSeams.scanned()
    _CountingSeams.reset()
    _ref_find_continuation(dataclasses.replace(agg), cands, entity_cache={})
    reference = _CountingSeams.scanned()

    assert shipped <= 2 * len(seams), (
        f"the inventory was scanned {shipped:,} times for {len(seams)} views — "
        "the seam map is still being rebuilt per candidate pair")
    assert reference >= 10 * max(shipped, 1), (
        f"reference scanned {reference:,} vs {shipped:,} — the fixture no "
        "longer reproduces the per-pair inventory scan")


# ── 2. EQUIVALENCE — the continuation decision may not move ─────────────────

def test_shipped_and_reference_agree_on_the_live_shaped_estate(estate):
    _seams, pop, agg = estate
    idx = ContinuationIndex(pop)
    assert (find_continuation(dataclasses.replace(agg), idx.candidates(agg))
            == _ref_find_continuation(dataclasses.replace(agg), pop))


def _corpus_obj(rng: random.Random, i: int, seams, foreign):
    """One randomized object: network half or cloud half, seam-grounded or not,
    authoritative or rank-7, own inventory or an inventory carrying a foreign
    tenant's duplicate of the same seam id."""
    tenant = rng.choice(("", "t-a", "t-b"))
    sid = rng.randrange(12)
    if rng.random() < 0.35:
        # the tracker-154b CLOUD half: the seam's OTHER endpoint, so a bridge to
        # the network half of the same seam has ZERO shared entities.
        window = tuple(
            sig("cloud_bgp_session_down", EntityType.CLOUD_RESOURCE,
                f"dxcon-{sid}/vif", offset_s=k * 10, observer="cloudapi",
                modality=ModalityClass.CONTROL_PLANE, severity=Severity.CRIT)
            for k in range(rng.randrange(1, 3)))
    else:
        window = tuple(
            sig("device_cpu_high", EntityType.DEVICE, f"dev-{sid + k}",
                offset_s=rng.randrange(0, 40))
            for k in range(rng.randrange(1, 4)))
    nodes = build_nodes(window)
    edges: tuple[Edge, ...] = ()
    roll = rng.random()
    if roll < 0.7:
        # An object usually grounds on a seam it TOUCHES (roll < 0.55); the rest
        # ground on a far seam, which must never bridge.
        ref = f"seam-{sid}" if roll < 0.55 else f"seam-{rng.randrange(12, 24)}"
        edges = (Edge(from_node=nodes[0].key, to_node=nodes[-1].key,
                      grounding=Grounding("seam", ref,
                                          seam_relation(ref, roll < 0.5)),
                      weight=0.8, w_temporal=1.0, w_topo=0.8, w_reinforce=1.0,
                      direction_conf=0.0, direction_basis="none"),)
    inv = seams if rng.random() < 0.7 else (*foreign, *seams)
    # Windows are varied so the overlap guard is a live discriminator in the
    # oracle, not a constant that always passes.
    shift = timedelta(seconds=rng.randrange(-60, 61))
    return dataclasses.replace(
        BASE, correlation_id=f"c-{i:04d}", tenant_id=tenant,
        nodes=nodes, edges=edges, seams=inv,
        window_start=BASE.window_start + shift,
        window_end=BASE.window_end + shift)


def _corpus(rng: random.Random, n: int):
    """Randomized objects: seam-grounded / ungrounded / non-authoritative,
    network and cloud halves, overlapping and disjoint entity sets, several
    tenants, and inventories that carry a foreign tenant's duplicate seam id."""
    seams = _inventory(24)
    foreign = tuple(dataclasses.replace(v, tenant_id="t-other") for v in seams[:6])
    return [_corpus_obj(rng, i, seams, foreign) for i in range(n)]


@pytest.mark.parametrize("seed", [1, 7, 42, 1337, 20260830])
def test_seam_bridged_matches_the_reference_pairwise(seed):
    corpus = _corpus(random.Random(seed), 26)
    checked = bridged = 0
    for a in corpus:
        for b in corpus:
            got, want = _seam_bridged(a, b), _ref_seam_bridged(a, b)
            assert got == want, (
                f"seed {seed}: _seam_bridged({a.correlation_id}, "
                f"{b.correlation_id}) = {got}, reference says {want}")
            checked += 1
            bridged += bool(want)
    assert bridged, f"seed {seed}: no pair bridged — the oracle proves nothing"
    assert checked == len(corpus) ** 2


@pytest.mark.parametrize("seed", [1, 7, 42, 1337, 20260830])
def test_find_continuation_matches_the_reference_over_a_random_corpus(seed):
    rng = random.Random(seed)
    corpus = _corpus(rng, 60)
    probes = _corpus(random.Random(seed + 999), 24)
    adopted = 0
    for probe in probes:
        excl = frozenset(s.correlation_id
                         for s in corpus if rng.random() < 0.2)
        got = find_continuation(dataclasses.replace(probe), corpus,
                                exclude=excl, entity_cache={})
        want = _ref_find_continuation(dataclasses.replace(probe), corpus,
                                      exclude=excl, entity_cache={})
        assert got == want, f"seed {seed}: probe {probe.correlation_id}"
        adopted += bool(want)
    assert adopted, f"seed {seed}: nothing continued — the oracle proves nothing"


@pytest.mark.parametrize("seed", [3, 11, 99])
def test_jaccard_rewrite_is_bit_identical(seed):
    """|A ∪ B| = |A| + |B| - |A ∩ B|, including at the 0.4 admission boundary."""
    rng = random.Random(seed)
    for _ in range(3000):
        a = frozenset(rng.randrange(40) for _ in range(rng.randrange(1, 20)))
        b = frozenset(rng.randrange(40) for _ in range(rng.randrange(0, 20)))
        inter = len(a & b)
        assert inter / (len(a) + len(b) - inter) == len(a & b) / len(a | b)


# ── 3. the seam-view index, and the instance caches ─────────────────────────

def test_seam_view_index_keeps_first_admissible_view_and_tenant_filter():
    dup_foreign = SeamView(seam_id="seam-1", tenant_id="t-other", seam_type="DX",
                           endpoints=(("member_edge", "wrong"),))
    dup_own = SeamView(seam_id="seam-1", tenant_id="t-a", seam_type="DX",
                       endpoints=(("member_edge", "right"),))
    later = SeamView(seam_id="seam-1", tenant_id="", seam_type="DX",
                     endpoints=(("member_edge", "later"),))
    inv = (dup_foreign, dup_own, later)
    got = _seam_view_index(inv, "t-a")
    assert got["seam-1"] is dup_own, "first ADMISSIBLE view must win"
    assert _seam_view_index(inv, "t-b")["seam-1"] is later, (
        "a foreign tenant's view may never be selected")
    # identity-verified: the same id() with a different tuple must not be served
    assert _seam_view_index(tuple(inv), "t-a")["seam-1"] is dup_own


def test_bridge_takes_the_first_snapshot_s_view_when_inventories_disagree():
    """`(*a.seams, *b.seams)` + setdefault means A's view of a seam id wins over
    B's. That ordering is load-bearing — it decides the answer whenever the two
    embedded inventories disagree about the same seam — so it is pinned in both
    directions, against the reference."""
    blind = SeamView(seam_id="seam-7", tenant_id="", seam_type="DX",
                     endpoints=(("member_edge", "somewhere-else"),))
    seeing = SeamView(seam_id="seam-7", tenant_id="", seam_type="DX",
                      endpoints=(("member_edge", "dev-7"),))
    a = dataclasses.replace(_open_object(7, (blind,)), correlation_id="a")
    b = dataclasses.replace(_open_object(7, (seeing,)), correlation_id="b")
    # a first ⇒ the blind view is the one consulted ⇒ no bridge.
    assert _seam_bridged(a, b) is False
    assert _ref_seam_bridged(a, b) is False
    # b first ⇒ the seeing view is consulted ⇒ bridged.
    assert _seam_bridged(b, a) is True
    assert _ref_seam_bridged(b, a) is True


def test_seam_view_index_is_hard_bounded():
    before = dict(engine._SEAM_VIEW_INDEX)
    try:
        for i in range(engine._SEAM_VIEW_INDEX_MAX * 3):
            _seam_view_index(_inventory(2 + i), f"t-{i}")
            assert len(engine._SEAM_VIEW_INDEX) <= engine._SEAM_VIEW_INDEX_MAX
    finally:
        engine._SEAM_VIEW_INDEX.clear()
        engine._SEAM_VIEW_INDEX.update(before)


def test_snapshot_caches_do_not_survive_a_copy():
    """The instance caches follow content_hash's rule: NOT dataclass fields, so
    a `dataclasses.replace` copy is uncached and recomputes. A cache that
    survived a copy would hand a re-keyed continuation the WRONG identity."""
    seams = _inventory(4)
    obj = _open_object(1, seams)
    assert obj.identity_refs() == frozenset(
        r for n in obj.nodes for r in n.identity_refs())
    assert obj.grounded_seam_ids() == frozenset({"seam-1"})

    other = build_nodes((sig("device_cpu_high", EntityType.DEVICE, "dev-999"),))
    copy = dataclasses.replace(obj, nodes=other, edges=())
    assert copy.identity_refs() == frozenset(
        r for n in other for r in n.identity_refs())
    assert copy.identity_refs() != obj.identity_refs()
    assert copy.grounded_seam_ids() == frozenset()
    # …and the original is untouched by its copy.
    assert obj.grounded_seam_ids() == frozenset({"seam-1"})


def test_membership_values_is_the_endpoint_set_plus_the_seam_id():
    v = SeamView(seam_id="s1", tenant_id="", seam_type="DX",
                 endpoints=(("a", "x"), ("b", "y")))
    assert v.membership_values() == frozenset({"x", "y", "s1"})
    assert v.membership_values() is v.membership_values()   # cached
    assert dataclasses.replace(v, seam_id="s2").membership_values() == \
        frozenset({"x", "y", "s2"})


def test_identity_refs_union_equals_the_per_node_any_predicate():
    """The algebraic step the fix rests on, pinned directly."""
    seams = _inventory(6)
    obj = _open_object(3, seams)
    for view in seams:
        assert (bool(obj.identity_refs() & view.membership_values())
                == _ref_touches(obj, view))
