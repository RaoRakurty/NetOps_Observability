"""Tracker 192 — the un-instrumented loop block on the cleanup / re-key path.

WHAT HAPPENED. `storm-s05` recorded a **9,134.9 ms** process-lifetime
`corr_loop_lag_max_ms` and `storm-s06` **13,881.1 ms**, both during harness
CLEANUP (the mass delete of the run's 2,500 devices), with the signature
"log silence, then a dense burst of *continued under re-keyed window*". In both
legs `corr_sync_stretch_max_ms` stayed **≤ 443.5 ms with 0 overruns**, so the
block happened somewhere **no `sync_span` covered** — the whole complaint of
tracker 192 (`STORM_S05_S06_CLOSEOUT_2026-08-30.md` §6.1).

WHAT THE EVIDENCE ACTUALLY SHOWS (measured on the live `netops-correlation-3`
process, 2026-08-30 23:0x UTC, which was still reproducing the same 1.0-2.9 s
stalls after the run):

  * per-thread `/proc/<pid>/task/*/stat` sampling at 100 ms across 16 logged
    stalls shows the EVENT-LOOP (main) thread burning 0.3-0.9 core for
    1.3-1.8 s continuously without servicing its own 0.5 s watchdog timer. The
    block is loop-thread Python, not IO;
  * it is NOT executor/GIL starvation: a control experiment (8 s of offloaded
    pure-Python CPU against an 8M-object heap, GC on) costs the loop **≤ 39 ms**;
  * no `sync_span` site is attributed to it (`stretch_max_site`
    `lifecycle.merge_index`, 401.1 ms) ⇒ the block is in an UNSPANNED
    loop-thread stretch.

THE PRIME SUSPECT IN THE TRACKER — the `_cont_buckets` build — IS RULED OUT.
It is O(open objects) with a dict-lookup constant: 463 open objects live,
1,385 epoch peak (`/healthz` `epoch.cohort_open_objects` /
`open_objects_epoch_peak`). It cannot be seconds. It is instrumented anyway
(`reconcile.cont_buckets`), because "cannot be" is an argument and a span is a
measurement.

THE TERM THIS FILE BOUNDS. Of the unspanned loop-thread stretches on the
cohort path, one is genuinely superlinear in the drain depth:

    _carried_edges_for(tenant, live) re-scans and re-filters the ENTIRE
    per-tenant edge cache on EVERY cohort — O(K x |edge cache|) per epoch —
    while `live` is the epoch's FROZEN live_keys[tenant] and cannot change
    between the cohorts of one epoch.

Live: **132,528 cached edges across 4 tenants** (`/healthz` `edge_cache.edges`),
re-tested once per cohort, with no `sync_span` and no `loop_yield` in the whole
per-tenant transaction body. A mass device delete is what makes the DROP side
maximal — every retired device's keys test stale at once — which is why the
worst numbers land in cleanup.

THE FIX is algebraic, not a yield: a key that survived a test against this
epoch's `live` survives every later test against the same set, so only the keys
`_remember_edges` has ADDED since the last test have an unknown verdict. Per
epoch: O(|cache| + |added|) instead of O(K x |cache|).

WHAT THIS FILE PINS.
  * EQUIVALENCE, over randomized multi-epoch / multi-cohort corpora, against the
    pre-192 algorithm reproduced here from first principles: the carried edge
    tuple, the surviving cache and `EDGE_CACHE_DROPPED` are identical, key for
    key, drop for drop. Carried edges decide component formation, so this is the
    engine's INPUT — it may not move.
  * THE BOUND, counted not timed: on a live-shaped 132,528-edge cache with a
    2,500-device mass delete and an 8-cohort epoch, the shipped code performs
    at most `|cache| + |added|` key tests for the whole epoch, and the pre-192
    algorithm performs ≥ 4x more on the SAME fixture (so the fixture is proven
    pathological rather than merely small).
  * ATTRIBUTION: every stretch this change instruments actually records under
    its `sync_span` name. Delete a span and the matching assertion fails.
"""
from __future__ import annotations

import asyncio
import random
import time

import pytest

import main
from test_prune_buffer_156 import mk

# ── live-shaped constants, from the s05/s06 carrier replica ──────────────────
EDGE_CACHE_EDGES = 132_528      # /healthz engine_v2.retention.edge_cache.edges
DELETED_DEVICES = 2_500         # what harness cleanup removes in one sweep
SURVIVING_DEVICES = 2_500       # the estate the delete does NOT touch
COHORTS = 8                     # CORR_ENGINE_DRAIN_COHORTS-shaped epoch depth
# 40 % of the cache is incident to the deleted devices, 60 % is estate-internal
# and survives the delete. Both halves matter: the surviving half is what the
# pre-192 algorithm re-tested on every one of the 8 cohorts.
RETIRED_FRACTION = 0.4


class _Edge:
    """Minimal stand-in carrying the two fields the cache keys on."""

    __slots__ = ("from_node", "to_node")

    def __init__(self, a: str, b: str) -> None:
        self.from_node, self.to_node = a, b


class _Snap:
    def __init__(self, edges) -> None:
        self.edges = edges


class _CountingLive(set):
    """`live`, with the KEY TESTS counted.

    The bound is stated in OPERATIONS, not milliseconds: a wall-clock assertion
    on a shared CI runner measures the runner. `tests` counts exactly the
    `k[0] not in live or k[1] not in live` containment checks — the work the
    fix removes — in the shipped code and in the reference alike.
    """

    def __init__(self, *a) -> None:
        super().__init__(*a)
        self.tests = 0

    def __contains__(self, k: object) -> bool:
        self.tests += 1
        return super().__contains__(k)


# ── the pre-192 implementation, reproduced from first principles ─────────────
#
# Deliberately NOT imported from main: it is the ORACLE this change is judged
# against, so it has to keep working after the shipped code changes.

def _ref_carried_edges_for(cache: dict, live) -> tuple[tuple, int]:
    """Returns (carried, dropped). The full scan, on every call."""
    if not cache:
        return (), 0
    stale = [k for k in cache if k[0] not in live or k[1] not in live]
    for k in stale:
        del cache[k]
    if not cache:
        return (), len(stale)
    return tuple(cache.values()), len(stale)


def _ref_remember_edges(cache: dict, snapshots) -> None:
    for snap in snapshots:
        for e in snap.edges:
            cache[(e.from_node, e.to_node)] = e


@pytest.fixture(autouse=True)
def _clean():
    main._TENANT_EDGES.clear()
    main._TENANT_EDGE_FILTERED.clear()
    main._TENANT_EDGE_ADDED.clear()
    main.EDGE_CACHE_DROPPED = 0
    main.EDGE_CACHE_ADDED = 0
    yield
    main._TENANT_EDGES.clear()
    main._TENANT_EDGE_FILTERED.clear()
    main._TENANT_EDGE_ADDED.clear()


def _install(tenant: str, edges: dict) -> None:
    """Seed both the shipped cache and a private reference copy."""
    main._TENANT_EDGES[tenant] = dict(edges)
    main._TENANT_EDGE_FILTERED.pop(tenant, None)
    main._TENANT_EDGE_ADDED.pop(tenant, None)


def _keys(carried) -> list[tuple[str, str]]:
    return sorted((e.from_node, e.to_node) for e in carried)


# ── 1. EQUIVALENCE — the carried edge set is the engine's INPUT ──────────────


@pytest.mark.parametrize("seed", [1, 7, 23, 101, 2026])
def test_epoch_scoped_filter_is_output_identical_to_the_full_rescan(seed):
    """Randomized multi-epoch corpus: shipped vs the pre-192 full re-scan.

    Every epoch gets a fresh, randomly SHRUNK `live` (the cleanup shape) and a
    random number of cohorts; between cohorts both sides settle the same new
    edges, including edges whose endpoints are already dead — the case the
    incremental filter must not miss.
    """
    rng = random.Random(seed)
    nodes = [f"device:dev-{i}:link_down" for i in range(60)]
    seed_edges = {}
    for _ in range(400):
        a, b = rng.choice(nodes), rng.choice(nodes)
        seed_edges[(a, b)] = _Edge(a, b)
    _install("acme", seed_edges)
    ref_cache = {k: v for k, v in seed_edges.items()}

    for epoch in range(1, 6):
        live = set(rng.sample(nodes, rng.randrange(5, len(nodes))))
        for _cohort in range(rng.randrange(1, 6)):
            before = main.EDGE_CACHE_DROPPED
            got = main._carried_edges_for("acme", live, epoch)
            want, ref_dropped = _ref_carried_edges_for(ref_cache, live)
            assert _keys(got) == _keys(want), (
                f"seed {seed} epoch {epoch}: carried edge set moved")
            assert main.EDGE_CACHE_DROPPED - before == ref_dropped, (
                f"seed {seed} epoch {epoch}: EDGE_CACHE_DROPPED accounting moved")
            assert sorted(main._TENANT_EDGES.get("acme", {})) == sorted(ref_cache), (
                f"seed {seed} epoch {epoch}: surviving cache diverged")
            # …and both sides settle the same new edges for the next cohort.
            fresh = []
            for _ in range(rng.randrange(0, 12)):
                a, b = rng.choice(nodes), rng.choice(nodes)
                fresh.append(_Edge(a, b))
            main._remember_edges("acme", [_Snap(fresh)])
            _ref_remember_edges(ref_cache, [_Snap(fresh)])


def test_an_edge_added_mid_epoch_whose_endpoint_is_dead_is_still_dropped():
    """The one case the incremental filter exists to get right: a key added
    AFTER the epoch's full scan has an unknown verdict and must be tested."""
    live = {"a", "b"}
    _install("acme", {("a", "b"): _Edge("a", "b")})
    assert _keys(main._carried_edges_for("acme", live, 1)) == [("a", "b")]
    main._remember_edges("acme", [_Snap([_Edge("a", "zz")])])
    assert _keys(main._carried_edges_for("acme", live, 1)) == [("a", "b")], (
        "an edge settled mid-epoch onto a node outside the window survived — "
        "a stale edge resurrecting an expired node undoes retention (166A)")


def test_a_new_epoch_forces_the_full_scan_again():
    """`live` changes at an epoch boundary, so the memo may not carry over."""
    _install("acme", {("a", "b"): _Edge("a", "b"), ("a", "c"): _Edge("a", "c")})
    assert len(main._carried_edges_for("acme", {"a", "b", "c"}, 1)) == 2
    # epoch 2: c has left the window.
    assert _keys(main._carried_edges_for("acme", {"a", "b"}, 2)) == [("a", "b")]


def test_no_epoch_token_keeps_the_exact_pre_192_behaviour():
    """Every caller outside a drain epoch (tests, tooling) passes no epoch, and
    nothing then guarantees `live` is the same set twice — so it must full-scan
    every call. The tracker-166 lifecycle suite depends on exactly this."""
    _install("acme", {("a", "b"): _Edge("a", "b"), ("a", "c"): _Edge("a", "c")})
    assert len(main._carried_edges_for("acme", {"a", "b", "c"})) == 2
    assert _keys(main._carried_edges_for("acme", {"a", "b"})) == [("a", "b")]
    assert main._carried_edges_for("acme", set()) == ()
    assert "acme" not in main._TENANT_EDGES, "an emptied cache must be released"


def test_derived_state_never_changes_a_result_if_it_leaks():
    """`_TENANT_EDGE_FILTERED` / `_TENANT_EDGE_ADDED` are derived: dropping them
    costs a redundant scan and nothing else. Asserted, because they are
    module-level state that `conftest` does not clear."""
    _install("acme", {("a", "b"): _Edge("a", "b"), ("a", "c"): _Edge("a", "c")})
    main._carried_edges_for("acme", {"a", "b", "c"}, 9)
    main._remember_edges("acme", [_Snap([_Edge("a", "d")])])
    main._TENANT_EDGE_FILTERED.clear()
    main._TENANT_EDGE_ADDED.clear()
    assert _keys(main._carried_edges_for("acme", {"a", "b", "c"}, 9)) == [
        ("a", "b"), ("a", "c")]


# ── 2. THE BOUND — counted, on the live-shaped cleanup fixture ───────────────


def _cleanup_fixture() -> tuple[dict, set, list[list]]:
    """A 132,528-edge cache the moment harness cleanup retires 2,500 devices.

    `RETIRED_FRACTION` of the edges are incident to a deleted device (they go);
    the rest are estate-internal (they stay, and are exactly what the pre-192
    algorithm re-tested on every one of the epoch's 8 cohorts). Each cohort then
    settles a small batch of new estate edges, as a draining epoch does.
    """
    rng = random.Random(192)
    dead = [f"device:mlx-{i}:link_down" for i in range(DELETED_DEVICES)]
    alive = [f"device:est-{i}:link_down" for i in range(SURVIVING_DEVICES)]
    cache: dict[tuple[str, str], _Edge] = {}
    retired = int(EDGE_CACHE_EDGES * RETIRED_FRACTION)
    while len(cache) < retired:
        a, b = rng.choice(dead), rng.choice(dead + alive)
        cache[(a, b)] = _Edge(a, b)
    while len(cache) < EDGE_CACHE_EDGES:
        a, b = rng.choice(alive), rng.choice(alive)
        cache[(a, b)] = _Edge(a, b)
    settled = [[_Edge(rng.choice(alive), rng.choice(alive)) for _ in range(500)]
               for _ in range(COHORTS - 1)]
    return cache, set(alive), settled


def _drive_shipped(cache, live, settled) -> int:
    _install("acme", cache)
    counted = _CountingLive(live)
    for i in range(COHORTS):
        main._carried_edges_for("acme", counted, 1)
        if i < len(settled):
            main._remember_edges("acme", [_Snap(settled[i])])
    return counted.tests


def _drive_reference(cache, live, settled) -> int:
    ref = dict(cache)
    counted = _CountingLive(live)
    for i in range(COHORTS):
        _ref_carried_edges_for(ref, counted)
        if i < len(settled):
            _ref_remember_edges(ref, [_Snap(settled[i])])
    return counted.tests


def test_the_carried_edge_filter_is_bounded_by_the_cache_plus_what_was_added():
    """THE BOUND. One epoch, 8 cohorts, a 132,528-edge cache and a 2,500-device
    mass delete: the whole epoch may test each cached key ONCE, plus once per
    key a cohort added. Stated as operation counts, so it holds on any runner."""
    cache, live, settled = _cleanup_fixture()
    added = sum(len(batch) for batch in settled)
    fixed = _drive_shipped(cache, live, settled)
    # Each KEY may be examined once for the whole epoch; examining one key costs
    # at most two containment tests (`k[0] not in live or k[1] not in live`
    # short-circuits when the first endpoint is already gone).
    budget = 2 * (len(cache) + added)
    assert fixed <= budget, (
        f"{fixed} key tests for one epoch over a {len(cache)}-edge cache "
        f"exceeds the 2 x (|cache| + |added|) = {budget} bound — the "
        f"epoch-scoped filter is re-testing keys whose verdict cannot have "
        f"changed")


def test_the_pre_192_rescan_is_multiples_worse_on_the_same_fixture():
    """The mutation guard for the bound: restore the per-cohort full re-scan
    (which is what dropping the epoch token does) and the same fixture blows the
    budget by a factor. If this ratio ever collapses, the fixture stopped being
    pathological and the bound above stopped proving anything."""
    cache, live, settled = _cleanup_fixture()
    fixed = _drive_shipped(cache, live, settled)
    ref = _drive_reference(cache, live, settled)
    assert ref >= 4 * fixed, (
        f"pre-192 {ref} vs shipped {fixed} key tests — under 4x, so this "
        f"fixture no longer exhibits the O(cohorts x cache) defect")


def test_dropping_the_epoch_token_reproduces_the_unbounded_shape():
    """The same mutation, driven through the SHIPPED function: pass no epoch and
    the per-cohort full re-scan comes straight back."""
    cache, live, settled = _cleanup_fixture()
    _install("acme", cache)
    counted = _CountingLive(live)
    for i in range(COHORTS):
        main._carried_edges_for("acme", counted)      # ← the mutant: no epoch
        if i < len(settled):
            main._remember_edges("acme", [_Snap(settled[i])])
    budget = len(cache) + sum(len(b) for b in settled)
    assert counted.tests > 4 * budget, (
        "the epoch token is decorative — without it the filter is already "
        "bounded, so the fix is not the thing being measured")


@pytest.mark.perf_canary
def test_carried_edge_filter_holds_the_sync_budget_in_wall_clock():
    """The operation bound in milliseconds, on the perf-nightly rung only.

    CORR_SYNC_BUDGET_MS is 500: no single `reconcile.carry_edges` stretch may
    approach it on the live-shaped fixture.
    """
    cache, live, settled = _cleanup_fixture()
    _install("acme", cache)
    worst = 0.0
    for i in range(COHORTS):
        t0 = time.perf_counter()
        main._carried_edges_for("acme", live, 1)
        worst = max(worst, (time.perf_counter() - t0) * 1000.0)
        if i < len(settled):
            main._remember_edges("acme", [_Snap(settled[i])])
    assert worst < main.CORR_SYNC_BUDGET_MS, (
        f"worst carry_edges stretch {worst:.1f} ms >= the "
        f"{main.CORR_SYNC_BUDGET_MS:.0f} ms sync budget")


# ── 3. ATTRIBUTION — every stretch this change instruments must NAME itself ──


@pytest.fixture
def _sites(monkeypatch):
    """Capture every `sync_span` site the code under test records."""
    seen: list[str] = []
    real = main.sync_record

    def spy(site: str, elapsed: float) -> None:
        seen.append(site)
        real(site, elapsed)

    monkeypatch.setattr(main, "sync_record", spy)
    return seen


def test_carry_edges_and_remember_edges_are_attributed(_sites):
    _install("acme", {("a", "b"): _Edge("a", "b")})
    main._carried_edges_for("acme", {"a", "b"}, 1)
    main._remember_edges("acme", [_Snap([_Edge("a", "b")])])
    assert "reconcile.carry_edges" in _sites, (
        "the per-tenant carried-edge filter is dark again — a block there can "
        "only surface as un-attributed loop lag (tracker 192)")
    assert "reconcile.remember_edges" in _sites


class _StubCH:
    async def insert_detailed(self, table, rows, dedup_token=""):
        return main.InsertOutcome(committed=True, kind="committed",
                                  rows=len(list(rows)))


def _load(n: int, tenant: str = "acme") -> None:
    for i in range(n):
        s = main.dc_replace(mk(i, i), tenant_id=tenant)
        main.WINDOW_BUFFER.append(s)
        main._BUFFERED_ID_ORDER.append(str(s.signal_id))
        main._BUFFERED_IDS.add(str(s.signal_id))


# Every loop-thread stretch on the epoch/cohort/re-key path that tracker 192
# found unspanned. The set is the assertion: a span deleted from main.py drops
# its name here and this test fails.
EPOCH_PATH_SITES = {
    "epoch.freeze",
    "epoch.enrichment",
    "epoch.tenant_context",
    "cohort.admit",
    "reconcile.cont_buckets",
}


def test_the_whole_epoch_and_cohort_path_is_attributed(monkeypatch, _sites):
    """Drive a real cycle and assert every previously-dark stretch names itself.

    This is the half of tracker 192 that is instrumentation rather than a bound:
    `corr_sync_stretch_max_ms` stayed at 443.5 ms through a 9,135 ms block
    because none of these had a span.
    """
    monkeypatch.setattr(main, "ch", _StubCH())
    monkeypatch.setattr(main, "OPEN_OBJECTS", {})
    _load(40)
    asyncio.run(main.engine_cycle())
    missing = EPOCH_PATH_SITES - set(_sites)
    assert not missing, f"loop-thread stretches with no sync_span: {sorted(missing)}"


def test_the_storm_priority_sort_is_attributed(monkeypatch, _sites):
    """The storm sort runs only under a DECLARED storm — i.e. only on the runs
    that stall — so it is exercised under a forced declaration."""
    monkeypatch.setattr(main, "ch", _StubCH())
    monkeypatch.setattr(main, "OPEN_OBJECTS", {})
    monkeypatch.setattr(main, "_STORM_ACTIVE", False)
    monkeypatch.setattr(main, "STORM_BUFFER_FRACTION", 0.0)
    monkeypatch.setattr(main, "STORM_EXIT_FRACTION", -0.1)
    _load(40)
    asyncio.run(main.engine_cycle())
    assert main.OPEN_OBJECTS, "the cycle produced no snapshots — nothing sorted"
    assert "reconcile.storm_sort" in _sites
