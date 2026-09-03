"""The lifecycle MERGE pass may never own the event-loop thread.

LIVE EVIDENCE — run storm-s02, 2026-08-29 20:01:09→20:01:44Z, replica-4, image
at HEAD: a **35,690 ms** event-loop stall (three more at 5–6 s). That is past
the 30 s Kafka session timeout, so the consumer was ejected twice — 106
`UnknownMemberId`, 2 `CommitFailed`. The stall began immediately after a
cohort's reconciliation lines ("corr-object … continued under re-keyed window"),
i.e. at the END of an epoch, and the stage profile had NO span covering it:
`engine.run_window` (26 s) runs on the executor, `persist.batch_flush` (28 s)
and `persist.decision` (15.9 s) are wall clock around an INSERT await, and
`handle.syslog` (34.5 s) was the consumer STARVED BY the stall, not its cause.

THE CAUSE, measured offline (see `bench_lifecycle_merge_storm.py`, and the
table in `engine.ContinuationIndex`): `find_merges`'s survivor index keyed its
two seam clauses on EV(x) = every seam the snapshot EMBEDS. `run_window` stamps
the WHOLE tenant seam inventory into EVERY snapshot, so EV(x) was identical for
every object and the "index" returned the entire population for every probe —
the exact O(survivors × candidates) cross-product it existed to remove, on the
loop thread. On the live storm shape (5,000 survivors × 2,500 candidates, one
seam per device) that is 12,500,000 pairs and **45,120 ms** on the loop; at 1,000
seams, 22,665 ms — the two rows that bracket the observed stall.

THE FIX, and what each part of it owes this file:

  * **the token index** (the root fix) — key the seam clauses on GROUNDED
    seams (GEV/TCH) rather than every embedded seam. `_seam_bridged` never
    consults a seam outside G(P) ∪ G(S), so this is the predicate's own
    precondition, not a heuristic. Tests: `test_oracle_*` (output identity vs
    an un-indexed cross-product, at every seam density),
    `test_index_prunes_the_storm_population`, and — with the offload turned OFF
    so the index is the only thing under test — the mutant pair
    `test_index_alone_holds_the_loop_bound` (13 ms) against
    `test_mutant_ev_index_breaches_the_loop_bound` (1,177 ms, i.e. RED past the
    500 ms budget). Both measured on this file's fixture.
  * **the offload** — past CORR_LIFECYCLE_MERGE_OFFLOAD_PAIRS the pure merge
    computation goes to the executor, so a population the index cannot save
    still cannot own the loop. Test: `test_offload_keeps_the_loop_alive_and_
    inline_does_not`, whose inline leg is the "drop the offload → red" witness.
  * **the chunking** — awaits between candidate groups. Test:
    `test_chunking_is_output_identical` over every chunk size.

The two mutants are deliberately INDEPENDENT: each is exercised with the other
disabled, because belt-and-braces protections that are only ever tested
together prove neither.

Plus the observability that would have NAMED this on the first read instead of
the fourth: `test_spans_*` and `test_metrics_*`.
"""
from __future__ import annotations

import asyncio
import dataclasses
import random
import time
from datetime import datetime, timedelta, timezone

import pytest

import main
import timing_gate
from catalog import builtin_catalog
from engine import (
    ContinuationIndex,
    EngineConfig,
    SeamView,
    _entity_ids,
    _snap_grounded_seam_ids,
    find_continuation,
    find_merges,
    run_window,
)
from signals import EntityType
from test_engine import sig
from test_find_merges_index_stage2 import brute_find_merges
from test_seam_affinity_fold import _cloud_snap, _net_snap

CAT = builtin_catalog()
CFG = EngineConfig()


# ── the storm-shaped population ──────────────────────────────────────────────

def _seam_inventory(n: int) -> tuple[SeamView, ...]:
    """One seam per device — the estate shape that made the index degenerate.

    Every device in the population is a seam ENDPOINT, so under the old EV
    keying every object matched every other object through the seam maps while
    NOTHING was actually seam-grounded (no object here holds an authoritative
    seam edge). That gap between "embeds the inventory" and "grounded on a
    seam" is the whole defect.
    """
    return tuple(
        SeamView(seam_id=f"seam-{i}", tenant_id="", seam_type="DX",
                 endpoints=(("member_edge", f"dev-{i}"),
                            ("provider_resource", f"dxcon-{i}/vif")))
        for i in range(n))


def _storm_population(n: int, devices: int, seams: tuple[SeamView, ...]):
    """`n` distinct open objects over `devices` devices, each embedding the
    whole `seams` inventory — genuine engine output, not hand-built snapshots.

    Objects are built without seams (cheap) and the inventory is attached
    afterwards, which is byte-identical to what run_window would have emitted:
    `seams=` is passed straight through to every ObjectSnapshot it constructs.
    """
    out: list = []
    i = 0
    while len(out) < n:
        d = f"dev-{i % devices}"
        out.extend(run_window(
            [sig("device_cpu_high", EntityType.DEVICE, d, offset_s=i * 0.5),
             sig("if_errors", EntityType.INTERFACE, f"{d}:Gi0/{i % 8}",
                 offset_s=i * 0.5 + 5)], CAT, (), CFG))
        i += 1
    uniq: dict = {}
    for s in out[:n]:
        uniq.setdefault(s.correlation_id, s)
    return [dataclasses.replace(s, seams=seams) for s in uniq.values()]


# Sized from measurement, not taste: at 1,200 survivors x 600 candidates the
# EV-keyed mutant takes 1,177 ms on the loop (RED against the 500 ms budget)
# while the fix takes 13 ms — a 90x margin, so neither assertion is marginal on
# a slow CI runner. Building it costs ~3 s, once, module-scoped.
POP, DEVICES, SEAMS = 1800, 500, 500
# …and the cap the EV mutant may be grown to when a machine is fast enough to
# finish the cross-product inside the budget (timing_gate.py). The mutant is
# quadratic in POP and every other test here is linear in it, so this axis buys
# the witness a lot of stall for a little fixture: measured on the 4-core lab
# box, POP 1,800 → 2,671 ms and POP 3,000 → 5,502 ms on the loop, while the
# grounded index stayed at 65 ms and 86 ms. The 1,177 ms in the header was
# measured on a different box, which is exactly the point.
POP_MAX = 3_600
# The bound this file exists to defend. Well under the 30 s Kafka session
# timeout that storm-s02 breached, so a breach is caught long before ejection.
LOOP_BUDGET_S = 0.5


def _storm_pair(pop: int):
    """(survivors, candidates) in the live gauges' proportion — 2:1, every
    object embedding a seam inventory that makes every device an endpoint."""
    population = _storm_population(pop, DEVICES, _seam_inventory(SEAMS))
    rng = random.Random(20260829)
    rng.shuffle(population)
    cut = (len(population) * 2) // 3
    return population[:cut], population[cut:]


@pytest.fixture(scope="module")
def storm():
    """The live-shaped population, built once for the whole module."""
    return _storm_pair(POP)


# ── the EV-keyed index: the shipped shape, kept as an executable witness ─────

class _EVKeyedIndex:
    """The index as it was BEFORE the fix — seam clauses keyed on every seam
    the snapshot embeds. Reproduced here (not imported) so the fix cannot
    quietly delete its own witness."""

    def __init__(self, snaps) -> None:
        self._snaps = tuple(snaps)
        self.candidates_returned = 0     # same interface as the real index
        self._by_entity: dict[str, list[int]] = {}
        self._by_ref: dict[str, list[int]] = {}
        self._by_ev: dict[str, list[int]] = {}
        for i, s in enumerate(self._snaps):
            for e in _entity_ids(s):
                self._by_entity.setdefault(e, []).append(i)
            for r in ContinuationIndex._refs(s):
                self._by_ref.setdefault(r, []).append(i)
            for x in self._ev(s):
                self._by_ev.setdefault(x, []).append(i)

    @staticmethod
    def _ev(snap) -> frozenset[str]:
        out: set[str] = set()
        for v in snap.seams:
            out |= v.endpoint_values()
            out.add(v.seam_id)
        return frozenset(out)

    def candidates(self, snap):
        hits: set[int] = set()
        for e in _entity_ids(snap):
            hits.update(self._by_entity.get(e, ()))
        for x in self._ev(snap):
            hits.update(self._by_ref.get(x, ()))
        for r in ContinuationIndex._refs(snap):
            hits.update(self._by_ev.get(r, ()))
        out = tuple(self._snaps[i] for i in sorted(hits))
        self.candidates_returned += len(out)
        return out


# ── output identity: the index may only shrink what is EXAMINED ─────────────

def test_oracle_storm_merges_match_brute_force(storm):
    """The contract. On the seam-dense storm shape the indexed find_merges must
    return the byte-identical pair list an un-indexed cross-product returns."""
    survivors, candidates = storm
    assert find_merges(survivors, candidates) == brute_find_merges(
        survivors, candidates)


@pytest.mark.parametrize("seams", [0, 1, 5, 200])
def test_oracle_holds_at_every_seam_density(seams):
    """Seam density changed the PAIR COUNT by 3,541x and must change the
    RESULT by nothing — at zero seams, one seam, and a seam per device."""
    pop = _storm_population(180, 40, _seam_inventory(seams))
    rng = random.Random(7)
    rng.shuffle(pop)
    survivors, candidates = pop[:120], pop[120:]
    assert find_merges(survivors, candidates) == brute_find_merges(
        survivors, candidates)


def test_oracle_seam_bridged_pair_still_merges_inside_a_decoy_inventory():
    """The tracker-154b blocker case, now buried in a 200-seam inventory.

    The cloud half and the network half of one interconnect incident share ZERO
    entities — they share only the GROUNDED seam. Tightening the index onto
    grounded seams must not lose them, and the decoy seams (which neither side
    grounded on) must not be what finds them."""
    net, cloud = _net_snap(), _cloud_snap(5)
    assert not (_entity_ids(net) & _entity_ids(cloud)), "premise: disjoint entities"
    assert _snap_grounded_seam_ids(net) or _snap_grounded_seam_ids(cloud), (
        "premise: at least one side grounds the bridging seam")
    decoys = _seam_inventory(200)
    net_d = dataclasses.replace(net, seams=tuple(net.seams) + decoys)
    cloud_d = dataclasses.replace(cloud, seams=tuple(cloud.seams) + decoys)

    assert ContinuationIndex([net_d]).candidates(cloud_d) == (net_d,)
    assert find_merges([net_d], [cloud_d]) == [
        (cloud_d.correlation_id, net_d.correlation_id)]
    # …and its twin on the reconciliation path, which shares the index.
    assert find_continuation(
        cloud_d, ContinuationIndex([net_d]).candidates(cloud_d)
    ) == net_d.correlation_id


def test_index_and_entity_cache_are_pure_performance_inputs(storm):
    """`index=` and `entity_cache=` must change scheduling, never results."""
    survivors, candidates = storm
    plain = find_merges(survivors, candidates)
    shared = ContinuationIndex(survivors)
    cache: dict = {}
    assert find_merges(survivors, candidates, index=shared,
                       entity_cache=cache) == plain
    # A REUSED index and a warm cache must still give the same answer.
    assert find_merges(survivors, candidates, index=shared,
                       entity_cache=cache) == plain


# ── the prune is real, and the old keying is the witness that it matters ────

def test_index_prunes_the_storm_population(storm):
    """Pairs examined must be a small fraction of survivors x candidates."""
    survivors, candidates = storm
    idx = ContinuationIndex(survivors)
    for c in candidates:
        idx.candidates(c)
    full = len(survivors) * len(candidates)
    assert idx.candidates_returned < full / 20, (
        f"index examined {idx.candidates_returned} of {full} possible pairs — "
        "that is not a filter, it is the cross-product wearing an index's name")


def test_mutant_ev_keyed_index_returns_the_cross_product(storm):
    """THE WITNESS. Restore the old EV keying and the very same population
    explodes to (near) every pair — silently, with identical merge output.

    This is why the bug shipped and why the pair-count metric exists: the
    results never changed, only the cost. Drop the grounded restriction and
    `test_lifecycle_merge_never_blocks_the_loop` goes red while every oracle in
    this file stays green.
    """
    survivors, candidates = storm
    tight = ContinuationIndex(survivors)
    loose = _EVKeyedIndex(survivors)
    tight_pairs = sum(len(tight.candidates(c)) for c in candidates)
    loose_pairs = sum(len(loose.candidates(c)) for c in candidates)
    full = len(survivors) * len(candidates)
    assert loose_pairs > full * 0.9, (
        "the fixture no longer reproduces the degeneration — the witness "
        "proves nothing; restore an inventory whose endpoints are the devices")
    assert loose_pairs > tight_pairs * 20, (
        f"EV keying examined {loose_pairs} pairs, grounded keying "
        f"{tight_pairs} — the tightening is not load-bearing here")
    # …and the results were IDENTICAL all along, which is exactly the trap.
    assert find_merges(survivors, candidates, index=tight) == find_merges(
        survivors, candidates, index=loose)


# ── the loop-thread bound ────────────────────────────────────────────────────

async def _worst_lag_while(work, interval: float = 0.02) -> tuple[float, float]:
    """Run `work()` while a ticker measures loop scheduling delay — the same
    stand-in for aiokafka's heartbeat task that test_loop_blocking.py uses."""
    worst = 0.0
    stop = asyncio.Event()

    async def ticker():
        nonlocal worst
        while not stop.is_set():
            t0 = time.monotonic()
            await asyncio.sleep(interval)
            worst = max(worst, time.monotonic() - t0 - interval)

    t = asyncio.create_task(ticker())
    await asyncio.sleep(interval * 4)      # ticker running BEFORE we block
    t0 = time.monotonic()
    await work()
    dur = time.monotonic() - t0
    stop.set()
    await t
    return worst, dur


def _merge_lag(storm) -> tuple[float, float]:
    survivors, candidates = storm
    return asyncio.run(_worst_lag_while(
        lambda: main._lifecycle_find_merges(
            list(survivors), list(candidates), main._make_loop_yield()[0])))


def test_lifecycle_merge_never_blocks_the_loop(storm):
    """THE BOUND the 35,690 ms stall breached, under the SHIPPED configuration:
    the whole merge computation over a storm-shaped population must not hold
    the loop thread. Absolute, not a ratio — 500 ms is the number that matters
    against a 30 s session timeout."""
    lag, dur = _merge_lag(storm)
    assert lag < LOOP_BUDGET_S, (
        f"merge pass held the loop for {lag*1000:.0f} ms (work took "
        f"{dur*1000:.0f} ms) — the storm-s02 failure mode")


def test_index_alone_holds_the_loop_bound(storm, monkeypatch):
    """The ROOT fix, isolated: with the offload DISABLED the merge runs entirely
    on the loop thread, and the grounded-seam index alone keeps it inside the
    budget. This is what makes the next test a witness rather than a tautology."""
    monkeypatch.setattr(main, "CORR_LIFECYCLE_MERGE_OFFLOAD_PAIRS", 0)
    lag, dur = _merge_lag(storm)
    assert lag < LOOP_BUDGET_S, (
        f"on-loop merge stalled {lag*1000:.0f} ms (work {dur*1000:.0f} ms)")


def test_mutant_ev_index_breaches_the_loop_bound(storm, monkeypatch):
    """THE WITNESS. Put the old EV keying back, with the offload still off, and
    the identical population blows through the budget — which is precisely what
    it did in production. Drop the grounded restriction and this goes red while
    every oracle in this file stays green, because the RESULTS never changed.

    THE POPULATION IS SIZED TO THE MACHINE (timing_gate.py): "grow the fixture"
    used to be advice in a failure message, and hand-sizing a wall-clock witness
    is what put two sibling gates red on a hosted runner on 2026-09-03. The
    budget the bound tests assert against is untouched — only the size of the
    cross-product this witness has to chew through."""
    monkeypatch.setattr(main, "CORR_LIFECYCLE_MERGE_OFFLOAD_PAIRS", 0)
    monkeypatch.setattr(main, "ContinuationIndex", _EVKeyedIndex)
    built = {POP: storm}
    work: dict[int, float] = {}

    def grind(pop: int) -> float:
        if pop not in built:
            built[pop] = _storm_pair(pop)
        lag, dur = _merge_lag(built[pop])
        work[pop] = dur
        return lag

    gate = timing_gate.calibrated_stall(
        grind, size=POP, floor=LOOP_BUDGET_S, max_size=POP_MAX, unit="s",
        name="EV-keyed merge index on the loop thread")
    assert gate.ok and work[gate.size] > LOOP_BUDGET_S, (
        f"the EV-keyed mutant only stalled {gate.value*1000:.0f} ms (work "
        f"{work[gate.size]*1000:.0f} ms) — it is not reproducing the "
        f"regression, so test_index_alone_holds_the_loop_bound proves nothing "
        f"({gate.report()})")


def test_offload_keeps_the_loop_alive_and_inline_does_not():
    """The OFFLOAD half, isolated from how fast the index happens to be.

    A deliberately slow (still pure) merge computation stands in for a
    population the index cannot save. Offloaded, the loop keeps ticking;
    inline — the "drop the offload" mutant — the stall IS the work, because the
    loop thread is the thing doing it.
    """
    hold = 0.6
    snaps = _storm_population(4, 2, ())
    survivors, candidates = snaps[:2], snaps[2:]

    def slow(*_a, **_kw):
        time.sleep(hold)               # a pure-CPU stand-in, on whichever thread
        return []

    async def run(threshold):
        main.find_merges = slow
        try:
            return await _worst_lag_while(lambda: main._lifecycle_find_merges(
                survivors, candidates, main._make_loop_yield()[0]))
        finally:
            main.find_merges = find_merges

    real_thresh = main.CORR_LIFECYCLE_MERGE_OFFLOAD_PAIRS
    try:
        main.CORR_LIFECYCLE_MERGE_OFFLOAD_PAIRS = 1        # always offload
        off_lag, off_dur = asyncio.run(run(1))
        main.CORR_LIFECYCLE_MERGE_OFFLOAD_PAIRS = 0        # never offload
        in_lag, in_dur = asyncio.run(run(0))
    finally:
        main.CORR_LIFECYCLE_MERGE_OFFLOAD_PAIRS = real_thresh

    assert off_dur >= hold and in_dur >= hold, "both legs must do the same work"
    assert off_lag < hold / 4, (
        f"offloaded merge still stalled the loop {off_lag*1000:.0f} ms")
    assert in_lag > hold / 2, (
        f"the inline control only stalled {in_lag*1000:.0f} ms — it is not "
        "reproducing the regression, so the offload assertion proves nothing")


@pytest.mark.parametrize("chunk", [0, 1, 7, 500])
def test_chunking_is_output_identical(storm, chunk):
    """Chunk size is a scheduling knob. Every candidate picks its own best
    survivor over the SAME survivor set, so splitting the candidate list and
    re-sorting must reproduce a single call exactly."""
    survivors, candidates = storm
    expected = find_merges(survivors, candidates)
    real = main.CORR_LIFECYCLE_MERGE_CHUNK
    try:
        main.CORR_LIFECYCLE_MERGE_CHUNK = chunk
        got = asyncio.run(main._lifecycle_find_merges(
            list(survivors), list(candidates), main._make_loop_yield()[0]))
    finally:
        main.CORR_LIFECYCLE_MERGE_CHUNK = real
    assert got == expected


def test_empty_sides_short_circuit():
    """No survivors or no candidates ⇒ no index build, no offload, no pairs."""
    snaps = _storm_population(2, 2, ())
    assert asyncio.run(main._lifecycle_find_merges(
        [], snaps, main._make_loop_yield()[0])) == []
    assert asyncio.run(main._lifecycle_find_merges(
        snaps, [], main._make_loop_yield()[0])) == []


# ── observability: no loop-thread stage may be invisible again ──────────────

def _run_lifecycle_pass(monkeypatch, survivors, candidates):
    """One `_epoch_lifecycle` over a real OPEN_OBJECTS registry."""
    now = datetime.now(timezone.utc)
    objects = {}
    for s in list(survivors) + list(candidates):
        objects[s.correlation_id] = {
            "version": 1, "hash": "h", "material": "m", "last_seen": now,
            "last_persist": now, "snapshot": s, "opened_at": now,
            "last_version": now}
    monkeypatch.setattr(main, "OPEN_OBJECTS", objects)
    monkeypatch.setattr(main, "_EVIDENCE_QUEUE", None)
    monkeypatch.setattr(main, "CORR_QUIESCE_S", 10_000_000.0)
    monkeypatch.setattr(main, "CORR_OPEN_OBJECTS_MAX", 1)  # force the cap pass

    async def _noop_persist(*_a, **_kw):
        return None

    monkeypatch.setattr(main, "_persist_snapshot", _noop_persist)

    seen = {s.correlation_id for s in survivors}

    class _Epoch:
        def __init__(self) -> None:
            self.seen = set(seen)
            self.now = now + timedelta(seconds=1)

    asyncio.run(main._epoch_lifecycle(_Epoch(), main._make_loop_yield()[0],
                                      seen=set(seen)))


def test_spans_cover_every_lifecycle_stage(monkeypatch, storm):
    """`lifecycle.merge`, `lifecycle.quiesce` and `lifecycle.cap` must all
    appear. The storm-s02 profile had none of them, which is why a 35 s stall
    could sit inside a pass with nothing to point at."""
    survivors, candidates = storm
    monkeypatch.setattr(main, "CORR_PROFILE_STAGES", True)
    monkeypatch.setattr(main, "_STAGE_STATS", {})
    monkeypatch.setattr(main, "_STAGE_SAMPLES", {})
    _run_lifecycle_pass(monkeypatch, survivors[:40], candidates[:20])
    stages = set(main.stage_profile()["stages"])
    for name in ("lifecycle.merge", "lifecycle.quiesce", "lifecycle.cap"):
        assert name in stages, f"{name} has no span — {sorted(stages)}"


def test_reconcile_spans_cover_the_cohort_path(monkeypatch):
    """The reconciliation path's two loop-thread stretches — the per-cohort
    continuation-index build and the snapshot loop — must be named too. Driven
    through a REAL `engine_cycle`, not pinned textually: a span that is only
    asserted to exist in the source is not an observable."""
    import test_loop_yield_resilience as Y

    monkeypatch.setattr(main, "CORR_PROFILE_STAGES", True)
    monkeypatch.setattr(main, "_STAGE_STATS", {})
    monkeypatch.setattr(main, "_STAGE_SAMPLES", {})
    monkeypatch.setattr(main, "OPEN_OBJECTS", {})
    monkeypatch.setattr(main, "CORR_ENGINE_COHORT_SIZE", 40_000)
    monkeypatch.setattr(main, "ch", Y._StubCH())
    Y._load(50)
    try:
        asyncio.run(main.engine_cycle())
    finally:
        Y._load(0)                      # leave the shared buffers clean
    stages = set(main.stage_profile()["stages"])
    for name in ("reconcile.continuation_index", "reconcile.loop"):
        assert name in stages, f"{name} has no span — {sorted(stages)}"


def test_metrics_expose_pairs_and_seconds(monkeypatch, storm):
    """`corr_lifecycle_merge_pairs_evaluated_total` and `_seconds_max` are the
    two numbers that name a degeneration before it becomes a rebalance."""
    survivors, candidates = storm
    monkeypatch.setattr(main, "LIFECYCLE_MERGE_PAIRS_EVALUATED_TOTAL", 0)
    monkeypatch.setattr(main, "LIFECYCLE_MERGE_SECONDS_MAX", 0.0)
    monkeypatch.setattr(main, "LIFECYCLE_MERGE_OFFLOADS_TOTAL", 0)
    _run_lifecycle_pass(monkeypatch, survivors[:40], candidates[:20])

    assert main.LIFECYCLE_MERGE_PAIRS_EVALUATED_TOTAL > 0
    assert main.LIFECYCLE_MERGE_SECONDS_MAX > 0.0
    body = main._metrics_text()
    for name in ("corr_lifecycle_merge_pairs_evaluated_total",
                 "corr_lifecycle_merge_seconds_max",
                 "corr_lifecycle_merge_offloads_total"):
        assert name in body, f"{name} missing from /metrics"
    state = main.epoch_state()
    for key in ("lifecycle_merge_pairs_evaluated_total",
                "lifecycle_merge_seconds_max",
                "lifecycle_merge_offloads_total"):
        assert key in state, f"{key} missing from epoch_state()"


def test_offload_threshold_is_respected(monkeypatch, storm):
    """Below the threshold the pass stays inline; above it, it offloads. The
    counter is what tells an operator which happened."""
    survivors, candidates = storm
    monkeypatch.setattr(main, "LIFECYCLE_MERGE_OFFLOADS_TOTAL", 0)
    monkeypatch.setattr(main, "CORR_LIFECYCLE_MERGE_OFFLOAD_PAIRS",
                        len(survivors) * len(candidates) + 1)
    asyncio.run(main._lifecycle_find_merges(
        list(survivors), list(candidates), main._make_loop_yield()[0]))
    assert main.LIFECYCLE_MERGE_OFFLOADS_TOTAL == 0

    monkeypatch.setattr(main, "CORR_LIFECYCLE_MERGE_OFFLOAD_PAIRS",
                        len(survivors) * len(candidates))
    asyncio.run(main._lifecycle_find_merges(
        list(survivors), list(candidates), main._make_loop_yield()[0]))
    assert main.LIFECYCLE_MERGE_OFFLOADS_TOTAL == 1
