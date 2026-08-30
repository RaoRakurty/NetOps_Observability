"""No SYNCHRONOUS stretch of the lifecycle/reconcile path may own the loop.

LIVE EVIDENCE — run storm-s03 (t-storm-2.5k, replica-3, image at HEAD with the
tracker-185 part-2 lifecycle index fix): the 35 s merge stall was gone, but two
stalls of 26.0 s and 26.8 s at 22:2x UTC ejected the consumer. The stage
profile's `lifecycle.quiesce` max was 26,024 ms — an almost exact match, and it
was read as the cause.

IT IS NOT THE SAME QUANTITY, and that is the finding this file is built on.
Every span in the profile is WALL CLOCK and encloses awaits. Measured offline on
the storm shape (1,300 open objects, 400 simultaneous closes, real
`_persist_snapshot`, a ClickHouse stub that never suspends — i.e. adversarially
awaitless):

    lifecycle.quiesce (wall)                 1,400-2,000 ms for 400 closes
    worst UNINTERRUPTED loop-thread stretch     55-70 ms
    worst per-builder inline block            <= 15 ms

Scale the per-object cost to the live population and the 26 s wall figure falls
straight out of ~400 closes at ~65 ms each — a pass that is LONG, not a loop
that is HELD. So the two numbers the next investigation needs are the ones the
profile could not give it, and `sync_record` now does: `corr_sync_stretch_max_ms`
(worst block with no await in it) and `corr_sync_overruns_total`.

WHAT THIS FILE PINS:

  1. THE BOUND — a storm-shaped close batch, driven through the real
     `_epoch_lifecycle`, never holds the event-loop thread past
     CORR_SYNC_BUDGET_MS (500 ms), however many objects quiesce at once. The
     MUTANT (`CORR_LOOP_YIELD_MS` set past reach, i.e. the cooperative yield
     removed) breaches it, so the assertion has teeth.
  2. IDENTITY — the yields and the rate-projected offload are SCHEDULING. The
     same population produces byte-identical closes, merges, rows and counters
     with both on and both off.
  3. THE RATE GATE — an object UNDER the element threshold whose builder costs
     more than the budget is offloaded anyway, which is the half of the bound a
     count of elements cannot provide.
  4. THE OBSERVABLE — every loop-thread block in these regions has a `sync.*`
     span, so a stall can never again be inferred from a wall-clock span.
"""
from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import hashlib
import json
import logging
import random
import time
from datetime import datetime, timedelta, timezone

import pytest

import main
from catalog import builtin_catalog
from engine import run_window
from signals import EntityType, Severity
from test_engine import sig as engine_sig
from test_find_merges_index_stage2 import _mixed_population

# The bound, shared with test_lifecycle_merge_storm_p1: an order of magnitude
# under the 1,000 ms loop-lag warn and two under the session timeout, so a
# breach is a defect long before it is an ejection.
BUDGET_S = 0.5
# The storm shape the live run had: ~1,300 open objects, ~400 of them stale in
# one pass. `OPEN` is deliberately above the live peak (1,362 open objects) and
# `STALE` is the batch that closes together.
OPEN, STALE = 1_300, 400
# Signals per closing object. Sized from measurement, not taste: at 240 signals
# one close costs ~4 ms, so the mutant's un-yielded grind is ~1.6 s — three
# times the budget, not a marginal call on a slow CI runner — while the bounded
# leg's worst stretch stays at ~70 ms, a 7x margin the other way. Neither
# assertion is close to its threshold.
STALE_SIGNALS = 240
# A budget past any wall clock the pass can reach: the deadline is never met,
# so `loop_yield` never yields and the loop behaves exactly as it did before the
# cooperative gate existed. This is the BEFORE baseline.
_YIELD_DISABLED_MS = 10 ** 9


class _StubCH:
    """Records inserts with NO await that can suspend — so the only thing that
    can reschedule the loop during the close batch is the engine's own yield.
    A real ClickHouse insert awaits a socket and would mask the defect."""

    def __init__(self) -> None:
        self.rows: dict[str, list[dict]] = {}

    async def insert(self, table: str, rows, **_kw) -> bool:
        self.rows.setdefault(table, []).extend(dict(r) for r in rows)
        return True


# ── the population ───────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def _proto():
    """One real engine snapshot to clone. Built through `run_window` so the
    shape under test is genuine engine output, not a hand-rolled dataclass."""
    return run_window(
        [engine_sig("link_state_change", EntityType.DEVICE, "dev0",
                    severity=Severity.CRIT),
         engine_sig("device_resource_anomaly", EntityType.DEVICE, "dev0",
                    severity=Severity.CRIT, offset_s=1)],
        builtin_catalog(), ())[0]


def _objects(proto, n: int, signals: int, *, prefix: str, nodes: int = 4):
    """`n` distinct snapshots carrying `signals` signals over `nodes` nodes —
    the storm shape: the mass is in node signals, not in edges."""
    base_node = proto.nodes[0]
    per_node = max(1, signals // nodes)
    out = []
    for o in range(n):
        built = []
        for i in range(nodes):
            sigs = tuple(
                engine_sig("link_state_change", EntityType.DEVICE,
                           f"{prefix}{o}n{i}", severity=Severity.WARN,
                           offset_s=j * 0.25 + i * 0.001)
                for j in range(per_node))
            built.append(dataclasses.replace(
                base_node, key=f"device:{prefix}{o}n{i}:link_state_change",
                entity_id=f"{prefix}{o}n{i}", signals=sigs, onset=sigs[0].ts,
                peak_severity=Severity.WARN, occurrences=per_node))
        out.append(dataclasses.replace(
            proto, correlation_id=f"a1b2c3d4-0000-0000-{prefix}-{o:012d}"[:36],
            nodes=tuple(built), edges=()))
    return out


@pytest.fixture(scope="module")
def storm_close_batch(_proto):
    """(stale, live) — `STALE` objects that will quiesce this pass and the rest
    of the open population, which must not."""
    stale = _objects(_proto, STALE, STALE_SIGNALS, prefix="c", nodes=6)
    live = _objects(_proto, OPEN - STALE, 4, prefix="l", nodes=2)
    return stale, live


def _drop_memos(snaps) -> None:
    """`content_hash` / `material_hash` memoize on the frozen snapshot, so a
    second leg over a module-scoped population would measure a cache hit rather
    than the serialize the bound is about. Every leg pays the same work."""
    for s in snaps:
        for attr in ("_content_hash_c", "_material_hash_c"):
            with contextlib.suppress(AttributeError):
                object.__delattr__(s, attr)


class _Epoch:
    """The two attributes `_epoch_lifecycle` reads off an epoch."""

    def __init__(self, seen: set[str], now: datetime) -> None:
        self.seen = set(seen)
        self.now = now


@pytest.fixture(autouse=True)
def _isolated(monkeypatch):
    """Clean engine + clean sync accounting for every test: the rate table and
    the overrun counters are process-wide by design (they are the §10 safety
    observable), so a test that inherits another's must not exist."""
    monkeypatch.setattr(main, "OPEN_OBJECTS", {})
    monkeypatch.setattr(main, "_EVIDENCE_QUEUE", None)
    monkeypatch.setattr(main, "SYNC_STRETCH_MAX_MS", 0.0)
    monkeypatch.setattr(main, "SYNC_STRETCH_MAX_SITE", "")
    monkeypatch.setattr(main, "SYNC_OVERRUNS_TOTAL", 0)
    monkeypatch.setattr(main, "_SYNC_RATE", {})
    monkeypatch.setattr(main, "CORR_LOOP_YIELD_MS", 50.0)
    monkeypatch.setattr(main, "CORR_SYNC_BUDGET_MS", BUDGET_S * 1000.0)
    monkeypatch.setattr(main, "CORR_SYNC_OFFLOAD", True)
    main._ARCHIVE_SLICE_HASH.clear()
    lvl = main.log.level
    main.log.setLevel(logging.WARNING)   # per-object INFO would dwarf the grind
    yield
    main.log.setLevel(lvl)
    main._ARCHIVE_SLICE_HASH.clear()


# ── the instrument ───────────────────────────────────────────────────────────

async def _worst_stretch_while(coro):
    """Run `coro` while a `sleep(0)` spinner measures the longest it is ever
    kept off the loop. A `sleep(0)` task is re-queued every pass, so the gap
    between two of its resumptions IS the time the loop spent running something
    else without yielding — the quantity aiokafka's heartbeat competes for.

    Returned alongside a 10 ms ticker (the heartbeat proxy) because they answer
    different questions: the spinner bounds one uninterrupted stretch, the
    ticker says what a periodic task actually experiences.
    """
    worst_sync = 0.0
    worst_tick = 0.0
    stop = asyncio.Event()

    async def spin():
        nonlocal worst_sync
        while not stop.is_set():
            t0 = time.monotonic()
            await asyncio.sleep(0)
            worst_sync = max(worst_sync, time.monotonic() - t0)

    async def tick():
        nonlocal worst_tick
        while not stop.is_set():
            t0 = time.monotonic()
            await asyncio.sleep(0.01)
            worst_tick = max(worst_tick, time.monotonic() - t0 - 0.01)

    tasks = [asyncio.create_task(spin()), asyncio.create_task(tick())]
    await asyncio.sleep(0.05)            # both must be running BEFORE the grind
    t0 = time.monotonic()
    await coro
    dur = time.monotonic() - t0
    stop.set()
    for t in tasks:
        await t
    return worst_sync, worst_tick, dur


def _run_close_batch(stale, live, *, yield_ms: float, rate_gate: bool = True):
    """One real `_epoch_lifecycle` over a storm-shaped registry, with the REAL
    `_persist_snapshot` (the earlier lifecycle tests stub it out, which is
    exactly why the per-object builders were never in the measurement)."""
    now = datetime.now(timezone.utc)
    registry: dict[str, dict] = {}
    for s in stale:
        registry[s.correlation_id] = {
            "version": 1, "hash": "h", "material": "m",
            "last_seen": now - timedelta(seconds=10_000), "last_persist": now,
            "snapshot": s, "opened_at": now, "last_version": now}
    for s in live:
        registry[s.correlation_id] = {
            "version": 1, "hash": "h", "material": "m", "last_seen": now,
            "last_persist": now, "snapshot": s, "opened_at": now,
            "last_version": now}
    _drop_memos(list(stale) + list(live))
    ch = _StubCH()
    main.ch = ch
    main.OPEN_OBJECTS = registry
    main.CORR_LOOP_YIELD_MS = yield_ms
    main.CORR_SYNC_OFFLOAD = rate_gate
    main.CORR_QUIESCE_S = 300.0
    main.CORR_OPEN_OBJECTS_MAX = 0         # cap off: isolate the close batch
    main.VERSIONS_PERSISTED = 0
    main._SYNC_RATE = {}
    main._ARCHIVE_SLICE_HASH.clear()
    seen = {s.correlation_id for s in live}
    epoch = _Epoch(seen, now)

    async def go():
        return await _worst_stretch_while(
            main._epoch_lifecycle(epoch, main._make_loop_yield()[0],
                                  seen=set(seen)))

    worst_sync, worst_tick, dur = asyncio.run(go())
    return worst_sync, worst_tick, dur, ch, registry


# ── 1. the bound ─────────────────────────────────────────────────────────────

def test_storm_close_batch_never_holds_the_loop_past_the_budget(storm_close_batch):
    """400 objects quiescing in ONE pass out of 1,300 open, with an awaitless
    ClickHouse: no single stretch may reach the 500 ms budget, and the engine's
    own sync accounting must agree with the external spinner."""
    stale, live = storm_close_batch
    worst, tick, dur, _ch, _registry = _run_close_batch(
        stale, live, yield_ms=50.0)

    # Teeth: the batch has to be a real one, or the bound proves nothing.
    assert len(main.OPEN_OBJECTS) == OPEN - STALE, (
        f"the close batch did not close {STALE} objects "
        f"({OPEN - len(main.OPEN_OBJECTS)} closed)")
    assert dur > 0.4, (
        f"the pass took only {dur*1000:.0f} ms — too short to bound anything")

    assert worst < BUDGET_S, (
        f"a storm close batch held the event-loop thread for {worst*1000:.0f} ms "
        f"(budget {BUDGET_S*1000:.0f} ms) — the per-object yield is not "
        f"bounding the grind")
    assert main.SYNC_OVERRUNS_TOTAL == 0, (
        f"the engine counted {main.SYNC_OVERRUNS_TOTAL} over-budget loop-thread "
        f"blocks (worst {main.SYNC_STRETCH_MAX_MS:.0f} ms at "
        f"{main.SYNC_STRETCH_MAX_SITE})")
    # The heartbeat proxy is the reason the bound exists at all.
    assert tick < BUDGET_S, (
        f"a 10 ms periodic task was starved {tick*1000:.0f} ms — aiokafka's "
        f"heartbeat runs on exactly this budget")


def test_mutant_without_the_yield_budget_breaches_the_bound(storm_close_batch):
    """Remove the cooperative yield (budget past reach) and the SAME batch
    holds the loop for the whole grind. Without this the bound above could pass
    on a workload that was simply too small."""
    stale, live = storm_close_batch
    worst, _tick, dur, _ch, _reg = _run_close_batch(
        stale, live, yield_ms=_YIELD_DISABLED_MS)
    assert len(main.OPEN_OBJECTS) == OPEN - STALE
    assert worst >= BUDGET_S, (
        f"the mutant only stalled {worst*1000:.0f} ms — it is not reproducing "
        f"the defect, so the bound assertion proves nothing (pass took "
        f"{dur*1000:.0f} ms)")


# ── 2. identity: the yields and the rate gate are scheduling ────────────────

def _digest(ch: _StubCH, registry: dict) -> str:
    """Everything the close batch decided: the rows it wrote, the objects it
    left open (with their versions) and the version counter."""
    rows = {t: sorted(json.dumps(r, sort_keys=True, default=str) for r in rs)
            for t, rs in ch.rows.items()}
    left = {cid: reg["version"] for cid, reg in sorted(registry.items())}
    blob = json.dumps([rows, left, main.VERSIONS_PERSISTED],
                      sort_keys=True, default=str)
    return hashlib.sha256(blob.encode()).hexdigest()


def test_closes_are_byte_identical_with_and_without_the_scheduling_fixes(
        storm_close_batch):
    """The yields interleave scheduling and the rate gate moves a pure function
    to another thread. Neither may change a byte: same rows, same terminal
    versions, same survivors, same counters."""
    stale, live = storm_close_batch
    _w, _t, _d, ch_on, reg_on = _run_close_batch(
        stale, live, yield_ms=50.0, rate_gate=True)
    on = _digest(ch_on, reg_on)
    _w, _t, _d, ch_off, reg_off = _run_close_batch(
        stale, live, yield_ms=_YIELD_DISABLED_MS, rate_gate=False)
    off = _digest(ch_off, reg_off)
    assert on == off, (
        f"the scheduling fixes changed the close batch's output — "
        f"determinism/replay broken (on={on[:16]} off={off[:16]})")
    # …and the comparison must not be vacuous.
    assert ch_on.rows.get("netops.corr_objects"), "no terminal rows were written"
    assert len(ch_on.rows["netops.corr_objects"]) == STALE


@pytest.fixture(scope="module")
def merge_population():
    """A population where the merge pass actually folds pairs: overlapping
    device sets over a small pool, plus the seam-bridged DX pair — the same
    builder the find_merges equivalence oracle uses, so what is merged here is
    what that file proves correct."""
    rng = random.Random(20260829)
    return _mixed_population(rng, n_surv=120, n_stale=160, pool_size=8)


def _run_merge_pass(survivors, candidates, *, yield_ms: float, rate_gate: bool):
    now = datetime.now(timezone.utc)
    registry = {
        s.correlation_id: {"version": 1, "hash": "h", "material": "m",
                           "last_seen": now, "last_persist": now,
                           "snapshot": s, "opened_at": now, "last_version": now}
        for s in list(survivors) + list(candidates)}
    _drop_memos(list(survivors) + list(candidates))
    ch = _StubCH()
    main.ch = ch
    main.OPEN_OBJECTS = registry
    main.CORR_LOOP_YIELD_MS = yield_ms
    main.CORR_SYNC_OFFLOAD = rate_gate
    main.CORR_QUIESCE_S = 10_000_000.0      # quiesce off: isolate the merges
    main.CORR_OPEN_OBJECTS_MAX = 0
    main.VERSIONS_PERSISTED = 0
    main._SYNC_RATE = {}
    main._ARCHIVE_SLICE_HASH.clear()
    seen = {s.correlation_id for s in survivors}
    asyncio.run(main._epoch_lifecycle(_Epoch(seen, now),
                                      main._make_loop_yield()[0], seen=set(seen)))
    return ch, registry


def test_merges_are_byte_identical_with_and_without_the_scheduling_fixes(
        merge_population):
    """Same proof for the merge half: the tombstone versions, their rows and
    which cid survived are unchanged by when the loop reschedules."""
    survivors, candidates = merge_population
    ch_on, reg_on = _run_merge_pass(survivors, candidates,
                                    yield_ms=50.0, rate_gate=True)
    merged_on = main.VERSIONS_PERSISTED
    on = _digest(ch_on, reg_on)
    ch_off, reg_off = _run_merge_pass(survivors, candidates,
                                      yield_ms=_YIELD_DISABLED_MS, rate_gate=False)
    off = _digest(ch_off, reg_off)
    assert merged_on > 0, "the merge pass found no pairs — the test is vacuous"
    assert on == off, (
        f"the scheduling fixes changed the merge pass's output "
        f"(on={on[:16]} off={off[:16]})")


# ── 3. the rate gate: elements are a proxy for time only while cost is flat ──

def test_rate_gate_offloads_a_subthreshold_object_that_costs_the_budget(_proto):
    """An object UNDER CORR_OFFLOAD_MIN_ELEMENTS whose builder costs more than
    the budget must still be offloaded — that is the case a count of elements
    can never see (a signal carrying a 4 KB blob costs many times a bare one).

    The first such object pays the block (and is counted); every later one of
    that size goes to the executor.
    """
    snap = _objects(_proto, 1, 600, prefix="r", nodes=4)[0]
    assert (main._SYNC_RATE_MIN_COST <= main._snap_cost(snap)
            < main.CORR_OFFLOAD_MIN_ELEMENTS), (
        "the fixture must sit in the BAND the projection governs: above the "
        "min-cost floor, under the element threshold")

    seen: list[str] = []
    real_offload = main._offload

    async def spy(fn, /, *a, **k):
        seen.append(getattr(fn, "__name__", repr(fn)))
        return await real_offload(fn, *a, **k)

    def slow_builder(_s):
        time.sleep(0.02)                 # a builder that costs real loop time
        return "{}"

    slow_builder.__name__ = "slow_builder"
    main._offload = spy
    try:
        # Budget below the builder's cost. The FIRST call is the cold sample —
        # recorded, deliberately not used as a rate (see _SYNC_RATE: a cold
        # first call over-reads by orders of magnitude). The SECOND is the
        # first usable measurement, and from the THIRD on the projection stands
        # and the object goes to the executor.
        main.CORR_SYNC_BUDGET_MS = 10.0
        asyncio.run(main._snap_call(snap, slow_builder, snap))
        assert seen == [], "the cold first call must be the inline measurement"
        assert not main._SYNC_RATE["slow_builder"], (
            "the cold sample must not be usable as a rate")
        asyncio.run(main._snap_call(snap, slow_builder, snap))
        assert seen == [], "the first usable measurement is still inline"
        assert max(r for _, r in main._SYNC_RATE["slow_builder"]) > 0.0
        asyncio.run(main._snap_call(snap, slow_builder, snap))
        assert seen == ["slow_builder"], (
            "a sub-threshold object whose builder costs more than the budget "
            "was run on the loop thread a third time")

        # …and the gate is a knob: with the projection off, behaviour is the
        # element threshold alone (the A/B leg).
        main.CORR_SYNC_OFFLOAD = False
        seen.clear()
        asyncio.run(main._snap_call(snap, slow_builder, snap))
        assert seen == [], "CORR_SYNC_OFFLOAD=0 must restore the element gate"
    finally:
        main._offload = real_offload


def test_a_single_cold_outlier_cannot_poison_the_gate(_proto):
    """The regression the rate WINDOW exists for: one anomalous measurement
    (a cold first call, a GC pause landing inside a builder) must not turn the
    gate into 'offload everything' for the life of the process.

    Measured: `estimate_bytes` read 2.6 ms/element on its first call against
    ~0.01 ms/element warm — a running maximum would have offloaded every object
    over ~190 elements forever on the strength of that one sample."""
    snap = _objects(_proto, 1, 600, prefix="p", nodes=4)[0]
    cost = main._snap_cost(snap)
    # A budget the outlier does NOT breach, so the builder keeps running inline
    # and the window keeps refilling — this test is about the LENGTH bound; the
    # TTL (the escape when the gate has fired and the samples stop) is the next
    # test.
    main.CORR_SYNC_BUDGET_MS = 5_000.0

    calls = {"n": 0}

    def spiky(_s):
        calls["n"] += 1
        if calls["n"] == 2:          # one outlier, AFTER the cold sample
            time.sleep(0.06)
        else:
            time.sleep(0.0015)
        return "{}"

    spiky.__name__ = "spiky"
    for _ in range(2):
        asyncio.run(main._snap_call(snap, spiky, snap))
    spiked = main._sync_projected_ms("spiky", cost)
    assert spiked > 20.0, (
        f"the outlier did not move the projection ({spiked:.1f} ms) — the test "
        f"is not reproducing the poisoning it exists to bound")
    for _ in range(main._SYNC_RATE_WINDOW):
        asyncio.run(main._snap_call(snap, spiky, snap))
    settled = main._sync_projected_ms("spiky", cost)
    assert settled < spiked / 4, (
        f"one outlier is still driving the projection ({settled:.1f} ms vs "
        f"{spiked:.1f} ms) — the rate window is not bounded by length")


def test_a_poisoned_rate_expires_instead_of_standing_forever(_proto, monkeypatch):
    """The other half of the ageing rule, and the one that cannot be reached by
    refilling: once the projection sends a builder to the executor it produces
    no further inline samples, so a length-only window would stand at the
    moment it fired for the life of the process. The TTL is what lets the next
    call be measured again."""
    monkeypatch.setattr(main, "_SYNC_RATE_TTL_S", 0.05)
    snap = _objects(_proto, 1, 600, prefix="t", nodes=4)[0]
    cost = main._snap_cost(snap)
    main.CORR_SYNC_BUDGET_MS = 50.0
    # A rate that says "this object costs ten budgets" — the poisoned state.
    main._SYNC_RATE["ghost"] = main.deque(
        [(time.monotonic(), 10 * main.CORR_SYNC_BUDGET_MS / 1000.0 / cost)],
        maxlen=main._SYNC_RATE_WINDOW)
    assert main._sync_projected_ms("ghost", cost) >= main.CORR_SYNC_BUDGET_MS
    time.sleep(0.06)
    assert main._sync_projected_ms("ghost", cost) == 0.0, (
        "a stale rate still drives the gate — a builder that became cheap "
        "would never come back off the executor")


def test_rate_gate_does_not_offload_a_cheap_object(_proto):
    """The other direction, so the gate cannot be 'offload everything': a cheap
    builder on a small object stays inline however many times it runs."""
    snap = _objects(_proto, 1, 8, prefix="q", nodes=2)[0]
    seen: list[str] = []
    real_offload = main._offload

    async def spy(fn, /, *a, **k):
        seen.append(getattr(fn, "__name__", repr(fn)))
        return await real_offload(fn, *a, **k)

    main._offload = spy
    try:
        for _ in range(20):
            asyncio.run(main._snap_call(snap, main.cycle_hypotheses_blob, snap))
        assert seen == [], (
            f"a cheap sub-threshold builder was offloaded {len(seen)} times — "
            f"the rate gate is over-firing and will saturate the executor")
    finally:
        main._offload = real_offload


# ── 4. the observable ───────────────────────────────────────────────────────

def test_sync_spans_name_every_loop_thread_block(storm_close_batch, monkeypatch):
    """A loop-thread block with no span is how storm-s03 spent four
    investigations reading a wall-clock number as a stall. Every one of them
    must be named, and named as SYNC — separately from the wall-clock stages."""
    monkeypatch.setattr(main, "CORR_PROFILE_STAGES", True)
    monkeypatch.setattr(main, "_STAGE_STATS", {})
    monkeypatch.setattr(main, "_STAGE_SAMPLES", {})
    stale, live = storm_close_batch
    _run_close_batch(stale[:20], live[:50], yield_ms=50.0)
    stages = set(main.stage_profile()["stages"])
    assert "sync.lifecycle.partition" in stages, sorted(stages)
    for builder in ("content_hash", "to_object_row", "cycle_hypotheses_blob"):
        assert f"sync.builder.{builder}" in stages, (
            f"the inline {builder} block has no sync span — {sorted(stages)}")
    # Wall-clock and sync spans must both be present and distinguishable.
    assert "lifecycle.quiesce" in stages
    assert all(not k.startswith("sync.") or k.count(".") >= 2 for k in stages)


def test_sync_record_counts_and_reports_an_overrun():
    """The counter an operator alerts on: a block over the budget is counted,
    attributed to its site, and exported on /metrics and the health payload."""
    main.sync_record("unit.block", 0.6)
    assert main.SYNC_OVERRUNS_TOTAL == 1
    assert main.SYNC_OVERRUN_LAST_SITE == "unit.block"
    assert main.SYNC_STRETCH_MAX_MS == pytest.approx(600.0, rel=0.01)
    assert main.SYNC_STRETCH_MAX_SITE == "unit.block"
    prof = main.sync_profile()
    assert prof["overruns_total"] == 1
    assert prof["budget_ms"] == BUDGET_S * 1000.0
    body = main._metrics_text()
    for metric in ("corr_sync_stretch_max_ms", "corr_sync_overruns_total"):
        assert metric in body, f"{metric} missing from /metrics"
    assert "sync" in main.epoch_state()


def test_sync_record_never_raises_into_the_engine(monkeypatch):
    """§16.1 / §10: a profiler fault costs a metric, never a cohort."""
    monkeypatch.setattr(main, "CORR_PROFILE_STAGES", True)

    def boom(*_a, **_k):
        raise RuntimeError("profiler exploded")

    monkeypatch.setattr(main, "stage_record", boom)
    main.sync_record("unit.block", 0.001)      # must not raise


def test_stall_watchdog_quotes_the_configured_session_timeout(caplog, monkeypatch):
    """The watchdog's warning must read the CONFIGURED session timeout, never a
    hard-coded 30 s: raising CORR_SESSION_TIMEOUT_MS may not leave an operator
    reading a stale number in the one line that says what is at risk."""
    monkeypatch.setattr(main, "CORR_LOOP_LAG_SAMPLE_S", 0.001)
    monkeypatch.setattr(main, "CORR_LOOP_LAG_WARN_MS", 0.0)   # every sample warns
    monkeypatch.setattr(main, "CORR_SESSION_TIMEOUT_MS", 77_000)

    async def one_sample():
        task = asyncio.create_task(main.loop_lag_watchdog())
        await asyncio.sleep(0.05)
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task

    main.log.setLevel(logging.WARNING)
    with caplog.at_level(logging.WARNING, logger=main.log.name):
        asyncio.run(one_sample())
    warned = [r.getMessage() for r in caplog.records if "STALLED" in r.getMessage()]
    assert warned, "the watchdog never reported a stall"
    assert "77000ms" in warned[0], (
        f"the stall warning does not quote the configured session timeout: "
        f"{warned[0]}")


def test_a_tiny_object_is_never_offloaded_on_a_projection(_proto):
    """The floor. Below `_SYNC_RATE_MIN_COST` elements the projection is not
    consulted at all: a rate that claims a 10-element object costs half a
    second is measuring a GC pause or executor contention that landed inside
    the call, not the object — and acting on it would put work on the executor
    that the loop runs in microseconds, changing the scheduling of everything
    else for nothing.
    """
    snap = _objects(_proto, 1, 8, prefix="f", nodes=2)[0]
    cost = main._snap_cost(snap)
    assert cost < main._SYNC_RATE_MIN_COST, "fixture must be under the floor"
    main.CORR_SYNC_BUDGET_MS = 50.0
    # A rate that would project a hundred budgets for this object.
    main._SYNC_RATE["ghost2"] = main.deque(
        [(time.monotonic(), 100 * main.CORR_SYNC_BUDGET_MS / 1000.0 / cost)],
        maxlen=main._SYNC_RATE_WINDOW)
    assert main._sync_projected_ms("ghost2", cost) == 0.0

    seen: list[str] = []
    real_offload = main._offload

    async def spy(fn, /, *a, **k):
        seen.append(getattr(fn, "__name__", repr(fn)))
        return await real_offload(fn, *a, **k)

    def ghost2(_s):
        return "{}"

    main._offload = spy
    try:
        asyncio.run(main._snap_call(snap, ghost2, snap))
        assert seen == [], "a tiny object was offloaded on a projection"
    finally:
        main._offload = real_offload
