"""P2 delivery step 4 — the ASYNC EVIDENCE PLANE.

Spec: `docs/design/DECISION_EVIDENCE_SPLIT_P2_2026-08-28.md` §1, §4, §9 item 4.
Measured brief: `docs/scale/P2_STEPS012_2P5K_VERDICT_2026-08-29.md` §4.3 — a
5,000-signal cohort costs ~1,000 s and essentially all of it is the per-version
persist path; the operator's verdict exists in the first ~100 ms and waits behind
the Evidence rows of every earlier object in the cohort.

THE CLAIM UNDER TEST, in one sentence: deferring the Evidence write onto a
bounded, content-ordered queue changes WHEN a row is written and NOTHING ELSE —
not one byte, not one dedup token, not one archive-damping decision — while the
Decision rows of a cohort land before any Evidence row of that cohort.

Every test below is one of five mutant checks:

  * **byte identity** (E1, E1b, E1c) — every row and every dedup token a
    flag-ON run produces is IDENTICAL to a flag-OFF run's, per table. Move a
    byte, drop a token suffix, or let the drain order decide an archive-damping
    call and these go red.
  * **ordering** (E2, E2b, E3) — the drain order is a pure function of the
    items' CONTENT (shuffle the arrivals, get the same order), and a cohort's
    Decision rows precede its Evidence rows. MUTANT: `test_E2c` replaces the
    content key with arrival order and asserts the property is then LOST, so E2
    cannot pass vacuously.
  * **bounds** (E4, E4b, E4c) — the queue blocks instead of growing, counts the
    block, and never drops. MUTANT: `test_E4c` raises the bound and asserts the
    backpressure counter goes to 0, so E4 is measuring the bound and not luck.
  * **failure and loss** (E5, E6, E6b) — a failed Evidence write is counted and
    leaves every Decision row standing; a shutdown that outruns its deadline
    logs and counts each lost item.
  * **liveness** (E7, E8) — the consumer yields (2,000 queued items keep loop
    lag under the watchdog threshold) and every counter reaches /metrics and
    `epoch_state()`.
"""
from __future__ import annotations

import asyncio
import dataclasses
import gc
import json
import os
import pathlib
import random
import re
import time
import tracemalloc
from datetime import datetime, timedelta, timezone

import pytest

import engine
import main
import rank_memo as RM
import signals
from catalog import builtin_catalog
from engine import EngineConfig, run_window
from evidence_plane import (
    EVIDENCE_CLASS_DECISION,
    EVIDENCE_CLASS_HEARTBEAT,
    EVIDENCE_CLASS_TERMINAL,
    EvidenceItem,
    EvidenceQueue,
    estimate_bytes,
    loose_slice_signals,
)
from signals import (
    EntityType,
    ModalityClass,
    Observer,
    ObserverType,
    Severity,
    Signal,
    Source,
)

# `test_p2_memflat_bounds` owns the `gc.get_referents` REFERENCE walk (and its
# two ownership rules); E11h needs the same instrument the rank memo's B5b is
# judged against, so it is imported rather than forked.
from test_p2_memflat_bounds import reference_deep_bytes

CAT = builtin_catalog()
CFG = EngineConfig()
T0 = datetime(2026, 8, 29, 10, 0, 0, tzinfo=timezone.utc)

EVIDENCE_TABLES = ("netops.corr_edges", "netops.corr_evidence",
                   "netops.corr_signals_archive")
DECISION_TABLES = ("netops.corr_objects", "netops.corr_current")


# ── fixtures ─────────────────────────────────────────────────────────────────

def sig(kind: str, entity_id: str, *, offset_s: float = 0.0,
        modality: ModalityClass = ModalityClass.DEVICE_TELEMETRY,
        tenant: str = "t1", severity: Severity = Severity.HIGH) -> Signal:
    """The shared P1/P2 fixture shape (test_cohort_touch_gate_p1.sig)."""
    return Signal(
        tenant_id=tenant, ts=T0 + timedelta(seconds=offset_s), source=Source.METRIC,
        kind=kind,
        observer=Observer(observer_id="obs1", observer_type=ObserverType.DEVICE),
        modality_class=modality, entity_type=EntityType.INTERFACE,
        entity_id=entity_id, severity=severity,
        native_id=f"p2ev|{tenant}|{kind}|{entity_id}|{offset_s}",
        attrs={"onset_uncertainty_s": 5.0})


def component(i: int, *, tenant: str = "t1") -> list[Signal]:
    """One two-node, identity-grounded component (so the pair always edges)."""
    return [
        sig("if_util_high", f"dev{i}:Gi0/1", offset_s=i * 0.1, tenant=tenant),
        sig("if_errors_high", f"dev{i}:Gi0/1", offset_s=i * 0.1 + 5,
            modality=ModalityClass.CONTROL_PLANE, tenant=tenant,
            severity=Severity.WARN),
    ]


def mixed_window(n: int = 8, *, tenant: str = "t1") -> list[Signal]:
    return [s for i in range(n) for s in component(i, tenant=tenant)]


class _RecCH:
    """Records every insert IN ORDER, with its table, rows and dedup token.

    The order is the point: the byte tests read the rows, the ordering tests read
    the sequence, and both need the SAME recorder so a run cannot satisfy one
    while quietly breaking the other."""

    def __init__(self, reject: tuple[str, ...] = ()) -> None:
        self.writes: list[tuple[str, list[dict], str]] = []
        self.reject = set(reject)
        self.delay_s = 0.0
        self.slow_tables: dict[str, float] = {}

    async def insert(self, table, rows, dedup_token="", **kw):
        rows = [dict(r) for r in rows]
        self.writes.append((table, rows, dedup_token))
        delay = self.slow_tables.get(table, self.delay_s)
        if delay:
            await asyncio.sleep(delay)
        return table not in self.reject

    # ── views the tests read ────────────────────────────────────────────────
    def rows_of(self, table: str) -> list[dict]:
        return [r for t, rr, _tok in self.writes if t == table for r in rr]

    def tokens_of(self, table: str) -> list[str]:
        return [tok for t, _rr, tok in self.writes if t == table]

    def tables(self) -> set[str]:
        return {t for t, _rr, _tok in self.writes}

    def first_index(self, tables) -> int:
        for i, (t, _rr, _tok) in enumerate(self.writes):
            if t in tables:
                return i
        return -1

    def last_index(self, tables) -> int:
        out = -1
        for i, (t, _rr, _tok) in enumerate(self.writes):
            if t in tables:
                out = i
        return out


def _canon(rows: list[dict]) -> list[str]:
    """Rows as sorted canonical JSON — a MULTISET comparison.

    Deliberately not a list comparison for the Evidence tables: reordering the
    drain is the whole feature, so two legs may write the same rows in a
    different sequence. Per-ROW bytes are what must not move, and sorting the
    serialized rows compares exactly that (a dropped, added or altered row moves
    the multiset). The Decision tables ARE compared in order — see E1."""
    return sorted(json.dumps(r, sort_keys=True, default=str) for r in rows)


def _load(sigs) -> None:
    for s in sigs:
        sid = str(s.signal_id)
        main.WINDOW_BUFFER.append(s)
        main._BUFFERED_ID_ORDER.append(sid)
        main._BUFFERED_IDS.add(sid)
        main._advance_watermark(s, 0.0)


def _reset_engine_state() -> None:
    main.WINDOW_BUFFER.clear(); main._BUFFERED_IDS.clear()
    main._BUFFERED_ID_ORDER.clear(); main._PROCESSED_IDS.clear()
    main.TENANT_WATERMARK.clear(); main._TENANT_EDGES.clear()
    main._ARCHIVE_SLICE_HASH.clear()
    main._LIFECYCLE_SEEN_WINDOW.clear()
    main.OPEN_OBJECTS.clear()


@pytest.fixture
def _stack(monkeypatch):
    """A clean engine + a clean Evidence plane, restored on the way out."""
    _reset_engine_state()
    monkeypatch.setattr(main, "OPEN_OBJECTS", {})
    monkeypatch.setattr(main, "_EVIDENCE_QUEUE", None)
    monkeypatch.setattr(main, "_EVIDENCE_TASK", None)
    monkeypatch.setattr(main, "_EVIDENCE_LOOP", None)
    monkeypatch.setattr(main, "EVIDENCE_ITEMS_MATERIALIZED", 0)
    monkeypatch.setattr(main, "EVIDENCE_ITEMS_FAILED", 0)
    monkeypatch.setattr(main, "EVIDENCE_ITEMS_LOST", 0)
    monkeypatch.setattr(main, "CORR_EVIDENCE_ASYNC", True)
    monkeypatch.setattr(main, "CORR_EVIDENCE_QUEUE_MAX", 5000)
    monkeypatch.setattr(main, "CORR_EVIDENCE_QUEUE_BYTES_MAX", 512 * 1024 * 1024)
    monkeypatch.setattr(main, "CORR_EVIDENCE_DRAIN_ON_STOP_S", 30.0)
    # P2 step 4c (cross-version batching) is ON in production and is pinned by
    # test_p2_evidence_batching.py. It is OFF here on purpose: every test in
    # THIS file pins step 4's contract — one INSERT per (item, table, page),
    # its own dedup token, and an item counted the moment its write returns.
    # Batching changes exactly those three things and nothing else, so leaving
    # it on here would replace step 4's pins with step 4c's instead of adding
    # to them.
    monkeypatch.setattr(main, "CORR_EVIDENCE_BATCH", False)
    monkeypatch.setattr(main, "CORR_DECISION_BATCH", False)
    monkeypatch.setattr(main, "CORR_COHORT_TOUCH_GATE", True)
    monkeypatch.setattr(main, "CORR_LIFECYCLE_EPOCH_CADENCE", True)
    # Every module global these tests assign DIRECTLY (helpers do, for
    # readability) is registered with monkeypatch at its current value first, so
    # teardown restores it whatever the test did. Without this, `_sweep`'s
    # CORR_ENGINE_EPOCH_BUDGET_S=0 and DRAIN_COHORTS=8 leaked into whatever ran
    # next under pytest-randomly and turned unrelated scheduler tests red.
    for _name in ("CORR_ENGINE_COHORT_SIZE", "CORR_ENGINE_DRAIN_COHORTS",
                  "CORR_ENGINE_EPOCH_BUDGET_S", "CORR_STORM_COHORT_SIZE",
                  "CORR_QUIESCE_S", "CORR_OPEN_OBJECTS_MAX",
                  "CORR_LIFECYCLE_COHORT_WINDOW", "CORR_ARCHIVE_CHUNK_ROWS",
                  "CORR_ROW_PAGE_SIZE", "CORR_PROFILE_STAGES",
                  "CORR_EVIDENCE_QUEUE_MAX", "CORR_EVIDENCE_BATCH_MS",
                  "CORR_DECISION_OFFLOAD", "ch", "find_merges",
                  "_persist_snapshot", "_offload", "_LIFECYCLE_SEEN_WINDOW"):
        monkeypatch.setattr(main, _name, getattr(main, _name))
    yield monkeypatch
    _reset_engine_state()


async def _drain_cohorts(k: int, size: int) -> None:
    """K cohorts against ONE epoch, then the epoch's lifecycle pass, then the
    Evidence drain — the drain sweep's shape (`_drain_epoch_sweep`)."""
    epoch = await main._begin_epoch(datetime.now(timezone.utc))
    try:
        for _ in range(k):
            await main.engine_cycle(epoch)
            epoch.cohorts += 1
        await main._epoch_lifecycle(epoch, main._make_loop_yield()[0])
    finally:
        main._close_epoch(epoch)
    left = await main.evidence_drain(30.0)
    assert left == 0, f"evidence queue did not drain: {left} item(s) left"


def _run_leg(monkeypatch, *, async_on: bool, components: int = 6,
             cohorts: int = 3, cohort_size: int = 4) -> _RecCH:
    """One full leg of the A/B: the SAME fixture, the SAME cohort schedule, only
    CORR_EVIDENCE_ASYNC differs. Everything a leg could carry over (open objects,
    processed ids, carried edges, the archive-slice hashes, the lifecycle
    window, the queue itself) is reset first."""
    _reset_engine_state()
    ch = _RecCH()
    monkeypatch.setattr(main, "ch", ch)
    monkeypatch.setattr(main, "OPEN_OBJECTS", {})
    monkeypatch.setattr(main, "_EVIDENCE_QUEUE", None)
    monkeypatch.setattr(main, "_EVIDENCE_TASK", None)
    monkeypatch.setattr(main, "_EVIDENCE_LOOP", None)
    monkeypatch.setattr(main, "CORR_EVIDENCE_ASYNC", async_on)
    monkeypatch.setattr(main, "CORR_ENGINE_COHORT_SIZE", cohort_size)
    _load(mixed_window(components))
    asyncio.run(_drain_cohorts(cohorts, cohort_size))
    return ch


# ═══ E1 — byte identity, table by table ══════════════════════════════════════

def test_E1_flag_on_is_byte_identical_to_flag_off(_stack):
    """THE test the whole step stands on. Same fixture, same schedule; the only
    difference is whether the Evidence rows were written inline or drained from
    the queue. Every row of every table, and every dedup token, must match."""
    off = _run_leg(_stack, async_on=False)
    on = _run_leg(_stack, async_on=True)

    assert off.writes, "the fixture must actually persist something"
    assert off.tables() == on.tables(), (
        f"a table appeared or vanished: {off.tables() ^ on.tables()}")

    # Decision tables: identical rows in identical ORDER — the Decision plane is
    # untouched, so not even its sequence may move.
    for table in DECISION_TABLES:
        assert [json.dumps(r, sort_keys=True, default=str) for r in off.rows_of(table)] == \
               [json.dumps(r, sort_keys=True, default=str) for r in on.rows_of(table)], \
               f"{table} rows moved"
        assert off.tokens_of(table) == on.tokens_of(table), f"{table} tokens moved"

    # Evidence tables: identical rows and identical tokens as MULTISETS. The
    # drain order is content-derived, not arrival-derived, so the sequence may
    # legitimately differ between the legs — the bytes may not.
    for table in EVIDENCE_TABLES:
        assert _canon(off.rows_of(table)) == _canon(on.rows_of(table)), \
            f"{table} rows moved"
        assert sorted(off.tokens_of(table)) == sorted(on.tokens_of(table)), \
            f"{table} dedup tokens moved"


def test_E1b_the_typed_edge_table_is_byte_identical_too(_stack):
    """CORR_EDGES_V2's table travels the same deferred path; it is off by
    default, so it needs its own leg or the E1 comparison is vacuous for it."""
    _stack.setattr(main, "CORR_EDGES_V2", True)
    off = _run_leg(_stack, async_on=False)
    on = _run_leg(_stack, async_on=True)
    table = main.CORR_PATH_EDGES_TABLE
    assert off.rows_of(table), "the typed-edge table must have been written"
    assert _canon(off.rows_of(table)) == _canon(on.rows_of(table))
    assert sorted(off.tokens_of(table)) == sorted(on.tokens_of(table))


def test_E1c_the_archive_damping_decision_is_not_taken_by_the_drain_order(_stack):
    """The one place where a deferred write could change WHAT is persisted.

    `_ARCHIVE_SLICE_HASH` says "this membership is already archived, skip it".
    Evaluated in the consumer it would be decided by the drain order; evaluated
    on the Decision path it is decided in version order, as today. The proof is
    the damped COUNT plus the archived versions matching across the legs."""
    def slices(ch):
        arch = "netops.corr_signals_archive"
        return sorted((r["archived_for"], r["archived_version"])
                      for r in ch.rows_of(arch))

    d0 = main.ARCHIVE_SLICES_DAMPED
    off = _run_leg(_stack, async_on=False, components=4, cohorts=4, cohort_size=2)
    off_damped = main.ARCHIVE_SLICES_DAMPED - d0
    d1 = main.ARCHIVE_SLICES_DAMPED
    on = _run_leg(_stack, async_on=True, components=4, cohorts=4, cohort_size=2)
    on_damped = main.ARCHIVE_SLICES_DAMPED - d1
    assert off_damped == on_damped, (
        "the number of damped slices must be a property of the versions, not "
        "of when their rows were written")
    assert slices(off) == slices(on), (
        "the set of (object, version) archive slices must not depend on when "
        "the Evidence rows were written")
    assert slices(off), "the fixture must actually archive something"


# ═══ E2/E3 — ordering ════════════════════════════════════════════════════════

def _item(cls: int, ws: float, cid: str, version: int) -> EvidenceItem:
    return EvidenceItem(correlation_id=cid, tenant_id="t1", version=version,
                        state="open", tok=f"{cid}:{version}", snap=None,
                        priority_class=cls, window_start_ts=ws)


ITEMS = [
    (EVIDENCE_CLASS_HEARTBEAT, 10.0, "cid-a", 7),
    (EVIDENCE_CLASS_DECISION, 30.0, "cid-b", 1),
    (EVIDENCE_CLASS_TERMINAL, 5.0, "cid-c", 3),
    (EVIDENCE_CLASS_DECISION, 10.0, "cid-d", 2),
    (EVIDENCE_CLASS_DECISION, 10.0, "cid-a", 1),
    (EVIDENCE_CLASS_HEARTBEAT, 1.0, "cid-e", 9),
    (EVIDENCE_CLASS_TERMINAL, 5.0, "cid-c", 4),
]


async def _drain_order(order: list[tuple]) -> list[tuple]:
    """Drain the queue and report each item by its OWN FIELDS, never by `key`.

    Reading `.key` back would make the assertions self-fulfilling: a mutant that
    returns a constant key would drain in arrival order and still compare equal
    to `sorted([constant, constant, ...])`. The identity tuple below is what the
    caller put in, so a lost ordering is visible as a moved item."""
    q = EvidenceQueue(len(order) + 1, 1 << 40)
    for spec in order:
        await q.put(_item(*spec))
    out = []
    while q.qsize():
        it = await q.get()
        out.append((it.priority_class, it.window_start_ts,
                    it.correlation_id, it.version))
    return out


@pytest.mark.parametrize("seed", range(12))
def test_E2_the_drain_order_is_content_derived_and_shuffle_stable(seed):
    """Shuffle the arrivals; the drain order must not move. It is exactly
    `sorted(key)` — (priority_class, window_start, correlation_id, version) —
    with nothing arrival-, clock- or id()-derived in it."""
    shuffled = list(ITEMS)
    random.Random(seed).shuffle(shuffled)
    got = asyncio.run(_drain_order(shuffled))
    assert got == sorted(ITEMS), "the drain order is exactly sorted(content key)"
    assert got == asyncio.run(_drain_order(list(ITEMS)))


def test_E2b_a_new_incident_drains_before_a_heartbeat_of_an_older_window():
    """The class dominates the key: a v1 in a LATER window still outranks an
    unchanged re-persist of an earlier one. That is the whole priority claim."""
    got = asyncio.run(_drain_order([
        (EVIDENCE_CLASS_HEARTBEAT, 1.0, "cid-old", 40),
        (EVIDENCE_CLASS_DECISION, 999.0, "cid-new", 1),
    ]))
    assert got[0][0] == EVIDENCE_CLASS_DECISION
    assert got[0][2] == "cid-new"


def test_E2c_MUTANT_arrival_order_loses_the_property():
    """E2 is not vacuous: a queue keyed on ARRIVAL (what a plain FIFO is) gives
    a different order for a different shuffle of the same items."""
    async def fifo(order):
        q = asyncio.Queue()
        for spec in order:
            q.put_nowait(_item(*spec))
        return [(await q.get()).key for _ in range(q.qsize())]

    a = asyncio.run(fifo(list(ITEMS)))
    b = asyncio.run(fifo(list(reversed(ITEMS))))
    assert a != b, "if arrival order were stable this test would prove nothing"
    assert asyncio.run(_drain_order(list(ITEMS))) == \
           asyncio.run(_drain_order(list(reversed(ITEMS))))


def test_E3_a_cohorts_decision_rows_land_before_any_of_its_evidence_rows(_stack):
    """Spec §1, stated as an assertion on the write SEQUENCE: within one cohort
    every corr_objects / corr_current row is written before the first
    corr_edges / corr_evidence / corr_signals_archive row.

    Flag OFF this is false by construction (each object writes its own Evidence
    before the next object's verdict), which is what the second half asserts —
    so a regression that quietly reverted to the inline path goes red here."""
    on = _run_leg(_stack, async_on=True, components=6, cohorts=1, cohort_size=12)
    last_decision = on.last_index(DECISION_TABLES)
    first_evidence = on.first_index(EVIDENCE_TABLES)
    assert first_evidence >= 0 and last_decision >= 0, "both planes must have written"
    assert last_decision < first_evidence, (
        "a cohort's verdict rows must all land before its first Evidence row")

    off = _run_leg(_stack, async_on=False, components=6, cohorts=1, cohort_size=12)
    assert off.first_index(EVIDENCE_TABLES) < off.last_index(DECISION_TABLES), (
        "inline, Evidence necessarily interleaves — if it did not, E3 would be "
        "proving nothing about the split")


# ═══ E4 — bounds, backpressure, no loss ══════════════════════════════════════

async def _produce_and_drain(n: int, max_items: int) -> tuple[EvidenceQueue, list]:
    q = EvidenceQueue(max_items, 1 << 40)
    drained: list[EvidenceItem] = []

    async def consumer():
        while True:
            it = await q.get()
            drained.append(it)
            await asyncio.sleep(0)      # let the producer run between items

    task = asyncio.get_running_loop().create_task(consumer())
    for i in range(n):
        await q.put(_item(EVIDENCE_CLASS_DECISION, float(i), f"cid-{i:04d}", 1))
        assert q.qsize() <= max_items, "the bound is a BOUND"
    while q.qsize():
        await asyncio.sleep(0)
    task.cancel()
    return q, drained


def test_E4_the_queue_blocks_instead_of_growing_and_never_drops():
    """Bounded, blocking, lossless (owner memo §22). 200 items through a queue
    of 3: every one arrives, the depth never exceeds the bound, and the blocking
    is COUNTED rather than being an invisible stall."""
    q, drained = asyncio.run(_produce_and_drain(200, 3))
    assert len(drained) == 200, "nothing may be dropped"
    assert len({it.correlation_id for it in drained}) == 200
    assert q.backpressure_total > 0, "a queue of 3 fed 200 items must have blocked"


def test_E4b_the_byte_bound_blocks_as_well_as_the_item_bound():
    """The second bound is the RSS one: an item that is small in COUNT can still
    be large in referenced bytes, and `max_bytes` is what stops a storm cohort
    parking thousands of graphs in memory."""
    async def go():
        q = EvidenceQueue(1_000_000, 4096)
        big = _item(EVIDENCE_CLASS_DECISION, 1.0, "cid-big", 1)
        big.est_bytes = 4096
        await q.put(big)
        assert q.full(), "one over-large item must saturate the byte bound"
        blocked = asyncio.get_running_loop().create_task(
            q.put(_item(EVIDENCE_CLASS_DECISION, 2.0, "cid-2", 1)))
        await asyncio.sleep(0)
        assert not blocked.done(), "a full-by-BYTES queue must block the producer"
        await q.get()
        await blocked
        assert q.qsize() == 1 and q.backpressure_total == 1
    asyncio.run(go())


def test_E4c_MUTANT_a_bound_wide_enough_never_counts_backpressure():
    """E4 measures the bound and not luck: raise the bound above the workload
    and the backpressure counter must be exactly 0."""
    q, drained = asyncio.run(_produce_and_drain(200, 500))
    assert len(drained) == 200
    assert q.backpressure_total == 0


def test_E4d_the_cohort_hold_yields_to_the_bound_and_cannot_deadlock():
    """The hold is an ordering PREFERENCE; the bound is a rule. A cohort that
    produces more items than the queue can hold must not block on its own hold."""
    async def go():
        q = EvidenceQueue(2, 1 << 40)
        got: list[EvidenceItem] = []

        async def consumer():
            while True:
                got.append(await q.get())

        task = asyncio.get_running_loop().create_task(consumer())
        q.hold()
        for i in range(6):
            await asyncio.wait_for(
                q.put(_item(EVIDENCE_CLASS_DECISION, float(i), f"cid-{i}", 1)), 2.0)
        assert got, "the bound must have lifted the hold"
        await q.release()
        while q.qsize():
            await asyncio.sleep(0)
        task.cancel()
        assert len(got) == 6
    asyncio.run(go())


def test_E4e_while_held_and_under_the_bound_the_consumer_takes_nothing():
    """The other half of E4d: below the bound the hold really holds."""
    async def go():
        q = EvidenceQueue(10, 1 << 40)
        got: list[EvidenceItem] = []

        async def consumer():
            while True:
                got.append(await q.get())

        task = asyncio.get_running_loop().create_task(consumer())
        q.hold()
        await q.put(_item(EVIDENCE_CLASS_DECISION, 1.0, "cid-1", 1))
        for _ in range(20):
            await asyncio.sleep(0)
        assert got == [], "a held consumer must not drain below the bound"
        await q.release()
        for _ in range(20):
            await asyncio.sleep(0)
        assert len(got) == 1
        task.cancel()
    asyncio.run(go())


# ═══ E5 — a failing Evidence write ═══════════════════════════════════════════

def test_E5_a_failing_evidence_write_is_counted_and_spares_the_decision_rows(_stack):
    """`corr_edges` is an RCA-critical table, so a rejection RAISES. From the
    consumer that must be caught, counted and logged — never propagated into the
    Decision plane and never silent. The verdict rows must all still be there."""
    _reset_engine_state()
    ch = _RecCH(reject=("netops.corr_edges",))
    _stack.setattr(main, "ch", ch)
    _stack.setattr(main, "CORR_ENGINE_COHORT_SIZE", 12)
    _load(mixed_window(5))
    asyncio.run(_drain_cohorts(1, 12))
    assert main.EVIDENCE_ITEMS_FAILED > 0, "the failure must be counted"
    assert main.EVIDENCE_ITEMS_MATERIALIZED == 0
    objs = ch.rows_of("netops.corr_objects")
    assert len(objs) == 5, "every Decision row must stand"
    assert len(ch.rows_of("netops.corr_current")) == 5
    assert main.evidence_stats()["failed_total"] == main.EVIDENCE_ITEMS_FAILED


def test_E5b_a_failed_archive_slice_reverts_its_optimistic_hash(_stack):
    """The damping record is written before the rows land, so a failed archive
    write must REVERT it — otherwise the next version would damp against a slice
    that was never archived. (Today's rule, expressed the other way round.)"""
    _reset_engine_state()
    ch = _RecCH(reject=("netops.corr_signals_archive",))
    _stack.setattr(main, "ch", ch)
    _stack.setattr(main, "CORR_ENGINE_COHORT_SIZE", 12)
    _load(mixed_window(3))
    asyncio.run(_drain_cohorts(1, 12))
    assert main.EVIDENCE_ITEMS_FAILED == 3
    assert main._ARCHIVE_SLICE_HASH == {}, (
        "a slice that did not land whole must leave no damping record behind")


# ═══ E6 — shutdown drain and lost accounting ═════════════════════════════════

def test_E6_shutdown_drains_within_its_deadline(_stack):
    """The happy path: everything queued lands, nothing is counted lost."""
    async def go():
        _stack.setattr(main, "ch", _RecCH())
        q = main._evidence_ensure_consumer()
        assert q is not None
        snap = run_window(mixed_window(2), CAT, (), CFG)[0]
        for v in range(1, 6):
            await q.put(EvidenceItem(
                correlation_id=snap.correlation_id, tenant_id=snap.tenant_id,
                version=v, state="open", tok=f"tok:{v}", snap=snap,
                priority_class=EVIDENCE_CLASS_DECISION,
                window_start_ts=snap.window_start.timestamp(),
                est_bytes=estimate_bytes(snap)))
        await main._evidence_stop()
        assert main.EVIDENCE_ITEMS_MATERIALIZED == 5
        assert main.EVIDENCE_ITEMS_LOST == 0
    asyncio.run(go())


def test_E6b_what_the_deadline_leaves_behind_is_logged_and_counted(_stack, caplog):
    """An Evidence row that never landed is a FACT on the way out (§10): one
    INFO line per item plus corr_evidence_items_total{outcome="lost"}."""
    async def go():
        ch = _RecCH()
        ch.delay_s = 0.05          # slower than the deadline below
        _stack.setattr(main, "ch", ch)
        _stack.setattr(main, "CORR_EVIDENCE_DRAIN_ON_STOP_S", 0.05)
        q = main._evidence_ensure_consumer()
        assert q is not None
        snap = run_window(mixed_window(2), CAT, (), CFG)[0]
        for v in range(1, 21):
            await q.put(EvidenceItem(
                correlation_id=snap.correlation_id, tenant_id=snap.tenant_id,
                version=v, state="open", tok=f"tok:{v}", snap=snap,
                priority_class=EVIDENCE_CLASS_DECISION,
                window_start_ts=snap.window_start.timestamp()))
        with caplog.at_level("INFO", logger="correlation"):
            await main._evidence_stop()
        assert main.EVIDENCE_ITEMS_LOST > 0, "undrained items must be counted lost"
        lost_lines = [r for r in caplog.records if "evidence LOST" in r.getMessage()]
        assert len(lost_lines) == main.EVIDENCE_ITEMS_LOST, (
            "every lost item gets its own line — a count with no names is not "
            "an operator signal")
        assert main.evidence_stats()["lost_total"] == main.EVIDENCE_ITEMS_LOST
    asyncio.run(go())


def test_E6c_a_queue_stranded_on_a_dead_loop_is_counted_not_carried(_stack):
    """A queue whose consumer belongs to a loop that is gone can never drain.
    Starting a new consumer must ACCOUNT for what it abandons rather than
    silently inheriting it — and a persist on the new loop must not enqueue onto
    the dead one (that would swallow Evidence for the rest of the process)."""
    async def leg1():
        _stack.setattr(main, "ch", _RecCH())
        q = main._evidence_ensure_consumer()
        assert q is not None
        q.hold()                       # park the consumer so nothing drains
        await q.put(_item(EVIDENCE_CLASS_DECISION, 1.0, "cid-x", 1))
    asyncio.run(leg1())
    assert main._active_evidence_queue() is None, (
        "outside a loop there is no active queue — the caller writes inline")

    async def leg2():
        assert main._active_evidence_queue() is None, (
            "a queue bound to a dead loop must never be handed out")
        main._evidence_ensure_consumer()
        assert main.EVIDENCE_ITEMS_LOST == 1
    asyncio.run(leg2())


# ═══ E7 — liveness ═══════════════════════════════════════════════════════════

def test_E7_a_two_thousand_item_queue_keeps_loop_lag_under_the_watchdog(_stack):
    """The consumer is a task on the loop the Kafka consumer lives on, so a
    backlog it refused to yield inside would look exactly like the 130 s stalls
    tracker 172 exists to prevent. Measured with the watchdog's own rule: the
    overshoot of a 10 ms sleep, against CORR_LOOP_LAG_WARN_MS."""
    async def go():
        _stack.setattr(main, "ch", _RecCH())
        q = main._evidence_ensure_consumer()
        assert q is not None
        _stack.setattr(main, "CORR_EVIDENCE_QUEUE_MAX", 5000)
        snap = run_window(mixed_window(3), CAT, (), CFG)[0]
        worst = 0.0
        stop = False

        async def watchdog():
            nonlocal worst
            while not stop:
                t0 = time.monotonic()
                await asyncio.sleep(0.01)
                worst = max(worst, (time.monotonic() - t0 - 0.01) * 1000.0)

        wd = asyncio.get_running_loop().create_task(watchdog())
        q.hold()                       # build the backlog first, as a cohort does
        for v in range(1, 2001):
            await q.put(EvidenceItem(
                correlation_id=f"cid-{v:05d}", tenant_id=snap.tenant_id,
                version=v, state="open", tok=f"tok:{v}", snap=snap,
                priority_class=EVIDENCE_CLASS_DECISION,
                window_start_ts=snap.window_start.timestamp()))
        assert q.qsize() == 2000
        await q.release()
        left = await main.evidence_drain(60.0)
        stop = True
        await wd
        assert left == 0
        assert main.EVIDENCE_ITEMS_MATERIALIZED == 2000
        assert worst < main.CORR_LOOP_LAG_WARN_MS, (
            f"draining 2,000 items stalled the loop for {worst:.0f} ms "
            f"(watchdog threshold {main.CORR_LOOP_LAG_WARN_MS:.0f} ms)")
    asyncio.run(go())


# ═══ E8 — observability ══════════════════════════════════════════════════════

def test_E8_every_counter_reaches_metrics_and_epoch_state(_stack):
    """§10: none of this is real unless an operator can read it."""
    async def go():
        _stack.setattr(main, "ch", _RecCH())
        q = main._evidence_ensure_consumer()
        assert q is not None
        snap = run_window(mixed_window(2), CAT, (), CFG)[0]
        q.hold()
        for v in range(1, 4):
            await q.put(EvidenceItem(
                correlation_id=f"cid-{v}", tenant_id=snap.tenant_id, version=v,
                state="open", tok=f"tok:{v}", snap=snap,
                priority_class=EVIDENCE_CLASS_DECISION,
                window_start_ts=snap.window_start.timestamp(), est_bytes=1234))
        stats = main.evidence_stats()
        assert stats["depth"] == 3 and stats["bytes"] == 3702
        assert stats["oldest_age_seconds"] >= 0.0
        text = main._metrics_text()
        for series in ("corr_evidence_queue_depth",
                       "corr_evidence_queue_bytes",
                       "corr_evidence_queue_oldest_age_seconds",
                       "corr_evidence_lag_seconds",
                       "corr_evidence_queue_backpressure_total",
                       'corr_evidence_items_total{outcome="materialized"}',
                       'corr_evidence_items_total{outcome="failed"}',
                       'corr_evidence_items_total{outcome="lost"}'):
            assert series in text, f"{series} missing from /metrics"
        assert "corr_evidence_queue_depth 3" in text
        st = main.epoch_state()["evidence"]
        assert isinstance(st, dict) and st["depth"] == 3 and st["enabled"] is True
        await q.release()
        await main.evidence_drain(30.0)
        assert main.evidence_stats()["lag_seconds"] >= 0.0
        await main._evidence_stop()
    asyncio.run(go())


def test_E8b_the_profiler_shows_the_decision_evidence_split(_stack):
    """`stage_record` spans: the split is only visible if the two halves are
    timed apart. Both names must appear once the profiler is on."""
    _reset_engine_state()
    _stack.setattr(main, "ch", _RecCH())
    _stack.setattr(main, "CORR_PROFILE_STAGES", True)
    _stack.setattr(main, "CORR_ENGINE_COHORT_SIZE", 12)
    main._STAGE_STATS.pop("persist.decision", None)
    main._STAGE_STATS.pop("persist.evidence", None)
    _load(mixed_window(3))
    asyncio.run(_drain_cohorts(1, 12))
    assert main._STAGE_STATS.get("persist.decision"), "decision span missing"
    assert main._STAGE_STATS.get("persist.evidence"), "evidence span missing"


def test_E8c_the_flag_reverts_the_plane_on_one_image(_stack):
    """A/B on ONE image: CORR_EVIDENCE_ASYNC=0 and every persist writes inline,
    with no queue and no consumer anywhere."""
    async def go():
        _stack.setattr(main, "ch", _RecCH())
        _stack.setattr(main, "CORR_EVIDENCE_ASYNC", False)
        assert main._evidence_ensure_consumer() is None
        assert main._active_evidence_queue() is None
        assert main.evidence_stats()["enabled"] is False
        assert await main.evidence_drain(0.1) == 0
    asyncio.run(go())


# ═══ E9 — the level-1 rank memo's byte bound on the same surfaces ════════════
#
# Not the Evidence plane, but the SAME `_metrics_text()` block this step edited:
# the memflat work (2026-08-29) gave `RankMemo.stats()` a byte readout
# (`bytes`, `bytes_max`, `evicted_bytes`, bound `CORR_RANK_MEMO_BYTES_MAX`), and
# main.py's two hand-written surfaces — the memo-OFF branch of
# `rank_memo_stats()` and the hand-enumerated `corr_rank_memo*` series — do not
# pick that up for free. A bound nobody can read is a bound nobody will notice
# failing, so both are pinned here.

RANK_MEMO_STAT_KEYS = {"entries", "max_entries", "hits", "misses", "evicted",
                       "unkeyable", "bytes", "bytes_max", "evicted_bytes"}


def test_E9_the_memo_stat_keys_do_not_move_with_the_flag(monkeypatch):
    """A key that appears and disappears with a flag reads as a ZERO on the day
    it matters. The OFF branch is hand-written, so it is pinned field for field
    against the real memo's."""
    assert main.RANK_MEMO is not None, "the default build must have the memo on"
    on = main.rank_memo_stats()
    assert set(on) == RANK_MEMO_STAT_KEYS, (
        f"RankMemo.stats() gained or lost a key: {set(on) ^ RANK_MEMO_STAT_KEYS}")
    monkeypatch.setattr(main, "RANK_MEMO", None)
    off = main.rank_memo_stats()
    assert set(off) == set(on), (
        f"the memo-OFF branch is out of step: {set(off) ^ set(on)}")
    assert all(v == 0 for v in off.values())


def test_E9b_the_byte_bound_reaches_metrics_and_epoch_state():
    """`corr_rank_memo_bytes` / `_bytes_max` / `_evicted_bytes_total` must be on
    /metrics with the values `rank_memo_stats()` reports, and `epoch_state()`
    must pass the whole dict through."""
    rm = main.rank_memo_stats()
    text = main._metrics_text()
    for series, key in (("corr_rank_memo_bytes", "bytes"),
                        ("corr_rank_memo_bytes_max", "bytes_max"),
                        ("corr_rank_memo_evicted_bytes_total", "evicted_bytes")):
        assert f"# TYPE {series} " in text, f"{series} missing from /metrics"
        assert f"\n{series} {rm[key]}\n" in text + "\n", (
            f"{series} does not carry rank_memo_stats()['{key}']")
    assert rm["bytes_max"] > 0, "the byte bound must be a real number, not 0"
    assert set(main.epoch_state()["rank_memo"]) == RANK_MEMO_STAT_KEYS


# ═══ E10 — the live 2.5K regressions (run p2-s04-08290653) ═══════════════════
#
# What that run showed: the queue pinned at its 5,000 bound for the whole drain,
# backpressure_total 8,767, and `held=True` at idle. The root cause was NOT a
# leaked hold — `_evidence_cohort_hold` is balanced on every exit, and E10b pins
# that — but a hold that was STRICTLY STRONGER than spec §1 requires: it blocked
# the consumer from draining EARLIER cohorts' Evidence too. A drain sweep runs
# cohorts back to back with one `asyncio.sleep(0)` between them, so the consumer
# got one scheduling slot per cohort, drained ONE item, and was held again.
# The hold is now generational (evidence_plane's module docstring).

class _SlowCH(_RecCH):
    """A sink with latency, so the decision path actually has I/O waits for the
    consumer to work inside — which is the whole mechanism under test."""

    def __init__(self, delay_s: float = 0.002) -> None:
        super().__init__()
        self.delay_s = delay_s


async def _sweep(components: int, cohorts: int, cohort_size: int) -> None:
    main.CORR_ENGINE_COHORT_SIZE = cohort_size
    main.CORR_ENGINE_DRAIN_COHORTS = cohorts
    main.CORR_ENGINE_EPOCH_BUDGET_S = 0.0
    _load(mixed_window(components))
    await main._drain_epoch_sweep()


def test_E10_the_consumer_drains_between_cohorts_without_the_queue_being_full(_stack):
    """THE regression. Eight back-to-back cohorts, a queue bound far above the
    workload (so a bound can never be what lets the consumer run) and a sink with
    latency. The Evidence plane must make real progress from the decision path's
    own I/O waits.

    Before the generational hold this materialized 7 items out of 61 and the
    depth climbed monotonically; the bound was the only thing that ever released
    the consumer."""
    _reset_engine_state()
    _stack.setattr(main, "ch", _SlowCH())
    _stack.setattr(main, "CORR_EVIDENCE_QUEUE_MAX", 100_000)
    asyncio.run(_sweep(components=40, cohorts=8, cohort_size=8))
    q = main._EVIDENCE_QUEUE
    assert q is not None
    assert q.backpressure_total == 0, (
        "the bound must never be reached — otherwise this test proves only that "
        "pressure lifts the hold, which was never in doubt")
    produced = main.VERSIONS_PERSISTED
    assert produced >= 40, "the fixture must actually produce Evidence items"
    assert main.EVIDENCE_ITEMS_MATERIALIZED >= 4 * 8, (
        f"the consumer drained only {main.EVIDENCE_ITEMS_MATERIALIZED} of "
        f"{produced} items across 8 cohorts — that is the one-item-per-cohort "
        f"starvation the generational hold exists to fix")
    assert q.held is False and q.hold_expired_total == 0


def test_E10b_the_hold_is_released_by_every_exit_including_a_raising_cohort(_stack):
    """`held` must be False between cohorts on BOTH paths. The live `held=True`
    was a scrape landing inside a cohort's decision pass (`engine.run_window`
    p50 was 8 s on that run), not a leak — and `held_since_seconds` is what now
    tells those two apart."""
    async def go():
        _stack.setattr(main, "ch", _RecCH())
        _stack.setattr(main, "CORR_ENGINE_COHORT_SIZE", 12)
        _load(mixed_window(4))
        epoch = await main._begin_epoch(datetime.now(timezone.utc))
        try:
            await main.engine_cycle(epoch)
            q = main._EVIDENCE_QUEUE
            assert q is not None and q.held is False, "clean exit must release"
            assert q.held_since_s() == 0.0

        finally:
            main._close_epoch(epoch)
            await main.evidence_drain(30.0)

        # A RAISING cohort, in its own epoch so its cohort is genuinely
        # non-empty (an epoch is frozen at _begin_epoch, so signals loaded
        # afterwards are not in it and nothing would persist — the test would
        # then pass for the wrong reason).
        _load(mixed_window(4, tenant="t2"))
        epoch2 = await main._begin_epoch(datetime.now(timezone.utc))
        real = main._persist_snapshot

        async def boom(*a, **kw):
            raise RuntimeError("persist exploded")

        main._persist_snapshot = boom
        try:
            with pytest.raises(RuntimeError):
                await main.engine_cycle(epoch2)
        finally:
            main._persist_snapshot = real
            main._close_epoch(epoch2)
        q = main._EVIDENCE_QUEUE
        assert q is not None
        assert q.held is False, "a cohort that RAISES must release the hold"
        assert q.held_since_s() == 0.0
    asyncio.run(go())


def test_E10c_the_hold_is_generational_earlier_cohorts_still_drain(_stack):
    """The correction, stated as an invariant. Items queued BEFORE a hold are
    drainable during it (spec §1 says nothing about earlier cohorts); items
    queued DURING it are not, which is what E3 depends on."""
    async def go():
        q = EvidenceQueue(1000, 1 << 40, hold_max_s=0.0)
        got: list[EvidenceItem] = []

        async def consumer():
            while True:
                got.append(await q.get())

        task = asyncio.get_running_loop().create_task(consumer())
        # Generation 1, closed immediately.
        await q.put(_item(EVIDENCE_CLASS_DECISION, 1.0, "cid-old", 1))
        q.hold()
        # Generation 2, open: must NOT drain while the hold is up...
        await q.put(_item(EVIDENCE_CLASS_DECISION, 2.0, "cid-new", 1))
        for _ in range(40):
            await asyncio.sleep(0)
        assert [i.correlation_id for i in got] == ["cid-old"], (
            "the earlier cohort's item must drain during a later cohort's hold")
        assert q.stats()["depth_open"] == 1
        await q.release()
        for _ in range(40):
            await asyncio.sleep(0)
        assert [i.correlation_id for i in got] == ["cid-old", "cid-new"]
        task.cancel()
    asyncio.run(go())


def test_E10d_a_hold_that_outlives_its_deadline_expires_and_is_counted(_stack):
    """Defence in depth: a hold nobody releases must not starve the Evidence
    plane in silence. It expires, the open generation drains, and the break is
    counted — never a hang, never a silence."""
    async def go():
        q = EvidenceQueue(1000, 1 << 40, hold_max_s=0.05)
        got: list[EvidenceItem] = []

        async def consumer():
            while True:
                got.append(await q.get())

        task = asyncio.get_running_loop().create_task(consumer())
        q.hold()                       # deliberately never released
        await q.put(_item(EVIDENCE_CLASS_DECISION, 1.0, "cid-stuck", 1))
        for _ in range(10):
            await asyncio.sleep(0)
        assert got == [], "before the deadline the hold is honoured"
        await asyncio.sleep(0.12)
        assert [i.correlation_id for i in got] == ["cid-stuck"], (
            "past the deadline the consumer must drain anyway")
        assert q.hold_expired_total == 1, "and it must be COUNTED"
        assert q.held is True and q.held_since_s() > 0.0, (
            "held_since_seconds is what names a leak on /metrics")
        task.cancel()
    asyncio.run(go())


def test_E10e_backpressure_wait_is_its_own_span_and_is_in_neither_persist_stage(_stack):
    """A Decision write that took 200 ms and then waited 20 s for queue room is
    not a 20-second Decision write. The wait is timed as
    `persist.backpressure_wait`, outside both persist spans, so the live profile
    sends the next investigation at the right function."""
    _reset_engine_state()
    ch = _RecCH()
    ch.slow_tables = {t: 0.02 for t in EVIDENCE_TABLES}
    _stack.setattr(main, "ch", ch)
    _stack.setattr(main, "CORR_PROFILE_STAGES", True)
    _stack.setattr(main, "CORR_EVIDENCE_QUEUE_MAX", 1)   # every put after the
    _stack.setattr(main, "CORR_ENGINE_COHORT_SIZE", 24)  # first one blocks
    for name in ("persist.decision", "persist.evidence", "persist.backpressure_wait"):
        main._STAGE_STATS.pop(name, None)
        main._STAGE_SAMPLES.pop(name, None)
    asyncio.run(_sweep(components=8, cohorts=1, cohort_size=24))
    bp = main._STAGE_STATS.get("persist.backpressure_wait")
    dec = main._STAGE_STATS.get("persist.decision")
    assert bp and dec, "both spans must have been recorded"
    assert main._EVIDENCE_QUEUE is not None
    assert main._EVIDENCE_QUEUE.backpressure_total > 0, (
        "a queue of 1 must have blocked the Decision plane")
    # [count, total_s, max_s]. The Evidence tables are the slow ones here, so a
    # put into a queue bounded at 1 waits out a whole Evidence write while the
    # Decision write is two instant inserts. If the wait had leaked into
    # `persist.decision`, its max could not stay below the wait's.
    assert bp[1] > 0.0, "the blocked time must be recorded"
    assert dec[2] < bp[2], (
        f"the worst DECISION write ({dec[2] * 1000:.1f} ms) must be shorter "
        f"than the worst backpressure wait ({bp[2] * 1000:.1f} ms) — if it is "
        f"not, the wait leaked into the decision span")
    ev = main._STAGE_STATS.get("persist.evidence")
    assert ev and ev[2] < bp[2] + ev[2], "sanity: the spans are distinct"


def test_E10f_a_big_archive_chunk_is_built_off_the_event_loop(_stack):
    """The other half of the loop-lag regression. `cache=False` (the deferred
    path cannot use the id()-keyed per-cycle cache) costs ~15x the cached build:
    measured, a 10,000-row chunk is ~410 ms fresh vs ~27 ms cached, and
    CORR_ARCHIVE_CHUNK_ROWS is 10,000 — one uninterruptible stretch per chunk on
    the loop thread, competing with run_window for the GIL. Big chunks now go
    through `_offload`; small ones stay inline (an executor hop is not free)."""
    async def go():
        snap = run_window(mixed_window(2), CAT, (), CFG)[0]
        offloaded: list[str] = []
        real_offload = main._offload

        async def spy(fn, /, *a, **kw):
            offloaded.append(getattr(fn, "__name__", str(fn)))
            return await real_offload(fn, *a, **kw)

        _stack.setattr(main, "ch", _RecCH())
        _stack.setattr(main, "_offload", spy)
        _stack.setattr(main, "CORR_ARCHIVE_CHUNK_ROWS", 10_000)
        _stack.setattr(main, "CORR_ROW_PAGE_SIZE", 4)

        def item_with(n_sigs: int) -> EvidenceItem:
            sigs = mixed_window(max(1, n_sigs // 2))
            return EvidenceItem(
                correlation_id=snap.correlation_id, tenant_id=snap.tenant_id,
                version=1, state="open", tok="tok", snap=snap,
                priority_class=EVIDENCE_CLASS_DECISION,
                window_start_ts=snap.window_start.timestamp(),
                slice_sigs=list(sigs))

        offloaded.clear()
        await main._write_evidence(item_with(2))
        assert "_archive_chunk" not in offloaded, (
            "a 2-row chunk must not pay an executor hop")
        offloaded.clear()
        await main._write_evidence(item_with(40))
        assert "_archive_chunk" in offloaded, (
            "a chunk at or above CORR_ROW_PAGE_SIZE must be built off the loop")
    asyncio.run(go())


def test_E10g_the_new_hold_fields_reach_metrics_and_survive_the_flag(_stack):
    """Same key-set rule as E9: `held_since_seconds` / `hold_expired_total` /
    `depth_open` must exist whether or not the plane is on."""
    async def go():
        _stack.setattr(main, "ch", _RecCH())
        on_keys = set(main.evidence_stats())
        q = main._evidence_ensure_consumer()
        assert q is not None
        assert set(main.evidence_stats()) == on_keys, (
            "the stat key set must not change when the queue exists")
        text = main._metrics_text()
        for series in ("corr_evidence_hold_seconds",
                       "corr_evidence_hold_expired_total",
                       "corr_evidence_queue_depth_open"):
            assert f"# TYPE {series} " in text, f"{series} missing from /metrics"
        await main._evidence_stop()
    asyncio.run(go())


# ═══ E11 — the BYTE ESTIMATOR, calibrated against tracemalloc ════════════════
#
# WHY THIS SECTION EXISTS. The queue's second bound is denominated in
# `EvidenceItem.est_bytes`, and the first version of that number was three flat
# constants (2048 B/node + 768 B/edge + 1024 B/slice signal) with no id-`seen`
# set and no model of ownership. Walked against the items it was charging
# (`docs/scale/P2_MEMFLAT_EVIDENCE_QUEUE_2026-08-29.md` §4) it read **2.84x the
# true marginal and 25 % UNDER the standalone worst case** — wrong in both
# directions at once. A bound written against a meter like that is not a bound.
#
# THE REFERENCE is the same instrument that calibrated the rank memo
# (`test_p2_memflat_bounds.py::test_B5`): start tracemalloc, mint N real
# snapshots, read `current`, drop them, read `current` again. The difference IS
# the memory the process gives back when nothing else holds them — the
# STANDALONE figure §6a says the bound must be sized against, because whether an
# item's snapshot is shared with a live `OPEN_OBJECTS` entry goes to zero
# exactly when the bound has to hold.
#
# Every test below is a mutant check:
#   * E11a is the band, and executes BOTH mutants — drop catalog ownership, or
#     re-add the slice double count, and the same measurement leaves the band.
#   * E11b pins the loose-slice arithmetic against the REAL `_archive_slice`.
#   * E11c pins the inverted rule: `OPEN_OBJECTS` ownership is NOT discounted.
#   * E11d/E11e pin determinism and cost; E11f pins the measured defaults.

TEMPLATES = CAT.enabled_templates()
CALIBRATION_MIN_ITEMS = 200


def wide_component(i: int) -> list[Signal]:
    """One component of several nodes with several signals each — the item shape
    the offline bench measured (2.7-5.7 nodes, 5.5-6.1 node signals per item),
    not the 2-node minimum the ordering tests use.

    Every signal carries the SAME entity_id, so the nodes are identity-grounded
    into one object; the KINDS come from a real template's clause vocabulary, so
    consecutive components score against different templates and their
    `RankingResult` payloads differ (which is what makes the estimator's spread
    in E11 non-trivial)."""
    tpl = TEMPLATES[i % len(TEMPLATES)]
    kinds = [min(c.kinds()) for c in tpl.requires][:4] or ["if_util_high"]
    mods = [ModalityClass.DEVICE_TELEMETRY, ModalityClass.CONTROL_PLANE,
            ModalityClass.PASSIVE_FLOW, ModalityClass.ACTIVE_PROBE]
    return [sig(k, f"cal{i}:Gi0/1", offset_s=i * 0.01 + j + 10 * r,
                modality=mods[j % 4],
                severity=Severity.HIGH if r == 0 else Severity.WARN)
            for j, k in enumerate(kinds) for r in range(3)]


def calibration_snapshots(n: int, base: int = 0) -> list:
    """`n` components through the REAL engine — no fixture snapshots, because
    the payload under measurement IS what `run_window` builds."""
    out = []
    for i in range(base, base + n):
        out.extend(run_window(wide_component(i), CAT, (), CFG))
    return out


def _node_signals(snap) -> int:
    return sum(len(nd.signals) for nd in snap.nodes)


def test_E11_the_estimator_is_not_a_constant_and_reads_the_graph():
    """PREMISE for everything below. An estimator that returned a constant, or
    one that never reached the snapshot, would make the band vacuous."""
    snaps = calibration_snapshots(6, base=9_000)
    sizes = [estimate_bytes(s) for s in snaps]
    assert len(snaps) >= 3, "the fixture must materialize objects"
    assert all(sz > 4_000 for sz in sizes), sizes
    assert len(set(sizes)) > 1, f"the estimator returns one number for all: {sizes}"
    # …and it is the SNAPSHOT it reads: an item with no snapshot costs the
    # overhead alone, which is what a synthetic test item is worth.
    assert estimate_bytes(None) == 512, estimate_bytes(None)


def test_E11a_the_estimator_is_calibrated_against_a_tracemalloc_standalone():
    """THE CALIBRATION. `estimate_bytes` must read within **0.80x-1.30x** of the
    memory the process gives back when N real snapshots are dropped and nothing
    else holds them — the STANDALONE figure §6a sizes the bound against.

    Measured here: **~1.10x** over 200+ engine-built objects. Both mutants are
    EXECUTED, not described:

      * charge catalog-owned objects (template titles, owner strings, the shared
        `inapplicable` HypothesisScore objects) to every item and the same
        measurement lands at ~1.49x — out of band;
      * re-add the slice double count (charge every slice signal at 1 KiB, when
        100 % of them are already held by the item's own snapshot nodes) and it
        lands well above 1.30x too.

    SKIPS CLEANLY when tracemalloc is unavailable or already tracing — its
    counters are process-global, so a second instrument would be measuring this
    one."""
    if tracemalloc.is_tracing():
        pytest.skip("tracemalloc is already tracing this process")
    # Warm every lazily built structure a first call would allocate — the
    # catalog plan, the clause-kinds cache, the estimator's per-type field table
    # and its per-catalog ownership set — so none of it is charged to the items
    # inside the traced window.
    warm = calibration_snapshots(6, base=7_000)
    estimate_bytes(warm[0])
    RM.estimate_result_bytes(warm[0], frozenset())
    del warm
    gc.collect()

    try:
        tracemalloc.start(1)
    except (RuntimeError, ValueError) as exc:   # pragma: no cover - exotic build
        pytest.skip(f"tracemalloc unavailable: {exc}")
    try:
        gc.collect()
        snaps = calibration_snapshots(CALIBRATION_MIN_ITEMS)
        gc.collect()
        held = tracemalloc.get_traced_memory()[0]
        n = len(snaps)
        estimated = sum(estimate_bytes(s) for s in snaps)
        # MUTANT 1: no ownership rule — the catalog charged to every item.
        no_ownership = sum(512 + RM.estimate_result_bytes(s, frozenset())
                           for s in snaps)
        # MUTANT 2: the slice double count restored. 100 % of a real archive
        # slice is the signals of the item's own nodes (§5), so charging the
        # whole slice at 1 KiB/signal is exactly this.
        double_slice = estimated + sum(_node_signals(s) * 1024 for s in snaps)
        nodes = sum(len(s.nodes) for s in snaps) / n
        del snaps
        gc.collect()
        after = tracemalloc.get_traced_memory()[0]
    finally:
        tracemalloc.stop()

    standalone = held - after
    assert n >= CALIBRATION_MIN_ITEMS, f"only {n} items measured"
    assert standalone > 0, "tracemalloc saw nothing freed — the reference is broken"
    per_item = standalone / n
    assert 2_000 <= per_item <= 200_000, f"{per_item:.0f} B/item is not an object"
    assert nodes >= 2.0, f"{nodes:.1f} nodes/item — the fixture went trivial"
    ratio = estimated / standalone
    assert 0.80 <= ratio <= 1.30, (
        f"estimator {estimated} vs tracemalloc standalone {standalone} = "
        f"{ratio:.3f}x over {n} items ({per_item / 1024:.1f} KiB/item)")
    assert no_ownership / standalone > 1.30, (
        f"ownership-off ratio {no_ownership / standalone:.3f}x is inside the "
        "band — the catalog-ownership rule is not what is doing the work")
    assert double_slice / standalone > 1.30, (
        f"slice-double-count ratio {double_slice / standalone:.3f}x is inside "
        "the band — the loose-only slice rule is not what is doing the work")


def test_E11b_only_the_LOOSE_slice_signals_are_charged():
    """THE SLICE RULE, against the real `main._archive_slice`.

    A slice is "every signal of every component node, PLUS the loose ones"
    (`*_clear`, `source=app_identity`, matched identity signals). The node part
    is a second reference to signals the snapshot already holds — measured at
    100 % of the slice on the offline fixture — so only the loose remainder may
    be charged.

    MUTANT: charge `len(slice_sigs)` instead of the loose count and the second
    assertion below goes red by 9 KiB on this fixture alone."""
    main._WINDOW_INDEX_CACHE.clear()
    window = wide_component(4_242)
    snaps = run_window(window, CAT, (), CFG)
    assert snaps, "fixture must materialize an object"
    snap = snaps[0]
    slice_sigs = main._archive_slice(snap, window)
    assert slice_sigs, "the fixture must produce a real archive slice"
    assert loose_slice_signals(snap, slice_sigs) == 0, (
        "every signal of this slice is held by the object's own nodes")
    assert estimate_bytes(snap, slice_sigs) == estimate_bytes(snap), (
        "a fully node-owned slice must add nothing")
    assert estimate_bytes(snap, slice_sigs) < estimate_bytes(snap) + (
        len(slice_sigs) * 1024), "the double count is back"

    # Now the LOOSE half, which is the part a live estate has and this fixture
    # otherwise does not: a `*_clear` is excluded from build_nodes, so it lands
    # in the slice held by nothing but the item.
    main._WINDOW_INDEX_CACHE.clear()
    # INSIDE the object's own span (`_archive_slice` keeps a loose signal only
    # while `window_start <= ts <= window_end`), which for this component starts
    # at `4_242 * 0.01`.
    base = 4_242 * 0.01
    clears = [sig("if_util_high_clear", "cal4242:Gi0/1", offset_s=base + 5),
              sig("if_errors_high_clear", "cal4242:Gi0/1", offset_s=base + 6)]
    window2 = window + clears
    snaps2 = run_window(window2, CAT, (), CFG)
    snap2 = snaps2[0]
    slice2 = main._archive_slice(snap2, window2)
    loose = loose_slice_signals(snap2, slice2)
    assert loose == 2, f"the two clears must be loose, got {loose}"
    assert (estimate_bytes(snap2, slice2)
            == estimate_bytes(snap2, None) + 2 * 1024), (
        "each loose signal is charged exactly one measured Signal (1 KiB)")
    # …and the floor holds if the two lists ever disagree.
    assert loose_slice_signals(snap2, slice2[:1]) == 0


def test_E11c_OPEN_OBJECTS_ownership_is_NOT_discounted(_stack):
    """THE INVERTED RULE (§6b item 3). The rank memo charges catalog-owned
    objects zero because the catalog outlives every entry. A live open object
    does NOT outlive its queued item — it closes, and the item becomes the sole
    holder (measured: 45 % of a pinned 5,000-item queue shared its snapshot at
    `drained`, 0 % once the objects closed).

    So the estimate must be identical whether or not the object is open. MUTANT:
    add an `OPEN_OBJECTS` ownership set to the walk and this goes red."""
    snap = run_window(wide_component(11), CAT, (), CFG)[0]
    before = estimate_bytes(snap)
    main.OPEN_OBJECTS[snap.correlation_id] = {"snapshot": snap, "state": "open"}
    try:
        assert estimate_bytes(snap) == before, (
            "an OPEN object must not make its queued item look cheaper")
    finally:
        main.OPEN_OBJECTS.pop(snap.correlation_id, None)
    assert estimate_bytes(snap) == before


def test_E11d_the_estimate_is_deterministic_and_content_derived():
    """`sys.getsizeof`, `len` and `id` only — `id` as a membership token, never
    in the sum. Two engine runs over the SAME evidence must estimate identically
    (different objects, different addresses), and a repeat call must not drift."""
    main._WINDOW_INDEX_CACHE.clear()
    a = run_window(wide_component(77), CAT, (), CFG)[0]
    b = run_window(wide_component(77), CAT, (), CFG)[0]
    assert a is not b
    assert estimate_bytes(a) == estimate_bytes(b) == estimate_bytes(a)
    # A structurally BIGGER object must cost more — the walk reads the graph.
    big = run_window(wide_component(78) + wide_component(79), CAT, (), CFG)
    assert max(estimate_bytes(s) for s in big) > 0


def test_E11e_the_estimate_costs_less_than_a_persist():
    """COST. The walk runs on the DECISION path, once per persisted version, and
    only when a queue is actually active. Measured 0.24-0.38 ms/item on a
    15-27 KiB item — ~13-14 us per KiB walked, the same per-byte cost as
    `rank_memo`'s calibrated walk — against a persist path of ~7 ms/version.

    The ceiling asserted here is deliberately loose (2 ms/item, best of three) —
    this runs on shared CI hardware and the number that matters is the one in
    the docstring. It is a TRIPWIRE for an estimator that becomes quadratic, not
    a benchmark."""
    snaps = calibration_snapshots(40, base=3_000)
    for s in snaps[:5]:                     # warm the ownership set + type table
        estimate_bytes(s)
    best = float("inf")
    for _ in range(3):
        t0 = time.perf_counter()
        for s in snaps:
            estimate_bytes(s)
        best = min(best, (time.perf_counter() - t0) / len(snaps))
    assert best < 2e-3, f"{best * 1000:.3f} ms/item — the estimator went quadratic"


def test_E11f_the_measured_bounds_are_the_defaults():
    """The two knobs are MEASURED numbers (§6a): 2,000 items = 55.2 MiB
    standalone, 64 MiB = ~2,200 items at the measured 29 KiB/item, so the two
    bounds agree and either can hold the line. A silent revert to 5,000 / 512
    MiB would put the queue back at 142 MiB worst case on a 1.25 GiB container.

    Skipped (not failed) when the environment overrides them — an operator's
    knob is not a regression."""
    for knob in ("CORR_EVIDENCE_QUEUE_MAX", "CORR_EVIDENCE_QUEUE_BYTES_MAX"):
        if os.environ.get(knob):
            pytest.skip(f"{knob} is set in the environment")
    src = main.__dict__
    assert src["CORR_EVIDENCE_QUEUE_MAX"] == 2000
    assert src["CORR_EVIDENCE_QUEUE_BYTES_MAX"] == 64 * 1024 * 1024
    # The byte bound must be able to BIND: at the measured ~29 KiB/item it has
    # to sit near the item bound, not three orders of magnitude above it.
    assert (src["CORR_EVIDENCE_QUEUE_BYTES_MAX"] / 29_850
            < 2 * src["CORR_EVIDENCE_QUEUE_MAX"]), (
        "the byte bound is inert again — it cannot bind before the item bound")


def test_E11g_the_bounds_and_the_estimator_mean_are_readable(_stack):
    """§10. A bound nobody can scrape is a bound nobody will notice failing, and
    `est_bytes_mean` is the ONLY live view of the estimator outside the bench —
    the number that says whether the measured 29.9 KiB/item still holds on a
    real estate."""
    async def go():
        _stack.setattr(main, "ch", _RecCH())
        q = main._evidence_ensure_consumer()
        assert q is not None
        snap = run_window(mixed_window(2), CAT, (), CFG)[0]
        q.hold()
        for v in range(1, 5):
            await q.put(EvidenceItem(
                correlation_id=f"cid-mean-{v}", tenant_id=snap.tenant_id,
                version=v, state="open", tok=f"tok:{v}", snap=snap,
                priority_class=EVIDENCE_CLASS_DECISION,
                window_start_ts=snap.window_start.timestamp(), est_bytes=2000))
        stats = main.evidence_stats()
        assert stats["est_bytes_mean"] == 2000.0, stats["est_bytes_mean"]
        assert stats["max_items"] == main.CORR_EVIDENCE_QUEUE_MAX
        assert stats["max_bytes"] == main.CORR_EVIDENCE_QUEUE_BYTES_MAX
        text = main._metrics_text()
        for series, value in (
                ("corr_evidence_queue_max_items", stats["max_items"]),
                ("corr_evidence_queue_bytes_max", stats["max_bytes"]),
                ("corr_evidence_queue_est_bytes_mean", stats["est_bytes_mean"])):
            assert f"# TYPE {series} " in text, f"{series} missing from /metrics"
            assert f"\n{series} {value}\n" in text + "\n", (
                f"{series} does not carry evidence_stats()['{series}']")
        assert main.epoch_state()["evidence"]["est_bytes_mean"] == 2000.0
        # …and the key exists with the plane OFF, so a dashboard never reads a
        # missing key as a zero (the E9 rule).
        await q.release()
        await main._evidence_stop()
        assert "est_bytes_mean" in main.evidence_stats()
    asyncio.run(go())


def _warm_instance_caches(snap) -> None:
    """Ask for every derived value the engine memoizes on a frozen instance —
    the state a snapshot is in by the time it has been persisted once."""
    snap.node_index()
    snap.content_hash()
    snap.material_hash()
    snap.identity_refs()
    snap.grounded_seam_ids()
    snap.agg_provenance()
    # `signal_id` is a PROPERTY whose read is the cache write, so the values are
    # collected and counted rather than evaluated and dropped.
    minted = [signal.signal_id for node in snap.nodes for signal in node.signals]
    assert len(minted) == sum(len(node.signals) for node in snap.nodes)
    for seam in snap.seams:
        seam.membership_values()


def test_E11h_a_populated_instance_cache_is_charged_and_tracks_the_walk():
    """THE CACHED PROJECTIONS (rank_memo, `MEMO_CACHED_ATTRS`). An
    `ObjectSnapshot` memoizes six derived values on itself via
    `object.__setattr__` — `node_index`, `content_hash`, `material_hash`,
    `identity_refs`, `grounded_seam_ids`, `agg_provenance` — and its signals and
    seams memoize one each. None of them is a dataclass field, so until
    2026-09-03 the walk never reached them and the queue believed a persisted
    item was CHEAPER than the memory it held: `node_index` alone is a dict of
    one entry per node, allocated on first use and freed only with the snapshot.

    The claim is exact, not banded: whatever the reference `gc.get_referents`
    walk gains when the caches are populated, the estimator must gain the SAME
    number — the caches hold no new leaves, only new containers over strings and
    nodes the walk had already charged once.

    MUTANT: drop `MEMO_CACHED_ATTRS` from `_walk`'s plan (or the `, None`
    default that makes an unpopulated cache free) and the estimator's delta
    falls to 0 while the reference's does not."""
    snaps = calibration_snapshots(12, base=21_000)
    owned = RM._owned_ids(snaps[0].ranking.catalog_version)
    assert owned, "the catalog ownership set did not resolve"
    cold_est = [RM.estimate_result_bytes(s, owned) for s in snaps]
    cold_ref = [reference_deep_bytes(s, None, owned) for s in snaps]
    for snap in snaps:
        _warm_instance_caches(snap)
    warm_est = [RM.estimate_result_bytes(s, owned) for s in snaps]
    warm_ref = [reference_deep_bytes(s, None, owned) for s in snaps]

    gained_est = sum(warm_est) - sum(cold_est)
    gained_ref = sum(warm_ref) - sum(cold_ref)
    assert gained_ref > 0, "the fixture populated no cache — the test is vacuous"
    assert gained_est == gained_ref, (gained_est, gained_ref)
    # …and the estimate still tracks the walk item by item, warm and cold.
    for est, ref in list(zip(cold_est, cold_ref)) + list(zip(warm_est, warm_ref)):
        assert 0.75 <= est / ref <= 1.30, (est, ref)
    # An UNPOPULATED cache is free: a fresh copy (which by the recompute-on-copy
    # rule carries none of them) must read the cold number, not the warm one.
    fresh = dataclasses.replace(snaps[0])
    assert RM.estimate_result_bytes(fresh, owned) == cold_est[0]


def test_E11i_every_instance_cache_is_declared_to_the_byte_meter():
    """THE DRIFT GUARD for E11h. `MEMO_CACHED_ATTRS` is a hand-written list, so
    the next `object.__setattr__(self, "_x_c", ...)` cache would be invisible to
    the meter exactly the way `node_index` was. Every such name in the engine
    and signal modules must be declared by a class in that module, and every
    declared name must exist in it — a stale declaration is silently free."""
    for module in (engine, signals):
        src = pathlib.Path(module.__file__).read_text(encoding="utf-8")
        # Every PRIVATE name written through `object.__setattr__` — not just the
        # `_x_c` convention, so a cache that breaks the convention is caught too.
        written = set(re.findall(
            r'object\.__setattr__\(\s*self,\s*"(_[A-Za-z0-9_]+)"', src))
        assert written, f"{module.__name__}: the source scan found no cache"
        declared: set[str] = set()
        fields: set[str] = set()
        for value in vars(module).values():
            if not (isinstance(value, type) and value.__module__ == module.__name__):
                continue
            if dataclasses.is_dataclass(value):
                fields |= {f.name for f in dataclasses.fields(value)}
            if "MEMO_CACHED_ATTRS" in vars(value):
                names = value.MEMO_CACHED_ATTRS
                assert isinstance(names, tuple), (value, names)
                # …and declaring one must not have turned it into a FIELD.
                assert "MEMO_CACHED_ATTRS" not in {
                    f.name for f in dataclasses.fields(value)}, value
                declared |= set(names)
        # A write to a real FIELD (the __post_init__ cap/normalize pattern) is
        # already walked as a field; only the non-field writes are caches.
        cached = written - fields
        assert cached, f"{module.__name__}: no non-field instance cache found"
        assert cached <= declared, (
            f"{module.__name__}: undeclared instance caches {cached - declared} "
            "— the byte meter cannot see them (rank_memo, THE CACHED PROJECTIONS)")
        assert declared <= cached, (
            f"{module.__name__}: declared but never set {declared - cached}")
