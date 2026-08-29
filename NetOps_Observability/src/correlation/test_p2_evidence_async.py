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
import json
import random
import time
from datetime import datetime, timedelta, timezone

import pytest

import main
from catalog import builtin_catalog
from engine import EngineConfig, run_window
from evidence_plane import (
    EVIDENCE_CLASS_DECISION,
    EVIDENCE_CLASS_HEARTBEAT,
    EVIDENCE_CLASS_TERMINAL,
    EvidenceItem,
    EvidenceQueue,
    estimate_bytes,
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

    async def insert(self, table, rows, dedup_token="", **kw):
        rows = [dict(r) for r in rows]
        self.writes.append((table, rows, dedup_token))
        if self.delay_s:
            await asyncio.sleep(self.delay_s)
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
    monkeypatch.setattr(main, "CORR_COHORT_TOUCH_GATE", True)
    monkeypatch.setattr(main, "CORR_LIFECYCLE_EPOCH_CADENCE", True)
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
                est_bytes=estimate_bytes(len(snap.nodes), len(snap.edges), 0)))
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
