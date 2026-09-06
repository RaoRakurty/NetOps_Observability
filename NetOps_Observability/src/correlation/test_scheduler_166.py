# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Tracker 166 — the scheduler must bound new work per transaction.

The defect: the engine loop is single-flight (`cycle(); sleep(interval)`), so
the effective period is cycle+interval and the next transaction admits whatever
arrived during it. A slow transaction therefore SIZES the next one — 84 s plus
30 s at 400 eps accumulates ~45,600 signals, whose pairing is quadratic, which
makes the next transaction slower again.

What is bounded is NEW WORK. What is emphatically not bounded is retained
history: tracker 165's ~516.5 s horizon is a correctness contract and every
cohort is still scored against the whole of it.
"""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

import pytest

import main
from test_prune_buffer_156 import T0, mk


@pytest.fixture(autouse=True)
def _clean():
    main.WINDOW_BUFFER.clear(); main._BUFFERED_IDS.clear()
    main._BUFFERED_ID_ORDER.clear(); main._PROCESSED_IDS.clear()
    main.TENANT_WATERMARK.clear(); main._TENANT_EDGES.clear()
    main.COHORTS_PROCESSED = 0; main.COHORT_SIGNALS_TOTAL = 0
    main.PENDING_PEAK = 0
    yield
    main._PROCESSED_IDS.clear(); main._TENANT_EDGES.clear()


def _load(n, tenant="acme", start=0):
    for i in range(n):
        s = main.dc_replace(mk(start + i, start + i), tenant_id=tenant)
        main.WINDOW_BUFFER.append(s)
        main._BUFFERED_ID_ORDER.append(str(s.signal_id))
        main._BUFFERED_IDS.add(str(s.signal_id))


# ── the frontier ─────────────────────────────────────────────────────────────

def test_everything_starts_pending():
    _load(50)
    assert len(main.pending_signals()) == 50


def test_marking_processed_removes_from_pending():
    _load(50)
    cohort = main._select_cohort(main.pending_signals(), 20)
    main._mark_processed(cohort)
    assert len(main.pending_signals()) == 30


def test_the_frontier_is_bounded_by_the_window():
    """§9 — ids leave the frontier with the signals they describe, so it can
    never outgrow the window it is a property of."""
    _load(20)
    main._mark_processed(main.pending_signals())
    assert len(main._PROCESSED_IDS) == 20
    main.WINDOW_BUFFER.clear()
    for sid in list(main._BUFFERED_ID_ORDER):
        main._PROCESSED_IDS.discard(sid)
        main._BUFFERED_IDS.discard(sid)
    main._BUFFERED_ID_ORDER.clear()
    assert main._PROCESSED_IDS == set()


def test_a_timestamp_frontier_would_have_been_unsafe():
    """Why the frontier is a SET of ids and not a high-water timestamp: arrival
    is not monotonic in event time. An out-of-order signal landing behind a
    timestamp frontier would be treated as already processed and never
    evaluated — silent evidence loss, which is precisely what 165 forbids."""
    _load(10, start=100)                  # event times 100..109
    main._mark_processed(main.pending_signals())
    late = main.dc_replace(mk(1, 5), tenant_id="acme")   # arrives late, ts=5
    main.WINDOW_BUFFER.append(late)
    main._BUFFERED_ID_ORDER.append(str(late.signal_id))
    main._BUFFERED_IDS.add(str(late.signal_id))
    pending = main.pending_signals()
    assert [s.native_id for s in pending] == [late.native_id], (
        "a late signal behind the high-water mark must still be pending")


# ── bounded admission — the core invariant ───────────────────────────────────

@pytest.mark.parametrize("pending_n", [100, 1_000, 10_000, 30_000])
def test_one_transaction_never_admits_more_than_the_bound(pending_n):
    """THE tracker 166 invariant. Growing the backlog must produce MORE
    transactions, never a bigger one."""
    _load(pending_n)
    limit = 5_000
    cohort = main._select_cohort(main.pending_signals(), limit)
    assert len(cohort) <= limit, (
        f"{pending_n} pending admitted {len(cohort)} into one transaction")


def test_backlog_growth_does_not_enlarge_the_transaction():
    """Explicitly the 8k -> 80k case from the wave."""
    _load(8_000)
    small = len(main._select_cohort(main.pending_signals(), 5_000))
    _load(30_000, start=8_000)
    big = len(main._select_cohort(main.pending_signals(), 5_000))
    assert small == big == 5_000, (
        f"cohort grew with the backlog: {small} -> {big}")


def test_a_small_backlog_is_taken_whole():
    """The bound is a ceiling, not a quantum — no artificial batching delay."""
    _load(37)
    assert len(main._select_cohort(main.pending_signals(), 5_000)) == 37


def test_admission_preserves_arrival_order():
    """The engine's identity and continuation rules depend on onset ordering;
    admission may choose WHICH signals, never reorder the stream.

    MULTI-tenant on purpose: with one tenant the round-robin is a no-op and
    deleting the final re-sort survives the test. Interleaving tenants is the
    only way the round-robin can actually scramble arrival order.
    """
    _load(60, tenant="a", start=0)
    _load(60, tenant="b", start=60)
    pending = main.pending_signals()
    cohort = main._select_cohort(pending, 40)
    order = {id(s): i for i, s in enumerate(pending)}
    got = [order[id(s)] for s in cohort]
    assert got == sorted(got), (
        f"admission reordered the stream: {got[:12]}")
    assert len({s.tenant_id for s in cohort}) == 2, "fixture must interleave tenants"


# ── tenant fairness ──────────────────────────────────────────────────────────

def test_a_hot_tenant_cannot_starve_a_quiet_one():
    _load(20_000, tenant="hot")
    _load(10, tenant="quiet", start=50_000)
    cohort = main._select_cohort(main.pending_signals(), 1_000)
    tenants = {s.tenant_id for s in cohort}
    assert "quiet" in tenants, "the quiet tenant was starved out of the cohort"
    quiet = sum(1 for s in cohort if s.tenant_id == "quiet")
    assert quiet == 10, f"the quiet tenant should be fully served, got {quiet}"


def test_several_hot_tenants_share_the_cohort():
    for t in ("a", "b", "c"):
        _load(8_000, tenant=t, start=hash(t) % 1000 * 100)
    cohort = main._select_cohort(main.pending_signals(), 900)
    counts = {}
    for s in cohort:
        counts[s.tenant_id] = counts.get(s.tenant_id, 0) + 1
    assert len(counts) == 3, f"expected all three tenants served: {counts}"
    assert max(counts.values()) - min(counts.values()) <= 1, (
        f"round-robin should be near-even: {counts}")


def test_fairness_does_not_apply_when_everything_fits():
    """No reordering or round-robin cost when the whole backlog is admitted."""
    _load(10, tenant="a")
    _load(10, tenant="b", start=10)
    pending = main.pending_signals()
    cohort = main._select_cohort(pending, 5_000)
    assert [s.native_id for s in cohort] == [s.native_id for s in pending]


# ── pending-evidence visibility (phase 7) ────────────────────────────────────

def test_oldest_pending_age_is_reported_against_the_horizon():
    """A signal must not wait in the scheduler until it expires without that
    being visible. This is the number that says how close we are."""
    _load(100, start=0)
    st = main.scheduler_state()
    assert st["pending"] == 100
    assert st["oldest_pending_event_age_s"] == pytest.approx(99, abs=1)
    assert 0 < st["oldest_pending_horizon_fraction"] < 1


def test_pending_state_names_the_tenants():
    _load(10, tenant="a")
    _load(30, tenant="b", start=10)
    st = main.scheduler_state()
    assert st["pending_tenants"] == 2
    assert st["pending_max_tenant"] == 30


def test_the_frontier_advances_only_through_a_completed_cycle(monkeypatch):
    """The atomicity boundary. `_mark_processed` is reached at the very end of
    the cycle, after every tenant's snapshots have been through
    `_persist_snapshot`. A cycle that raises must leave its cohort pending and
    fully replayable — mutating the advance away, or moving it earlier, has to
    be visible."""
    import asyncio

    _load(40)
    assert len(main.pending_signals()) == 40

    class _StubCH:
        def __init__(self): self.rows = {}
        async def insert(self, table, rows, **kw):
            self.rows.setdefault(table, []).extend(rows); return True
    monkeypatch.setattr(main, "ch", _StubCH())
    monkeypatch.setattr(main, "OPEN_OBJECTS", {})
    before = main.COHORTS_PROCESSED
    asyncio.run(main.engine_cycle())
    assert main.COHORTS_PROCESSED == before + 1, "a completed cycle must advance"
    assert main.pending_signals() == [], "the cohort should now be processed"


def test_a_failed_cycle_leaves_the_cohort_pending(monkeypatch):
    """Failure safety: the frontier must not advance past work that did not
    complete, or the signals are silently never correlated."""
    import asyncio

    _load(40)

    async def _boom(*a, **kw):
        raise RuntimeError("persistence failed")
    monkeypatch.setattr(main, "ch", object())
    monkeypatch.setattr(main, "_prune_buffer", _boom)
    with pytest.raises(RuntimeError):
        asyncio.run(main.engine_cycle())
    assert len(main.pending_signals()) == 40, (
        "a failed transaction advanced the frontier over unprocessed work")


def test_stream_time_expiry_also_releases_the_frontier():
    """The frontier must shrink through BOTH exits from the window: the
    capacity cap and tracker 165's stream-time expiry. An earlier revision
    cleaned up only the capacity path, leaving an unbounded id set hiding
    inside a bounded window — it grows for the life of the process while the
    window it describes turns over completely."""
    import asyncio

    _load(60, start=0)
    main._mark_processed(main.pending_signals())
    assert len(main._PROCESSED_IDS) == 60

    # move the tenant's stream clock past the horizon so everything expires
    main.TENANT_WATERMARK["acme"] = (
        (T0 + timedelta(seconds=main.RETENTION_REQUIRED_S + 10_000)).timestamp(),
        time.monotonic())
    asyncio.run(main._prune_buffer(datetime.now(timezone.utc)))
    assert len(main.WINDOW_BUFFER) == 0
    assert main._PROCESSED_IDS == set(), (
        f"{len(main._PROCESSED_IDS)} frontier ids outlived their signals")
