"""Tracker 166 — the drain epoch, at the SCHEDULER level.

test_snapshot_epoch_166.py pins the pure engine's prep reuse. This file pins the
caller: that one drain sweep prepares ONCE however many cohorts it drains, that
the epoch's snapshot is genuinely immutable, and that failure in cohort N leaves
exactly the right things committed and pending.
"""
from __future__ import annotations

import asyncio

import pytest

import main
from test_prune_buffer_156 import mk


@pytest.fixture(autouse=True)
def _clean():
    main.WINDOW_BUFFER.clear(); main._BUFFERED_IDS.clear()
    main._BUFFERED_ID_ORDER.clear(); main._PROCESSED_IDS.clear()
    main.TENANT_WATERMARK.clear(); main._TENANT_EDGES.clear()
    main.COHORTS_PROCESSED = 0; main.COHORT_SIGNALS_TOTAL = 0
    main.PENDING_PEAK = 0
    main.EPOCHS_TOTAL = 0; main.EPOCH_PREPARATIONS = 0
    yield
    main._PROCESSED_IDS.clear(); main._TENANT_EDGES.clear()


def _load(n, tenant="acme", start=0):
    for i in range(n):
        s = main.dc_replace(mk(start + i, start + i), tenant_id=tenant)
        main.WINDOW_BUFFER.append(s)
        main._BUFFERED_ID_ORDER.append(str(s.signal_id))
        main._BUFFERED_IDS.add(str(s.signal_id))


class _StubCH:
    def __init__(self):
        self.rows: dict = {}

    async def insert(self, table, rows, **kw):
        self.rows.setdefault(table, []).extend(rows)
        return True


@pytest.fixture
def _stack(monkeypatch):
    monkeypatch.setattr(main, "ch", _StubCH())
    monkeypatch.setattr(main, "OPEN_OBJECTS", {})
    return monkeypatch


# ── the invariant: one epoch, one preparation, K cohorts (Phase 8) ───────────


@pytest.mark.parametrize("k", [1, 2, 4, 8])
def test_K_cohorts_in_one_epoch_prepare_ONCE(_stack, k):
    """THE tracker 166 invariant. Draining K cohorts against one unchanged
    snapshot must perform ONE per-tenant preparation, not K."""
    _stack.setattr(main, "CORR_ENGINE_COHORT_SIZE", max(1, 40 // k))
    _load(40)

    async def drive():
        epoch = await main._begin_epoch(main.datetime.now(main.timezone.utc))
        try:
            for _ in range(k):
                await main.engine_cycle(epoch)
        finally:
            main._close_epoch(epoch)

    asyncio.run(drive())
    assert main.EPOCHS_TOTAL == 1
    assert main.EPOCH_PREPARATIONS == 1, (
        f"{k} cohorts produced {main.EPOCH_PREPARATIONS} preparations for one "
        f"tenant — the snapshot state is being rebuilt per transaction")
    assert main.COHORTS_PROCESSED == k


def test_a_cohort_WITHOUT_an_epoch_still_prepares_its_own(_stack):
    """The control. `engine_cycle()` with no epoch must build one — otherwise
    the invariant test above is measuring nothing."""
    _load(20)
    asyncio.run(main.engine_cycle())
    assert main.EPOCHS_TOTAL == 1 and main.EPOCH_PREPARATIONS == 1
    asyncio.run(main.engine_cycle())
    assert main.EPOCHS_TOTAL == 2 and main.EPOCH_PREPARATIONS == 2


def test_preparations_track_epochs_not_cohorts(_stack):
    """Mutation-facing: if the prep is ever rebuilt per transaction this ratio
    becomes preparations == cohorts, which is the failing shape."""
    _stack.setattr(main, "CORR_ENGINE_COHORT_SIZE", 5)
    _load(40)

    async def drive():
        epoch = await main._begin_epoch(main.datetime.now(main.timezone.utc))
        try:
            for _ in range(8):
                await main.engine_cycle(epoch)
        finally:
            main._close_epoch(epoch)

    asyncio.run(drive())
    st = main.epoch_state()
    assert st["preparations"] == st["epochs"] == 1
    assert main.COHORTS_PROCESSED == 8
    assert st["preparations"] != main.COHORTS_PROCESSED


# ── the snapshot is genuinely immutable (Phase 3) ────────────────────────────


def test_signals_arriving_MID_EPOCH_wait_for_the_next_one(_stack):
    """Immutability, stated as behaviour: a signal ingested while an epoch is
    draining must not be admitted to that epoch — the epoch has no prepared node
    for it, and admitting it would mark it processed without evaluating it."""
    _stack.setattr(main, "CORR_ENGINE_COHORT_SIZE", 1000)
    _load(10)

    async def drive():
        epoch = await main._begin_epoch(main.datetime.now(main.timezone.utc))
        try:
            _load(10, start=500)          # arrives mid-epoch
            await main.engine_cycle(epoch)
            return epoch.pending()
        finally:
            main._close_epoch(epoch)

    remaining = asyncio.run(drive())
    assert remaining == [], "the epoch drained its own snapshot"
    # the late arrivals are still pending against the LIVE buffer
    assert len(main.pending_signals()) == 10, (
        "mid-epoch arrivals must survive as pending for the next epoch")


def test_no_signal_is_marked_processed_without_being_evaluated(_stack):
    """The failure this design exists to prevent: a cohort admitting a signal
    the epoch has no prepared node for would advance the frontier over evidence
    that was never scored."""
    _stack.setattr(main, "CORR_ENGINE_COHORT_SIZE", 1000)
    _load(15)

    async def drive():
        epoch = await main._begin_epoch(main.datetime.now(main.timezone.utc))
        try:
            snapshot_ids = {str(s.signal_id) for s in epoch.snapshot}
            _load(15, start=900)
            await main.engine_cycle(epoch)
            return snapshot_ids
        finally:
            main._close_epoch(epoch)

    snapshot_ids = asyncio.run(drive())
    assert main._PROCESSED_IDS <= snapshot_ids, (
        "the frontier advanced over signals the epoch never prepared")


def test_the_epoch_hands_run_window_the_SAME_window_object_every_cohort(_stack):
    """Object identity is the prep's reuse guard. A fresh-but-equal tuple per
    cohort would invalidate the prep silently and reinstate the whole defect."""
    _stack.setattr(main, "CORR_ENGINE_COHORT_SIZE", 5)
    _load(20)
    seen: list[int] = []
    real = main.run_window

    def spy(window, *a, **kw):
        seen.append(id(window))
        return real(window, *a, **kw)

    _stack.setattr(main, "run_window", spy)

    async def drive():
        epoch = await main._begin_epoch(main.datetime.now(main.timezone.utc))
        try:
            for _ in range(4):
                await main.engine_cycle(epoch)
        finally:
            main._close_epoch(epoch)

    asyncio.run(drive())
    assert len(seen) == 4
    assert len(set(seen)) == 1, (
        "run_window was handed a different window object per cohort — the "
        "identity guard cannot hold and the prep is rebuilt every transaction")


# ── lifecycle: the prepared state must not outlive its snapshot ──────────────


def test_closing_an_epoch_releases_the_prepared_state(_stack):
    _load(20)

    async def drive():
        epoch = await main._begin_epoch(main.datetime.now(main.timezone.utc))
        assert epoch.preps and epoch.snapshot
        main._close_epoch(epoch)
        return epoch

    epoch = asyncio.run(drive())
    assert epoch.preps == {} and epoch.ctx == {} and epoch.snapshot == ()
    assert epoch.live_keys == {}


def test_a_failing_cohort_still_releases_the_epoch(_stack):
    """Prepared state pins the whole retained node set. Leaking it on the error
    path would hold evidence the 165 horizon has already released."""
    _load(20)
    epochs: list = []

    def boom(*a, **kw):
        raise RuntimeError("scoring failed")

    # run_window, not _offload: _begin_epoch offloads the preparation itself, so
    # breaking _offload would fail the epoch before there is one to leak.
    _stack.setattr(main, "run_window", boom)

    async def drive():
        epoch = await main._begin_epoch(main.datetime.now(main.timezone.utc))
        epochs.append(epoch)
        try:
            await main.engine_cycle(epoch)
        finally:
            main._close_epoch(epoch)

    with pytest.raises(RuntimeError, match="scoring failed"):
        asyncio.run(drive())
    assert epochs[0].preps == {} and epochs[0].snapshot == (), (
        "the epoch leaked its prepared state on the failure path")


# ── failure safety across cohorts (Phase 11) ─────────────────────────────────


def test_cohorts_before_a_failure_stay_committed_and_the_failing_one_replays(_stack):
    """Cohort N fails: 1..N-1 are past their persistence boundary and their
    frontier advance stands; N's signals remain pending and fully replayable."""
    _stack.setattr(main, "CORR_ENGINE_COHORT_SIZE", 10)
    _load(40)
    calls = {"n": 0}
    real = main._persist_snapshot

    async def flaky(*a, **kw):
        calls["n"] += 1
        if calls["n"] > 2:
            raise RuntimeError("durability boundary failed")
        return await real(*a, **kw)

    _stack.setattr(main, "_persist_snapshot", flaky)

    async def drive():
        epoch = await main._begin_epoch(main.datetime.now(main.timezone.utc))
        completed = 0
        try:
            for _ in range(4):
                try:
                    await main.engine_cycle(epoch)
                except RuntimeError:
                    break
                completed += 1
        finally:
            main._close_epoch(epoch)
        return completed

    completed = asyncio.run(drive())
    assert main.COHORTS_PROCESSED == completed, (
        "the frontier advanced for a cohort that never reached persistence")
    assert len(main.pending_signals()) == 40 - completed * 10, (
        "the failed cohort's signals must remain pending and replayable")


def test_a_retry_after_failure_runs_on_a_FRESH_epoch(_stack):
    """Prepared state is never carried across an epoch boundary, so a retry can
    never see state derived from a window that has since changed."""
    _load(20)
    asyncio.run(main.engine_cycle())
    first = main.EPOCHS_TOTAL
    asyncio.run(main.engine_cycle())
    assert main.EPOCHS_TOTAL == first + 1
