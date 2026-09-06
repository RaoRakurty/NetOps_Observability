# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Ultra-review findings 15, 16, 17, 19 (main.py) and 18 (engine.py).

Every test here pins one CONFIRMED defect's fix, written so that reverting the
fix turns exactly that test red:

  * **#15 liveness** — the engine parked FOREVER in `EvidenceQueue.put` under
    backpressure once the consumer task died (cancellation, or a BaseException
    escaping its `except Exception`): no timeout, no done-callback, and
    `_evidence_ensure_consumer` was only called from the coroutine that was
    parked. Now: the consumer task's done-callback wakes queue waiters, a
    parked put re-checks liveness (wake + CORR_EVIDENCE_PUT_RECHECK_S belt)
    and escapes with `EvidencePutAborted`, and `_evidence_put` revives the
    consumer ON THE SAME QUEUE — nothing stranded, backpressure semantics
    under a HEALTHY consumer unchanged (test three pins that).
  * **#16 replay pin** — a LOST item never reverted the optimistically
    recorded `_ARCHIVE_SLICE_HASH`, so later unchanged-membership versions
    were damped against a slice that never landed. Now every loss path
    reverts through `_archive_slice_revert` (counted + logged).
  * **#17 silent buffer loss** — plane replacement cleared `_EVIDENCE_PENDING`
    and rebuilt the batcher, discarding unflushed buffered rows in no outcome.
    Now: same-loop revival KEEPS the batcher (rows still flush); dead-loop
    replacement counts every buffered row (`batch_rows_abandoned_total`) and
    every unsettled item (outcome=lost), loudly.
  * **#19 lifecycle KeyError** — quiesce and the cap loop indexed
    `OPEN_OBJECTS[cid]` after awaits while a rebalance `_forget_object` could
    run concurrently, aborting the WHOLE pass. Now `.get` + skip + counter,
    mirroring the merge loop, and `.pop` on the post-persist removal.
  * **#18 observability** — the cohort branch's adjacency ceiling record
    reported `len(idx.adj_pairs)` (the full inventory) instead of the
    cohort-emitted size.
"""
from __future__ import annotations

import asyncio
import contextlib
from datetime import datetime, timedelta, timezone
from typing import Any, cast

import pytest

import main
from engine import TopologyAdjacency, _CandidateIndex, _emit_candidates
from evidence_plane import (
    EVIDENCE_CLASS_DECISION,
    EvidenceItem,
    EvidencePutAborted,
    EvidenceQueue,
)
from test_p2_evidence_async import _reset_engine_state

EDGES = "netops.corr_edges"


class _Died(BaseException):
    """A non-Exception, non-CancelledError escape — the class `except
    Exception` cannot see. Deliberately NOT KeyboardInterrupt/SystemExit,
    which asyncio re-raises into the loop itself."""


def _mkitem(cid: str, version: int, *, slice_hash: str = "",
            slice_sigs: list | None = None) -> EvidenceItem:
    return EvidenceItem(
        correlation_id=cid, tenant_id="t1", version=version, state="open",
        tok=f"{cid}:{version}", snap=None,
        priority_class=EVIDENCE_CLASS_DECISION, window_start_ts=1.0,
        slice_sigs=slice_sigs, slice_hash=slice_hash)


async def _spin(n: int = 20) -> None:
    for _ in range(n):
        await asyncio.sleep(0)


@pytest.fixture
def _plane(monkeypatch):
    """A clean Evidence plane + clean counters, restored on the way out."""
    _reset_engine_state()
    monkeypatch.setattr(main, "OPEN_OBJECTS", {})
    monkeypatch.setattr(main, "_EVIDENCE_QUEUE", None)
    monkeypatch.setattr(main, "_EVIDENCE_TASK", None)
    monkeypatch.setattr(main, "_EVIDENCE_LOOP", None)
    monkeypatch.setattr(main, "_EVIDENCE_BATCHER", None)
    monkeypatch.setattr(main, "_EVIDENCE_FLUSHER", None)
    monkeypatch.setattr(main, "EVIDENCE_ITEMS_MATERIALIZED", 0)
    monkeypatch.setattr(main, "EVIDENCE_ITEMS_FAILED", 0)
    monkeypatch.setattr(main, "EVIDENCE_ITEMS_LOST", 0)
    monkeypatch.setattr(main, "EVIDENCE_CONSUMER_REVIVED", 0)
    monkeypatch.setattr(main, "EVIDENCE_BATCH_ROWS_ABANDONED", 0)
    monkeypatch.setattr(main, "ARCHIVE_SLICE_REVERTS", 0)
    monkeypatch.setattr(main, "LIFECYCLE_FORGOTTEN_SKIPPED_TOTAL", 0)
    # Monotonic process counter another suite may already have moved (this file
    # asserts absolute values); monkeypatch restores the pre-test value.
    monkeypatch.setattr(main, "OPEN_OBJECTS_FORCE_CLOSED", 0)
    monkeypatch.setattr(main, "CORR_EVIDENCE_ASYNC", True)
    monkeypatch.setattr(main, "CORR_EVIDENCE_BATCH", False)
    monkeypatch.setattr(main, "CORR_DECISION_BATCH", False)
    monkeypatch.setattr(main, "CORR_EVIDENCE_QUEUE_MAX", 5000)
    monkeypatch.setattr(main, "CORR_EVIDENCE_QUEUE_BYTES_MAX", 1 << 30)
    monkeypatch.setattr(main, "CORR_EVIDENCE_DRAIN_ON_STOP_S", 10.0)
    monkeypatch.setattr(main, "CORR_EVIDENCE_PUT_RECHECK_S", 0.05)
    # Registered at their current value so teardown restores whatever a test
    # (or a helper it drives) assigned directly.
    for _name in ("_write_evidence", "ch_insert", "VERSIONS_PERSISTED",
                  "CORR_QUIESCE_S",
                  "CORR_OPEN_OBJECTS_MAX", "_persist_snapshot",
                  "_affected_final", "_wa_note_outcome", "_seed_tenant_owned"):
        monkeypatch.setattr(main, _name, getattr(main, _name))
    yield monkeypatch
    main._EVIDENCE_PENDING.clear()
    _reset_engine_state()


# ═══ #15 — consumer death cannot park the engine ═════════════════════════════

def test_15_put_escapes_and_revives_when_the_consumer_is_cancelled(_plane):
    """THE scenario of the finding: queue at its bound, engine parked in put,
    consumer killed by cancellation mid-write. The put must escape, the
    consumer must be revived ON THE SAME QUEUE (no stranded backlog), and
    every item except the one killed mid-write must still land."""
    async def go():
        writes: list[tuple[str, int]] = []
        gate = asyncio.Event()

        async def parked_write(item, loop_yield=None, emit=None):
            writes.append((item.correlation_id, item.version))
            await gate.wait()
            return True

        _plane.setattr(main, "_write_evidence", parked_write)
        _plane.setattr(main, "CORR_EVIDENCE_QUEUE_MAX", 1)
        q = main._evidence_ensure_consumer()
        assert q is not None
        await q.put(_mkitem("cid-a", 1))
        await _spin()
        assert writes == [("cid-a", 1)], "consumer must be parked mid-write"
        await q.put(_mkitem("cid-b", 1))          # queue now AT its bound
        putter = asyncio.ensure_future(
            main._evidence_put(q, _mkitem("cid-c", 1)))
        await asyncio.sleep(0.02)
        assert not putter.done(), "healthy consumer: put parks (backpressure)"

        main._EVIDENCE_TASK.cancel()              # kill it mid-write
        await asyncio.wait_for(putter, 5.0)       # ← the engine ESCAPES

        assert main.EVIDENCE_CONSUMER_REVIVED == 1
        assert main._EVIDENCE_TASK is not None and not main._EVIDENCE_TASK.done()
        assert main._EVIDENCE_QUEUE is q, (
            "revival keeps the SAME queue — a replacement would have stranded "
            "the backlog as lost")
        gate.set()
        assert await main.evidence_drain(10.0) == 0
        assert main.EVIDENCE_ITEMS_LOST == 1, "only the mid-write item is lost"
        assert ("cid-b", 1) in writes and ("cid-c", 1) in writes
        assert main.EVIDENCE_ITEMS_MATERIALIZED == 2
        assert q.inflight == 0, "the killed item's begin() was balanced"
        await main._evidence_stop()
    asyncio.run(go())


def test_15_put_escapes_when_the_consumer_dies_of_a_non_exception_error(_plane):
    """Same scenario, but the consumer dies of a BaseException that escapes
    `except Exception` — the exact class the finding names. The item in hand
    is counted lost, the queue's inflight is balanced, and the parked put
    escapes and is served by the revived consumer."""
    async def go():
        gate = asyncio.Event()

        async def dying_write(item, loop_yield=None, emit=None):
            if item.correlation_id == "cid-a":
                await gate.wait()
                raise _Died("simulated non-Exception death")
            return True

        _plane.setattr(main, "_write_evidence", dying_write)
        _plane.setattr(main, "CORR_EVIDENCE_QUEUE_MAX", 1)
        q = main._evidence_ensure_consumer()
        assert q is not None
        await q.put(_mkitem("cid-a", 1))
        await _spin()
        await q.put(_mkitem("cid-b", 1))          # at the bound
        putter = asyncio.ensure_future(
            main._evidence_put(q, _mkitem("cid-c", 1)))
        await asyncio.sleep(0.02)
        assert not putter.done()

        gate.set()                                 # write raises _Died → task dies
        await asyncio.wait_for(putter, 5.0)        # ← the engine ESCAPES

        assert main.EVIDENCE_CONSUMER_REVIVED == 1
        assert main._EVIDENCE_TASK is not None and not main._EVIDENCE_TASK.done()
        assert main._EVIDENCE_QUEUE is q
        assert await main.evidence_drain(10.0) == 0
        assert main.EVIDENCE_ITEMS_LOST == 1
        assert main.EVIDENCE_ITEMS_MATERIALIZED == 2
        assert q.inflight == 0, (
            "a BaseException escape must still balance queue.begin() or "
            "idle()/drain lie forever")
        await main._evidence_stop()
    asyncio.run(go())


def test_15_backpressure_under_a_healthy_consumer_is_unchanged(_plane):
    """The semantics clause: with a live (merely slow) consumer the put still
    BLOCKS until room appears — several recheck intervals long — with no
    revival, no abort, no loss, and one backpressure count."""
    async def go():
        async def slow_write(item, loop_yield=None, emit=None):
            await asyncio.sleep(0.1)               # >> CORR_EVIDENCE_PUT_RECHECK_S
            return True

        _plane.setattr(main, "_write_evidence", slow_write)
        _plane.setattr(main, "CORR_EVIDENCE_QUEUE_MAX", 1)
        _plane.setattr(main, "CORR_EVIDENCE_PUT_RECHECK_S", 0.02)
        q = main._evidence_ensure_consumer()
        assert q is not None
        await q.put(_mkitem("cid-a", 1))
        await _spin()
        await q.put(_mkitem("cid-b", 1))
        t0 = asyncio.get_running_loop().time()
        await main._evidence_put(q, _mkitem("cid-c", 1))
        waited = asyncio.get_running_loop().time() - t0
        assert waited >= 0.05, (
            f"the put must have genuinely waited for room, not bailed at the "
            f"first recheck (waited {waited * 1000:.0f} ms)")
        assert main.EVIDENCE_CONSUMER_REVIVED == 0, "no revival: it never died"
        assert q.backpressure_total == 1
        assert await main.evidence_drain(10.0) == 0
        assert main.EVIDENCE_ITEMS_MATERIALIZED == 3
        assert main.EVIDENCE_ITEMS_LOST == 0
        await main._evidence_stop()
    asyncio.run(go())


def test_15_put_abort_raises_without_enqueueing():
    """The queue-level contract `_evidence_put` builds on: an abort escape
    mutates NOTHING (no enqueue, no byte accounting)."""
    async def go():
        q = EvidenceQueue(1, 1 << 30)
        await q.put(_mkitem("cid-a", 1))
        with pytest.raises(EvidencePutAborted):
            await q.put(_mkitem("cid-b", 1), abort=lambda: True, recheck_s=0.01)
        assert q.qsize() == 1
        assert q.pending()[0].correlation_id == "cid-a"
    asyncio.run(go())


# ═══ #16 — the slice hash is reverted on EVERY loss path ═════════════════════

def _park_forever():
    """A `_write_evidence` stand-in that parks until cancelled, signalling when
    the item is in hand."""
    started = asyncio.Event()

    async def park(item, loop_yield=None, emit=None):
        started.set()
        await asyncio.Event().wait()
        return True
    return park, started


def test_16_cancel_mid_write_reverts_the_optimistic_slice_hash(_plane):
    """The item CARRIED the slice write and was killed mid-write: the record
    must be reverted (else every later unchanged-membership version damps
    against a slice that never landed) and the revert counted."""
    async def go():
        park, started = _park_forever()
        _plane.setattr(main, "_write_evidence", park)
        main._ARCHIVE_SLICE_HASH["cid-a"] = "h1"      # the optimistic record
        q = main._evidence_ensure_consumer()
        assert q is not None
        await q.put(_mkitem("cid-a", 2, slice_hash="h1", slice_sigs=[object()]))
        await asyncio.wait_for(started.wait(), 5.0)
        task = main._EVIDENCE_TASK
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        assert "cid-a" not in main._ARCHIVE_SLICE_HASH, (
            "a lost slice must leave no damping record behind (ultra #16)")
        assert main.ARCHIVE_SLICE_REVERTS == 1
        assert main.EVIDENCE_ITEMS_LOST == 1
    asyncio.run(go())


def test_16_the_revert_is_guarded_on_identity_and_on_carrying_the_slice(_plane):
    """The two guards: a DAMPED item (slice_sigs None — its hash names an
    earlier, landed slice) must NOT revert; and an older version's loss must
    not clobber a NEWER version's record."""
    async def go():
        park, started = _park_forever()
        _plane.setattr(main, "_write_evidence", park)

        async def lose_by_cancel(item):
            started.clear()
            q = main._evidence_ensure_consumer()   # first start, then revival
            assert q is not None
            await q.put(item)
            await asyncio.wait_for(started.wait(), 5.0)
            task = main._EVIDENCE_TASK
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)

        # Damped item: same hash in the map, but it carried no slice write.
        main._ARCHIVE_SLICE_HASH["cid-d"] = "h-damped"
        await lose_by_cancel(_mkitem("cid-d", 3, slice_hash="h-damped",
                                     slice_sigs=None))
        assert main._ARCHIVE_SLICE_HASH.get("cid-d") == "h-damped", (
            "a damped item's loss must not revert the record of the slice "
            "that DID land")
        # Out-of-order loss: the map already carries a newer version's record.
        main._ARCHIVE_SLICE_HASH["cid-e"] = "h-newer"
        await lose_by_cancel(_mkitem("cid-e", 4, slice_hash="h-older",
                                     slice_sigs=[object()]))
        assert main._ARCHIVE_SLICE_HASH.get("cid-e") == "h-newer", (
            "an older version's loss must never clobber a newer record")
        assert main.ARCHIVE_SLICE_REVERTS == 0
    asyncio.run(go())


def test_16_stranded_queue_replacement_reverts_slice_hashes(_plane, caplog):
    """The stranded-replacement loss path: items abandoned with a dead loop
    revert their records exactly like the failed paths do — and the warning
    NAMES the gap that used to be silent."""
    held = _mkitem("cid-a", 2, slice_hash="h1", slice_sigs=[object()])
    damped = _mkitem("cid-b", 2, slice_hash="h2", slice_sigs=None)

    async def leg1():
        q = main._evidence_ensure_consumer()
        assert q is not None
        q.hold()                                   # park the consumer
        await q.put(held)
        await q.put(damped)
    asyncio.run(leg1())
    main._ARCHIVE_SLICE_HASH["cid-a"] = "h1"
    main._ARCHIVE_SLICE_HASH["cid-b"] = "h2"

    async def leg2():
        with caplog.at_level("WARNING", logger="correlation"):
            main._evidence_ensure_consumer()       # replacement: loop is gone
    asyncio.run(leg2())
    assert main.EVIDENCE_ITEMS_LOST == 2
    assert "cid-a" not in main._ARCHIVE_SLICE_HASH, "stranded slice reverted"
    assert main._ARCHIVE_SLICE_HASH.get("cid-b") == "h2", "damped record kept"
    assert main.ARCHIVE_SLICE_REVERTS == 1
    assert any("REVERTED" in r.getMessage() and "cid-a" in r.getMessage()
               for r in caplog.records), (
        "the revert must be logged, naming the object — that log IS the "
        "detection of the gap that used to be silent")


# ═══ #17 — replacement drains-or-counts the old batcher's buffers ════════════

def test_17_dead_loop_replacement_counts_the_batchers_buffers(_plane, caplog):
    """Rows buffered by a dead loop's batcher cannot be flushed (its lock,
    flusher and write tasks belong to that loop) — so they are counted and
    named, never silently discarded; unsettled pending items are counted
    lost."""
    _plane.setattr(main, "CORR_EVIDENCE_BATCH", True)
    item = _mkitem("cid-a", 1)

    async def leg1():
        q = main._evidence_ensure_consumer()
        assert q is not None
        main._EVIDENCE_PENDING[id(item)] = main._EvidencePending(item=item)
        await main._EVIDENCE_BATCHER.add(
            EDGES, [{"r": 1}, {"r": 2}], member=item, dedup_token="tok:edges:0")
    asyncio.run(leg1())
    assert main._EVIDENCE_BATCHER.buffered() == 2, "fixture: rows left buffered"

    async def leg2():
        with caplog.at_level("WARNING", logger="correlation"):
            main._evidence_ensure_consumer()
    asyncio.run(leg2())
    assert main.EVIDENCE_BATCH_ROWS_ABANDONED == 2, (
        "every buffered row of the dead batcher must land in a named outcome")
    assert main.EVIDENCE_ITEMS_LOST == 1, (
        "the unsettled pending item's outcome was counted nowhere before #17")
    assert len(main._EVIDENCE_PENDING) == 0
    assert any("ABANDONED" in r.getMessage() and EDGES in r.getMessage()
               and "tok:edges:0" in r.getMessage() for r in caplog.records), (
        "the loss must name the table and the member tokens")
    assert main.evidence_stats()["batch_rows_abandoned_total"] == 2


def test_17_same_loop_revival_keeps_the_batcher_and_its_rows_flush(_plane):
    """The 'flush if safe' half: when only the TASK died, the loop — and so
    the batcher — is alive. Revival keeps it; its rows still reach the sink."""
    _plane.setattr(main, "CORR_EVIDENCE_BATCH", True)
    writes: list[tuple[str, int]] = []

    async def rec_insert(table, rows, *, dedup_token=None, **ctx):
        writes.append((table, len(rows)))
        return True

    _plane.setattr(main, "ch_insert", rec_insert)

    async def go():
        q = main._evidence_ensure_consumer()
        assert q is not None
        batcher = main._EVIDENCE_BATCHER
        item = _mkitem("cid-a", 1)
        await batcher.add(EDGES, [{"r": 1}], member=item, dedup_token="t1")
        task = main._EVIDENCE_TASK
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        q2 = main._evidence_ensure_consumer()      # revival, same loop
        assert q2 is q and main._EVIDENCE_BATCHER is batcher, (
            "same-loop revival must keep the queue AND the batcher")
        assert batcher.buffered() == 1, "nothing abandoned on a live loop"
        await batcher.flush_all()
        assert writes == [(EDGES, 1)], "the kept buffer still flushed"
        assert main.EVIDENCE_BATCH_ROWS_ABANDONED == 0
        await main._evidence_stop()
    asyncio.run(go())


# ═══ #19 — lifecycle loops tolerate a concurrent forget ══════════════════════

class _Snap:
    def __init__(self, cid: str) -> None:
        self.correlation_id = cid
        self.tenant_id = "t1"


class _Epoch:
    def __init__(self, now: datetime) -> None:
        self.seen: set[str] = set()
        self.now = now


def _lifecycle_rig(_plane, *, forget_during_persist_of: str,
                   forgets: str) -> list[tuple[str, str, int]]:
    """Three open objects; persisting `forget_during_persist_of` concurrently
    forgets `forgets` (the rebalance race). Returns the persisted terminals."""
    now = datetime.now(timezone.utc)
    persisted: list[tuple[str, str, int]] = []
    for cid in ("c1", "c2", "c3"):
        main.OPEN_OBJECTS[cid] = {
            "version": 1, "hash": "h", "material": "m",
            "last_seen": now - timedelta(seconds=3600),
            "last_persist": now, "snapshot": _Snap(cid), "opened_at": now}

    async def persist(snap, version, state, _sigs, **kw):
        persisted.append((snap.correlation_id, state, version))
        if snap.correlation_id == forget_during_persist_of:
            main.OPEN_OBJECTS.pop(forgets, None)   # what _forget_object does
        await asyncio.sleep(0)

    async def affected(reg, snap):
        return None

    _plane.setattr(main, "_persist_snapshot", persist)
    _plane.setattr(main, "_affected_final", affected)
    _plane.setattr(main, "_wa_note_outcome", lambda *a, **k: None)
    _plane.setattr(main, "_seed_tenant_owned", lambda t: True)
    _plane.setattr(main, "_EVIDENCE_QUEUE", None)
    asyncio.run(main._epoch_lifecycle(
        cast(Any, _Epoch(now)), main._make_loop_yield()[0], seen=set()))
    return persisted


def test_19_quiesce_survives_a_concurrent_forget(_plane):
    """Pre-fix this pass ABORTED with KeyError at c2 and c3 never closed."""
    _plane.setattr(main, "CORR_QUIESCE_S", 0.0)
    _plane.setattr(main, "CORR_OPEN_OBJECTS_MAX", 0)     # cap disabled
    persisted = _lifecycle_rig(_plane, forget_during_persist_of="c1",
                               forgets="c2")
    assert [p[0] for p in persisted] == ["c1", "c3"], (
        "c2 was forgotten mid-pass: skipped, while c1 and c3 still close")
    assert all(state == "closed" for _c, state, _v in persisted)
    assert main.OPEN_OBJECTS == {}
    assert main.LIFECYCLE_FORGOTTEN_SKIPPED_TOTAL == 1


def test_19_the_count_cap_survives_a_concurrent_forget(_plane):
    """Same race inside the tracker-163 cap loop: the victims list is
    snapshotted before the loop's awaits, so a victim forgotten mid-loop must
    be skipped — the pass, and the bound, still complete."""
    _plane.setattr(main, "CORR_QUIESCE_S", 1e9)          # quiesce inert
    _plane.setattr(main, "CORR_OPEN_OBJECTS_MAX", 1)     # victims: c1, c2
    persisted = _lifecycle_rig(_plane, forget_during_persist_of="c1",
                               forgets="c2")
    assert [p[0] for p in persisted] == ["c1"]
    assert set(main.OPEN_OBJECTS) == {"c3"}, "the bound is still honoured"
    assert main.LIFECYCLE_FORGOTTEN_SKIPPED_TOTAL == 1
    assert main.OPEN_OBJECTS_FORCE_CLOSED == 1, (
        "a skipped-because-forgotten victim is NOT counted force-closed")


# ═══ #18 — the cohort ceiling records the cohort-emitted adjacency size ══════

def _adjacency_index(n: int = 10) -> _CandidateIndex:
    """`n` single-node devices with a FULL adjacency mesh (C(n,2) inventory
    pairs) and no other grouping dimension."""
    adjacency = TopologyAdjacency(frozenset(
        frozenset({f"d{i}", f"d{j}"})
        for i in range(n) for j in range(i + 1, n)))
    return _CandidateIndex(
        n, [frozenset()] * n, [frozenset()] * n, [],
        [f"d{i}" for i in range(n)], adjacency, None, None)


def test_18_cohort_ceiling_records_the_cohort_emitted_adjacency_size():
    """A one-node cohort in a 10-device full mesh emits 9 adjacency pairs; the
    ceiling record must say 9 — not the 45-pair inventory, which was never on
    the table and sends the investigation at the wrong population."""
    idx = _adjacency_index(10)
    stats: dict = {}
    cand = _emit_candidates(idx, cohort=frozenset({0}), ceiling=1, stats=stats)
    assert cand == {(0, j) for j in range(1, 10)}, "emission itself unchanged"
    assert stats.get("ceiling_hit") is True
    assert stats.get("ceiling_dimension") == "adjacency"
    assert stats.get("ceiling_group_size") == 9, (
        f"the record must carry the COHORT-emitted size, got "
        f"{stats.get('ceiling_group_size')}")
    assert stats.get("ceiling_group_size") != len(idx.adj_pairs), (
        "the mutant (full inventory size) must not satisfy this test")
    assert stats.get("ceiling_emitted") == 9


def test_18_full_window_ceiling_still_records_the_inventory_size():
    """The non-cohort branch emits `idx.adj_pairs` whole, so there the
    inventory size IS the emission — pinned unchanged."""
    idx = _adjacency_index(10)
    stats: dict = {}
    cand = _emit_candidates(idx, ceiling=1, stats=stats)
    assert len(cand) == 45
    assert stats.get("ceiling_dimension") == "adjacency"
    assert stats.get("ceiling_group_size") == 45 == len(idx.adj_pairs)


# ═══ observability plumbing ══════════════════════════════════════════════════

def test_the_new_counters_reach_evidence_stats_and_metrics(_plane):
    """§10: zeros, not absent keys — and the exposition lines exist."""
    stats = main.evidence_stats()
    assert stats["consumer_revived_total"] == 0
    assert stats["batch_rows_abandoned_total"] == 0
    body = main._metrics_text()
    for name in ("corr_evidence_consumer_revived_total",
                 "corr_evidence_batch_rows_abandoned_total",
                 "corr_archive_slice_reverts_total",
                 "corr_lifecycle_forgotten_skipped_total"):
        assert name in body, f"{name} missing from /metrics"


def test_a_stale_done_callback_of_a_replaced_task_is_inert(_plane):
    """The done-callback must not misfire for a task that is no longer THE
    consumer (revival replaces `_EVIDENCE_TASK`; the old task's callback still
    runs). Inert means: no log noise beyond its own death, no wake storm, and
    crucially no exception out of the callback."""
    async def go():
        park, started = _park_forever()
        _plane.setattr(main, "_write_evidence", park)
        q = main._evidence_ensure_consumer()
        assert q is not None
        await q.put(_mkitem("cid-a", 1))
        await asyncio.wait_for(started.wait(), 5.0)
        old = main._EVIDENCE_TASK
        old.cancel()
        await asyncio.gather(old, return_exceptions=True)
        q2 = main._evidence_ensure_consumer()      # revival installs a new task
        assert q2 is q and main._EVIDENCE_TASK is not old
        # The old task's callback already ran during gather; the plane must be
        # fully live afterwards.
        with contextlib.suppress(asyncio.TimeoutError):
            await asyncio.wait_for(asyncio.sleep(0.01), 1.0)
        assert not main._EVIDENCE_TASK.done()
        await main._evidence_stop()
    asyncio.run(go())
