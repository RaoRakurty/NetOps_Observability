# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Tracker 156 — window eviction must not recompute signal ids.

`_prune_buffer` and the maxlen-eviction branch of `buffer_signal` both did
`str(WINDOW_BUFFER[0].signal_id)` — a uuid5, i.e. a SHA-1 — for EVERY signal
they evicted, inline on the event loop. `buffer_signal` had already computed
that exact id at insert to key the dedup set, so it was pure recomputation, and
unbounded: a 50,000-signal window aging out in one prune is 50,000 SHA-1s with
no await between them.

Captured live 2026-08-20 as the top frame of a 30,989 ms stall — past the 30 s
Kafka session timeout — while the container had ~800 MB of FREE memory. A stall
source independent of memory pressure.

Measured on a 50,000-signal full eviction: 770.0 ms -> 60.3 ms, 50,000 -> 0
uuid5 calls, output byte-identical.

The risk of a parallel id deque is DESYNC, so every test below is about the two
structures staying aligned, and the last ones prove a desync degrades to
correct-and-slow rather than to wrong.
"""
from __future__ import annotations

import asyncio
import dataclasses
import time
import uuid
from datetime import datetime, timedelta, timezone

import pytest

import main
import signals as S


def run(coro):
    return asyncio.run(coro)


T0 = datetime(2026, 8, 20, 12, 0, 0, tzinfo=timezone.utc)


def mk(i: int, secs: int | None = None) -> S.Signal:
    return S.Signal(
        tenant_id="acme", ts=T0 + timedelta(seconds=i if secs is None else secs),
        source=S.Source.SYSLOG, kind="link_state_change",
        observer=S.observer_of(f"leaf{i}", S.ObserverType.DEVICE,
                               collection_path="direct", clock_quality="unknown"),
        modality_class=S.ModalityClass.CONTROL_PLANE,
        entity_type=S.EntityType.INTERFACE, entity_id=f"leaf{i}:Gi0/1",
        severity=S.Severity.WARN, native_id=f"nat-{i}",
        entity_tokens=(f"leaf{i}",))


def load(n: int, secs=None):
    main.WINDOW_BUFFER.clear()
    main._BUFFERED_IDS.clear()
    main._BUFFERED_ID_ORDER.clear()
    main.TENANT_WATERMARK.clear()
    for i in range(n):
        sig = mk(i, secs(i) if secs else None)
        sid = str(sig.signal_id)
        main._BUFFERED_IDS.add(sid)
        main.WINDOW_BUFFER.append(sig)
        main._BUFFERED_ID_ORDER.append(sid)
        # tracker 165: retention now runs on the tenant's STREAM clock, so the
        # fixture must advance it exactly as buffer_signal does. Loading the
        # window without a watermark would test a clock that never started.
        main._advance_watermark(sig, time.monotonic())


def stream_at(offset_s: float) -> None:
    """Push every loaded tenant's stream clock to T0 + offset_s.

    The prune horizon is `watermark - RETENTION_REQUIRED_S`, so this — not the
    wall clock passed to _prune_buffer — is what decides what expires."""
    ts = (T0 + timedelta(seconds=offset_s)).timestamp()
    now_mono = time.monotonic()
    for tenant in list(main.TENANT_WATERMARK) or ["acme"]:
        main.TENANT_WATERMARK[tenant] = (ts, now_mono)


def prune_at_stream(offset_s: float):
    """Advance the stream clock to T0 + offset_s and prune."""
    stream_at(offset_s)
    return run(main._prune_buffer(datetime.now(timezone.utc)))


def reference_prune(offset_s):
    """Independent stream-time oracle: keep exactly the signals within
    RETENTION_REQUIRED_S of the tenant's watermark. Written as a naive filter so
    it shares no code with the chunked implementation under test."""
    horizon = ((T0 + timedelta(seconds=offset_s)).timestamp()
               - main.RETENTION_REQUIRED_S)
    keep = [s for s in main.WINDOW_BUFFER if s.ts.timestamp() >= horizon]
    dropped = {str(s.signal_id) for s in main.WINDOW_BUFFER
               if s.ts.timestamp() < horizon}
    main.WINDOW_BUFFER.clear()
    main.WINDOW_BUFFER.extend(keep)
    main._BUFFERED_ID_ORDER.clear()
    main._BUFFERED_ID_ORDER.extend(str(s.signal_id) for s in keep)
    main._BUFFERED_IDS.difference_update(dropped)


def snapshot():
    return ([str(s.signal_id) for s in main.WINDOW_BUFFER], set(main._BUFFERED_IDS))


@pytest.fixture(autouse=True)
def _clean():
    yield
    main.WINDOW_BUFFER.clear()
    main._BUFFERED_IDS.clear()
    main._BUFFERED_ID_ORDER.clear()


# --- output equivalence ----------------------------------------------------

@pytest.mark.parametrize("ahead", [0, 1, 50, 300, 5000, 100_000])
def test_prune_matches_an_independent_stream_time_oracle(ahead):
    """Same evicted set, same remaining window, same dedup set — at every depth
    from 'evict nothing' to 'evict everything'.

    tracker 165: the oracle changed. It used to be the pre-fix WALL-CLOCK
    implementation; retention is now stream-time, and reproducing the old
    behaviour would mean reproducing the defect."""
    offset = main.RETENTION_REQUIRED_S + ahead
    load(400)
    reference_prune(offset)
    want = snapshot()
    load(400)
    prune_at_stream(offset)
    assert snapshot() == want


def test_prune_preserves_arrival_order():
    load(200)
    prune_at_stream(main.RETENTION_REQUIRED_S + 50)
    remaining = [str(s.signal_id) for s in main.WINDOW_BUFFER]
    assert remaining == sorted(remaining, key=lambda x: remaining.index(x))
    assert list(main._BUFFERED_ID_ORDER) == remaining, "id deque drifted from the window"


def test_dedup_set_and_window_stay_the_same_size():
    load(300)
    prune_at_stream(main.RETENTION_REQUIRED_S + 100)
    assert len(main._BUFFERED_IDS) == len(main.WINDOW_BUFFER) == len(main._BUFFERED_ID_ORDER)


# --- the expensive thing is actually gone ----------------------------------

def test_prune_computes_no_uuid5(monkeypatch):
    """THE POINT. Not 'fewer' — none."""
    load(500)
    calls = {"n": 0}
    real = uuid.uuid5

    def counting(ns, name):
        calls["n"] += 1
        return real(ns, name)

    monkeypatch.setattr(S.uuid, "uuid5", counting)
    monkeypatch.setattr(uuid, "uuid5", counting)
    prune_at_stream(main.RETENTION_REQUIRED_S + 100_000)
    assert len(main.WINDOW_BUFFER) == 0, "the whole window should have aged out"
    assert calls["n"] == 0, f"prune still computed {calls['n']} uuid5s"


def test_a_full_window_prune_is_fast_enough_not_to_threaten_membership():
    """Bounded wall-clock: the acceptance criterion is that one prune cannot
    approach the Kafka session timeout. Generous ceiling so this is a
    catastrophic-regression canary, not a flaky micro-benchmark."""
    import time
    load(20_000)
    t0 = time.perf_counter()
    prune_at_stream(main.RETENTION_REQUIRED_S + 100_000)
    elapsed = time.perf_counter() - t0
    assert len(main.WINDOW_BUFFER) == 0
    assert elapsed < 2.0, (
        f"a 20k-signal prune blocked the loop for {elapsed:.2f}s — the old "
        "implementation is back or something equally expensive is inline")


# --- the desync hazard the parallel deque introduces -----------------------

def test_desync_self_heals_and_is_counted():
    """A drifted id deque must degrade to correct-and-slow, never to wrong."""
    load(100)
    main._BUFFERED_ID_ORDER.clear()          # simulate drift
    before = main.WINDOW_ID_ORDER_RESYNCS
    prune_at_stream(main.RETENTION_REQUIRED_S + 50)
    assert main.WINDOW_ID_ORDER_RESYNCS == before + 1, "a resync must be counted"
    assert len(main._BUFFERED_IDS) == len(main.WINDOW_BUFFER)
    assert list(main._BUFFERED_ID_ORDER) == [str(s.signal_id) for s in main.WINDOW_BUFFER]


def test_desync_still_produces_the_right_answer():
    offset = main.RETENTION_REQUIRED_S + 120
    load(300)
    reference_prune(offset)
    want = snapshot()
    load(300)
    main._BUFFERED_ID_ORDER.clear()          # drift before pruning
    prune_at_stream(offset)
    assert snapshot() == want


def test_a_test_that_clears_only_the_window_does_not_corrupt_state():
    """Existing suites clear WINDOW_BUFFER and _BUFFERED_IDS directly."""
    load(50)
    main.WINDOW_BUFFER.clear()
    main._BUFFERED_IDS.clear()
    prune_at_stream(main.RETENTION_REQUIRED_S + 10)
    assert len(main._BUFFERED_ID_ORDER) == 0


# --- the maxlen path -------------------------------------------------------

def test_maxlen_eviction_keeps_all_three_structures_aligned(monkeypatch):
    """A full deque drops its head silently; the dedup set must drop it too, or
    the set leaks AND a later redelivery of an evicted signal is wrongly
    deduped."""
    from collections import deque
    monkeypatch.setattr(main, "WINDOW_BUFFER", deque(maxlen=10))
    monkeypatch.setattr(main, "_BUFFERED_ID_ORDER", deque(maxlen=10))
    monkeypatch.setattr(main, "_BUFFERED_IDS", set())
    for i in range(40):
        main.buffer_signal(mk(i))
    assert len(main.WINDOW_BUFFER) == 10
    assert len(main._BUFFERED_ID_ORDER) == 10
    assert len(main._BUFFERED_IDS) == 10, "the dedup set leaked past the window bound"
    assert list(main._BUFFERED_ID_ORDER) == [str(s.signal_id) for s in main.WINDOW_BUFFER]


def test_a_signal_evicted_by_maxlen_can_be_redelivered(monkeypatch):
    """Its stale id must not linger in the dedup set and swallow the redelivery."""
    from collections import deque
    monkeypatch.setattr(main, "WINDOW_BUFFER", deque(maxlen=5))
    monkeypatch.setattr(main, "_BUFFERED_ID_ORDER", deque(maxlen=5))
    monkeypatch.setattr(main, "_BUFFERED_IDS", set())
    first = mk(0)
    main.buffer_signal(first)
    for i in range(1, 12):
        main.buffer_signal(mk(i))
    assert str(first.signal_id) not in main._BUFFERED_IDS
    main.buffer_signal(first)
    assert str(first.signal_id) in main._BUFFERED_IDS, (
        "a redelivered signal that had aged out was wrongly deduped")


def test_redelivery_inside_the_window_is_still_deduped(monkeypatch):
    from collections import deque
    monkeypatch.setattr(main, "WINDOW_BUFFER", deque(maxlen=100))
    monkeypatch.setattr(main, "_BUFFERED_ID_ORDER", deque(maxlen=100))
    monkeypatch.setattr(main, "_BUFFERED_IDS", set())
    sig = mk(1)
    main.buffer_signal(sig)
    main.buffer_signal(sig)
    main.buffer_signal(sig)
    assert len(main.WINDOW_BUFFER) == 1, "at-least-once redelivery was not deduped"
    assert len(main._BUFFERED_ID_ORDER) == 1


# --- the architectural invariant: bounded work per loop slice --------------
#
# "No maintenance operation may perform unbounded synchronous work on the
# correlation event loop." The prune still COMPLETES in one call — partial
# pruning would leave expired signals for run_window and silently change RCA
# semantics — but the contiguous block is bounded and the loop is handed back
# between chunks. Same total work, bounded slice: Flink's incremental-cleanup
# shape.

def test_prune_actually_hands_the_loop_back():
    """THE INVARIANT, proven by a CONCURRENT TASK making progress — not by a
    counter.

    Counting yields proves only that a counter was incremented. What matters is
    whether another coroutine (aiokafka's heartbeat, in production) got
    scheduled while the prune was running. So run a ticker alongside it and
    require the ticker to have advanced.
    """
    async def scenario():
        load(4 * main.CORR_PRUNE_CHUNK)
        ticks = {"n": 0}

        async def ticker():
            while True:
                ticks["n"] += 1
                await asyncio.sleep(0)

        t = asyncio.ensure_future(ticker())
        await asyncio.sleep(0)
        start = ticks["n"]
        stream_at(main.RETENTION_REQUIRED_S + 100_000)
        await main._prune_buffer(datetime.now(timezone.utc))
        progressed = ticks["n"] - start
        t.cancel()
        return progressed, len(main.WINDOW_BUFFER)

    progressed, left = asyncio.run(scenario())
    assert left == 0, "the prune must still finish the job"
    assert progressed >= 3, (
        f"a concurrent task advanced only {progressed} times across 4 chunks — "
        "the prune is monopolising the event loop again, which is exactly the "
        "condition that costs Kafka membership")


def test_prune_yield_counter_tracks_the_chunking():
    load(3 * main.CORR_PRUNE_CHUNK + 17)
    before = main.PRUNE_YIELDS
    prune_at_stream(main.RETENTION_REQUIRED_S + 100_000)
    assert main.PRUNE_YIELDS - before >= 3


def test_a_small_prune_does_not_yield_at_all():
    """Bounded does not mean gratuitous: under one chunk there is nothing to
    hand back for."""
    load(10)
    before = main.PRUNE_YIELDS
    prune_at_stream(main.RETENTION_REQUIRED_S + 100_000)
    assert main.PRUNE_YIELDS == before


def test_the_gauge_reports_worst_block_not_total_elapsed():
    """Blocking time is what threatens Kafka membership. A gauge reporting TOTAL
    elapsed would overstate the risk and, worse, hide a single long block inside
    a long total.

    Discriminated by making total and worst-block genuinely diverge: a
    concurrent task sleeps a real 5 ms at every yield point, so wall-clock total
    grows with the number of chunks while no single chunk does. A gauge
    reporting elapsed then reads ~20x the gauge reporting worst-block.
    """
    async def scenario():
        main.CORR_PRUNE_CHUNK = 200
        load(20 * 200)
        stop = {"v": False}

        async def burner():
            # A READY task that consumes real time each turn. A sleeping task
            # would not do: the prune yields with asyncio.sleep(0), which hands
            # control to tasks that are already runnable and does NOT wait for a
            # timer — correct behaviour, and it means only a ready task can
            # inflate the wall clock here.
            while not stop["v"]:
                spin = time.monotonic() + 0.004
                while time.monotonic() < spin:
                    pass
                await asyncio.sleep(0)

        t = asyncio.ensure_future(burner())
        began = time.monotonic()
        stream_at(main.RETENTION_REQUIRED_S + 100_000)
        await main._prune_buffer(datetime.now(timezone.utc))
        total = time.monotonic() - began
        stop["v"] = True
        t.cancel()
        return total

    try:
        total = asyncio.run(scenario())
        assert total > 0.05, (
            f"the concurrent sleeper did not inflate the total ({total:.4f}s) — "
            "the prune never yielded, so this test cannot discriminate")
        assert main.PRUNE_SECONDS_LAST < total / 5, (
            f"gauge {main.PRUNE_SECONDS_LAST:.4f}s vs total {total:.4f}s across "
            "20 chunks — it is reporting elapsed, not the worst contiguous block")
    finally:
        main.CORR_PRUNE_CHUNK = 5000


# --- housekeeping observability -------------------------------------------

def test_prune_counters_move():
    load(200)
    calls, evicted = main.PRUNE_CALLS, main.PRUNE_EVICTED
    prune_at_stream(main.RETENTION_REQUIRED_S + 100)
    assert main.PRUNE_CALLS == calls + 1
    assert main.PRUNE_EVICTED > evicted, "evicted signals must be counted"


def test_window_overflow_drop_is_counted(monkeypatch):
    """The silent horizon-narrowing the review flagged: a full window sheds its
    oldest signal, which is not data loss but IS thinner RCA, and used to be
    invisible."""
    from collections import deque
    monkeypatch.setattr(main, "WINDOW_BUFFER", deque(maxlen=5))
    monkeypatch.setattr(main, "_BUFFERED_ID_ORDER", deque(maxlen=5))
    monkeypatch.setattr(main, "_BUFFERED_IDS", set())
    before = main.WINDOW_OVERFLOW_DROPPED
    for i in range(12):
        main.buffer_signal(mk(i))
    assert main.WINDOW_OVERFLOW_DROPPED == before + 7, (
        "7 signals were shed to make room and the counter must say so")


def test_no_overflow_drop_when_the_window_has_room(monkeypatch):
    from collections import deque
    monkeypatch.setattr(main, "WINDOW_BUFFER", deque(maxlen=100))
    monkeypatch.setattr(main, "_BUFFERED_ID_ORDER", deque(maxlen=100))
    monkeypatch.setattr(main, "_BUFFERED_IDS", set())
    before = main.WINDOW_OVERFLOW_DROPPED
    for i in range(20):
        main.buffer_signal(mk(i))
    assert main.WINDOW_OVERFLOW_DROPPED == before


# --- capacity shedding vs age pruning (2026-08-20) -------------------------
#
# The window is bounded by COUNT (50,000) and the RCA horizon is a TIME
# (RETENTION_REQUIRED_S). A count bound cannot express a time horizon: the window
# holds 50,000 / signal_rate seconds, so above ~55.6 signals/s it physically
# cannot cover 900 s. When that happens the evicted signal is still INSIDE the
# horizon the engine is about to correlate over — evidence degradation, not
# housekeeping. These pin the distinction.

def _at(i, when):
    """Signal i stamped at `when` — fresh, so any eviction is capacity-driven."""
    return dataclasses.replace(mk(i), ts=when)


def _fill(monkeypatch, *, spacing_s: float, n: int = 12, maxlen: int = 5):
    """Push `n` signals `spacing_s` apart in EVENT time through a `maxlen`
    window, returning (overflow_delta, in_horizon_delta).

    With maxlen=5 the incoming signal is always 5 slots ahead of the victim, so
    the event-time gap each eviction is judged on is exactly 5 * spacing_s.
    """
    from collections import deque
    monkeypatch.setattr(main, "WINDOW_BUFFER", deque(maxlen=maxlen))
    monkeypatch.setattr(main, "_BUFFERED_ID_ORDER", deque(maxlen=maxlen))
    monkeypatch.setattr(main, "_BUFFERED_IDS", set())
    before_all = main.WINDOW_OVERFLOW_DROPPED
    before_horizon = main.WINDOW_OVERFLOW_IN_HORIZON
    # Anchored so the NEWEST signal lands at wall-clock now and the rest run
    # into the past: a future-stamped signal is clamped to arrival by the H14
    # clock bound, which would collapse the event-time spread this fixture is
    # built on.
    base = datetime.now(timezone.utc) - timedelta(seconds=(n - 1) * spacing_s)
    for i in range(n):
        main.buffer_signal(_at(i, base + timedelta(seconds=i * spacing_s)))
    return (main.WINDOW_OVERFLOW_DROPPED - before_all,
            main.WINDOW_OVERFLOW_IN_HORIZON - before_horizon)


def test_capacity_drop_inside_the_horizon_is_counted_separately(monkeypatch):
    """A signal shed by capacity while the engine could still have attached it
    was eligible evidence — degradation, not housekeeping.

    tracker 165: eligibility is judged in EVENT time against ENGINE_REACH_S (the
    gap at which an edge can still clear attach_threshold), not against the
    window_s buffering constant and not against wall-clock arrival.
    """
    dropped, in_horizon = _fill(monkeypatch, spacing_s=1.0)   # gaps of 5 s
    assert dropped == 7
    assert in_horizon == 7, (
        "signals shed by capacity while still attachable must be counted as "
        "degradation, not folded in with age-based pruning")


def test_a_capacity_drop_beyond_the_ENGINE_REACH_is_not_degradation(monkeypatch):
    """The negative control for the counter above.

    A victim further from the incoming evidence than ENGINE_REACH_S could never
    have formed an edge with it — no RCA context is lost by shedding it.
    Counting it would inflate the one number this wave turns on.
    """
    spacing = (main.ENGINE_REACH_S / 5.0) + 20.0      # gaps of reach + 100 s
    dropped, in_horizon = _fill(monkeypatch, spacing_s=spacing)
    assert dropped == 7, "capacity drops still counted"
    assert in_horizon == 0, (
        "victims beyond the engine's temporal reach were shed — that is "
        "ordinary loss, not RCA evidence degradation")


def test_the_eligibility_boundary_is_the_derived_reach_not_window_s(monkeypatch):
    """Straddle ENGINE_REACH_S. The retired 900 s yardstick would have called
    BOTH of these degradation; the engine's own reach separates them."""
    just_inside = (main.ENGINE_REACH_S - 25.0) / 5.0
    just_outside = (main.ENGINE_REACH_S + 25.0) / 5.0
    assert main.ENGINE_REACH_S < main.RETENTION_REQUIRED_S, "premise of the test"
    assert _fill(monkeypatch, spacing_s=just_inside)[1] == 7
    assert _fill(monkeypatch, spacing_s=just_outside)[1] == 0


def test_window_span_reports_the_time_actually_held():
    """Below the configured horizon means the COUNT bound is deciding what the
    engine sees, not the TIME bound."""
    load(0)
    assert main._window_span_s() == 0.0
    load(100, secs=lambda i: i)          # 100 signals, 1 s apart
    span = main._window_span_s()
    assert 98 <= span <= 100, f"span {span}s should be ~99s for 100 signals 1s apart"


def test_window_span_is_zero_for_a_trivial_window():
    load(1)
    assert main._window_span_s() == 0.0


def test_a_full_window_holding_less_than_the_horizon_is_detectable():
    """The diagnostic the whole wave turns on: capacity < horizon."""
    load(200, secs=lambda i: i * 0.5)    # 200 signals over 100s
    span = main._window_span_s()
    assert span < main.RETENTION_REQUIRED_S, (
        "this fixture is meant to represent a window holding less than the "
        "required retention horizon")
