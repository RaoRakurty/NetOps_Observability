"""Tracker 165 Part B — the profiler must not become the thing it measures.

Earlier profiling work in this programme produced a run that had to be thrown
away: a tracemalloc.statistics() call on the event loop turned into six stalls
between 5 and 96 seconds, and every conclusion drawn from it was worthless. So
the bar for this instrument is not "is it useful" but "can it be shown not to
distort the system".

These tests hold three lines: it is genuinely off when disabled, it costs
approximately nothing when enabled, and the numbers it reports are real.
"""
from __future__ import annotations

import time

import pytest

import main


@pytest.fixture(autouse=True)
def _clean():
    with main._STAGE_LOCK:
        main._STAGE_STATS.clear()
        main._STAGE_SAMPLES.clear()
    was = main.CORR_PROFILE_STAGES
    yield
    main.CORR_PROFILE_STAGES = was
    with main._STAGE_LOCK:
        main._STAGE_STATS.clear()
        main._STAGE_SAMPLES.clear()


# ── disabled means disabled ──────────────────────────────────────────────────

def test_records_nothing_when_disabled():
    main.CORR_PROFILE_STAGES = False
    for _ in range(100):
        with main.stage("x"):
            pass
    assert main.stage_profile()["stages"] == {}
    assert main.stage_profile()["enabled"] is False


def test_the_disabled_path_allocates_no_generator():
    """`stage` is a __slots__ class, not @contextmanager, precisely so the
    per-event path does not allocate a generator per use. If someone converts
    it back, this goes red."""
    assert not hasattr(main.stage, "__wrapped__"), "stage became a generator CM"
    assert main.stage.__slots__ == ("_name", "_t0")


def test_disabled_overhead_is_negligible():
    """A profiler that taxes the hot path when switched OFF is not opt-in."""
    main.CORR_PROFILE_STAGES = False
    n = 200_000
    t0 = time.perf_counter()
    for _ in range(n):
        with main.stage("x"):
            pass
    per_call_us = 1e6 * (time.perf_counter() - t0) / n
    assert per_call_us < 5.0, f"{per_call_us:.2f}us per disabled stage() call"


# ── enabled: the numbers are real ────────────────────────────────────────────

def test_records_calls_and_time_when_enabled():
    main.CORR_PROFILE_STAGES = True
    for _ in range(10):
        with main.stage("work"):
            time.sleep(0.002)
    prof = main.stage_profile()
    assert prof["enabled"] is True
    row = prof["stages"]["work"]
    assert row["calls"] == 10
    assert row["total_s"] >= 0.015
    assert row["mean_ms"] >= 1.5
    assert row["max_ms"] >= row["p50_ms"]


def test_shares_sum_to_one_across_stages():
    main.CORR_PROFILE_STAGES = True
    with main.stage("a"):
        time.sleep(0.004)
    with main.stage("b"):
        time.sleep(0.002)
    stages = main.stage_profile()["stages"]
    assert abs(sum(r["share"] for r in stages.values()) - 1.0) < 0.01
    assert stages["a"]["share"] > stages["b"]["share"], "shares must rank by cost"


def test_stages_are_ordered_most_expensive_first():
    main.CORR_PROFILE_STAGES = True
    with main.stage("cheap"):
        time.sleep(0.001)
    with main.stage("dear"):
        time.sleep(0.005)
    assert next(iter(main.stage_profile()["stages"])) == "dear"


def test_an_exception_still_records_the_time():
    """A stage that raises is often the interesting one; it must not vanish."""
    main.CORR_PROFILE_STAGES = True
    with pytest.raises(ValueError), main.stage("boom"):
        time.sleep(0.002)
        raise ValueError("x")
    assert main.stage_profile()["stages"]["boom"]["calls"] == 1


def test_the_stage_does_not_swallow_exceptions():
    main.CORR_PROFILE_STAGES = True
    with pytest.raises(KeyError), main.stage("s"):
        raise KeyError("must propagate")


def test_samples_are_bounded():
    """§9 — a profiler that grows without bound under load is a memory leak
    dressed as observability."""
    main.CORR_PROFILE_STAGES = True
    for _ in range(main.CORR_PROFILE_SAMPLES * 3):
        with main.stage("many"):
            pass
    with main._STAGE_LOCK:
        assert len(main._STAGE_SAMPLES["many"]) == main.CORR_PROFILE_SAMPLES
    assert main.stage_profile()["stages"]["many"]["calls"] == main.CORR_PROFILE_SAMPLES * 3, (
        "the COUNT must keep counting even though the sample reservoir is capped")


def test_enabled_overhead_is_small_enough_not_to_distort():
    """Bounds the tax when it IS on. If a stage timer costs more than a few
    microseconds it starts to matter on a per-event path at thousands of
    events per second, and the run would have to be called CONTAMINATED."""
    main.CORR_PROFILE_STAGES = True
    n = 50_000
    t0 = time.perf_counter()
    for _ in range(n):
        with main.stage("hot"):
            pass
    per_call_us = 1e6 * (time.perf_counter() - t0) / n
    assert per_call_us < 25.0, f"{per_call_us:.2f}us per enabled stage() call"


def test_concurrent_stages_do_not_lose_counts():
    """Executor threads record stages too — run_window runs off-loop, so its
    timings are written from a worker thread while the loop writes others.

    HONEST LIMITATION, same as `_OFFLOAD_LOCK`: removing `_STAGE_LOCK` passes
    every test here. What the lock actually protects is a genuine MULTI-STEP
    invariant — `row[0] += 1; row[1] += elapsed; if elapsed > row[2]` is three
    read-modify-writes on a shared list, plus a check-then-insert on the dict —
    and CPython merely happens to complete those inside one GIL slice at these
    sizes. The lock is kept because the language guarantees none of it and a
    free-threaded build guarantees the opposite, NOT because a red test demands
    it. What this test does catch is a counting-logic error: a path that
    double-counts or never records."""
    import threading
    main.CORR_PROFILE_STAGES = True
    def work():
        for _ in range(500):
            with main.stage("threaded"):
                pass
    ts = [threading.Thread(target=work) for _ in range(4)]
    for t in ts: t.start()
    for t in ts: t.join()
    assert main.stage_profile()["stages"]["threaded"]["calls"] == 2000
