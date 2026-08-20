"""Tracker 164 — PASSIVE accounting for the offload executor.

`_offload` submits to asyncio's default executor, whose work queue is an
unbounded `SimpleQueue`: submission never blocks and never fails, so a producer
that outruns the workers builds a backlog with no symptom except latency
somewhere else. The architecture review named that a suspected contributor to
the 12-19 minute drain lag; nothing had ever measured it.

This wave adds the measurement ONLY. These tests hold two lines at once:

  1. the numbers are real (they move, under contention, in the right direction);
  2. the behaviour did not change (same result, same exceptions, nothing
     refused, nothing delayed) — because an instrumentation change that alters
     admission would invalidate the very measurement it exists to take.
"""
from __future__ import annotations

import asyncio
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import pytest

import main


@pytest.fixture(autouse=True)
def _reset_offload():
    """Counters are module-level; every test starts from a known state and
    leaves no residue for the next one."""
    with main._OFFLOAD_LOCK:
        main._OFFLOAD_PENDING.clear()
        main._OFFLOAD_RUNNING.clear()
        main._OFFLOAD_WAIT_S.clear()
        main._OFFLOAD_EXEC_S.clear()
        main.OFFLOAD_SUBMITTED = 0
        main.OFFLOAD_STARTED = 0
        main.OFFLOAD_COMPLETED = 0
        main.OFFLOAD_FAILED = 0
        main.OFFLOAD_DEPTH_PEAK = 0
        main.OFFLOAD_ACTIVE_PEAK = 0
        main.OFFLOAD_WAIT_MAX_S = 0.0
        main.OFFLOAD_EXEC_MAX_S = 0.0
    yield


def _run(coro, *, workers: int | None = None):
    """Drive `coro` on a fresh loop, optionally with a size-pinned executor so
    queueing is deterministic instead of racing the host's CPU count."""
    async def _main():
        if workers is not None:
            asyncio.get_running_loop().set_default_executor(
                ThreadPoolExecutor(max_workers=workers))
        return await coro()
    return asyncio.run(_main())


# ── behaviour is unchanged ───────────────────────────────────────────────────

def test_the_result_still_comes_back():
    assert _run(lambda: main._offload(lambda a, b: a + b, 2, b=3)) == 5


def test_an_exception_still_propagates_and_is_counted_as_failed():
    def boom():
        raise ValueError("kaboom")
    with pytest.raises(ValueError, match="kaboom"):
        _run(lambda: main._offload(boom))
    assert main.OFFLOAD_FAILED == 1
    assert main.OFFLOAD_COMPLETED == 0
    assert main.OFFLOAD_STARTED == 1


def test_nothing_is_ever_refused():
    """The queue is unbounded today; the metric says so explicitly rather than
    being absent. When 164 is implemented this test must be revisited on
    purpose."""
    async def many():
        return await asyncio.gather(*(main._offload(lambda i=i: i)
                                      for i in range(64)))
    assert _run(many, workers=2) == list(range(64))
    stats = main.offload_stats()
    assert stats["rejected"] == 0
    assert stats["queue_bounded"] is False
    assert stats["submitted_total"] == 64
    assert stats["completed_total"] == 64


# ── the numbers are real ─────────────────────────────────────────────────────

def test_a_backlog_is_visible_while_it_exists():
    """One worker, three calls: depth and oldest-queued-age must be non-zero
    while the first call is still running — the whole point of the metric."""
    seen: dict[str, object] = {}
    started = threading.Event()
    release = threading.Event()

    def blocker():
        started.set()
        release.wait(5)

    async def scenario():
        tasks = [asyncio.ensure_future(main._offload(blocker))]
        tasks += [asyncio.ensure_future(main._offload(lambda: None))
                  for _ in range(2)]
        # let the loop hand everything to the executor, then observe
        for _ in range(200):
            await asyncio.sleep(0.01)
            if started.is_set():
                break
        seen["stats"] = main.offload_stats()
        release.set()
        await asyncio.gather(*tasks)

    _run(scenario, workers=1)
    s = seen["stats"]
    assert s["queue_depth"] == 2, f"expected two calls queued, saw {s['queue_depth']}"
    assert s["active_workers"] == 1
    assert s["oldest_queued_age_s"] > 0.0
    assert main.OFFLOAD_DEPTH_PEAK >= 2


def test_queue_wait_is_measured_not_assumed():
    """The second call cannot start until the first finishes, so its recorded
    WAIT must be at least the first call's execution time."""
    hold = 0.25

    async def scenario():
        a = asyncio.ensure_future(main._offload(time.sleep, hold))
        await asyncio.sleep(0.02)          # ensure a is submitted first
        b = asyncio.ensure_future(main._offload(lambda: None))
        await asyncio.gather(a, b)

    _run(scenario, workers=1)
    stats = main.offload_stats()
    assert stats["wait_max_s"] >= hold * 0.8, stats
    assert stats["exec_max_s"] >= hold * 0.8, stats
    assert stats["samples"] == 2


def test_no_contention_means_no_wait():
    """Negative control: with a free worker the wait must stay near zero, so a
    non-zero p95 in production is evidence of real queueing rather than a
    constant this code adds."""
    async def scenario():
        for _ in range(10):
            await main._offload(lambda: None)
    _run(scenario, workers=4)
    assert main.offload_stats()["wait_p95_s"] < 0.05


def test_counters_balance_after_the_queue_drains():
    async def scenario():
        await asyncio.gather(*(main._offload(lambda: None) for _ in range(50)))
    _run(scenario, workers=3)
    s = main.offload_stats()
    assert s["submitted_total"] == s["started_total"] == 50
    assert s["completed_total"] + s["failed_total"] == 50
    assert s["queue_depth"] == 0 and s["active_workers"] == 0
    assert s["oldest_queued_age_s"] == 0.0


def test_counts_are_complete_under_concurrency():
    """Eight workers, 400 calls: every submission is accounted for exactly once.

    HONEST LIMITATION — this does NOT prove `_OFFLOAD_LOCK` is necessary. The
    mutation run for this wave removed the lock and all 14 tests still passed,
    and direct probes could not produce a lost update or a torn dict snapshot on
    CPython at any switch interval or dict size: `+=` on a module int and
    `list(dict.values())` both complete inside one GIL slice here. The lock is
    kept because the language guarantees none of that (and a free-threaded build
    guarantees the opposite), not because a red test demands it. What this test
    DOES catch is a counting-logic error — a path that double-counts, or one
    that never records — which is the failure mode instrumentation actually has.
    """
    n = 400

    async def scenario():
        await asyncio.gather(*(main._offload(lambda: None) for _ in range(n)))
    _run(scenario, workers=8)
    s = main.offload_stats()
    assert s["submitted_total"] == n
    assert s["started_total"] == n
    assert s["completed_total"] == n


def test_samples_are_bounded():
    """§9: the reservoirs cannot grow without bound."""
    assert main._OFFLOAD_WAIT_S.maxlen == main.CORR_OFFLOAD_SAMPLES
    assert main._OFFLOAD_EXEC_S.maxlen == main.CORR_OFFLOAD_SAMPLES


# ── quantiles ────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("q,expected", [(0.5, 5), (0.95, 10), (0.99, 10)])
def test_quantile_is_nearest_rank(q, expected):
    assert main._quantile(list(range(1, 11)), q) == expected


def test_quantile_of_nothing_is_zero_not_a_crash():
    assert main._quantile([], 0.5) == 0.0


def test_max_workers_reports_where_the_number_came_from():
    """Outside a running loop there is no executor to read, and a computed
    default must not be presented as a measurement."""
    workers, source = main._offload_max_workers()
    assert workers > 0
    assert source == "cpython_default"

    async def inside():
        await main._offload(lambda: None)
        return main._offload_max_workers()
    w, src = _run(inside, workers=3)
    assert (w, src) == (3, "executor")
