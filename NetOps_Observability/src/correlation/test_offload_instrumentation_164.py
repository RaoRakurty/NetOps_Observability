"""Tracker 164 — the BOUNDED offload plane, and the accounting that justified it.

`_offload` used to submit to asyncio's DEFAULT executor. Its worker count was
bounded; its work QUEUE was an unbounded `SimpleQueue`, so submission never
blocked and never failed and a producer that outran the workers built a backlog
whose only symptom was latency somewhere else. Wave 1 of this tracker measured
that (the tests below under "the numbers are real"). Wave 2 — this file's
"the plane is bounded" half — replaced the default executor with a dedicated,
size-pinned pool behind a strictly FIFO admission gate, as §9 requires: bounded
queue, real backpressure, nothing dropped.

Three lines are held at once:

  1. the plane is BOUNDED and the bound BLOCKS rather than drops (a full plane
     makes the caller await; `corr_offload_admission_waits_total` says so);
  2. the numbers are real (they move, under contention, in the right direction);
  3. the SEMANTICS did not change — same results, same exceptions, same order.
     `_offload` changes where work waits, never what runs.

Mutation targets, both verified red:
  * `run_in_executor(executor, …)` → `run_in_executor(None, …)` fails
    `test_work_runs_on_the_dedicated_pool_not_the_default_executor`;
  * an unbounded admission gate fails
    `test_a_full_plane_makes_the_caller_wait_instead_of_queueing`.
"""
from __future__ import annotations

import ast
import asyncio
import pathlib
import threading
import time

import pytest

import main


@pytest.fixture(autouse=True)
def _reset_offload():
    """Counters, sizing and the plane itself are module-level; every test starts
    from a known state and leaves none behind for the next one."""
    sizes = (main.CORR_OFFLOAD_WORKERS, main.CORR_OFFLOAD_INFLIGHT_MAX)
    _stop_plane()
    _zero_counters()
    yield
    main.CORR_OFFLOAD_WORKERS, main.CORR_OFFLOAD_INFLIGHT_MAX = sizes
    _stop_plane()
    _zero_counters()


def _zero_counters() -> None:
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
        main.OFFLOAD_ADMISSION_WAITS = 0
        main.OFFLOAD_ADMISSION_WAIT_MAX_S = 0.0
        main.OFFLOAD_ABANDONED = 0


def _stop_plane(drain_s: float = 3.0) -> dict[str, int]:
    return asyncio.run(main.offload_stop(drain_s=drain_s))


def _live_offload_threads() -> list[str]:
    return [t.name for t in threading.enumerate()
            if t.name.startswith("corr-offload") and t.is_alive()]


def _run(coro, *, workers: int | None = None, inflight: int | None = None):
    """Drive `coro` on a fresh loop with the plane pinned to a known size, so
    queueing is deterministic instead of racing the host's CPU count."""
    if workers is not None:
        main.CORR_OFFLOAD_WORKERS = workers
    if inflight is not None:
        main.CORR_OFFLOAD_INFLIGHT_MAX = inflight
    elif workers is not None:
        main.CORR_OFFLOAD_INFLIGHT_MAX = 2 * workers
    # A size change only takes effect on a fresh pool.
    _stop_plane()
    return asyncio.run(coro())


# ── the plane is bounded (wave 2) ────────────────────────────────────────────

def test_work_runs_on_the_dedicated_pool_not_the_default_executor():
    """MUTATION TARGET. The whole point of owning an executor is that "the
    offload queue" is actually the offload queue: the default pool is shared
    with every `asyncio.to_thread` in the process (diagnostics snapshots, the
    cloud-log tailer's blocking reads), so its depth never described this
    plane and its size was somebody else's decision.

    Reverting to `run_in_executor(None, …)` puts the call on a thread named
    `asyncio_*` and fails here.
    """
    async def scenario():
        name = await main._offload(lambda: threading.current_thread().name)
        loop = asyncio.get_running_loop()
        return name, getattr(loop, "_default_executor", None)

    name, default_ex = _run(scenario, workers=2)
    assert name.startswith("corr-offload"), (
        f"offloaded work ran on {name!r} — the default executor, not the "
        f"dedicated offload pool")
    assert default_ex is None, (
        "the default executor was created, so something still routes offload "
        "work through the shared pool")


def test_the_pool_is_sized_by_configuration_not_by_the_host():
    workers, source = _run(lambda: main._offload(main._offload_max_workers),
                           workers=3)
    assert (workers, source) == (3, "executor")


def test_max_workers_is_honest_before_the_pool_exists():
    """Nothing has been offloaded, so there is no pool to read. Report the
    configured value and SAY it is configuration — never dress a default up as
    a measurement."""
    main.CORR_OFFLOAD_WORKERS = 4
    _stop_plane()
    assert main._offload_max_workers() == (4, "config")


def test_a_full_plane_makes_the_caller_wait_instead_of_queueing():
    """MUTATION TARGET — §9 backpressure.

    One worker, an in-flight ceiling of two, five calls. Exactly two may be
    admitted (one executing, one queued in the executor); the other three must
    be held at the gate, awaiting, and counted. Removing the bound admits all
    five, drives `admission_waiting` to 0 and fails here.
    """
    started = threading.Event()
    release = threading.Event()
    seen: dict[str, object] = {}

    def blocker():
        started.set()
        release.wait(10)

    async def scenario():
        tasks = [asyncio.ensure_future(main._offload(blocker))]
        tasks += [asyncio.ensure_future(main._offload(lambda: None))
                  for _ in range(4)]
        for _ in range(500):
            await asyncio.sleep(0.01)
            if started.is_set() and main.offload_stats()["admission_waiting"]:
                break
        seen["stats"] = main.offload_stats()
        release.set()
        return await asyncio.gather(*tasks)

    results = _run(scenario, workers=1, inflight=2)
    s = seen["stats"]
    assert s["queue_bounded"] is True
    assert s["admission_limit"] == 2
    assert s["admission_inflight"] == 2, s
    assert s["admission_waiting"] == 3, (
        f"three callers should be held at the gate, saw {s['admission_waiting']}"
        f" — the admission bound is not blocking anyone")
    # The executor queue itself is bounded BY the gate: admitted minus running.
    assert s["queue_depth"] == 1, s
    assert s["active_workers"] == 1
    assert s["rejected"] == 0, "backpressure must block, never drop"
    # and it RESUMES: every call still ran, and the waits were counted.
    assert len(results) == 5
    after = main.offload_stats()
    assert after["admission_waits_total"] == 3, after
    assert after["admission_wait_max_s"] > 0.0
    assert after["admission_waiting"] == 0 and after["admission_inflight"] == 0
    assert after["completed_total"] == 5


def test_the_executor_queue_can_never_exceed_the_admission_bound():
    """Sampled continuously rather than once: `queue_depth` is now a BOUND, and
    a bound that only holds at the instant you look at it is not a bound."""
    peak: list[int] = []
    release = threading.Event()

    async def watcher():
        while not release.is_set():
            peak.append(int(main.offload_stats()["queue_depth"]))
            await asyncio.sleep(0.002)

    async def scenario():
        w = asyncio.ensure_future(watcher())
        await asyncio.gather(*(main._offload(time.sleep, 0.01)
                               for _ in range(40)))
        release.set()
        await w

    _run(scenario, workers=2, inflight=4)
    assert peak, "the watcher never sampled"
    assert max(peak) <= 4, f"queue depth reached {max(peak)} with a bound of 4"
    assert main.OFFLOAD_DEPTH_PEAK <= 4


def test_admission_is_strictly_fifo_so_nobody_starves():
    """A bound that lets late arrivals barge is a starvation bug wearing a
    safety bound's clothes — which is exactly what `asyncio.Semaphore` does on
    3.10 (it re-checks its counter before a woken waiter is rescheduled). Under
    a bound of two and one worker, execution order must be arrival order."""
    order: list[int] = []
    lock = threading.Lock()

    def record(i: int) -> int:
        with lock:
            order.append(i)
        return i

    async def scenario():
        return await asyncio.gather(*(main._offload(record, i)
                                      for i in range(24)))

    results = _run(scenario, workers=1, inflight=2)
    assert results == list(range(24))
    assert order == list(range(24)), f"admission reordered the queue: {order}"


def test_a_slot_is_released_when_the_call_raises():
    """A leaked slot shrinks the plane silently until it wedges. One slot, one
    raising call, then a normal one that must still get through."""
    def boom():
        raise ValueError("kaboom")

    async def scenario():
        with pytest.raises(ValueError):
            await main._offload(boom)
        # Would hang forever on a leaked slot; the timeout turns a wedge into a
        # failure instead of a hung suite.
        return await asyncio.wait_for(main._offload(lambda: "through"), 5)

    assert _run(scenario, workers=1, inflight=1) == "through"
    assert main.offload_stats()["admission_inflight"] == 0


def test_a_slot_is_released_when_the_awaiting_caller_is_cancelled():
    """Cancellation at the gate must drop the caller out of line, and
    cancellation AFTER the slot was granted must hand it straight on."""
    release = threading.Event()
    started = threading.Event()

    def blocker():
        started.set()
        release.wait(10)

    async def scenario():
        held = asyncio.ensure_future(main._offload(blocker))
        for _ in range(500):
            await asyncio.sleep(0.01)
            if started.is_set():
                break
        queued = asyncio.ensure_future(main._offload(lambda: None))
        await asyncio.sleep(0.05)          # let it reach the gate and wait
        assert main.offload_stats()["admission_waiting"] == 1
        queued.cancel()
        with pytest.raises(asyncio.CancelledError):
            await queued
        release.set()
        await held
        return await asyncio.wait_for(main._offload(lambda: "through"), 5)

    assert _run(scenario, workers=1, inflight=1) == "through"
    st = main.offload_stats()
    assert st["admission_inflight"] == 0 and st["admission_waiting"] == 0


def test_a_call_cancelled_while_queued_does_not_leak_queue_depth():
    """`_timed` clears the pending entry, and a cancelled-while-queued call
    never runs it. Before the bound that was a cosmetic drift in a gauge; now
    the gauge is a queue bound, and drift would shrink the plane for good."""
    release = threading.Event()
    started = threading.Event()

    def blocker():
        started.set()
        release.wait(10)

    async def scenario():
        held = asyncio.ensure_future(main._offload(blocker))
        for _ in range(500):
            await asyncio.sleep(0.01)
            if started.is_set():
                break
        queued = asyncio.ensure_future(main._offload(lambda: None))
        await asyncio.sleep(0.05)
        assert main.offload_stats()["queue_depth"] == 1
        queued.cancel()
        with pytest.raises(asyncio.CancelledError):
            await queued
        release.set()
        await held

    _run(scenario, workers=1, inflight=2)
    assert main.offload_stats()["queue_depth"] == 0
    assert main.offload_stats()["active_workers"] == 0


def test_nothing_offloaded_can_re_enter_the_admission_gate():
    """THE DEADLOCK AUDIT, as an assertion rather than a comment.

    A gate held across an await deadlocks the instant offloaded work needs the
    gate itself. Today it cannot: every callable handed to `_offload` (directly
    or through `_snap_call` / `_decision_offload`) is a SYNCHRONOUS pure
    function running on an executor thread, and `_offload` is a coroutine, so an
    offloaded callable has no way to re-enter it. This walks the real call sites
    in main.py and fails the day someone offloads a coroutine function — the
    change that would need a nested-call reservation before it is safe.
    """
    tree = ast.parse(pathlib.Path(main.__file__).read_text())
    forwarders = {"_offload": 0, "_decision_offload": 1, "_snap_call": 1}
    names: set[str] = set()
    sites = 0
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)):
            continue
        skip = forwarders.get(node.func.id)
        if skip is None or len(node.args) <= skip:
            continue
        sites += 1
        target = node.args[skip]
        if isinstance(target, ast.Name):
            names.add(target.id)
        elif isinstance(target, ast.Attribute):
            names.add(target.attr)
    assert sites >= 15, f"only found {sites} offload call sites — the walk broke"
    # `fn` is the parameter the two forwarders pass through; their own callers
    # are the sites already collected above.
    checked = 0
    for name in sorted(names - {"fn"}):
        for holder in (main, getattr(main, "ObjectSnapshot", None)):
            obj = getattr(holder, name, None) if holder is not None else None
            if obj is None:
                continue
            checked += 1
            assert not asyncio.iscoroutinefunction(obj), (
                f"{name} is a coroutine function handed to the offload plane — "
                f"it would re-enter the admission gate and wedge it")
    assert checked >= 8, f"resolved only {checked} offload targets"


# ── shutdown ─────────────────────────────────────────────────────────────────

def test_stopping_the_plane_leaves_no_threads_behind():
    _run(lambda: main._offload(lambda: None), workers=3)
    assert _live_offload_threads(), "the pool never started a worker"
    report = _stop_plane()
    assert report == {"drained": 0, "abandoned": 0}, (
        "nothing was in flight, so the stop had nothing to drain or abandon")
    for _ in range(200):                    # workers exit on the pool's sentinel
        if not _live_offload_threads():
            break
        time.sleep(0.01)
    assert _live_offload_threads() == []
    assert main._OFFLOAD_EXECUTOR is None and main._OFFLOAD_GATE is None


def test_stop_counts_what_the_drain_actually_saved():
    """`drained` is the work THIS stop waited out, not a process-lifetime total
    — a lifetime figure would read as success on a shutdown that abandoned
    everything it was holding."""
    release = threading.Event()
    started = threading.Event()
    holder: dict[str, object] = {}

    def slow():
        started.set()
        release.wait(10)
        return "landed"

    async def scenario():
        task = asyncio.ensure_future(main._offload(slow))
        for _ in range(500):
            await asyncio.sleep(0.01)
            if started.is_set():
                break
        stopping = asyncio.ensure_future(main.offload_stop(drain_s=5.0))
        await asyncio.sleep(0.05)          # the drain is waiting, not spinning
        release.set()
        holder["report"] = await stopping
        return await task

    assert _run(scenario, workers=2) == "landed"
    assert holder["report"] == {"drained": 1, "abandoned": 0}, holder["report"]
    assert main.OFFLOAD_ABANDONED == 0


def test_stop_is_idempotent_and_the_plane_comes_back():
    assert _stop_plane() == {"drained": 0, "abandoned": 0}
    assert _stop_plane() == {"drained": 0, "abandoned": 0}
    assert _run(lambda: main._offload(lambda: 7), workers=2) == 7


def test_stop_reports_what_it_abandoned_rather_than_hanging():
    """A `run_window` mid-storm can outlast any deadline worth having. Shutdown
    must be bounded and must SAY what it left — a hung shutdown is the worse
    failure, and a silent one is worse still."""
    release = threading.Event()
    started = threading.Event()

    def blocker():
        started.set()
        release.wait(10)

    holder: dict[str, object] = {}

    async def scenario():
        task = asyncio.ensure_future(main._offload(blocker))
        for _ in range(500):
            await asyncio.sleep(0.01)
            if started.is_set():
                break
        holder["report"] = await main.offload_stop(drain_s=0.05)
        release.set()
        await task

    _run(scenario, workers=2)
    assert holder["report"]["abandoned"] == 1, holder["report"]
    assert main.OFFLOAD_ABANDONED == 1
    assert main.offload_stats()["abandoned_total"] == 1
    for _ in range(200):
        if not _live_offload_threads():
            break
        time.sleep(0.01)
    assert _live_offload_threads() == []


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


@pytest.mark.parametrize("rows", [
    [],
    [{"a": 1}],
    [{"tenant": f"t{i}", "n": i, "s": "x" * (i % 17)} for i in range(400)],
])
def test_a_representative_offload_is_byte_identical_to_running_it_inline(rows):
    """SEMANTICS EQUIVALENCE. Two of the pure builders that actually run on this
    plane (the ClickHouse body and the retained-batch dedup token — the token is
    load-bearing: a different token across a retry means a DUPLICATE insert
    instead of a server-side dedup). Bounded admission changes where the work
    waits, never what it produces."""
    async def scenario():
        return (await main._offload(main._ndjson_body, rows),
                await main._offload(main._batch_token, rows))

    body, token = _run(scenario, workers=1, inflight=1)
    assert body == main._ndjson_body(rows)
    assert token == main._batch_token(rows)


def test_nothing_is_ever_refused():
    """The plane is bounded now, so this is the load-bearing half of §9: the
    bound must express itself as a WAIT, never as a drop. 64 calls through a
    two-slot plane, and all 64 results come back in order."""
    async def many():
        return await asyncio.gather(*(main._offload(lambda i=i: i)
                                      for i in range(64)))
    assert _run(many, workers=2, inflight=2) == list(range(64))
    stats = main.offload_stats()
    assert stats["rejected"] == 0
    assert stats["queue_bounded"] is True
    assert stats["submitted_total"] == 64
    assert stats["completed_total"] == 64
    assert stats["admission_waits_total"] > 0, (
        "a two-slot plane and 64 calls must have made someone wait")


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

    _run(scenario, workers=1, inflight=4)
    s = seen["stats"]
    assert s["queue_depth"] == 2, f"expected two calls queued, saw {s['queue_depth']}"
    assert s["active_workers"] == 1
    assert s["oldest_queued_age_s"] > 0.0
    assert main.OFFLOAD_DEPTH_PEAK >= 2


def test_queue_wait_is_measured_not_assumed():
    """The second call cannot start until the first finishes, so its recorded
    WAIT must be at least the first call's execution time. Measured from
    ADMISSION, so it still means "queued in the executor" and stays comparable
    with the pre-bound numbers."""
    hold = 0.25

    async def scenario():
        a = asyncio.ensure_future(main._offload(time.sleep, hold))
        await asyncio.sleep(0.02)          # ensure a is submitted first
        b = asyncio.ensure_future(main._offload(lambda: None))
        await asyncio.gather(a, b)

    _run(scenario, workers=1, inflight=4)
    stats = main.offload_stats()
    assert stats["wait_max_s"] >= hold * 0.8, stats
    assert stats["exec_max_s"] >= hold * 0.8, stats
    assert stats["samples"] == 2


def test_no_contention_means_no_wait():
    """Negative control: with a free worker the wait must stay near zero, so a
    non-zero p95 in production is evidence of real queueing rather than a
    constant this code adds — and the admission gate must add none of it."""
    async def scenario():
        for _ in range(10):
            await main._offload(lambda: None)
    _run(scenario, workers=4)
    assert main.offload_stats()["wait_p95_s"] < 0.05
    assert main.offload_stats()["admission_waits_total"] == 0


def test_counters_balance_after_the_queue_drains():
    async def scenario():
        await asyncio.gather(*(main._offload(lambda: None) for _ in range(50)))
    _run(scenario, workers=3)
    s = main.offload_stats()
    assert s["submitted_total"] == s["started_total"] == 50
    assert s["completed_total"] + s["failed_total"] == 50
    assert s["queue_depth"] == 0 and s["active_workers"] == 0
    assert s["oldest_queued_age_s"] == 0.0
    assert s["admission_inflight"] == 0 and s["admission_waiting"] == 0


def test_counts_are_complete_under_concurrency():
    """Four workers, 400 calls: every submission is accounted for exactly once.

    HONEST LIMITATION — this does NOT prove `_OFFLOAD_LOCK` is necessary. The
    mutation run for wave 1 removed the lock and all 14 tests still passed, and
    direct probes could not produce a lost update or a torn dict snapshot on
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
    _run(scenario, workers=4)
    s = main.offload_stats()
    assert s["submitted_total"] == n
    assert s["started_total"] == n
    assert s["completed_total"] == n


def test_samples_are_bounded():
    """§9: the reservoirs cannot grow without bound."""
    assert main._OFFLOAD_WAIT_S.maxlen == main.CORR_OFFLOAD_SAMPLES
    assert main._OFFLOAD_EXEC_S.maxlen == main.CORR_OFFLOAD_SAMPLES


def test_the_configured_bounds_are_sane():
    """A zero-worker plane hangs and a ceiling under the worker count starves
    the pool it is supposed to protect; both must be impossible to configure."""
    assert main.CORR_OFFLOAD_WORKERS >= 1
    assert main.CORR_OFFLOAD_INFLIGHT_MAX >= main.CORR_OFFLOAD_WORKERS


# ── quantiles ────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("q,expected", [(0.5, 5), (0.95, 10), (0.99, 10)])
def test_quantile_is_nearest_rank(q, expected):
    assert main._quantile(list(range(1, 11)), q) == expected


def test_quantile_of_nothing_is_zero_not_a_crash():
    assert main._quantile([], 0.5) == 0.0


def test_stats_never_touch_the_event_loop():
    """uvloop — which is what actually runs in the container — has no
    `_default_executor` attribute at all. The first build of this metric read it
    off the running loop, guarded only RuntimeError, and so /metrics and
    /healthz raised AttributeError on startup: the container never went healthy,
    and unit tests missed it because pytest drives the stdlib loop, which does
    have the attribute.

    Owning the executor removes the question — nothing here asks the loop
    anything. Asserted the strong way: `asyncio.get_running_loop` is replaced
    with a landmine, and the whole snapshot must still render. That also keeps
    it safe from the health sidecar, which calls it from its own thread where
    there is no loop at all.
    """
    from unittest import mock

    def _landmine():
        raise AssertionError("offload_stats must not touch the event loop")

    _run(lambda: main._offload(lambda: None), workers=2)
    with mock.patch.object(asyncio, "get_running_loop", _landmine):
        stats = main.offload_stats()
        workers, source = main._offload_max_workers()
    assert stats["max_workers"] == workers > 0
    assert source == "executor"
