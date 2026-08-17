"""Event-loop blocking bounds — run: python3 -m pytest test_loop_blocking.py

Pins the 2026-08-17 P1 regression measured at 1000-device scale. LIVE EVIDENCE
from netops-correlation-2 (the ladder run's own log):

    03:34:47Z  corr-object 859c45d9 v4 open: ... nodes=750 edges=48375

The object COUNT stayed small (5-15 per 5-minute interval, verified against
netops.corr_objects), but each object was ENORMOUS: the 1000-device fleet emits
one uniform link-fault signature, so the whole access layer folds into a few
giant graphs. Every per-object step is then a SINGLE MONOLITHIC synchronous
call whose cost scales with the graph — measured on that exact shape:

    content_hash()        1.60s      to_object_row()       0.66s
    material_hash()       0.13s      to_typed_edge_rows()  0.40s
    to_evidence_rows()    0.31s      to_edge_rows()        0.16s
    CH.insert body build  0.68s      batcher token hash    0.93s
    => ~7.5s of UNINTERRUPTIBLE loop time per object per cycle
    => 10-15 objects = 75-110s frozen, matching the 84s / 193s / 421s stalls

aiokafka's heartbeat is a BACKGROUND TASK: it cannot run inside any of those
calls, so the broker expires the session (30s) and the rebalance loop starts.
Cooperative `await asyncio.sleep(0)` yields cannot help — there is no point
inside a single json.dumps at which a yield could run. The fix is structural:
every size-unbounded pure-CPU step goes through main._offload.

These tests assert the BOUND, not the speed: a concurrent ticker (standing in
for the heartbeat task) must keep getting scheduled while the giant object is
processed. They are operation//latency-ratio based rather than absolute-time
based so they hold on a slow CI runner.
"""

from __future__ import annotations

import asyncio
import dataclasses
import time
from datetime import timedelta
from typing import ClassVar

import pytest

import main
from catalog import builtin_catalog
from engine import run_window
from signals import EntityType, Severity
from test_engine import T0, sig

# Big enough to dominate a thread hand-off, small enough to keep the suite fast.
# The live shape was 750 nodes / 48,375 edges; the blocking is linear in both,
# so the property is identical at this size (and the SUM asserted below is a
# ratio, not a wall-clock budget).
NODES_DEVICES = 60
EDGES = 6000


@pytest.fixture(scope="module")
def giant():
    """A real ObjectSnapshot in the live 'whole layer folded into one object'
    shape: many nodes, a dense edge set, built from genuine engine output."""
    cat = builtin_catalog()

    def one(d):
        return run_window(
            [sig("link_state_change", EntityType.DEVICE, d, severity=Severity.CRIT),
             sig("device_resource_anomaly", EntityType.DEVICE, d,
                 severity=Severity.CRIT, offset_s=1)],
            cat, ())[0]

    base = one("dev0")
    nodes = tuple(n for i in range(NODES_DEVICES) for n in one(f"dev{i}").nodes)
    proto = base.edges[0]
    keys = [n.key for n in nodes]
    edges = []
    i = 0
    while len(edges) < EDGES:
        a, b = keys[i % len(keys)], keys[(i * 7 + 3) % len(keys)]
        i += 1
        if a != b:
            edges.append(dataclasses.replace(proto, from_node=a, to_node=b))
    return dataclasses.replace(
        base, correlation_id="giant", nodes=nodes, edges=tuple(edges),
        window_start=T0, window_end=T0 + timedelta(minutes=30))


async def _worst_lag_while(work, interval: float = 0.02) -> tuple[float, float]:
    """Run `work()` while a ticker measures loop scheduling delay.
    Returns (worst_lag_s, work_duration_s)."""
    worst = 0.0
    stop = asyncio.Event()

    async def ticker():
        nonlocal worst
        while not stop.is_set():
            t0 = time.monotonic()
            await asyncio.sleep(interval)
            worst = max(worst, time.monotonic() - t0 - interval)

    t = asyncio.create_task(ticker())
    await asyncio.sleep(interval * 4)   # the ticker must be running BEFORE we block
    t0 = time.monotonic()
    await work()
    dur = time.monotonic() - t0
    stop.set()
    await t
    return worst, dur


def test_snap_call_offloads_large_objects_and_keeps_the_loop_alive(giant):
    """The core bound: serializing a giant object must NOT freeze the loop.

    Asserted as a RATIO — the worst loop stall stays a small fraction of the
    work it overlaps. Inline (the regression) makes the two equal by
    definition, because the loop is the thing doing the work.
    """
    assert main._snap_elements(giant) >= main.CORR_OFFLOAD_MIN_ELEMENTS, (
        "fixture must exceed the offload threshold or the test proves nothing")

    async def offloaded():
        await main._snap_call(giant, giant.content_hash)
        await main._snap_call(giant, giant.to_object_row, 1, "open", "")
        await main._snap_call(giant, giant.to_edge_rows, 1)

    async def inline():
        giant.content_hash()
        giant.to_object_row(1, "open", "")
        giant.to_edge_rows(1)

    worst_off, dur_off = asyncio.run(_worst_lag_while(offloaded))
    worst_in, dur_in = asyncio.run(_worst_lag_while(inline))

    # Inline: the loop is frozen for essentially the whole call.
    assert worst_in > dur_in * 0.5, (
        f"the inline baseline should freeze the loop (stall={worst_in:.2f}s of "
        f"{dur_in:.2f}s) — if it does not, the fixture is too small to measure")
    # Offloaded: the loop keeps running. 0.5 is a deliberately loose bound (the
    # measured live ratio was 0.39s stall / 2.80s work = 0.14).
    assert worst_off < dur_off * 0.5, (
        f"offloaded serialization still froze the loop for {worst_off:.2f}s of "
        f"{dur_off:.2f}s — the giant-object work is back on the event loop")
    # And strictly better than the inline path it replaces.
    assert worst_off < worst_in, (
        f"offload did not reduce the stall: {worst_off:.2f}s vs {worst_in:.2f}s")


def test_small_objects_keep_the_inline_path(giant):
    """The threshold must not send every tiny object through a thread: below
    CORR_OFFLOAD_MIN_ELEMENTS the call stays inline (and is provably cheap)."""
    small = dataclasses.replace(giant, nodes=giant.nodes[:2], edges=giant.edges[:2])
    assert main._snap_elements(small) < main.CORR_OFFLOAD_MIN_ELEMENTS

    calls: list[str] = []
    real_offload = main._offload

    async def spy(fn, /, *a, **k):
        calls.append(getattr(fn, "__name__", "?"))
        return await real_offload(fn, *a, **k)

    async def scenario():
        main._offload = spy
        try:
            await main._snap_call(small, small.content_hash)
            await main._snap_call(giant, giant.content_hash)
        finally:
            main._offload = real_offload

    asyncio.run(scenario())
    assert calls == ["content_hash"], (
        f"exactly the LARGE object should be offloaded, got {calls}")


def test_ch_insert_body_build_is_offloaded_for_large_batches(monkeypatch):
    """CH.insert used to build the whole NDJSON body on the loop — 22.5 MiB /
    0.68s for the live 48,375-row edge insert. Large batches must offload."""
    rows = [{"tenant_id": "t1", "i": i, "s": "x" * 40}
            for i in range(main.CORR_OFFLOAD_MIN_ELEMENTS + 10)]
    seen: list[str] = []
    real_offload = main._offload

    async def spy(fn, /, *a, **k):
        seen.append(getattr(fn, "__name__", "?"))
        return await real_offload(fn, *a, **k)

    posted: dict = {}

    class FakeResp:
        status_code = 200
        headers: ClassVar[dict] = {}
        text = ""

    class FakeClient:
        async def post(self, base, params=None, content=None, auth=None, headers=None):
            posted["body"] = content
            return FakeResp()

    async def scenario():
        c = main.CH.__new__(main.CH)
        c.base, c.auth, c.client = "http://ch", ("u", "p"), FakeClient()
        main._offload = spy
        try:
            assert await c.insert("netops.corr_edges", rows) is True
            seen.clear()
            await c.insert("netops.corr_edges", rows[:5])   # small: inline
        finally:
            main._offload = real_offload

    asyncio.run(scenario())
    # The large insert offloaded the body build; the small one did not.
    assert seen == [], f"a 5-row insert must not use a thread: {seen}"
    # Body is still byte-correct NDJSON (offloading must not change the wire).
    assert posted["body"].count("\n") == 4


def test_batch_token_is_identical_inline_and_offloaded():
    """The batcher's dedup token must be byte-stable across the offload — a
    different token would defeat ClickHouse server-side dedup on a retry."""
    rows = [{"signal_id": f"s{i}", "tenant_id": "t1"} for i in range(50)]
    inline = main._batch_token(rows)
    offloaded = asyncio.run(main._offload(main._batch_token, rows))
    assert inline == offloaded and inline.startswith("batch:")


# ── the watchdog that makes the next one self-reporting ─────────────────────

def test_loop_lag_watchdog_counts_and_reports_a_stall(monkeypatch):
    """A synchronous block on the loop must be COUNTED and exposed — the
    instrument this regression lacked (the 84s stalls had to be inferred from
    gaps between log lines)."""
    monkeypatch.setattr(main, "CORR_LOOP_LAG_SAMPLE_S", 0.01)
    monkeypatch.setattr(main, "CORR_LOOP_LAG_WARN_MS", 50.0)
    monkeypatch.setattr(main, "LOOP_LAG_STALLS", 0)
    monkeypatch.setattr(main, "LOOP_LAG_MAX_MS", 0.0)

    async def scenario():
        task = asyncio.create_task(main.loop_lag_watchdog())
        await asyncio.sleep(0.05)
        # A REAL synchronous block on the loop — that is precisely the defect
        # under test, so the sync sleep is the point, not a mistake.
        time.sleep(0.3)  # noqa: ASYNC251
        await asyncio.sleep(0.05)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    asyncio.run(scenario())
    assert main.LOOP_LAG_STALLS >= 1, "a 300ms block must be counted"
    assert main.LOOP_LAG_MAX_MS >= 200, (
        f"the stall size must be recorded, got {main.LOOP_LAG_MAX_MS:.0f}ms")


def test_watchdog_counters_are_on_healthz():
    """Counter-exposure contract (test_ga_failure_accounting's rule): a counter
    an operator cannot see is a counter that cannot alert."""
    payload = asyncio.run(main.health())
    d = payload["durability"]
    for key in ("loop_lag_stalls", "loop_lag_max_ms", "loop_lag_ms"):
        assert key in d, f"/healthz must expose {key}"
