# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Reconciliation-loop yield budget — the storm-collapse resilience fix.

Root cause (production loop-lag watchdog, worst stall 130,561 ms): the
per-snapshot reconciliation loop in ``main._engine_cycle_inner`` yielded
PER TENANT only (`await asyncio.sleep(0)` at the top of the tenant loop). Its
inner ``for snap in snapshots`` loop took no yield between snapshots, and on the
damped/unchanged path (content moved, material didn't → no `_persist_snapshot`,
no I/O await) it ran `find_continuation` + an inline `content_hash` synchronously
for thousands of snapshots. An S1 storm concentrates on ONE tenant, so the
per-tenant yield fired once and then the loop ground for tens of seconds with no
heartbeat → aiokafka session expiry → consumer ejection → "lag never drains"
livelock.

The fix (`CORR_LOOP_YIELD_MS`, default 50 ms): a time-budgeted cooperative
yield inside the per-object stretches (the snapshot loop, the find_merges result
loop, quiesce, the count cap) so the loop can never hold the event-loop thread
past the budget, for any single-tenant object count.

These tests assert the three properties that make the fix correct and safe:

1. RESILIENCE — driving a single-tenant storm cohort through the reconciliation
   loop, the loop hands the event-loop thread back BETWEEN OBJECTS. Measured in
   OBJECTS, not milliseconds: a heartbeat-proxy coroutine (standing in for
   aiokafka's background heartbeat task) samples `VERSIONS_PERSISTED` every time
   it is scheduled, so "the worst stretch the loop held" is a COUNT of objects
   the engine got through without letting anyone else run. With the gate armed
   that count is 1. With the budget disabled it is the WHOLE cohort — the
   production livelock, reproduced exactly, with no clock in the assertion.

2. BUDGET — the gate itself hands back when, and only when, the budget it was
   given has elapsed. Driven against a FAKE clock, so 50 ms means 50 ms and not
   "whatever this machine did".

3. DETERMINISM — the yields interleave scheduling ONLY. The same workload
   produces byte-identical OPEN_OBJECTS state, persisted rows and version
   counters with the budget on and off. The golden-wire/replay suite is the
   broader guardrail; this is the direct one for exactly this change.

WHY 1 AND 2 ARE NOT ONE WALL-CLOCK RATIO ANY MORE (2026-09-12)
--------------------------------------------------------------
Until this change, 1 was a wall-clock A/B: measure the worst heartbeat-proxy
scheduling GAP with the budget on and with it disabled, and assert the disabled
leg was at least 4x the armed one, with `timing_gate` growing the device count
until the disabled leg was big enough to be a witness. It failed on three
GitHub-hosted runs (359834be, 7375cfa7, bb9fb33b) while passing on the lab box,
and the correlation tree was byte-for-byte identical between the last green run
and the first red one. Two measured reasons, both fatal to the shape, neither a
defect in the fix:

  * THE DISABLED LEG SATURATES, so growing the fixture cannot rescue it.
    `CORR_OPEN_OBJECTS_MAX` (5,000) force-closes the excess, so past ~5,000
    objects the cohort — and the grind — stops growing. Measured on the lab box:
    700 devices → 2.05 s, 2,690 → 3.35 s, 5,705 → 3.94 s (5,910 objects
    force-closed), 12,342 → 3.31 s, i.e. it goes DOWN. The hosted runner walked
    the same wall: 0.885 s, 1.603 s, 1.572 s, 1.546 s against a 1.7 s floor, and
    reported "this machine outran the size cap" when nothing of the sort had
    happened. `timing_gate` requires "bigger fixture => bigger number"; on this
    axis that is false.

  * THE ARMED LEG IS NOT MACHINE-PINNED EITHER, so growing the fixture actively
    works against the ratio: the armed number appears in BOTH sides of it.
    Measured on the lab box: 144 ms at 700 devices but 358 ms at 2,690, because
    one un-splittable stretch per cycle scales with the cohort
    (`engine.epoch_prepare`, 216 ms at 4,880 objects, no yield inside it —
    tracker 288). That is what run 359834be actually hit: the sizer grew the
    fixture to 2,800 devices and the ratio it then computed was 1,795 ms off vs
    512 ms on, 3.5x, under the asserted 4x.

So the resilience property is now counted rather than timed. A count has no
tolerance to widen and no runner to blame: the armed loop hands back after one
object or the test is red.

The absolute design SLO stays (`worst_on < 1 s` against a 30 s Kafka session
timeout, at the live single-tenant shape). Its BOUND is unchanged; its
INSTRUMENT is not. It reads the hold off `time.thread_time()`, the event-loop
thread's own CPU, because holding the loop is what the fix prevents and being
descheduled by a neighbour on the host is not. Measured on the lab box with both
instruments in the same run: at load average 3, 144 ms of wall clock; at load
average 38, 382 ms of wall clock against 86 ms of loop-thread CPU; with eight
extra CPU hogs on top, 645 ms of wall clock against 43 ms of CPU. The wall-clock
reading crossed the 1 s bound on this box at load average 43 with the engine
untouched, which is the same class of false red the ratio produced on CI.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import time
from datetime import timedelta

import pytest

import main
import signals as S
from test_prune_buffer_156 import T0

# A "disabled" budget: the wall-time deadline is never reached, so the loop
# behaves exactly as it did before the fix (per-tenant yield only). This is the
# BEFORE baseline every assertion is measured against.
_YIELD_DISABLED_MS = 10 ** 9
# The shipped budget, and the leg the absolute SLO is asserted against.
_YIELD_BUDGET_MS = 50.0
# The gate ARMED on every guarded point: a zero budget means the deadline is
# already spent on every call (`monotonic() >= monotonic() + 0` always holds),
# so the loop yields at each `await _loop_yield()`. This is what makes the
# resilience assertion a machine-independent COUNT: it takes the wall clock out
# of the measurement without changing which code runs.
_YIELD_EVERY_OBJECT_MS = 0.0
# The storm cohort, in DEVICES at a fixed 1 s spacing (one device folds to one
# incident). 700 is the live single-tenant shape. It is FIXED, not calibrated:
# the count assertions do not care how fast the machine is, and the axis cannot
# be grown past `CORR_OPEN_OBJECTS_MAX` anyway (see the module docstring).
_STORM_DEVICES = 700
# The counted legs run smaller. They assert that the un-yielded stretch is O(1)
# in the cohort rather than O(n), and that is size-independent — the disabled leg
# still proves the whole cohort runs as ONE stretch, just a 300-object one. 300
# keeps both legs (two engine cycles each) inside ~10 s; 700 costs ~23 s and
# proves exactly the same two counts. The live 700-device shape is still driven
# in full by the absolute SLO test below.
_COUNTED_DEVICES = 300
_DET_DEVICES = 300     # equality needs no scale; keep the determinism run quick


class _StubCH:
    """Records inserts without any real I/O — so the ONLY thing that can yield
    the loop during the reconciliation grind is the fix under test (a real
    ClickHouse insert awaits a socket; the stub does not). That makes the storm
    adversarial: every branch of the inner loop is awaitless here, exactly the
    damped-path shape the production livelock ran on."""

    def __init__(self) -> None:
        self.rows: dict[str, list[dict]] = {}

    async def insert(self, table: str, rows, **_kw) -> bool:
        self.rows.setdefault(table, []).extend(dict(r) for r in rows)
        return True


def _pair(i: int) -> list[S.Signal]:
    """Two correlated signals on device ``leaf{i}`` — a link-state change plus a
    device resource anomaly — the shape that grounds into one open object."""
    dev = f"leaf{i}"
    base = {
        "tenant_id": "acme", "source": S.Source.SYSLOG,
        "observer": S.observer_of(dev, S.ObserverType.DEVICE,
                                  collection_path="direct", clock_quality="unknown"),
        "modality_class": S.ModalityClass.CONTROL_PLANE,
    }
    return [
        S.Signal(ts=T0 + timedelta(seconds=i), kind="link_state_change",
                 entity_type=S.EntityType.INTERFACE, entity_id=f"{dev}:Gi0/1",
                 severity=S.Severity.CRIT, native_id=f"a-{i}",
                 entity_tokens=(dev,), **base),
        S.Signal(ts=T0 + timedelta(seconds=i + 1), kind="device_resource_anomaly",
                 entity_type=S.EntityType.DEVICE, entity_id=dev,
                 severity=S.Severity.CRIT, native_id=f"b-{i}",
                 entity_tokens=(dev,), **base),
    ]


def _load(n: int) -> None:
    for buf in (main.WINDOW_BUFFER, main._BUFFERED_IDS, main._BUFFERED_ID_ORDER,
                main.TENANT_WATERMARK, main._PROCESSED_IDS, main._TENANT_EDGES):
        buf.clear()
    for i in range(n):
        for s in _pair(i):
            sid = str(s.signal_id)
            main._BUFFERED_IDS.add(sid)
            main.WINDOW_BUFFER.append(s)
            main._BUFFERED_ID_ORDER.append(sid)
            main._advance_watermark(s, time.monotonic())


@pytest.fixture(autouse=True)
def _quiet_and_isolated(monkeypatch):
    """A single-tenant storm cohort in one cohort, no per-object log spam, and a
    clean engine slate (OPEN_OBJECTS / archive-slice cache / counters) so the two
    runs a determinism test compares start identical."""
    monkeypatch.setattr(main, "OPEN_OBJECTS", {})
    monkeypatch.setattr(main, "CORR_ENGINE_COHORT_SIZE", 40_000)
    # …and a FROZEN topology-staleness verdict. `topology_stale` is stamped into
    # every ObjectSnapshot, so it is part of the digest the determinism test
    # compares — but its value is a function of WALL CLOCK, not of anything this
    # file is testing: with the enrichment files absent (as they are in any test
    # run) `_topology_stale` returns False for CORR_TOPO_STALE_S=180 s after the
    # first call in the process and True forever after. A suite whose 180 s mark
    # happens to fall BETWEEN the test's two legs therefore digests one leg as
    # fresh and the other as stale and fails, with nothing wrong with the yield
    # budget at all. Reproduce it on any revision with:
    #     CORR_TOPO_STALE_S=3 pytest test_loop_yield_resilience.py
    # Pinning it here keeps the comparison about the only variable under test.
    monkeypatch.setattr(main, "_topology_stale", lambda _now: False)
    # …and a retention horizon that spans the whole synthetic storm. The window
    # expires on STREAM time (tracker 165), and `_pair` stamps one second per
    # device, so past ~516 devices (RETENTION_REQUIRED_S) the engine cycle
    # prunes the oldest signals mid-fixture and the cohort stops growing at 533
    # objects however many devices were loaded. Retention is not what this file
    # tests — every leg loads its window in one shot and drives ONE cycle — so
    # the horizon is lifted off the fixture and the device count becomes the
    # honest size knob it reads as.
    monkeypatch.setattr(main, "RETENTION_REQUIRED_S",
                        float(_STORM_DEVICES) * 4.0 + 120.0)
    main._ARCHIVE_SLICE_HASH.clear()
    main.VERSIONS_PERSISTED = 0
    main.VERSIONS_DAMPED = 0
    lvl = main.log.level
    main.log.setLevel(logging.WARNING)   # the per-object INFO would dwarf the grind
    yield
    main.log.setLevel(lvl)
    main._ARCHIVE_SLICE_HASH.clear()


async def _worst_loop_hold_while(coro_fn, interval: float = 0.01):
    """Run ``coro_fn()`` while a ticker (the heartbeat proxy) measures the worst
    stretch of EVENT-LOOP-THREAD CPU the work ever holds without letting it run.
    Returns (worst_hold_s, work_duration_s).

    `time.thread_time()` and not `time.monotonic()`, deliberately. What the fix
    bounds is the loop thread being HELD by CPU-bound work. Time the OS spends
    running some OTHER process is not a hold, it is contention on the host, and
    on a shared CI runner that is most of what a wall-clock reading measures:
    this same assertion, read off `monotonic`, went red on the lab box at load
    average 43 (144 ms of work stretched to over a second of wall clock) with the
    engine untouched. The ticker burns no CPU while it is asleep, so the thread
    CPU it sees advance between two of its own wakeups was all spent by the work
    under test, whatever else the machine was doing. `thread_time` never exceeds
    the wall-clock gap, so this reads the same number on a quiet box and simply
    stops reading the neighbours' load on a busy one.
    """
    worst = 0.0
    stop = asyncio.Event()

    async def ticker():
        nonlocal worst
        while not stop.is_set():
            t0 = time.thread_time()
            await asyncio.sleep(interval)
            worst = max(worst, time.thread_time() - t0)

    t = asyncio.create_task(ticker())
    await asyncio.sleep(interval * 4)   # the ticker must be running BEFORE we grind
    t0 = time.monotonic()
    await coro_fn()
    dur = time.monotonic() - t0
    stop.set()
    await t
    return worst, dur


def _measure(yield_ms: float, devices: int):
    """One fresh open cohort of ``devices`` single-tenant incidents, driven
    through a real engine cycle with the given yield budget; returns the worst
    loop-thread hold the heartbeat proxy saw and the cohort's object count."""
    main.ch = _StubCH()
    main.OPEN_OBJECTS = {}
    main.VERSIONS_PERSISTED = 0
    main._ARCHIVE_SLICE_HASH.clear()
    main.CORR_LOOP_YIELD_MS = yield_ms
    _load(devices)

    async def cycle():
        await main.engine_cycle()

    worst, _dur = asyncio.run(_worst_loop_hold_while(cycle))
    return worst, len(main.OPEN_OBJECTS)


def _objects_between_handoffs(yield_ms: float, devices: int):
    """Drive a single-tenant storm cohort through the DAMPED reconciliation path
    and measure, IN OBJECTS, the longest stretch the loop ran without handing the
    event-loop thread back.

    The damped path is the one the production livelock ran on, and it is the only
    one where this measurement has teeth. Cycle 1 OPENS every object, and an open
    object goes through `_persist_snapshot`, which carries the same gate — so an
    all-open cycle stays bounded even with the snapshot loop's own per-object
    yield deleted. Cycle 2 moves every object's content without moving its
    material, which takes the damped branch: no `_persist_snapshot`, no I/O
    await, nothing between one object and the next except
    `_engine_cycle_inner`'s own `await _loop_yield()`. That is the stretch that
    held the loop for tens of seconds in production, so that is the stretch this
    test measures.

    The heartbeat proxy (standing in for aiokafka's background heartbeat task) is
    a coroutine that does nothing but `await asyncio.sleep(0)` in a loop, so it is
    scheduled once per event-loop handoff. Every time it runs it reads
    `main.VERSIONS_DAMPED` — which the damped branch increments once per object —
    and the difference from its previous reading is exactly "how many objects the
    engine got through while nobody else could run".

    That is the same quantity the old wall-clock gap measured, in the unit the
    defect is actually about (objects held without a heartbeat) rather than in
    milliseconds of a shared runner's wall clock. Returns
    (worst_objects_between_handoffs, handoffs, damped_count).
    """
    main.ch = _StubCH()
    main.OPEN_OBJECTS = {}
    main.VERSIONS_PERSISTED = 0
    main.VERSIONS_DAMPED = 0
    main._ARCHIVE_SLICE_HASH.clear()
    main.CORR_LOOP_YIELD_MS = yield_ms
    _load(devices)

    asyncio.run(main.engine_cycle())        # cycle 1 — every object opens

    # Force the damped branch for the measured cycle: re-admit the identical
    # signals (same material) and mark each object's content as moved.
    main._PROCESSED_IDS.clear()
    for reg in main.OPEN_OBJECTS.values():
        reg["hash"] = "__content_moved__"
    main.VERSIONS_DAMPED = 0

    async def drive():
        worst = 0
        handoffs = 0
        stop = asyncio.Event()

        async def heartbeat_proxy():
            nonlocal worst, handoffs
            last = main.VERSIONS_DAMPED
            while not stop.is_set():
                await asyncio.sleep(0)
                handoffs += 1
                done = main.VERSIONS_DAMPED
                worst = max(worst, done - last)
                last = done

        t = asyncio.create_task(heartbeat_proxy())
        await asyncio.sleep(0)          # the proxy must be running BEFORE we grind
        await main.engine_cycle()       # cycle 2 — every object damps
        stop.set()
        await t
        return worst, handoffs

    worst, handoffs = asyncio.run(drive())
    return worst, handoffs, main.VERSIONS_DAMPED


def test_reconciliation_loop_yields_under_single_tenant_storm():
    """The resilience invariant, COUNTED: a single-tenant storm cohort cannot
    hold the event loop across objects. With the gate armed the loop hands back
    after every single object, so aiokafka's heartbeat would run between any two
    of them — no session expiry, no ejection. With the gate disabled the SAME
    cohort runs end to end as one un-yielded stretch, which is the production
    livelock reproduced.

    There is no clock in this test. Both numbers are machine-independent counts:
    on the 4-core lab box and on a GitHub-hosted runner alike, armed = 1 object
    and disabled = the whole cohort. See the module docstring for why the
    wall-clock ratio this replaced could not be made to hold on a shared runner.

    Proven to catch its own regression: deleting the `await _loop_yield()` at the
    foot of `_engine_cycle_inner`'s snapshot loop takes the armed number from 1
    to the whole cohort and this test goes red (2026-09-12).
    """
    armed, handoffs_armed, objs_armed = _objects_between_handoffs(
        _YIELD_EVERY_OBJECT_MS, _COUNTED_DEVICES)
    loose, _handoffs_loose, objs_loose = _objects_between_handoffs(
        _YIELD_DISABLED_MS, _COUNTED_DEVICES)

    # Teeth: the workload must actually be a storm, or neither number means
    # anything. Both legs drive the identical cohort, so they must agree on it.
    assert objs_armed == objs_loose >= 200, (
        f"the storm cohort collapsed to {objs_armed}/{objs_loose} objects — too "
        f"small to exercise the reconciliation grind")

    # The DEFECT, still reproduced: without the gate the whole cohort is one
    # un-yielded stretch. Measured at exactly `objs_loose`; the halving is slack
    # for a future await appearing somewhere on the path, never for timing.
    assert loose >= objs_loose // 2, (
        f"the un-yielded baseline held the loop for only {loose} of "
        f"{objs_loose} objects — the fixture is no longer a witness for the "
        f"stall the yield budget exists to prevent, so this gate proves nothing")

    # The FIX: one object, then the event loop gets the thread back. `<= 2`
    # rather than `== 1` only because the ready-queue order between two
    # cooperating tasks is an asyncio implementation detail; it is 1 in practice
    # and the property is that this is O(1) in the cohort size, not O(n).
    assert armed <= 2, (
        f"the reconciliation loop ran {armed} objects without handing the event "
        f"loop back (cohort {objs_armed} objects) — the per-object yield in "
        f"`_engine_cycle_inner` is not firing, and a single-tenant storm can "
        f"again hold the thread past the Kafka session timeout")
    # …and it really did hand back, per object, rather than skipping the loop.
    assert handoffs_armed >= objs_armed, (
        f"only {handoffs_armed} event-loop handoffs for {objs_armed} objects")


def _handed_back(coro) -> bool:
    """Run one `_loop_yield()` coroutine to completion WITHOUT an event loop and
    report whether it suspended. `asyncio.sleep(0)` is a bare `yield`, so a
    single `send(None)` either finishes the coroutine (the gate did not fire) or
    suspends it once (the gate handed the thread back). Driving it by hand is
    what lets the budget be tested against a frozen clock."""
    try:
        coro.send(None)
    except StopIteration:
        return False
    try:
        coro.send(None)
    except StopIteration:
        return True
    coro.close()
    raise AssertionError("the loop-yield gate suspended more than once")


def test_the_yield_gate_hands_back_exactly_on_its_budget(monkeypatch):
    """The budget half of the fix, on a FAKE clock: `_make_loop_yield` hands the
    thread back when the configured budget has been spent and not one call
    before, re-arms the deadline each time it fires, and `_reset` re-arms it from
    now (which is what the per-tenant boundary in the reconciliation loop relies
    on). 50 ms here means 50 ms, not "whatever this runner managed"."""
    clock = [1_000.0]
    monkeypatch.setattr(main.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(main, "CORR_LOOP_YIELD_MS", 50.0)

    loop_yield, reset = main._make_loop_yield()

    assert _handed_back(loop_yield()) is False      # nothing spent yet
    clock[0] += 0.049
    assert _handed_back(loop_yield()) is False      # 49 ms — still inside budget
    clock[0] += 0.002
    assert _handed_back(loop_yield()) is True       # 51 ms — the budget is spent
    assert _handed_back(loop_yield()) is False      # …and the deadline re-armed
    clock[0] += 0.050
    assert _handed_back(loop_yield()) is True       # the next 50 ms fires again
    clock[0] += 10.0
    reset()                                         # a new tenant starts fresh
    assert _handed_back(loop_yield()) is False, (
        "_reset did not re-arm the deadline from now")


def test_the_storm_cycle_stays_far_under_the_session_timeout():
    """The absolute design SLO: at the live single-tenant shape, with the SHIPPED
    50 ms budget, the worst the reconciliation loop HOLDS the event-loop thread
    is under a second — against the 30 s Kafka session timeout whose expiry
    caused the production ejection and livelock.

    The bound is 1 s, absolute and unchanged. It is not a ratio against a mutant,
    so no machine's speed can hollow it out, and it has never been the assertion
    that failed on CI: measured 144-156 ms on the 4-core lab box and 212 ms on a
    GitHub-hosted runner. What DID change (2026-09-12) is the instrument: the
    hold is read off `time.thread_time()`, the loop thread's own CPU, not off the
    wall clock — see `_worst_loop_hold_while`. Holding the loop is what the fix
    prevents; being descheduled by a neighbour on the host is not, and reading it
    off the wall clock is how this assertion went red at load average 43 with
    nothing wrong with the engine.
    """
    worst_on, objs = _measure(_YIELD_BUDGET_MS, _STORM_DEVICES)
    assert objs >= 200, (
        f"the storm cohort collapsed to {objs} objects — too small to exercise "
        f"the reconciliation grind")
    assert worst_on < 1.0, (
        f"the reconciliation loop held the event-loop thread for "
        f"{worst_on*1000:.0f}ms of CPU "
        f"with the yield budget on — a storm this size ({_STORM_DEVICES} "
        f"devices, {objs} objects) must never approach the session timeout")


def _digest_after_open_then_damped(yield_ms: float, devices: int) -> str:
    """Run the full lifecycle the fix touches — open every object, then drive
    the SAME objects back through the DAMPED path (content moved, material did
    not) — and hash the deterministic engine output: the OPEN_OBJECTS registry
    (version/content-hash/material-hash per object), every persisted row, and
    the version counters."""
    main.ch = _StubCH()
    main.OPEN_OBJECTS = {}
    main.VERSIONS_PERSISTED = 0
    main.VERSIONS_DAMPED = 0
    main._ARCHIVE_SLICE_HASH.clear()
    main.CORR_LOOP_YIELD_MS = yield_ms
    _load(devices)

    asyncio.run(main.engine_cycle())        # cycle 1 — every object opens

    # Force the damped branch for the next cycle: re-admit the identical signals
    # (same material) and mark each object's content as moved. `reg["hash"]` no
    # longer matches the recomputed content_hash → the elif fires; the material
    # is unchanged and the heartbeat has not elapsed → damped, exactly the
    # awaitless path the storm ran on.
    main._PROCESSED_IDS.clear()
    for reg in main.OPEN_OBJECTS.values():
        reg["hash"] = "__content_moved__"

    asyncio.run(main.engine_cycle())        # cycle 2 — every object damps

    registry = {
        cid: (reg["version"], reg["hash"], reg["material"])
        for cid, reg in sorted(main.OPEN_OBJECTS.items())
    }
    rows = {
        table: sorted(json.dumps(r, sort_keys=True, default=str) for r in rs)
        for table, rs in main.ch.rows.items()
    }
    blob = json.dumps(
        [registry, rows, main.VERSIONS_PERSISTED, main.VERSIONS_DAMPED],
        sort_keys=True, default=str)
    return hashlib.sha256(blob.encode()).hexdigest()


def test_yields_do_not_change_results():
    """Determinism guardrail: the cooperative yields interleave scheduling only.
    Byte-for-byte identical engine state, persisted rows and counters with the
    budget on (50 ms) and effectively off — proving the yields changed WHEN the
    loop reschedules, never WHAT it computed, in what order, or which versions
    it persisted."""
    on = _digest_after_open_then_damped(_YIELD_BUDGET_MS, _DET_DEVICES)
    off = _digest_after_open_then_damped(_YIELD_DISABLED_MS, _DET_DEVICES)
    assert on == off, (
        "the yield budget changed the engine's output — determinism/replay "
        f"broken (on={on[:16]} off={off[:16]})")
    # The damped path must actually have been exercised, or the equality is
    # vacuous for the branch the storm livelocked on.
    assert main.VERSIONS_DAMPED >= 200, (
        f"the damped branch was not exercised (damped={main.VERSIONS_DAMPED})")
