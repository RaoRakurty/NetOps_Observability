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

These tests assert the two properties that make the fix correct and safe:

1. RESILIENCE — driving a single-tenant storm cohort through the reconciliation
   loop, an instrumented heartbeat-proxy coroutine (standing in for aiokafka's
   background heartbeat task) keeps getting scheduled. With the budget disabled
   the loop freezes it for the whole grind; with the budget on, the worst
   scheduling gap collapses to a small fraction of that, well under the Kafka
   session timeout.

2. DETERMINISM — the yields interleave scheduling ONLY. The same workload
   produces byte-identical OPEN_OBJECTS state, persisted rows and version
   counters with the budget on and off. The golden-wire/replay suite is the
   broader guardrail; this is the direct one for exactly this change.
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
_STORM_DEVICES = 700   # folds to ~500 open objects — a real single-tenant storm
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
    main._ARCHIVE_SLICE_HASH.clear()
    main.VERSIONS_PERSISTED = 0
    main.VERSIONS_DAMPED = 0
    lvl = main.log.level
    main.log.setLevel(logging.WARNING)   # the per-object INFO would dwarf the grind
    yield
    main.log.setLevel(lvl)
    main._ARCHIVE_SLICE_HASH.clear()


async def _worst_scheduling_gap_while(coro_fn, interval: float = 0.01):
    """Run ``coro_fn()`` while a ticker (the heartbeat proxy) measures the worst
    delay it is ever kept from running. Returns (worst_gap_s, work_duration_s)."""
    worst = 0.0
    stop = asyncio.Event()

    async def ticker():
        nonlocal worst
        while not stop.is_set():
            t0 = time.monotonic()
            await asyncio.sleep(interval)
            worst = max(worst, time.monotonic() - t0 - interval)

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
    heartbeat-proxy scheduling gap and the cohort's object count."""
    main.ch = _StubCH()
    main.OPEN_OBJECTS = {}
    main.VERSIONS_PERSISTED = 0
    main._ARCHIVE_SLICE_HASH.clear()
    main.CORR_LOOP_YIELD_MS = yield_ms
    _load(devices)

    async def cycle():
        await main.engine_cycle()

    worst, _dur = asyncio.run(_worst_scheduling_gap_while(cycle))
    return worst, len(main.OPEN_OBJECTS)


def test_reconciliation_loop_yields_under_single_tenant_storm():
    """The resilience invariant: a single-tenant storm cohort cannot hold the
    event loop past the budget. The heartbeat proxy keeps getting scheduled, so
    aiokafka's real heartbeat would too — no session expiry, no ejection."""
    worst_off, objs_off = _measure(_YIELD_DISABLED_MS, _STORM_DEVICES)
    worst_on, objs_on = _measure(50.0, _STORM_DEVICES)

    # Teeth: the workload must actually be a storm, and the un-yielded loop must
    # actually freeze the heartbeat proxy — otherwise the test proves nothing.
    assert objs_off >= 200 and objs_on >= 200, (
        f"the storm cohort collapsed to {objs_off}/{objs_on} objects — too "
        f"small to exercise the reconciliation grind")
    assert worst_off > 0.4, (
        f"the BEFORE baseline did not freeze the loop (worst gap "
        f"{worst_off*1000:.0f}ms) — the grind is too short to measure the fix")

    # The fix: the worst scheduling gap collapses to a small fraction of the
    # frozen baseline, and stays far under the 30s Kafka session timeout (the
    # thing whose expiry caused the production ejection/livelock).
    assert worst_on < 1.0, (
        f"the reconciliation loop still held the event loop for "
        f"{worst_on*1000:.0f}ms with the yield budget on — a storm this size "
        f"must never approach the session timeout")
    assert worst_off > 4 * worst_on, (
        f"the yield budget did not materially reduce the stall: "
        f"{worst_off*1000:.0f}ms (off) vs {worst_on*1000:.0f}ms (on)")


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
    on = _digest_after_open_then_damped(50.0, _DET_DEVICES)
    off = _digest_after_open_then_damped(_YIELD_DISABLED_MS, _DET_DEVICES)
    assert on == off, (
        "the yield budget changed the engine's output — determinism/replay "
        f"broken (on={on[:16]} off={off[:16]})")
    # The damped path must actually have been exercised, or the equality is
    # vacuous for the branch the storm livelocked on.
    assert main.VERSIONS_DAMPED >= 200, (
        f"the damped branch was not exercised (damped={main.VERSIONS_DAMPED})")
