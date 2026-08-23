"""Tracker 173 — the post-storm refusal-stream deadlock is BROKEN by 172.

THE OBSERVED INCIDENT (S1 run 082220005r1a end-state): cleanup deleted every
device, so all consumed events were tenant-refused BEFORE buffer_signal — the
stream watermark froze, semantic expiry stalled, and the engine re-correlated
a frozen dead window at ~1 core while the consumer starved at 2.7 eps.
Cleared that night by replica restart.

THE TRUE STRUCTURE (found reading _tenant_idle): the wall-clock idle backstop
deliberately requires the consumer to be LEVEL WITH THE BROKER (its condition
2 — idleness must be provable, not assumed), so with 2.8M of lag the backstop
COULD NOT fire — while, pre-172, the engine's own cycles were what kept the
lag from draining. A mutual deadlock: eviction waits for lag 0; lag waits for
the engine to yield.

THE RESOLUTION, pinned here as a case split over every reachable state:
  A. lag > CORR_INGEST_PRIORITY_LAG (fresh)  -> 172 DEFERS the engine, so the
     consumer drains the refusal stream at full speed. Exactly the state
     where the backstop cannot act — the two mechanisms are complementary
     with NO gap in which both stand down and work is unbounded.
  B. lag == 0 + watermark frozen past CORR_TENANT_IDLE_EVICT_S -> the idle
     backstop evicts the dead window (and releases its frontier ids), so
     engine cycles collapse to trivial and open objects quiesce.
  C. the remaining gap (0 < lag <= threshold) is BOUNDED WORK by definition
     of the threshold — no unbounded state exists.

Recovery is therefore bounded and unattended (drain + <=1h idle + quiesce) —
the SRE criterion — with NO new mechanism. 173 closes on this proof; if
either prong regresses, this file goes red.
"""
from __future__ import annotations

import asyncio
import time
from datetime import datetime, timedelta, timezone

import pytest

import main
from test_prune_buffer_156 import T0, mk


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    main.WINDOW_BUFFER.clear(); main._BUFFERED_IDS.clear()
    main._BUFFERED_ID_ORDER.clear(); main._PROCESSED_IDS.clear()
    main.TENANT_WATERMARK.clear(); main._TENANT_EDGES.clear()
    monkeypatch.setattr(main, "ENGINE_LAST_SWEEP_MONO", time.monotonic())
    monkeypatch.setattr(main, "CONSUMER_LAG_UNKNOWN_PARTITIONS", 0)
    yield
    main.WINDOW_BUFFER.clear(); main._BUFFERED_IDS.clear()
    main._BUFFERED_ID_ORDER.clear(); main._PROCESSED_IDS.clear()
    main.TENANT_WATERMARK.clear()


def _dead_window(n=50, tenant="global"):
    """The S1 end-state's retained window: admitted long ago, stream frozen."""
    for i in range(n):
        s = main.dc_replace(mk(i, i), tenant_id=tenant)
        main.WINDOW_BUFFER.append(s)
        main._BUFFERED_ID_ORDER.append(str(s.signal_id))
        main._BUFFERED_IDS.add(str(s.signal_id))
    # Watermark frozen LONG ago in wall time (refusals never advance it).
    main.TENANT_WATERMARK[tenant] = (
        (T0 + timedelta(seconds=100)).timestamp(),
        time.monotonic() - main.CORR_TENANT_IDLE_EVICT_S - 60,
    )


def test_prong_a_engine_defers_exactly_where_the_backstop_cannot(monkeypatch):
    """The deadlock-breaker: in the S1 end-state (huge fresh lag + frozen
    watermark) the idle backstop must refuse to act (idleness unproven) AND
    172 must defer the sweep — complementary, no standing-down gap."""
    _dead_window()
    now = time.monotonic()
    monkeypatch.setattr(main, "CONSUMER_LAG_TOTAL", 2_810_872)   # measured
    monkeypatch.setattr(main, "CONSUMER_LAG_AT", now)
    assert main._tenant_idle("global", now) is False, (
        "idle backstop fired with 2.8M of lag — idleness is no longer "
        "PROVEN, tracker 165's wall-clock-destroys-evidence defect is back")
    defer, reason = main._ingest_priority_decision(now)
    assert defer and reason == "ingest-behind", (
        "the engine does not defer in the exact state where the idle "
        "backstop cannot act — the S1 mutual deadlock is reachable again")


def test_prong_b_caught_up_frozen_stream_is_evicted_and_released(monkeypatch):
    """Once the refusal backlog is drained (lag 0), the frozen dead window
    must leave via the idle backstop — with its processed-frontier ids —
    so engine cycles collapse to trivial."""
    _dead_window()
    main._mark_processed(list(main.WINDOW_BUFFER)[:20])
    now = time.monotonic()
    monkeypatch.setattr(main, "CONSUMER_LAG_TOTAL", 0)
    monkeypatch.setattr(main, "CONSUMER_LAG_AT", now)
    assert main._tenant_idle("global", now) is True
    before = main.IDLE_TENANT_EVICTIONS
    asyncio.run(main._prune_buffer(datetime.now(timezone.utc)))
    assert len(main.WINDOW_BUFFER) == 0, "the dead window survived the backstop"
    assert main._PROCESSED_IDS == set(), "frontier ids outlived their signals"
    assert main.IDLE_TENANT_EVICTIONS == before + 50, (
        "evictions must be counted on the IDLE counter — this is the "
        "resource backstop, never semantic expiry")


def test_prong_b_requires_the_full_idle_threshold(monkeypatch):
    """The backstop must NOT fire early: a watermark frozen for less than
    CORR_TENANT_IDLE_EVICT_S keeps the evidence (it may still correlate)."""
    _dead_window()
    main.TENANT_WATERMARK["global"] = (
        (T0 + timedelta(seconds=100)).timestamp(),
        time.monotonic() - 30.0,                     # frozen only 30s
    )
    now = time.monotonic()
    monkeypatch.setattr(main, "CONSUMER_LAG_TOTAL", 0)
    monkeypatch.setattr(main, "CONSUMER_LAG_AT", now)
    assert main._tenant_idle("global", now) is False
    asyncio.run(main._prune_buffer(datetime.now(timezone.utc)))
    assert len(main.WINDOW_BUFFER) == 50, "evidence shed before the threshold"


def test_case_split_has_no_unbounded_gap(monkeypatch):
    """Prong C, stated as an executable table: for every (lag, watermark)
    state either the engine defers, the backstop may act, or the remaining
    work is bounded by the deferral threshold itself."""
    now = time.monotonic()
    monkeypatch.setattr(main, "CONSUMER_LAG_AT", now)
    frozen = time.monotonic() - main.CORR_TENANT_IDLE_EVICT_S - 60
    cases = [
        # (lag, expect_defer, expect_idle_possible)
        (5_000_000, True, False),      # A: storm end-state
        (main.CORR_INGEST_PRIORITY_LAG + 1, True, False),
        (main.CORR_INGEST_PRIORITY_LAG, False, False),   # C: bounded work
        (1, False, False),             # C: bounded work
        (0, False, True),              # B: backstop territory
    ]
    for lag, want_defer, want_idle in cases:
        main.TENANT_WATERMARK["global"] = ((T0.timestamp()), frozen)
        monkeypatch.setattr(main, "CONSUMER_LAG_TOTAL", lag)
        defer, _ = main._ingest_priority_decision(now)
        idle = main._tenant_idle("global", now)
        assert defer == want_defer, f"lag={lag}: defer={defer}"
        assert idle == want_idle, f"lag={lag}: idle={idle}"
        assert defer or idle or lag <= main.CORR_INGEST_PRIORITY_LAG, (
            f"lag={lag}: nobody acts and work is not bounded — the deadlock "
            f"gap is open")
