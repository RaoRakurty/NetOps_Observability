"""Tracker 165 phase 3 — which clock decides what Correlix may correlate?

Three different clocks are in play and they were never reconciled:

  * `build_edges`  — pure EVENT time. `gap` comes from `Signal.ts` and nothing
    else, so the engine's own semantics are event-time semantics.
  * `_prune_buffer` — WALL clock. The horizon is `datetime.now() - window_s`,
    compared against each signal's EVENT timestamp.
  * `consumer_state` / `cold_partitions` — MONOTONIC clock, also against
    `window_s`.

Mixing the first two meant the retained event-time span was not `window_s` but

    window_s - processing_lag

so processing delay alone silently shortened the RCA horizon, and past
`window_s` of lag it drove the horizon to zero. Measured lag on the 1K rig was
12-19 minutes against a 900 s window — inside the failure zone.

FIXED in this wave: retention runs on each tenant's STREAM clock (the newest
event timestamp seen for that tenant), so wall-clock backlog cannot shorten the
horizon. These tests were originally written to DOCUMENT the defect; they are
now inverted, and they are the regression proof. The same event-time story, with
an unchanged gap inside the engine's 396.5 s reach, must produce the SAME RCA
evidence no matter when it was processed.
"""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

import pytest

import main
from engine import EngineConfig, build_edges, build_nodes, engine_temporal_reach_s
from test_prune_buffer_156 import T0, mk, run

CFG = EngineConfig()

# A at 12:00:00, B at 12:05:00 — 300 s apart in EVENT time.
A_AT = 0
B_AT = 300


def _story():
    """The two signals of the story, same device so they ground by containment."""
    a = mk(1, A_AT)
    b = mk(1, B_AT)
    b = b.__class__(**{**{f.name: getattr(b, f.name)
                         for f in b.__dataclass_fields__.values()},
                       "kind": "if_util_high", "native_id": "nat-b"})
    return a, b


def _load(*sigs):
    main.WINDOW_BUFFER.clear()
    main._BUFFERED_IDS.clear()
    main._BUFFERED_ID_ORDER.clear()
    for s in sigs:
        main.WINDOW_BUFFER.append(s)
        main._BUFFERED_ID_ORDER.append(str(s.signal_id))
        main._BUFFERED_IDS.add(str(s.signal_id))


def _survivors(delay_s: float):
    """Buffer the story, then prune as if processing happened `delay_s` after B."""
    a, b = _story()
    _load(a, b)
    run(main._prune_buffer(T0 + timedelta(seconds=B_AT + delay_s)))
    return tuple(main.WINDOW_BUFFER)


# ── the engine's own verdict on the story, independent of any clock ──────────

def test_the_story_is_well_inside_the_engines_reach():
    """300 s apart, containment-grounded: the engine can still attach these."""
    gap = B_AT - A_AT
    assert gap < engine_temporal_reach_s(CFG)
    a, b = _story()
    edges, _ = build_edges(build_nodes((a, b)), (), CFG)
    assert len(edges) == 1, "fixture must be attachable in event time"


# ── but the buffer decides in wall-clock time ────────────────────────────────

def test_processed_promptly_both_signals_survive_and_rca_forms():
    surv = _survivors(delay_s=10)
    assert len(surv) == 2
    edges, _ = build_edges(build_nodes(surv), (), CFG)
    assert len(edges) == 1


@pytest.mark.parametrize("delay_min", [15, 30, 120])
def test_processing_lag_no_longer_destroys_the_story(delay_min):
    """THE regression test for tracker 165.

    Before the fix, 15 minutes of processing lag evicted the CAUSE and the edge
    disappeared. Retention is now stream-relative, so an arbitrarily late
    replay of the same events keeps exactly the same evidence.
    """
    surv = _survivors(delay_s=delay_min * 60)
    assert len(surv) == 2, (
        f"{delay_min} min of wall-clock lag must not evict event-time-valid "
        f"evidence; kept {[s.kind for s in surv]}")
    edges, _ = build_edges(build_nodes(surv), (), CFG)
    assert len(edges) == 1, "the RCA edge must survive processing delay"


def test_a_full_day_of_backlog_still_correlates():
    """The strong form: retention no longer references the wall clock at all
    for semantic expiry, so backlog depth is irrelevant to what is retained."""
    surv = _survivors(delay_s=24 * 3600)
    assert len(surv) == 2
    edges, _ = build_edges(build_nodes(surv), (), CFG)
    assert len(edges) == 1


def test_the_retained_span_no_longer_shrinks_with_lag():
    """The old formula was `retained = window_s - lag`. There is no lag term
    any more: the same stream produces the same span at every delay."""
    spans = []
    for lag in (0, 300, 600, 3600):
        main.WINDOW_BUFFER.clear()
        main._BUFFERED_IDS.clear()
        main._BUFFERED_ID_ORDER.clear()
        main.TENANT_WATERMARK.clear()
        sigs = [mk(i % 50, i) for i in range(400)]
        _load(*sigs)
        newest = 399
        main.TENANT_WATERMARK["acme"] = (
            (T0 + timedelta(seconds=newest)).timestamp(), time.monotonic())
        run(main._prune_buffer(T0 + timedelta(seconds=newest + lag)))
        spans.append(round(main._window_span_s()))
    assert len(set(spans)) == 1, f"span varied with lag: {spans}"
    assert spans[0] == 399


# ── stream time still expires what it should ─────────────────────────────────

def test_evidence_beyond_the_retention_horizon_is_still_expired():
    """The fix must not become 'never prune'. Once the tenant's OWN stream has
    moved past the horizon, old evidence goes — that is semantic expiry."""
    main.WINDOW_BUFFER.clear()
    main._BUFFERED_IDS.clear()
    main._BUFFERED_ID_ORDER.clear()
    main.TENANT_WATERMARK.clear()
    old = mk(2, 0)
    fresh = mk(3, int(main.RETENTION_REQUIRED_S) + 100)
    _load(old, fresh)
    main._advance_watermark(fresh, time.monotonic())
    run(main._prune_buffer(datetime.now(timezone.utc)))
    assert [s.native_id for s in main.WINDOW_BUFFER] == ["nat-3"]
    assert main.STREAM_TIME_EVICTIONS > 0


def test_a_stalled_tenant_does_not_expire_a_moving_one(monkeypatch):
    """Per-tenant watermarks, not one global clock. Tenant B streaming far
    ahead must not evict tenant A's evidence — a global watermark would, and
    the loss would be invisible."""
    main.WINDOW_BUFFER.clear()
    main._BUFFERED_IDS.clear()
    main._BUFFERED_ID_ORDER.clear()
    main.TENANT_WATERMARK.clear()
    a = main.dc_replace(mk(1, 0), tenant_id="slow")
    b_old = main.dc_replace(mk(2, 0), tenant_id="fast")
    b_new = main.dc_replace(mk(3, int(main.RETENTION_REQUIRED_S) + 100),
                            tenant_id="fast")
    _load(a, b_old, b_new)
    for s in (a, b_old, b_new):
        main._advance_watermark(s, time.monotonic())
    run(main._prune_buffer(datetime.now(timezone.utc)))
    kept = {s.tenant_id for s in main.WINDOW_BUFFER}
    assert "slow" in kept, "a fast tenant's stream must not expire a slow one"
    assert [s.native_id for s in main.WINDOW_BUFFER
            if s.tenant_id == "fast"] == ["nat-3"], (
        "the fast tenant's own old evidence SHOULD expire")


def test_the_idle_backstop_is_a_resource_control_not_semantic_expiry(monkeypatch):
    """A tenant whose stream stops would retain forever. The wall-clock
    backstop bounds that — and is counted separately so it can never be read as
    ordinary expiry."""
    main.WINDOW_BUFFER.clear()
    main._BUFFERED_IDS.clear()
    main._BUFFERED_ID_ORDER.clear()
    main.TENANT_WATERMARK.clear()
    monkeypatch.setattr(main, "CORR_TENANT_IDLE_EVICT_S", 60.0)
    s = mk(4, 0)
    _load(s)
    # watermark frozen well in the past (monotonic), i.e. the stream stalled
    main.TENANT_WATERMARK["acme"] = (s.ts.timestamp(), time.monotonic() - 600)
    before = main.IDLE_TENANT_EVICTIONS
    before_stream = main.STREAM_TIME_EVICTIONS
    run(main._prune_buffer(T0 + timedelta(seconds=10_000)))
    assert len(main.WINDOW_BUFFER) == 0
    assert main.IDLE_TENANT_EVICTIONS == before + 1
    assert main.STREAM_TIME_EVICTIONS == before_stream, (
        "a backstop eviction must not be counted as stream-time expiry")


def test_watermarks_are_monotonic():
    """An out-of-order arrival must not drag the clock backwards — that would
    resurrect an expired horizon and make eviction non-deterministic."""
    main.TENANT_WATERMARK.clear()
    newer, older = mk(1, 500), mk(2, 100)
    main._advance_watermark(newer, time.monotonic())
    before = main.WATERMARK_REGRESSIONS
    main._advance_watermark(older, time.monotonic())
    assert main.TENANT_WATERMARK["acme"][0] == newer.ts.timestamp()
    assert main.WATERMARK_REGRESSIONS == before + 1, "regressions must be counted"


def test_the_watermark_map_is_bounded(monkeypatch):
    """§9: tenant churn cannot grow the map without limit."""
    main.TENANT_WATERMARK.clear()
    monkeypatch.setattr(main, "CORR_TENANT_WATERMARK_MAX", 5)
    for i in range(50):
        main._advance_watermark(
            main.dc_replace(mk(1, i), tenant_id=f"t{i}"), time.monotonic() + i)
    assert len(main.TENANT_WATERMARK) <= 5
