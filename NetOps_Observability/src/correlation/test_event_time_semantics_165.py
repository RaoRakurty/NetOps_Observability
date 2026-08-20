"""Tracker 165 phase 3 — which clock decides what Correlix may correlate?

Three different clocks are in play and they were never reconciled:

  * `build_edges`  — pure EVENT time. `gap` comes from `Signal.ts` and nothing
    else, so the engine's own semantics are event-time semantics.
  * `_prune_buffer` — WALL clock. The horizon is `datetime.now() - window_s`,
    compared against each signal's EVENT timestamp.
  * `consumer_state` / `cold_partitions` — MONOTONIC clock, also against
    `window_s`.

Mixing the first two means the retained event-time span is not `window_s` but

    window_s - processing_lag

so processing delay alone silently shortens the RCA horizon, and past
`window_s` of lag it drives it to zero. Measured lag on the 1K rig was
12-19 minutes against a 900 s window — inside the failure zone.

These tests state that behaviour as a fact rather than a suspicion: the SAME
event-time story, with an unchanged event-to-event gap well inside the engine's
396.5 s reach, produces different RCA evidence depending only on WHEN it was
processed.
"""
from __future__ import annotations

from datetime import timedelta

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


def test_processed_late_the_cause_is_evicted_and_the_edge_disappears():
    """15 minutes of processing lag — nothing about the story changed."""
    surv = _survivors(delay_s=15 * 60)
    assert len(surv) == 1, "the older signal should have been pruned"
    assert surv[0].kind == "if_util_high", "the CAUSE is the one that was lost"
    edges, _ = build_edges(build_nodes(surv), (), CFG)
    assert edges == (), "same event-time story, no RCA edge — decided by lag alone"


def test_the_whole_story_is_gone_past_a_full_window_of_lag():
    """Lag > window_s means signals are pruned as fast as they arrive."""
    assert _survivors(delay_s=CFG.window_s + 60) == ()


def test_retained_event_span_is_window_minus_lag():
    """The quantitative statement: retention is not window_s, it is
    window_s - lag. This is the formula that turns a 900 s configuration into a
    180 s horizon at 12 minutes of lag."""
    for lag in (0, 300, 600):
        main.WINDOW_BUFFER.clear()
        main._BUFFERED_IDS.clear()
        main._BUFFERED_ID_ORDER.clear()
        # one signal per second across a full window
        sigs = [mk(i % 50, i) for i in range(int(CFG.window_s))]
        _load(*sigs)
        newest = int(CFG.window_s) - 1
        run(main._prune_buffer(T0 + timedelta(seconds=newest + lag)))
        span = main._window_span_s()
        expected = max(0.0, CFG.window_s - lag)
        assert span == pytest.approx(expected, abs=2.0), (
            f"lag={lag}s: retained {span:.0f}s, expected ~{expected:.0f}s")


def test_prune_is_the_only_place_the_two_clocks_meet():
    """A guard on the mixing point itself: the horizon is built from the
    caller's wall-clock `now` and compared to an EVENT timestamp. If someone
    changes the comparison to be event-time-relative (e.g. newest buffered ts),
    this test must be revisited deliberately, not silently."""
    a, b = _story()
    _load(a, b)
    # A wall clock far in the future prunes everything, regardless of the
    # signals' own relative timing — proof the decision is not event-relative.
    run(main._prune_buffer(T0 + timedelta(days=1)))
    assert len(main.WINDOW_BUFFER) == 0


# ── negative control: pruning must still work on genuinely old evidence ──────

def test_genuinely_aged_evidence_is_still_pruned():
    """The fix must not become 'never prune'. Evidence older than the retention
    horizon, with NO lag, still ages out."""
    main.WINDOW_BUFFER.clear()
    main._BUFFERED_IDS.clear()
    main._BUFFERED_ID_ORDER.clear()
    old = mk(2, -int(CFG.window_s) - 100)
    fresh = mk(3, 0)
    _load(old, fresh)
    run(main._prune_buffer(T0))
    assert [s.native_id for s in main.WINDOW_BUFFER] == ["nat-3"]
