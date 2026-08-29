"""2026-08-29 — OBSERVABILITY MAY NEVER REJECT A CORRELATION WINDOW.

THE DEFECT THIS FILE KILLS (run p2-s012-08290116, reproduced with a traceback).
With the opt-in stage profiler on (`CORR_PROFILE_STAGES=1`) EVERY engine cycle
raised:

    File "/app/main.py", in _engine_cycle_inner:  _record_cycle_work(tenant, work)
    File "/app/main.py", in _record_cycle_work:   CYCLE_WORK[k] = ... + int(v)
    ValueError: invalid literal for int() with base 10: ''

`_record_cycle_work` summed the engine's work sink with `int(v)`; commit dea93c20
(#168 hub-token cap) had added two NON-numeric fields to that sink
(`candidate_ceiling_dimension: ""`, `candidate_ceiling_hit: bool`). Two things
then made a bookkeeping bug into a correctness one:

  1. the call sat INSIDE the cohort loop's `except ValueError: ... continue`, so
     an accounting fault rejected the tenant's window;
  2. it sat BEFORE `evaluated.append(...)`, so the already-computed snapshots
     were discarded with it.

Consequence: every cohort's snapshots were thrown away, `_mark_processed` still
advanced the frontier, pending fell to 0, and the scale harness's
`correlation_completion` gate PASSED in 14 s on a run that produced ZERO
incidents. The log line was `log.error("engine window rejected: %s", exc)` — no
traceback, no count, no metric.

So the tests below hold three separate claims:

  A. the real #168 work-sink shape, with the profiler ON, correlates and
     PERSISTS (the end-to-end regression — this is the test that would have gone
     red on 2026-08-27);
  B. a fault ANYWHERE in profiler/accounting code is COUNTED and the window
     survives it (isolation, from the other side: injected faults);
  C. a genuine engine `ValueError` still rejects that tenant's window, but is
     counted, logged WITH its traceback, and the evidence it costs is accounted
     to `corr_signals_dropped_total{reason="window_rejected"}`.

Run:  cd src/correlation && python3 -m pytest test_observability_never_rejects_a_window.py -q
"""
from __future__ import annotations

import asyncio
import logging
import math

import pytest

import main
from test_cohort_touch_gate_p1 import _load, _StubCH, component


@pytest.fixture
def _stack(monkeypatch):
    """A cycle-able main.py with every counter this file reads reset.

    The counters are module globals and MONOTONIC, so without the reset a later
    test's "nothing was rejected" assertion is satisfied (or broken) by an
    earlier one's arithmetic rather than by its own behaviour.
    """
    main.WINDOW_BUFFER.clear(); main._BUFFERED_IDS.clear()
    main._BUFFERED_ID_ORDER.clear(); main._PROCESSED_IDS.clear()
    main.TENANT_WATERMARK.clear(); main._TENANT_EDGES.clear()
    main._ARCHIVE_SLICE_HASH.clear()
    monkeypatch.setattr(main, "ch", _StubCH())
    monkeypatch.setattr(main, "OPEN_OBJECTS", {})
    monkeypatch.setattr(main, "COHORTS_PROCESSED", 0)
    monkeypatch.setattr(main, "COHORT_SIGNALS_TOTAL", 0)
    monkeypatch.setattr(main, "VERSIONS_PERSISTED", 0)
    monkeypatch.setattr(main, "ENGINE_WINDOWS_REJECTED_TOTAL", 0)
    monkeypatch.setattr(main, "PROFILER_ERRORS_TOTAL", 0)
    monkeypatch.setattr(main, "_PROFILER_ERROR_LOGGED", False)
    monkeypatch.setattr(main, "SIGNALS_DROPPED_TOTAL", {"window_rejected": 0})
    monkeypatch.setattr(main, "CYCLE_WORK", {})
    monkeypatch.setattr(main, "CYCLE_WORK_LABELS", {})
    monkeypatch.setattr(main, "CYCLE_WORK_CYCLES", 0)
    # The whole point: the opt-in profiler ON. It is a module-level bool read at
    # import from CORR_PROFILE_STAGES, so the flag is what the test flips.
    monkeypatch.setattr(main, "CORR_PROFILE_STAGES", True)
    yield monkeypatch
    main.WINDOW_BUFFER.clear(); main._BUFFERED_IDS.clear()
    main._BUFFERED_ID_ORDER.clear(); main._PROCESSED_IDS.clear()
    main._TENANT_EDGES.clear(); main._ARCHIVE_SLICE_HASH.clear()


def _objects_persisted() -> int:
    return len(main.ch.rows.get("netops.corr_objects", []))


# ══ A. the end-to-end regression ═════════════════════════════════════════════


def test_the_168_work_sink_shape_with_the_profiler_ON_still_persists(_stack):
    """THE regression. Real signals, real engine, real work sink, profiler ON.

    Pre-fix this raised ValueError on `candidate_ceiling_dimension: ""`,
    discarded every snapshot, and persisted nothing while still reporting a
    completed cohort — a run that looked fast instead of empty.
    """
    _load(component(0) + component(1) + component(2))

    asyncio.run(main.engine_cycle())

    assert main.COHORTS_PROCESSED == 1
    assert _objects_persisted() == 3, (
        f"the cohort completed but persisted {_objects_persisted()} objects — "
        f"this is the hollow-completion shape the profiler used to produce")
    assert main.VERSIONS_PERSISTED == 3
    assert len(main.OPEN_OBJECTS) == 3
    assert main.ENGINE_WINDOWS_REJECTED_TOTAL == 0, (
        "accounting rejected a window again")
    assert main.PROFILER_ERRORS_TOTAL == 0


def test_the_work_accounting_is_populated_INCLUDING_the_string_label(_stack):
    """The fix must keep the measurement, not delete the offending fields: #168
    added `candidate_ceiling_dimension` precisely so an operator can see WHICH
    grouping hit the candidate ceiling."""
    _load(component(0) + component(1))
    asyncio.run(main.engine_cycle())

    assert main.CYCLE_WORK_CYCLES == 1
    assert main.CYCLE_WORK["nodes"] == 4
    assert "pairs_candidate" in main.CYCLE_WORK
    # bool is numeric here (False -> 0), a str is a label.
    assert main.CYCLE_WORK["candidate_ceiling_hit"] == 0
    assert "candidate_ceiling_dimension" in main.CYCLE_WORK_LABELS
    prof = main.cycle_work_profile()
    assert prof["cycles"] == 1
    assert prof["candidate_ceiling_dimension"] == \
        main.CYCLE_WORK_LABELS["candidate_ceiling_dimension"], (
        "cycle_work_profile() must still report the label — otherwise the fix "
        "bought correctness by losing #168's observable")


def test_the_exact_shape_that_raised_is_accepted_by_the_accumulator():
    """Unit-level, at the literal dict dea93c20 introduced."""
    main.CYCLE_WORK.clear(); main.CYCLE_WORK_LABELS.clear()
    main._record_cycle_work("t1", {
        "nodes": 6, "nodes_new": 0, "pairs_naive": 15, "pairs_candidate": 3,
        "pairs_old_old": 3, "pairs_new_old": 0, "pairs_new_new": 0,
        "hub_tokens_capped": 0, "hub_pairs_skipped": 0,
        "candidate_ceiling_hit": False,        # bool  -> summed as 0
        "candidate_ceiling_dimension": "",     # str   -> label (used to raise)
        "candidate_ceiling_group_size": 0,
    })
    assert main.CYCLE_WORK["nodes"] == 6
    assert main.CYCLE_WORK["candidate_ceiling_hit"] == 0
    assert main.CYCLE_WORK_LABELS["candidate_ceiling_dimension"] == ""


@pytest.mark.parametrize("value", ["", "token", None, float("nan"),
                                   float("inf"), object(), [1, 2], {"a": 1}])
def test_record_cycle_work_NEVER_raises_on_a_value(value):
    """The contract, stated as a property: no value in the work sink may end a
    correlation cycle. int() rejects a str, None, a NaN and an inf alike."""
    main.CYCLE_WORK.clear(); main.CYCLE_WORK_LABELS.clear()
    main._record_cycle_work("t1", {"nodes": 3, "odd": value})
    assert main.CYCLE_WORK["nodes"] == 3, "the numeric fields still accumulate"
    assert "odd" not in main.CYCLE_WORK
    assert "odd" in main.CYCLE_WORK_LABELS


def test_numeric_fields_sum_across_cycles_and_bools_count_as_one():
    main.CYCLE_WORK.clear(); main.CYCLE_WORK_LABELS.clear()
    main._record_cycle_work("t1", {"n": 2, "hit": True, "f": 1.5, "dim": "a"})
    main._record_cycle_work("t1", {"n": 3, "hit": True, "f": 1.5, "dim": "b"})
    assert main.CYCLE_WORK == {"n": 5, "hit": 2, "f": 2}
    assert main.CYCLE_WORK_LABELS["dim"] == "b", "a label keeps the LAST value"
    assert not any(isinstance(v, float) and not math.isfinite(v)
                   for v in main.CYCLE_WORK.values())


# ══ B. a profiler fault is counted, and the window SURVIVES it ═══════════════


def test_a_profiler_fault_is_COUNTED_and_the_snapshots_are_KEPT(_stack):
    """Isolation, from the injected-fault side. `_record_cycle_work` is made to
    raise the way the real one did; the cohort must still persist its objects.

    This is the mutant that dies if the accounting is ever moved back inside the
    `except ValueError` block or back above `evaluated.append(...)`.
    """
    def boom(_tenant, _work):
        raise ValueError("invalid literal for int() with base 10: ''")

    _stack.setattr(main, "_record_cycle_work", boom)
    _load(component(0) + component(1) + component(2))

    asyncio.run(main.engine_cycle())

    assert main.PROFILER_ERRORS_TOTAL == 1, (
        "an accounting fault was not counted — it is invisible again")
    assert main.ENGINE_WINDOWS_REJECTED_TOTAL == 0, (
        "an accounting fault rejected the window: the 2026-08-29 defect exactly")
    assert _objects_persisted() == 3, (
        "the tenant's snapshots were discarded by a bookkeeping error")
    assert main.epoch_state()["profiler_errors_total"] == 1


def test_the_first_profiler_fault_is_logged_WITH_its_traceback(_stack, caplog):
    def boom(_tenant, _work):
        raise ValueError("invalid literal for int() with base 10: ''")

    _stack.setattr(main, "_record_cycle_work", boom)
    _load(component(0))
    with caplog.at_level(logging.ERROR, logger=main.log.name):
        asyncio.run(main.engine_cycle())

    recs = [r for r in caplog.records if "profiler/accounting fault" in r.message]
    assert len(recs) == 1
    assert recs[0].exc_info is not None, (
        "logged without a traceback — the original defect took a day to find "
        "for exactly this reason")
    assert "_record_cycle_work" in recs[0].getMessage()


def test_repeated_profiler_faults_are_counted_but_logged_ONCE(_stack, caplog):
    """A per-cycle fault must not become a per-cycle log storm; the COUNTER is
    the durable signal."""
    def boom(_tenant, _work):
        raise RuntimeError("nope")

    _stack.setattr(main, "_record_cycle_work", boom)
    _stack.setattr(main, "CORR_ENGINE_COHORT_SIZE", 2)
    _load(component(0) + component(1) + component(2))
    with caplog.at_level(logging.ERROR, logger=main.log.name):
        for _ in range(3):
            asyncio.run(main.engine_cycle())

    assert main.PROFILER_ERRORS_TOTAL >= 3
    assert sum("profiler/accounting fault" in r.message for r in caplog.records) == 1
    assert main.ENGINE_WINDOWS_REJECTED_TOTAL == 0


def test_the_stage_timer_itself_cannot_raise_into_the_engine(_stack):
    """`stage(...)` wraps the run_window call, so a fault in the TIMER's own
    bookkeeping would propagate out of the engine call it only measures."""
    class _Hostile(dict):
        def get(self, *_a, **_kw):
            raise RuntimeError("stats table is wedged")

    _stack.setattr(main, "_STAGE_STATS", _Hostile())
    main.stage_record("engine.run_window", 0.01)          # must not raise
    assert main.PROFILER_ERRORS_TOTAL == 1
    assert main.ENGINE_WINDOWS_REJECTED_TOTAL == 0


# ══ C. a REAL engine ValueError: counted, traced, and its cost accounted ════


def test_a_real_ValueError_from_run_window_is_counted_and_accounted(_stack, caplog):
    """The genuine rejection path is KEPT — but it is now measurable.

    The decision it encodes (see `_engine_cycle_inner`): the rejected tenant's
    signals ARE still marked processed, because a deterministic input error
    would otherwise replay forever and stall every tenant's drain. The price is
    dropped evidence, so the price is counted.
    """
    def boom(*_a, **_kw):
        raise ValueError("window has a malformed node")

    _stack.setattr(main, "run_window", boom)
    sigs = component(0) + component(1)
    _load(sigs)
    with caplog.at_level(logging.ERROR, logger=main.log.name):
        asyncio.run(main.engine_cycle())

    assert main.ENGINE_WINDOWS_REJECTED_TOTAL == 1
    assert main.SIGNALS_DROPPED_TOTAL["window_rejected"] == len(sigs), (
        "the signals the rejected window cost were not accounted — a silent "
        "drop is what made a 14 s empty run look complete")
    assert main.PROFILER_ERRORS_TOTAL == 0, "this is not a profiler fault"
    assert _objects_persisted() == 0

    recs = [r for r in caplog.records if "window REJECTED" in r.message]
    assert len(recs) == 1
    assert recs[0].exc_info is not None, "rejection logged without a traceback"
    msg = recs[0].getMessage()
    assert "tenant=t1" in msg
    assert f"{len(sigs)} cohort signal(s)" in msg, (
        "the log must say HOW MANY signals the rejection discarded")


def test_the_rejected_cohort_is_still_marked_processed_and_that_is_DELIBERATE(_stack):
    """Pins the documented decision so a future change to it is a conscious one:
    the frontier is per-COHORT, and a poison window must not stall the drain.
    The invariant that makes it acceptable is that the loss is counted."""
    def boom(*_a, **_kw):
        raise ValueError("window has a malformed node")

    _stack.setattr(main, "run_window", boom)
    sigs = component(0) + component(1)
    _load(sigs)
    asyncio.run(main.engine_cycle())

    assert main.pending_signals() == [], (
        "the cohort was left pending: a deterministic input error would now "
        "replay every epoch forever — if this is the new intent, the harness "
        "gate and the docstring in _engine_cycle_inner must change with it")
    assert main.SIGNALS_DROPPED_TOTAL["window_rejected"] == len(sigs)


def test_ONE_tenants_rejection_does_not_discard_ANOTHER_tenants_snapshots(_stack):
    """Per-tenant blast radius, and the signal accounting is per tenant too."""
    real = main.run_window

    def only_t1_explodes(window, *a, **kw):
        if window and window[0].tenant_id == "t1":
            raise ValueError("t1's window is malformed")
        return real(window, *a, **kw)

    _stack.setattr(main, "run_window", only_t1_explodes)
    t1 = component(0, tenant="t1") + component(1, tenant="t1")
    t2 = component(2, tenant="t2")
    _load(t1 + t2)

    asyncio.run(main.engine_cycle())

    assert main.ENGINE_WINDOWS_REJECTED_TOTAL == 1
    assert main.SIGNALS_DROPPED_TOTAL["window_rejected"] == len(t1), (
        "the drop must be accounted for the REJECTED tenant only")
    assert _objects_persisted() == 1, "t2's object was lost to t1's rejection"


# ══ the counters are actually exported ═══════════════════════════════════════


def test_epoch_state_exposes_all_three(_stack):
    st = main.epoch_state()
    assert st["windows_rejected_total"] == 0
    assert st["profiler_errors_total"] == 0
    assert st["signals_dropped_total"] == {"window_rejected": 0}


def test_metrics_export_all_three(_stack):
    body = main._metrics_text()
    assert "corr_engine_windows_rejected_total 0" in body
    assert "corr_engine_profiler_errors_total 0" in body
    assert 'corr_signals_dropped_total{reason="window_rejected"} 0' in body, (
        "the series must exist at zero: the scale harness reads an ABSENT "
        "counter as UNKNOWN, and UNKNOWN is never PASS")


def test_metrics_report_a_rejection_after_it_happens(_stack):
    def boom(*_a, **_kw):
        raise ValueError("window has a malformed node")

    _stack.setattr(main, "run_window", boom)
    sigs = component(0)
    _load(sigs)
    asyncio.run(main.engine_cycle())
    body = main._metrics_text()
    assert "corr_engine_windows_rejected_total 1" in body
    assert f'corr_signals_dropped_total{{reason="window_rejected"}} {len(sigs)}' in body
