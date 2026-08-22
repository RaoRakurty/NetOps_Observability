"""Tracker 172 — ingest-priority scheduling (the S1 storm fix).

THE MEASURED DEFECT (S1 design storm, run 082220005r1a, 2026-08-22): engine
cycles under storm produced event-loop stalls up to 49.3s — past the 30s
Kafka session timeout — so the broker ejected the consumer mid-stall
(8 restarts, 117 UnknownMember, 5 CommitFailed) and ingest collapsed to
~150-250 eps against 3,975 offered. Losing group membership is strictly worse
than deferring evaluation.

THE CONTRACT PINNED HERE (ratified subset degradation, gate spec §4.3):
  * behind + fresh lag  -> DEFER the sweep (consumer keeps wire speed)
  * the deadline ALWAYS breaks a deferral chain — deferral, never starvation
    (the alarm-management deadline-override; also bounds 171's prune-cadence
    deferral)
  * every uncertain case runs the sweep NORMALLY (fail-open — deferral is an
    optimisation; the opposite polarity from _consumer_caught_up, which
    fail-safes toward retention because its caller deletes evidence)
  * while storm mode is DECLARED, admitted cohorts shrink to
    CORR_STORM_COHORT_SIZE so each GIL-heavy stretch is shorter
  * deferrals are counted and the active state is a declared gauge
"""
from __future__ import annotations

import asyncio
import time

import pytest

import main
from test_prune_buffer_156 import mk


@pytest.fixture(autouse=True)
def _fresh(monkeypatch):
    now = time.monotonic()
    monkeypatch.setattr(main, "CONSUMER_LAG_TOTAL", 0)
    monkeypatch.setattr(main, "CONSUMER_LAG_AT", now)
    monkeypatch.setattr(main, "CONSUMER_LAG_UNKNOWN_PARTITIONS", 0)
    monkeypatch.setattr(main, "ENGINE_LAST_SWEEP_MONO", now)
    monkeypatch.setattr(main, "CORR_INGEST_PRIORITY_LAG", 10_000)
    monkeypatch.setattr(main, "CORR_INGEST_PRIORITY_MAX_DEFER_S", 300.0)
    monkeypatch.setattr(main, "INGEST_PRIORITY_DEFERRALS", 0)
    monkeypatch.setattr(main, "INGEST_PRIORITY_ACTIVE", False)
    yield


def _now():
    return time.monotonic()


# ── the defer decision ───────────────────────────────────────────────────────

def test_s1_regression_defers_at_the_measured_storm_lag(monkeypatch):
    """THE incident, replayed as numbers: fresh lag 3,068,647 (partition 3's
    measured backlog) must defer the sweep."""
    monkeypatch.setattr(main, "CONSUMER_LAG_TOTAL", 3_068_647)
    defer, reason = main._ingest_priority_decision(_now())
    assert defer and reason == "ingest-behind"


def test_caught_up_never_defers():
    defer, reason = main._ingest_priority_decision(_now())
    assert not defer and reason == "caught-up"


def test_threshold_is_strictly_greater(monkeypatch):
    """Nominal operation always carries transient lag; deferring at the
    threshold itself would flap the engine on ordinary traffic."""
    monkeypatch.setattr(main, "CONSUMER_LAG_TOTAL", 10_000)
    assert main._ingest_priority_decision(_now())[0] is False
    monkeypatch.setattr(main, "CONSUMER_LAG_TOTAL", 10_001)
    assert main._ingest_priority_decision(_now())[0] is True


def test_the_deadline_always_breaks_a_deferral_chain(monkeypatch):
    """THE load-bearing bound: with the worst possible lag, a sweep still runs
    once the deadline has elapsed — deferral can reduce evaluation cadence,
    it can NEVER starve evaluation (or retention maintenance, tracker 171)."""
    monkeypatch.setattr(main, "CONSUMER_LAG_TOTAL", 50_000_000)
    monkeypatch.setattr(main, "ENGINE_LAST_SWEEP_MONO", _now() - 301.0)
    defer, reason = main._ingest_priority_decision(_now())
    assert not defer and reason == "deadline"


@pytest.mark.parametrize("mutate,reason", [
    (lambda m, mp: mp.setattr(m, "CONSUMER_LAG_TOTAL", None), "lag-never-measured"),
    (lambda m, mp: mp.setattr(m, "CONSUMER_LAG_AT", time.monotonic() - 10_000),
     "lag-stale"),
    (lambda m, mp: mp.setattr(m, "CONSUMER_LAG_UNKNOWN_PARTITIONS", 2),
     "lag-partitions-unknown"),
])
def test_every_uncertain_case_fails_open(monkeypatch, mutate, reason):
    """Unknown must RUN the sweep (fail-open): a broken lag probe may never
    stall the engine. The deadline bounds even a wrongly-deferring bug, but
    fail-open means the bug never engages at all."""
    monkeypatch.setattr(main, "CONSUMER_LAG_TOTAL", 99_999_999)
    mutate(main, monkeypatch)
    defer, got = main._ingest_priority_decision(_now())
    assert not defer and got == reason


def test_mutation_without_the_deadline_deferral_is_unbounded(monkeypatch):
    """Prove the deadline is load-bearing: push it out of reach and the same
    stuck-behind state defers forever — the starvation the bound exists to
    prevent. If this passes with the real deadline, the guard is decorative."""
    monkeypatch.setattr(main, "CONSUMER_LAG_TOTAL", 3_068_647)
    monkeypatch.setattr(main, "CORR_INGEST_PRIORITY_MAX_DEFER_S", 1e12)
    monkeypatch.setattr(main, "ENGINE_LAST_SWEEP_MONO", _now() - 86_400.0)
    assert main._ingest_priority_decision(_now())[0] is True, (
        "with the deadline removed the decision no longer defers — the "
        "deadline test above is not testing what it claims")


# ── storm-shrunk cohorts ─────────────────────────────────────────────────────

def _load(n):
    main.WINDOW_BUFFER.clear(); main._BUFFERED_IDS.clear()
    main._BUFFERED_ID_ORDER.clear(); main._PROCESSED_IDS.clear()
    main._TENANT_EDGES.clear()
    for i in range(n):
        s = main.dc_replace(mk(i, i), tenant_id="acme")
        main.WINDOW_BUFFER.append(s)
        main._BUFFERED_ID_ORDER.append(str(s.signal_id))
        main._BUFFERED_IDS.add(str(s.signal_id))


class _StubCH:
    async def insert_detailed(self, table, rows, dedup_token=""):
        return main.InsertOutcome(committed=True, kind="committed",
                                  rows=len(list(rows)))


def _run_cycle(monkeypatch, *, storm: bool, n=40):
    _load(n)
    monkeypatch.setattr(main, "ch", _StubCH())
    monkeypatch.setattr(main, "OPEN_OBJECTS", {})
    monkeypatch.setattr(main, "COHORT_SIGNALS_TOTAL", 0)
    monkeypatch.setattr(main, "CORR_STORM_COHORT_SIZE", 10)
    monkeypatch.setattr(main, "_STORM_ACTIVE", False)
    # Force the storm declaration through the real hysteresis entry.
    monkeypatch.setattr(main, "STORM_BUFFER_FRACTION", 0.0 if storm else 1.1)
    monkeypatch.setattr(main, "STORM_EXIT_FRACTION", -0.1 if storm else 0.45)
    asyncio.run(main.engine_cycle())
    admitted = main.COHORT_SIGNALS_TOTAL
    main.WINDOW_BUFFER.clear(); main._BUFFERED_IDS.clear()
    main._BUFFERED_ID_ORDER.clear(); main._PROCESSED_IDS.clear()
    main._TENANT_EDGES.clear()
    return admitted


def test_storm_cohorts_shrink_to_the_storm_size(monkeypatch):
    assert _run_cycle(monkeypatch, storm=True) == 10, \
        "a declared storm did not shrink the admitted cohort"


def test_normal_cohorts_are_unchanged(monkeypatch):
    assert _run_cycle(monkeypatch, storm=False) == 40, \
        "the storm cohort size leaked into normal operation"
