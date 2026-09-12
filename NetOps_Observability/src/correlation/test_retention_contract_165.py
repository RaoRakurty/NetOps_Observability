# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Tracker 165 — retention is a contract, and its breach is reportable.

`corr_window_overflow_dropped_total` said evidence was shed. It could not say
whether that mattered. The missing half is the engine's own answer: could the
shed signal still have formed an edge? These tests pin the reported state —
effective horizon, required horizon, and the single boolean an operator alerts
on — and, critically, pin that the boolean can be BOTH values for reasons that
are not "the window is empty".
"""
from __future__ import annotations

import asyncio
from collections import deque
from datetime import datetime, timedelta, timezone

import pytest

import main
from test_prune_buffer_156 import mk


@pytest.fixture
def window(monkeypatch):
    """A small window we can fill deterministically."""
    def _install(maxlen: int):
        monkeypatch.setattr(main, "WINDOW_BUFFER", deque(maxlen=maxlen))
        monkeypatch.setattr(main, "_BUFFERED_ID_ORDER", deque(maxlen=maxlen))
        monkeypatch.setattr(main, "_BUFFERED_IDS", set())
    return _install


def _fill(n: int, spacing_s: float):
    base = datetime.now(timezone.utc) - timedelta(seconds=(n - 1) * spacing_s)
    for i in range(n):
        main.buffer_signal(main.dc_replace(
            mk(i % 40), ts=base + timedelta(seconds=i * spacing_s)))


# ── the contract itself ──────────────────────────────────────────────────────

def test_required_retention_is_reach_plus_lateness_not_window_s():
    assert main.ENGINE_REACH_S == pytest.approx(396.5267, abs=1e-3)
    assert main.RETENTION_REQUIRED_S == pytest.approx(
        main.ENGINE_REACH_S + main.CORR_PERMITTED_LATENESS_S)
    # The retired window_s was 900 s — the requirement is 2.1x smaller, which
    # is why sizing to 900 would have over-retained ~2.5x beyond what attaches.
    assert main.RETENTION_REQUIRED_S < 900.0
    assert not hasattr(main.ENGINE_CFG, "window_s"), (
        "window_s must not come back as an independent temporal knob")


def test_lateness_floor_is_one_engine_cycle():
    """Less than one evaluation interval past the reach and a signal can expire
    before it is ever scored against — so the floor is not a taste question."""
    assert main.CORR_PERMITTED_LATENESS_S >= main.CORR_ENGINE_INTERVAL_S


def test_lateness_env_cannot_go_below_the_floor(monkeypatch):
    monkeypatch.setenv("CORR_PERMITTED_LATENESS_S", "1")
    lateness = max(main.CORR_ENGINE_INTERVAL_S,
                   float(main.os.environ["CORR_PERMITTED_LATENESS_S"]))
    assert lateness == main.CORR_ENGINE_INTERVAL_S


# ── the degradation boolean ──────────────────────────────────────────────────

def test_not_degraded_when_the_window_is_merely_thin(window):
    """A quiet tenant or a cold start holds little history and sheds nothing.
    That is not degradation, and calling it degradation would make the alert
    fire permanently on every restart."""
    window(1000)
    _fill(50, spacing_s=0.1)               # 5 s of history, window nowhere near full
    assert main._window_span_s() < main.ENGINE_REACH_S
    assert main.rca_evidence_degraded() is False
    assert main.retention_state()["horizon_satisfied"] is True


def test_degraded_when_a_full_window_holds_less_than_the_reach(window):
    """The measured 1K condition: the window is at its record cap and the time
    it represents has collapsed below what the engine can still use."""
    window(200)
    _fill(400, spacing_s=0.05)             # 200 signals spanning ~10 s
    assert len(main.WINDOW_BUFFER) == main.WINDOW_BUFFER.maxlen
    assert main._window_span_s() < main.ENGINE_REACH_S
    assert main.rca_evidence_degraded() is True
    st = main.retention_state()
    assert st["horizon_satisfied"] is False
    assert st["rca_evidence_degraded"] is True
    assert st["window_utilization"] == 1.0


def test_not_degraded_when_a_full_window_still_covers_the_reach(window):
    """The negative control that matters: FULL is not the same as DEGRADED. A
    window at its cap that still spans the engine's reach is doing its job."""
    window(200)
    _fill(400, spacing_s=5.0)              # 200 signals spanning ~995 s
    assert len(main.WINDOW_BUFFER) == main.WINDOW_BUFFER.maxlen
    assert main._window_span_s() > main.ENGINE_REACH_S
    assert main.rca_evidence_degraded() is False
    assert main.retention_state()["horizon_satisfied"] is True


def test_the_yardstick_is_the_reach_not_window_s(window):
    """The discriminating case. A full window spanning ~600 s covers the
    engine's 396.5 s reach comfortably, so nothing usable is being lost — but a
    yardstick of window_s (900 s) would call it degraded and alert forever.
    Only a test in the gap between the two numbers can tell them apart."""
    window(200)
    _fill(400, spacing_s=3.0)              # 200 signals spanning ~597 s
    span = main._window_span_s()
    assert len(main.WINDOW_BUFFER) == main.WINDOW_BUFFER.maxlen
    assert main.ENGINE_REACH_S < span < 900.0, (
        f"fixture must land between the two yardsticks, span={span:.1f}s")
    assert main.rca_evidence_degraded() is False


def test_degradation_separates_eligible_from_stale_capacity_drops(window):
    """Both counters move independently, and the derived one is never larger
    than the total it is a subset of."""
    window(50)
    _fill(200, spacing_s=0.05)             # tight: victims stay attachable
    st = main.retention_state()
    assert st["capacity_dropped_total"] > 0
    assert st["capacity_dropped_still_eligible"] > 0
    assert (st["capacity_dropped_still_eligible"]
            + st["capacity_dropped_already_stale"] == st["capacity_dropped_total"])


# ── exposure ─────────────────────────────────────────────────────────────────

def test_the_state_is_exported(window):
    """A state nobody can scrape is not a state. Mutation target: deleting any
    of these lines from the metrics body must go red here."""
    window(100)
    _fill(300, spacing_s=0.02)
    resp = asyncio.run(main.metrics_exposition())
    body = resp.body.decode() if hasattr(resp, "body") else str(resp)
    # A HELP/TYPE comment mentions the name too — assert the SAMPLE line, i.e.
    # the name followed by an actual value. Dropping the sample and keeping the
    # TYPE header must go red here.
    samples = {ln.split(" ", 1)[0]: ln.split(" ", 1)[1]
               for ln in body.splitlines()
               if ln and not ln.startswith("#") and " " in ln}
    for series in (
        "corr_engine_reach_seconds",
        "corr_retention_required_seconds",
        "corr_permitted_lateness_seconds",
        "corr_window_utilization",
        "corr_rca_evidence_degraded",
        "corr_event_time_lag_seconds",
        "corr_offload_queue_depth",
        "corr_offload_queue_depth_peak",
        "corr_offload_active_workers",
        "corr_offload_max_workers",
        "corr_offload_oldest_queued_age_seconds",
        "corr_offload_submitted_total",
        "corr_offload_completed_total",
        "corr_offload_failed_total",
        "corr_offload_rejected_total",
        "corr_offload_wait_max_seconds",
        "corr_offload_exec_max_seconds",
    ):
        assert series in samples, f"{series} has no sample line in the exposition"
        float(samples[series])           # and it must carry a parsable value
    assert samples["corr_rca_evidence_degraded"] in ("0", "1")
    # Exporting a series is not the same as exporting the RIGHT number: pin the
    # values that carry the contract, or a gauge could quietly report window_s.
    assert float(samples["corr_engine_reach_seconds"]) == pytest.approx(
        main.ENGINE_REACH_S, abs=1e-3)
    assert float(samples["corr_retention_required_seconds"]) == pytest.approx(
        main.RETENTION_REQUIRED_S, abs=1e-3)
    assert float(samples["corr_permitted_lateness_seconds"]) == pytest.approx(
        main.CORR_PERMITTED_LATENESS_S, abs=1e-3)
    assert float(samples["corr_engine_reach_seconds"]) != 900.0
    assert float(samples["corr_offload_max_workers"]) == main.offload_stats()["max_workers"]
    # the summaries carry quantile labels, so they are matched separately
    for q in ("0.5", "0.95", "0.99"):
        assert f'corr_offload_wait_seconds{{quantile="{q}"}} ' in body
        assert f'corr_offload_exec_seconds{{quantile="{q}"}} ' in body


def test_the_public_healthz_carries_the_retention_and_offload_blocks():
    """The FIRST build of this put the retention block only in the diagnostic
    snapshot, so the live container's /healthz had none of it — caught by
    querying the running stack, not by a test. Pin the public endpoint."""
    hz = asyncio.run(main.health())
    corr = hz["engine_v2"]
    assert "retention" in corr, "/healthz must carry the retention contract"
    assert "offload" in corr, "/healthz must carry the offload queue state"
    assert "event_time_lag_s" in corr
    assert set(corr["retention"]) >= {
        "effective_horizon_s", "required_horizon_s", "engine_reach_s",
        "rca_evidence_degraded", "rca_degradation_reason", "window_utilization"}


def test_diag_snapshot_also_carries_them():
    async def _grab():
        return main.diag_app_state()
    state = asyncio.run(_grab())
    assert set(state["retention"]) >= {
        "effective_horizon_s", "required_horizon_s", "engine_reach_s",
        "rca_evidence_degraded", "window_utilization"}
    assert set(state["offload"]) >= {
        "queue_depth", "max_workers", "wait_p99_s", "submitted_total"}
    assert "event_time_lag_s" in state


def test_window_s_is_gone_and_the_horizon_metric_reports_the_derived_value():
    """window_s is removed outright, and the metric that used to carry it now
    carries the derived requirement — so a dashboard reading
    corr_window_horizon_seconds gets the number that is actually enforced."""
    assert not hasattr(main.ENGINE_CFG, "window_s")
    st = main.retention_state()
    assert "prune_bound_s" not in st, "the wall-clock prune bound no longer exists"
    resp = asyncio.run(main.metrics_exposition())
    body = resp.body.decode() if hasattr(resp, "body") else str(resp)
    line = next(ln for ln in body.splitlines()
                if ln.startswith("corr_window_horizon_seconds "))
    assert float(line.split()[1]) == pytest.approx(main.RETENTION_REQUIRED_S, abs=0.1)
