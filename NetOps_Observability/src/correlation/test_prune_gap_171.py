# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Tracker 171 (residual) — maintenance starvation must be MEASURED, not argued.

`CORR_ENGINE_EPOCH_BUDGET_S` ends a drain sweep BETWEEN cohorts, never inside
one, so the honest worst case for anything that only happens at an epoch
boundary — retention prune, the lifecycle pass, the 163 cap — is
`budget + one cohort`. That is a sound argument and it was, until now,
completely unmeasured: nothing in the process said how long maintenance had
actually gone without running on the box the argument was made about.

`corr_prune_gap_max_s` is the measurement. Prune runs exactly once per epoch,
at its head (`_begin_epoch` -> `_prune_buffer`), so the wall gap between two
successive prune passes IS the maintenance interval, and its running maximum is
the observed worst starvation. Behaviour is unchanged: nothing schedules on it.

Run:  python3 -m pytest src/correlation/test_prune_gap_171.py -v
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

import pytest

import main
import signals as S

T0 = datetime(2026, 8, 30, 12, 0, 0, tzinfo=timezone.utc)


def run(coro):
    return asyncio.run(coro)


@pytest.fixture(autouse=True)
def _fresh():
    """Every test starts from a process that has never pruned."""
    main.WINDOW_BUFFER.clear()
    main._BUFFERED_IDS.clear()
    main._BUFFERED_ID_ORDER.clear()
    main.TENANT_WATERMARK.clear()
    main.PRUNE_GAP_MAX_S = 0.0
    main.PRUNE_LAST_MONO = None
    yield
    main.PRUNE_GAP_MAX_S = 0.0
    main.PRUNE_LAST_MONO = None


class _Clock:
    """A monotonic clock the test drives, so the gauge is tested on arithmetic
    rather than on sleeping (a sleep-based test measures the CI box, not us)."""

    def __init__(self, marks: list[float]) -> None:
        self._marks = list(marks)
        self.last = marks[0]

    def __call__(self) -> float:
        if self._marks:
            self.last = self._marks.pop(0)
        return self.last


def _prune_at(monkeypatch, marks: list[float]) -> None:
    """Run one prune pass per mark, with monotonic() pinned to that mark."""
    for m in marks:
        monkeypatch.setattr(main.time, "monotonic", lambda m=m: m)
        run(main._prune_buffer(T0))


def _mk(i: int) -> S.Signal:
    return S.Signal(
        tenant_id="acme", ts=T0 + timedelta(seconds=i),
        source=S.Source.SYSLOG, kind="link_state_change",
        observer=S.observer_of(f"leaf{i}", S.ObserverType.DEVICE,
                               collection_path="direct", clock_quality="unknown"),
        modality_class=S.ModalityClass.CONTROL_PLANE,
        entity_type=S.EntityType.INTERFACE, entity_id=f"leaf{i}:Gi0/1",
        severity=S.Severity.WARN, native_id=f"nat-{i}",
        entity_tokens=(f"leaf{i}",))


def test_the_first_pass_reports_no_gap(monkeypatch):
    """There is no earlier pass to measure from. Reporting the time since
    process start would call a normal startup interval starvation."""
    _prune_at(monkeypatch, [1000.0])
    assert main.PRUNE_GAP_MAX_S == 0.0
    assert main.PRUNE_LAST_MONO == 1000.0


def test_the_gauge_advances_to_the_widest_gap(monkeypatch):
    """THE TRACKER-171 CLAIM, made measurable: three epochs, the middle one
    starved, and the gauge must report the STARVED one — not the last, not the
    mean, not the first."""
    _prune_at(monkeypatch, [100.0, 110.0, 445.0, 450.0])
    #                              +10    +335    +5
    assert main.PRUNE_GAP_MAX_S == pytest.approx(335.0)


def test_the_gauge_never_shrinks_after_a_starved_epoch(monkeypatch):
    """A monotonic maximum, or a burst of healthy epochs erases the evidence
    of the one that starved — which is the whole failure mode."""
    _prune_at(monkeypatch, [0.0, 400.0])
    assert main.PRUNE_GAP_MAX_S == pytest.approx(400.0)
    _prune_at(monkeypatch, [401.0, 402.0, 403.0])
    assert main.PRUNE_GAP_MAX_S == pytest.approx(400.0)


def test_an_empty_window_still_counts_as_a_maintenance_pass(monkeypatch):
    """`_prune_buffer` returns early when the window is empty. That is still a
    pass — an epoch that starves them all is exactly what must show — so the
    mark is taken BEFORE the early return."""
    assert not main.WINDOW_BUFFER
    _prune_at(monkeypatch, [10.0, 310.0])
    assert main.PRUNE_CALLS  # the early-return path did run
    assert main.PRUNE_GAP_MAX_S == pytest.approx(300.0)


def test_a_loaded_window_records_the_same_gap(monkeypatch):
    """The full path (rebuild + evictions) marks the gap identically to the
    early-return path — one mark, at the head, on every call."""
    for i in range(5):
        main.buffer_signal(_mk(i))
    _prune_at(monkeypatch, [50.0, 170.0])
    assert main.PRUNE_GAP_MAX_S == pytest.approx(120.0)


def test_the_gauge_is_exported(monkeypatch):
    """Unexported, it is not a measurement — the scale harness reads /metrics."""
    _prune_at(monkeypatch, [0.0, 12.5])
    text = main._metrics_text()
    assert "# TYPE corr_prune_gap_max_s gauge" in text
    line = [ln for ln in text.splitlines()
            if ln.startswith("corr_prune_gap_max_s ")]
    assert len(line) == 1
    assert float(line[0].split()[1]) == pytest.approx(12.5)


def test_the_session_timeout_contract_is_exported():
    """Tracker 190: the harness must be able to READ the engine's Kafka session
    timeout instead of hard-coding a copy that drifts."""
    text = main._metrics_text()
    assert "# TYPE corr_session_timeout_ms gauge" in text
    line = [ln for ln in text.splitlines()
            if ln.startswith("corr_session_timeout_ms ")]
    assert len(line) == 1
    assert int(float(line[0].split()[1])) == main.CORR_SESSION_TIMEOUT_MS
    assert main.CORR_SESSION_TIMEOUT_MS > 0
