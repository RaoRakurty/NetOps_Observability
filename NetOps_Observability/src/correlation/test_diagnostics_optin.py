"""Diagnostics must be inert when disabled, and honest about gaps when enabled.

Two properties matter equally:

  * DISABLED (the default) changes nothing — no thread, no tracemalloc, no file,
    no work on any hot path. A diagnostic that costs something in production is
    a diagnostic nobody leaves in.
  * ENABLED never reports evidence it does not have. A run whose snapshots or
    stack dumps are missing must read as INCOMPLETE, not healthy — the whole
    point of the wave is that missing measurement was being scored as a pass.
"""
from __future__ import annotations

import importlib
import os

import pytest


def _fresh(monkeypatch, **env):
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    import diagnostics
    return importlib.reload(diagnostics)


# --- disabled: genuinely inert ---------------------------------------------

def test_disabled_by_default(monkeypatch):
    monkeypatch.delenv("CORR_DIAG_MEMORY", raising=False)
    d = _fresh(monkeypatch)
    assert d.enabled() is False


def test_disabled_start_creates_no_thread_and_no_tracemalloc(monkeypatch, tmp_path):
    import threading
    import tracemalloc
    monkeypatch.delenv("CORR_DIAG_MEMORY", raising=False)
    d = _fresh(monkeypatch, CORR_DIAG_DIR=str(tmp_path))
    before_threads = threading.active_count()
    was_tracing = tracemalloc.is_tracing()
    d.start()
    assert threading.active_count() == before_threads, "a thread was started while disabled"
    assert tracemalloc.is_tracing() == was_tracing, "tracemalloc was started while disabled"
    assert list(tmp_path.iterdir()) == [], "a file was written while disabled"


def test_disabled_snapshot_is_a_noop(monkeypatch, tmp_path):
    monkeypatch.delenv("CORR_DIAG_MEMORY", raising=False)
    d = _fresh(monkeypatch, CORR_DIAG_DIR=str(tmp_path))
    assert d.snapshot("x", {"a": 1}) == {}
    assert list(tmp_path.iterdir()) == []


def test_disabled_heartbeat_is_a_noop(monkeypatch):
    monkeypatch.delenv("CORR_DIAG_MEMORY", raising=False)
    d = _fresh(monkeypatch)
    d.heartbeat()
    assert d._heartbeat[0] == 0.0, "the heartbeat cell was written while disabled"


# --- enabled: real evidence, honestly reported -----------------------------

@pytest.fixture
def diag(monkeypatch, tmp_path):
    d = _fresh(monkeypatch, CORR_DIAG_MEMORY="true", CORR_DIAG_DIR=str(tmp_path))
    yield d, tmp_path
    import tracemalloc
    if tracemalloc.is_tracing():
        tracemalloc.stop()


def test_enabled_snapshot_carries_all_three_planes(diag):
    d, tmp = diag
    d.start()
    snap = d.snapshot("test", {"open_objects": 7, "window_signals": 50000})
    assert snap["process"]["rss_bytes"] > 0, "no OS-plane evidence"
    assert snap["python"]["tracing"] is True, "no Python-plane evidence"
    assert snap["gc"]["gc_objects"] > 0, "no GC evidence"
    assert snap["app"]["open_objects"] == 7, "no application-plane evidence"
    assert (tmp / "memory-snapshots.jsonl").exists()


def test_tracemalloc_overhead_is_reported_so_it_can_be_subtracted(diag):
    """The profiler's own footprint must not be confused with the subject's."""
    d, _ = diag
    d.start()
    snap = d.snapshot("test")
    assert snap["python"]["tracemalloc_overhead_bytes"] > 0


def test_smaps_rollup_is_captured(diag):
    d, _ = diag
    d.start()
    snap = d.snapshot("test")
    keys = [k for k in snap["process"] if k.startswith("smaps_")]
    assert keys, "smaps_rollup missing — the native/anon breakdown is unavailable"
    assert "smaps_rss" in snap["process"] or "smaps_error" in snap["process"]


def test_stats_report_what_was_actually_collected(diag):
    """A run must be able to prove its evidence is complete, not assume it."""
    d, _ = diag
    d.start()
    before = d.stats()["snapshots_taken"]
    d.snapshot("a")
    d.snapshot("b")
    st = d.stats()
    assert st["snapshots_taken"] == before + 2
    assert st["enabled"] is True and st["started"] is True


def test_zero_snapshots_is_visible_as_missing_evidence(monkeypatch, tmp_path):
    """If nothing was collected, stats must SAY so rather than look healthy."""
    d = _fresh(monkeypatch, CORR_DIAG_MEMORY="true", CORR_DIAG_DIR=str(tmp_path))
    st = d.stats()
    assert st["snapshots_taken"] == 0
    assert st["started"] is False, (
        "diagnostics that never started must not report as started — that is "
        "how missing measurement becomes a false pass")


def test_baseline_enables_growth_attribution(diag):
    d, _ = diag
    d.start()
    d.set_baseline()
    held = [bytearray(50_000) for _ in range(40)]
    snap = d.snapshot("after-allocation")
    assert "growth_since_baseline" in snap["python"], (
        "without a baseline diff there is no way to attribute GROWTH, only "
        "total size")
    assert len(held) == 40


def test_stall_dump_writes_stacks_and_a_snapshot(diag):
    """The stack dump is the evidence for what is running during a stall."""
    d, tmp = diag
    d.start()
    before = d.stats()["stack_dumps"]
    d._dump_stacks("unit-test")
    assert d.stats()["stack_dumps"] == before + 1
    text = (tmp / "stall-stacks.txt").read_text()
    assert "reason=unit-test" in text
    assert "Thread" in text or "File " in text, "no traceback content captured"


def test_stall_detector_runs_off_the_event_loop(diag):
    """A task cannot observe the stall that stops it from being scheduled, so
    the detector must be a plain thread."""
    import threading
    d, _ = diag
    d.start()
    names = [t.name for t in threading.enumerate()]
    assert "diag-stall-watch" in names
    watcher = next(t for t in threading.enumerate() if t.name == "diag-stall-watch")
    assert watcher.daemon, "the watchdog must not hold the process open"
