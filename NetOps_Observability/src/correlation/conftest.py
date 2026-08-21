"""Shared test fixtures for the correlation suite.

The consume-loop ClickHouse writes are BATCHED (main.SIGNAL_BATCH, perf defect
#2): a handler no longer awaits its own insert, so rows a test produced but
never flushed would otherwise linger in the module-level batcher and surface in
a LATER test's fake ClickHouse — cross-test contamination. This autouse fixture
makes every test hermetic: pending rows are dropped on entry and on exit.
Tests that assert rows LANDED flush explicitly (``main.SIGNAL_BATCH.flush()``)
after driving the handler, exactly as the consume loop does before an offset
commit.
"""
from __future__ import annotations

import os

import pytest

import main


def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "perf_canary: bounded WALL-CLOCK catastrophic-regression canary "
        "(perf-nightly rung, not the PR gate); collected but skipped unless "
        "PERF_CANARY=1",
    )


def pytest_collection_modifyitems(config, items):
    """perf_canary tests measure wall-clock time, so unlike the rest of the
    suite (operation-count based, runner-speed independent) they are opted
    INTO, not out of: perf-nightly.yml sets PERF_CANARY=1. Everywhere else —
    the blocking correlation-ci PR gate included — they show up as explicit
    skips, never as silent timing hazards on a busy 2-core runner."""
    if os.environ.get("PERF_CANARY") == "1":
        return
    skip = pytest.mark.skip(
        reason="wall-clock canary: set PERF_CANARY=1 (perf-nightly rung)")
    for item in items:
        if "perf_canary" in item.keywords:
            item.add_marker(skip)


@pytest.fixture(autouse=True)
def _hermetic_signal_batch():
    main.SIGNAL_BATCH.drop_pending()
    yield
    main.SIGNAL_BATCH.drop_pending()


@pytest.fixture(autouse=True)
def _hermetic_stream_clock():
    """Tracker 165: retention now runs on per-tenant STREAM watermarks, which
    are module-level state like the window itself.

    A suite that clears WINDOW_BUFFER but leaves TENANT_WATERMARK behind hands
    the next test a stream clock that is already far ahead of the signals it
    loads — so its evidence is expired the moment it prunes, and the failure
    surfaces somewhere unrelated. That is exactly the cross-test contamination
    the batcher fixture above exists to prevent, so it gets the same treatment:
    cleared on entry AND exit, for every test, whether or not it touches
    retention.
    """
    # Some suites REPLACE the window deques outright (direct assignment rather
    # than monkeypatch) to get a small maxlen. That leaks a 200-entry window
    # into every later test, which then cannot load enough signals to exercise
    # anything. Snapshot the objects and put them back.
    _orig = (main.WINDOW_BUFFER, main._BUFFERED_ID_ORDER, main._BUFFERED_IDS)
    main.TENANT_WATERMARK.clear()
    # tracker 166 adds two more window-scoped structures with the same hazard:
    # the processed frontier and the carried-edge cache. A suite that clears the
    # window but leaves these behind hands the next test signals that are
    # already "processed" and edges for nodes it never loaded.
    main._PROCESSED_IDS.clear()
    main._TENANT_EDGES.clear()
    # Co-partitioning health gates stream-time expiry (tracker 165 phase 2):
    # a suite that drives a divergent rebalance and leaves the flag false makes
    # every later test's retention silently stop expiring.
    main.COPARTITION_OK = True
    yield
    main.WINDOW_BUFFER, main._BUFFERED_ID_ORDER, main._BUFFERED_IDS = _orig
    main.WINDOW_BUFFER.clear()
    main._BUFFERED_ID_ORDER.clear()
    main._BUFFERED_IDS.clear()
    main.TENANT_WATERMARK.clear()
    main._PROCESSED_IDS.clear()
    main._TENANT_EDGES.clear()
    main.COPARTITION_OK = True
