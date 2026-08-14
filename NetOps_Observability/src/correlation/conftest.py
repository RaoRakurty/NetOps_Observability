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
