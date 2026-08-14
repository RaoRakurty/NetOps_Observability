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

import pytest

import main


@pytest.fixture(autouse=True)
def _hermetic_signal_batch():
    main.SIGNAL_BATCH.drop_pending()
    yield
    main.SIGNAL_BATCH.drop_pending()
