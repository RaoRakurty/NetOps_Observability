"""#101 corr_current projection reliability — the hot-read source of truth
must count its own lost dual-writes (metric + structured log) and tag
intentional chaos fixtures, without ever blocking the history (truth) write.

Uses the lane-soak harness's stub-CH pattern (test_lane_soak.py)."""

import asyncio
import logging
from datetime import datetime, timezone

import main
from test_lane_soak import _StubCH, lane_signal


class _FlakyCH(_StubCH):
    """Stub CH whose corr_current inserts fail (HTTP-reject or exception)."""

    def __init__(self, mode: str):
        super().__init__()
        self.mode = mode

    async def insert(self, table: str, rows: list) -> bool:
        if table == "netops.corr_current":
            if self.mode == "reject":
                return False  # what CH.insert returns on an HTTP 4xx/5xx
            raise ConnectionError("clickhouse unreachable")
        await super().insert(table, rows)
        return True


def _run_one_cycle(stub) -> None:
    now = datetime.now(timezone.utc)
    saved_ch, saved_open = main.ch, main.OPEN_OBJECTS
    main.ch, main.OPEN_OBJECTS = stub, {}
    main.WINDOW_BUFFER.clear()
    main._BUFFERED_IDS.clear()
    try:
        main.buffer_signal(lane_signal("link_state_change", "proj-dev-1", offset_s=-60, now=now))
        main.buffer_signal(lane_signal("device_resource_anomaly", "proj-dev-1", offset_s=-58, now=now))
        asyncio.run(main.engine_cycle())
    finally:
        main.ch, main.OPEN_OBJECTS = saved_ch, saved_open
        main.WINDOW_BUFFER.clear()
        main._BUFFERED_IDS.clear()


def test_projection_reject_counts_and_history_survives(caplog):
    """An HTTP-rejected projection insert increments the failure counter, logs
    every attribution field the runbook greps for, and never blocks history."""
    before = main.PROJECTION_WRITE_FAILURES
    stub = _FlakyCH("reject")
    with caplog.at_level(logging.WARNING):
        _run_one_cycle(stub)
    assert main.PROJECTION_WRITE_FAILURES == before + 1
    # History (truth) and the archive slice still landed.
    assert len(stub.rows.get("netops.corr_objects", [])) == 1
    assert stub.rows.get("netops.corr_signals_archive")
    msg = next(r.message for r in caplog.records
               if "corr_current projection write FAILED" in r.message)
    for field in ("tenant_id=", "corr_id=", "version_id=", "material_hash=",
                  "retryable=", "error="):
        assert field in msg, f"structured field {field!r} missing from failure log"


def test_projection_exception_counts_as_retryable_or_not(caplog):
    """A transport-level exception is also counted (not raised into the engine
    loop) — the persist path stays non-fatal by contract."""
    before = main.PROJECTION_WRITE_FAILURES
    with caplog.at_level(logging.WARNING):
        _run_one_cycle(_FlakyCH("raise"))
    assert main.PROJECTION_WRITE_FAILURES == before + 1
    assert any("ConnectionError" in r.message for r in caplog.records)


def test_metrics_exposition_carries_projection_counter():
    body = asyncio.run(main.metrics_exposition()).body.decode()
    assert "corr_current_projection_write_failures_total" in body


def test_chaos_fixture_tags_current_row(monkeypatch):
    """An object whose affected entities match a registered chaos fixture is
    tagged in corr_current (badge + sweeper-skip driver); others stay ''. The
    fixture still persists/damps like any incident — that is its purpose."""
    monkeypatch.setattr(main, "CHAOS_FIXTURES",
                        main._parse_chaos_fixtures("lab_probe_storm_fixture_120=proj-dev-1"))
    stub = _StubCH()
    _run_one_cycle(stub)
    cur = stub.rows["netops.corr_current"]
    assert cur and cur[-1]["chaos_fixture"] == "lab_probe_storm_fixture_120"

    monkeypatch.setattr(main, "CHAOS_FIXTURES", {})
    stub2 = _StubCH()
    _run_one_cycle(stub2)
    assert stub2.rows["netops.corr_current"][-1]["chaos_fixture"] == ""


def test_chaos_fixture_env_parsing():
    assert main._parse_chaos_fixtures("") == {}
    assert main._parse_chaos_fixtures(
        "lab_probe_storm_fixture_120=192.0.2.120, other=devX"
    ) == {"192.0.2.120": "lab_probe_storm_fixture_120", "devX": "other"}
    # Malformed pairs are dropped, never crash the engine at import time.
    assert main._parse_chaos_fixtures("oops,=x,name=") == {}
