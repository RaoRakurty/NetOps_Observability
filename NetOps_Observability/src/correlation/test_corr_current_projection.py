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

    async def insert(self, table: str, rows: list, dedup_token="") -> bool:
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


# ── tracker 197: seam_type is a projection column, not a blob read ────────────
#
# The time-intelligence fold needs twelve values per object and corr_current
# carried eleven; that ONE missing string (`seam_type`) was the entire reason
# the fold still had to read corr_objects' ~5.7 KB hypotheses blob. The engine
# now projects it at persist time, so what the projection writes MUST be
# byte-identical to what
# `JSONExtractString(hypotheses,'grounding_context','seams',1,'seam_type')`
# would have returned from the very same row's blob — that equality is the
# whole safety argument for deleting the wide read.

def _json_extract_seam_type(hypotheses_blob: str) -> str:
    """Python's answer to ClickHouse's
    JSONExtractString(blob,'grounding_context','seams',1,'seam_type').
    Deliberately spelled out here rather than imported from main: a test that
    reused the projection's own helper could not detect the projection drifting
    away from the reader it replaced."""
    import json as _json
    doc = _json.loads(hypotheses_blob)
    seams = (doc.get("grounding_context") or {}).get("seams") or []
    if not seams:
        return ""            # absent key -> '' -> UNGROUNDED (never "unknown")
    return str(seams[0].get("seam_type") or "")


def _seam_views(*types):
    """Seam inventory for tenant t-soak, minted with DESCENDING seam_ids so the
    test also pins WHICH seam wins: the blob sorts by seam_id, so the answer
    must be the seam_id-lowest one, never insertion order."""
    from engine import SeamView
    return tuple(
        SeamView(seam_id=f"seam-{len(types) - i}", tenant_id="t-soak", seam_type=t,
                 endpoints=(("device", "proj-dev-1"),))
        for i, t in enumerate(types)
    )


def _current_and_object_rows(stub):
    cur = stub.rows["netops.corr_current"]
    obj = stub.rows["netops.corr_objects"]
    assert cur and obj
    return cur[-1], obj[-1]


def test_seam_type_projected_matches_the_json_extract_it_replaces(monkeypatch):
    """The projected column equals the JSON extraction, seam or no seam."""
    for inventory in ((), _seam_views("DIA"), _seam_views("DIA", "SDWAN", "VPN")):
        monkeypatch.setattr(main, "seam_inventory", lambda inv=inventory: inv)
        stub = _StubCH()
        _run_one_cycle(stub)
        current, obj = _current_and_object_rows(stub)
        assert "seam_type" in current, "corr_current row must carry seam_type"
        assert current["seam_type"] == _json_extract_seam_type(obj["hypotheses"]), (
            f"projection drifted from the blob extraction for inventory {inventory!r}")


def test_seam_type_is_the_seam_id_lowest_embedded_seam(monkeypatch):
    """`hypotheses_blob` sorts seams by seam_id, so element 1 — and therefore
    the projected value — is the seam_id-lowest seam, not the first supplied."""
    monkeypatch.setattr(main, "seam_inventory", lambda: _seam_views("VPN", "SDWAN", "DIA"))
    stub = _StubCH()
    _run_one_cycle(stub)
    current, obj = _current_and_object_rows(stub)
    assert current["seam_type"] == "DIA"          # seam-1 < seam-2 < seam-3
    assert current["seam_type"] == _json_extract_seam_type(obj["hypotheses"])


def test_seam_type_is_empty_when_the_object_grounds_on_no_seam(monkeypatch):
    """No inventory -> '' , the same value an old (pre-197) corr_current row
    carries under the column DEFAULT. The reader treats '' as UNGROUNDED, which
    is exactly what a missing JSON key meant to it before."""
    monkeypatch.setattr(main, "seam_inventory", tuple)
    stub = _StubCH()
    _run_one_cycle(stub)
    current, obj = _current_and_object_rows(stub)
    assert current["seam_type"] == ""
    assert _json_extract_seam_type(obj["hypotheses"]) == ""


def test_seam_type_badge_builders_agree_on_the_unparseable_blob():
    """`_current_badges` degrades to '' on a blob it cannot parse — the same
    answer JSONExtractString gives — and never raises into the persist path."""
    for blob in ("", "{", "[]", '{"grounding_context":null}',
                 '{"grounding_context":{"seams":[]}}',
                 '{"grounding_context":{"seams":[{}]}}'):
        assert main._current_badges(blob)["seam_type"] == "", blob
