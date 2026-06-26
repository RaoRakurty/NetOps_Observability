"""App-identity lane runtime intake tests — #81 Fusion Layer P5b (handle_app_identity).

Drives main.handle_app_identity without a live ClickHouse (a fake CH captures
inserted rows), proving the RUNTIME contract the pure-producer unit tests can't
reach:

  * a valid identity event → one source=app_identity corr_signal, buffered into the
    engine window, INFO severity (enrichment, never a fault)
  * tenancy is DEFAULT-CLOSED: an untenanted identity event is DROPPED + counted
  * a malformed event (no app / invalid band) dead-letters (counted), emits no signal
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone

import main


class FakeCH:
    """Captures rows handed to insert() so tests assert the canonical row."""

    def __init__(self) -> None:
        self.rows: list[dict] = []

    async def insert(self, table: str, rows) -> None:
        for r in rows:
            self.rows.append({"_table": table, **r})


def _reset() -> FakeCH:
    ch = FakeCH()
    main.ch = ch
    main.CORR_SIGNALS_ENABLED = True
    main.WINDOW_BUFFER.clear()
    main._BUFFERED_IDS.clear()
    return ch


def _appid_rows(ch: FakeCH) -> list[dict]:
    return [r for r in ch.rows
            if r["_table"] == "netops.corr_signals" and r.get("source") == "app_identity"]


def test_handle_app_identity_valid_event_signals_and_buffers():
    ch = _reset()
    before = main.APP_ID_SIGNALS
    ev = {"tenant_id": "acme", "app": "Microsoft Teams", "band": "authoritative",
          "state": "fused", "evidence_score": 92, "sources": ["ngfw_app_id"],
          "fusion_version": "appfuse-1", "dst_ip": "13.107.6.152", "flow_id": "f-1",
          "ts": datetime.now(timezone.utc).isoformat()}
    asyncio.run(main.handle_app_identity(ev))
    rows = _appid_rows(ch)
    assert len(rows) == 1
    assert rows[0]["entity_id"] == "Microsoft Teams" and rows[0]["kind"] == "app_identity"
    assert rows[0]["tenant_id"] == "acme"
    assert rows[0]["severity"] == "info"  # enrichment, never a fault → can't seed an object
    assert rows[0]["entity_type"] == "app"
    assert main.APP_ID_SIGNALS == before + 1
    assert len(main.WINDOW_BUFFER) == 1  # entered the engine window


def test_handle_app_identity_untenanted_dropped_default_closed():
    ch = _reset()
    before = main.APP_ID_DROPPED
    asyncio.run(main.handle_app_identity({"app": "Teams", "band": "high"}))  # no tenant_id
    assert _appid_rows(ch) == []
    assert len(main.WINDOW_BUFFER) == 0
    assert main.APP_ID_DROPPED == before + 1  # default-closed isolation, counted not guessed


def test_handle_app_identity_no_app_dead_letters():
    ch = _reset()
    dl, dr = main.DEADLETTER_COUNT, main.APP_ID_DROPPED
    asyncio.run(main.handle_app_identity({"tenant_id": "acme", "band": "high"}))
    assert _appid_rows(ch) == []
    assert main.DEADLETTER_COUNT == dl + 1
    assert main.APP_ID_DROPPED == dr + 1


def test_handle_app_identity_invalid_band_dead_letters():
    ch = _reset()
    dl, dr = main.DEADLETTER_COUNT, main.APP_ID_DROPPED
    asyncio.run(main.handle_app_identity(
        {"tenant_id": "acme", "app": "x", "band": "totally-bogus"}))
    assert _appid_rows(ch) == []
    assert main.DEADLETTER_COUNT == dl + 1
    assert main.APP_ID_DROPPED == dr + 1
