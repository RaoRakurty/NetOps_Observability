"""Cloud lane runtime intake tests — #81 P3G/P3B (handle_cloud + the cloud-log tailer).

Drives main.handle_cloud + main._scan_cloud_logs without a live ClickHouse (a fake
CH captures inserted rows), proving the RUNTIME contract the unit tests on the pure
producers/parsers can't reach:

  * a valid cloud event → one source=cloud corr_signal, buffered into the engine window
  * tenancy is DEFAULT-CLOSED: an untenanted cloud event is DROPPED + counted, never guessed
  * a malformed cloud event dead-letters (counted), emits no signal
  * the file tailer parses *.alb/*.vpc, feeds the lane, and is OFFSET-TRACKED (no re-ingest)
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone

import main


class FakeCH:
    """Captures rows handed to insert() so tests assert the canonical row."""

    def __init__(self) -> None:
        self.rows: list[dict] = []

    async def insert(self, table: str, rows, dedup_token="") -> None:
        for r in rows:
            self.rows.append({"_table": table, **r})


def _reset() -> FakeCH:
    ch = FakeCH()
    main.ch = ch
    main.CORR_SIGNALS_ENABLED = True
    main.WINDOW_BUFFER.clear()
    main._BUFFERED_IDS.clear()
    main._cloud_log_offsets.clear()
    return ch


def _cloud_rows(ch: FakeCH) -> list[dict]:
    return [r for r in ch.rows if r["_table"] == "netops.corr_signals" and r.get("source") == "cloud"]


def test_handle_cloud_valid_event_signals_and_buffers():
    ch = _reset()
    before = main.CLOUD_SIGNALS
    ev = {"tenant_id": "acme", "kind": "cloud_health", "app": "billing", "account": "123",
          "region": "us-east-1", "severity": "high", "ts": datetime.now(timezone.utc).isoformat()}
    asyncio.run(main.handle_cloud(ev))
    asyncio.run(main.SIGNAL_BATCH.flush())  # drain the batched write path
    rows = _cloud_rows(ch)
    assert len(rows) == 1
    assert rows[0]["entity_id"] == "billing" and rows[0]["kind"] == "cloud_health"
    assert rows[0]["tenant_id"] == "acme"
    assert main.CLOUD_SIGNALS == before + 1
    assert len(main.WINDOW_BUFFER) == 1  # entered the engine window


def test_handle_cloud_untenanted_dropped_default_closed():
    ch = _reset()
    before = main.CLOUD_DROPPED
    asyncio.run(main.handle_cloud({"kind": "cloud_health", "app": "billing"}))  # no tenant_id
    assert _cloud_rows(ch) == []
    assert len(main.WINDOW_BUFFER) == 0
    assert main.CLOUD_DROPPED == before + 1  # default-closed isolation, counted not guessed


def test_handle_cloud_malformed_dead_letters():
    ch = _reset()
    dl, dr = main.DEADLETTER_COUNT, main.CLOUD_DROPPED
    asyncio.run(main.handle_cloud({"tenant_id": "acme", "kind": "not_a_kind", "app": "x"}))
    assert _cloud_rows(ch) == []
    assert main.DEADLETTER_COUNT == dl + 1
    assert main.CLOUD_DROPPED == dr + 1


ALB_5XX = (
    'http 2026-06-25T22:00:00.000000Z app/billing-alb/0a1b2c3d 203.0.113.10:54321 10.0.1.20:443 '
    '0.001 0.002 0.000 502 502 412 900 "GET https://billing.example.com:443/pay HTTP/1.1" "curl/8.0" '
    'ECDHE-RSA-AES128-GCM-SHA256 TLSv1.2 '
    'arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/billing-tg/abc123 '
    '"Root=1-abc" "billing.example.com" "-" 0 2026-06-25T21:59:59.000000Z "forward" "-" "-" "10.0.1.20:443" "502" "-" "-"'
)
VPC_REJECT = "2 123456789012 eni-0abc123 203.0.113.55 10.0.1.20 44321 443 6 8 480 1719352800 1719352830 REJECT OK"


def test_cloud_log_tailer_feeds_and_is_offset_tracked(tmp_path):
    ch = _reset()
    (tmp_path / "billing.alb").write_text(ALB_5XX + "\n")
    (tmp_path / "prod.vpc").write_text(VPC_REJECT + "\n")
    main.CLOUD_LOGS_DIR = str(tmp_path)
    main.CLOUD_LOGS_TENANT = "acme"

    fed = asyncio.run(main._scan_cloud_logs())
    asyncio.run(main.SIGNAL_BATCH.flush())  # drain the batched write path
    assert fed == 2
    kinds = sorted(r["kind"] for r in _cloud_rows(ch))
    assert kinds == ["cloud_flow_log", "cloud_lb_log"]
    assert all(r["tenant_id"] == "acme" for r in _cloud_rows(ch))

    # offset-tracked: a re-scan with no new bytes feeds nothing
    assert asyncio.run(main._scan_cloud_logs()) == 0

    # an appended line is picked up on the next scan (tail semantics)
    with open(tmp_path / "billing.alb", "a") as f:
        f.write(ALB_5XX + "\n")
    assert asyncio.run(main._scan_cloud_logs()) == 1


def test_cloud_log_tailer_skips_non_signal_lines(tmp_path):
    ch = _reset()
    # a 2xx ALB line is not a fault → no signal. ACCEPT flows are no longer
    # dropped (audit P1-6): the batch rolls up to ONE cloud_flow_volume signal
    # per ENI plus ONE cloud_flow_pair per (src,dst) pair (#9 talks_to edges) —
    # bounded rollups, never a per-flow firehose.
    (tmp_path / "ok.alb").write_text(ALB_5XX.replace(" 502 502 ", " 200 200 ") + "\n")
    (tmp_path / "ok.vpc").write_text(
        VPC_REJECT.replace("REJECT", "ACCEPT") + "\n"
        + VPC_REJECT.replace("REJECT", "ACCEPT") + "\n")
    main.CLOUD_LOGS_DIR = str(tmp_path)
    main.CLOUD_LOGS_TENANT = "acme"
    assert asyncio.run(main._scan_cloud_logs()) == 2  # 2 ACCEPT records → 2 rollups
    asyncio.run(main.SIGNAL_BATCH.flush())  # drain the batched write path
    kinds = sorted(r["kind"] for r in _cloud_rows(ch))
    assert kinds == ["cloud_flow_pair", "cloud_flow_volume"]
