"""Wiring tests: findings rows must persist the EVENT time, not rely on
ClickHouse's insert-time default, and must carry full time provenance in
labels. Uses a stub CH — no Kafka/ClickHouse required.

    cd src/correlation
    python -m pytest test_main_time.py
"""

import asyncio
import unittest
from datetime import datetime, timezone

import main
from timenorm import ResolvedTime

UTC = timezone.utc
EVENT = datetime(2026, 7, 17, 6, 15, 0, tzinfo=UTC)
INGEST = datetime(2026, 7, 17, 6, 30, 0, 250000, tzinfo=UTC)


class StubCH:
    def __init__(self):
        self.rows: list[dict] = []

    async def insert(self, table: str, rows):
        self.rows.extend(rows)


class TestEmitTimeFields(unittest.TestCase):
    def setUp(self):
        self._old_ch = main.ch
        self.ch = StubCH()
        main.ch = self.ch

    def tearDown(self):
        main.ch = self._old_ch

    def _emit(self, when):
        asyncio.run(
            main.emit(
                kind="anomaly",
                severity="warning",
                device="r1",
                component="cpu",
                summary="s",
                description="d",
                score=4.2,
                labels={"metric": "cpu"},
                when=when,
            )
        )

    def test_row_carries_event_time_and_provenance(self):
        when = ResolvedTime(
            event_time=EVENT,
            ingest_time=INGEST,
            tz_assumed=True,
            raw_timestamp="Jul 17 00:15:00",
        )
        self._emit(when)
        row = self.ch.rows[0]
        # ts = the EVENT's source time as fractional epoch seconds — the
        # timezone-unambiguous form for a DateTime64(3) column. Without
        # it ClickHouse stamps INSERT time and occurrence time is lost.
        self.assertAlmostEqual(row["ts"], EVENT.timestamp(), places=3)
        self.assertEqual(row["labels"]["event_time"], "2026-07-17T06:15:00.000Z")
        self.assertEqual(row["labels"]["ingest_time"], "2026-07-17T06:30:00.250Z")
        self.assertEqual(row["labels"]["tz_assumed"], "true")
        self.assertEqual(row["labels"]["raw_timestamp"], "Jul 17 00:15:00")
        self.assertEqual(row["labels"]["metric"], "cpu")  # original labels kept

    def test_handle_syslog_burst_stamps_event_time(self):
        # Drive a real burst through handle(): 6 crit messages (weight 6
        # each) crosses the 30-point threshold and emits a correlation
        # finding stamped with the LAST event's source time.
        ev = {
            "hostname": "core-sw1",
            "severity": "crit",
            "event_time": "2026-07-17T06:15:00Z",
            "tz_assumed": False,
        }
        async def burst():
            for _ in range(6):
                await main.handle("netops.syslog", dict(ev))
        main.SYSLOG_BUCKET.clear()
        asyncio.run(burst())
        findings = [r for r in self.ch.rows if r["kind"] == "correlation"]
        self.assertEqual(len(findings), 1)
        self.assertAlmostEqual(findings[0]["ts"], EVENT.timestamp(), places=3)
        self.assertEqual(findings[0]["labels"]["tz_assumed"], "false")


if __name__ == "__main__":
    unittest.main()
