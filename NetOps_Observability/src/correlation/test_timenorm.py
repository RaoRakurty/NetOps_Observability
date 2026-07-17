"""Regression tests for time normalization + skew detection.

Fixture logs per family, per docs/design/log-time-standard.md. Run with:

    cd src/correlation
    python -m pytest test_timenorm.py
"""

import unittest
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

from timenorm import (
    ResolvedTime,
    SkewTracker,
    parse_any_timestamp,
    parse_rfc3164_timestamp,
    resolve_event_time,
    resolve_tz,
)

UTC = timezone.utc

# Receive reference used across fixtures: 2026-07-17T06:30:00Z.
REF = datetime(2026, 7, 17, 6, 30, 0, tzinfo=UTC)


class TestResolveTz(unittest.TestCase):
    def test_fixed_offsets(self):
        self.assertEqual(resolve_tz("+05:30").utcoffset(None), timedelta(hours=5, minutes=30))
        self.assertEqual(resolve_tz("+0545").utcoffset(None), timedelta(hours=5, minutes=45))
        self.assertEqual(resolve_tz("-06:00").utcoffset(None), timedelta(hours=-6))

    def test_iana_names(self):
        self.assertIsNotNone(resolve_tz("America/Chicago"))
        self.assertIsNotNone(resolve_tz("Asia/Kolkata"))

    def test_garbage_raises(self):
        for bad in ("Mars/Olympus", "UTC+25", "+99:00", ""):
            with self.assertRaises(ValueError, msg=bad):
                resolve_tz(bad)


class TestRFC3164(unittest.TestCase):
    """RFC 3164 headers carry no year and no zone — both are inferred."""

    def test_utc_minus_6_device(self):
        # Fixture: RFC 3164 from a UTC−6 device. Wall clock 00:15:00 on
        # Jul 17 local == 06:15:00Z.
        got = parse_rfc3164_timestamp(
            "Jul 17 00:15:00", reference=REF, tz=resolve_tz("-06:00")
        )
        self.assertEqual(got, datetime(2026, 7, 17, 6, 15, 0, tzinfo=UTC))

    def test_ist_device(self):
        # Fixture: IST (+05:30) device — 11:45:00 IST == 06:15:00Z.
        got = parse_rfc3164_timestamp(
            "Jul 17 11:45:00", reference=REF, tz=resolve_tz("+05:30")
        )
        self.assertEqual(got, datetime(2026, 7, 17, 6, 15, 0, tzinfo=UTC))

    def test_nepal_device(self):
        # +05:45 zone — 12:00:00 NPT == 06:15:00Z.
        got = parse_rfc3164_timestamp(
            "Jul 17 12:00:00", reference=REF, tz=resolve_tz("+05:45")
        )
        self.assertEqual(got, datetime(2026, 7, 17, 6, 15, 0, tzinfo=UTC))

    def test_december_january_rollover_backward(self):
        # Fixture: "Dec 31 23:59:58" received Jan 1 → LAST year, not a
        # 364-day-future date in the receive year.
        ref = datetime(2027, 1, 1, 0, 0, 30, tzinfo=UTC)
        got = parse_rfc3164_timestamp("Dec 31 23:59:58", reference=ref, tz=UTC)
        self.assertEqual(got, datetime(2026, 12, 31, 23, 59, 58, tzinfo=UTC))

    def test_december_january_rollover_forward(self):
        # A device a few seconds AHEAD across the year boundary: "Jan  1
        # 00:00:05" received Dec 31 23:59:50 → NEXT year, preserved as a
        # (slightly future) timestamp, never clamped.
        ref = datetime(2026, 12, 31, 23, 59, 50, tzinfo=UTC)
        got = parse_rfc3164_timestamp("Jan  1 00:00:05", reference=ref, tz=UTC)
        self.assertEqual(got, datetime(2027, 1, 1, 0, 0, 5, tzinfo=UTC))

    def test_dst_transition_spring_forward(self):
        # America/Chicago 2026-03-08: 01:59:59 CST (UTC-6) vs 03:00:01
        # CDT (UTC-5) — one wall-clock hour apart but 2 real seconds.
        tz = ZoneInfo("America/Chicago")
        ref = datetime(2026, 3, 8, 8, 0, 0, tzinfo=UTC)
        before = parse_rfc3164_timestamp("Mar  8 01:59:59", reference=ref, tz=tz)
        after = parse_rfc3164_timestamp("Mar  8 03:00:01", reference=ref, tz=tz)
        self.assertEqual(before, datetime(2026, 3, 8, 7, 59, 59, tzinfo=UTC))
        self.assertEqual(after, datetime(2026, 3, 8, 8, 0, 1, tzinfo=UTC))
        self.assertEqual((after - before).total_seconds(), 2)

    def test_dst_transition_fall_back(self):
        # America/Chicago 2026-11-01: 01:30 occurs twice; Python resolves
        # the ambiguity with fold=0 (first occurrence, CDT). Documented,
        # deterministic behavior — not silent corruption.
        tz = ZoneInfo("America/Chicago")
        ref = datetime(2026, 11, 1, 6, 45, 0, tzinfo=UTC)
        got = parse_rfc3164_timestamp("Nov  1 01:30:00", reference=ref, tz=tz)
        self.assertEqual(got, datetime(2026, 11, 1, 6, 30, 0, tzinfo=UTC))

    def test_fractional_seconds(self):
        got = parse_rfc3164_timestamp("Jul 17 06:15:00.250", reference=REF, tz=UTC)
        self.assertEqual(got, datetime(2026, 7, 17, 6, 15, 0, 250000, tzinfo=UTC))

    def test_not_rfc3164(self):
        self.assertIsNone(parse_rfc3164_timestamp("2026-07-17T06:15:00Z", reference=REF, tz=UTC))
        self.assertIsNone(parse_rfc3164_timestamp("garbage", reference=REF, tz=UTC))


class TestParseAny(unittest.TestCase):
    def test_rfc5424_with_offset_not_assumed(self):
        # Fixture: RFC 5424 timestamp with explicit offset — trusted.
        got = parse_any_timestamp("2026-07-17T11:45:00.500+05:30", reference=REF)
        self.assertIsNotNone(got)
        dt, assumed = got
        self.assertEqual(dt, datetime(2026, 7, 17, 6, 15, 0, 500000, tzinfo=UTC))
        self.assertFalse(assumed)

    def test_zulu(self):
        dt, assumed = parse_any_timestamp("2026-07-17T06:15:00Z", reference=REF)
        self.assertEqual(dt, datetime(2026, 7, 17, 6, 15, 0, tzinfo=UTC))
        self.assertFalse(assumed)

    def test_zoneless_iso_applies_hierarchy_zone_and_flags(self):
        dt, assumed = parse_any_timestamp(
            "2026-07-17 00:15:00", reference=REF, tz=resolve_tz("-06:00")
        )
        self.assertEqual(dt, datetime(2026, 7, 17, 6, 15, 0, tzinfo=UTC))
        self.assertTrue(assumed)

    def test_epoch_units(self):
        want = datetime(2026, 7, 17, 6, 15, 0, tzinfo=UTC)
        for v in (1784268900, 1784268900_000, 1784268900_000_000, 1784268900_000_000_000):
            dt, assumed = parse_any_timestamp(v, reference=REF)
            self.assertEqual(dt, want, v)
            self.assertFalse(assumed)
        dt, _ = parse_any_timestamp("1784268900000", reference=REF)  # numeric string
        self.assertEqual(dt, want)

    def test_future_event_preserved(self):
        # Fixture: future-dated event — surfaced as-is, never clamped.
        dt, assumed = parse_any_timestamp("2033-07-24T06:10:00Z", reference=REF)
        self.assertEqual(dt, datetime(2033, 7, 24, 6, 10, 0, tzinfo=UTC))
        self.assertFalse(assumed)

    def test_unparseable(self):
        for v in (None, "", "not a time", True, {"nested": 1}):
            self.assertIsNone(parse_any_timestamp(v, reference=REF), v)


class TestResolveEventTime(unittest.TestCase):
    def test_vector_normalized_event_passes_through(self):
        ev = {
            "hostname": "core-sw1",
            "event_time": "2026-07-17T06:15:00.000Z",
            "raw_timestamp": "<189>Jul 17 06:15:00 core-sw1 ...",
            "tz_assumed": False,
        }
        r = resolve_event_time(ev, received_at=REF)
        self.assertEqual(r.event_time, datetime(2026, 7, 17, 6, 15, 0, tzinfo=UTC))
        self.assertEqual(r.ingest_time, REF)
        self.assertFalse(r.tz_assumed)
        self.assertEqual(r.raw_timestamp, "<189>Jul 17 06:15:00 core-sw1 ...")
        self.assertAlmostEqual(r.skew_seconds, 900.0)

    def test_upstream_tz_assumed_is_never_downgraded(self):
        ev = {"event_time": "2026-07-17T06:15:00Z", "tz_assumed": True}
        r = resolve_event_time(ev, received_at=REF)
        self.assertTrue(r.tz_assumed)

    def test_device_tz_map_applies_to_zoneless(self):
        # Fixture: RFC 3164-style zoneless time + per-device zone config.
        ev = {"hostname": "branch-rtr", "timestamp": "2026-07-17 00:15:00"}
        r = resolve_event_time(
            ev, received_at=REF, device_tz_map={"branch-rtr": "-06:00"}
        )
        self.assertEqual(r.event_time, datetime(2026, 7, 17, 6, 15, 0, tzinfo=UTC))
        self.assertTrue(r.tz_assumed)  # zone came from config, not payload

    def test_site_default_tz(self):
        ev = {"hostname": "blr-fw1", "timestamp": "2026-07-17 11:45:00"}
        r = resolve_event_time(ev, received_at=REF, default_tz="Asia/Kolkata")
        self.assertEqual(r.event_time, datetime(2026, 7, 17, 6, 15, 0, tzinfo=UTC))
        self.assertTrue(r.tz_assumed)

    def test_no_time_falls_back_to_ingest_flagged(self):
        r = resolve_event_time({"hostname": "x"}, received_at=REF)
        self.assertEqual(r.event_time, REF)
        self.assertTrue(r.tz_assumed)
        self.assertEqual(r.raw_timestamp, "")

    def test_bad_config_entry_degrades_gracefully(self):
        ev = {"hostname": "r1", "timestamp": "2026-07-17 06:15:00"}
        r = resolve_event_time(
            ev, received_at=REF, device_tz_map={"r1": "Not/AZone"}, default_tz="UTC"
        )
        self.assertEqual(r.event_time, datetime(2026, 7, 17, 6, 15, 0, tzinfo=UTC))
        self.assertTrue(r.tz_assumed)


def _resolved(skew_s: float) -> ResolvedTime:
    return ResolvedTime(
        event_time=REF - timedelta(seconds=skew_s),
        ingest_time=REF,
        tz_assumed=False,
        raw_timestamp="",
    )


class TestSkewTracker(unittest.TestCase):
    def test_stable_hour_offset_is_tz_misconfig(self):
        tr = SkewTracker(window=50, min_samples=20)
        verdict = None
        for i in range(25):
            verdict = tr.observe("r1", _resolved(3600.0 + (i % 5)))
        self.assertIsNotNone(verdict)
        self.assertEqual(verdict.kind, "tz_misconfig")
        self.assertEqual(verdict.nearest_offset_s, 3600)

    def test_stable_half_hour_offset_is_tz_misconfig(self):
        # IST-vs-UTC style +5:30 misconfig shows as a 30-min-multiple.
        tr = SkewTracker(window=50, min_samples=20)
        verdict = None
        for i in range(25):
            verdict = tr.observe("blr-fw1", _resolved(19800.0 + (i % 3)))
        self.assertIsNotNone(verdict)
        self.assertEqual(verdict.kind, "tz_misconfig")
        self.assertEqual(verdict.nearest_offset_s, 19800)

    def test_negative_offset_detected(self):
        # Device clock/zone AHEAD of real time → negative skew.
        tr = SkewTracker(window=50, min_samples=20)
        verdict = None
        for _ in range(25):
            verdict = tr.observe("r2", _resolved(-21600.0))
        self.assertIsNotNone(verdict)
        self.assertEqual(verdict.kind, "tz_misconfig")
        self.assertEqual(verdict.nearest_offset_s, -21600)

    def test_stable_odd_offset_is_clock_drift(self):
        # 7½ minutes off, steady: an NTP problem, not a zone.
        tr = SkewTracker(window=50, min_samples=20)
        verdict = None
        for _ in range(25):
            verdict = tr.observe("r3", _resolved(450.0))
        self.assertIsNotNone(verdict)
        self.assertEqual(verdict.kind, "clock_drift")

    def test_normal_pipeline_lag_is_quiet(self):
        tr = SkewTracker(window=50, min_samples=20)
        for i in range(40):
            self.assertIsNone(tr.observe("ok-dev", _resolved(1.0 + (i % 3))))

    def test_noisy_deltas_yield_no_verdict(self):
        # Wildly varying skew (e.g. replayed backlog) must not be called
        # a timezone problem.
        tr = SkewTracker(window=50, min_samples=20)
        verdicts = [tr.observe("noisy", _resolved(float(i * 900))) for i in range(30)]
        self.assertTrue(all(v is None for v in verdicts))

    def test_below_min_samples_is_quiet(self):
        tr = SkewTracker(window=50, min_samples=20)
        for _ in range(19):
            self.assertIsNone(tr.observe("young", _resolved(3600.0)))


if __name__ == "__main__":
    unittest.main()
