# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Sanity tests for the correlation engine's anomaly scorer.

Doesn't spin up Kafka — exercises the pure logic directly. Run with:

    cd src/correlation
    python -m unittest test_anomaly

M29: `score` is keyed by (tenant, entity, metric) — the tenant is part of the
identity, and LRU evictions are counted (never silent).
"""

import asyncio
import unittest

# Import without triggering the FastAPI / Kafka side effects in main.py.
# We treat the module as a library here.
import main
from main import SERIES, Series, score


class TestSeries(unittest.TestCase):
    def setUp(self):
        SERIES.clear()

    def test_mean_and_stddev(self):
        s = Series()
        for v in [1.0, 2.0, 3.0, 4.0, 5.0]:
            s.push(v)
        self.assertAlmostEqual(s.mean(), 3.0)
        self.assertAlmostEqual(s.stddev(), 1.5811, places=3)

    def test_below_threshold_returns_none(self):
        # Push 21 stable samples; the 22nd is within range → no anomaly.
        for _ in range(21):
            self.assertIsNone(score("t1", "dev", "metric", 50.0))
        # A slightly off value should not score.
        self.assertIsNone(score("t1", "dev", "metric", 50.5))

    def test_above_threshold_returns_z(self):
        # A z-score is only defined when the baseline has variance — a perfectly
        # flat series has stddev 0 and is deliberately not scored (see the
        # `sigma == 0` guard, which test_below_threshold_returns_none relies on).
        # Real telemetry is noisy, so feed a normal noisy baseline, then a spike.
        baseline = [100.0, 101.0, 99.0, 100.0, 102.0, 98.0, 100.0]
        for i in range(25):
            score("t1", "dev2", "m", baseline[i % len(baseline)])
        # A massive spike — should fire.
        z = score("t1", "dev2", "m", 9999.0)
        self.assertIsNotNone(z)
        self.assertGreater(z, 3.0)

    def test_warmup_pushes_silently(self):
        # First 19 pushes after the first one return None and grow the window.
        for i in range(19):
            self.assertIsNone(score("t1", "warmup", "x", float(i)))


class TestM29TenantIsolation(unittest.TestCase):
    """M29b: two tenants may own the same device name + metric; their baselines
    must never mix. Pre-fix the key was (device, metric) — tenant-blind."""

    def setUp(self):
        SERIES.clear()

    def test_same_device_metric_series_are_tenant_scoped(self):
        # Warm tenant A's baseline (noisy, so sigma > 0 and a spike would fire).
        baseline = [100.0, 101.0, 99.0, 100.0, 102.0, 98.0, 100.0]
        for i in range(25):
            score("tenant-a", "dev", "cpu", baseline[i % len(baseline)])
        # Tenant B, same device + metric, wildly different value range: with a
        # SHARED (tenant-blind) series this scores as a huge z; with per-tenant
        # series it is the first sample of a fresh warm-up → None.
        self.assertIsNone(score("tenant-b", "dev", "cpu", 9999.0))
        self.assertIn(("tenant-a", "dev", "cpu"), SERIES)
        self.assertIn(("tenant-b", "dev", "cpu"), SERIES)
        # And tenant A's own baseline is uncontaminated by B's values:
        # its spike still scores against the ~100 baseline.
        z = score("tenant-a", "dev", "cpu", 9999.0)
        self.assertIsNotNone(z)
        self.assertGreater(z, 3.0)


class TestM29EvictionObservability(unittest.TestCase):
    """M29a: LRU eviction is legitimate, silence about it is not (§10)."""

    def setUp(self):
        SERIES.clear()
        self._saved_max = main.SERIES_MAX
        self._saved_evicted = main.SERIES_EVICTED

    def tearDown(self):
        SERIES.clear()
        main.SERIES_MAX = self._saved_max
        main.SERIES_EVICTED = self._saved_evicted

    def test_eviction_past_cap_is_counted_and_on_healthz(self):
        main.SERIES_MAX = 3
        before = main.SERIES_EVICTED
        for i in range(6):
            score("t1", f"dev-{i}", "cpu", 1.0)
        self.assertEqual(len(SERIES), 3, "cap must hold")
        self.assertEqual(main.SERIES_EVICTED, before + 3, "every eviction counted")
        h = asyncio.run(main.health())
        self.assertGreater(h["engine_v2"]["series_evicted"], 0)
        self.assertEqual(h["engine_v2"]["series_len"], 3)
        self.assertEqual(h["engine_v2"]["series_max"], 3)

    def test_metrics_exposition_carries_series_counters(self):
        body = asyncio.run(main.metrics_exposition()).body.decode()
        self.assertIn("corr_zscore_series_evicted_total", body)
        self.assertIn('corr_zscore_series{k="len"}', body)


class _CaptureCH:
    def __init__(self):
        self.rows: list[dict] = []

    async def insert(self, table, rows, dedup_token=""):
        for r in rows:
            self.rows.append({"_table": table, **r})
        return True


class TestM29FindingTenant(unittest.TestCase):
    """M29b: the legacy z-score finding row must carry the tenant the event was
    VERIFIED under (verified_tenant in handle_metric), not a second registry
    lookup by device name — pre-fix an unregistered device's finding was
    stamped 'global' even when the producer's verified claim said otherwise."""

    def setUp(self):
        SERIES.clear()
        self._saved_ch = main.ch

    def tearDown(self):
        SERIES.clear()
        main.ch = self._saved_ch
        main.WINDOW_BUFFER.clear()
        main._BUFFERED_IDS.clear()

    def test_finding_row_carries_verified_tenant(self):
        fake = _CaptureCH()
        main.ch = fake

        from datetime import datetime, timezone

        def ev(value):
            return {
                "device": "d-m29", "metric": "cpu", "value": value,
                "signal_family": "device_resource",
                "tenant_id": "acme",   # verified claim (registry has no row → claim stands)
                "ts": datetime.now(timezone.utc).isoformat(),
            }

        baseline = [100.0, 101.0, 99.0, 100.0, 102.0, 98.0, 100.0]
        for i in range(25):
            asyncio.run(main.handle_metric(ev(baseline[i % len(baseline)])))
        asyncio.run(main.handle_metric(ev(9999.0)))   # spike → finding

        findings = [r for r in fake.rows if r["_table"] == "netops.findings"]
        self.assertTrue(findings, "the z-score spike must emit a finding")
        self.assertEqual(findings[-1]["tenant_id"], "acme",
                         "finding must carry the VERIFIED tenant, not the "
                         "registry fallback ('global')")


if __name__ == "__main__":
    unittest.main()
