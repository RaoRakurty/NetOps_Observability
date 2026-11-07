# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""tracker 379 — cumulative counters reach the episode detector as RATES.

Pins:
  * the defect: a steady counter fed raw opens a never-clearing episode
    (reproduced with the real EpisodeDetector, so the fix is shown to matter);
  * the fix: the same counter as a rate opens nothing; a real error burst still
    opens an episode;
  * seed / reset-wrap / non-advancing clock / per-source separation / bound;
  * the Python counter set equals the Go allowlist's cumulative families;
  * end to end through handle_metric, and the CORR_COUNTER_RATES kill switch.
"""
from __future__ import annotations

import os
import re
import unittest
from datetime import datetime, timedelta, timezone

import main
from counter_rate import CUMULATIVE_METRICS, RATE, RESET, SEED, STALE, CounterRates
from episodes import EpisodeDetector

HERE = os.path.dirname(os.path.abspath(__file__))
GO_FAMILIES = os.path.join(HERE, "..", "backend", "collectors", "metric_events.go")
T0 = datetime(2026, 11, 7, tzinfo=timezone.utc)
CUMULATIVE_UNITS = {"bytes", "errors", "discards", "fcs_errors", "transitions"}


def at(minute: float) -> datetime:
    return T0 + timedelta(minutes=minute)


def onsets(values: list[float], rates: bool) -> list[int]:
    det, cr, out = EpisodeDetector(), CounterRates(), []
    for i, v in enumerate(values):
        x = v
        if rates:
            _o, r = cr.observe(("t", "leaf1:Et1", "device_if_in_errors", "snmp_poll"), v, at(i))
            if r is None:
                continue
            x = r
        ev = det.observe("t", "leaf1:Et1", "device_if_in_errors", at(i), x)
        if ev is not None and ev.phase == "onset":
            out.append(i)
    return out


class DefectAndFixTest(unittest.TestCase):
    def test_raw_steady_counter_opens_a_false_episode(self):
        """Pins today's defect: the reason the fix exists."""
        self.assertTrue(onsets([1000.0 * i for i in range(300)], rates=False))

    def test_steady_counter_as_a_rate_opens_nothing(self):
        self.assertEqual(onsets([1000.0 * i for i in range(300)], rates=True), [])

    def test_a_real_error_burst_still_opens_an_episode(self):
        vals, total = [], 0.0
        for i in range(120):
            total += 50_000.0 if 90 <= i < 100 else 1000.0   # 50x burst for 10 polls
            vals.append(total)
        got = onsets(vals, rates=True)
        self.assertTrue(got and 90 <= got[0] < 100, got)


class CounterRatesTest(unittest.TestCase):
    K = ("t", "leaf1:Et1", "device_if_in_octets", "snmp_poll")

    def test_seed_then_rate_per_second(self):
        cr = CounterRates()
        self.assertEqual(cr.observe(self.K, 1000.0, at(0)), (SEED, None))
        self.assertEqual(cr.observe(self.K, 7000.0, at(1)), (RATE, 100.0))   # 6000 / 60 s

    def test_negative_delta_is_a_reset_and_reseeds(self):
        cr = CounterRates()
        cr.observe(self.K, 5000.0, at(0))
        self.assertEqual(cr.observe(self.K, 10.0, at(1)), (RESET, None))
        self.assertEqual(cr.observe(self.K, 610.0, at(2)), (RATE, 10.0))

    def test_non_advancing_clock_is_dropped_and_keeps_the_older_point(self):
        cr = CounterRates()
        cr.observe(self.K, 1000.0, at(1))
        self.assertEqual(cr.observe(self.K, 2000.0, at(1)), (STALE, None))
        self.assertEqual(cr.observe(self.K, 500.0, at(0)), (STALE, None))
        self.assertEqual(cr.observe(self.K, 7000.0, at(2)), (RATE, 100.0))

    def test_sources_and_tenants_never_share_a_base(self):
        cr = CounterRates()
        cr.observe(("t", "e", "device_if_in_octets", "snmp_poll"), 1_000_000.0, at(0))
        self.assertEqual(cr.observe(("t", "e", "device_if_in_octets", "via_controller"), 5.0, at(1))[0], SEED)
        self.assertEqual(cr.observe(("u", "e", "device_if_in_octets", "snmp_poll"), 5.0, at(1))[0], SEED)

    def test_counts_and_bound(self):
        cr = CounterRates(max_keys=3)
        for i in range(10):
            cr.observe(("t", f"e{i}", "m", "p"), 1.0, at(0))
        self.assertEqual(len(cr), 3)
        self.assertEqual(cr.counts[SEED], 10)
        with self.assertRaises(ValueError):
            CounterRates(max_keys=0)


class GoAllowlistDriftTest(unittest.TestCase):
    def test_python_set_equals_go_cumulative_families(self):
        with open(GO_FAMILIES, encoding="utf-8") as fh:
            src = fh.read()
        block = src[src.index("var rcaMetricFamilies"):]
        block = block[:block.index("\n}\n")]
        pairs = re.findall(r'"(device_[a-z0-9_]+)":\s*\{"[a-z_]+",\s*"([a-z_]+)"\}', block)
        self.assertGreater(len(pairs), 15, "parsed too few families — the regex rotted")
        go = {name for name, unit in pairs if unit in CUMULATIVE_UNITS}
        self.assertEqual(go, set(CUMULATIVE_METRICS))


class HandleMetricTest(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.fed: list[float] = []

        async def fake_feed(tenant, entity_id, metric, value, ts, **kw):
            self.fed.append(value)
            return False

        self._prev = (main.feed_episode_detector, main.COUNTER_RATES, main.COUNTER_RATES_ENABLED,
                      main.score, main.verified_tenant)
        main.feed_episode_detector = fake_feed
        main.COUNTER_RATES = CounterRates()
        main.score = lambda *a, **k: None
        main.verified_tenant = lambda claim, device, lane, **k: "t1"

    def tearDown(self):
        (main.feed_episode_detector, main.COUNTER_RATES, main.COUNTER_RATES_ENABLED,
         main.score, main.verified_tenant) = self._prev

    def ev(self, metric: str, value: float, ts: datetime) -> dict:
        return {"metric": metric, "value": value, "device": "leaf1", "if_name": "Ethernet1",
                "index": "1", "signal_family": "interface", "ts": ts.isoformat(),
                "collection_path": "snmp_poll", "tenant_id": "t1"}

    async def test_cumulative_metric_is_fed_as_a_rate(self):
        main.COUNTER_RATES_ENABLED = True
        now = datetime.now(timezone.utc)
        await main.handle_metric(self.ev("device_if_in_errors", 1000.0, now - timedelta(seconds=60)))
        await main.handle_metric(self.ev("device_if_in_errors", 1600.0, now))
        self.assertEqual(self.fed, [10.0])
        self.assertEqual(main.COUNTER_RATES.counts[SEED], 1)

    async def test_gauges_are_untouched(self):
        main.COUNTER_RATES_ENABLED = True
        await main.handle_metric(self.ev("device_cpu_percent", 42.0, datetime.now(timezone.utc)))
        self.assertEqual(self.fed, [42.0])

    async def test_kill_switch_restores_the_raw_feed(self):
        main.COUNTER_RATES_ENABLED = False
        await main.handle_metric(self.ev("device_if_in_errors", 1000.0, datetime.now(timezone.utc)))
        self.assertEqual(self.fed, [1000.0])


if __name__ == "__main__":
    unittest.main()
