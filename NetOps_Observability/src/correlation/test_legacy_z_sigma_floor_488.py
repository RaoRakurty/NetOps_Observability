# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Tracker 488: the legacy z-score lane (`main.score`, netops.findings) applies
the owner-approved σ floor (2026-11-24) — the SAME constants and kill switch as
the episode detector, so an idle port can no longer write CRITICAL findings.

Lab evidence before the fix (7 days): 5,222 critical `anomaly` findings, octet
rates at z up to ~20,000, read by Iris "detected anomalies", reports and flows.
"""

import random
import unittest

import episodes
import main
from main import SERIES, Z_THRESHOLD, Series, score


def _reference_score(state: dict, key: tuple, value: float) -> float | None:
    """The pre-488 algorithm, verbatim, over its own series — the oracle the
    flag-OFF and unfloored-metric paths must match byte for byte."""
    s = state.setdefault(key, Series())
    if len(s.values) < 20:
        s.push(value)
        return None
    sigma = s.stddev()
    if sigma == 0:
        s.push(value)
        return None
    z = abs((value - s.mean()) / sigma)
    s.push(value)
    if z >= Z_THRESHOLD:
        return z
    return None


def _feed(device: str, metric: str, values: list[float]) -> list[float | None]:
    return [score("t", device, metric, v) for v in values]


class _FlagCase(unittest.TestCase):
    flag = True

    def setUp(self):
        SERIES.clear()
        self._saved = main.SCORE_SIGMA_FLOOR
        main.SCORE_SIGMA_FLOOR = self.flag

    def tearDown(self):
        main.SCORE_SIGMA_FLOOR = self._saved
        SERIES.clear()


class TestFloorOn(_FlagCase):
    flag = True

    def test_lab_idle_port_wobble_writes_no_finding(self):
        # cEDGE-80 Gi4.200: ~12.8 B/s with tiny noise, then 13.9 B/s.
        base = [12.8 + (0.01 if i % 2 else -0.01) for i in range(25)]
        _feed("cedge-80:Gi4.200", "device_if_in_octets", base)
        self.assertIsNone(score("t", "cedge-80:Gi4.200", "device_if_in_octets", 13.9))

    def test_real_traffic_spike_still_fires_critical(self):
        base = [12.8 + (0.01 if i % 2 else -0.01) for i in range(25)]
        _feed("p", "device_if_in_octets", base)
        z = score("t", "p", "device_if_in_octets", 150_000.0)
        self.assertIsNotNone(z)
        self.assertGreaterEqual(z, 5.0)  # the lane's own "critical" bar

    def test_clean_error_counter_first_real_error_is_scored(self):
        _feed("e", "device_if_in_errors", [0.0] * 25)
        # A trickle below the 0.1/s floor is not a finding …
        self.assertIsNone(score("t", "e", "device_if_in_errors", 0.02))
        SERIES.clear()
        _feed("e2", "device_if_in_errors", [0.0] * 25)
        # … a real burst is, on its FIRST sample (σ = 0 no longer swallows it).
        z = score("t", "e2", "device_if_in_errors", 5.0)
        self.assertIsNotNone(z)
        self.assertGreaterEqual(z, 5.0)

    def test_cpu_small_move_writes_no_finding(self):
        _feed("c", "device_cpu_percent", [42.9 + (0.05 if i % 2 else -0.05) for i in range(25)])
        self.assertIsNone(score("t", "c", "device_cpu_percent", 45.5))

    def test_unfloored_metric_matches_the_legacy_algorithm_exactly(self):
        rng = random.Random(488)
        ref: dict = {}
        for metric in ("cpu", "metric", "device_bgp_fsm_transitions", "device_if_speed"):
            for i in range(120):
                v = rng.choice([0.0, 1.0, 1.0, 2.0, 50.0]) if i % 9 else rng.uniform(0, 1e6)
                self.assertEqual(score("t", "d", metric, v), _reference_score(ref, ("t", "d", metric), v), metric)

    def test_reuses_the_episode_detectors_floor(self):
        self.assertIs(main.sigma_floor, episodes.sigma_floor)
        self.assertIs(main.sigma_floor_enabled, episodes.sigma_floor_enabled)


class TestFloorOff(_FlagCase):
    flag = False

    def test_flag_off_is_byte_identical_to_the_legacy_algorithm(self):
        rng = random.Random(4880)
        ref: dict = {}
        metrics = ("device_if_in_octets", "device_if_out_discards", "device_cpu_percent",
                   "device_mem_percent", "cpu")
        for metric in metrics:
            for i in range(150):
                if i < 30:
                    v = 12.8 + rng.choice([-0.01, 0.0, 0.01])
                else:
                    v = rng.choice([12.8, 13.9, 0.0, 5.0, 150_000.0])
                self.assertEqual(score("t", "d", metric, v), _reference_score(ref, ("t", "d", metric), v), metric)

    def test_flag_off_reproduces_the_lab_defect(self):
        base = [12.8 + (0.01 if i % 2 else -0.01) for i in range(25)]
        _feed("x", "device_if_in_octets", base)
        z = score("t", "x", "device_if_in_octets", 13.9)
        self.assertIsNotNone(z)
        self.assertGreater(z, 100.0)  # the idle-port explosion the floor removes


class TestKillSwitch(unittest.TestCase):
    def test_default_follows_the_shared_switch(self):
        self.assertEqual(main.SCORE_SIGMA_FLOOR, episodes.sigma_floor_enabled())


if __name__ == "__main__":
    unittest.main()
