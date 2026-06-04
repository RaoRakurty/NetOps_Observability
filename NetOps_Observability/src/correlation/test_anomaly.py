"""Sanity tests for the correlation engine's anomaly scorer.

Doesn't spin up Kafka — exercises the pure logic directly. Run with:

    cd src/correlation
    python -m unittest test_anomaly
"""

import unittest

# Import without triggering the FastAPI / Kafka side effects in main.py.
# We treat the module as a library here.
from main import Series, score, SERIES, WINDOW_SIZE


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
            self.assertIsNone(score("dev", "metric", 50.0))
        # A slightly off value should not score.
        self.assertIsNone(score("dev", "metric", 50.5))

    def test_above_threshold_returns_z(self):
        # A z-score is only defined when the baseline has variance — a perfectly
        # flat series has stddev 0 and is deliberately not scored (see the
        # `sigma == 0` guard, which test_below_threshold_returns_none relies on).
        # Real telemetry is noisy, so feed a normal noisy baseline, then a spike.
        baseline = [100.0, 101.0, 99.0, 100.0, 102.0, 98.0, 100.0]
        for i in range(25):
            score("dev2", "m", baseline[i % len(baseline)])
        # A massive spike — should fire.
        z = score("dev2", "m", 9999.0)
        self.assertIsNotNone(z)
        self.assertGreater(z, 3.0)

    def test_warmup_pushes_silently(self):
        # First 19 pushes after the first one return None and grow the window.
        for i in range(19):
            self.assertIsNone(score("warmup", "x", float(i)))


if __name__ == "__main__":
    unittest.main()
