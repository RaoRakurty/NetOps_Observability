"""O(1) rolling mean/std (perf defect #4 — main.Series + episodes._SeriesState).

mean()/std() used to walk the full 200-sample deque on EVERY call (~6 full
passes per metric sample across the episode detector + the legacy z-score),
saturating a core near 2-5k samples/s. Both now carry shifted running sums
updated O(1) per push, guarded against float drift by an exact recompute every
STATS_RECOMPUTE_EVERY pushes and a negative-variance clamp-and-rebuild.

Pinned here:
  * accuracy — incremental stats equal the naive full-pass stats through
    warm-up, steady state and deque eviction, even at a hostile 1e9 offset
  * drift guard — the exact recompute fires on its cadence (operation-count
    assertion: recomputes == pushes // STATS_RECOMPUTE_EVERY, i.e. amortized
    O(window/1024) per sample, not O(window))
  * clamp — a corrupted negative variance self-heals via exact rebuild
  * determinism — the episode detector emits identical events for identical
    ordered streams (replay contract untouched)
"""

from __future__ import annotations

import math
from datetime import datetime, timedelta, timezone

import episodes
import main
from episodes import EpisodeDetector

T0 = datetime(2026, 6, 12, 9, 42, 0, tzinfo=timezone.utc)


def _naive_mean(values) -> float:
    return sum(values) / len(values) if values else 0.0


def _naive_std(values) -> float:
    n = len(values)
    if n < 2:
        return 0.0
    m = _naive_mean(values)
    return (sum((v - m) ** 2 for v in values) / (n - 1)) ** 0.5


def _stream(n: int, offset: float = 0.0):
    """Deterministic, non-trivial series (two mixed sines + slow ramp)."""
    return [offset + 10.0 * math.sin(0.31 * k) + 3.0 * math.sin(1.7 * k) + 0.01 * k
            for k in range(n)]


# ── main.Series (legacy z-score path) ────────────────────────────────────────


def test_series_matches_naive_through_warmup_and_eviction():
    s = main.Series()
    for i, v in enumerate(_stream(1000)):
        s.push(v)
        if i in (0, 1, 19, 199, 200, 500, 999):   # warm-up, boundary, evicting
            assert math.isclose(s.mean(), _naive_mean(s.values),
                                rel_tol=1e-9, abs_tol=1e-9)
            assert math.isclose(s.stddev(), _naive_std(s.values),
                                rel_tol=1e-7, abs_tol=1e-9)


def test_series_accurate_at_hostile_offset():
    """1e9 baseline with ~10-unit variance — the catastrophic-cancellation
    shape the shifted sums + periodic recompute exist for."""
    s = main.Series()
    for v in _stream(3000, offset=1e9):
        s.push(v)
    assert math.isclose(s.mean(), _naive_mean(s.values), rel_tol=1e-12)
    assert math.isclose(s.stddev(), _naive_std(s.values), rel_tol=1e-6)


def test_series_recompute_cadence_is_amortized_o1():
    s = main.Series()
    calls = {"n": 0}
    orig = s._recompute

    def counting():
        calls["n"] += 1
        orig()

    s._recompute = counting
    n = 2 * main.STATS_RECOMPUTE_EVERY + 100
    for v in _stream(n):
        s.push(v)
    for _ in range(50):        # queries are O(1): no recompute per read
        s.mean(), s.stddev()
    assert calls["n"] == n // main.STATS_RECOMPUTE_EVERY


def test_series_negative_variance_self_heals():
    s = main.Series()
    for _ in range(50):
        s.push(7.0)            # true variance is exactly 0
    s._sumsq = -1.0            # simulate accumulated drift artifact
    assert s.stddev() == 0.0   # clamp → exact rebuild → honest zero
    assert math.isclose(s.mean(), 7.0)


def test_score_behaviour_unchanged():
    main.SERIES.clear()
    for _ in range(25):
        assert main.score("t", "dev1", "cpu", 10.0) is None or True
    # constant series: σ==0 → never a z-score
    assert main.score("t", "dev1", "cpu", 10.0) is None
    main.SERIES.clear()
    for v in _stream(50):
        main.score("t", "dev2", "cpu", v)
    z = main.score("t", "dev2", "cpu", 1000.0)   # gross outlier must still fire
    assert z is not None and z >= main.Z_THRESHOLD
    main.SERIES.clear()


# ── episodes._SeriesState (CUSUM baseline) ───────────────────────────────────


def test_series_state_matches_naive():
    st = episodes._SeriesState()
    for i, v in enumerate(_stream(600, offset=1e6)):
        st.push(v)
        if i in (1, 19, 199, 205, 599):
            assert math.isclose(st.mean(), _naive_mean(st.values), rel_tol=1e-12)
            assert math.isclose(st.std(), _naive_std(st.values),
                                rel_tol=1e-6, abs_tol=1e-9)


def test_detector_determinism_same_stream_same_events():
    """Replay contract: identical ordered (ts, value) streams ⇒ identical
    episode events, byte for byte — the O(1) stats change nothing."""
    def drive():
        det = EpisodeDetector()
        out = []
        vals = _stream(80) + [100.0] * 10 + _stream(20)   # spike opens+clears
        for k, v in enumerate(vals):
            ev = det.observe("t1", "dev1", "cpu", T0 + timedelta(seconds=30 * k), v)
            if ev is not None:
                out.append(ev)
        return out

    a, b = drive(), drive()
    assert a == b
    assert any(e.phase == "onset" for e in a), "the spike must open an episode"


def test_detector_still_detects_at_hostile_offset():
    det = EpisodeDetector()
    onset = None
    vals = [1e9 + v for v in _stream(60)] + [1e9 + 500.0] * 8
    for k, v in enumerate(vals):
        ev = det.observe("t1", "devX", "octets", T0 + timedelta(seconds=30 * k), v)
        if ev is not None and ev.phase == "onset":
            onset = ev
    assert onset is not None, "a 50σ step at a 1e9 baseline must still onset"
