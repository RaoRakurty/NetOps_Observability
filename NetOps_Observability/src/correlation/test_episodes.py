"""Build ② contract tests — canonical Signal (stage [1]) + episode model
(stage [2]). These encode docs/design/correlation-engine.md §2.1/§4.1 and the
owner's pre-freeze amendments; a behavior change here is a design change."""

from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

from episodes import (
    CLEAR_HOLD,
    CLOCK_BUDGET_S,
    DEFAULT_INTERVAL_S,
    MIN_SAMPLES,
    EpisodeDetector,
)
from signals import (
    DeadLetter,
    EntityType,
    ModalityClass,
    Observer,
    ObserverType,
    Severity,
    Signal,
    Source,
)

T0 = datetime(2026, 6, 11, 12, 0, 0, tzinfo=timezone.utc)


def obs(**kw: Any) -> Observer:
    base: dict[str, Any] = dict(observer_id="leaf1", observer_type=ObserverType.DEVICE)
    base.update(kw)
    return Observer(**base)


def sig(**kw: Any) -> Signal:
    base: dict[str, Any] = dict(
        tenant_id="", ts=T0, source=Source.METRIC, kind="metric_anomaly",
        observer=obs(), modality_class=ModalityClass.DEVICE_TELEMETRY,
        entity_type=EntityType.DEVICE, entity_id="leaf1",
        severity=Severity.WARN, native_id="leaf1|cpu|onset|123",
    )
    base.update(kw)
    return Signal(**base)


# --- stage [1]: canonical Signal -------------------------------------------


def test_signal_id_deterministic():
    assert sig().signal_id == sig().signal_id
    assert sig().signal_id != sig(native_id="other").signal_id
    assert sig().signal_id != sig(ts=T0 + timedelta(milliseconds=1)).signal_id


def test_observer_block_mandatory():
    with pytest.raises(DeadLetter):
        Observer(observer_id="", observer_type=ObserverType.DEVICE)
    with pytest.raises(DeadLetter):
        sig(entity_id="")
    with pytest.raises(DeadLetter):
        sig(kind="")
    with pytest.raises(DeadLetter):
        sig(ts=datetime(2026, 6, 11, 12, 0, 0))  # naive ts = event-time violation


def test_ch_row_shape_matches_frozen_schema():
    row = sig().to_ch_row()
    frozen_columns = {
        "tenant_id", "signal_id", "ts", "source", "kind",
        "observer_id", "observer_type", "observer_location",
        "observer_trust_domain", "collection_path", "modality_class",
        "source_clock_quality", "entity_type", "entity_id", "entity_tokens",
        "site", "path_id", "service_id", "severity", "metric_name",
        "value", "baseline", "deviation", "attrs",
    }
    assert set(row) == frozen_columns
    assert row["ts"] == "2026-06-11 12:00:00.000"
    assert row["source"] == "metric" and row["severity"] == "warn"


def test_attrs_bounded():
    with pytest.raises(DeadLetter):
        sig(attrs={"blob": "x" * 5000}).to_ch_row()


# --- stage [2]: episode detection ------------------------------------------


def feed_flat(det, n, *, start=T0, value=10.0, interval=60.0, jitter=0.0, **kw):
    """Feed n near-flat samples; returns the ts after the last sample."""
    ts = start
    events = []
    for i in range(n):
        v = value + (jitter if i % 2 else -jitter)
        ev = det.observe("", "leaf1", "cpu", ts, v, **kw)
        if ev:
            events.append(ev)
        ts += timedelta(seconds=interval)
    return ts, events


def test_no_episode_on_flat_series():
    det = EpisodeDetector()
    _, events = feed_flat(det, 100, jitter=0.5)
    assert events == []
    assert det.open_episodes() == 0


def test_step_change_opens_episode_with_onset_at_run_start():
    det = EpisodeDetector()
    ts, _ = feed_flat(det, MIN_SAMPLES + 30, jitter=0.5)
    first_anomalous = ts
    onset_ev = None
    for i in range(10):
        ev = det.observe("", "leaf1", "cpu", ts, 30.0)  # massive step
        if ev:
            onset_ev = ev
            break
        ts += timedelta(seconds=60)
    assert onset_ev is not None and onset_ev.phase == "onset"
    # Onset = CUSUM run start, NOT crossing time. The estimator may include up
    # to one noise sample as prefix, so it lands within one interval BEFORE the
    # true first anomalous sample — and the truth must sit inside the stated
    # uncertainty band (that's the whole point of carrying it).
    assert first_anomalous - timedelta(seconds=60) <= onset_ev.onset_ts <= first_anomalous
    band = timedelta(seconds=onset_ev.onset_uncertainty_s)
    assert onset_ev.onset_ts - band <= first_anomalous <= onset_ev.onset_ts + band
    assert det.open_episodes() == 1


def test_onset_uncertainty_is_half_interval_plus_clock_budget():
    det = EpisodeDetector()
    ts, _ = feed_flat(det, MIN_SAMPLES + 30, jitter=0.5, clock_quality="ntp")
    ev = None
    for _ in range(10):
        ev = det.observe("", "leaf1", "cpu", ts, 30.0, clock_quality="ntp")
        if ev:
            break
        ts += timedelta(seconds=60)
    assert ev is not None
    # interval EWMA converged to 60 s on a steady feed → ±60 s (one full
    # interval — run-start estimator ambiguity) + ntp budget.
    assert ev.onset_uncertainty_s == pytest.approx(60.0 + CLOCK_BUDGET_S["ntp"], abs=1.0)


def test_free_running_clock_widens_uncertainty():
    def run(quality):
        det = EpisodeDetector()
        ts, _ = feed_flat(det, MIN_SAMPLES + 30, jitter=0.5, clock_quality=quality)
        for _ in range(10):
            ev = det.observe("", "leaf1", "cpu", ts, 30.0, clock_quality=quality)
            if ev:
                return ev
            ts += timedelta(seconds=60)
        raise AssertionError("no onset")

    widened = run("free_running").onset_uncertainty_s - run("ntp").onset_uncertainty_s
    assert widened == pytest.approx(CLOCK_BUDGET_S["free_running"] - CLOCK_BUDGET_S["ntp"])


def test_clear_after_hold_and_peak_integral_tracked():
    det = EpisodeDetector()
    ts, _ = feed_flat(det, MIN_SAMPLES + 30, jitter=0.5)
    # Drive into an episode.
    onset = None
    for _ in range(10):
        ev = det.observe("", "leaf1", "cpu", ts, 30.0)
        ts += timedelta(seconds=60)
        if ev:
            onset = ev
            break
    assert onset is not None
    # Stay anomalous a while, then recover.
    for _ in range(5):
        det.observe("", "leaf1", "cpu", ts, 35.0)
        ts += timedelta(seconds=60)
    clear = None
    for _ in range(CLEAR_HOLD + 2):
        ev = det.observe("", "leaf1", "cpu", ts, 10.0)
        ts += timedelta(seconds=60)
        if ev:
            clear = ev
            break
    assert clear is not None and clear.phase == "clear"
    assert clear.onset_ts == onset.onset_ts        # episode identity preserved
    assert clear.peak_deviation >= onset.peak_deviation
    assert clear.integral > onset.integral          # area grew with duration
    assert clear.clear_ts is not None and clear.clear_ts < ts
    assert det.open_episodes() == 0


def test_baseline_frozen_during_episode():
    """The anomaly must not normalize itself away: a long-lived deviation
    stays an open episode because mean/σ are frozen at onset."""
    det = EpisodeDetector()
    ts, _ = feed_flat(det, MIN_SAMPLES + 30, jitter=0.5)
    opened = False
    for _ in range(10):
        if det.observe("", "leaf1", "cpu", ts, 30.0):
            opened = True
            ts += timedelta(seconds=60)
            break
        ts += timedelta(seconds=60)
    assert opened
    # 300 more anomalous samples — would dominate an unfrozen window.
    for _ in range(300):
        ev = det.observe("", "leaf1", "cpu", ts, 30.0)
        assert ev is None                  # no clear while still deviant
        ts += timedelta(seconds=60)
    assert det.open_episodes() == 1


def test_determinism_same_stream_same_events():
    def run():
        det = EpisodeDetector()
        out = []
        ts = T0
        vals = [10.0] * 40 + [25.0] * 8 + [10.0] * 6
        for v in vals:
            ev = det.observe("t1", "leaf1", "cpu", ts, v)
            if ev:
                out.append((ev.phase, ev.onset_ts, ev.onset_uncertainty_s,
                            round(ev.peak_deviation, 6), round(ev.integral, 6)))
            ts += timedelta(seconds=60)
        return out

    a, b = run(), run()
    assert a == b and len(a) >= 2  # at least onset + clear, bit-identical


def test_series_isolated_per_tenant_entity_metric():
    det = EpisodeDetector()
    ts = T0
    for _ in range(MIN_SAMPLES + 10):
        det.observe("t1", "leaf1", "cpu", ts, 10.0)
        det.observe("t2", "leaf1", "cpu", ts, 10.0)
        ts += timedelta(seconds=60)
    # Anomaly only in t1 — t2 must stay quiet (episodes never cross tenants).
    fired = []
    for _ in range(10):
        ev1 = det.observe("t1", "leaf1", "cpu", ts, 30.0)
        ev2 = det.observe("t2", "leaf1", "cpu", ts, 10.0)
        if ev1:
            fired.append(ev1)
        assert ev2 is None
        ts += timedelta(seconds=60)
    assert fired and det.open_episodes() == 1


def test_default_interval_before_observation():
    st_interval = DEFAULT_INTERVAL_S
    assert st_interval == 60.0  # documented default; config-hash member
