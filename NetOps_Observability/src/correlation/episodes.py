"""Episode detection — pipeline stage [2] of Correlation Engine v2 (#67).

Replaces "every z-crossing is a finding" with bounded **anomaly episodes**
(docs/design/correlation-engine.md §4.1):

  * onset: two-sided CUSUM over the signed z-deviation crosses H (default 4σ
    cumulative, slack K=0.5σ). The onset timestamp is the START of the
    accumulation run — not the crossing time, and never the alert firing time
    (those systematically lie about causal order).
  * onset uncertainty: ± one observed sampling interval, plus the source's
    clock-quality budget (owner: per-source timing budget — research C2: a
    60 s timing error collapses localization, so uncertainty is carried, not
    assumed away). One full interval, not half: the CUSUM run-start estimator
    can include up to one noise sample as a prefix (a noise sample that opened
    the accumulator run just before the real change), so ±interval/2 was
    empirically optimistic — the truth fell outside the band in testing.
  * clear: |z| back inside CLEAR_SIGMA for CLEAR_HOLD consecutive samples.
  * baseline freeze: mean/σ stop updating while an episode is open, so the
    anomaly cannot normalize itself away.

Detection constants are part of the future engine config hash — deterministic
first, calibrated at P4 (replay-driven calibration), never silently tuned.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Deque
from collections import deque

# --- Detection constants (config-hash members; P4 calibration re-fits them) ---
WINDOW_SIZE = 200          # rolling baseline samples
MIN_SAMPLES = 20           # no scoring before this many baseline samples
CUSUM_H = 4.0              # cumulative σ to open an episode
CUSUM_K = 0.5              # slack per sample (σ) — absorbs drift
CLEAR_SIGMA = 1.0          # |z| considered "back to normal"
CLEAR_HOLD = 3             # consecutive normal samples to close
DEFAULT_INTERVAL_S = 60.0  # assumed sampling interval until observed

# Owner: source-specific timing budget. Clock quality widens onset uncertainty
# beyond the sampling-interval term (seconds).
CLOCK_BUDGET_S = {
    "ptp": 0.0,
    "ntp": 0.1,
    "unknown": 2.0,
    "free_running": 10.0,
}


@dataclass(frozen=True)
class EpisodeEvent:
    """Emitted at onset and clear. The engine turns these into corr_signals
    rows; later stages attach them to objects."""

    phase: str                 # 'onset' | 'clear'
    key: tuple[str, str, str]  # (tenant_id, entity_id, metric)
    onset_ts: datetime
    onset_uncertainty_s: float
    value: float               # sample value at emission
    baseline: float            # frozen baseline mean at onset
    deviation: float           # signed z at emission
    peak_deviation: float      # max |z| so far / overall
    integral: float            # Σ|z|·dt (σ·seconds) — magnitude × duration
    clear_ts: datetime | None = None


@dataclass
class _SeriesState:
    values: Deque[float] = field(default_factory=lambda: deque(maxlen=WINDOW_SIZE))
    # CUSUM accumulators (two-sided, in σ units). Each side tracks its OWN run
    # start: alternating noise ping-pongs between sides, and a shared run-start
    # would pin onset to stale noise instead of the real anomaly's first sample.
    s_pos: float = 0.0
    s_neg: float = 0.0
    run_start_pos: datetime | None = None
    run_start_neg: datetime | None = None
    run_interval_pos: float = DEFAULT_INTERVAL_S
    run_interval_neg: float = DEFAULT_INTERVAL_S
    # open-episode state
    open: bool = False
    onset_ts: datetime | None = None
    onset_uncertainty_s: float = 0.0
    frozen_mean: float = 0.0
    frozen_std: float = 0.0
    peak: float = 0.0
    integral: float = 0.0
    clear_run: int = 0
    # sampling-interval EWMA
    last_ts: datetime | None = None
    interval_s: float = DEFAULT_INTERVAL_S
    clock_quality: str = "unknown"

    def mean(self) -> float:
        return sum(self.values) / len(self.values) if self.values else 0.0

    def std(self) -> float:
        n = len(self.values)
        if n < 2:
            return 0.0
        m = self.mean()
        return (sum((v - m) ** 2 for v in self.values) / (n - 1)) ** 0.5


class EpisodeDetector:
    """Per-(tenant, entity, metric) CUSUM episode state machine.

    Deterministic: same ordered (ts, value) stream ⇒ same events. No wall-clock
    reads — event time only (replay contract).
    """

    def __init__(self) -> None:
        self._state: dict[tuple[str, str, str], _SeriesState] = {}

    def observe(
        self,
        tenant_id: str,
        entity_id: str,
        metric: str,
        ts: datetime,
        value: float,
        clock_quality: str = "unknown",
    ) -> EpisodeEvent | None:
        """Feed one sample; returns an EpisodeEvent on onset/clear, else None."""
        key = (tenant_id, entity_id, metric)
        st = self._state.setdefault(key, _SeriesState())
        st.clock_quality = clock_quality

        # Sampling-interval EWMA (event-time): the uncertainty budget's first term.
        if st.last_ts is not None:
            dt = (ts - st.last_ts).total_seconds()
            if 0 < dt < 24 * 3600:
                st.interval_s = 0.8 * st.interval_s + 0.2 * dt
        st.last_ts = ts

        # Baseline warm-up: collect only.
        if len(st.values) < MIN_SAMPLES:
            st.values.append(value)
            return None

        mean = st.frozen_mean if st.open else st.mean()
        std = st.frozen_std if st.open else st.std()
        if std <= 0.0:
            if not st.open:
                st.values.append(value)
            return None
        z = (value - mean) / std

        if st.open:
            return self._while_open(st, key, ts, value, z)
        return self._while_closed(st, key, ts, value, z)

    # -- closed: accumulate CUSUM toward onset --------------------------------

    def _while_closed(
        self, st: _SeriesState, key: tuple[str, str, str],
        ts: datetime, value: float, z: float,
    ) -> EpisodeEvent | None:
        pos_was = st.s_pos > 0.0
        neg_was = st.s_neg > 0.0
        st.s_pos = max(0.0, st.s_pos + z - CUSUM_K)
        st.s_neg = max(0.0, st.s_neg - z - CUSUM_K)

        if st.s_pos > 0.0 and not pos_was:
            st.run_start_pos = ts          # this sample started the upward run
            st.run_interval_pos = st.interval_s
        elif st.s_pos == 0.0:
            st.run_start_pos = None
        if st.s_neg > 0.0 and not neg_was:
            st.run_start_neg = ts
            st.run_interval_neg = st.interval_s
        elif st.s_neg == 0.0:
            st.run_start_neg = None

        if max(st.s_pos, st.s_neg) >= CUSUM_H:
            # Onset = first sample of the CROSSING side's run.
            if st.s_pos >= st.s_neg:
                onset = st.run_start_pos or ts
                run_interval = st.run_interval_pos
            else:
                onset = st.run_start_neg or ts
                run_interval = st.run_interval_neg
            # Owner timing budget: ± one sampling interval (run-start estimator
            # ambiguity, see module docstring) + clock-quality term.
            clock = CLOCK_BUDGET_S.get(st.clock_quality, CLOCK_BUDGET_S["unknown"])
            uncertainty = run_interval + clock
            st.open = True
            st.onset_ts = onset
            st.onset_uncertainty_s = uncertainty
            st.frozen_mean = st.mean()
            st.frozen_std = st.std()
            st.peak = abs(z)
            st.integral = abs(z) * st.interval_s
            st.clear_run = 0
            st.s_pos = st.s_neg = 0.0
            st.run_start_pos = st.run_start_neg = None
            return EpisodeEvent(
                phase="onset", key=key, onset_ts=onset,
                onset_uncertainty_s=uncertainty, value=value,
                baseline=st.frozen_mean, deviation=z,
                peak_deviation=st.peak, integral=st.integral,
            )

        st.values.append(value)  # below threshold: sample joins the baseline
        return None

    # -- open: track peak/integral, watch for clear ---------------------------

    def _while_open(
        self, st: _SeriesState, key: tuple[str, str, str],
        ts: datetime, value: float, z: float,
    ) -> EpisodeEvent | None:
        st.peak = max(st.peak, abs(z))
        st.integral += abs(z) * st.interval_s

        if abs(z) < CLEAR_SIGMA:
            st.clear_run += 1
        else:
            st.clear_run = 0

        if st.clear_run >= CLEAR_HOLD:
            # clear_ts = first sample of the hold run (the actual recovery point).
            clear_ts = ts - timedelta(seconds=st.interval_s * (CLEAR_HOLD - 1))
            ev = EpisodeEvent(
                phase="clear", key=key,
                onset_ts=st.onset_ts or ts,
                onset_uncertainty_s=st.onset_uncertainty_s,
                value=value, baseline=st.frozen_mean, deviation=z,
                peak_deviation=st.peak, integral=st.integral,
                clear_ts=clear_ts,
            )
            # Reset for the next episode; recovered samples re-seed the baseline.
            st.open = False
            st.onset_ts = None
            st.peak = 0.0
            st.integral = 0.0
            st.clear_run = 0
            st.values.append(value)
            return ev
        return None

    def open_episodes(self) -> int:
        return sum(1 for st in self._state.values() if st.open)
