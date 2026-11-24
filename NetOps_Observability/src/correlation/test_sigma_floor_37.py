# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""ENGINE_SEMVER 3.7.0, stage [2] — the σ floor (owner 2026-11-24).

z = (value − mean) / σ had no floor: on the lab an idle cEdge port moving from
12.8 to 13.9 B/s scored z = 2,366 and became a CRIT signal. The detector now
divides by σ_eff = max(σ, REL·|mean|, ABS[metric]) for the floored metrics and
freezes σ_eff at onset; CORR_SIGMA_FLOOR=0 restores the unfloored z byte for byte.
"""
from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone

import pytest

import episodes as EP
from episodes import EpisodeDetector, sigma_floor
from producers import severity_for
from series_admission import SERIES_SEMANTICS
from signals import Severity

T0 = datetime(2026, 11, 24, 0, 0, 0, tzinfo=timezone.utc)


def _feed(det: EpisodeDetector, metric: str, values: list[float], entity: str = "cedge-80:Gi4.200"):
    out = []
    for i, v in enumerate(values):
        ev = det.observe("t1", entity, metric, T0 + timedelta(seconds=60 * i), v)
        if ev is not None:
            out.append(ev)
    return out


def _noisy(base: float, jitter: float, n: int = 25, seed: int = 7) -> list[float]:
    rnd = random.Random(seed)
    return [base + rnd.uniform(-jitter, jitter) for _ in range(n)]


def test_idle_port_wobble_opens_no_episode():
    """The lab case: ~12.8 B/s baseline, then 13.9 B/s."""
    det = EpisodeDetector(sigma_floor=True)
    assert _feed(det, "device_if_in_octets", _noisy(12.8, 0.01) + [13.9] * 5) == []


def test_unfloored_detector_still_reads_the_wobble_as_crit():
    """Proves the regression fixture reproduces the defect with the floor off."""
    det = EpisodeDetector(sigma_floor=False)
    evs = _feed(det, "device_if_in_octets", _noisy(12.8, 0.01) + [13.9] * 5)
    assert evs and evs[0].phase == "onset"
    assert severity_for(evs[0].peak_deviation) is Severity.CRIT


def test_a_real_traffic_surge_is_still_crit():
    det = EpisodeDetector(sigma_floor=True)
    evs = _feed(det, "device_if_in_octets", _noisy(12.8, 0.01) + [150_000.0])
    assert [e.phase for e in evs] == ["onset"]
    assert severity_for(evs[0].peak_deviation) is Severity.CRIT


def test_error_counter_trickle_is_quiet_and_a_burst_opens_at_once():
    det = EpisodeDetector(sigma_floor=True)
    assert _feed(det, "device_if_in_errors", [0.0] * 25 + [0.02]) == []
    det = EpisodeDetector(sigma_floor=True)
    evs = _feed(det, "device_if_in_errors", [0.0] * 25 + [5.0])
    # The FIRST error on a clean port opens (σ = 0 used to swallow it into the baseline).
    assert [e.phase for e in evs] == ["onset"]
    assert severity_for(evs[0].peak_deviation) is Severity.CRIT


def test_cpu_wiggle_opens_no_episode():
    det = EpisodeDetector(sigma_floor=True)
    assert _feed(det, "device_cpu_percent", _noisy(42.9, 0.2) + [45.5, 43.0, 42.8]) == []


def test_floor_is_frozen_at_onset_so_clear_uses_the_same_scale():
    det = EpisodeDetector(sigma_floor=True)
    evs = _feed(det, "device_if_in_octets", _noisy(12.8, 0.01) + [150_000.0] * 3 + [13.0] * 3)
    assert [e.phase for e in evs] == ["onset", "clear"]


def test_unfloored_metrics_keep_the_legacy_path():
    for flag in (True, False):
        det = EpisodeDetector(sigma_floor=flag)
        got = _feed(det, "probe_rtt_ms", _noisy(20.0, 0.5) + [60.0] * 4, entity="p1")
        if flag:
            floored = got
        else:
            legacy = got
    assert floored == legacy and floored


@pytest.mark.parametrize("metric", sorted(EP.SIGMA_FLOOR_ABS))
def test_the_floor_changes_nothing_where_sigma_already_exceeds_it(metric):
    """ON == OFF, event for event, whenever the real σ is above the floor — the
    floor only ever bites on a near-flat baseline. (OFF is the legacy code path
    itself: `std_eff` stays None, so `_while_closed` freezes st.std() as before.)"""
    base = 10.0 * max(EP.SIGMA_FLOOR_ABS[metric], 1.0)
    jitter = 0.9 * base                    # σ ≈ 0.52·base ≫ ABS, and ≫ 10 % of mean
    vals = _noisy(base * 5, jitter, n=40) + [base * 40] * 4 + [base * 5] * 4
    on = _feed(EpisodeDetector(sigma_floor=True), metric, vals)
    off = _feed(EpisodeDetector(sigma_floor=False), metric, vals)
    assert on == off and on, metric


def test_env_switch(monkeypatch):
    monkeypatch.setenv("CORR_SIGMA_FLOOR", "0")
    assert EpisodeDetector().sigma_floor is False
    monkeypatch.setenv("CORR_SIGMA_FLOOR", "1")
    assert EpisodeDetector().sigma_floor is True
    monkeypatch.delenv("CORR_SIGMA_FLOOR")
    assert EpisodeDetector().sigma_floor is True  # default ON


def test_every_rca_family_has_a_floor_or_an_explicit_exemption():
    families = set(SERIES_SEMANTICS)
    undecided = sorted(families - set(EP.SIGMA_FLOOR_ABS) - EP.SIGMA_FLOOR_EXEMPT)
    assert undecided == [], f"give these a σ floor or list them in SIGMA_FLOOR_EXEMPT: {undecided}"
    assert not (set(EP.SIGMA_FLOOR_ABS) & EP.SIGMA_FLOOR_EXEMPT)
    assert set(EP.SIGMA_FLOOR_REL) <= set(EP.SIGMA_FLOOR_ABS)


def test_floor_values():
    assert sigma_floor("device_if_in_octets", 0.0) == 12_500.0
    assert sigma_floor("device_if_in_octets", 1_000_000.0) == 100_000.0  # 10 % of baseline
    assert sigma_floor("device_cpu_percent", 90.0) == 2.0                 # absolute only
    assert sigma_floor("device_bgp_fsm_transitions", 5.0) is None
