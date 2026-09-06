"""The onboard gate must never fail a run for STARTING FASTER (tracker 202).

THE FALSE FAILURE THIS FILE KILLS. The clause was
`last_window_rate >= --linearity-floor x FIRST_window_rate`. At 2,500 devices
the last-window create rate is a stable property of the device store —
30.5 / 28.6 / 26.1 / 25.2 / 24.8 /s across the five clean legs (s05, s06, s07,
n2k5, s09) — while the FIRST-window rate swings 27.7 -> 44.5 /s with api
process age and tombstone-store state. So the ratio graded the START:

  * `storm-s09` — the tracker-175 compaction had just IMPROVED the start
    (44.5/s against s08's 27.7/s). End rate 24.8/s, all 2,500 devices created,
    0 failures, 103 s of a 467 s budget. The clause FAILED the leg at 0.56 for
    exactly that improvement.
  * `storm-s06` — 28.5 -> 28.6 /s, "PASS 1.00". It merely started slow.

The replacement gates on an ABSOLUTE end-rate floor plus a decay reading taken
on the run's BODY (everything after the first window), so start speed cannot
move the verdict by construction; `last_over_first` stays in the evidence as
ADVISORY. The gate's real purpose — catching a super-linear (O(N^2))
per-device-persistence collapse — is covered here by slowdowns that still FAIL.

Run:  python3 -m pytest tests/test_miniladder_onboard_rate_gate.py -v
"""

from __future__ import annotations

import importlib.util
import json
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


def _load_harness():
    """Import the hyphen-named harness by path; the import must not touch PATH
    (the discipline every miniladder suite asserts)."""
    path = ROOT / "scripts" / "scale-miniladder.py"
    spec = importlib.util.spec_from_file_location("scale_miniladder_onboard", path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    before = os.environ.get("PATH", "")
    sys.modules["scale_miniladder_onboard"] = mod
    spec.loader.exec_module(mod)
    assert os.environ.get("PATH", "") == before
    return mod


ml = _load_harness()
H = ml.Harness

FLOOR = 0.6                     # --linearity-floor, the decay floor
END_FLOOR = 15.0                # --onboard-end-rate-floor, devices/s


def durations(*segments: tuple[int, float]) -> list[float]:
    """A per-create duration list from (count, rate) segments."""
    out: list[float] = []
    for count, rate in segments:
        out += [1.0 / rate] * count
    return out


def verdict(durs: list[float], k: int = 100, floor: float = FLOOR,
            end_floor: float = END_FLOOR) -> dict:
    return H.onboard_rate_verdict(durs, k, floor, end_floor)


# ═══════════════════════════════════════════════════════════════════════════
# 1. THE bug — storm-s09, a faster start graded as a slowdown
# ═══════════════════════════════════════════════════════════════════════════
# s09 as measured: 2,500 devices, first window 44.5/s, last window 24.8/s,
# 103 s wall (so the body runs at ~23.7/s).
S09 = durations((100, 44.5), (2300, 23.7), (100, 24.8))


def test_THE_bug_the_old_ratio_clause_fails_s09():
    """The artifact, reproduced at the store size it was measured at: the
    reading the OLD gate used is below the floor on a leg that created every
    device it asked for."""
    v = verdict(S09)
    assert v["last_over_first"] == pytest.approx(0.557, abs=0.005)
    assert v["last_over_first"] < FLOOR, (
        "if this ever stops being below the floor the fixture no longer "
        "reproduces the false failure and the regression is untested")


def test_s09_now_passes_because_a_faster_start_is_not_a_slowdown():
    v = verdict(S09)
    assert v["ok"], v["failures"]
    assert v["failures"] == []
    ev = v["evidence"]
    assert ev["last_window_rate_per_s"] == pytest.approx(24.8, abs=0.1)
    assert ev["last_over_body"] >= FLOOR
    assert ev["end_rate_floor_per_s"] == END_FLOOR


def test_the_ratio_is_recorded_but_flagged_advisory():
    """It is a true reading of start-vs-end and stays in the evidence — the
    fix is that it no longer DECIDES anything."""
    ev = verdict(S09)["evidence"]
    assert ev["last_over_first"] == pytest.approx(0.557, abs=0.005)
    assert ev["last_over_first_is_advisory"] is True
    assert verdict(S09)["ratio_below_floor"] is True


@pytest.mark.parametrize("first_rate", [20.0, 27.7, 44.5, 80.0, 200.0])
def test_no_start_speed_can_change_the_verdict(first_rate):
    """The property the fix rests on: with the body and the tail held fixed,
    sweeping the first window from 20/s to 200/s must not move the gate. Under
    the old clause 44.5/s and above FAILED and 20/s PASSED — the same store."""
    v = verdict(durations((100, first_rate), (2300, 23.7), (100, 24.8)))
    assert v["ok"], f"start {first_rate}/s failed the gate: {v['failures']}"
    assert v["evidence"]["last_over_body"] == pytest.approx(1.045, abs=0.01), (
        "the decay reading must be independent of the first window")


def test_storm_s11_the_baseline_of_record_still_passes():
    """The 9/9 leg of record (`docs/scale/baselines/storm-s11.v1.json`,
    tracker 203) must grade the same after the fix, or the fix silently
    re-bases the V1 comparison. Numbers read from the checked-in leg fixture."""
    report = json.loads(
        (ROOT / "tests" / "fixtures" / "storm-s11" / "report.json").read_text())
    onboard = next(p for p in report["phases"] if p["phase"] == "onboard")
    ev = onboard["evidence"]
    assert onboard["status"] == "PASS"
    n, k = ev["devices_created"], ev["window"]
    first, last = ev["first_window_rate_per_s"], ev["last_window_rate_per_s"]
    # The body rate implied by the leg's own wall clock and its two windows.
    body_wall = ev["total_wall_s"] - k / first - k / last
    body_rate = (n - 2 * k) / body_wall
    v = verdict(durations((k, first), (n - 2 * k, body_rate), (k, last)))
    assert v["ok"], v["failures"]
    assert v["last_over_first"] == pytest.approx(ev["last_over_first"], abs=0.01)


# ═══════════════════════════════════════════════════════════════════════════
# 2. the gate's real purpose — a genuine slowdown still FAILS
# ═══════════════════════════════════════════════════════════════════════════
def test_a_genuine_super_linear_collapse_still_fails():
    """The O(N^2) per-device-persistence class the clause exists for: the run
    starts at the plan rate and grinds down to a crawl."""
    v = verdict(durations((100, 30.0), (1200, 18.0), (1100, 6.0), (100, 4.0)))
    assert not v["ok"]
    joined = " ".join(v["failures"])
    assert "SUPER-LINEAR SLOWDOWN" in joined
    assert "BELOW THE 15/s FLOOR" in joined


def test_decay_still_fails_even_when_the_end_rate_clears_the_floor():
    """The absolute floor must not swallow the decay clause: a store that
    halves its throughput but stays above 15/s is still decaying."""
    v = verdict(durations((100, 200.0), (2300, 90.0), (100, 20.0)))
    assert not v["ok"]
    assert v["evidence"]["last_window_rate_per_s"] > END_FLOOR
    assert any("SUPER-LINEAR SLOWDOWN" in f for f in v["failures"])
    assert not any("BELOW THE" in f for f in v["failures"])


def test_a_uniformly_slow_store_fails_on_the_absolute_floor_alone():
    """Flat is not linear-enough when the whole run crawls: the decay reading
    is a clean 1.0 and only the end-rate floor can catch it. This is the case
    the old ratio clause PASSED with a perfect 1.00."""
    v = verdict(durations((2500, 8.0)))
    assert not v["ok"]
    assert v["last_over_first"] == pytest.approx(1.0, abs=1e-6)
    assert v["evidence"]["last_over_body"] == pytest.approx(1.0, abs=1e-6)
    assert any("BELOW THE 15/s FLOOR" in f for f in v["failures"])


def test_a_healthy_flat_run_passes():
    v = verdict(durations((2500, 26.0)))
    assert v["ok"]
    assert v["evidence"]["last_over_first"] == pytest.approx(1.0, abs=1e-6)


# ═══════════════════════════════════════════════════════════════════════════
# 3. arithmetic honesty
# ═══════════════════════════════════════════════════════════════════════════
def test_a_fleet_smaller_than_the_window_reports_the_window_it_used():
    """`k` as a numerator over fewer samples would invent a rate."""
    v = verdict(durations((10, 20.0)), k=100)
    assert v["evidence"]["window_used"] == 10
    assert v["evidence"]["last_window_rate_per_s"] == pytest.approx(20.0, abs=0.1)


def test_a_fleet_of_one_window_carries_no_decay_evidence_either_way():
    """With no body there is nothing to compare against; the decay reading is
    exactly 1.0 and the end-rate floor is the only clause that speaks."""
    fast = verdict(durations((10, 40.0)), k=10)
    slow = verdict(durations((10, 4.0)), k=10)
    assert fast["evidence"]["last_over_body"] == pytest.approx(1.0, abs=1e-6)
    assert fast["ok"]
    assert not slow["ok"]
    assert all("SUPER-LINEAR" not in f for f in slow["failures"])


def test_the_floors_are_parameters_not_constants():
    """`--linearity-floor` and `--onboard-end-rate-floor` both reach the
    arithmetic; a run can tighten either without a code change."""
    durs = durations((100, 44.5), (2300, 23.7), (100, 24.8))
    assert verdict(durs, floor=1.5)["failures"], "decay floor must bite"
    assert verdict(durs, end_floor=30.0)["failures"], "end floor must bite"


# ═══════════════════════════════════════════════════════════════════════════
# 4. the phase — what the run records and what the operator reads
# ═══════════════════════════════════════════════════════════════════════════
class _CreateApi:
    """The narrowest stack the onboard phase needs: every create is accepted
    under the id it asked for. The RATE is supplied by a scripted clock, so
    nothing here sleeps."""

    def __init__(self):
        self.posted: list[str] = []

    def api(self, method, path, body=None, timeout=30):
        assert (method, path) == ("POST", "/api/devices")
        self.posted.append(body["id"])
        return 201, {"id": body["id"]}


def _onboard_phase(tmp_path, monkeypatch, segments, devices):
    """Drive the real phase with a scripted monotonic clock: each create costs
    exactly the segment's per-device time, so the phase measures the rate this
    test asked for without sleeping."""
    costs: list[float] = []
    for count, rate in segments:
        costs += [1.0 / rate] * count
    per_create = iter(costs)
    now = {"t": 0.0}

    def monotonic():
        return now["t"]

    api = _CreateApi()
    accept = api.api            # bound BEFORE the wrapper replaces it

    def api_with_cost(method, path, body=None, timeout=30):
        now["t"] += next(per_create)
        return accept(method, path, body, timeout)

    monkeypatch.setattr(ml.time, "monotonic", monotonic)
    monkeypatch.setattr(ml, "RUN_LOCK_PATH", str(tmp_path / ".lock"))
    argv = ["--devices", str(devices), "--run-dir", str(tmp_path / "run"),
            "--env-file", str(tmp_path / "stack.env"),
            "--base-url", "http://stack.test"]
    h = ml.Harness(ml.parse_args(argv))
    h.stack = api
    h.stack.api = api_with_cost
    h.prefix = "mlx-090612000000-"
    h.runid = "090612000000"
    h.onboard()
    return next(p for p in h.phases if p["phase"] == "onboard")


def test_the_phase_passes_a_faster_start_and_says_why(tmp_path, monkeypatch):
    phase = _onboard_phase(tmp_path, monkeypatch,
                           [(100, 44.5), (2300, 23.7), (100, 24.8)], 2500)
    assert phase["status"] == "PASS"
    assert "advisory: last/first" in phase["notes"]
    assert "FASTER START, not decay" in phase["notes"]
    assert "[stop=none]" in phase["notes"]
    assert phase["evidence"]["last_over_first_is_advisory"] is True


def test_the_phase_still_fails_a_genuine_slowdown(tmp_path, monkeypatch):
    phase = _onboard_phase(tmp_path, monkeypatch,
                           [(100, 30.0), (1200, 18.0), (1100, 6.0),
                            (100, 4.0)], 2500)
    assert phase["status"] == "FAIL"
    assert "SUPER-LINEAR SLOWDOWN" in phase["notes"]
    # The owner's 2026-08-29 rule is untouched: a SPEED verdict never costs the
    # run its correlation evidence.
    assert phase["evidence"]["onboard_stop_reason"] == "none"
    assert phase["evidence"]["devices_created"] == 2500
