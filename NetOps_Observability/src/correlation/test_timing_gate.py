# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Unit tests for `timing_gate` — the fixture sizer four wall-clock gates rely on.

WHY THIS FILE EXISTS (tracker 289). This module decides whether
`test_p2_evidence_batching`, `test_p2_evidence_async`,
`test_sync_stretch_bound_p1` and `test_lifecycle_merge_storm_p1` are witnessing
anything at all, and it had NO tests of its own (§11). That is not an oversight
worth shrugging at: a sizer defect does not make a gate red, it makes a gate
UNABLE TO FAIL, and the one defect it did have took a full diagnosis cycle to
find precisely because nothing here could have caught it.

THE DEFECT, in one line: `calibrated_stall` extrapolates on a LINEAR cost model,
so an axis that SATURATES makes it ask for a bigger fixture, get nothing back,
burn every attempt, and then report "this machine outran the size cap" — which
blames the hardware for a workload that was bounded all along.
`test_loop_yield_resilience` walked that wall on 2026-09-12
(`CORR_OPEN_OBJECTS_MAX` force-closes past 5,000 objects: 700 -> 12,342 devices
moved the stall 2.05 s -> 3.31 s, and the LAST step went DOWN).

Not one test here takes a wall-clock measurement. `measure` is injected, so
every case is an exact statement about the sizer's arithmetic and its verdicts,
and the suite is as true on a hosted runner as on the lab box — which is the
property the module exists to give its callers.
"""
from __future__ import annotations

import pytest

import timing_gate


def recorder(fn):
    """(measure, sizes) — `fn(size)` with every size it was asked for."""
    sizes: list[int] = []

    def measure(size: int) -> float:
        sizes.append(size)
        return fn(size)

    return measure, sizes


# ── the cheap path: a fixture that was already big enough ───────────────────

def test_an_adequate_fixture_is_measured_once_and_never_grown():
    """A slow machine must pay nothing. This is the whole reason the first
    measurement doubles as the calibration probe."""
    measure, sizes = recorder(lambda n: 900.0)
    gate = timing_gate.calibrated_stall(measure, size=100, floor=500.0,
                                        max_size=10_000, name="g")
    assert gate.ok and not gate.calibrated
    assert sizes == [100]
    assert gate.size == 100 and gate.value == 900.0
    assert gate.tried == ((100, 900.0),)
    assert not gate.saturated


def test_exactly_the_floor_is_adequate():
    """The floor is the adequacy threshold, inclusive — a gate that demanded
    strictly more would grow a fixture that was already a witness."""
    measure, sizes = recorder(lambda n: 500.0)
    gate = timing_gate.calibrated_stall(measure, size=100, floor=500.0,
                                        max_size=10_000, name="g")
    assert gate.ok and sizes == [100]


# ── growing ────────────────────────────────────────────────────────────────

def test_a_linear_axis_is_grown_to_the_target_not_merely_to_the_floor():
    """The re-sized run aims at `target_mult` x floor, so a second attempt is
    not itself marginal — landing exactly ON the floor is how a gate flakes."""
    measure, sizes = recorder(lambda n: n * 2.0)      # 2 units per size unit
    # grow_cap lifted off the default 4.0 so the TARGET is what decides the
    # step here and not the step cap (which test_one_step_is_capped_by_grow_cap
    # owns): want = 100 * (500 x 2) / 200 = 500.
    gate = timing_gate.calibrated_stall(measure, size=100, floor=500.0,
                                        max_size=100_000, name="g",
                                        grow_cap=10.0)
    assert gate.ok and gate.calibrated
    assert sizes == [100, 500]
    assert gate.value == 1000.0 == gate.target
    assert not gate.saturated


def test_the_default_step_cap_binds_before_the_target_does():
    """With the shipped grow_cap of 4.0 the same axis stops at x4, which is the
    point: one step can overshoot by at most that much."""
    measure, sizes = recorder(lambda n: n * 2.0)
    gate = timing_gate.calibrated_stall(measure, size=100, floor=500.0,
                                        max_size=100_000, name="g")
    assert sizes == [100, 400] and gate.ok and gate.value == 800.0


def test_one_step_is_capped_by_grow_cap():
    """A mis-measured probe must not build an enormous fixture in one jump."""
    measure, sizes = recorder(lambda n: 1.0)          # absurdly low reading
    gate = timing_gate.calibrated_stall(measure, size=100, floor=500.0,
                                        max_size=10_000_000, name="g",
                                        attempts=2, grow_cap=4.0)
    assert sizes == [100, 400]                        # x4, not x1000
    assert not gate.ok


def test_growth_is_clamped_by_max_size_and_stops_there():
    measure, sizes = recorder(lambda n: n * 0.001)
    gate = timing_gate.calibrated_stall(measure, size=100, floor=500.0,
                                        max_size=250, name="g", attempts=4)
    assert sizes == [100, 250]        # clamped, and then `size < max_size` ends it
    assert gate.size == 250 and not gate.ok


def test_attempts_bounds_the_whole_thing():
    """A pathological machine costs a bounded number of legs, then fails with a
    report naming every size tried."""
    measure, sizes = recorder(lambda n: n * 0.0001)
    gate = timing_gate.calibrated_stall(measure, size=100, floor=500.0,
                                        max_size=10 ** 9, name="g", attempts=3)
    assert len(sizes) == 3 == len(gate.tried)
    assert not gate.ok


def test_a_zero_measurement_asks_for_the_step_cap_not_for_infinity():
    """`want` is floored at `floor / 32` so a zero (or near-zero) reading cannot
    divide by ~nothing and demand an unbuildable fixture."""
    measure, sizes = recorder(lambda n: 0.0)
    timing_gate.calibrated_stall(measure, size=100, floor=500.0,
                                 max_size=10 ** 9, name="g", attempts=2,
                                 grow_cap=4.0)
    assert sizes == [100, 400]


def test_the_caller_can_run_its_fixed_leg_against_the_size_that_was_measured():
    """`StallGate.size` is the contract that lets the FIXED leg run against the
    SAME fixture the mutant breached on."""
    measure, _ = recorder(lambda n: n * 2.0)
    gate = timing_gate.calibrated_stall(measure, size=100, floor=500.0,
                                        max_size=100_000, name="g")
    assert gate.size == gate.tried[-1][0]


# ── the saturating axis: the 2026-09-12 defect ──────────────────────────────

def test_an_axis_that_goes_down_is_named_as_saturated():
    """The sharpest form: a bigger fixture measures LESS. `test_loop_yield_
    resilience` did exactly this (5,705 -> 12,342 devices, 3.94 s -> 3.31 s)
    because CORR_OPEN_OBJECTS_MAX had already capped the cohort."""
    readings = iter([2.05, 3.35, 3.31])
    measure, _ = recorder(lambda n: next(readings))
    gate = timing_gate.calibrated_stall(measure, size=700, floor=8.0,
                                        max_size=100_000, name="loop yield",
                                        unit="s", attempts=3)
    assert not gate.ok
    assert gate.saturated
    assert "THE GROWTH AXIS SATURATED" in gate.report()
    assert "RAISING THE CAP WILL NOT HELP" in gate.report()


def test_a_flattening_axis_is_named_as_saturated():
    """It does not have to go down. An axis whose measurement grows far slower
    than the fixture is already extrapolation nonsense: the sizer's model is
    LINEAR, so it will keep asking for more and keep being disappointed."""
    # 17.6x the fixture for 1.61x the reading — the lab box's real curve.
    readings = iter([2.05, 3.31])
    measure, _ = recorder(lambda n: next(readings))
    gate = timing_gate.calibrated_stall(measure, size=700, floor=8.0,
                                        max_size=100_000, name="loop yield",
                                        unit="s", attempts=2, grow_cap=17.6)
    assert not gate.ok and gate.saturated
    assert gate.elasticity is not None and gate.elasticity < 0.5


def test_a_sound_axis_that_merely_ran_out_of_cap_is_NOT_called_saturated():
    """The distinction the whole property exists to draw. This axis pays
    linearly — it simply was not allowed to grow far enough — so the honest
    advice IS "raise the cap", and the report must still say so."""
    measure, _ = recorder(lambda n: n * 0.5)
    gate = timing_gate.calibrated_stall(measure, size=100, floor=500.0,
                                        max_size=200, name="g", attempts=3)
    assert not gate.ok
    assert not gate.saturated
    assert gate.elasticity == pytest.approx(1.0)
    assert "outran the size cap" in gate.report()
    assert "SATURATED" not in gate.report()


def test_a_superlinear_axis_is_never_called_saturated():
    """The EV-keyed merge witness is quadratic in POP. Nothing about paying MORE
    than linearly is a defect."""
    measure, _ = recorder(lambda n: (n / 100.0) ** 2)
    gate = timing_gate.calibrated_stall(measure, size=100, floor=10_000.0,
                                        max_size=200, name="g", attempts=2)
    assert not gate.ok and not gate.saturated
    assert gate.elasticity == pytest.approx(2.0)


def test_a_gate_that_passed_is_never_reported_as_saturated():
    """`saturated` describes a trail, and a single adequate measurement is not
    one. A passing gate must not carry a diagnosis."""
    measure, _ = recorder(lambda n: 900.0)
    gate = timing_gate.calibrated_stall(measure, size=100, floor=500.0,
                                        max_size=10_000, name="g")
    assert gate.ok and not gate.saturated and gate.elasticity is None


# ── the report, and the arguments ──────────────────────────────────────────

def test_the_report_names_every_size_tried_in_the_unit_the_caller_used():
    """A gate measured in seconds printed its trail as "0" under `:.0f` once.
    Both unit scales have to read correctly."""
    readings = iter([0.4673, 0.9])
    measure, _ = recorder(lambda n: next(readings))
    gate = timing_gate.calibrated_stall(measure, size=100, floor=4.0,
                                        max_size=400, name="ticker", unit="s",
                                        attempts=2)
    text = gate.report()
    assert "0.4673 s" in text and "size 100" in text and "size 400" in text
    assert "cap 400" in text and "ticker" in text


@pytest.mark.parametrize("kwargs", [
    {"size": 0, "max_size": 10},
    {"size": -1, "max_size": 10},
    {"size": 100, "max_size": 99},
])
def test_an_impossible_size_window_is_refused_not_silently_worked_around(kwargs):
    with pytest.raises(ValueError):
        timing_gate.calibrated_stall(lambda n: 1.0, floor=1.0, name="g", **kwargs)


def test_zero_attempts_is_refused():
    """`attempts=0` would return a gate that never measured anything, whose
    `ok` would be a statement about nothing."""
    with pytest.raises(ValueError):
        timing_gate.calibrated_stall(lambda n: 1.0, size=1, floor=1.0,
                                     max_size=10, name="g", attempts=0)
