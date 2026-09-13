# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Machine-calibrated fixture sizing for the WALL-CLOCK mutant gates.

WHY THIS EXISTS (two hosted-runner failures, 2026-09-03)
--------------------------------------------------------
Several tests in this suite are A/B mutant tests over a *stall*: run the
shipped-before code (the MUTANT) and prove it holds the event-loop thread past
the budget, then run the fix and prove it does not. The fixed leg's assertion is
the design SLO (`fixed < 500 ms`, `worst_on < 1 s`) and is absolute on purpose.
The mutant leg's assertion is NOT an SLO — it is a FIXTURE-ADEQUACY gate: it
says "the workload I just drove is big enough that the SLO assertion means
something on this machine".

Written as a hard-coded fixture size plus an absolute floor, that adequacy gate
is a latent flake, because the size was measured on ONE machine:

    test_loop_yield_resilience  — "the yield budget did not materially reduce
        the stall: 467 ms (off) vs 150 ms (on)" (needs 4x, got 3.1x)
        [this caller was retired from the sizer on 2026-09-12 — see the growth
        axis section below for why calibration could never have fixed it]
    test_p2_evidence_batching   — "the mutant must reproduce the defect
        (worst lag 466 ms) — assert >= 500.0"

Both passed locally and on the lab box and failed on a GitHub-hosted runner that
is roughly 2.5x faster on these paths: the mutant simply finished its grind
before the floor. Nothing was wrong with the code under test — the fixture was
sized for slower hardware, so the test refused to prove anything and said so by
going red. `test_sync_stretch_bound_p1` already carries a hand-applied x5 rescale
from the same cause (2026-09-01), which is the evidence that hand-sizing does not
hold.

WHAT THIS MODULE DOES
---------------------
Sizes the fixture to the MACHINE instead of to a remembered number. The first
measurement doubles as the calibration probe — it measures exactly the quantity
the gate is about, on exactly the code path under test, so there is no synthetic
benchmark to drift out of step with reality:

  1. measure the mutant at the documented live-shape size (one leg, the cost the
     test already paid);
  2. if that lands at or above the floor, stop — nothing changed, and a slow
     machine pays nothing;
  3. otherwise extrapolate the size that WOULD have produced `target`
     (= `target_mult` x floor, i.e. a deliberate over-shoot so the retry is not
     itself marginal) under a linear cost model, clamped by `grow_cap` per step
     and by `max_size` overall, and measure again.

`attempts` bounds the whole thing, so a pathological machine costs a bounded
number of legs and then fails with a report naming every size tried.

WHAT IT DELIBERATELY DOES NOT DO
--------------------------------
  * It never weakens an assertion. Every SLO, ratio and count invariant stays
    exactly as it was; growing the fixture can only make the mutant's breach
    more emphatic.
  * It never SHRINKS a fixture. The size is a floor, never a ceiling.
  * It is not a retry of a failed assertion. The re-measurement happens because
    the workload was too small to be a witness — an input problem, decided
    before any invariant is evaluated — and the growth is computed from the
    measurement, not blindly doubled.

CHOOSING THE GROWTH AXIS IS THE CALLER'S JOB, and it is not free. The axis must
grow the MUTANT's stall without moving the shape the defect lives in — AND
without moving anything else the test asserts.

THE AUDIT OF RECORD (tracker 289, 2026-09-13). Every caller's axis was walked to
its cap and past it on the 4-core lab box, with BOTH legs measured at every
size. Two numbers decide whether an axis is sound, and each caller's own
constant carries its full table:

  * ELASTICITY of the mutant — the exponent `e` in `value ~ size**e`. Below ~0.5
    the axis has SATURATED and no amount of calibration can reach the floor;
    `StallGate.saturated` now says so in the failure message instead of blaming
    the machine.
  * The FIXED leg's elasticity beside it. A fixed leg that grows is fine — B10's
    does — as long as it grows SLOWER, so the fixed:mutant ratio falls as the
    fixture grows. When the two exponents match, the legs are locked together
    and growing the fixture cannot separate them.

      caller                        mutant e   fixed e   verdict
      B10  ambient window               1.23      0.61   SOUND, ratio falls
                                                         0.033 -> 0.009; fixed
                                                         59 ms at the cap, 8.5x
      test_lifecycle_merge_storm_p1     1.14      0.86   SOUND, ratio falls
      test_sync_stretch_bound_p1        0.80      0.02   SOUND, fixed leg FLAT
                                                         (53.0/54.8/54.2 ms)
      B12  signals per node             2.35      2.29   **RETIRED** — locked
      test_p2_evidence_async E10        1.24       n/a   sound axis, CAP CUT
      test_loop_yield_resilience        0.17       —     RETIRED 2026-09-12

NONE of the four had the saturating axis the loop-yield gate had. Two were
unsound for the OTHER reason, and it is the one worth remembering:

  * B12's fixed leg pays at 2.29 against its mutant's 2.35 — the same exponent —
    so the sizer cannot buy margin. Worse, `calibrated_stall` extrapolates
    LINEARLY, so on a 2.35 axis it overshoots the size badly (to multiply the
    reading by 4x the axis needs 1.8x the fixture; the model asks for 4x).
    Simulated against the measured curve on this file's own documented anchors,
    a machine 2x the 2026-09-03 hosted runner grows to B12's old 360 cap with
    the fixed leg at 79 % of the very budget it asserts — and the failure
    message would have blamed the offload. B12 no longer uses this module: its
    adequacy claim is structural and its dispatch proof is B12b's count.
  * E10's axis is sound, but it grows each cohort's WALL-CLOCK duration into
    `CORR_EVIDENCE_HOLD_MAX_S` (5 s) — a deadline the same test asserts is never
    hit. At its old cap a hold expired. The cap is now the largest size measured
    with none.

SO: "does the axis saturate" is NOT the whole check. Before adding a caller, ask
BOTH questions — does the mutant keep paying, and does anything else in the test
(the fixed leg, a timeout, a queue bound, a wall-clock deadline) grow with the
same knob? Per-caller notes:

  * `test_p2_evidence_batching::B12` USED to grow SIGNALS PER NODE. It no longer
    uses this module at all — see the audit above: the axis pays superlinearly
    and so does its fixed leg, at the same exponent. (Its shape rule stands for
    anyone who re-sizes that fixture by hand: `_snap_elements` (nodes + edges)
    must stay under `CORR_OFFLOAD_MIN_ELEMENTS` or the mutant sizer starts
    offloading and the defect evaporates — measured, at 2,375 nodes the "mutant"
    stall fell from 2,418 ms to 339 ms because it was no longer a mutant.)
  * `test_loop_yield_resilience` USED to grow DEVICES at a fixed 1 s spacing.
    It no longer uses this module at all, and the reason is the sharpest lesson
    here (2026-09-12): **the axis saturated, so no amount of calibration could
    ever reach the floor.** `CORR_OPEN_OBJECTS_MAX` (5,000) force-closes the
    excess, so past ~5,000 objects the cohort — and therefore the mutant's
    grind — stops growing. Measured on the lab box: 700 devices → 2.05 s, 2,690
    → 3.35 s, 5,705 → 3.94 s, 12,342 → 3.31 s, i.e. it goes DOWN. A hosted
    runner walked the same wall (0.885 s, 1.603 s, 1.572 s, 1.546 s against a
    1.7 s floor) and this module reported "this machine outran the size cap"
    when nothing of the sort had happened. Worse, that caller's FIXED leg also
    scaled with the cohort (144 ms at 700 devices, 358 ms at 2,690), so it
    appeared on BOTH sides of the ratio and growing the fixture actively hurt.
    Its resilience invariant is now a machine-independent COUNT of objects
    processed between event-loop handoffs, with no clock in the assertion.
    BEFORE ADDING A CALLER, CHECK ITS AXIS: "bigger fixture => bigger number"
    must hold, and the quantity being grown must not appear in the fixed leg
    too. `StallGate.saturated` now catches the first half mechanically; the
    second half is still the caller's to check, and the audit above is what it
    looks like done.
  * `test_sync_stretch_bound_p1` grows the CLOSE COUNT, never the signals per
    object (its own module docstring's rule: signals per object would grow the
    bounded leg's single-builder block toward the budget).

Units are the caller's: pass the floor in whatever unit `measure` returns
(milliseconds for the loop-lag watchdog tests, seconds for the ticker tests).
"""
from __future__ import annotations

import math
from collections.abc import Callable
from dataclasses import dataclass


@dataclass(frozen=True)
class StallGate:
    """The outcome of a calibration: what was measured, at what size, and the
    full trail — so a genuine failure reads as "this machine outran the cap",
    never as "something timed out"."""

    name: str
    floor: float
    target: float
    unit: str
    size: int
    value: float
    tried: tuple[tuple[int, float], ...]
    max_size: int

    @property
    def ok(self) -> bool:
        """The workload was big enough to witness the defect."""
        return self.value >= self.floor

    @property
    def calibrated(self) -> bool:
        """True when the base size was not enough and the fixture was grown."""
        return len(self.tried) > 1

    @property
    def elasticity(self) -> float | None:
        """How hard the axis actually pays, over the whole trail: the exponent
        `e` in `value ~ size**e`.

        A sound growth axis reads ~1.0 (linear) or above (the EV-keyed merge
        witness is quadratic). `None` when there is nothing to compare —
        one attempt, or a degenerate measurement.
        """
        if len(self.tried) < 2:
            return None
        (s0, v0), (s1, v1) = self.tried[0], self.tried[-1]
        if s1 <= s0 or v0 <= 0 or v1 <= 0:
            return None
        return math.log(v1 / v0) / math.log(s1 / s0)

    @property
    def saturated(self) -> bool:
        """The axis STOPPED PAYING: the fixture was grown and the measurement
        did not follow.

        This is the defect that cost a diagnosis cycle on 2026-09-12 and is the
        reason this property exists. `calibrated_stall` extrapolates on a LINEAR
        cost model, so when the axis saturates it asks for a bigger and bigger
        fixture, gets nothing back, burns every attempt and then reports "this
        machine outran the size cap" — blaming the hardware for a workload that
        was bounded all along. `test_loop_yield_resilience` walked exactly that
        wall: `CORR_OPEN_OBJECTS_MAX` force-closes past 5,000 objects, so 700 ->
        12,342 devices (17.6x) moved the stall 2.05 s -> 3.31 s (1.61x, and the
        last step went DOWN) — elasticity 0.17 against the ~1.0 a sound axis
        reads.

        Deliberately ADVISORY: it changes what a failure SAYS, never whether it
        fails. A gate that cannot witness its defect is red either way; the
        point is that the next reader is told to fix the invariant instead of
        raising the cap.
        """
        if len(self.tried) < 2:
            return False
        (s0, v0), (s1, v1) = self.tried[0], self.tried[-1]
        if s1 <= s0 or v0 <= 0:
            return False
        if v1 <= v0:
            return True                  # grew the fixture, got the same or less
        e = self.elasticity
        return e is not None and e < 0.5

    def report(self) -> str:
        # 4 significant digits, so the same formatter reads correctly for a
        # gate measured in milliseconds (1086) and one measured in seconds
        # (0.4673) — `:.0f` printed the latter as "0".
        trail = ", ".join(f"size {size} -> {value:.4g} {self.unit}"
                          for size, value in self.tried)
        if self.saturated:
            (s0, v0), (s1, v1) = self.tried[0], self.tried[-1]
            e = self.elasticity
            return (
                f"{self.name}: THE GROWTH AXIS SATURATED — growing the fixture "
                f"{s1 / s0:.1f}x moved the measurement {v1 / v0:.2f}x "
                f"(elasticity {e:.2f}; a sound axis reads ~1.0 or above) "
                f"[{trail}], cap {self.max_size}. This is NOT a fast machine "
                f"and RAISING THE CAP WILL NOT HELP: something bounds the "
                f"workload — a cap like CORR_OPEN_OBJECTS_MAX, a threshold the "
                f"grown fixture crossed so it stopped being the shape under "
                f"test, or a defect that is simply gone. Make this gate's "
                f"invariant machine-independent (a COUNT, as "
                f"test_loop_yield_resilience did on 2026-09-12) and retire it "
                f"from this module. Do NOT widen a tolerance.")
        return (
            f"{self.name}: the workload did not reach the adequacy floor on "
            f"this machine — {self.value:.4g} {self.unit} against a floor of "
            f"{self.floor:.4g} {self.unit}, after {len(self.tried)} calibration "
            f"attempt(s) [{trail}], cap {self.max_size}. The fixture is sized "
            f"to the MACHINE (timing_gate.py), so this is not a slow-runner "
            f"flake: either this machine outran the size cap — raise it — or "
            f"the behaviour being witnessed is gone and the gate should be "
            f"retired with it.")


def calibrated_stall(
    measure: Callable[[int], float],
    *,
    size: int,
    floor: float,
    max_size: int,
    name: str,
    unit: str = "ms",
    target_mult: float = 2.0,
    grow_cap: float = 4.0,
    attempts: int = 3,
) -> StallGate:
    """Measure the mutant, growing the fixture until it witnesses the defect.

    `measure(size)` runs ONE mutant leg at that fixture size and returns the
    quantity the gate is about (a worst stall, a drained count — anything where
    "bigger fixture => bigger number" holds). It is called at least once and at
    most `attempts` times; the caller keeps whatever it built, so the fixed leg
    can be run against the SAME size (`StallGate.size`).

    `floor` is the adequacy threshold the caller's own assertion needs. `target`
    (`target_mult` x floor) is what a re-sized run aims for, so a second attempt
    is not itself marginal. `grow_cap` bounds one step and `max_size` the total,
    which is what stops a mis-measured probe from building an enormous fixture.
    """
    if size <= 0 or max_size < size:
        raise ValueError(f"{name}: size {size} / max_size {max_size} invalid")
    if attempts < 1:
        raise ValueError(f"{name}: attempts must be >= 1")

    target = floor * target_mult
    tried: list[tuple[int, float]] = []
    value = measure(size)
    tried.append((size, value))

    while value < floor and len(tried) < attempts and size < max_size:
        # Linear cost model, floored so a near-zero (or zero) measurement asks
        # for `grow_cap` rather than for infinity.
        want = size * target / max(value, floor / 32.0)
        grown = int(min(float(max_size), math.ceil(min(want, size * grow_cap))))
        if grown <= size:
            break
        size = grown
        value = measure(size)
        tried.append((size, value))

    return StallGate(name=name, floor=floor, target=target, unit=unit,
                     size=size, value=value, tried=tuple(tried),
                     max_size=max_size)
