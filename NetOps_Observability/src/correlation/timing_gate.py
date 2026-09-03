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
grow the MUTANT's stall without moving the shape the defect lives in:

  * `test_p2_evidence_batching::B12` grows SIGNALS PER NODE, never the node
    count: `_snap_elements` (nodes + edges) must stay under
    `CORR_OFFLOAD_MIN_ELEMENTS` or the mutant sizer starts offloading and the
    defect evaporates — measured, at 2,375 nodes the "mutant" stall fell from
    2,418 ms to 339 ms because it was no longer a mutant at all.
  * `test_loop_yield_resilience` grows DEVICES at a fixed 1 s spacing, with the
    retention horizon lifted off the fixture, so one device still folds to the
    same objects.
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

    def report(self) -> str:
        # 4 significant digits, so the same formatter reads correctly for a
        # gate measured in milliseconds (1086) and one measured in seconds
        # (0.4673) — `:.0f` printed the latter as "0".
        trail = ", ".join(f"size {size} -> {value:.4g} {self.unit}"
                          for size, value in self.tried)
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
