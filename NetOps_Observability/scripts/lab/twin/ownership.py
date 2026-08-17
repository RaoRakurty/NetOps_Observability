"""Ownership-movement correctness harness (tracker 155, GA gate defect class 4).

WHAT THIS EXISTS TO MEASURE
---------------------------
`OPEN_OBJECTS` (src/correlation/main.py:910) is a plain in-process dict with NO
rehydration path — no restore, no checkpoint, no transfer. `on_partitions_revoked`
flushes and commits DURABLE output but evicts no window state;
`on_partitions_assigned` records ownership and reconstructs nothing. So whenever
partitions move between members, the acquiring replica starts with an EMPTY
window for the tenants it just took, and the previous owner holds state for
tenants it no longer serves. Evidence accumulated across the move is lost
silently: nothing errors, and lag returns to zero exactly as on a healthy move.

This is NOT confined to a partition-count increase. `fa69894b` (tenant-keyed
co-partitioning) made rebalances routine, so it fires on any ordinary restart,
scale, crash, deploy or broker disturbance in any deployment running N>1.

THE ANTI-VACUITY RULE (read before changing anything here)
-----------------------------------------------------------
A run that moves partitions while the in-flight window is EMPTY proves nothing:
there is no carried-over state to lose, so accuracy trivially matches and the
harness would report PASS for a defect it never exercised. That is exactly the
failure class this wave catalogued five times over (promtool's empty result set
reported as SUCCESS; `-dryRun` "validated" meaning "parses"; a scorer recording
a LOST query as a MISS; a grep counting a field NAME as a set predicate). It
also already bit this programme once: the P1 giant-object burst proved nothing
about its own hypothesis because the ladder's cleanup had emptied the tenant
registry, so no correlation objects could form.

Therefore this harness has THREE outcomes, not two:

    PASS     the move happened WITH in-flight state present, and RCA
             ground-truth accuracy did not regress.
    FAIL     accuracy regressed, or a tenant observed another tenant's state.
    INVALID  the precondition was not met (no in-flight state at move time, or
             partitions did not actually move). NOT a pass. The run measured
             nothing and must be re-run.

`verdict()` below is pure and unit-tested, deliberately separated from all stack
I/O, so the decision logic can be proven — including proven to FAIL — without a
live stack. See tests/test_ownership.py, which injects a synthetic regression
and asserts this harness detects it.
"""
from __future__ import annotations

from dataclasses import dataclass, field

# Verdicts
PASS = "PASS"
FAIL = "FAIL"
INVALID = "INVALID"

# The six scenarios GA gate defect class 4 requires. `partition_raise` is the
# one the original drain note covered; the other five are ORDINARY ownership
# movement, which is the part that was under-scoped until 2026-08-17.
MOVES = (
    "restart_one",       # restart a single replica under --scale N>1
    "scale_up",          # N -> N+1
    "scale_down",        # N -> N-1
    "rolling_restart",   # every replica, one at a time
    "rapid_rebalance",   # repeated joins/leaves without settling
    "partition_raise",   # BUS_PARTITIONS 2 -> 4 with the documented drain
)


@dataclass(frozen=True)
class Preconditions:
    """Captured at the instant of the move, before anything is disturbed.

    `open_objects` is the sum across replicas of in-flight correlation objects
    (healthz consumer/engine_v2 `open_objects`). `assignment_before/after` are
    the per-replica owned-partition maps; if they are equal, nothing moved and
    the run is INVALID no matter how good the accuracy looks.
    """
    open_objects: int
    assignment_before: dict
    assignment_after: dict
    tenants_in_flight: int = 0

    @property
    def had_state(self) -> bool:
        return self.open_objects > 0

    @property
    def ownership_moved(self) -> bool:
        return self.assignment_before != self.assignment_after


@dataclass(frozen=True)
class Scores:
    """Twin ground-truth scoring, before and after the move.

    `matched`/`total` come from scorer.score_run. Accuracy is compared as a
    RATIO, not a raw count, because the after-run may legitimately observe a
    different number of stories.
    """
    matched_before: int
    total_before: int
    matched_after: int
    total_after: int

    @staticmethod
    def _ratio(m: int, t: int) -> float:
        return (m / t) if t else 0.0

    @property
    def before(self) -> float:
        return self._ratio(self.matched_before, self.total_before)

    @property
    def after(self) -> float:
        return self._ratio(self.matched_after, self.total_after)

    @property
    def delta(self) -> float:
        return self.after - self.before


@dataclass(frozen=True)
class Verdict:
    outcome: str
    reasons: tuple[str, ...] = field(default_factory=tuple)
    detail: dict = field(default_factory=dict)


def verdict(move: str, pre: Preconditions, scores: Scores,
            isolation_violations: tuple[str, ...] = (),
            tolerance: float = 0.0) -> Verdict:
    """Decide PASS / FAIL / INVALID. Pure — no I/O, no clock, no stack.

    `tolerance` is the permitted accuracy DROP as a ratio (0.0 = none). It
    exists so a future owner can loosen the bar deliberately and visibly; it is
    NOT a knob for making a red run green. Any negative delta beyond it fails.

    Order matters. Isolation is checked FIRST because a cross-tenant leak is a
    §3a violation that no accuracy result can excuse. Preconditions are checked
    BEFORE the accuracy comparison, so a vacuous run can never be reported as a
    pass on the strength of an accuracy number it did not earn.
    """
    if move not in MOVES:
        return Verdict(INVALID, ((f"unknown move {move!r}; expected one of "
                                  f"{', '.join(MOVES)}"),))

    if isolation_violations:
        return Verdict(FAIL, tuple(
            [f"§3a cross-tenant state observed after {move}"]
            + [f"  {v}" for v in isolation_violations]),
            {"delta": scores.delta})

    problems: list[str] = []
    if not pre.had_state:
        problems.append(
            "no in-flight correlation state at move time (open_objects=0) — "
            "nothing could be lost, so this run did not exercise tracker 155")
    if not pre.ownership_moved:
        problems.append(
            "partition assignment identical before and after — ownership did "
            "not actually move")
    if problems:
        return Verdict(INVALID, tuple(problems), {
            "open_objects": pre.open_objects,
            "assignment_before": pre.assignment_before,
            "assignment_after": pre.assignment_after,
        })

    if scores.total_before == 0:
        return Verdict(INVALID, (
            ("baseline scored zero stories — the twin produced no ground "
             "truth to compare against"),), {"scores": scores.__dict__})

    if scores.delta < -tolerance:
        return Verdict(FAIL, (
            (f"RCA ground-truth accuracy regressed across {move}: "
             f"{scores.before:.2%} -> {scores.after:.2%} "
             f"(delta {scores.delta:+.2%}, tolerance {tolerance:.2%})"),
            f"{pre.open_objects} object(s) were in flight when ownership moved",
        ), {"delta": scores.delta, "open_objects": pre.open_objects})

    return Verdict(PASS, (
        (f"accuracy held across {move}: {scores.before:.2%} -> "
         f"{scores.after:.2%} (delta {scores.delta:+.2%})"),
        f"exercised with {pre.open_objects} object(s) in flight",
    ), {"delta": scores.delta, "open_objects": pre.open_objects})


def summarize(results: dict[str, Verdict]) -> dict:
    """Roll the six moves into one gate result.

    An INVALID run does NOT count toward the gate. The gate passes only when
    every required move was exercised AND passed — silence is not success.
    """
    missing = [m for m in MOVES if m not in results]
    invalid = [m for m, v in results.items() if v.outcome == INVALID]
    failed = [m for m, v in results.items() if v.outcome == FAIL]
    passed = [m for m, v in results.items() if v.outcome == PASS]

    if failed:
        gate = FAIL
    elif missing or invalid:
        gate = INVALID
    else:
        gate = PASS

    return {
        "gate": gate,
        "passed": sorted(passed),
        "failed": sorted(failed),
        "invalid": sorted(invalid),
        "not_run": sorted(missing),
        "note": ("GA gate defect class 4 passes only when all six moves are "
                 "exercised and pass; INVALID and not-run both block it."),
    }
