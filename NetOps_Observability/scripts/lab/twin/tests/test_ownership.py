# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Tests for the tracker-155 ownership-movement harness.

The point of this file is NOT to show the harness can say PASS. It is to prove
the harness can say FAIL and INVALID — because this wave found five separate
checks that were structurally incapable of reporting bad news, and a correctness
gate that can only go green would be the sixth.

So the load-bearing tests here are:
  * an injected accuracy regression MUST be detected (test_injected_regression_*)
  * an empty in-flight window MUST be INVALID, never PASS (test_vacuous_*)
  * ownership that did not move MUST be INVALID even with perfect accuracy
  * a cross-tenant leak MUST fail regardless of accuracy
  * the roll-up MUST NOT pass on partial coverage
"""
from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from ownership import (
    FAIL,
    INVALID,
    MOVES,
    PASS,
    Preconditions,
    Scores,
    Verdict,
    summarize,
    verdict,
)


def pre(open_objects: int = 3, moved: bool = True) -> Preconditions:
    before = {"correlation-1": [0, 1], "correlation-2": [2, 3]}
    after = ({"correlation-1": [0, 1, 2], "correlation-2": [3]} if moved
             else dict(before))
    return Preconditions(open_objects=open_objects,
                         assignment_before=before, assignment_after=after,
                         tenants_in_flight=2)


def scores(before=(4, 4), after=(4, 4)) -> Scores:
    return Scores(matched_before=before[0], total_before=before[1],
                  matched_after=after[0], total_after=after[1])


# --- the harness must be able to fail -------------------------------------

@pytest.mark.parametrize("move", MOVES)
def test_injected_regression_is_detected_on_every_move(move):
    """Ground truth says 4/4 before and 2/4 after — exactly the shape tracker
    155 predicts when a window is stranded in the previous owner's memory."""
    v = verdict(move, pre(), scores(before=(4, 4), after=(2, 4)))
    assert v.outcome == FAIL, f"{move}: a 50% accuracy drop was not detected"
    assert "regressed" in v.reasons[0]
    assert v.detail["delta"] == pytest.approx(-0.5)


def test_regression_reason_names_the_in_flight_count():
    """A FAIL must say how much state was in flight, or the reader cannot tell
    a real loss from a rounding artefact."""
    v = verdict("restart_one", pre(open_objects=17), scores(after=(3, 4)))
    assert v.outcome == FAIL
    assert any("17 object(s) were in flight" in r for r in v.reasons)


def test_tiny_regression_still_fails_at_zero_tolerance():
    v = verdict("scale_down", pre(), scores(before=(100, 100), after=(99, 100)))
    assert v.outcome == FAIL


def test_tolerance_is_explicit_and_bounded():
    """Tolerance exists so a human can loosen the bar deliberately — it must
    not silently swallow a drop larger than what was asked for."""
    s = scores(before=(10, 10), after=(9, 10))          # -10%
    assert verdict("scale_up", pre(), s, tolerance=0.10).outcome == PASS
    assert verdict("scale_up", pre(), s, tolerance=0.05).outcome == FAIL


# --- the anti-vacuity rule -------------------------------------------------

def test_vacuous_run_with_empty_window_is_invalid_not_pass():
    """THE central guard. Perfect accuracy, but nothing was in flight, so the
    defect was never exercised. Reporting PASS here is the exact failure this
    wave catalogued five times."""
    v = verdict("restart_one", pre(open_objects=0), scores())
    assert v.outcome == INVALID
    assert v.outcome != PASS
    assert "nothing could be lost" in " ".join(v.reasons)


def test_vacuous_run_is_invalid_even_when_accuracy_improves():
    v = verdict("rolling_restart", pre(open_objects=0),
                scores(before=(2, 4), after=(4, 4)))
    assert v.outcome == INVALID


def test_ownership_that_did_not_move_is_invalid():
    """A restart that put every partition back on the same replica exercised
    nothing, however healthy it looked."""
    v = verdict("restart_one", pre(moved=False), scores())
    assert v.outcome == INVALID
    assert "did not actually move" in " ".join(v.reasons)


def test_zero_baseline_stories_is_invalid():
    v = verdict("scale_up", pre(), scores(before=(0, 0), after=(0, 0)))
    assert v.outcome == INVALID
    assert "zero stories" in " ".join(v.reasons)


def test_unknown_move_is_invalid():
    assert verdict("reboot_the_planet", pre(), scores()).outcome == INVALID


# --- isolation outranks accuracy ------------------------------------------

def test_cross_tenant_leak_fails_even_with_perfect_accuracy():
    """§3a is not tradeable against an accuracy number."""
    v = verdict("scale_down", pre(), scores(before=(4, 4), after=(4, 4)),
                isolation_violations=("tenant-b object cites tenant-a device",))
    assert v.outcome == FAIL
    assert "cross-tenant" in v.reasons[0]


def test_isolation_is_checked_before_the_precondition():
    """A leak must be reported as FAIL, not masked as INVALID, even when the
    run was otherwise vacuous — a leak observed is a leak."""
    v = verdict("restart_one", pre(open_objects=0), scores(),
                isolation_violations=("cross-tenant evidence",))
    assert v.outcome == FAIL


# --- the happy path, last --------------------------------------------------

def test_pass_requires_both_state_and_movement():
    v = verdict("partition_raise", pre(open_objects=5), scores())
    assert v.outcome == PASS
    assert "exercised with 5 object(s)" in " ".join(v.reasons)


# --- the roll-up cannot pass on partial coverage ---------------------------

def test_gate_needs_every_move_exercised():
    partial = {m: Verdict(PASS) for m in MOVES[:3]}
    out = summarize(partial)
    assert out["gate"] == INVALID
    assert set(out["not_run"]) == set(MOVES[3:])


def test_gate_invalid_when_any_move_was_vacuous():
    res = {m: Verdict(PASS) for m in MOVES}
    res["rapid_rebalance"] = Verdict(INVALID)
    assert summarize(res)["gate"] == INVALID


def test_gate_fails_if_any_move_failed():
    res = {m: Verdict(PASS) for m in MOVES}
    res["scale_down"] = Verdict(FAIL)
    assert summarize(res)["gate"] == FAIL


def test_gate_passes_only_on_full_green():
    res = {m: Verdict(PASS) for m in MOVES}
    out = summarize(res)
    assert out["gate"] == PASS
    assert out["not_run"] == [] and out["invalid"] == [] and out["failed"] == []


# ==========================================================================
# §3/§4 — the tracked-story contract. open_objects>0 is not enough.
# ==========================================================================

from ownership import StoryProbe, story_preconditions


def good_story(**kw) -> StoryProbe:
    base = {
        "story_id": "twin-story-7", "tenant": "acme", "partition": 3,
        "owner_before": "cid-a", "owner_after": "cid-b",
        "open_object_id": "corr-abc", "resolved_before": False,
        "expected_rca": "sig.ent.wan.dx-circuit-flap",
        "final_rca": "sig.ent.wan.dx-circuit-flap",
        "evidence_a": 5, "evidence_b": 4, "evidence_b_consumed": 4,
        "evidence_query_ok": True, "tenant_proven": True, "executed": True,
        "duplicate_rca": 0,
    }
    base.update(kw)
    return StoryProbe(**base)


@pytest.mark.parametrize("field,value,needle", [
    ("executed", False, "was not executed"),
    ("evidence_query_ok", False, "evidence query FAILED"),
    ("tenant_proven", False, "tenant ownership"),
    ("open_object_id", "", "no OPEN_OBJECT"),
    ("resolved_before", True, "ALREADY RESOLVED"),
    ("expected_rca", "", "no recorded ground truth"),
    ("evidence_a", 0, "no pre-move evidence"),
    ("evidence_b", 0, "no post-move evidence"),
    ("evidence_b_consumed", 0, "NONE was consumed"),
    ("partition", -1, "never identified"),
])
def test_every_anti_vacuity_condition_yields_invalid(field, value, needle):
    """§4: each of these must be INVALID — never PASS, never FAIL."""
    v = verdict("restart_one", pre(), scores(), story=good_story(**{field: value}))
    assert v.outcome == INVALID, f"{field}={value!r} did not invalidate"
    assert needle in " ".join(v.reasons)


def test_story_partition_must_actually_change_owner():
    v = verdict("scale_up", pre(),
                scores(), story=good_story(owner_after="cid-a"))
    assert v.outcome == INVALID
    assert "did not change owner" in " ".join(v.reasons)


def test_unfinished_story_that_completes_correctly_passes():
    v = verdict("restart_one", pre(), scores(), story=good_story())
    assert v.outcome == PASS


def test_rca_changing_across_the_move_is_a_fail():
    """The whole gate: the story must survive ownership movement intact."""
    v = verdict("scale_down", pre(), scores(),
                story=good_story(final_rca="sig.ent.access.fhrp-failover"))
    assert v.outcome == FAIL
    assert "changed across" in v.reasons[0]


def test_duplicate_rca_from_ownership_movement_is_a_fail():
    v = verdict("rolling_restart", pre(), scores(),
                story=good_story(duplicate_rca=1))
    assert v.outcome == FAIL
    assert "duplicate RCA" in v.reasons[0]


def test_story_precondition_outranks_a_healthy_accuracy_number():
    """A perfect score must not rescue a vacuous run."""
    v = verdict("restart_one", pre(open_objects=99),
                scores(before=(4, 4), after=(4, 4)),
                story=good_story(resolved_before=True))
    assert v.outcome == INVALID


def test_isolation_still_outranks_the_story_contract():
    v = verdict("restart_one", pre(), scores(), story=good_story(),
                isolation_violations=("tenant-b saw tenant-a evidence",))
    assert v.outcome == FAIL
    assert "cross-tenant" in v.reasons[0]


def test_story_preconditions_reports_every_problem_not_just_the_first():
    ok, reasons = story_preconditions(
        good_story(open_object_id="", expected_rca="", evidence_b=0))
    assert ok is False
    assert len(reasons) >= 3


def test_legacy_callers_without_a_story_still_work():
    """Backward compatibility: the coarse precondition remains the floor."""
    assert verdict("restart_one", pre(), scores()).outcome == PASS
    assert verdict("restart_one", pre(open_objects=0), scores()).outcome == INVALID
