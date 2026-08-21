"""Tracker 166 phase 2 — measure the re-derivation before optimising it.

The incremental design turns on one number: what fraction of the candidate
pairs a cycle grounds and scores involve only signals that were already present
and unchanged last cycle. Those are pure recomputation.

`new x old` pairs are explicitly NOT waste, and that distinction is the whole
correctness constraint on tracker 166: a new signal may legitimately attach to
retained evidence anywhere inside the engine's temporal reach, which is exactly
the evidence tracker 165 exists to keep available. An "optimisation" that only
compared new signals with each other would silently destroy those attachments.
"""
from __future__ import annotations

from engine import EngineConfig, build_edges, build_nodes
from signals import EntityType
from test_engine import sig

CFG = EngineConfig()


def _window(n_old: int, n_new: int, old_at: float = 0.0, new_at: float = 30.0):
    """`n_old` signals at `old_at`, `n_new` at `new_at`, all on one device so
    every pair is a genuine containment candidate."""
    sigs = [sig(f"kind_o{i}", EntityType.INTERFACE, "leaf1:Gi0/1",
                observer="leaf1", offset_s=old_at) for i in range(n_old)]
    sigs += [sig(f"kind_n{i}", EntityType.INTERFACE, "leaf1:Gi0/1",
                 observer="leaf1", offset_s=new_at) for i in range(n_new)]
    return build_nodes(tuple(sigs))


def _work(nodes, since_ts):
    sink: dict = {}
    build_edges(nodes, (), CFG, since_ts=since_ts, work_sink=sink)
    return sink


def _cut(offset_s: float) -> float:
    """A since_ts between the old and new cohorts, in the same frame `sig` uses."""
    from datetime import timedelta

    from test_engine import T0
    return (T0 + timedelta(seconds=offset_s)).timestamp()


# ── the accounting is real ───────────────────────────────────────────────────

def test_every_candidate_pair_is_classified_exactly_once():
    w = _work(_window(6, 3), _cut(15))
    assert w["pairs_old_old"] + w["pairs_new_old"] + w["pairs_new_new"] == w["pairs_candidate"]


def test_old_and_new_cohorts_are_identified():
    w = _work(_window(6, 3), _cut(15))
    assert w["nodes"] == 9
    assert w["nodes_new"] == 3, "only the post-cutoff cohort is new"


def test_all_old_window_is_all_redundant():
    """Nothing arrived since the last cycle, so every pair the cycle grounds is
    re-derivation of an unchanged relationship. This is the shape the engine is
    in when the window is large and the arrival rate is modest."""
    w = _work(_window(8, 0), _cut(15))
    assert w["pairs_new_old"] == w["pairs_new_new"] == 0
    assert w["pairs_old_old"] == w["pairs_candidate"] > 0


def test_all_new_window_is_no_redundancy():
    w = _work(_window(0, 8), _cut(15))
    assert w["pairs_old_old"] == 0
    assert w["pairs_new_new"] == w["pairs_candidate"] > 0


def test_new_old_pairs_are_counted_as_REQUIRED_not_redundant():
    """The correctness constraint. One new signal against many retained ones
    produces work that MUST still happen — tracker 165 keeps that evidence
    precisely so it can attach."""
    w = _work(_window(10, 1), _cut(15))
    assert w["pairs_new_old"] == 10, "each retained node must still pair with the new one"
    assert w["pairs_new_new"] == 0
    assert w["pairs_old_old"] == 45, "the 10 retained nodes still re-pair with each other"


def test_redundancy_grows_quadratically_with_retained_state():
    """Why this is the bottleneck: the required work grows with ARRIVALS, the
    redundant work grows with the square of what is RETAINED."""
    ratios = []
    for n_old in (5, 10, 20, 40):
        w = _work(_window(n_old, 1), _cut(15))
        assert w["pairs_new_old"] == n_old                 # linear in retained
        assert w["pairs_old_old"] == n_old * (n_old - 1) // 2
        ratios.append(w["pairs_old_old"] / w["pairs_candidate"])
    assert ratios == sorted(ratios), f"redundant share must rise with N: {ratios}"
    assert ratios[-1] > 0.9, "at 40 retained vs 1 new, >90% of the work is re-derivation"


def test_no_cutoff_means_everything_counts_as_new():
    """Cold start: with no previous cycle there is no 'unchanged' state, so
    nothing may be treated as already-derived."""
    w = _work(_window(5, 5), None)
    assert w["nodes_new"] == 0, "without a cutoff, freshness is unknown"
    assert w["pairs_old_old"] == w["pairs_candidate"], (
        "unknown freshness must be accounted conservatively, not skipped")


def test_the_sink_is_optional_and_costs_nothing_when_absent():
    nodes = _window(6, 3)
    e1, g1 = build_edges(nodes, (), CFG)
    e2, g2 = build_edges(nodes, (), CFG, since_ts=_cut(15), work_sink={})
    assert len(e1) == len(e2) and g1 == g2, (
        "work accounting must not change edges or gap hints")


def test_candidate_pruning_is_already_in_effect():
    """Context for the optimisation: the waste is NOT naive O(N^2) over the
    window — `_candidate_pairs` is already a sound superset. Two unrelated
    devices produce no candidate at all, so the redundancy that remains is
    re-grounding the SAME candidate pairs every cycle."""
    nodes = build_nodes((
        sig("if_util_high", EntityType.INTERFACE, "leaf1:Gi0/1", observer="leaf1"),
        sig("if_util_high", EntityType.INTERFACE, "leaf9:Gi0/9", observer="leaf9"),
    ))
    w = _work(nodes, _cut(-1))
    assert w["pairs_naive"] == 1
    assert w["pairs_candidate"] == 0, "ungrounded pair must be pruned before scoring"
