"""Tracker 166 — bounded cohorts must change WHEN work happens, never WHAT.

The defect is a positive feedback loop: a slow engine transaction lets more
signals accumulate, the next cohort is larger, `new x new` pairing is quadratic
in cohort size, so the next transaction is slower again. The fix bounds the new
work admitted per transaction. It must not bound what the engine may reason
over — tracker 165's ~516.5 s horizon is a correctness contract.

The whole design rests on edge admission being PAIR-LOCAL: `resolve_grounding`
reads only the two nodes plus embedded context, so a pair's verdict cannot
depend on which other pairs were scored beside it. These tests hold that claim
to account, and hold the two things a wrong optimisation would break —
`new x old` and cross-cohort `B2 x B1` coverage.
"""
from __future__ import annotations

import pytest

from engine import EngineConfig, build_edges, build_nodes
from signals import EntityType, ModalityClass
from test_engine import sig

CFG = EngineConfig()


def _window(devices: int = 6, kinds: int = 5, spacing: float = 10.0):
    sigs = []
    for d in range(devices):
        for k in range(kinds):
            sigs.append(sig(f"kind{k}", EntityType.INTERFACE, f"leaf{d}:Gi0/1",
                            observer=f"leaf{d}", offset_s=k * spacing,
                            modality=(ModalityClass.CONTROL_PLANE if k % 2
                                      else ModalityClass.DEVICE_TELEMETRY)))
    return build_nodes(tuple(sigs))


def _full(nodes):
    edges, gaps = build_edges(nodes, (), CFG)
    return {(e.from_node, e.to_node): e for e in edges}, gaps


def _streamed(nodes, n_cohorts):
    """Evaluate in arrival order, cohort by cohort, the way the scheduler will.

    Cohort K's transaction sees nodes[0 : end_of_K] and evaluates only pairs
    touching cohort K — exactly the streaming shape, where earlier cohorts are
    already retained and later ones do not exist yet.
    """
    size = (len(nodes) + n_cohorts - 1) // n_cohorts
    admitted: dict = {}
    for start in range(0, len(nodes), size):
        end = min(start + size, len(nodes))
        visible = nodes[:end]
        cohort = frozenset(range(start, end))
        edges, _ = build_edges(visible, (), CFG, cohort=cohort)
        for e in edges:
            admitted[(e.from_node, e.to_node)] = e
    return admitted


# ── the core equivalence ─────────────────────────────────────────────────────

@pytest.mark.parametrize("n_cohorts", [2, 3, 4, 5, 10])
def test_streamed_cohorts_admit_exactly_the_full_window_edge_set(n_cohorts):
    nodes = _window()
    full, _ = _full(nodes)
    streamed = _streamed(nodes, n_cohorts)
    assert set(streamed) == set(full), (
        f"{n_cohorts} cohorts admitted a different edge SET than one batch")


@pytest.mark.parametrize("n_cohorts", [2, 3, 5])
def test_edge_ATTRIBUTES_are_identical_not_merely_the_pairs(n_cohorts):
    """Same pair is not enough — weight, temporal term, grounding and direction
    must match, or RCA ranking would differ downstream."""
    nodes = _window()
    full, _ = _full(nodes)
    streamed = _streamed(nodes, n_cohorts)
    for key, e in full.items():
        s = streamed[key]
        assert (s.weight, s.w_temporal, s.w_topo, s.w_reinforce) == \
               (e.weight, e.w_temporal, e.w_topo, e.w_reinforce)
        assert (s.grounding.kind, s.grounding.ref) == (e.grounding.kind, e.grounding.ref)
        assert (s.direction_conf, s.direction_basis) == (e.direction_conf, e.direction_basis)


def test_every_candidate_pair_is_evaluated_exactly_once_across_cohorts():
    """No pair may be scored twice (wasted work) or zero times (lost edge)."""
    nodes = _window()
    size = 7
    seen: list[tuple[int, int]] = []
    for start in range(0, len(nodes), size):
        end = min(start + size, len(nodes))
        sink: dict = {}
        build_edges(nodes[:end], (), CFG, cohort=frozenset(range(start, end)),
                    work_sink=sink)
        seen.append((sink["pairs_candidate"], end))
    total_evaluated = sum(c for c, _ in seen)
    sink_full: dict = {}
    build_edges(nodes, (), CFG, work_sink=sink_full)
    assert total_evaluated == sink_full["pairs_candidate"], (
        f"cohorts evaluated {total_evaluated} candidate pairs, one batch "
        f"evaluated {sink_full['pairs_candidate']} — pairs are being dropped "
        "or duplicated")


# ── the two things a wrong optimisation would break ──────────────────────────

def test_new_x_old_pairs_are_still_evaluated():
    """A new signal must still be scored against RETAINED evidence. Dropping
    this is how an 'optimisation' silently undoes tracker 165."""
    nodes = _window(devices=1, kinds=6, spacing=5.0)
    last = len(nodes) - 1
    sink: dict = {}
    build_edges(nodes, (), CFG, cohort=frozenset({last}), work_sink=sink)
    assert sink["pairs_candidate"] == last, (
        "the newest node must pair with every earlier retained node")


def test_cross_cohort_B2_x_B1_pairs_are_covered():
    """Phase 3's explicit requirement: cohort B2 must be scored against B1, not
    only against itself and the pre-existing window."""
    # ONE device, so every pair grounds by containment and the split falls
    # INSIDE the grounded set. Splitting across devices produces no
    # cross-cohort edges at all (different devices do not ground), which made
    # an earlier version of this test vacuously pass on an empty set.
    nodes = _window(devices=1, kinds=8, spacing=5.0)
    half = len(nodes) // 2
    b1 = frozenset(range(half))
    b2 = frozenset(range(half, len(nodes)))
    e2, _ = build_edges(nodes, (), CFG, cohort=b2)
    cross = {(e.from_node, e.to_node) for e in e2
             if (nodes.index(next(n for n in nodes if n.key == e.from_node)) in b1)
             != (nodes.index(next(n for n in nodes if n.key == e.to_node)) in b1)}
    full, _ = _full(nodes)
    expected_cross = {
        (a, b) for (a, b) in full
        if (nodes.index(next(n for n in nodes if n.key == a)) in b1)
        != (nodes.index(next(n for n in nodes if n.key == b)) in b1)}
    assert cross == expected_cross, "cross-cohort pairs were not evaluated"
    assert expected_cross, "fixture produced no cross-cohort edges to check"


def test_a_cohort_covering_everything_is_the_full_window():
    nodes = _window()
    full, _ = _full(nodes)
    all_idx = frozenset(range(len(nodes)))
    edges, _ = build_edges(nodes, (), CFG, cohort=all_idx)
    assert {(e.from_node, e.to_node) for e in edges} == set(full)


def test_an_empty_cohort_admits_nothing():
    """Negative control: the restriction must actually restrict."""
    nodes = _window()
    edges, _ = build_edges(nodes, (), CFG, cohort=frozenset())
    assert edges == ()


def test_no_cohort_means_evaluate_everything():
    """Default behaviour is unchanged — cohort=None is the full-window path."""
    nodes = _window()
    a, ga = build_edges(nodes, (), CFG)
    b, gb = build_edges(nodes, (), CFG, cohort=None)
    assert a == b and ga == gb


# ── the work actually shrinks ────────────────────────────────────────────────

def test_bounding_caps_PER_TRANSACTION_work_and_leaves_the_total_alone():
    """What bounding actually buys — and what it does not.

    I expected splitting to reduce TOTAL pairs. It does not, and the test that
    claimed so was wrong: each candidate pair is evaluated exactly once either
    way, so the totals match by construction (see the exactly-once test above).

    What bounding does is cap the work of any SINGLE transaction. That is the
    fix for the feedback loop — a slow transaction can no longer make the next
    one arbitrarily larger — but it is not, by itself, a throughput improvement,
    and it should not be sold as one.
    """
    nodes = _window(devices=8, kinds=6, spacing=5.0)
    one: dict = {}
    build_edges(nodes, (), CFG, cohort=frozenset(range(len(nodes))), work_sink=one)

    size = len(nodes) // 4
    per_transaction, split_total = [], 0
    for start in range(0, len(nodes), size):
        end = min(start + size, len(nodes))
        sink: dict = {}
        build_edges(nodes[:end], (), CFG, cohort=frozenset(range(start, end)),
                    work_sink=sink)
        per_transaction.append(sink["pairs_candidate"])
        split_total += sink["pairs_candidate"]

    assert split_total == one["pairs_candidate"], (
        "total work must be identical — every pair is scored exactly once")
    assert max(per_transaction) < one["pairs_candidate"] / 2, (
        f"no single transaction may approach the unbounded cost: "
        f"worst {max(per_transaction)} vs {one['pairs_candidate']}")


def test_gap_hints_are_scoped_to_what_the_transaction_evaluated():
    """gap_hints changes meaning under a cohort, deliberately and visibly.

    The window-global count is not computable without doing the work the cohort
    exists to avoid, so a bounded transaction reports ungrounded pairs among the
    candidates it actually scored. This is confined to a diagnostic: the
    archive-slice contract already names the window-global gap-hint count as the
    one value that legitimately differs on replay.
    """
    nodes = _window()
    _, gaps_full = _full(nodes)
    sink: dict = {}
    _, gaps_cohort = build_edges(nodes, (), CFG, cohort=frozenset({0}), work_sink=sink)
    assert gaps_cohort <= sink["pairs_candidate"], (
        "a per-transaction gap count cannot exceed the pairs it evaluated")
    assert gaps_cohort != gaps_full, "the two scopes should be distinguishable here"
    # full-window mode is unchanged
    _, gaps_none = build_edges(nodes, (), CFG, cohort=None)
    assert gaps_none == gaps_full


# ── carried edges: components must see settled history ───────────────────────
#
# A bounded transaction only SCORES pairs touching its cohort, so the edges it
# returns are a subset. Components are built from the union with edges admitted
# in earlier transactions — otherwise objects would fragment every time the
# cohort boundary fell inside one. `carried_edges` is that union, and these
# tests exist because mutating it away survived every test above.

from catalog import builtin_catalog
from engine import run_window

CAT = builtin_catalog()


def _tenant_sigs(kinds: int, spacing: float = 5.0):
    return tuple(sig(f"kind{k}", EntityType.INTERFACE, "leaf1:Gi0/1",
                     observer="leaf1", offset_s=k * spacing,
                     modality=(ModalityClass.CONTROL_PLANE if k % 2
                               else ModalityClass.DEVICE_TELEMETRY))
                 for k in range(kinds))


def test_carried_edges_are_unioned_into_the_result():
    sigs = _tenant_sigs(6)
    nodes = build_nodes(sigs)
    keys = [n.key for n in nodes]
    early, _ = build_edges(nodes[:3], (), CFG)
    assert early, "fixture must admit some early edges"

    # a later transaction whose cohort is only the tail
    snaps_without = run_window(sigs, CAT, (), CFG,
                               cohort_keys=frozenset(keys[3:]))
    snaps_with = run_window(sigs, CAT, (), CFG,
                            cohort_keys=frozenset(keys[3:]),
                            carried_edges=early)
    edges_without = sum(len(s.edges) for s in snaps_without)
    edges_with = sum(len(s.edges) for s in snaps_with)
    assert edges_with > edges_without, (
        "carrying settled edges must restore them to object formation; "
        f"{edges_with} vs {edges_without}")


def test_carrying_everything_reproduces_the_full_window_objects():
    """The equivalence that matters: cohort + carried == one batch."""
    sigs = _tenant_sigs(6)
    nodes = build_nodes(sigs)
    keys = [n.key for n in nodes]
    full = run_window(sigs, CAT, (), CFG)
    early, _ = build_edges(nodes[:3], (), CFG)
    split = run_window(sigs, CAT, (), CFG,
                       cohort_keys=frozenset(keys[3:]), carried_edges=early)
    assert [s.correlation_id for s in full] == [s.correlation_id for s in split]
    assert [sorted(n.key for n in s.nodes) for s in full] == \
           [sorted(n.key for n in s.nodes) for s in split]
    assert [len(s.edges) for s in full] == [len(s.edges) for s in split]
    assert [s.ranking.verdict_tier for s in full] == \
           [s.ranking.verdict_tier for s in split]
    assert [s.content_hash() for s in full] == [s.content_hash() for s in split], (
        "the replay content hash must match a full-window run")


def test_carried_edges_for_EXPIRED_nodes_are_dropped():
    """Tracker 165 expires evidence on stream time. A carried edge whose
    endpoint has since left the window must not resurrect it — that would
    reintroduce evidence the retention contract deliberately released."""
    sigs = _tenant_sigs(6)
    nodes = build_nodes(sigs)
    early, _ = build_edges(nodes, (), CFG)
    assert early

    # the window has moved on: only the last two nodes remain retained
    survivors = sigs[4:]
    live_keys = {n.key for n in build_nodes(survivors)}
    snaps = run_window(survivors, CAT, (), CFG,
                       cohort_keys=live_keys, carried_edges=early)
    for s in snaps:
        for e in s.edges:
            assert e.from_node in live_keys and e.to_node in live_keys, (
                f"edge {e.from_node}->{e.to_node} references an evicted node")


def test_a_freshly_scored_edge_wins_over_a_carried_one():
    """If this transaction re-scored a pair, its verdict is the current one —
    a stale carried copy must not shadow it."""
    sigs = _tenant_sigs(4)
    nodes = build_nodes(sigs)
    keys = [n.key for n in nodes]
    fresh, _ = build_edges(nodes, (), CFG)
    assert fresh
    stale = tuple(type(e)(**{**{f: getattr(e, f) for f in e.__dataclass_fields__},
                             "weight": 0.99}) for e in fresh)
    snaps = run_window(sigs, CAT, (), CFG,
                       cohort_keys=frozenset(keys), carried_edges=stale)
    got = {(e.from_node, e.to_node): e.weight for s in snaps for e in s.edges}
    for e in fresh:
        if (e.from_node, e.to_node) in got:
            assert got[(e.from_node, e.to_node)] == e.weight, (
                "a stale carried edge shadowed a freshly scored one")


def test_candidate_GENERATION_is_bounded_not_just_scoring():
    """The bound has to be inside `_candidate_pairs`, not applied to its output.

    The first implementation generated every pair in the window and filtered
    afterwards. Scoring was bounded, generation was not, and live transactions
    still grew 12s -> 25s -> 54s as the window filled. `_link` is O(bucket^2)
    per index bucket, so the cost tracked the window regardless of the cohort.

    This test pins the work at the point it is created: one cohort member in a
    large bucket must produce a number of candidates proportional to the bucket,
    not to its square.
    """
    from engine import _candidate_pairs

    n = 200
    toks = [frozenset({"shared"}) for _ in range(n)]
    refs = [frozenset() for _ in range(n)]
    from engine import NO_ADJACENCY
    # This fixture exercises COHORT bounding (tracker 166), which is orthogonal to
    # the #168 rank-7 hub cap. A single token shared by all 200 nodes is exactly a
    # hub, so the cap would (correctly) drop the whole mesh and defeat the fixture;
    # pass token_hub_cap=n to disable the cap here and keep the bucket fully
    # connected. The hub cap itself is covered in test_engine_complexity /
    # test_hub_token_cap_stage2.
    unbounded = _candidate_pairs(n, toks, refs, [], [None] * n, NO_ADJACENCY,
                                 None, None, token_hub_cap=n)
    assert len(unbounded) == n * (n - 1) // 2, "fixture must be fully connected"

    one = _candidate_pairs(n, toks, refs, [], [None] * n, NO_ADJACENCY,
                           None, None, frozenset({0}), token_hub_cap=n)
    assert len(one) == n - 1, (
        f"a single cohort member should generate {n - 1} candidates, got {len(one)}")

    ten = _candidate_pairs(n, toks, refs, [], [None] * n, NO_ADJACENCY,
                           None, None, frozenset(range(10)), token_hub_cap=n)
    # 10 members x 199 others, minus the 45 pairs counted twice within the cohort
    assert len(ten) == 10 * (n - 1) - 45
    assert len(ten) < len(unbounded) / 2, "generation must actually be bounded"


def test_cohort_generation_still_covers_every_pair_across_a_partition():
    """Bounding generation must not lose pairs: the union over a partition is
    still the full candidate set."""
    from engine import NO_ADJACENCY, _candidate_pairs

    n = 60
    toks = [frozenset({f"g{i % 5}"}) for i in range(n)]
    refs = [frozenset() for _ in range(n)]
    full = _candidate_pairs(n, toks, refs, [], [None] * n, NO_ADJACENCY, None, None)
    union: set = set()
    for start in range(0, n, 12):
        cohort = frozenset(range(start, min(start + 12, n)))
        union |= _candidate_pairs(n, toks, refs, [], [None] * n, NO_ADJACENCY,
                                  None, None, cohort)
    assert union == full, "partitioned generation lost candidate pairs"
