"""Routing (BGP-LS/IGP SPF) direction source (C7.5) — the precedence-3 source, and
the full three-source fusion it completes.

Properties: a computed forwarding pair directs; both-ways (transit) → AMBIGUOUS;
absent → abstain; and in the assembled oracle, a higher-precedence source that
COVERS a pair takes priority while routing fills the pairs the others can't.
"""
from directed_topology import DirectedTopology, Verdict, frozen_oracle
from flow_direction import netflow_direction_source
from path_direction import traceroute_direction_source
from routing_direction import forwarding_pairs, routing_direction_source


def test_forwarding_pair_directs_both_ways_is_ambiguous_absent_abstains():
    fwd = forwarding_pairs([{"from": "core1", "to": "edge1"}])
    s = routing_direction_source(fwd)
    assert s("core1", "edge1").verdict is Verdict.A_UPSTREAM
    assert s("edge1", "core1").verdict is Verdict.B_UPSTREAM
    assert s("core1", "edge1").source == "routing"
    assert abs(s("core1", "edge1").confidence - 0.7) < 1e-9
    # a transit link carrying both ways → ambiguous (never an assumed direction)
    both = routing_direction_source(forwarding_pairs(
        [{"from": "a", "to": "b"}, {"from": "b", "to": "a"}]))
    assert both("a", "b").verdict is Verdict.AMBIGUOUS
    # not in the set → abstain
    assert s("core1", "spine9") is None


def test_forwarding_pairs_drops_incomplete_and_self_rows():
    fwd = forwarding_pairs([
        {"from": "a", "to": "b"},
        {"from": "a", "to": "a"},   # self → dropped
        {"from": "", "to": "b"},    # incomplete → dropped
        {"to": "b"},                # missing from → dropped
    ])
    assert fwd == {("a", "b")}


# ── the three-source fusion (the C7 completion) ─────────────────────────────────

def test_routing_fills_a_pair_the_higher_sources_do_not_cover():
    # traceroute + netflow cover (a,b); routing covers (c,d). The oracle answers each
    # from whichever source covers it — routing extends reach to unprobed/unflowed pairs.
    before = {("a", "b")}                                   # traceroute: a→b
    vol = {("a", "b"): 1000.0, ("b", "a"): 10.0}            # netflow agrees a→b
    fwd = {("c", "d")}                                      # routing only: c→d
    oracle = DirectedTopology(sources=(
        ("traceroute", traceroute_direction_source(before)),
        ("netflow", netflow_direction_source(vol)),
        ("routing", routing_direction_source(fwd)),
    ))
    assert oracle.orient("a", "b").verdict is Verdict.A_UPSTREAM
    assert oracle.orient("a", "b").source == "traceroute"  # highest-precedence covering
    assert oracle.orient("c", "d").verdict is Verdict.A_UPSTREAM
    assert oracle.orient("c", "d").source == "routing"     # only routing covers it
    assert oracle.orient("x", "y").verdict is Verdict.UNKNOWN


def test_routing_conflicting_with_a_higher_source_abstains():
    # traceroute says a→b, routing says b→a: conservative v1 fusion → AMBIGUOUS.
    oracle = DirectedTopology(sources=(
        ("traceroute", traceroute_direction_source({("a", "b")})),
        ("routing", routing_direction_source({("b", "a")})),
    ))
    assert oracle.orient("a", "b").verdict is Verdict.AMBIGUOUS


def test_routing_orientation_round_trips_through_frozen_oracle():
    # provenance survives embedding → replay (source label preserved).
    fwd = {("core1", "edge1")}
    live = DirectedTopology(sources=(("routing", routing_direction_source(fwd)),))
    o = live.orient("core1", "edge1")
    frozen = frozen_oracle([("core1", "edge1", o.verdict.value, o.source)])
    assert frozen.orient("core1", "edge1").verdict is Verdict.A_UPSTREAM
    assert frozen.orient("core1", "edge1").source == "routing"
