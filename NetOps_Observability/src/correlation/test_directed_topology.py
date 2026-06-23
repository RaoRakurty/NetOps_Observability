"""DirectedTopology oracle (C7) + its integration as causal-direction vote #2."""
from datetime import datetime, timedelta, timezone

from directed_topology import DirectedTopology, Orientation, Verdict
from engine import EngineConfig, build_edges, build_nodes
from signals import EntityType, ModalityClass, Observer, ObserverType, Severity, Signal, Source

T0 = datetime(2026, 6, 23, 9, 0, 0, tzinfo=timezone.utc)


def _src(mapping):
    """A test direction source: ordered-pair (a,b) → Orientation per `mapping`."""
    def fn(a, b):
        return mapping.get((a, b))
    return fn


# ── oracle fusion / abstention ────────────────────────────────────────────────
def test_oracle_unknown_without_sources():
    assert DirectedTopology().orient("leaf1", "spine1").verdict is Verdict.UNKNOWN


def test_oracle_unknown_on_degenerate_input():
    d = DirectedTopology((("s", _src({("leaf1", "spine1"): Orientation(Verdict.A_UPSTREAM)})),))
    assert d.orient("leaf1", "leaf1").verdict is Verdict.UNKNOWN  # same device
    assert d.orient(None, "spine1").verdict is Verdict.UNKNOWN
    assert d.orient("leaf1", "spine2").verdict is Verdict.UNKNOWN  # not covered


def test_oracle_single_source_orients():
    d = DirectedTopology((("flow", _src({("leaf1", "spine1"): Orientation(Verdict.A_UPSTREAM, 0.8, "flow")})),))
    o = d.orient("leaf1", "spine1")
    assert o.verdict is Verdict.A_UPSTREAM and o.source == "flow"


def test_oracle_agreeing_sources_take_highest_precedence():
    d = DirectedTopology((
        ("trace", _src({("leaf1", "spine1"): Orientation(Verdict.A_UPSTREAM, 0.9, "trace")})),
        ("flow", _src({("leaf1", "spine1"): Orientation(Verdict.A_UPSTREAM, 0.7, "flow")})),
    ))
    assert d.orient("leaf1", "spine1").source == "trace"  # first/highest-precedence


def test_oracle_conflicting_sources_abstain():
    d = DirectedTopology((
        ("trace", _src({("leaf1", "spine1"): Orientation(Verdict.A_UPSTREAM, 0.9, "trace")})),
        ("flow", _src({("leaf1", "spine1"): Orientation(Verdict.B_UPSTREAM, 0.7, "flow")})),
    ))
    assert d.orient("leaf1", "spine1").verdict is Verdict.AMBIGUOUS  # never pick a side on conflict


# ── the C7 win: same-layer fabric pair gets DIRECTED once oriented ─────────────
def _dev_sig(kind, dev, off):
    return Signal(
        tenant_id="", ts=T0 + timedelta(seconds=off), source=Source.SYSLOG, kind=kind,
        observer=Observer(observer_id=dev, observer_type=ObserverType.DEVICE),
        modality_class=ModalityClass.CONTROL_PLANE, entity_type=EntityType.DEVICE,
        entity_id=dev, severity=Severity.HIGH, native_id=f"{dev}|{kind}|{off}",
        entity_tokens=(dev, "fab"),  # shared 'fab' token → containment grounding
        attrs={"onset_uncertainty_s": 1.0},
    )


def _fabric_pair():
    # Two SAME-LAYER devices (both DEVICE entity), clear onset (leaf1 then spine1),
    # grounded via the shared 'fab' token. Layer vote abstains (equal layer) → before
    # C7 only onset votes (1 of 2) → direction NEVER claimed.
    return build_nodes((_dev_sig("isis_adjacency_change", "leaf1", 0),
                        _dev_sig("isis_adjacency_change", "spine1", 30)))


def test_same_layer_pair_undirected_without_oracle():
    edges, _ = build_edges(_fabric_pair(), (), EngineConfig())
    assert len(edges) == 1
    assert edges[0].direction_conf == 0.0 and edges[0].direction_basis == "none"


def test_same_layer_pair_directed_when_oracle_orients_it():
    # leaf1 upstream of spine1 (the from_node is the earlier-onset leaf1) → topo agrees.
    d = DirectedTopology((("flow", _src({("leaf1", "spine1"): Orientation(Verdict.A_UPSTREAM, 0.8, "flow")})),))
    edges, _ = build_edges(_fabric_pair(), (), EngineConfig(), directed=d)
    assert len(edges) == 1
    e = edges[0]
    assert e.direction_conf > 0.0                       # NOW directed (onset + topo = 2 votes)
    assert e.direction_basis == "onset_order+topo_updown"


def test_oracle_conflict_with_onset_yields_mixed():
    # Oracle says spine1 upstream of leaf1, but onset says leaf1 first → conflict → mixed.
    d = DirectedTopology((("flow", _src({("leaf1", "spine1"): Orientation(Verdict.B_UPSTREAM, 0.8, "flow")})),))
    edges, _ = build_edges(_fabric_pair(), (), EngineConfig(), directed=d)
    assert edges[0].direction_basis in ("mixed", "none")
    assert edges[0].direction_conf == 0.0
