# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Tracker 397: the stage [4] rank-3 control-session rung (engine 3.6.0).

The SD-WAN controller fan-in (engine 3.4.0) is silent past CORR_TOKEN_HUB_CAP
edges: the edges' control-connection losses meet ONLY on the shared controller
address, a rank-7 token, and a token on more than the cap never grounds. The API
now exports the controller's own control sessions as `proto: "sdwan_control"`
topology_links rows; the engine grounds on one ONLY when one side is a
control-connection loss naming the other end's session key. What is pinned here:

* the predicate matrix — an edge's loss grounds to the node on the controller it
  names, the controller's loss of an edge grounds to that edge, a loss naming one
  controller never grounds to another, and two edges never ground to each other;
* the weld guard — a controller's own alarms and an edge's unrelated link flap
  never ground on a session row (rows never enter `pairs`);
* evidence with no session row is byte-identical; malformed rows are dropped;
* the embedded rows replay; rows never cross tenants;
* the fast path, the candidate index and the reference grounding agree;
* the scale behaviour: without rows 64 edges → one object, 65 → zero (the hub
  cap); with rows and a controller-side node, one authoritative object holding
  every edge at N ∈ {65, 500, 2000}; with rows and no controller-side node, still
  zero — rank 3 is pair-shaped, and that limit is stated, not hidden.
"""
from __future__ import annotations

import json
from datetime import timedelta

import pytest

import engine as E
from catalog import builtin_catalog
from controller_events import controller_event_to_signal
from engine import (
    CORR_TOKEN_HUB_CAP,
    NO_ADJACENCY,
    SESSION_PROTO,
    TopologyAdjacency,
    build_edges,
    build_nodes,
    node_controller_peers,
    resolve_grounding,
    run_window,
)
from replay import StoredObject, replay
from signals import (
    EntityType,
    ModalityClass,
    Observer,
    ObserverType,
    Severity,
    Signal,
    Source,
)
from test_sdwan_controller_fan_in import T0, TENANT, VMANAGE, VSMART, trap_control_down

CAT = builtin_catalog()


def edge(i: int) -> str:
    return f"vedge-{i}"


def edge_key(i: int) -> str:
    return f"10.1.{i // 250}.{i % 250 + 1}"


def row(sa: str, ka: str, sb: str, kb: str, tenant: str = TENANT) -> dict:
    return {"tenant_id": tenant, "proto": SESSION_PROTO, "sa": sa, "sa_key": ka,
            "sb": sb, "sb_key": kb}


def rows_to(controller: str, n: int, tenant: str = TENANT) -> list[dict]:
    return [row(edge(i), edge_key(i), controller, controller, tenant) for i in range(n)]


def ctl_event(kind: str, device: str, off: float, peer: str = "",
              sev: str = "high", event_id: str = "") -> Signal:
    ev = {"tenant_id": TENANT, "integration_id": "vm1", "source_system": "vmanage",
          "normalized_event_type": kind, "severity": sev, "device_id": device,
          "peer_id": peer, "event_time": (T0 + timedelta(seconds=off)).isoformat(),
          "event_id": event_id or f"{kind}-{device}-{off}"}
    sig = controller_event_to_signal(ev, T0 + timedelta(seconds=off))
    assert sig is not None
    return sig


def hub_unreachable(controller: str = VSMART, off: float = 5.0) -> Signal:
    return ctl_event("controller_device_unreachable", controller, off)


def link_flap(device: str, off: float) -> Signal:
    return Signal(
        tenant_id=TENANT, ts=T0 + timedelta(seconds=off), source=Source.TRAP,
        kind="link_state_change",
        observer=Observer(observer_id=device, observer_type=ObserverType.DEVICE),
        modality_class=ModalityClass.CONTROL_PLANE, entity_type=EntityType.INTERFACE,
        entity_id=f"{device}:ge0/0", severity=Severity.HIGH,
        native_id=f"link|{device}|{off}", entity_tokens=(device,),
        attrs={"state": "down", "link_cause": "fault"})


def nodes_of(*sigs: Signal) -> dict[str, E.Node]:
    return {n.key: n for n in build_nodes(tuple(sigs))}


def one(nodes: dict[str, E.Node], entity_id: str) -> E.Node:
    (n,) = [n for n in nodes.values() if n.entity_id == entity_id]
    return n


# ── rows: parsing, kind scoping ─────────────────────────────────────────────


def test_session_rows_never_enter_pairs():
    adj = TopologyAdjacency.from_links(rows_to(VSMART, 2) + [{"a": "x", "b": "y"}])
    assert adj.pairs == frozenset({frozenset({"x", "y"})})
    assert len(adj.sessions) == 2
    assert not adj.adjacent(edge(0), VSMART)


def test_a_session_row_carrying_a_and_b_still_never_enters_pairs():
    r = row(edge(0), edge_key(0), VSMART, VSMART) | {"a": edge(0), "b": VSMART}
    adj = TopologyAdjacency.from_links([r])
    assert adj.pairs == frozenset() and len(adj.sessions) == 1


@pytest.mark.parametrize("bad", [
    {"sa": "", "sa_key": "k", "sb": "b", "sb_key": "k2"},
    {"sa": "a", "sa_key": "k", "sb": "a", "sb_key": "k2"},       # one device
    {"sa": "a", "sa_key": 1, "sb": "b", "sb_key": "k2"},          # non-string
    {"sa": "a", "sa_key": "k", "sb": "b"},                        # missing key
    {"sa": "a" * 129, "sa_key": "k", "sb": "b", "sb_key": "k2"},  # oversized
    {"sa": ["a"], "sa_key": "k", "sb": "b", "sb_key": "k2"},
])
def test_malformed_session_rows_are_dropped(bad):
    adj = TopologyAdjacency.from_links([{"proto": SESSION_PROTO, **bad}])
    assert adj.sessions == frozenset() and adj.pairs == frozenset()


def test_session_keys_orient_to_the_asked_ends():
    adj = TopologyAdjacency.from_links([row("z-edge", "1.1.1.1", "a-ctl", "2.2.2.2")])
    assert adj.session_keys("z-edge", "a-ctl") == (("1.1.1.1", "2.2.2.2"),)
    assert adj.session_keys("a-ctl", "z-edge") == (("2.2.2.2", "1.1.1.1"),)
    assert adj.session_keys("a-ctl", "a-ctl") == ()


# ── the predicate matrix ────────────────────────────────────────────────────


def test_an_edge_loss_grounds_to_the_controller_it_names_at_rank_3():
    ns = nodes_of(trap_control_down(edge(0), 0.0), hub_unreachable())
    e0, hub = one(ns, edge(0)), one(ns, VSMART)
    assert node_controller_peers(e0) == frozenset({VSMART})
    g = resolve_grounding(e0, hub, (), TopologyAdjacency.from_links(rows_to(VSMART, 1)))
    assert g is not None and g.rank == 3 and g.authoritative
    lo, hi = sorted((edge(0), VSMART))
    assert g.ref == f"ctl:{lo}--{hi}"
    assert g.relation.observation_method == "control_session"


def test_without_rows_the_same_pair_is_only_a_candidate():
    ns = nodes_of(trap_control_down(edge(0), 0.0), hub_unreachable())
    g = resolve_grounding(one(ns, edge(0)), one(ns, VSMART), (), NO_ADJACENCY)
    assert g is None or not g.authoritative


def test_the_controller_loss_of_an_edge_grounds_to_any_node_on_that_edge():
    vsmart_loss = ctl_event("controller_control_connection_loss", VSMART, 0.0,
                            peer=edge_key(0))
    ns = nodes_of(vsmart_loss, link_flap(edge(0), 3.0))
    g = resolve_grounding(one(ns, VSMART), one(ns, f"{edge(0)}:ge0/0"), (),
                          TopologyAdjacency.from_links(rows_to(VSMART, 1)))
    assert g is not None and g.rank == 3


def test_a_loss_naming_the_vsmart_never_grounds_to_the_vmanage():
    alarm = ctl_event("controller_alarm", VMANAGE, 2.0)
    ns = nodes_of(trap_control_down(edge(0), 0.0), alarm)
    adj = TopologyAdjacency.from_links(rows_to(VSMART, 1) + rows_to(VMANAGE, 1))
    g = resolve_grounding(one(ns, edge(0)), one(ns, VMANAGE), (), adj)
    assert g is None or not g.authoritative


def test_two_edges_never_ground_to_each_other_through_the_controller():
    ns = nodes_of(trap_control_down(edge(0), 0.0), trap_control_down(edge(1), 1.0))
    g = resolve_grounding(one(ns, edge(0)), one(ns, edge(1)), (),
                          TopologyAdjacency.from_links(rows_to(VSMART, 2)))
    assert g is None or not g.authoritative


def test_a_row_between_other_devices_grounds_nothing():
    ns = nodes_of(trap_control_down(edge(0), 0.0), hub_unreachable())
    adj = TopologyAdjacency.from_links([row(edge(7), edge_key(7), VSMART, VSMART)])
    g = resolve_grounding(one(ns, edge(0)), one(ns, VSMART), (), adj)
    assert g is None or not g.authoritative


# ── the weld guard ──────────────────────────────────────────────────────────


def test_controller_alarms_and_unrelated_edge_flaps_never_weld():
    """vManage holds a session with every edge. Its own alarms and the edges'
    link flaps must not ground on those rows — the #99 class T4c refused."""
    alarm = ctl_event("controller_alarm", VMANAGE, 0.0, sev="high")
    flaps = [link_flap(edge(i), 2.0 + i) for i in range(3)]
    adj = TopologyAdjacency.from_links(rows_to(VMANAGE, 3))
    ns = nodes_of(alarm, *flaps)
    for n in ns.values():
        if n.entity_id != VMANAGE:
            g = resolve_grounding(one(ns, VMANAGE), n, (), adj)
            assert g is None or g.rank == 7, g
    objs = run_window([alarm, *flaps], CAT, (), adjacency=adj)
    assert not any(e.grounding.ref.startswith("ctl:") for o in objs for e in o.edges)
    assert all(not o.session_rows for o in objs)


# ── byte identity, replay, tenancy ──────────────────────────────────────────


def _outage(n: int) -> list[Signal]:
    return [trap_control_down(edge(i), 0.5 * i) for i in range(n)] + [hub_unreachable()]


def _blob(objs):
    return [(o.content_hash(), json.loads(o.hypotheses_blob())) for o in objs]


def test_no_session_rows_is_byte_identical():
    win = _outage(4) + [link_flap(edge(9), 8.0)]
    assert _blob(run_window(win, CAT, ())) == _blob(
        run_window(win, CAT, (), adjacency=TopologyAdjacency.from_links([{"a": "p", "b": "q"}])))


def test_rows_that_ground_nothing_leave_the_object_byte_identical():
    win = [link_flap(edge(0), 0.0), link_flap(edge(1), 1.0)]
    assert _blob(run_window(win, CAT, ())) == _blob(
        run_window(win, CAT, (), adjacency=TopologyAdjacency.from_links(rows_to(VSMART, 2))))


def test_the_rows_used_are_embedded_and_replay():
    adj = TopologyAdjacency.from_links(rows_to(VSMART, 4) + rows_to(VMANAGE, 4))
    (obj,) = run_window(_outage(4), CAT, (), adjacency=adj)
    ctx = json.loads(obj.hypotheses_blob())["grounding_context"]
    embedded = {tuple(r) for r in ctx["session_adjacency"]}
    want = set()
    for i in range(4):
        lo, hi = sorted([(edge(i), edge_key(i)), (VSMART, VSMART)])
        want.add(lo + hi)
    assert embedded == want
    assert not any(VMANAGE in r for r in embedded), "only rows an edge grounded on"
    win = _outage(4)
    stored = StoredObject.from_rows(obj.to_object_row(1), obj.to_edge_rows(1))
    assert stored.adjacency().sessions == frozenset(embedded)
    archive = [Signal.from_ch_row({**s.to_ch_row(), "archived_for": obj.correlation_id})
               for s in win]
    report = replay(stored, archive, CAT)
    assert report.clean, report
    # and WITHOUT the embedded rows the replay would not reproduce it
    bare = StoredObject(**{**stored.__dict__, "hypotheses_blob": json.dumps(
        {**json.loads(stored.hypotheses_blob), "grounding_context": {
            k: v for k, v in ctx.items() if k != "session_adjacency"}})})
    assert not replay(bare, archive, CAT).clean


def test_rows_never_cross_tenants():
    """main.py composes a tenant's adjacency from its own rows ∪ global — the same
    expression, over a file holding another tenant's sessions."""
    by_tenant: dict[str, list[dict]] = {}
    for link in rows_to(VSMART, 3, tenant="t-other"):
        by_tenant.setdefault(str(link.get("tenant_id") or ""), []).append(link)
    adj = TopologyAdjacency.from_links(by_tenant.get(TENANT, []) + by_tenant.get("", []))
    assert adj.sessions == frozenset()
    objs = run_window(_outage(3), CAT, (), adjacency=adj)
    assert not any(e.grounding.ref.startswith("ctl:") for o in objs for e in o.edges)


# ── fast path ≡ reference; candidate soundness ──────────────────────────────


def test_fast_path_agrees_with_the_reference_grounding():
    win = (_outage(6) + [link_flap(edge(2), 4.0), ctl_event("controller_alarm", VMANAGE, 3.0)]
           + [ctl_event("controller_control_connection_loss", VSMART, 1.5, peer=edge_key(3))])
    adj = TopologyAdjacency.from_links(rows_to(VSMART, 6) + rows_to(VMANAGE, 6))
    nodes = tuple(sorted(build_nodes(tuple(win)), key=lambda n: n.key))
    cfg = E.EngineConfig()
    edges, _ = build_edges(nodes, (), cfg, adj)
    fast = {tuple(sorted((e.from_node, e.to_node))): e.grounding.ref for e in edges}
    hub = E._CandidateIndex(len(nodes), [n.tokens() for n in nodes],
                            [n.identity_refs() for n in nodes], [],
                            [n.adjacency_key() for n in nodes], adj, None, None).hub_tokens
    ref: dict[tuple[str, str], str] = {}
    for i, a in enumerate(nodes):
        for b in nodes[i + 1:]:
            g = resolve_grounding(a, b, (), adj, hub_tokens=hub)
            if g is not None:
                ref[(a.key, b.key) if a.key < b.key else (b.key, a.key)] = g.ref
    ctl_ref = {k: v for k, v in ref.items() if v.startswith("ctl:")}
    ctl_fast = {k: v for k, v in fast.items() if v.startswith("ctl:")}
    assert ctl_ref, "the fixture must exercise the rung"
    assert ctl_fast == ctl_ref


# ── scale: the hub cap, and what the rows lift ──────────────────────────────


def _edge_ids(obj) -> set[str]:
    return {n.entity_id for n in obj.nodes if n.entity_id.startswith("vedge-")}


@pytest.mark.parametrize("n,expect", [(CORR_TOKEN_HUB_CAP, 1), (CORR_TOKEN_HUB_CAP + 1, 0)])
def test_without_rows_the_hub_cap_silences_the_fan_in(n, expect):
    """Pins the row-397 measurement: warn losses meeting only on the controller
    token form one object up to the cap and nothing past it."""
    win = [trap_control_down(edge(i), 0.1 * i) for i in range(n)]
    assert len(run_window(win, CAT, ())) == expect


@pytest.mark.parametrize("n", [CORR_TOKEN_HUB_CAP + 1, 500, 2000])
def test_with_rows_and_a_controller_node_one_authoritative_object(n):
    win = [trap_control_down(edge(i), 0.05 * i) for i in range(n)] + [hub_unreachable()]
    adj = TopologyAdjacency.from_links(rows_to(VSMART, n))
    objs = run_window(win, CAT, (), adjacency=adj)
    holding = [o for o in objs if _edge_ids(o)]
    assert len(holding) == 1
    (obj,) = holding
    assert _edge_ids(obj) == {edge(i) for i in range(n)}
    assert any(e.grounding.authoritative and e.grounding.ref.startswith("ctl:")
               for e in obj.edges)
    blob = obj.hypotheses_blob()
    assert "no authoritative edge" not in blob


def test_with_rows_but_no_controller_node_still_nothing():
    """Rank 3 is pair-shaped: edges do not ground to each other through a shared
    neighbour, so with no node on the controller the star has no hub. Stated."""
    n = CORR_TOKEN_HUB_CAP + 1
    win = [trap_control_down(edge(i), 0.1 * i) for i in range(n)]
    assert run_window(win, CAT, (), adjacency=TopologyAdjacency.from_links(rows_to(VSMART, n))) == []


def test_candidate_count_stays_linear_in_the_edges():
    n = 2000
    win = [trap_control_down(edge(i), 0.05 * i) for i in range(n)] + [hub_unreachable()]
    adj = TopologyAdjacency.from_links(rows_to(VSMART, n) + rows_to(VMANAGE, n))
    nodes = tuple(build_nodes(tuple(win)))
    prep = E.prepare_window(nodes, (), E.EngineConfig(), adj)
    assert prep.index.potential_pairs <= 4 * n, prep.index.potential_pairs


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-q"]))

