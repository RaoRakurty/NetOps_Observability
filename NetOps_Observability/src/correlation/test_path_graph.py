# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Service Path Graph contract (v1) — the ranked, explicit, tenant-scoped
relationship model that REPLACES token-overlap edge admission.

What these tests hold the engine to (docs/design/service-path-graph-contract.md):

  §3  ranks 1–5 (observed) may create an AUTHORITATIVE edge; rank 6 (cloud route /
      BGP / SD-WAN policy) is INFERRED — supporting only; rank 7 (shared token /
      name similarity) is CANDIDATE ONLY and may NEVER be authoritative.
  §4  inferred evidence alone can never confirm a verdict.
  §5  every edge states its evidence (ref, method, confidence, observed_at,
      data_class) — an edge that cannot is not emitted.
  §6  every join: same tenant · overlapping time · explicit membership ·
      compatible network context (or a modelled seam/NAT) · compatible direction
      and protocol.
  §8  missing hops preserved · asymmetric paths distinct · TCP vs ICMP distinct ·
      multiple vantages distinct · stale observation cannot anchor a live verdict.
  §9  two tenants with OVERLAPPING addresses, identical app names and identical
      path shapes never cross: not one resolution, edge or evidence lineage.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from catalog import builtin_catalog
from cloud_producers import cloud_signal
from engine import (
    EngineConfig,
    TopologyAdjacency,
    build_nodes,
    resolve_grounding,
    run_window,
)
from path_graph import (
    Confidence,
    DataClass,
    EdgeType,
    Endpoint,
    EvidenceClass,
    PathDefinition,
    PathGraphView,
    PathHop,
    PathIndex,
    PathObservation,
    Provenance,
    Relation,
    ResolutionMethod,
    ServiceBinding,
)
from signals import (
    EntityType,
    ModalityClass,
    Observer,
    ObserverType,
    Severity,
    Signal,
    Source,
)
from verdicts import VerdictTier

T0 = datetime(2026, 7, 12, 12, 0, 0, tzinfo=timezone.utc)
CAT = builtin_catalog()


# ── the live-lab fixture (contract §10), parameterised by tenant ──────────────
# Tenant A and tenant B get IDENTICAL addresses, an IDENTICAL application name and
# an IDENTICAL path shape — the §9 isolation fixture. Only tenant_id and the record
# ids differ, exactly as they would in a real multi-tenant deployment.


def _prov(tenant: str, pid: str, data_class: str = DataClass.LIVE.value) -> Provenance:
    return Provenance(tenant_id=tenant, producer_id="prober-1", provenance_id=pid,
                      data_class=data_class, environment="prod", run_id="run-1")


def lab_path_view(tenant: str = "acme", sfx: str = "a", *,
                  data_class: str = DataClass.LIVE.value,
                  observed_at: datetime | None = None,
                  protocol: str = "icmp",
                  direction: str = "forward",
                  vantage: str = "vantage-agent-1") -> PathGraphView:
    """The §10 acceptance path: client → LAN gw → WAN edge → AWS NVA (seam) →
    [unknown hop] → AWS app endpoint → the application.

    Every object is tenant-stamped and evidence-bearing. NOTHING here is a token."""
    at = observed_at or T0
    vf = at - timedelta(hours=1)
    eps = (
        Endpoint(f"ep-{sfx}-client", tenant, "172.40.40.92", "vrf-corp", kind="client",
                 resolved_entity_ref="user-laptop-7", valid_from=vf,
                 evidence_ref=f"ev-ep-{sfx}-client", prov=_prov(tenant, f"pv-ep-{sfx}-1", data_class)),
        Endpoint(f"ep-{sfx}-gw", tenant, "172.40.40.1", "vrf-corp", kind="lan_gateway",
                 resolved_entity_ref="lan-gw-1", valid_from=vf,
                 evidence_ref=f"ev-ep-{sfx}-gw", prov=_prov(tenant, f"pv-ep-{sfx}-2", data_class)),
        Endpoint(f"ep-{sfx}-wan", tenant, "10.70.245.122", "vrf-corp", kind="wan_edge",
                 resolved_entity_ref="wan-edge-1", valid_from=vf,
                 evidence_ref=f"ev-ep-{sfx}-wan", prov=_prov(tenant, f"pv-ep-{sfx}-3", data_class)),
        Endpoint(f"ep-{sfx}-nva", tenant, "10.60.1.10", "vpc-1", kind="nva",
                 resolved_entity_ref="nva-eni-1", valid_from=vf,
                 evidence_ref=f"ev-ep-{sfx}-nva", prov=_prov(tenant, f"pv-ep-{sfx}-4", data_class)),
        # rank 2: the cloud NIC/ENI inventory says WHICH resource owns 10.60.10.10.
        Endpoint(f"ep-{sfx}-app", tenant, "10.60.10.10", "vpc-1", kind="app_endpoint",
                 resolved_entity_ref="eni-store-api", valid_from=vf,
                 resolution_method=ResolutionMethod.ENDPOINT_BINDING.value,
                 confidence=Confidence.AUTHORITATIVE.value,
                 evidence_ref=f"ev-ep-{sfx}-app", prov=_prov(tenant, f"pv-ep-{sfx}-5", data_class)),
    )
    hops = (
        _hop(1, "172.40.40.92", "user-laptop-7", tenant, sfx, at),
        _hop(2, "172.40.40.1", "lan-gw-1", tenant, sfx, at),
        _hop(3, "10.70.245.122", "wan-edge-1", tenant, sfx, at),
        _hop(4, "10.60.1.10", "nva-eni-1", tenant, sfx, at, seam_id="sm-aws-dx",
             transformation="tunnel_egress"),
        # hop 5 does not answer. It is a FACT about the path: preserved, never bridged.
        PathHop(hop_index=5, state="missing", observed_address="", resolved_entity_ref="",
                confidence=Confidence.UNKNOWN.value, evidence_ref=f"ev-hop-{sfx}-5",
                observed_at=at, tenant_id=tenant),
        _hop(6, "10.60.10.10", "eni-store-api", tenant, sfx, at),
    )
    pid = f"p-{sfx}-{protocol}-{direction}-{vantage}"
    obs = PathObservation(
        observation_id=f"obs-{sfx}-1", path_id=pid, tenant_id=tenant, observed_at=at,
        method="traceroute_tcp" if protocol == "tcp" else "traceroute_icmp",
        vantage_id=vantage, status="partial", hops=hops,
        prov=_prov(tenant, f"prov-obs-{sfx}-1", data_class),
        definition=PathDefinition(
            path_id=pid, tenant_id=tenant, src_endpoint_ref=f"ep-{sfx}-client",
            dst_endpoint_ref=f"ep-{sfx}-app", direction=direction, protocol=protocol,
            dst_port=443 if protocol == "tcp" else None, vantage_id=vantage,
            network_context="vrf-corp"),
    )
    # rank 4: the application's OWN deployment/agent metadata names its endpoint.
    # THIS is what binds `store-api` to 10.60.10.10 — never a token.
    svc = ServiceBinding(
        service_ref="store-api", endpoint_ref=f"ep-{sfx}-app", tenant_id=tenant,
        evidence_ref=f"ev-svc-{sfx}", confidence=Confidence.STRONG.value, valid_from=vf,
        prov=_prov(tenant, f"pv-svc-{sfx}", data_class),
    )
    return PathGraphView(endpoints=eps, observations=(obs,), service_bindings=(svc,))


def _hop(i: int, addr: str, ref: str, tenant: str, sfx: str, at: datetime,
         seam_id: str = "", transformation: str = "none") -> PathHop:
    return PathHop(hop_index=i, state="responding", observed_address=addr,
                   resolved_entity_ref=ref, confidence=Confidence.STRONG.value,
                   seam_id=seam_id, transformation=transformation, rtt_ms=float(i),
                   evidence_ref=f"ev-hop-{sfx}-{i}", observed_at=at, tenant_id=tenant)


def lab_signals(tenant: str = "acme"):
    """A cloud application symptom + an on-prem WAN-edge interface fault. They share
    NO token: the app carries a NAME, the interface carries a DEVICE."""
    app = cloud_signal(tenant, T0 + timedelta(seconds=60), "cloud_health", app="store-api",
                       account="123", region="us-east-1", severity=Severity.HIGH,
                       metric_name="alb_5xx_pct", value=7.1, baseline=0.2)
    wan = Signal(
        tenant_id=tenant, ts=T0, source=Source.METRIC, kind="if_metric_anomaly",
        observer=Observer(observer_id="snmp-poller", observer_type=ObserverType.DEVICE),
        modality_class=ModalityClass.DEVICE_TELEMETRY, entity_type=EntityType.INTERFACE,
        entity_id="wan-edge-1:ge-0/0/0", severity=Severity.HIGH, native_id=f"w|{tenant}",
        deviation=6.0,
    )
    return app, wan


def _nodes(sigs):
    ns = build_nodes(tuple(sigs))
    return ns


# ── §5: an edge that cannot state its evidence is not emitted ────────────────


def test_relation_without_evidence_is_impossible():
    with pytest.raises(ValueError, match="evidence_ref"):
        Relation(edge_type=EdgeType.PATH_HAS_HOP.value,
                 method=ResolutionMethod.HOP_INVENTORY.value,
                 confidence=Confidence.STRONG.value, evidence_ref="",
                 observation_method="traceroute_icmp", observed_at="")


# ── §3: the ranking, and what each rank is allowed to do ─────────────────────


def test_rank7_shared_token_is_never_authoritative():
    """The forbidden shortcut. Two nodes that share ONLY a free-text token still get
    an edge (an object is not lost) — but it is labelled candidate, rank 7, and can
    never be authoritative. This is the guarantee the owner asked for."""
    a = Signal(tenant_id="acme", ts=T0, source=Source.SYSLOG, kind="link_state_change",
               observer=Observer(observer_id="syslog-leaf1", observer_type=ObserverType.DEVICE),
               modality_class=ModalityClass.CONTROL_PLANE, entity_type=EntityType.INTERFACE,
               entity_id="leaf1:Gi0/1", severity=Severity.HIGH, native_id="a|1",
               entity_tokens=("fabric-core",))
    b = Signal(tenant_id="acme", ts=T0 + timedelta(seconds=5), source=Source.METRIC,
               kind="if_metric_anomaly",
               observer=Observer(observer_id="snmp-poller", observer_type=ObserverType.DEVICE),
               modality_class=ModalityClass.DEVICE_TELEMETRY, entity_type=EntityType.INTERFACE,
               entity_id="leaf2:Gi0/2", severity=Severity.HIGH, native_id="b|1",
               deviation=6.0, entity_tokens=("fabric-core",))
    na, nb = _nodes([a, b])
    g = resolve_grounding(na, nb, (), TopologyAdjacency())
    assert g is not None                                   # the edge still forms
    assert g.relation.method == ResolutionMethod.SHARED_TOKEN.value
    assert g.relation.rank == 7
    assert g.relation.evidence_class == EvidenceClass.CANDIDATE.value
    assert g.authoritative is False                        # ← NEVER
    assert g.relation.evidence_ref == "token:fabric-core"  # honest about what it is

    # …and an object held together ONLY by a token can never be confirmed, even when
    # the evidence itself (2 modalities, 2 independent observers) would otherwise pass
    # the gate — the SAME evidence DOES confirm on an observed path relation below.
    snap = run_window([a, b], CAT, ())[0]
    assert snap.has_authoritative_edge() is False
    assert snap.ranking.verdict_tier is not VerdictTier.CONFIRMED
    assert any("candidate" in m for m in snap.ranking.evidence_missing)


def test_same_evidence_confirms_on_an_observed_path_relation():
    """The control for the two tests above and below: identical signals, identical
    catalog, identical verdict gate — ONLY the relationship class changes. On an
    OBSERVED (rank 3) path relation the object confirms. So the refusal to confirm on
    rank 6/7 is the contract doing its job, not a scoring accident."""
    a, b = _token_pair()
    view = _two_device_path("acme", "leaf1", "leaf2")
    snap = run_window([a, b], CAT, (), paths=view)[0]
    e = snap.edges[0]
    assert e.grounding.relation.method == ResolutionMethod.HOP_INVENTORY.value
    assert e.grounding.relation.rank == 3
    assert e.grounding.authoritative is True
    assert snap.ranking.verdict_tier is VerdictTier.CONFIRMED


def test_rank6_inferred_route_supports_but_never_confirms():
    """§4: the AWS route table says the subnet's default route points at the NVA.
    That is INFERRED — it may explain and predict, it may NOT assert that traffic took
    it, and it may NOT confirm. Same evidence as the test above ⇒ still not confirmed."""
    from path_graph import RouteRelation
    a, b = _token_pair(shared_token=False)
    view = PathGraphView(routes=(RouteRelation(
        tenant_id="acme", from_ref="leaf1", to_ref="leaf2", relation="routes_via",
        network_context="vrf-corp", evidence_ref="ev-rt-1", observed_at=T0,
        prov=_prov("acme", "pv-rt-1")),))
    snap = run_window([a, b], CAT, (), paths=view)[0]
    assert len(snap.nodes) == 2, "the inferred relation DOES admit a supporting edge"
    e = snap.edges[0]
    rel = e.grounding.relation
    assert rel.method == ResolutionMethod.CLOUD_ROUTE.value and rel.rank == 6
    assert rel.evidence_class == EvidenceClass.INFERRED.value
    assert rel.edge_type == EdgeType.EVIDENCE_SUPPORTS.value
    assert e.grounding.authoritative is False
    assert snap.ranking.verdict_tier is not VerdictTier.CONFIRMED
    assert any("inferred" in m for m in snap.ranking.evidence_missing)


def _token_pair(shared_token: bool = True):
    tok = ("fabric-core",) if shared_token else ()
    a = Signal(tenant_id="acme", ts=T0, source=Source.SYSLOG, kind="link_state_change",
               observer=Observer(observer_id="syslog-leaf1", observer_type=ObserverType.DEVICE),
               modality_class=ModalityClass.CONTROL_PLANE, entity_type=EntityType.INTERFACE,
               entity_id="leaf1:Gi0/1", severity=Severity.HIGH, native_id="a|1",
               entity_tokens=tok)
    b = Signal(tenant_id="acme", ts=T0 + timedelta(seconds=5), source=Source.METRIC,
               kind="if_metric_anomaly",
               observer=Observer(observer_id="snmp-poller", observer_type=ObserverType.DEVICE),
               modality_class=ModalityClass.DEVICE_TELEMETRY, entity_type=EntityType.INTERFACE,
               entity_id="leaf2:Gi0/2", severity=Severity.HIGH, native_id="b|1",
               deviation=6.0, entity_tokens=tok)
    return a, b


def _two_device_path(tenant: str, dev_a: str, dev_b: str, *,
                     data_class: str = DataClass.LIVE.value,
                     observed_at: datetime | None = None) -> PathGraphView:
    at = observed_at or T0
    hops = (
        PathHop(1, "responding", "10.0.0.1", dev_a, confidence=Confidence.STRONG.value,
                evidence_ref="ev-h1", observed_at=at, tenant_id=tenant),
        PathHop(2, "responding", "10.0.0.2", dev_b, confidence=Confidence.STRONG.value,
                evidence_ref="ev-h2", observed_at=at, tenant_id=tenant),
    )
    return PathGraphView(observations=(PathObservation(
        observation_id="obs-2dev", path_id="p-2dev", tenant_id=tenant, observed_at=at,
        method="traceroute_icmp", vantage_id="v1", status="complete", hops=hops,
        prov=_prov(tenant, "prov-2dev", data_class)),))


# ── §1: synthetic / lab / replay can never confirm ───────────────────────────


def test_lab_data_class_can_support_but_never_confirm():
    a, b = _token_pair(shared_token=False)
    view = _two_device_path("acme", "leaf1", "leaf2", data_class=DataClass.LAB.value)
    snap = run_window([a, b], CAT, (), paths=view)[0]
    assert snap.data_class == DataClass.LAB.value
    assert snap.edges[0].grounding.relation.rank == 3      # the relation is observed…
    assert snap.ranking.verdict_tier is not VerdictTier.CONFIRMED   # …but not live
    assert any("data_class=lab" in m for m in snap.ranking.evidence_missing)
    assert snap.provenance()["data_class"] == "lab"
    assert snap.provenance()["provenance_id"]


def test_synthetic_signal_taints_the_object_data_class():
    a, b = _token_pair(shared_token=False)
    a = Signal(**{**a.__dict__, "attrs": {"data_class": "synthetic", "scenario_id": "sc-7"}})
    view = _two_device_path("acme", "leaf1", "leaf2")
    snap = run_window([a, b], CAT, (), paths=view)[0]
    assert snap.data_class == "synthetic" and snap.scenario_id == "sc-7"
    assert snap.ranking.verdict_tier is not VerdictTier.CONFIRMED


# ── §8: stale observation cannot anchor a live verdict ───────────────────────


def test_stale_observation_is_not_authoritative():
    a, b = _token_pair(shared_token=False)
    view = _two_device_path("acme", "leaf1", "leaf2",
                            observed_at=T0 - timedelta(hours=6))
    snap = run_window([a, b], CAT, (), paths=view)[0]
    rel = snap.edges[0].grounding.relation
    assert rel.stale is True
    assert rel.authoritative is False          # rank 3, but outside its freshness window
    assert snap.ranking.verdict_tier is not VerdictTier.CONFIRMED


# ── §8: path identity — direction, protocol, vantage ─────────────────────────


def test_tcp_and_icmp_paths_are_distinct_objects():
    v_icmp = lab_path_view(protocol="icmp")
    v_tcp = lab_path_view(sfx="t", protocol="tcp")
    assert (v_icmp.observations[0].path_id != v_tcp.observations[0].path_id)
    assert v_tcp.observations[0].method == "traceroute_tcp"
    # a signal that declares its own path_id joins ONLY through that path (§6 rule 5)
    idx = PathIndex(PathGraphView(
        endpoints=v_icmp.endpoints + v_tcp.endpoints,
        observations=v_icmp.observations + v_tcp.observations,
        service_bindings=v_icmp.service_bindings + v_tcp.service_bindings), "acme")
    rel = idx.relate(frozenset({"wan-edge-1"}), frozenset({"store-api"}),
                     (T0, T0), (T0, T0),
                     a_paths=frozenset({v_tcp.observations[0].path_id}),
                     b_paths=frozenset({v_tcp.observations[0].path_id}))
    assert rel is not None and rel.ref == "obs-t-1"     # never the ICMP observation


def test_forward_and_reverse_paths_are_never_merged():
    fwd = lab_path_view(direction="forward")
    rev = lab_path_view(sfx="r", direction="reverse")
    assert fwd.observations[0].path_id != rev.observations[0].path_id
    assert fwd.observations[0].definition.direction == "forward"
    assert rev.observations[0].definition.direction == "reverse"


def test_multiple_vantages_are_distinct_paths():
    v1 = lab_path_view(vantage="vantage-agent-1")
    v2 = lab_path_view(sfx="v2", vantage="vantage-agent-2")
    assert v1.observations[0].path_id != v2.observations[0].path_id
    # both remain queryable; neither is silently collapsed into the other
    idx = PathIndex(PathGraphView(
        endpoints=v1.endpoints + v2.endpoints,
        observations=v1.observations + v2.observations,
        service_bindings=v1.service_bindings + v2.service_bindings), "acme")
    assert {o.observation_id for o in idx.view.observations} == {"obs-a-1", "obs-v2-1"}


# ── §8: unknown hops are preserved ───────────────────────────────────────────


def test_missing_hop_is_preserved_and_declared():
    app, wan = lab_signals()
    snap = next(s for s in run_window([app, wan], CAT, (), paths=lab_path_view())
            if len(s.nodes) == 2)
    rel = snap.edges[0].grounding.relation
    assert rel.unknown_hops == (5,)                 # the hop that did not answer
    spine = snap.path_spine()
    states = [h["state"] for h in spine["spine"]]
    assert states.count("missing") == 1             # rendered, not dropped
    assert spine["evidence_missing"][0]["hop_index"] == 5
    assert any(e["type"] == EdgeType.EVIDENCE_MISSING.value for e in spine["edges"])


# ── §6 rule 4: network context ───────────────────────────────────────────────


def test_context_change_without_a_seam_or_nat_is_refused():
    """Two endpoints in DIFFERENT network contexts (an overlapping-IP world) may only
    join across an explicitly modelled seam or NAT transformation. Strip the seam and
    the transformation from the hop and the join is refused — not guessed."""
    view = lab_path_view()
    obs = view.observations[0]
    hops = tuple(
        h if h.hop_index != 4 else PathHop(
            h.hop_index, h.state, h.observed_address, h.resolved_entity_ref,
            h.resolution_method, h.confidence, "", h.rtt_ms, "none",
            h.evidence_ref, h.observed_at, h.tenant_id)
        for h in obs.hops)
    stripped = PathGraphView(
        endpoints=view.endpoints, service_bindings=view.service_bindings,
        observations=(PathObservation(
            obs.observation_id, obs.path_id, obs.tenant_id, obs.observed_at, obs.method,
            obs.vantage_id, obs.status, hops, obs.prov, obs.definition),))
    idx = PathIndex(stripped, "acme")
    assert idx.relate(frozenset({"wan-edge-1"}), frozenset({"store-api"}),
                      (T0, T0), (T0, T0)) is None


# ── §9: TWO-TENANT ISOLATION (mandatory) ─────────────────────────────────────


def test_two_tenants_overlapping_addresses_never_cross():
    """Tenant A and tenant B: the SAME addresses, the SAME application name
    (`store-api`), the SAME path shape, the same seam id. Nothing crosses."""
    a_view, b_view = lab_path_view("t_a", "a"), lab_path_view("t_b", "b")
    both = PathGraphView(
        endpoints=a_view.endpoints + b_view.endpoints,
        observations=a_view.observations + b_view.observations,
        service_bindings=a_view.service_bindings + b_view.service_bindings)

    # 1. the index is tenant-scoped at CONSTRUCTION — B's objects are unreachable.
    idx_a = PathIndex(both, "t_a")
    assert {o.observation_id for o in idx_a.view.observations} == {"obs-a-1"}
    assert {e.endpoint_id for e in idx_a.view.endpoints} == {
        f"ep-a-{k}" for k in ("client", "gw", "wan", "nva", "app")}
    assert all(b.tenant_id == "t_a" for b in idx_a.view.service_bindings)

    # 2. resolution never reaches B, even though the addresses are identical.
    rel = idx_a.relate(frozenset({"wan-edge-1"}), frozenset({"store-api"}),
                       (T0, T0 + timedelta(seconds=60)), (T0, T0 + timedelta(seconds=60)))
    assert rel is not None and rel.ref == "obs-a-1"
    assert rel.evidence_ref == "prov-obs-a-1"
    assert "b" not in rel.supporting_refs and all("-b-" not in r for r in rel.supporting_refs)

    # 3. the object each tenant forms carries only ITS OWN evidence lineage.
    snaps: dict[str, object] = {}
    for tenant, sfx in (("t_a", "a"), ("t_b", "b")):
        app, wan = lab_signals(tenant)
        snap = next(s for s in run_window([app, wan], CAT, (), paths=both)
                if len(s.nodes) == 2)
        snaps[tenant] = snap
        assert snap.tenant_id == tenant
        assert snap.edges[0].grounding.relation.ref == f"obs-{sfx}-1"
        # the embedded (replay) context holds no other tenant's objects
        blob = snap.hypotheses_blob()
        other = "b" if sfx == "a" else "a"
        assert f"obs-{other}-1" not in blob
        assert f"ep-{other}-app" not in blob
        assert all(o.tenant_id == tenant for o in snap.paths.observations)
        assert all(e.tenant_id == tenant for e in snap.paths.endpoints)

    # 4. identical shapes ⇒ DIFFERENT objects (no id collision, no shared lineage).
    assert snaps["t_a"].correlation_id != snaps["t_b"].correlation_id
    assert snaps["t_a"].provenance()["provenance_id"] != snaps["t_b"].provenance()["provenance_id"]

    # 5. a cross-tenant window is refused outright (the engine's standing rule).
    app_a, _ = lab_signals("t_a")
    _, wan_b = lab_signals("t_b")
    with pytest.raises(ValueError, match="single-tenant"):
        run_window([app_a, wan_b], CAT, (), paths=both)


def test_empty_tenant_path_objects_are_dropped_fail_closed():
    """No 'global' path objects: an object with an empty tenant_id is reachable by
    NOBODY (seams may be platform-scoped; path relationships may not)."""
    view = lab_path_view("", "x")
    assert PathIndex(view, "acme").view.is_empty()


# ── the engine keeps working without any path objects (additive, no regression) ──


def test_no_path_view_keeps_the_pre_contract_grounding():
    a, b = _token_pair()
    snap = run_window([a, b], CAT, (), EngineConfig())[0]
    assert snap.edges[0].grounding.kind == "topo"
    assert snap.edges[0].grounding.ref == "shared:fabric-core"
    assert snap.paths.is_empty()
    assert snap.path_spine() == {}          # no spine ⇒ the UI must say so, not invent one


# ── §6 rule 2: NAT session validity time (the alias must be timely) ───────────


def test_nat_alias_respects_session_validity_time():
    """A NAT translation only aliases pre<->post NEAR its observation time. After
    NAT-pool reuse the same pair maps a different inside host, so a session observed
    far from the evidence time must NOT alias (it would weld the wrong host onto the
    path via an authoritative rank-5 stitch). Fail closed on an untimed session."""
    from datetime import timedelta

    from path_graph import NatSession
    fresh = 900.0
    nat = NatSession(tenant_id="acme", pre_address="10.0.0.5", post_address="203.0.113.9",
                     evidence_ref="ev-nat-1", observed_at=T0, prov=_prov("acme", "pv-nat-1"))
    idx = PathIndex(PathGraphView(nat_sessions=(nat,), freshness_s=fresh), "acme")
    refs = frozenset({"10.0.0.5"})

    # Fresh: observed at T0, evidence at T0 → aliases.
    assert idx._aliases(refs, T0).get("203.0.113.9") is not None

    # Within the window (edge): still aliases.
    assert idx._aliases(refs, T0 + timedelta(seconds=fresh - 1)).get("203.0.113.9") is not None

    # Stale: evidence far past the session's validity window → NO alias.
    assert idx._aliases(refs, T0 + timedelta(seconds=fresh + 60)) == {}

    # Fail closed: an untimed session can never be placed on a timeline.
    untimed = NatSession(tenant_id="acme", pre_address="10.0.0.5", post_address="203.0.113.9",
                         evidence_ref="ev-nat-2", observed_at=None, prov=_prov("acme", "pv-nat-2"))
    idx2 = PathIndex(PathGraphView(nat_sessions=(untimed,), freshness_s=fresh), "acme")
    assert idx2._aliases(refs, T0) == {}


def test_rank7_shared_token_uses_candidate_weight_not_containment():
    """The rank-7 shared-token edge must weigh at w_topo_candidate (weak), NEVER at
    w_topo_containment (0.9, the strongest). rank-1 identity and rank-7 token both
    emit a 'shared:<x>' ref, so the pre-fix ref-prefix branch mis-scored the token
    edge as containment and welded unrelated cross-modality episodes."""
    from engine import EngineConfig
    a = Signal(tenant_id="acme", ts=T0, source=Source.SYSLOG, kind="link_state_change",
               observer=Observer(observer_id="syslog-leaf1", observer_type=ObserverType.DEVICE),
               modality_class=ModalityClass.CONTROL_PLANE, entity_type=EntityType.INTERFACE,
               entity_id="leaf1:Gi0/1", severity=Severity.HIGH, native_id="a|1",
               entity_tokens=("fabric-core",))
    b = Signal(tenant_id="acme", ts=T0 + timedelta(seconds=5), source=Source.METRIC,
               kind="if_metric_anomaly",
               observer=Observer(observer_id="snmp-poller", observer_type=ObserverType.DEVICE),
               modality_class=ModalityClass.DEVICE_TELEMETRY, entity_type=EntityType.INTERFACE,
               entity_id="leaf2:Gi0/2", severity=Severity.HIGH, native_id="b|1",
               deviation=6.0, entity_tokens=("fabric-core",))
    cfg = EngineConfig()
    snap = run_window([a, b], CAT, (), cfg)[0]
    e = snap.edges[0]
    assert e.grounding.relation.rank == 7
    assert e.w_topo == cfg.w_topo_candidate, \
        f"rank-7 token edge scored at {e.w_topo}, must be w_topo_candidate ({cfg.w_topo_candidate})"
    assert e.w_topo < cfg.w_topo_containment and e.w_topo < cfg.w_topo_seam, \
        "a name coincidence must weigh below every real relation"
