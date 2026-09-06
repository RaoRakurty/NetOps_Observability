# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Cloud service dependency graph — Wave 3 #9 ("Service dependency map from
flow telemetry").

The gap this closes
-------------------
The engine already INGESTS every cloud edge-device signal (cloud_lb_log = the LB
5xx, cloud_waf_log = a WAF block, cloud_flow_log REJECT = an SG/NACL drop,
cloud_dns_log = an NXDOMAIN). But when one of those devices faulted the engine
could only say ``saas-experience-degraded, suspected`` and could NOT name the LB /
WAF / firewall / DNS as the cause — because there was no dependency EDGE tying the
edge device to the application in one request path. The device fault and the app
symptom landed in two separate objects (their tokens never intersect — an app is a
NAME, an LB is a resource id), so the engine had nothing to correlate.

What this module builds
-----------------------
The end-to-end cloud service dependency chain, per cloud service, as FIRST-CLASS
dependency edges expressed in the EXISTING Service Path Graph contract
(path_graph.py) — this module invents no new graph, it feeds the one the engine
already grounds against:

    end-user/client → DNS → WAF → LB → firewall/subnet → app VM

Edges are DERIVED from what is real, and their evidence class is HONEST about it:

  * cloud INVENTORY (config): LB→backend-service→instance, WAF↔LB association,
    DNS zone↔service, SG/firewall↔subnet↔instance. Config says traffic COULD go
    that way — so an inventory edge is a `RouteRelation` (rank 6, INFERRED). It
    grounds the device fault to the app (they now share ONE object → the device is
    NAMED), but it can never CONFIRM alone: config is not observation (§3/§4).
  * flow TELEMETRY (cloud_flow_* volume-weighted `talks_to`): an OBSERVED
    `PathObservation` whose ordered hops resolve to each tier. Traffic DID take
    this path — so the tier↔app edge is authoritative (rank 3) and CAN confirm,
    once an independent observer agrees (the verdict/independence gate decides).

The application is bound to its endpoint by a `ServiceBinding` (rank 4, observed) —
its own deployment metadata, never a token. DNS is a NAME dependency, not a
data-path hop, so it is only ever an inferred edge (a synthetic DNS probe is what
lifts a DNS-attributed verdict off `suspected`).

Tenant isolation is structural: every emitted object is tenant-stamped, and the
engine scopes the whole view with ``PathGraphView.for_tenant`` before any lookup
(§6 rule 1 / §9). A record with an empty tenant is dropped (fail-closed) — there
are no "global" dependency edges.

Pure + deterministic (no IO, no wall clock, no randomness): the same inventory +
flow always builds the byte-identical view. main.py owns IO and tenancy resolution.
"""

from __future__ import annotations

import itertools
from dataclasses import dataclass
from datetime import datetime, timezone

from path_graph import (
    DEFAULT_FRESHNESS_S,
    Confidence,
    DataClass,
    Endpoint,
    PathDefinition,
    PathGraphView,
    PathHop,
    PathObservation,
    Provenance,
    ResolutionMethod,
    RouteRelation,
    ServiceBinding,
    Transformation,
)

# Front→back order of the request path. A tier's position is its causal order:
# an earlier tier is upstream of (a dependency of) a later one. DNS is a NAME
# dependency consulted before the connection, not a forwarding hop — it never
# enters the observed data path (see _DATA_PATH_ROLES).
TIER_ORDER: dict[str, int] = {
    "client": 0,
    "dns": 1,
    "waf": 2,
    "lb": 3,
    "firewall": 4,
    "app": 5,
}

# The roles that actually carry packets — the ones a flow observation can witness.
# DNS/client resolve the name / originate the request but a cloud_flow_* record of
# the data path does not traverse the DNS resolver, so DNS stays inferred-only.
_DATA_PATH_ROLES = frozenset({"waf", "lb", "firewall", "app"})

# path_graph Endpoint.kind per tier role (drives the renderer's boundary grouping).
_KIND_OF_ROLE: dict[str, str] = {
    "client": "client",
    "dns": "service_endpoint",
    "waf": "cloud_edge",
    "lb": "cloud_edge",
    "firewall": "nva",
    "app": "app_endpoint",
}

# The `RouteRelation.relation` label per upstream tier — human/audit provenance of
# WHY the inferred edge exists (the config fact it came from).
_RELATION_OF_ROLE: dict[str, str] = {
    "dns": "resolves_name_for",
    "waf": "inspects_ingress_of",
    "lb": "load_balances_for",
    "firewall": "guards_ingress_of",
    "client": "originates_to",
}


@dataclass(frozen=True)
class DependencyTier:
    """One tier on a service's request path. ``resource_id`` is the id the tier's
    fault signal carries as its entity (cloud_lb_log's LB, cloud_waf_log's web
    ACL, cloud_flow_log's ENI/subnet, cloud_dns_log's name) — so the engine can
    resolve the fault node onto this tier. ``address`` is the data-path VIP/IP when
    the tier has one (DNS/client may not)."""

    role: str
    resource_id: str
    address: str = ""
    network_context: str = ""

    def __post_init__(self) -> None:
        if self.role not in TIER_ORDER:
            raise ValueError(f"unknown dependency tier role: {self.role!r}")
        if not self.resource_id:
            raise ValueError(f"dependency tier {self.role!r} needs a resource_id")


@dataclass(frozen=True)
class ServiceDependency:
    """One cloud service's end-to-end edge chain, tenant-stamped. ``app`` is the
    terminal application (what a cloud_health symptom names). ``tiers`` are the
    upstream edge devices + the app tier, in any order (sorted by TIER_ORDER here)."""

    tenant_id: str
    app: str
    tiers: tuple[DependencyTier, ...]
    network_context: str = "cloud"
    provider: str = ""
    evidence_ref: str = ""
    observed_at: datetime | None = None
    data_class: str = DataClass.LIVE.value

    def ordered_tiers(self) -> tuple[DependencyTier, ...]:
        return tuple(sorted(self.tiers, key=lambda t: (TIER_ORDER[t.role], t.resource_id)))


@dataclass(frozen=True)
class FlowEdge:
    """One volume-weighted `talks_to` observation from cloud flow telemetry
    (cloud_flow_* ACCEPT rollups). ``src``/``dst`` are resource ids OR addresses
    (either matches a tier); ``byte_count`` is the observed volume used to gate an
    edge in (below the floor it is noise, not a real dependency)."""

    tenant_id: str
    src: str
    dst: str
    byte_count: float = 0.0


def _prov(dep: ServiceDependency, suffix: str) -> Provenance:
    return Provenance(
        tenant_id=dep.tenant_id,
        producer_id="cloud-dependency-graph",
        provenance_id=f"clouddep:{dep.tenant_id}:{dep.app}:{suffix}",
        data_class=dep.data_class,
    )


def _observed_at(dep: ServiceDependency) -> datetime:
    return dep.observed_at or datetime(1970, 1, 1, tzinfo=timezone.utc)


def _talks_to(flows: tuple[FlowEdge, ...], tenant: str, min_bytes: float) -> dict[tuple[str, str], float]:
    """Volume-weighted directed adjacency for ONE tenant: {(src, dst) -> bytes}
    for every flow at/above the volume floor. The key is the ORDERED (src, dst)
    tuple — direction matters, and a plain tuple can never collide the way an
    unordered/sentinel key could (a frozenset both loses order and would collide
    with an endpoint literally named like the sentinel)."""
    out: dict[tuple[str, str], float] = {}
    for f in flows:
        if f.tenant_id != tenant or not f.src or not f.dst:
            continue
        if f.byte_count < min_bytes:
            continue
        key = (f.src, f.dst)
        out[key] = out.get(key, 0.0) + float(f.byte_count)
    return out


def _edge_observed(a: DependencyTier, b: DependencyTier, talks: dict[tuple[str, str], float]) -> bool:
    """Did flow telemetry witness traffic from tier a to tier b? Matches by either
    resource id or address (a flow record may carry either)."""
    a_ids = {x for x in (a.resource_id, a.address) if x}
    b_ids = {x for x in (b.resource_id, b.address) if x}
    return any((sa, sb) in talks for sa in a_ids for sb in b_ids)


def _build_endpoints(dep: ServiceDependency) -> dict[str, Endpoint]:
    """One Endpoint per tier that has an address, keyed by role. Binds the address
    to the tier's resource (rank-2 identity), in the service's network context."""
    eps: dict[str, Endpoint] = {}
    for t in dep.ordered_tiers():
        if not t.address:
            continue
        ctx = t.network_context or dep.network_context
        eps[t.role] = Endpoint(
            endpoint_id=f"clouddep-ep:{dep.tenant_id}:{t.resource_id}",
            tenant_id=dep.tenant_id,
            address=t.address,
            network_context=ctx,
            kind=_KIND_OF_ROLE.get(t.role, "unknown"),
            resolved_entity_ref=t.resource_id,
            resolution_method=ResolutionMethod.ENDPOINT_BINDING.value,
            confidence=Confidence.AUTHORITATIVE.value,
            valid_from=None,
            evidence_ref=dep.evidence_ref or f"clouddep-ep:{dep.tenant_id}:{t.resource_id}",
            prov=_prov(dep, f"ep:{t.resource_id}"),
        )
    return eps


def _build_routes(dep: ServiceDependency) -> list[RouteRelation]:
    """The INFERRED (rank 6) config-dependency edges: every upstream tier → the app,
    plus consecutive tier → tier for the spine. These say the config puts the device
    on the app's path — enough to GROUND the fault to the app (so it is named), never
    enough to CONFIRM (§4: config is not observation)."""
    at = _observed_at(dep)
    tiers = dep.ordered_tiers()
    routes: list[RouteRelation] = []
    # upstream device → the terminal app (the pairwise edge the engine correlates on)
    for t in tiers:
        if t.role == "app":
            continue
        routes.append(RouteRelation(
            tenant_id=dep.tenant_id,
            from_ref=t.resource_id,
            to_ref=dep.app,
            relation=_RELATION_OF_ROLE.get(t.role, "depends_on"),
            network_context=t.network_context or dep.network_context,
            evidence_ref=dep.evidence_ref or f"clouddep-rt:{dep.tenant_id}:{t.resource_id}->{dep.app}",
            observed_at=at,
            prov=_prov(dep, f"rt:{t.resource_id}->{dep.app}"),
        ))
    # tier → next tier (the ordered spine, for rendering / walk order)
    for a, b in itertools.pairwise(tiers):
        to_ref = dep.app if b.role == "app" else b.resource_id
        routes.append(RouteRelation(
            tenant_id=dep.tenant_id,
            from_ref=a.resource_id,
            to_ref=to_ref,
            relation="fronts",
            network_context=a.network_context or dep.network_context,
            evidence_ref=dep.evidence_ref or f"clouddep-rt:{dep.tenant_id}:{a.resource_id}->{to_ref}",
            observed_at=at,
            prov=_prov(dep, f"rt:{a.resource_id}->{to_ref}"),
        ))
    return routes


def _build_observation(
    dep: ServiceDependency, eps: dict[str, Endpoint], talks: dict,
) -> PathObservation | None:
    """An OBSERVED path (rank 3) over the data-path tiers, built ONLY when flow
    telemetry witnessed every consecutive data-path edge into the app. This is what
    promotes the tier↔app dependency from inferred (suspected) to authoritative
    (confirmable). Returns None when flow does not confirm the chain — honest: no
    observation is invented, the edge stays inferred."""
    data_tiers = [t for t in dep.ordered_tiers() if t.role in _DATA_PATH_ROLES]
    if len(data_tiers) < 2:
        return None  # nothing to observe (need at least an upstream tier + the app)
    if not all(t.address for t in data_tiers):
        return None  # a data-path hop with no address cannot be an observed hop
    # every consecutive data-path pair must be witnessed by flow volume
    if not all(_edge_observed(a, b, talks) for a, b in itertools.pairwise(data_tiers)):
        return None
    at = _observed_at(dep)
    hops: list[PathHop] = []
    for i, t in enumerate(data_tiers, start=1):
        transformation = (Transformation.LOAD_BALANCER.value if t.role == "lb"
                          else Transformation.NONE.value)
        hops.append(PathHop(
            hop_index=i,
            state="responding",
            observed_address=t.address,
            resolved_entity_ref=t.resource_id,
            resolution_method=ResolutionMethod.HOP_INVENTORY.value,
            confidence=Confidence.STRONG.value,
            transformation=transformation,
            evidence_ref=dep.evidence_ref or f"clouddep-hop:{dep.tenant_id}:{t.resource_id}",
            observed_at=at,
            tenant_id=dep.tenant_id,
        ))
    app_tier = data_tiers[-1]
    ctx = app_tier.network_context or dep.network_context
    pid = f"clouddep-path:{dep.tenant_id}:{dep.app}"
    return PathObservation(
        observation_id=f"clouddep-obs:{dep.tenant_id}:{dep.app}",
        path_id=pid,
        tenant_id=dep.tenant_id,
        observed_at=at,
        method="flow_stitch",
        vantage_id="cloud-flow",
        status="complete",
        hops=tuple(hops),
        prov=_prov(dep, "obs"),
        definition=PathDefinition(
            path_id=pid, tenant_id=dep.tenant_id,
            src_endpoint_ref=eps.get(data_tiers[0].role, Endpoint(
                "", dep.tenant_id, "", ctx)).endpoint_id,
            dst_endpoint_ref=eps.get("app", Endpoint("", dep.tenant_id, "", ctx)).endpoint_id,
            direction="forward", protocol="tcp", dst_port=443,
            vantage_id="cloud-flow", network_context=ctx,
        ),
    )


def _build_binding(dep: ServiceDependency, eps: dict[str, Endpoint]) -> ServiceBinding | None:
    """The app → its endpoint (rank 4, observed). This — not a token — is what lets
    the app symptom (a NAME) resolve onto the request path."""
    app_ep = eps.get("app")
    if app_ep is None:
        return None
    return ServiceBinding(
        service_ref=dep.app,
        endpoint_ref=app_ep.endpoint_id,
        tenant_id=dep.tenant_id,
        evidence_ref=dep.evidence_ref or f"clouddep-svc:{dep.tenant_id}:{dep.app}",
        confidence=Confidence.STRONG.value,
        valid_from=None,
        prov=_prov(dep, "svc"),
    )


def build_dependency_view(
    services: list[ServiceDependency] | tuple[ServiceDependency, ...],
    flows: list[FlowEdge] | tuple[FlowEdge, ...] = (),
    *,
    min_flow_bytes: float = 1.0,
    freshness_s: float = DEFAULT_FRESHNESS_S,
) -> PathGraphView:
    """Build the tenant-scoped cloud dependency view (Endpoints + ServiceBindings +
    inferred RouteRelations + observed PathObservations) from cloud inventory + flow
    telemetry. Pure and deterministic.

    Records whose tenant is empty are DROPPED (fail-closed — no global dependency
    edges). Every emitted object carries its own tenant_id, so the engine's
    ``for_tenant`` makes cross-tenant resolution structurally impossible."""
    flows_t = tuple(flows)
    endpoints: list[Endpoint] = []
    bindings: list[ServiceBinding] = []
    observations: list[PathObservation] = []
    routes: list[RouteRelation] = []
    for dep in services:
        if not dep.tenant_id or not dep.app or not dep.tiers:
            continue  # fail-closed: no tenant / no app / no tiers ⇒ no edges
        talks = _talks_to(flows_t, dep.tenant_id, min_flow_bytes)
        eps = _build_endpoints(dep)
        endpoints.extend(eps.values())
        routes.extend(_build_routes(dep))
        binding = _build_binding(dep, eps)
        if binding is not None:
            bindings.append(binding)
        obs = _build_observation(dep, eps, talks)
        if obs is not None:
            observations.append(obs)
    return PathGraphView(
        endpoints=tuple(endpoints),
        observations=tuple(observations),
        service_bindings=tuple(bindings),
        routes=tuple(routes),
        freshness_s=freshness_s,
    )


def merge_path_views(*views: PathGraphView) -> PathGraphView:
    """Fold several PathGraphViews into one (e.g. the Go-exported inventory view +
    this module's cloud dependency view). Freshness is the tightest (smallest) of
    the inputs — a stricter budget never loosens by merging."""
    fresh = min((v.freshness_s for v in views), default=DEFAULT_FRESHNESS_S)
    return PathGraphView(
        endpoints=tuple(e for v in views for e in v.endpoints),
        observations=tuple(o for v in views for o in v.observations),
        service_bindings=tuple(b for v in views for b in v.service_bindings),
        nat_sessions=tuple(n for v in views for n in v.nat_sessions),
        routes=tuple(r for v in views for r in v.routes),
        freshness_s=fresh,
    )


# ── wire adapter (enrichment JSON → typed inputs) ─────────────────────────────


def _tier_from_dict(d: dict) -> DependencyTier:
    return DependencyTier(
        role=str(d.get("role", "")),
        resource_id=str(d.get("resource_id", "")),
        address=str(d.get("address", "")),
        network_context=str(d.get("network_context", "")),
    )


def service_from_dict(d: dict) -> ServiceDependency:
    """One enrichment record → a ServiceDependency. Tenancy is the CALLER's job (an
    inventory record carries an explicit tenant_id)."""
    from producers import (
        parse_event_ts,  # local import: pure builder stays import-light
    )

    tiers = tuple(_tier_from_dict(t) for t in (d.get("tiers") or ()) if t.get("resource_id"))
    return ServiceDependency(
        tenant_id=str(d.get("tenant_id", "")),
        app=str(d.get("app", "")),
        tiers=tiers,
        network_context=str(d.get("network_context", "cloud")),
        provider=str(d.get("provider", "")),
        evidence_ref=str(d.get("evidence_ref", "")),
        observed_at=parse_event_ts(d.get("observed_at")),
        data_class=str(d.get("data_class", DataClass.LIVE.value)),
    )


def flow_from_dict(d: dict) -> FlowEdge:
    def _num(v: object) -> float:
        try:
            return float(v)  # type: ignore[arg-type]
        except (TypeError, ValueError):
            return 0.0

    return FlowEdge(
        tenant_id=str(d.get("tenant_id", "")),
        src=str(d.get("src", "")),
        dst=str(d.get("dst", "")),
        byte_count=_num(d.get("byte_count", d.get("bytes", 0))),
    )


def build_from_records(raw: dict, *, min_flow_bytes: float = 1.0) -> PathGraphView:
    """Enrichment-file dict → cloud dependency view. Shape:
    ``{"services": [ {tenant_id, app, tiers:[{role,resource_id,address}], ...} ],
       "flows": [ {tenant_id, src, dst, byte_count} ]}``.
    Malformed records are skipped (never a crash) — the builder fails closed."""
    services = [service_from_dict(s) for s in (raw.get("services") or []) if isinstance(s, dict)]
    flows = [flow_from_dict(f) for f in (raw.get("flows") or []) if isinstance(f, dict)]
    return build_dependency_view(services, flows, min_flow_bytes=min_flow_bytes)
