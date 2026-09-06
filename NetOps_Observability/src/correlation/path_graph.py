# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Service Path Graph — the explicit, ranked, tenant-scoped relationship model
(docs/design/service-path-graph-contract.md v1.0, contract_version = 1).

THIS REPLACES TOKEN OVERLAP AS THE BASIS OF EDGE ADMISSION.

The engine's old gate admitted an edge when two nodes shared *any* string (a
token), shared a seam endpoint VALUE, or were LLDP-adjacent. Token overlap is a
coincidence detector: it cannot express a validity window, a direction, a NAT
transition or a tenant, and two tenants that share an address produce a false
edge. Worse, it is structurally incapable of relating a cloud application node
(whose tokens are application NAMES) to a network node (whose tokens are
addresses and device names) — the sets never intersect, so cloud RCA could
never leave its 2-node silo.

What replaces it (§3): a RANKED relationship lookup over first-class objects —
Endpoints (an address BOUND to an entity, in a network context, over a time
window), PathDefinitions, immutable PathObservations and ordered PathHops,
application→endpoint service bindings, flow/NAT sessions, and (inferred) cloud
route relations.

    rank 1  resource identity          observed   → authoritative
    rank 2  endpoint / seam binding    observed   → authoritative
    rank 3  path-hop inventory / link  observed   → authoritative
    rank 4  application→endpoint       observed   → authoritative
    rank 5  flow / NAT session stitch  observed   → authoritative
    rank 6  cloud route / BGP / policy INFERRED   → supporting only, never confirms
    rank 7  shared token / rDNS / name CANDIDATE  → NEVER authoritative

Every relation states its evidence (§5): evidence_ref, observation_method,
confidence, observed_at, data_class. A relation that cannot state its evidence
is not returned — the caller then has no edge.

Purity is the replay contract: no IO, no wall clock, no randomness. The view an
object grounded against is embedded in its snapshot, exactly like SeamView.
"""

from __future__ import annotations

import json
import os
from collections import OrderedDict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum

CONTRACT_VERSION = 1

# An observation older than this, relative to the evidence window it is asked to
# explain, is STALE: it may still support, but it can never anchor a live verdict
# (§8 "stale observations").
DEFAULT_FRESHNESS_S = 900.0


# ── §1 provenance ────────────────────────────────────────────────────────────


class DataClass(str, Enum):
    LIVE = "live"
    SYNTHETIC = "synthetic"
    REPLAY = "replay"
    LAB = "lab"


# Ordered by "distance from live" — the worst (highest) wins when evidence mixes,
# so one lab record can never be laundered into a live verdict by live company.
_DATA_CLASS_SEVERITY: dict[str, int] = {
    DataClass.LIVE.value: 0,
    DataClass.REPLAY.value: 1,
    DataClass.SYNTHETIC.value: 2,
    DataClass.LAB.value: 3,
}


def worst_data_class(values: list[str] | tuple[str, ...]) -> str:
    """The least-live data_class present. Unknown strings fail CLOSED (treated as
    lab — the most restrictive), never silently as live."""
    worst = DataClass.LIVE.value
    for v in values:
        sev = _DATA_CLASS_SEVERITY.get(str(v), _DATA_CLASS_SEVERITY[DataClass.LAB.value])
        if sev > _DATA_CLASS_SEVERITY[worst]:
            worst = str(v) if str(v) in _DATA_CLASS_SEVERITY else DataClass.LAB.value
    return worst


def is_live(data_class: str) -> bool:
    return data_class == DataClass.LIVE.value


@dataclass(frozen=True)
class Provenance:
    """§1 — immutable, set at creation, never rewritten. `provenance_id` IS the
    evidence handle every edge must be able to state."""

    tenant_id: str
    producer_id: str
    provenance_id: str
    data_class: str = DataClass.LIVE.value
    environment: str = "prod"
    scenario_id: str = ""
    run_id: str = ""

    @classmethod
    def from_dict(cls, d: dict) -> Provenance:
        return cls(
            tenant_id=str(d.get("tenant_id", "")),
            producer_id=str(d.get("producer_id", "")),
            provenance_id=str(d.get("provenance_id", "")),
            data_class=str(d.get("data_class", DataClass.LIVE.value)),
            environment=str(d.get("environment", "prod")),
            scenario_id=str(d.get("scenario_id", "")),
            run_id=str(d.get("run_id", "")),
        )

    def to_dict(self) -> dict:
        return {
            "tenant_id": self.tenant_id, "producer_id": self.producer_id,
            "provenance_id": self.provenance_id, "data_class": self.data_class,
            "environment": self.environment, "scenario_id": self.scenario_id,
            "run_id": self.run_id,
        }


# ── §3 resolution ranking / §4 observed vs inferred ──────────────────────────


class ResolutionMethod(str, Enum):
    RESOURCE_IDENTITY = "resource_identity"          # rank 1
    ENDPOINT_BINDING = "endpoint_binding"            # rank 2
    SEAM_MEMBERSHIP = "seam_membership"              # rank 2 (declared seam inventory)
    HOP_INVENTORY = "hop_inventory"                  # rank 3
    TOPOLOGY_LINK = "topology_link"                  # rank 3 (LLDP/CDP/BGP-LS link)
    APP_ENDPOINT_BINDING = "app_endpoint_binding"    # rank 4
    FLOW_NAT_STITCH = "flow_nat_stitch"              # rank 5
    CLOUD_ROUTE = "cloud_route"                      # rank 6 — INFERRED
    SHARED_TOKEN = "shared_token"                    # rank 7 — CANDIDATE ONLY
    # ── wireless (#128 Phase 3, docs/Wireslessdesign.md §8.2) ────────────────
    WIRELESS_CONTAINMENT = "wireless_containment"    # rank 1: radio/BSSID within AP
    AP_UPLINK_BINDING = "ap_uplink_binding"          # rank 1: AP ↔ its switchport (the LAN join)
    WIRELESS_ASSOCIATION = "wireless_association"    # rank 3: observed L2 association (device/controller-reported)
    CAPWAP_TUNNEL_BINDING = "capwap_tunnel_binding"  # rank 3: observed tunnel endpoint pair
    WIRELESS_POLICY_RELATION = "wireless_policy_relation"  # rank 6 — INFERRED: WLAN→VLAN says
    # traffic SHOULD land there; only a flow/lease says it DID. An object held
    # together only by wireless configuration can never be confirmed.


RANK: dict[str, int] = {
    ResolutionMethod.RESOURCE_IDENTITY.value: 1,
    ResolutionMethod.ENDPOINT_BINDING.value: 2,
    ResolutionMethod.SEAM_MEMBERSHIP.value: 2,
    ResolutionMethod.HOP_INVENTORY.value: 3,
    ResolutionMethod.TOPOLOGY_LINK.value: 3,
    ResolutionMethod.APP_ENDPOINT_BINDING.value: 4,
    ResolutionMethod.FLOW_NAT_STITCH.value: 5,
    ResolutionMethod.CLOUD_ROUTE.value: 6,
    ResolutionMethod.SHARED_TOKEN.value: 7,
    ResolutionMethod.WIRELESS_CONTAINMENT.value: 1,
    ResolutionMethod.AP_UPLINK_BINDING.value: 1,
    ResolutionMethod.WIRELESS_ASSOCIATION.value: 3,
    ResolutionMethod.CAPWAP_TUNNEL_BINDING.value: 3,
    ResolutionMethod.WIRELESS_POLICY_RELATION.value: 6,
}


class EvidenceClass(str, Enum):
    OBSERVED = "observed"      # data plane — may establish an edge and (with an
                               # independent second observer) a confirmed verdict
    INFERRED = "inferred"      # control plane — supporting/explanatory ONLY
    CANDIDATE = "candidate"    # coincidence — never authoritative, never confirms


def evidence_class_of(method: str) -> str:
    r = RANK.get(method, 7)
    if r <= 5:
        return EvidenceClass.OBSERVED.value
    if r == 6:
        return EvidenceClass.INFERRED.value
    return EvidenceClass.CANDIDATE.value


class Confidence(str, Enum):
    AUTHORITATIVE = "authoritative"
    STRONG = "strong"
    CANDIDATE = "candidate"
    UNKNOWN = "unknown"


_CONF_RANK = {
    Confidence.AUTHORITATIVE.value: 3, Confidence.STRONG.value: 2,
    Confidence.CANDIDATE.value: 1, Confidence.UNKNOWN.value: 0,
}


def weakest_confidence(a: str, b: str) -> str:
    """A chain is only as strong as its weakest explicit link."""
    return a if _CONF_RANK.get(a, 0) <= _CONF_RANK.get(b, 0) else b


# ── §5 edge types ────────────────────────────────────────────────────────────


class EdgeType(str, Enum):
    PATH_HAS_HOP = "PATH_HAS_HOP"
    HOP_RESOLVES_TO = "HOP_RESOLVES_TO"
    CROSSES_SEAM = "CROSSES_SEAM"
    TERMINATES_AT_ENDPOINT = "TERMINATES_AT_ENDPOINT"
    ENDPOINT_HOSTED_ON = "ENDPOINT_HOSTED_ON"
    SERVICE_EXPOSED_BY_ENDPOINT = "SERVICE_EXPOSED_BY_ENDPOINT"
    EVIDENCE_SUPPORTS = "EVIDENCE_SUPPORTS"
    EVIDENCE_CONTRADICTS = "EVIDENCE_CONTRADICTS"
    EVIDENCE_MISSING = "EVIDENCE_MISSING"
    # ── wireless (#128 Phase 3, docs/Wireslessdesign.md §8.1) ────────────────
    # corr_path_edges.edge_type is LowCardinality(String): NO schema migration.
    # AP_MANAGED_BY_CONTROLLER (control/management association) and
    # AP_TUNNELS_TO_CONTROLLER (client DATA encapsulation) are DIFFERENT edges:
    # in local switching the first exists and the second does not — and its
    # absence is a fact of the deployment, never missing evidence.
    AP_UPLINKS_VIA_PORT = "AP_UPLINKS_VIA_PORT"
    RADIO_ON_AP = "RADIO_ON_AP"
    BSSID_ON_RADIO = "BSSID_ON_RADIO"
    BSSID_SERVES_WLAN = "BSSID_SERVES_WLAN"
    WLAN_BROADCASTS_SSID = "WLAN_BROADCASTS_SSID"
    CLIENT_ASSOCIATED_TO_BSSID = "CLIENT_ASSOCIATED_TO_BSSID"
    SESSION_OF_CLIENT = "SESSION_OF_CLIENT"
    AP_MANAGED_BY_CONTROLLER = "AP_MANAGED_BY_CONTROLLER"
    AP_TUNNELS_TO_CONTROLLER = "AP_TUNNELS_TO_CONTROLLER"
    CONTROLLER_MEMBER_OF_CLUSTER = "CONTROLLER_MEMBER_OF_CLUSTER"
    SESSION_AUTHENTICATED_BY = "SESSION_AUTHENTICATED_BY"
    MLO_LINK_OF_SESSION = "MLO_LINK_OF_SESSION"


class HopState(str, Enum):
    RESPONDING = "responding"
    MISSING = "missing"
    FILTERED = "filtered"


class Transformation(str, Enum):
    NONE = "none"
    NAT = "nat"
    PROXY = "proxy"
    LOAD_BALANCER = "load_balancer"
    TUNNEL_INGRESS = "tunnel_ingress"
    TUNNEL_EGRESS = "tunnel_egress"


# Endpoint kind → the boundary the renderer groups by (§7 boundaries are computed
# SERVER-side; the UI never guesses them).
BOUNDARY_OF_KIND: dict[str, str] = {
    "client": "LAN",
    "lan_gateway": "LAN",
    # #128 (owner ruling 2026-07-26): wired and wireless are ONE LAN domain —
    # wireless hops render inside the LAN boundary group, no separate WIRELESS
    # zone. The endpoint `kind` still distinguishes them for fault localization.
    "wireless_client": "LAN",
    "wireless_access": "LAN",
    "wan_edge": "SD-WAN",
    "transit": "CARRIER",
    "nva": "CLOUD",
    "cloud_edge": "CLOUD",
    "app_endpoint": "CLOUD",
    "service_endpoint": "CLOUD",
    "unknown": "UNKNOWN",
}


def _dt(v) -> datetime | None:
    if v is None or v == "":
        return None
    if isinstance(v, datetime):
        return v if v.tzinfo else v.replace(tzinfo=timezone.utc)
    # _iso() emits a tz-aware isoformat ("…+00:00"); parse the FULL inverse so a
    # path-graph datetime round-trips (blob → replay). fromisoformat handles the
    # offset (Python 3.11 also handles "Z"; normalize it here for 3.10). The
    # strptime fallback is for legacy CH strings that carry no offset.
    s = str(v).strip().replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(s)
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except ValueError:
        s2 = s.replace("T", " ")
        s2 = s2.removesuffix("+00:00")
        fmt = "%Y-%m-%d %H:%M:%S.%f" if "." in s2 else "%Y-%m-%d %H:%M:%S"
        return datetime.strptime(s2, fmt).replace(tzinfo=timezone.utc)


def _iso(v: datetime | None) -> str:
    return v.astimezone(timezone.utc).isoformat() if v else ""


# ── §2 entities ──────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Endpoint:
    """§2.1 — a BINDING of an address to an entity, within a network context, over
    a time window. NOT merely an IP: the same address in two tenants is two
    Endpoints and they never join."""

    endpoint_id: str
    tenant_id: str
    address: str
    network_context: str                     # REQUIRED — an address alone is meaningless
    kind: str = "unknown"
    address_family: str = "ipv4"
    resolved_entity_ref: str = ""
    resolution_method: str = ResolutionMethod.ENDPOINT_BINDING.value
    confidence: str = Confidence.STRONG.value
    valid_from: datetime | None = None
    valid_to: datetime | None = None         # None = currently valid
    evidence_ref: str = ""
    prov: Provenance | None = None

    def valid_at(self, when: datetime) -> bool:
        if self.valid_from and when < self.valid_from:
            return False
        return not (self.valid_to and when > self.valid_to)

    @classmethod
    def from_dict(cls, d: dict) -> Endpoint:
        return cls(
            endpoint_id=str(d["endpoint_id"]), tenant_id=str(d.get("tenant_id", "")),
            address=str(d.get("address", "")),
            network_context=str(d.get("network_context", "")),
            kind=str(d.get("kind", "unknown")),
            address_family=str(d.get("address_family", "ipv4")),
            resolved_entity_ref=str(d.get("resolved_entity_ref", "")),
            resolution_method=str(d.get("resolution_method",
                                        ResolutionMethod.ENDPOINT_BINDING.value)),
            confidence=str(d.get("confidence", Confidence.STRONG.value)),
            valid_from=_dt(d.get("valid_from")), valid_to=_dt(d.get("valid_to")),
            evidence_ref=str(d.get("evidence_ref", "")),
            prov=Provenance.from_dict(d["provenance"]) if d.get("provenance") else None,
        )

    def to_dict(self) -> dict:
        return {
            "endpoint_id": self.endpoint_id, "tenant_id": self.tenant_id,
            "address": self.address, "network_context": self.network_context,
            "kind": self.kind, "address_family": self.address_family,
            "resolved_entity_ref": self.resolved_entity_ref,
            "resolution_method": self.resolution_method, "confidence": self.confidence,
            "valid_from": _iso(self.valid_from), "valid_to": _iso(self.valid_to),
            "evidence_ref": self.evidence_ref,
            "provenance": self.prov.to_dict() if self.prov else None,
        }


@dataclass(frozen=True)
class PathDefinition:
    """§2.2 — path identity = (tenant, src, dst, direction, protocol, dst_port,
    vantage, network_context). Any difference is a DIFFERENT path: an ICMP path
    and a TCP:443 path to the same destination are not the same object and must
    be allowed to disagree (§8)."""

    path_id: str
    tenant_id: str
    src_endpoint_ref: str = ""
    dst_endpoint_ref: str = ""
    direction: str = "forward"
    protocol: str = "icmp"
    dst_port: int | None = None
    vantage_id: str = ""
    network_context: str = ""

    @classmethod
    def from_dict(cls, d: dict) -> PathDefinition:
        port = d.get("dst_port")
        return cls(
            path_id=str(d["path_id"]), tenant_id=str(d.get("tenant_id", "")),
            src_endpoint_ref=str(d.get("src_endpoint_ref", "")),
            dst_endpoint_ref=str(d.get("dst_endpoint_ref", "")),
            direction=str(d.get("direction", "forward")),
            protocol=str(d.get("protocol", "icmp")),
            dst_port=int(port) if port is not None and port != "" else None,
            vantage_id=str(d.get("vantage_id", "")),
            network_context=str(d.get("network_context", "")),
        )

    def to_dict(self) -> dict:
        return {
            "path_id": self.path_id, "tenant_id": self.tenant_id,
            "src_endpoint_ref": self.src_endpoint_ref,
            "dst_endpoint_ref": self.dst_endpoint_ref, "direction": self.direction,
            "protocol": self.protocol, "dst_port": self.dst_port,
            "vantage_id": self.vantage_id, "network_context": self.network_context,
        }


@dataclass(frozen=True)
class PathHop:
    """§2.4 — one ORDERED hop. A `missing`/`filtered` hop is a FACT about the path
    and is preserved: never dropped, never silently bridged."""

    hop_index: int                       # 1-based, ordered — spine order is DATA
    state: str = HopState.RESPONDING.value
    observed_address: str = ""           # empty when state != responding
    resolved_entity_ref: str = ""
    resolution_method: str = ResolutionMethod.HOP_INVENTORY.value
    confidence: str = Confidence.STRONG.value
    seam_id: str = ""
    rtt_ms: float | None = None
    transformation: str = Transformation.NONE.value
    evidence_ref: str = ""
    observed_at: datetime | None = None
    tenant_id: str = ""

    @property
    def responding(self) -> bool:
        return self.state == HopState.RESPONDING.value

    @classmethod
    def from_dict(cls, d: dict) -> PathHop:
        rtt = d.get("rtt_ms")
        return cls(
            hop_index=int(d["hop_index"]), state=str(d.get("state", HopState.RESPONDING.value)),
            observed_address=str(d.get("observed_address") or ""),
            resolved_entity_ref=str(d.get("resolved_entity_ref") or ""),
            resolution_method=str(d.get("resolution_method",
                                        ResolutionMethod.HOP_INVENTORY.value)),
            confidence=str(d.get("confidence", Confidence.STRONG.value)),
            seam_id=str(d.get("seam_id") or ""),
            rtt_ms=float(rtt) if rtt is not None and rtt != "" else None,
            transformation=str(d.get("transformation", Transformation.NONE.value)),
            evidence_ref=str(d.get("evidence_ref", "")),
            observed_at=_dt(d.get("observed_at")), tenant_id=str(d.get("tenant_id", "")),
        )

    def to_dict(self) -> dict:
        return {
            "hop_index": self.hop_index, "state": self.state,
            "observed_address": self.observed_address,
            "resolved_entity_ref": self.resolved_entity_ref,
            "resolution_method": self.resolution_method, "confidence": self.confidence,
            "seam_id": self.seam_id, "rtt_ms": self.rtt_ms,
            "transformation": self.transformation, "evidence_ref": self.evidence_ref,
            "observed_at": _iso(self.observed_at), "tenant_id": self.tenant_id,
        }


@dataclass(frozen=True)
class PathObservation:
    """§2.3 — IMMUTABLE, one per measurement run. Never updated in place: history
    IS the point (route changes). "Current path" is a QUERY, never a mutable row."""

    observation_id: str
    path_id: str
    tenant_id: str
    observed_at: datetime
    method: str = "traceroute_icmp"       # traceroute_icmp|traceroute_tcp|stamp|
                                          # transaction|flow_stitch
    vantage_id: str = ""
    status: str = "complete"              # complete|partial|failed
    hops: tuple[PathHop, ...] = ()
    prov: Provenance | None = None
    definition: PathDefinition | None = None

    @property
    def hop_count(self) -> int:
        return len(self.hops)

    @property
    def data_class(self) -> str:
        return self.prov.data_class if self.prov else DataClass.LIVE.value

    @property
    def evidence_ref(self) -> str:
        return self.prov.provenance_id if self.prov else ""

    def ordered_hops(self) -> tuple[PathHop, ...]:
        return tuple(sorted(self.hops, key=lambda h: h.hop_index))

    @classmethod
    def from_dict(cls, d: dict) -> PathObservation:
        return cls(
            observation_id=str(d["observation_id"]), path_id=str(d.get("path_id", "")),
            tenant_id=str(d.get("tenant_id", "")),
            observed_at=_dt(d.get("observed_at")) or datetime(1970, 1, 1, tzinfo=timezone.utc),
            method=str(d.get("method", "traceroute_icmp")),
            vantage_id=str(d.get("vantage_id", "")),
            status=str(d.get("status", "complete")),
            hops=tuple(PathHop.from_dict(h) for h in (d.get("hops") or ())),
            prov=Provenance.from_dict(d["provenance"]) if d.get("provenance") else None,
            definition=PathDefinition.from_dict(d["definition"]) if d.get("definition") else None,
        )

    def to_dict(self) -> dict:
        return {
            "observation_id": self.observation_id, "path_id": self.path_id,
            "tenant_id": self.tenant_id, "observed_at": _iso(self.observed_at),
            "method": self.method, "vantage_id": self.vantage_id, "status": self.status,
            "hop_count": self.hop_count,
            "hops": [h.to_dict() for h in self.ordered_hops()],
            "provenance": self.prov.to_dict() if self.prov else None,
            "definition": self.definition.to_dict() if self.definition else None,
            "contract_version": CONTRACT_VERSION,
        }


@dataclass(frozen=True)
class ServiceBinding:
    """§3 rank 4 — application/service → endpoint. Declared by the app's own agent
    registration, orchestration/deployment metadata, or telemetry that names its
    own listen endpoint. This — not a token — is what binds `store-api` to
    10.60.10.10."""

    service_ref: str                       # the application / service identity
    endpoint_ref: str                      # endpoint_id
    tenant_id: str
    evidence_ref: str = ""
    confidence: str = Confidence.STRONG.value
    valid_from: datetime | None = None
    valid_to: datetime | None = None
    prov: Provenance | None = None

    def valid_at(self, when: datetime) -> bool:
        if self.valid_from and when < self.valid_from:
            return False
        return not (self.valid_to and when > self.valid_to)

    @classmethod
    def from_dict(cls, d: dict) -> ServiceBinding:
        return cls(
            service_ref=str(d["service_ref"]), endpoint_ref=str(d["endpoint_ref"]),
            tenant_id=str(d.get("tenant_id", "")), evidence_ref=str(d.get("evidence_ref", "")),
            confidence=str(d.get("confidence", Confidence.STRONG.value)),
            valid_from=_dt(d.get("valid_from")), valid_to=_dt(d.get("valid_to")),
            prov=Provenance.from_dict(d["provenance"]) if d.get("provenance") else None,
        )

    def to_dict(self) -> dict:
        return {
            "service_ref": self.service_ref, "endpoint_ref": self.endpoint_ref,
            "tenant_id": self.tenant_id, "evidence_ref": self.evidence_ref,
            "confidence": self.confidence, "valid_from": _iso(self.valid_from),
            "valid_to": _iso(self.valid_to),
            "provenance": self.prov.to_dict() if self.prov else None,
        }


@dataclass(frozen=True)
class NatSession:
    """§3 rank 5 — a session record that ties pre- and post-translation tuples.
    The ONLY legal way to stitch across a NAT: never by address coincidence."""

    tenant_id: str
    pre_address: str
    post_address: str
    pre_context: str = ""
    post_context: str = ""
    protocol: str = ""
    evidence_ref: str = ""
    observed_at: datetime | None = None
    prov: Provenance | None = None

    @classmethod
    def from_dict(cls, d: dict) -> NatSession:
        return cls(
            tenant_id=str(d.get("tenant_id", "")), pre_address=str(d.get("pre_address", "")),
            post_address=str(d.get("post_address", "")),
            pre_context=str(d.get("pre_context", "")), post_context=str(d.get("post_context", "")),
            protocol=str(d.get("protocol", "")), evidence_ref=str(d.get("evidence_ref", "")),
            observed_at=_dt(d.get("observed_at")),
            prov=Provenance.from_dict(d["provenance"]) if d.get("provenance") else None,
        )

    def to_dict(self) -> dict:
        return {
            "tenant_id": self.tenant_id, "pre_address": self.pre_address,
            "post_address": self.post_address, "pre_context": self.pre_context,
            "post_context": self.post_context, "protocol": self.protocol,
            "evidence_ref": self.evidence_ref, "observed_at": _iso(self.observed_at),
            "provenance": self.prov.to_dict() if self.prov else None,
        }


@dataclass(frozen=True)
class RouteRelation:
    """§3 rank 6 — a cloud route table / UDR / BGP / SD-WAN policy relation.
    INFERRED (control plane): it may PREDICT an edge and EXPLAIN an observed one.
    It may NEVER alone assert that traffic took it, and never alone confirm."""

    tenant_id: str
    from_ref: str
    to_ref: str
    relation: str = "routes_via"           # routes_via | egresses_via | peers_with | …
    network_context: str = ""
    evidence_ref: str = ""
    observed_at: datetime | None = None
    prov: Provenance | None = None

    @classmethod
    def from_dict(cls, d: dict) -> RouteRelation:
        return cls(
            tenant_id=str(d.get("tenant_id", "")), from_ref=str(d.get("from_ref", "")),
            to_ref=str(d.get("to_ref", "")), relation=str(d.get("relation", "routes_via")),
            network_context=str(d.get("network_context", "")),
            evidence_ref=str(d.get("evidence_ref", "")), observed_at=_dt(d.get("observed_at")),
            prov=Provenance.from_dict(d["provenance"]) if d.get("provenance") else None,
        )

    def to_dict(self) -> dict:
        return {
            "tenant_id": self.tenant_id, "from_ref": self.from_ref, "to_ref": self.to_ref,
            "relation": self.relation, "network_context": self.network_context,
            "evidence_ref": self.evidence_ref, "observed_at": _iso(self.observed_at),
            "provenance": self.prov.to_dict() if self.prov else None,
        }


# ── the relation a lookup returns ────────────────────────────────────────────


@dataclass(frozen=True)
class Relation:
    """One explicit relationship between two graph nodes, WITH its evidence.
    §5: an edge that cannot state its evidence is not emitted — `evidence_ref`
    is mandatory (enforced in __post_init__)."""

    edge_type: str                    # EdgeType value, "" for structural containment
    method: str                       # ResolutionMethod value
    confidence: str                   # Confidence value
    evidence_ref: str                 # provenance_id / identity handle — MANDATORY
    observation_method: str           # traceroute_icmp | seam_inventory | …
    observed_at: str                  # ISO-8601, "" when identity-derived
    data_class: str = DataClass.LIVE.value
    ref: str = ""                     # the object that carries the relation
    seam_id: str = ""
    transformation: str = Transformation.NONE.value
    stale: bool = False               # §8 — outside its freshness window
    unknown_hops: tuple[int, ...] = ()  # missing/filtered hops inside the segment
    supporting_refs: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.evidence_ref:
            raise ValueError("Relation without evidence_ref (§5: an edge that cannot "
                             "state its evidence is not emitted)")

    @property
    def rank(self) -> int:
        return RANK.get(self.method, 7)

    @property
    def evidence_class(self) -> str:
        return evidence_class_of(self.method)

    @property
    def authoritative(self) -> bool:
        """§3: ONLY ranks 1–5 (observed) may be authoritative. Rank 6 is inferred
        (supporting), rank 7 is a candidate. A stale or low-confidence relation is
        never authoritative either — and neither is anything without evidence."""
        return (
            self.rank <= 5
            and self.evidence_class == EvidenceClass.OBSERVED.value
            and _CONF_RANK.get(self.confidence, 0) >= _CONF_RANK[Confidence.STRONG.value]
            and not self.stale
            and bool(self.evidence_ref)
        )

    def to_dict(self) -> dict:
        return {
            "edge_type": self.edge_type, "method": self.method, "rank": self.rank,
            "evidence_class": self.evidence_class, "confidence": self.confidence,
            "authoritative": self.authoritative, "evidence_ref": self.evidence_ref,
            "observation_method": self.observation_method, "observed_at": self.observed_at,
            "data_class": self.data_class, "ref": self.ref, "seam_id": self.seam_id,
            "transformation": self.transformation, "stale": self.stale,
            "unknown_hops": list(self.unknown_hops),
            "supporting_refs": list(self.supporting_refs),
            "contract_version": CONTRACT_VERSION,
        }


# TRACKER 156 memory forensics (2026-08-20). These relations are pure functions
# of their key and are built once per CANDIDATE PAIR, which is quadratic in the
# window. At the 85%-of-cap crossing on a 1k run, `shared_token_relation` and the
# Relation objects it returns accounted for 61.9 MB across ~800,000 blocks, and
# engine.py + path_graph.py together held 157.8 MB in 2,593,452 blocks — 85% of
# the traced heap. Relation is a frozen dataclass of scalars, so two calls with
# the same key are interchangeable by value and one instance is enough.
#
# Bounded per §9: the key derives from device-supplied tokens, so an unbounded
# map would be a memory amplifier reachable from untrusted input. On overflow the
# oldest entry is evicted and a fresh object is built — the cache is an
# allocation optimisation, never a correctness input.
RELATION_CACHE_MAX = int(os.environ.get("CORR_RELATION_CACHE_MAX", "50000"))
_SHARED_TOKEN_RELATIONS: OrderedDict[str, Relation] = OrderedDict()
_SEAM_RELATIONS: OrderedDict[tuple, Relation] = OrderedDict()
RELATION_CACHE_EVICTED = 0


def _cache_get(cache: OrderedDict, key, build):
    global RELATION_CACHE_EVICTED
    got = cache.get(key)
    if got is not None:
        cache.move_to_end(key)
        return got
    val = build()
    cache[key] = val
    if len(cache) > RELATION_CACHE_MAX:
        cache.popitem(last=False)
        RELATION_CACHE_EVICTED += 1
    return val


# The rank-7 relation the old gate used to treat as authoritative. Kept (an edge
# still forms, so an object is not lost) but DEMOTED and LABELLED: candidate,
# never authoritative, can never confirm a verdict.
def shared_token_relation(token: str) -> Relation:
    return _cache_get(_SHARED_TOKEN_RELATIONS, token, lambda: Relation(
        edge_type="", method=ResolutionMethod.SHARED_TOKEN.value,
        confidence=Confidence.CANDIDATE.value, evidence_ref=f"token:{token}",
        observation_method="name_similarity", observed_at="", ref=f"shared:{token}",
    ))


def resource_identity_relation(ref: str) -> Relation:
    """Rank 1 — the two nodes ARE the same resource (an interface and the device it
    is part of; two views of one device). The identity itself is the evidence."""
    return Relation(
        edge_type="", method=ResolutionMethod.RESOURCE_IDENTITY.value,
        confidence=Confidence.AUTHORITATIVE.value, evidence_ref=f"identity:{ref}",
        observation_method="resource_identity", observed_at="", ref=f"shared:{ref}",
    )


def topology_link_relation(lo: str, hi: str) -> Relation:
    """Rank 3 — an inventoried L2/L3 link (LLDP/CDP/BGP-LS), observed by the
    devices themselves."""
    return Relation(
        edge_type=EdgeType.HOP_RESOLVES_TO.value,
        method=ResolutionMethod.TOPOLOGY_LINK.value,
        confidence=Confidence.STRONG.value, evidence_ref=f"topology_link:{lo}--{hi}",
        observation_method="topology_link", observed_at="", ref=f"adj:{lo}--{hi}",
    )


def seam_relation(seam_id: str, structural: bool) -> Relation:
    """A declared seam instance. Rank 2 when BOTH nodes match the seam's endpoints
    by their structural identity (a real, declared binding); rank 7 CANDIDATE when
    the only thing matching is a free-text token — a name coincidence is not a
    seam membership.

    Interned by (seam_id, structural) — same reason as shared_token_relation: it
    is a pure function of its key, called once per candidate pair.
    """
    def build() -> Relation:
        if structural:
            return Relation(
                edge_type=EdgeType.CROSSES_SEAM.value,
                method=ResolutionMethod.SEAM_MEMBERSHIP.value,
                confidence=Confidence.STRONG.value, evidence_ref=f"seam:{seam_id}",
                observation_method="seam_inventory", observed_at="", ref=seam_id,
                seam_id=seam_id,
            )
        return Relation(
            edge_type="", method=ResolutionMethod.SHARED_TOKEN.value,
            confidence=Confidence.CANDIDATE.value, evidence_ref=f"seam_token:{seam_id}",
            observation_method="name_similarity", observed_at="", ref=seam_id,
            seam_id=seam_id,
        )

    return _cache_get(_SEAM_RELATIONS, (seam_id, structural), build)


# ── the view + the index ─────────────────────────────────────────────────────


@dataclass(frozen=True)
class PathGraphView:
    """The engine's read-model of the explicit relationship inventory, as supplied
    by the backend (contract §2/§7). Hashable + JSON-round-trippable, so a snapshot
    embeds exactly the view it grounded against (replay determinism, like SeamView).

    Empty view = the engine keeps its pre-contract behaviour minus authority:
    containment/adjacency/seam still ground; token overlap still forms an edge but
    is labelled candidate. No hidden dependency on live state."""

    endpoints: tuple[Endpoint, ...] = ()
    observations: tuple[PathObservation, ...] = ()
    service_bindings: tuple[ServiceBinding, ...] = ()
    nat_sessions: tuple[NatSession, ...] = ()
    routes: tuple[RouteRelation, ...] = ()
    freshness_s: float = DEFAULT_FRESHNESS_S

    def is_empty(self) -> bool:
        return not (self.endpoints or self.observations or self.service_bindings
                    or self.nat_sessions or self.routes)

    def for_tenant(self, tenant_id: str) -> PathGraphView:
        """§6 rule 1 / §9: the ONLY constructor the engine uses. Every object whose
        immutable tenant_id differs is dropped here — cross-tenant relation lookup is
        structurally impossible, not merely filtered later. Objects carrying an EMPTY
        tenant_id are dropped too (fail-closed: no 'global' path objects)."""
        return PathGraphView(
            endpoints=tuple(e for e in self.endpoints if e.tenant_id == tenant_id),
            observations=tuple(o for o in self.observations if o.tenant_id == tenant_id),
            service_bindings=tuple(b for b in self.service_bindings if b.tenant_id == tenant_id),
            nat_sessions=tuple(n for n in self.nat_sessions if n.tenant_id == tenant_id),
            routes=tuple(r for r in self.routes if r.tenant_id == tenant_id),
            freshness_s=self.freshness_s,
        )

    @classmethod
    def from_dict(cls, d: dict) -> PathGraphView:
        return cls(
            endpoints=tuple(Endpoint.from_dict(x) for x in (d.get("endpoints") or ())),
            observations=tuple(PathObservation.from_dict(x)
                               for x in (d.get("observations") or ())),
            service_bindings=tuple(ServiceBinding.from_dict(x)
                                   for x in (d.get("service_bindings") or ())),
            nat_sessions=tuple(NatSession.from_dict(x) for x in (d.get("nat_sessions") or ())),
            routes=tuple(RouteRelation.from_dict(x) for x in (d.get("routes") or ())),
            freshness_s=float(d.get("freshness_s", DEFAULT_FRESHNESS_S)),
        )

    def to_dict(self) -> dict:
        return {
            "endpoints": [e.to_dict() for e in sorted(self.endpoints,
                                                      key=lambda e: e.endpoint_id)],
            "observations": [o.to_dict() for o in sorted(self.observations,
                                                         key=lambda o: o.observation_id)],
            "service_bindings": [b.to_dict() for b in sorted(
                self.service_bindings, key=lambda b: (b.service_ref, b.endpoint_ref))],
            "nat_sessions": [n.to_dict() for n in sorted(
                self.nat_sessions, key=lambda n: (n.pre_address, n.post_address))],
            "routes": [r.to_dict() for r in sorted(self.routes,
                                                   key=lambda r: (r.from_ref, r.to_ref))],
            "freshness_s": self.freshness_s,
            "contract_version": CONTRACT_VERSION,
        }

    def blob(self) -> str:
        return json.dumps(self.to_dict(), separators=(",", ":"), sort_keys=True)


@dataclass(frozen=True)
class _Membership:
    """How ONE node is (explicitly) a member of ONE path observation."""

    observation: PathObservation
    hop_index: int
    method: str
    confidence: str
    evidence_ref: str
    network_context: str
    endpoint_id: str = ""
    is_service: bool = False


class PathIndex:
    """Tenant-scoped resolution over a PathGraphView (§3 ranking + §6 join rules).

    Pure: constructed from a view + a tenant, answers relate(...) with no IO and no
    wall clock. Freshness/staleness is judged against the CALLER's evidence window,
    never against `now` — so replay of a historical window is identical to the live
    run that produced it.
    """

    def __init__(self, view: PathGraphView, tenant_id: str) -> None:
        if not tenant_id:
            raise ValueError("PathIndex requires a tenant (§6 rule 1)")
        self.tenant_id = tenant_id
        # §6 rule 1 enforced at construction — nothing from another tenant is reachable.
        self.view = view.for_tenant(tenant_id)
        self._by_endpoint = {e.endpoint_id: e for e in self.view.endpoints}
        self._svc_by_service: dict[str, list[ServiceBinding]] = {}
        for b in self.view.service_bindings:
            self._svc_by_service.setdefault(b.service_ref, []).append(b)

    # ── NAT aliasing (rank 5): the ONLY legal cross-translation stitch ────────
    def _aliases(self, refs: frozenset[str], when: datetime
                 ) -> dict[str, tuple[str, str]]:
        """address → (evidence_ref, method) for addresses reachable from `refs`
        through an explicit NAT/flow session record that was valid AT `when`."""
        out: dict[str, tuple[str, str]] = {}
        fresh = self.view.freshness_s
        for n in self.view.nat_sessions:
            if not n.evidence_ref:
                continue
            # §6 rule 2 (compatible time ranges): a NAT translation is only valid
            # NEAR its observation time. After NAT-pool reuse the SAME pre<->post
            # pair maps a DIFFERENT inside host, so a session observed far from
            # `when` must not alias — otherwise it welds the wrong host onto the
            # path via an authoritative rank-5 stitch and can anchor a confirmed
            # verdict. Judged against the caller's evidence time, never the wall
            # clock, so replay is identical. Fail CLOSED when the session carries
            # no observation time (an untimed translation cannot be placed).
            if n.observed_at is None:
                continue
            if abs((when - n.observed_at).total_seconds()) > fresh:
                continue
            if n.pre_address and n.pre_address in refs and n.post_address:
                out[n.post_address] = (n.evidence_ref, ResolutionMethod.FLOW_NAT_STITCH.value)
            if n.post_address and n.post_address in refs and n.pre_address:
                out[n.pre_address] = (n.evidence_ref, ResolutionMethod.FLOW_NAT_STITCH.value)
        return out

    def _memberships(self, refs: frozenset[str], win: tuple[datetime, datetime],
                     path_ids: frozenset[str]) -> list[_Membership]:
        """Every explicit membership of a node (identified by its structural refs)
        in a path observation. NOTHING here uses free-text tokens."""
        out: list[_Membership] = []
        if not refs:
            return out
        for obs in sorted(self.view.observations, key=lambda o: o.observation_id):
            # §6 rule 5: a node that declares its own path_id may only join through
            # THAT path (a TCP:443 path and an ICMP path are different objects).
            if path_ids and obs.path_id not in path_ids:
                continue
            aliases = self._aliases(refs, obs.observed_at)
            all_refs = refs | frozenset(aliases)
            hop_of_address: dict[str, PathHop] = {}
            for hop in obs.ordered_hops():
                if hop.responding and hop.observed_address:
                    hop_of_address.setdefault(hop.observed_address, hop)
            best: _Membership | None = None

            def _offer(m: _Membership) -> None:
                nonlocal best
                if best is None or (RANK[m.method], m.hop_index) < (RANK[best.method], best.hop_index):
                    best = m

            # rank 3 — path-hop inventory resolution (hop → known entity / address)
            for hop in obs.ordered_hops():
                if not hop.responding:
                    continue
                hit = ""
                if hop.resolved_entity_ref and hop.resolved_entity_ref in all_refs:
                    hit = hop.resolved_entity_ref
                elif hop.observed_address and hop.observed_address in all_refs:
                    hit = hop.observed_address
                if not hit or not hop.evidence_ref:
                    continue
                method = ResolutionMethod.HOP_INVENTORY.value
                ev = hop.evidence_ref
                conf = hop.confidence
                if hit in aliases:                      # crossed an explicit NAT record
                    method = ResolutionMethod.FLOW_NAT_STITCH.value
                    ev = aliases[hit][0]
                _offer(_Membership(obs, hop.hop_index, method, conf, ev,
                                   network_context=self._context_of(obs, hop)))
            # rank 2 — endpoint binding (address bound to an entity, valid NOW-ish)
            for ep in sorted(self.view.endpoints, key=lambda e: e.endpoint_id):
                if not ep.valid_at(obs.observed_at) or not ep.evidence_ref:
                    continue
                if not ((ep.resolved_entity_ref and ep.resolved_entity_ref in all_refs)
                        or (ep.address and ep.address in all_refs)):
                    continue
                ep_hop = hop_of_address.get(ep.address)
                if ep_hop is None:
                    continue                            # the endpoint is not on this path
                _offer(_Membership(obs, ep_hop.hop_index,
                                   ResolutionMethod.ENDPOINT_BINDING.value,
                                   ep.confidence, ep.evidence_ref,
                                   network_context=ep.network_context, endpoint_id=ep.endpoint_id))
            # rank 4 — application → endpoint binding. THIS is how a cloud app node,
            # whose only identity is a NAME, reaches the path: not by token overlap.
            for ref in sorted(refs):
                for b in sorted(self._svc_by_service.get(ref, ()),
                                key=lambda b: b.endpoint_ref):
                    if not b.valid_at(obs.observed_at) or not b.evidence_ref:
                        continue
                    svc_ep = self._by_endpoint.get(b.endpoint_ref)
                    if svc_ep is None or not svc_ep.valid_at(obs.observed_at):
                        continue
                    svc_hop = hop_of_address.get(svc_ep.address)
                    if svc_hop is None:
                        continue
                    _offer(_Membership(obs, svc_hop.hop_index,
                                       ResolutionMethod.APP_ENDPOINT_BINDING.value,
                                       weakest_confidence(b.confidence, svc_ep.confidence),
                                       b.evidence_ref, network_context=svc_ep.network_context,
                                       endpoint_id=svc_ep.endpoint_id, is_service=True))
            if best is not None:
                out.append(best)
        return out

    def _context_of(self, obs: PathObservation, hop: PathHop) -> str:
        for ep in self.view.endpoints:
            if ep.address and ep.address == hop.observed_address:
                return ep.network_context
        return obs.definition.network_context if obs.definition else ""

    # ── §6: the join rules, applied to every candidate relation ──────────────
    def node_memberships(self, refs: frozenset[str],
                         window: tuple[datetime, datetime],
                         path_ids: frozenset[str] = frozenset(),
                         ) -> dict[str, _Membership]:
        """ONE node's explicit path-observation memberships, keyed by observation
        id. Pure and node-local, so the caller (build_edges) can compute it ONCE
        per node instead of once per PAIR — relate() is exactly
        relate_memberships(node_memberships(a), node_memberships(b), …)."""
        return {m.observation.observation_id: m
                for m in self._memberships(refs, window, path_ids)}

    def route_refs(self) -> frozenset[str]:
        """Every ref named by an evidence-bearing rank-6 route — the pruning
        surface for route-relatable candidate pairs. A pair where either side
        intersects none of these can never receive a route relation."""
        out: set[str] = set()
        for r in self.view.routes:
            if r.evidence_ref:
                out.add(r.from_ref)
                out.add(r.to_ref)
        return frozenset(out)

    def relate(self, a_refs: frozenset[str], b_refs: frozenset[str],
               a_window: tuple[datetime, datetime], b_window: tuple[datetime, datetime],
               a_paths: frozenset[str] = frozenset(),
               b_paths: frozenset[str] = frozenset()) -> Relation | None:
        """The strongest EXPLICIT relation between two nodes, or None.

        Never falls back to token overlap — the caller owns that (as a candidate).
        """
        return self.relate_memberships(
            self.node_memberships(a_refs, a_window, a_paths),
            self.node_memberships(b_refs, b_window, b_paths),
            a_refs, b_refs, a_window, b_window,
        )

    def relate_memberships(self, ma: dict[str, _Membership], mb: dict[str, _Membership],
                           a_refs: frozenset[str], b_refs: frozenset[str],
                           a_window: tuple[datetime, datetime],
                           b_window: tuple[datetime, datetime]) -> Relation | None:
        """relate() over PRECOMPUTED per-node memberships (see node_memberships).
        Byte-identical result to relate(); exists so an O(n²) pair loop does not
        recompute each node's memberships O(n) times."""
        best: Relation | None = None
        for oid in sorted(set(ma) & set(mb)):
            rel = self._relation_from(ma[oid], mb[oid], a_window, b_window)
            if rel is None:
                continue
            if best is None or _better(rel, best):
                best = rel
        if best is not None:
            return best
        # rank 6 — INFERRED cloud route / policy relation. Supporting only: it may
        # explain an observed edge and may predict one, but it can never assert that
        # traffic took it, and (verdict gate, engine) can never confirm alone.
        for r in sorted(self.view.routes, key=lambda r: (r.from_ref, r.to_ref)):
            if not r.evidence_ref:
                continue                     # no evidence ⇒ no edge (§5)
            if ((r.from_ref in a_refs and r.to_ref in b_refs)
                    or (r.from_ref in b_refs and r.to_ref in a_refs)):
                return Relation(
                    edge_type=EdgeType.EVIDENCE_SUPPORTS.value,
                    method=ResolutionMethod.CLOUD_ROUTE.value,
                    confidence=Confidence.STRONG.value, evidence_ref=r.evidence_ref,
                    observation_method=r.relation,
                    observed_at=_iso(r.observed_at),
                    data_class=r.prov.data_class if r.prov else DataClass.LIVE.value,
                    ref=f"route:{r.from_ref}->{r.to_ref}",
                )
        return None

    def _relation_from(self, a: _Membership, b: _Membership,
                       a_window: tuple[datetime, datetime],
                       b_window: tuple[datetime, datetime]) -> Relation | None:
        obs = a.observation
        if a.hop_index == b.hop_index and a.endpoint_id == b.endpoint_id:
            return None                       # the same hop is not a relation to itself
        lo, hi = sorted((a.hop_index, b.hop_index))
        segment = [h for h in obs.ordered_hops() if lo <= h.hop_index <= hi]
        # §8 — unknown hops are PRESERVED. A missing/filtered hop inside the segment is
        # carried on the relation (and rendered as an explicit unknown), never bridged.
        unknown = tuple(h.hop_index for h in segment if not h.responding)
        seam_id = next((h.seam_id for h in segment if h.seam_id), "")
        transformation = next((h.transformation for h in segment
                               if h.transformation and h.transformation != Transformation.NONE.value),
                              Transformation.NONE.value)
        # §6 rule 4 — compatible network context: differing contexts are legal ONLY
        # across an explicitly modelled seam or NAT/proxy/LB/tunnel transformation.
        if (a.network_context and b.network_context
                and a.network_context != b.network_context
                and not seam_id and transformation == Transformation.NONE.value):
            return None
        # §6 rule 2 — compatible time ranges, and §8 staleness: an observation outside
        # the freshness window of the evidence it is asked to explain is STALE. It is
        # still emitted (an honest, labelled supporting edge) but is NOT authoritative
        # and therefore cannot anchor a live verdict.
        win_start = min(a_window[0], b_window[0])
        win_end = max(a_window[1], b_window[1])
        fresh = timedelta(seconds=self.view.freshness_s)
        stale = not (win_start - fresh <= obs.observed_at <= win_end + fresh)
        method = a.method if RANK[a.method] >= RANK[b.method] else b.method  # weakest link
        confidence = weakest_confidence(a.confidence, b.confidence)
        edge_type = _edge_type(a, b, seam_id)
        return Relation(
            edge_type=edge_type, method=method, confidence=confidence,
            evidence_ref=obs.evidence_ref or a.evidence_ref,
            observation_method=obs.method, observed_at=_iso(obs.observed_at),
            data_class=obs.data_class, ref=obs.observation_id, seam_id=seam_id,
            transformation=transformation, stale=stale, unknown_hops=unknown,
            supporting_refs=tuple(sorted({a.evidence_ref, b.evidence_ref} - {""})),
        )


def _edge_type(a: _Membership, b: _Membership, seam_id: str) -> str:
    if seam_id:
        return EdgeType.CROSSES_SEAM.value
    if a.is_service or b.is_service:
        return EdgeType.SERVICE_EXPOSED_BY_ENDPOINT.value
    if a.endpoint_id or b.endpoint_id:
        return EdgeType.TERMINATES_AT_ENDPOINT.value
    return EdgeType.PATH_HAS_HOP.value


def _better(new: Relation, cur: Relation) -> bool:
    """Deterministic preference: stronger rank, then fresher, then non-stale,
    then observation id — never input order."""
    return (new.rank, new.stale, _neg_iso(new.observed_at), new.ref) < (
        cur.rank, cur.stale, _neg_iso(cur.observed_at), cur.ref)


def _neg_iso(s: str) -> str:
    # sort newer-first without arithmetic on strings: invert lexical order via a key
    return "".join(chr(0x10FFFF - ord(c)) if ord(c) < 0x10FFFF else c for c in s)


# ── §7 ordered spine (server-side; the UI is a dumb layout of this) ───────────


def spine_of(obs: PathObservation, view: PathGraphView) -> dict:
    """The ORDERED spine + typed edges + boundaries for ONE observation (§7).

    Hop order is DATA (hop_index), not layout. Missing/filtered hops are emitted as
    explicit `state: missing|filtered` entries with no address — never dropped and
    never bridged. Every entry and every edge carries its evidence block.
    """
    ep_by_addr = {e.address: e for e in view.endpoints if e.address}
    svc_by_ep: dict[str, list[str]] = {}
    for b in view.service_bindings:
        svc_by_ep.setdefault(b.endpoint_ref, []).append(b.service_ref)
    hops = obs.ordered_hops()
    spine: list[dict] = []
    edges: list[dict] = []
    for i, h in enumerate(hops):
        ep = ep_by_addr.get(h.observed_address) if h.observed_address else None
        kind = ep.kind if ep else "unknown"
        spine.append({
            "index": i,
            "kind": kind,
            "label": (h.resolved_entity_ref or h.observed_address
                      or f"unknown hop {h.hop_index}"),
            "address": h.observed_address,
            "boundary": BOUNDARY_OF_KIND.get(kind, "UNKNOWN"),
            "entity_ref": h.resolved_entity_ref,
            "state": h.state,
            "transformation": h.transformation,
            "seam_id": h.seam_id,
            "evidence": {
                "ref": h.evidence_ref, "method": obs.method, "confidence": h.confidence,
                "observed_at": _iso(h.observed_at or obs.observed_at),
                "data_class": obs.data_class,
            },
        })
        if i:
            prev = hops[i - 1]
            etype = (EdgeType.CROSSES_SEAM.value if (h.seam_id or prev.seam_id)
                     else EdgeType.PATH_HAS_HOP.value)
            if not h.responding or not prev.responding:
                etype = EdgeType.EVIDENCE_MISSING.value    # an honest absence IS an edge
            edges.append({
                "from": i - 1, "to": i, "type": etype,
                "seam_id": h.seam_id or prev.seam_id,
                "transformation": h.transformation,
                "evidence": {
                    "ref": obs.evidence_ref or h.evidence_ref, "method": obs.method,
                    "confidence": (Confidence.UNKNOWN.value if not h.responding
                                   else h.confidence),
                    "observed_at": _iso(obs.observed_at), "data_class": obs.data_class,
                },
            })
    # the terminal service, when an app is explicitly bound to the last endpoint
    last = hops[-1] if hops else None
    last_ep = ep_by_addr.get(last.observed_address) if (last and last.observed_address) else None
    if last_ep is not None:
        for svc in sorted(svc_by_ep.get(last_ep.endpoint_id, ())):
            # rank 4: the app is on the spine because a DECLARED binding puts it there.
            ev = next((b.evidence_ref for b in view.service_bindings
                       if b.service_ref == svc and b.endpoint_ref == last_ep.endpoint_id), "")
            if not ev:
                continue                       # §5 — no evidence, no edge, no node
            evidence = {
                "ref": ev, "method": ResolutionMethod.APP_ENDPOINT_BINDING.value,
                "confidence": Confidence.STRONG.value,
                "observed_at": _iso(obs.observed_at), "data_class": obs.data_class,
            }
            idx = len(spine)
            spine.append({
                "index": idx, "kind": "service", "label": svc, "address": "",
                "boundary": "CLOUD", "entity_ref": svc, "state": "responding",
                "transformation": Transformation.NONE.value, "seam_id": "",
                "evidence": evidence,
            })
            edges.append({
                "from": idx - 1, "to": idx,
                "type": EdgeType.SERVICE_EXPOSED_BY_ENDPOINT.value, "seam_id": "",
                "transformation": Transformation.NONE.value, "evidence": evidence,
            })
    boundaries: list[dict] = []
    for e in spine:
        if boundaries and boundaries[-1]["name"] == e["boundary"]:
            boundaries[-1]["to"] = e["index"]
        else:
            boundaries.append({"name": e["boundary"], "from": e["index"], "to": e["index"]})
    return {
        "path_id": obs.path_id, "observation_id": obs.observation_id,
        "observed_at": _iso(obs.observed_at), "method": obs.method,
        "vantage_id": obs.vantage_id, "status": obs.status,
        "data_class": obs.data_class, "contract_version": CONTRACT_VERSION,
        "spine": spine, "edges": edges, "boundaries": boundaries,
        "evidence_missing": [
            {"hop_index": h.hop_index, "state": h.state,
             "note": f"hop {h.hop_index} did not respond ({h.state}) — unknown segment preserved"}
            for h in hops if not h.responding
        ],
    }
