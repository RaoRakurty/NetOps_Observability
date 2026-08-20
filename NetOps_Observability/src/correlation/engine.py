"""Deterministic engine core — pipeline stages [3]–[7] of Correlation Engine v2
(#67 build ⑥). One pure function: a window of canonical Signals × the signature
catalog × the seam inventory → correlation-object snapshots.

PURITY IS THE REPLAY CONTRACT. No IO, no wall clock, no randomness, no dict-
order dependence: same inputs ⇒ byte-identical snapshots. ``engine_version``
pins the code semver + a content hash of every tunable constant, and each
snapshot embeds the grounding context (the seam views it grounded against), so
a stored object is re-runnable forever even after the live inventory evolves
(replay.py rehydrates the context from the snapshot, never from live state).

The owner's hard constraint is stage [4] and it NEVER relaxes: a pair of
episodes admits an edge ONLY with seam context or explicit topology grounding.
Ungrounded co-occurrences become counted topology-gap hints — never edges —
and the hints feed the seam bootstrap review queue (#68 §4.1, one workflow).
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import uuid
from collections import OrderedDict
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone

from catalog import Catalog
from directed_topology import Oracle, RecordingOracle
from directed_topology import Verdict as _Verdict
from layers import CausalLayer, layer_of, osi_label
from path_assembly import AssembledPath
from path_attribution import Attribution, object_attribution
from path_graph import (
    CONTRACT_VERSION,
    RANK,
    DataClass,
    EvidenceClass,
    PathGraphView,
    PathIndex,
    Relation,
    ResolutionMethod,
    is_live,
    resource_identity_relation,
    seam_relation,
    shared_token_relation,
    spine_of,
    topology_link_relation,
    worst_data_class,
)
from scoring import RankingResult, rank
from signals import SIGNAL_NS, EntityType, Severity, Signal, Source
from verdicts import Verdict as GateVerdict
from verdicts import VerdictTier

ENGINE_SEMVER = "3.1.0"  # 3.1.0: tracker 154 — (a) equal-confidence ranking ties break on
# grounded-seam-type affinity (the hypothesis whose declared seam scope matches the
# TYPE of the seam the object actually grounded on wins the tie; strictly-higher
# confidence is NEVER overridden, no seam ⇒ order unchanged); (b) same-window
# components whose entity sets are bridged THROUGH a shared grounded seam fold
# into ONE object, and the same seam-bridge criterion (plus window overlap)
# extends find_merges/find_continuation (cross-cycle) — both tenant-guarded.
# 3.0.0: Service Path Graph v1 — token overlap DEMOTED to rank-7
# candidate; edge admission is the ranked, evidence-bearing, tenant-scoped relationship
# gate (contract §3). Major bump: the meaning of an edge changed (an edge now carries a
# rank + an evidence block, and only ranks 1–5 may be authoritative).
# 2.2.0: C7.3 live directed-topology vote #2 (NetFlow) + adjacency/orientation embedding
# 2.1.0: C4 per-kind causal-layer direction prior (§4.3 vote #3)

# Default onset uncertainty when a signal does not carry one (episodes stamp
# attrs.onset_uncertainty_s; foreign signal kinds may not yet).
DEFAULT_ONSET_UNCERTAINTY_S = 15.0


@dataclass(frozen=True)
class EngineConfig:
    """Every tunable the core consumes. Members are part of the config hash —
    P4 replay-driven calibration re-fits them; they are never tuned silently."""

    tau_s: float = 300.0                  # temporal decay constant for w_temporal
    attach_threshold: float = 0.3         # min edge weight to admit into a component
    w_topo_seam: float = 0.8              # grounding via a seam instance
    w_topo_containment: float = 0.9       # grounding via same-device containment
    w_topo_adjacency: float = 0.65        # grounding via L2/L3 adjacency (§4.2 ladder)
    w_topo_path: float = 0.9              # OBSERVED explicit path relation (contract §3 ranks 1–5)
    w_topo_inferred: float = 0.5          # INFERRED control-plane relation (§3 rank 6, supporting)
    w_topo_candidate: float = 0.5         # §3 rank 7 CANDIDATE (shared token/rDNS/name): a weak
    #                                       grouping hint, NOT authoritative (the authoritative flag
    #                                       gates confirmation separately). At this weight the
    #                                       TEMPORAL DECAY is the discriminator: a legitimately
    #                                       related token pair minutes apart still groups, while an
    #                                       unrelated coincidence ~5 min apart falls below
    #                                       attach_threshold — instead of the old containment weight
    #                                       (0.9, the STRONGEST) that welded any name collision.
    w_topo_stale_cap: float = 0.4         # §8: cap w_topo when the topology view is stale
    reinforce_cross_modality: float = 1.25
    direction_conf: float = 0.8           # claimed only on 2-of-3 agreement
    severity_open_floor: str = "high"     # singleton episodes ≥ this open an object
    window_s: float = 900.0               # evidence window the caller buffers

    def config_hash(self) -> str:
        blob = json.dumps(
            {k: getattr(self, k) for k in sorted(self.__dataclass_fields__)},
            separators=(",", ":"), sort_keys=True,
        )
        return hashlib.sha256(blob.encode()).hexdigest()[:12]


def engine_version(cfg: EngineConfig) -> str:
    return f"{ENGINE_SEMVER}+cfg.{cfg.config_hash()}"


# ── seam views (grounding context) ────────────────────────────────────────────


@dataclass(frozen=True)
class SeamView:
    """The engine's read-model of one ACTIVE seam instance (#68 §4). Hashable
    and JSON-round-trippable: snapshots embed the views they grounded against."""

    seam_id: str
    tenant_id: str
    seam_type: str
    endpoints: tuple[tuple[str, str], ...]   # sorted (key, value) pairs
    visibility: str = "partial"
    control_plane_owner: str = "enterprise"

    @classmethod
    def from_dict(cls, d: dict) -> SeamView:
        eps = d.get("endpoints") or {}
        return cls(
            seam_id=str(d["seam_id"]),
            tenant_id=str(d.get("tenant_id", "")),
            seam_type=str(d.get("seam_type", "")),
            endpoints=tuple(sorted((str(k), str(v)) for k, v in eps.items() if v)),
            visibility=str(d.get("visibility", "partial")),
            control_plane_owner=str(d.get("control_plane_owner", "enterprise")),
        )

    def to_dict(self) -> dict:
        return {
            "seam_id": self.seam_id,
            "tenant_id": self.tenant_id,
            "seam_type": self.seam_type,
            "endpoints": {k: v for k, v in self.endpoints},
            "visibility": self.visibility,
            "control_plane_owner": self.control_plane_owner,
        }

    def endpoint_values(self) -> frozenset[str]:
        return frozenset(v for _, v in self.endpoints)


def seams_hash(seams: tuple[SeamView, ...]) -> str:
    """topology_version pin: content hash of the grounding context."""
    blob = json.dumps([s.to_dict() for s in sorted(seams, key=lambda s: s.seam_id)],
                      separators=(",", ":"), sort_keys=True)
    return "seams-" + hashlib.sha256(blob.encode()).hexdigest()[:12]


# ── episode nodes ─────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Node:
    """One graph node: the signals of one (entity, kind) within the window."""

    key: str                              # entity_type:entity_id:kind
    entity_type: EntityType
    entity_id: str
    kind: str
    signals: tuple[Signal, ...]           # sorted by (ts, signal_id)
    onset: datetime
    onset_uncertainty_s: float
    peak_severity: Severity

    def tokens(self) -> frozenset[str]:
        """Identity tokens for grounding: entity id, declared tokens, and the
        device part of a device-scoped id like 'dallas-edge:Gi0/1'.

        A shared measurement VANTAGE is deliberately NOT a grounding token: an
        observer probing two destinations does not make those destinations
        topologically related. Including it let the platform's own prober weld its
        self-monitoring (prober->nginx, prober->clickhouse) onto an unrelated
        customer incident via the shared `prober` token. So the vantage is excluded
        WHERE it appears as a vantage — the `A->B` probe prefix and declared
        entity_tokens — but never stripped from the entity's structural identity
        (its id and `device:iface` device-part), where the same name can legitimately
        be the SUBJECT (a device reporting its own interface).

        A cloud REGION/SITE is likewise NOT a grounding subject for a cloud-plane
        node. `site` = the region for every cloud signal, so two UNRELATED cloud
        resources in the same region (a different app's LB and this app's health)
        would weld on the region token alone — the coincidence detector the Service
        Path Graph contract exists to reject (a region is even coarser than a shared
        address). A cloud app/resource/service node therefore excludes `site`; it
        reaches its real edge devices through the dependency graph (routes/paths on
        its structural identity), never through 'same region'. Network nodes keep
        `site` (a physical site is a legitimate locality subject)."""
        observers = {s.observer.observer_id for s in self.signals if s.observer.observer_id}
        # Cloud-plane nodes: region/site is a coarse locality, not a topology subject.
        site_is_subject = self.entity_type not in (
            EntityType.APP, EntityType.CLOUD_RESOURCE, EntityType.SERVICE)
        toks = {self.entity_id}
        for s in self.signals:
            # entity_tokens can carry the measuring vantage (a probe's (prober, host));
            # the vantage is not a topology subject, the destination is.
            toks.update(t for t in s.entity_tokens if t not in observers)
            if s.site and site_is_subject:
                toks.add(s.site)
        if ":" in self.entity_id:
            toks.add(self.entity_id.split(":", 1)[0])  # device-part is always a subject
        if "->" in self.entity_id:
            # Left of a probe path is the vantage (== observer); drop it. A real
            # network segment (observer is a separate agent) keeps both endpoints.
            toks.update(p for p in self.entity_id.split("->") if p and p not in observers)
        return frozenset(toks)

    def identity_refs(self) -> frozenset[str]:
        """The node's STRUCTURAL identity — the refs an explicit relationship may be
        looked up by (contract §3): its entity id, the device part of a device-scoped
        id, the endpoints of a segment id, and the typed form `entity_type:entity_id`
        (how cloud/path inventory names a resource).

        Deliberately EXCLUDES free-text `entity_tokens` and `site`: those are the
        rank-7 coincidence surface and may never resolve an endpoint, a hop or a seam
        membership. `tokens()` (below) keeps them — but only as candidates."""
        refs = {self.entity_id, f"{self.entity_type.value}:{self.entity_id}"}
        observers = {s.observer.observer_id for s in self.signals if s.observer.observer_id}
        dp = self.device_part()
        if dp:
            refs.add(dp)
        if "->" in self.entity_id:
            # the left side of a probe path is the VANTAGE (== observer), not a subject.
            refs.update(p for p in self.entity_id.split("->") if p and p not in observers)
        return frozenset(r for r in refs if r)

    def declared_path_ids(self) -> frozenset[str]:
        """§6 rule 5 — a signal that declares its own path_id may only join through
        THAT path: a TCP:443 path and an ICMP path to the same destination are
        different objects and must be allowed to disagree (§8)."""
        return frozenset(s.path_id for s in self.signals if s.path_id)

    def window(self) -> tuple[datetime, datetime]:
        """The node's activity interval [onset … last signal] — the time range every
        join is checked against (§6 rule 2)."""
        return (self.onset, self.signals[-1].ts)

    def data_class(self) -> str:
        """§1 — the least-live data_class among this node's signals. Absent ⇒ live
        (every pre-contract producer is a live producer); an explicit synthetic/lab/
        replay stamp propagates and blocks confirmation."""
        return worst_data_class([
            str(s.attrs.get("data_class", DataClass.LIVE.value))
            if isinstance(s.attrs, dict) else DataClass.LIVE.value
            for s in self.signals
        ])

    def device_part(self) -> str | None:
        """The single device this node sits on, for L2/L3 adjacency grounding:
        'leaf1:Ethernet1' → 'leaf1'; a bare device id → itself; a path/segment
        ('a->b') has no single device → None.

        Wireless (#128): AP / controller / client entities are device-like —
        a bare 'ap-<id>' is its own device token, and 'ap-<id>:radio0' splits
        to 'ap-<id>' like any device:component id. The '-' joins (never ':')
        so the domain prefix stays part of the token — 'ap:<id>' would ground
        every AP in the estate to the literal token 'ap' (the #99 weld class;
        regression-tested in wireless/identity_test.go)."""
        eid = self.entity_id
        if "->" in eid:
            return None
        if ":" in eid:
            return eid.split(":", 1)[0]
        if self.entity_type in (EntityType.DEVICE, EntityType.INTERFACE,
                                EntityType.ACCESS_POINT, EntityType.WIRELESS_CONTROLLER,
                                EntityType.WIRELESS_CLIENT):
            return eid
        return None


_SEV_RANK = {Severity.INFO: 0, Severity.WARN: 1, Severity.HIGH: 2, Severity.CRIT: 3}


def build_nodes(window: tuple[Signal, ...]) -> tuple[Node, ...]:
    by_key: dict[str, list[Signal]] = {}
    for s in window:
        if s.kind.endswith("_clear"):
            continue  # clears close episodes; they are not evidence nodes
        if s.source is Source.APP_IDENTITY:
            continue  # #81 P5: identity is ENRICHMENT, never a graph node — it can
            # never seed/extend an object (AD-5 "NO separate app RCA"). It is matched
            # in as an app-impact PROJECTION on objects real faults already formed.
        by_key.setdefault(f"{s.entity_type.value}:{s.entity_id}:{s.kind}", []).append(s)
    nodes = []
    for key in sorted(by_key):
        sigs = tuple(sorted(by_key[key], key=lambda s: (s.ts, str(s.signal_id))))
        unc = max(
            (float(s.attrs.get("onset_uncertainty_s", DEFAULT_ONSET_UNCERTAINTY_S)) for s in sigs),
            default=DEFAULT_ONSET_UNCERTAINTY_S,
        )
        first = sigs[0]
        nodes.append(Node(
            key=key,
            entity_type=first.entity_type,
            entity_id=first.entity_id,
            kind=first.kind,
            signals=sigs,
            onset=first.ts,
            onset_uncertainty_s=unc,
            peak_severity=max((s.severity for s in sigs), key=lambda v: _SEV_RANK[v]),
        ))
    return tuple(nodes)


# The resolution methods that come FROM a path observation (as opposed to identity,
# seam inventory or an LLDP link) — i.e. the ones whose `ref` is an observation_id.
_PATH_OBSERVATION_METHODS = frozenset({
    ResolutionMethod.ENDPOINT_BINDING.value,
    ResolutionMethod.HOP_INVENTORY.value,
    ResolutionMethod.APP_ENDPOINT_BINDING.value,
    ResolutionMethod.FLOW_NAT_STITCH.value,
})


def RANK_OBSERVED_PATH(method: str) -> bool:  # uppercase: rung constant that reads as a predicate
    return method in _PATH_OBSERVATION_METHODS


# ── stage [4]: the grounding gate ─────────────────────────────────────────────


@dataclass(frozen=True)
class Grounding:
    """Why an edge exists. `kind`/`ref` are the FROZEN corr_edges columns
    (Enum8('seam','topo') + a non-empty ref); `relation` is the contract's explicit,
    ranked, evidence-bearing relationship (§3/§5) — the thing that actually decides
    whether this edge may be treated as authoritative. It is carried in memory, in
    the snapshot blob and in the typed edge row; it does NOT overload grounding_ref
    (the corr_edges migration that gives it its own columns is stated in the report)."""

    kind: str   # 'seam' | 'topo'  (CH grounding_kind enum; adjacency rides 'topo')
    ref: str    # seam_id | 'shared:<token>' (containment) | 'adj:<a>--<b>' | 'path:<obs>'
    relation: Relation | None = None


    @property
    def authoritative(self) -> bool:
        """No relation ⇒ NOT authoritative (fail-closed). Rank 6 (inferred) and
        rank 7 (candidate) are never authoritative — §3."""
        return self.relation is not None and self.relation.authoritative

    @property
    def rank(self) -> int:
        return self.relation.rank if self.relation else 7

    @property
    def evidence_class(self) -> str:
        return (self.relation.evidence_class if self.relation
                else EvidenceClass.CANDIDATE.value)

    @property
    def data_class(self) -> str:
        return self.relation.data_class if self.relation else DataClass.LIVE.value


# TRACKER 156 (2026-08-20). These two Groundings are pure functions of a token or
# seam id and were constructed once per CANDIDATE PAIR — quadratic in the window.
# At the 85%-of-cap crossing on a 1k run, engine.py:745 (the Grounding) and
# path_graph.py:675-678 (the Relation inside it) held 92.9 MB across ~1,600,000
# blocks; engine.py + path_graph.py together were 157.8 MB, 85% of the traced
# heap. Grounding is frozen and the Relation it wraps is interned too, so one
# instance per key is enough.
#
# Bounded per §9: the keys derive from device-supplied tokens, so an unbounded
# map would be a memory amplifier reachable from untrusted input. On overflow the
# oldest entry is evicted and a fresh object is built — an allocation
# optimisation, never a correctness input.
GROUNDING_CACHE_MAX = int(os.environ.get("CORR_GROUNDING_CACHE_MAX", "50000"))
_SHARED_TOKEN_GROUNDINGS: OrderedDict[str, Grounding] = OrderedDict()
_SEAM_TOKEN_GROUNDINGS: OrderedDict[str, Grounding] = OrderedDict()
GROUNDING_CACHE_EVICTED = 0


def _grounding_cached(cache: OrderedDict, key: str, build) -> Grounding:
    global GROUNDING_CACHE_EVICTED
    got = cache.get(key)
    if got is not None:
        cache.move_to_end(key)
        return got
    val = build()
    cache[key] = val
    if len(cache) > GROUNDING_CACHE_MAX:
        cache.popitem(last=False)
        GROUNDING_CACHE_EVICTED += 1
    return val


def _shared_token_grounding(tok: str) -> Grounding:
    return _grounding_cached(
        _SHARED_TOKEN_GROUNDINGS, tok,
        lambda: Grounding("topo", "shared:" + tok, shared_token_relation(tok)))


def _seam_token_grounding(seam_id: str) -> Grounding:
    return _grounding_cached(
        _SEAM_TOKEN_GROUNDINGS, seam_id,
        lambda: Grounding("seam", seam_id, seam_relation(seam_id, False)))


@dataclass(frozen=True)
class TopologyAdjacency:
    """Undirected L2/L3 device adjacency, learned from LLDP/CDP/BGP-LS and exported
    by the Go backend (/api/topology/links → topology_links.json). This is the
    grounding input the §4.2 'L2/L3 adjacent device' rung needs: it lets two signals
    on DIFFERENT devices ground when those devices are a known link (fabric flap,
    IGP adjacency). Empty = no adjacency (the gate then admits only seam/containment,
    same as before — backward compatible)."""

    pairs: frozenset[frozenset[str]] = frozenset()

    def adjacent(self, a: str, b: str) -> bool:
        return a != b and frozenset({a, b}) in self.pairs

    @staticmethod
    def from_links(links: list[dict] | tuple[dict, ...]) -> TopologyAdjacency:
        out: set[frozenset[str]] = set()
        for link in links or ():
            a, b = str(link.get("a") or ""), str(link.get("b") or "")
            if a and b and a != b:
                out.add(frozenset({a, b}))
        return TopologyAdjacency(frozenset(out))


# Shared empty-adjacency default. TopologyAdjacency is a frozen dataclass, so one
# module-level instance is safe to share across every signature that defaults to
# "no adjacency" (B008: no constructor calls in argument defaults).
NO_ADJACENCY = TopologyAdjacency()


def resolve_grounding(
    a: Node, b: Node, seams: tuple[SeamView, ...],
    adjacency: TopologyAdjacency = NO_ADJACENCY,
    paths: PathIndex | None = None,
) -> Grounding | None:
    """The RANKED relationship gate (contract §3) — this REPLACES token-overlap
    admission.

    OLD (forbidden): first shared token wins → Grounding('topo', 'shared:<tok>'),
    treated as fully authoritative. Any single coincidental string admitted an edge,
    and a cloud APP node (application-name tokens) could never intersect a network
    node (addresses/device names) — so no cloud↔network edge could ever form.

    NEW: the strongest EXPLICIT relationship wins, in rank order:

      rank 1  same resource identity (device containment)              observed
      rank 2  seam membership by structural identity / endpoint binding observed
      rank 3  path-hop inventory resolution · L2/L3 topology link       observed
      rank 4  application → endpoint binding                           observed
      rank 5  flow / NAT session stitch                                observed
      rank 6  cloud route / BGP / SD-WAN policy relation               INFERRED
      rank 7  shared token / name similarity                           CANDIDATE

    Ranks 1–5 may be authoritative. Rank 6 supports but never asserts that traffic
    took the path and never confirms alone. Rank 7 is KEPT (so an object still
    forms) but DEMOTED and LABELLED — `Grounding.authoritative` is False and the
    verdict gate in run_window() refuses to confirm on it.

    Every relation states its evidence (§5); one that cannot is not returned.
    Deterministic: paths by observation id, seams by seam_id, tokens by min()."""
    # ranks 1–5 (explicit path/endpoint/service/NAT relationships) ─────────────
    if paths is not None:
        rel = paths.relate(
            a.identity_refs(), b.identity_refs(), a.window(), b.window(),
            a.declared_path_ids(), b.declared_path_ids(),
        )
        if rel is not None and rel.rank <= 5:
            return Grounding("topo", f"path:{rel.ref}", rel)
    # rank 2 — seam membership. STRUCTURAL identity only (entity id / device part /
    # segment endpoint): matching a seam endpoint against a free-text token is a name
    # coincidence, not a membership, and is demoted to rank 7 below.
    ia, ib = a.identity_refs(), b.identity_refs()
    ta, tb = a.tokens(), b.tokens()
    token_seam: SeamView | None = None
    for seam in sorted(seams, key=lambda s: s.seam_id):
        ev = seam.endpoint_values() | {seam.seam_id}
        if (ia & ev) and (ib & ev):
            return Grounding("seam", seam.seam_id, seam_relation(seam.seam_id, True))
        if token_seam is None and (ta & ev) and (tb & ev):
            token_seam = seam
    # rank 1 — resource identity: an interface/path on the SAME device as the peer
    # (the shared ref is a structural identity of both, not a declared label).
    shared_ident = ia & ib
    if shared_ident:
        ref = min(sorted(shared_ident))
        return Grounding("topo", "shared:" + ref, resource_identity_relation(ref))
    # rank 3 — L2/L3 adjacency: two DIFFERENT devices joined by an inventoried link
    # (LLDP/CDP/BGP-LS), observed by the devices themselves.
    da, db = a.device_part(), b.device_part()
    if da and db and adjacency.adjacent(da, db):
        lo, hi = sorted((da, db))
        return Grounding("topo", f"adj:{lo}--{hi}", topology_link_relation(lo, hi))
    # rank 6 — INFERRED (cloud route / policy). Supporting only.
    if paths is not None:
        rel = paths.relate(ia, ib, a.window(), b.window(),
                           a.declared_path_ids(), b.declared_path_ids())
        if rel is not None:
            return Grounding("topo", f"route:{rel.ref}", rel)
    # rank 7 — CANDIDATE ONLY. A shared token (or a seam matched only by a token) is
    # a coincidence detector: no validity window, no direction, no NAT, no tenancy.
    # It still forms an edge (an object is not lost) but it is never authoritative.
    if token_seam is not None:
        return Grounding("seam", token_seam.seam_id,
                         seam_relation(token_seam.seam_id, False))
    shared = ta & tb
    if shared:
        tok = min(sorted(shared))
        return Grounding("topo", "shared:" + tok, shared_token_relation(tok))
    return None


# ── edges ─────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Edge:
    from_node: str
    to_node: str
    grounding: Grounding
    weight: float
    w_temporal: float
    w_topo: float
    w_reinforce: float
    direction_conf: float    # 0 = undirected co-occurrence
    direction_basis: str     # onset_order+layer_prior | mixed | none

    def to_ch_row(self, tenant_id: str, correlation_id: str, version: int) -> dict:
        return {
            "tenant_id": tenant_id,
            "correlation_id": correlation_id,
            "version": version,
            "from_node": self.from_node,
            "to_node": self.to_node,
            "grounding_kind": self.grounding.kind,
            "grounding_ref": self.grounding.ref,
            "weight": round(self.weight, 4),
            "w_temporal": round(self.w_temporal, 4),
            "w_topo": round(self.w_topo, 4),
            "w_reinforce": round(self.w_reinforce, 4),
            "direction_conf": round(self.direction_conf, 4),
            "direction_basis": self.direction_basis,
        }

    def to_typed_row(self, tenant_id: str, correlation_id: str, version: int) -> dict:
        """The contract §5 edge: an explicit type + the evidence block every edge
        MUST carry (evidence_ref, observation_method, confidence, observed_at,
        data_class). Written to the corr_edges v2 columns (migration stated in the
        report); until they exist this is the in-memory/API shape and is embedded in
        the snapshot's grounding context. An edge that cannot state its evidence is
        never produced — Relation enforces that at construction."""
        rel = self.grounding.relation
        row = {
            "tenant_id": tenant_id,
            "correlation_id": correlation_id,
            "version": version,
            "from_node": self.from_node,
            "to_node": self.to_node,
            "grounding_kind": self.grounding.kind,
            "grounding_ref": self.grounding.ref,
            "contract_version": CONTRACT_VERSION,
        }
        row.update(rel.to_dict() if rel else {
            "edge_type": "", "method": ResolutionMethod.SHARED_TOKEN.value, "rank": 7,
            "evidence_class": EvidenceClass.CANDIDATE.value, "confidence": "unknown",
            "authoritative": False, "evidence_ref": "", "observation_method": "",
            "observed_at": "", "data_class": DataClass.LIVE.value,
        })
        return row


# OSI-flavored layer prior over entity types: lower layers cause higher ones.
# (#81 P3G) APP is the top of the stack (application symptom); a CLOUD_RESOURCE
# (LB/DB/compute dependency) sits below the app it serves — so "DB saturation
# → app 5xx" orders correctly. Coarse fallback only; the finer per-kind
# layers.py map drives direction when both kinds are mapped.
_LAYER = {
    EntityType.DEVICE: 0, EntityType.INTERFACE: 0,
    EntityType.PREFIX: 1, EntityType.SITE: 1,
    EntityType.PATH: 2, EntityType.SEGMENT: 2, EntityType.CLOUD_RESOURCE: 2,
    EntityType.SERVICE: 3, EntityType.APP: 3,
}


def _direction(a: Node, b: Node, cfg: EngineConfig,
               directed: Oracle | None = None) -> tuple[float, str]:
    """2-of-3 to claim (§4.3): onset order + OSI layer prior + topology up/down.
    `a precedes b` (a is from_node). Each vote either agrees with a→b, conflicts
    (→ mixed/none), or abstains. The topology vote (#2) is supplied by the
    DirectedTopology oracle (C7); with no oracle / no covering source it abstains —
    exactly the pre-C7 behavior — so direction is only ever claimed it can support."""
    votes = []
    gap = (b.onset - a.onset).total_seconds()
    if gap > a.onset_uncertainty_s + b.onset_uncertainty_s:
        votes.append("onset_order")
    # Layer prior (vote #3): prefer the FINER per-kind causal layer (C4 — distinguishes
    # L2 link from L3 routing on the same DEVICE entity, which the entity-type layer
    # can't). Fall back to the coarse entity-type layer when either kind is unmapped, so
    # both nodes are always compared on ONE consistent scale (backward-compatible).
    ka, kb = layer_of(a.signals[0].kind), layer_of(b.signals[0].kind)
    if ka is not None and kb is not None:
        la, lb = int(ka), int(kb)
    else:
        la, lb = _LAYER[a.entity_type], _LAYER[b.entity_type]
    if la < lb:
        votes.append("layer_prior")
    elif la > lb:
        # Layer prior points the other way: conflict with a→b → mixed.
        return (0.0, "mixed") if votes else (0.0, "none")
    # Topology up/down (vote #2): measured/observed direction between the two devices.
    if directed is not None:
        o = directed.orient(a.device_part(), b.device_part())
        if o.verdict is _Verdict.A_UPSTREAM:
            votes.append("topo_updown")          # a upstream of b agrees with a→b
        elif o.verdict is _Verdict.B_UPSTREAM:
            return (0.0, "mixed") if votes else (0.0, "none")  # conflicts with a→b
        # AMBIGUOUS / UNKNOWN → abstain (no vote), honestly
    if len(votes) >= 2:
        return cfg.direction_conf, "+".join(votes)
    return 0.0, "none"


def _candidate_pairs(
    n: int,
    toks: list[frozenset[str]],
    refs: list[frozenset[str]],
    seam_evs: list[frozenset[str]],
    devs: list[str | None],
    adjacency: TopologyAdjacency,
    memb: list[dict] | None,
    route_hits: list[bool] | None,
) -> set[tuple[int, int]]:
    """The SOUND candidate superset for resolve_grounding: every pair NOT in this
    set is guaranteed to ground to None (each grounding rung requires one of the
    overlaps indexed here), so pruning changes operation count only — never the
    admitted edges or the gap-hint total. Derivation, rung by rung:

      ranks 1–6 via PathIndex.relate  → shared observation membership, or both
                                        sides touching an evidence-bearing route ref
      rank 2/7 seam membership        → both sides intersect one seam's
                                        endpoint-values ∪ {seam_id} (by identity
                                        refs OR tokens — both are indexed)
      rank 1 shared resource identity → identity_refs overlap (⊆ token∪ref index:
                                        every identity ref except the typed
                                        `type:id` form is also a token, and a
                                        shared typed form implies a shared id)
      rank 3 L2/L3 adjacency          → device pair in the adjacency inventory
      rank 7 shared token             → tokens overlap

    Pure + deterministic: derived only from the same inputs resolve_grounding
    reads; the returned pair set is order-independent."""
    cand: set[tuple[int, int]] = set()

    def _link(members: list[int]) -> None:
        for x in range(len(members)):
            for y in range(x + 1, len(members)):
                a, b = members[x], members[y]
                if a != b:
                    cand.add((a, b) if a < b else (b, a))

    # tokens ∪ identity refs (covers ranks 1, 7 and feeds the seam groups)
    index: dict[str, list[int]] = {}
    for i in range(n):
        for t in toks[i] | refs[i]:
            index.setdefault(t, []).append(i)
    for members in index.values():
        if len(members) > 1:
            _link(members)
    # seam groups: all nodes matching one seam's endpoint values / seam_id
    for ev in seam_evs:
        group = sorted({m for v in ev for m in index.get(v, ())})
        if len(group) > 1:
            _link(group)
    # L2/L3 adjacency: nodes on the two ends of an inventoried link
    dev_index: dict[str, list[int]] = {}
    for i, d in enumerate(devs):
        if d:
            dev_index.setdefault(d, []).append(i)
    for pair in adjacency.pairs:
        ends = sorted(pair)
        if len(ends) != 2:
            continue
        for i in dev_index.get(ends[0], ()):
            for j in dev_index.get(ends[1], ()):
                if i != j:
                    cand.add((i, j) if i < j else (j, i))
    # path relations: shared observation membership; route-touching nodes
    if memb is not None:
        obs_index: dict[str, list[int]] = {}
        for i, m in enumerate(memb):
            for oid in m:
                obs_index.setdefault(oid, []).append(i)
        for members in obs_index.values():
            if len(members) > 1:
                _link(members)
    if route_hits is not None:
        routed = [i for i in range(n) if route_hits[i]]
        _link(routed)
    return cand


def build_edges(
    nodes: tuple[Node, ...], seams: tuple[SeamView, ...], cfg: EngineConfig,
    adjacency: TopologyAdjacency = NO_ADJACENCY,
    topology_stale: bool = False,
    directed: Oracle | None = None,
    paths: PathIndex | None = None,
) -> tuple[tuple[Edge, ...], int]:
    """Returns (admitted edges, topology_gap_hints). Pairs are evaluated in
    deterministic node order; the earlier-onset node is always from_node.

    PERFORMANCE SHAPE (the #151-adjacent perf fix): the naive form recomputed
    tokens()/identity_refs()/path memberships and re-sorted the seams for every
    PAIR (~100µs/pair ⇒ ~48s synchronous at 1k nodes). Everything node-local is
    now precomputed ONCE per node, the seams are sorted once, and only pairs the
    inverted token/identity/seam/adjacency/observation index says are plausibly
    relatable are scored at all (_candidate_pairs is a sound superset, so the
    admitted edges and the gap-hint count are byte-identical to the naive loop —
    pinned by test_engine_complexity.py against a brute-force reference).
    Purity is untouched: no IO, no clock, no dict-order dependence."""
    n = len(nodes)
    if n < 2:
        return (), 0
    # ── per-node precomputation (node-local, pure) ────────────────────────────
    toks = [nd.tokens() for nd in nodes]
    refs = [nd.identity_refs() for nd in nodes]
    declared = [nd.declared_path_ids() for nd in nodes]
    windows = [nd.window() for nd in nodes]
    devs = [nd.device_part() for nd in nodes]
    seams_sorted = tuple(sorted(seams, key=lambda s: s.seam_id))
    seam_evs = [s.endpoint_values() | {s.seam_id} for s in seams_sorted]
    # per-node seam memberships, by STRUCTURAL identity and by token (rank 2 vs 7)
    seam_ident = [frozenset(k for k, ev in enumerate(seam_evs) if refs[i] & ev)
                  for i in range(n)]
    seam_token = [frozenset(k for k, ev in enumerate(seam_evs) if toks[i] & ev)
                  for i in range(n)]
    memb: list[dict] | None = None
    route_hits: list[bool] | None = None
    if paths is not None:
        memb = [paths.node_memberships(refs[i], windows[i], declared[i])
                for i in range(n)]
        rrefs = paths.route_refs()
        route_hits = [bool(refs[i] & rrefs) for i in range(n)]

    def _grounded(ai: int, bi: int) -> Grounding | None:
        """resolve_grounding over the precomputed per-node views — same rungs,
        same order, same tie-breaks (min seam ordinal == first seam in seam_id
        order; relate_memberships ≡ relate)."""
        rel = None
        if paths is not None and memb is not None:
            rel = paths.relate_memberships(memb[ai], memb[bi], refs[ai], refs[bi],
                                           windows[ai], windows[bi])
            if rel is not None and rel.rank <= 5:
                return Grounding("topo", f"path:{rel.ref}", rel)
        # rank 2 — seam membership by structural identity (first seam in seam_id order)
        ident_both = seam_ident[ai] & seam_ident[bi]
        if ident_both:
            seam = seams_sorted[min(ident_both)]
            return Grounding("seam", seam.seam_id, seam_relation(seam.seam_id, True))
        # rank 1 — shared resource identity
        shared_ident = refs[ai] & refs[bi]
        if shared_ident:
            ref = min(sorted(shared_ident))
            return Grounding("topo", "shared:" + ref, resource_identity_relation(ref))
        # rank 3 — L2/L3 adjacency
        da, db = devs[ai], devs[bi]
        if da and db and adjacency.adjacent(da, db):
            lo, hi = sorted((da, db))
            return Grounding("topo", f"adj:{lo}--{hi}", topology_link_relation(lo, hi))
        # rank 6 — INFERRED route (the SAME deterministic relate result as above:
        # a rank ≤ 5 relation already returned, so only a route relation reaches here)
        if rel is not None:
            return Grounding("topo", f"route:{rel.ref}", rel)
        # rank 7 — candidate only: token-matched seam, then bare shared token
        token_both = seam_token[ai] & seam_token[bi]
        if token_both:
            seam = seams_sorted[min(token_both)]
            return _seam_token_grounding(seam.seam_id)
        shared = toks[ai] & toks[bi]
        if shared:
            tok = min(sorted(shared))
            return _shared_token_grounding(tok)
        return None

    edges: list[Edge] = []
    total_pairs = n * (n - 1) // 2
    grounded_pairs = 0
    for i, j in sorted(_candidate_pairs(n, toks, refs, seam_evs, devs, adjacency,
                                        memb, route_hits)):
        a, b = nodes[i], nodes[j]
        ai, bi = i, j
        if b.onset < a.onset or (b.onset == a.onset and b.key < a.key):
            a, b = b, a
            ai, bi = bi, ai
        grounding = _grounded(ai, bi)
        if grounding is None:
            continue
        grounded_pairs += 1
        # Temporal proximity is measured between the two nodes' ACTIVITY
        # INTERVALS [onset … last signal], not their onsets. A long-running
        # condition (e.g. a chronically flapping BGP session whose first sample
        # in the window is minutes old) must not be penalized against a recent
        # partner it OVERLAPS in time: onset-to-onset distance would decay the
        # edge below attach_threshold and split a real cross-modality
        # corroboration (customer-path probe ⟂ control-plane fault) into two
        # objects. Overlapping intervals → gap 0 → full temporal weight; the
        # grounding gate above still bounds WHICH pairs may edge at all.
        a_last, b_last = a.signals[-1].ts, b.signals[-1].ts
        gap = max(0.0, (max(a.onset, b.onset) - min(a_last, b_last)).total_seconds())
        w_t = math.exp(-gap / cfg.tau_s)
        rel = grounding.relation
        if rel is not None and rel.rank == 7:
            # §3 rank 7 — shared token / rDNS / name coincidence: CANDIDATE only,
            # the weakest relation there is. It used to fall through to the
            # containment branch (0.9, the STRONGEST weight) because rank-1
            # identity and rank-7 token BOTH emit a 'shared:<x>' ref, so the ref
            # prefix could not tell them apart — two unrelated cross-modality
            # episodes sharing one token welded together and inflated affected()
            # and merge Jaccard. Branch on the RANK the edge carries, not the ref.
            w_topo = cfg.w_topo_candidate
        elif grounding.ref.startswith("path:"):
            # An OBSERVED path relation (ranks 1–5): measured, evidence-bearing.
            w_topo = cfg.w_topo_path
        elif grounding.ref.startswith("route:"):
            # INFERRED (§4): a control-plane relation may support, never assert.
            w_topo = cfg.w_topo_inferred
        elif grounding.kind == "seam":
            w_topo = cfg.w_topo_seam
        elif grounding.ref.startswith("adj:"):
            w_topo = cfg.w_topo_adjacency
        else:
            w_topo = cfg.w_topo_containment
        # §8 degradation: a stale topology view (the Go exporter stopped
        # refreshing seams/links) means grounding resolves against a last-known
        # snapshot whose confidence has decayed — cap w_topo so a stale edge can
        # never weigh like a fresh one. The admission gate itself never relaxes.
        if topology_stale:
            w_topo = min(w_topo, cfg.w_topo_stale_cap)
        cross = a.signals[0].modality_class is not b.signals[0].modality_class
        w_r = cfg.reinforce_cross_modality if cross else 1.0
        weight = min(w_t * w_topo * w_r, 1.0)
        if weight < cfg.attach_threshold:
            continue
        conf, basis = _direction(a, b, cfg, directed)
        edges.append(Edge(a.key, b.key, grounding, weight, w_t, w_topo, w_r, conf, basis))
    # gap hints = pairs with NO grounding at all. Non-candidate pairs are
    # guaranteed-None (soundness above), so the count is exactly the naive loop's.
    gap_hints = total_pairs - grounded_pairs
    return tuple(sorted(edges, key=lambda e: (e.from_node, e.to_node))), gap_hints


# ── snapshots ─────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class ObjectSnapshot:
    """One correlation object at one engine evaluation — everything that
    renders into corr_objects/corr_edges/corr_evidence, plus the embedded
    grounding context that makes replay self-contained."""

    correlation_id: str
    tenant_id: str
    window_start: datetime
    window_end: datetime
    trigger_signal: str
    nodes: tuple[Node, ...]
    edges: tuple[Edge, ...]
    ranking: RankingResult
    seams: tuple[SeamView, ...]
    engine_ver: str
    topology_version: str
    gap_hints: int
    topology_stale: bool = False   # §8: scored against a stale topology view (w_topo capped)
    storm_mode: bool = False       # §8: scored under window-flood (maxlen eviction active)
    # C7: the directed-topology orientations this object's edges were built on —
    # (from_dev, to_dev, verdict, source). EMBEDDED in the snapshot so a directed
    # edge replays deterministically (reconstructed via frozen_oracle), exactly like
    # seams. Empty for undirected objects → blob byte-identical to pre-C7 (no churn).
    orientations: tuple[tuple, ...] = ()
    # C7: the adjacency pairs (component-scoped) this object's edges grounded on.
    # Embedded for the SAME reason seams are — an adjacency-grounded (fabric) edge
    # must replay against the same topology, not live links. Empty when no adjacency
    # grounding was used → blob unchanged (seam/containment objects never churn).
    adjacency_pairs: tuple[tuple[str, str], ...] = ()
    # #81 P5: fused application-identity signals (source=app_identity) whose tokens
    # overlap this object's nodes — the ENRICHMENT pool, NOT graph nodes (they are
    # excluded from build_nodes, so they never seed/extend an object). Used only by
    # the app_impact() PROJECTION; deliberately NOT in content_hash, so an object
    # with no matched identity is byte-identical to pre-P5 and replays unchanged.
    identity_signals: tuple[Signal, ...] = ()
    # ── Service Path Graph contract (v1) ─────────────────────────────────────
    # §1 provenance of the OBJECT itself: the least-live data_class of everything
    # that contributed (signals + the relations its edges were built on) plus the
    # scenario/run it belongs to. `data_class != live` can NEVER be confirmed —
    # enforced in run_window(), not by convention.
    data_class: str = DataClass.LIVE.value
    environment: str = "prod"
    scenario_id: str = ""
    run_id: str = ""
    # The path objects this object grounded against — embedded (like seams) so the
    # snapshot replays deterministically against the SAME observations, never live
    # state. Empty for objects that used no path relation → blob byte-identical to
    # pre-contract (no version churn on existing objects).
    paths: PathGraphView = field(default_factory=PathGraphView)
    # Path-causality RCA P2: the on-path device attribution for this object (design
    # §2.4) — the named upstream-most on-path fault that explains the app symptom,
    # its verdict lift, explained-away victims, discounted off-path faults and the
    # honesty-cap reason. A PROJECTION-style enrichment: like app_impact/
    # layer_coverage it is NOT in content_hash / material_hash / hypotheses_blob, so
    # an object with no attribution (None) is byte-for-byte identical to pre-P2 and
    # REPLAY (which re-runs run_window with no discovery paths) never drifts on it.
    attribution: Attribution | None = None
    # The DISCOVERED typed path the attributed cause sits on (P1 AssembledPath) —
    # kept alongside the attribution so the render contract can show the segments /
    # key devices / unknown+ambiguous / head. Also NOT hashed (additive).
    attribution_path: AssembledPath | None = None

    def attribution_blob(self) -> str:
        """The corr_objects.attribution JSON the RCA report reads (the P3 render
        contract): the P2 attribution (named cause, verdict lift, explained-away,
        honesty-cap reason) PLUS the discovered typed `path` (segments + key devices +
        unknown/ambiguous + head). '{}' when no on-path cause was attributed — an
        honest empty, never an invented one."""
        if self.attribution is None:
            return "{}"
        blob = self.attribution.to_dict()
        if self.attribution_path is not None:
            blob["path"] = self.attribution_path.to_dict()
        return json.dumps(blob, separators=(",", ":"), sort_keys=True)

    def signal_count(self) -> int:
        return sum(len(n.signals) for n in self.nodes)

    def affected(self) -> dict:
        out: dict[str, list[str]] = {
            "devices": [], "interfaces": [], "sites": [], "paths": [],
            "segments": [], "services": [], "prefixes": [],
            "apps": [], "cloud_resources": [],
        }
        bucket = {
            EntityType.DEVICE: "devices", EntityType.INTERFACE: "interfaces",
            EntityType.SITE: "sites", EntityType.PATH: "paths",
            EntityType.SEGMENT: "segments", EntityType.SERVICE: "services",
            EntityType.PREFIX: "prefixes",
            # cloud plane (#81 P3G) — app + cloud resource blast-radius buckets.
            EntityType.APP: "apps", EntityType.CLOUD_RESOURCE: "cloud_resources",
        }
        for n in self.nodes:
            # Defensive: an unmapped entity_type must never crash the whole engine
            # cycle (one object would block persistence for EVERY tenant). Skip it
            # from the blast radius rather than KeyError — additive types stay safe.
            key = bucket.get(n.entity_type)
            if key is None:
                continue
            col = out[key]
            if n.entity_id not in col:
                col.append(n.entity_id)
        # #81 P5: name the applications this object affects from the fused identities
        # matched to it (the apps may not appear as graph nodes — a network fault
        # rarely is — so the blast radius would otherwise miss them).
        for app in self.app_impact().get("apps", []):
            if app["app"] not in out["apps"]:
                out["apps"].append(app["app"])
        return {k: sorted(v) for k, v in out.items() if v}

    def app_impact(self) -> dict:
        """The named application impact (#81 P5): which apps this object affects,
        with fused-identity provenance (band/state/sources/score), plus honest
        evidence_missing when a destination-bearing node has no admissible identity.

        A PROJECTION of the attached identity signals + this object's nodes — like
        layer_coverage, it is derived purely from already-hashed content and is NOT
        in content_hash. An object with no matched identity yields {} → its blob and
        affected() are byte-identical to pre-P5 (additive, replay-safe)."""
        apps: dict[str, dict] = {}
        for s in self.identity_signals:
            a = s.entity_id
            attrs = s.attrs if isinstance(s.attrs, dict) else {}
            cand = {
                "app": a,
                "band": str(attrs.get("band", "")),
                "state": str(attrs.get("state", "")),
                "sources": [str(x) for x in (attrs.get("sources") or [])],
                "evidence_score": int(attrs.get("evidence_score", 0) or 0),
            }
            for k in ("canonical_app_id", "provider", "component"):
                if attrs.get(k):
                    cand[k] = str(attrs[k])
            cur = apps.get(a)
            # strongest evidence_score wins when an app is asserted more than once.
            if cur is None or cand["evidence_score"] > cur["evidence_score"]:
                apps[a] = cand
        out: dict = {"apps": [apps[a] for a in sorted(apps)]}
        if not apps:
            # honest unknown: nodes that plausibly front an application but for which
            # no identity was admissible (unknown-first-class, never a guessed name).
            impactable = sorted({
                f"{n.entity_type.value}:{n.entity_id}" for n in self.nodes
                if n.entity_type in (EntityType.APP, EntityType.SERVICE,
                                     EntityType.PREFIX, EntityType.PATH,
                                     EntityType.SEGMENT)
            })
            if impactable:
                out["evidence_missing"] = [
                    "application identity unavailable for " + e for e in impactable]
        return out

    def app_impact_blob(self) -> str:
        return json.dumps(self.app_impact(), separators=(",", ":"), sort_keys=True)

    def layer_coverage(self) -> dict:
        """The causal-layer stack the RCA UI renders (C4): the FULL ladder
        device→application, each layer flagged observed/not, with the kinds +
        entities + peak severity that sit there, plus the root→impact causal span
        and any UNMAPPED kinds (honest — a kind with no layer is surfaced here, never
        silently dropped). The 'not observed' rows are the differentiator: they show
        which layers the evidence is blind to, between the root and the impact.

        Pure: derived ONLY from this object's nodes (same nodes content_hash hashes),
        so it can never drift from the object's identity and needs no version pin — it
        is a projection of already-hashed content, not new evidence."""
        per_layer: dict[CausalLayer, dict] = {}
        unmapped: set[str] = set()
        for n in self.nodes:
            cl = layer_of(n.kind)
            if cl is None:
                unmapped.add(n.kind)
                continue
            slot = per_layer.setdefault(
                cl, {"kinds": set(), "entities": set(), "sev": Severity.INFO})
            slot["kinds"].add(n.kind)
            slot["entities"].add(n.entity_id)
            if _SEV_RANK[n.peak_severity] > _SEV_RANK[slot["sev"]]:
                slot["sev"] = n.peak_severity
        layers = []
        for cl in CausalLayer:  # rf(-1) → application(6): the fixed bottom-up ladder
            cell = per_layer.get(cl)
            layers.append({
                "layer": cl.name.lower(),
                "osi": osi_label(cl),
                "observed": cell is not None,
                "kinds": sorted(cell["kinds"]) if cell else [],
                "entities": sorted(cell["entities"]) if cell else [],
                "peak_severity": cell["sev"].value if cell else "",
            })
        observed = list(per_layer)
        return {
            "layers": layers,
            # lowest observed layer = the most root-ward (cause); highest = the impact.
            "root_layer": min(observed).name.lower() if observed else "",
            "impact_layer": max(observed).name.lower() if observed else "",
            "unmapped_kinds": sorted(unmapped),
        }

    def layer_coverage_blob(self) -> str:
        return json.dumps(self.layer_coverage(), separators=(",", ":"), sort_keys=True)

    # ── Service Path Graph contract projections ──────────────────────────────

    def path_relations(self) -> tuple[Relation, ...]:
        """The explicit relations (§3) this object's edges were admitted on."""
        return tuple(e.grounding.relation for e in self.edges
                     if e.grounding.relation is not None)

    def used_observation_ids(self) -> tuple[str, ...]:
        return tuple(sorted({
            r.ref for r in self.path_relations()
            if RANK_OBSERVED_PATH(r.method) and r.ref
        }))

    def has_authoritative_edge(self) -> bool:
        """§3: at least one edge admitted on an OBSERVED rank-1..5 relationship."""
        return any(e.grounding.authoritative for e in self.edges)

    def provenance(self) -> dict:
        """§1 — the object's own provenance. `provenance_id` is deterministic
        (uuid5 over correlation_id + content hash), so the same evidence always
        yields the same evidence handle: replay-safe, never random."""
        producers = sorted({s.observer.observer_id for n in self.nodes for s in n.signals})
        return {
            "tenant_id": self.tenant_id,
            "data_class": self.data_class,
            "environment": self.environment,
            "scenario_id": self.scenario_id,
            "run_id": self.run_id,
            "producer_id": f"correlation-engine/{self.engine_ver}",
            "observed_by": producers,
            "provenance_id": str(uuid.uuid5(
                SIGNAL_NS, f"prov|{self.correlation_id}|{self.content_hash()}")),
            "contract_version": CONTRACT_VERSION,
        }

    def path_spine(self) -> dict:
        """§7 — the ORDERED spine for the RCA API/renderer, computed SERVER-side from
        the observation this object grounded on (hop order is data, not layout).
        Missing/filtered hops are preserved as explicit unknown segments. Returns {}
        when the object has no path observation — the UI then says so, and must never
        invent a spine (renderer contract §7)."""
        used = set(self.used_observation_ids())
        obs = [o for o in self.paths.observations if o.observation_id in used]
        if not obs:
            return {}
        newest = max(obs, key=lambda o: (o.observed_at, o.observation_id))
        out = spine_of(newest, self.paths)
        out["correlation_id"] = self.correlation_id
        out["tenant_id"] = self.tenant_id
        return out

    def path_spine_blob(self) -> str:
        return json.dumps(self.path_spine(), separators=(",", ":"), sort_keys=True)

    def to_typed_edge_rows(self, version: int) -> list[dict]:
        """§5 typed edges with their evidence blocks (corr_edges v2 / API shape)."""
        return [e.to_typed_row(self.tenant_id, self.correlation_id, version)
                for e in self.edges]

    def hypotheses_blob(self) -> str:
        """The corr_objects.hypotheses JSON: the ranking PLUS the grounding
        context — replay rehydrates seams from here, never from live state."""
        ctx: dict = {
            "topology_version": self.topology_version,
            "seams": [s.to_dict() for s in sorted(self.seams, key=lambda s: s.seam_id)],
            "topology_gap_hints": self.gap_hints,
        }
        # Declare degradation (§8) ONLY when present — a healthy object's blob (and
        # thus its content_hash + replay pin) is byte-identical to pre-C3, so the
        # common case never churns a version or drifts on replay.
        if self.topology_stale or self.storm_mode:
            ctx["degradation"] = {"topology_stale": self.topology_stale, "storm_mode": self.storm_mode}
        # C7: embed the directed-topology orientations ONLY when present, so an
        # undirected object's blob (hence content_hash + replay pin) is byte-identical
        # to pre-C7. A directed object embeds (from,to,verdict,source) → replay
        # reconstructs the same oracle → same direction (deterministic, no live state).
        if self.orientations:
            ctx["orientations"] = [list(o) for o in self.orientations]
        # C7: embed adjacency grounding (component-scoped) ONLY when used, so a
        # seam/containment object's blob is byte-identical to pre-C7. Lets an
        # adjacency-grounded fabric edge replay against the same links.
        if self.adjacency_pairs:
            ctx["adjacency"] = [list(p) for p in self.adjacency_pairs]
        # Service Path Graph (v1): embed the explicit relations this object's edges
        # were admitted on + the path objects they came from — ONLY when a path
        # relation was actually used, so every pre-contract object's blob (hence
        # content_hash + replay pin) stays byte-identical and never churns a version.
        rels = self.path_relations()
        # Embed for ANY path-graph relation, observed (rank 1-5) OR inferred route
        # (rank 6) — NOT just observed. A rank-6 cloud-route edge that was not
        # embedded re-grounded (or vanished) on replay, so DriftReport flagged a
        # FALSE edge-drift on a matching pin. Rank-7 shared-token edges do NOT use
        # the path graph (token overlap forms the edge from the signals), so they
        # stay excluded — an object grounded only on token overlap keeps its
        # pre-contract byte-identical blob. The view is embedded IN FULL
        # (nat_sessions/routes/freshness_s included) so run_window can rebuild the
        # exact PathIndex it grounded against.
        if any(RANK.get(r.method, 7) <= 6 for r in rels):
            used = set(self.used_observation_ids())
            ctx["path_graph"] = {
                "contract_version": CONTRACT_VERSION,
                "relations": [r.to_dict() for r in rels],
                "observations": [o.to_dict() for o in sorted(
                    self.paths.observations, key=lambda o: o.observation_id)
                    if o.observation_id in used],
                "endpoints": [e.to_dict() for e in sorted(
                    self.paths.endpoints, key=lambda e: e.endpoint_id)],
                "service_bindings": [b.to_dict() for b in sorted(
                    self.paths.service_bindings,
                    key=lambda b: (b.service_ref, b.endpoint_ref))],
                "nat_sessions": [n.to_dict() for n in sorted(
                    self.paths.nat_sessions, key=lambda n: (n.pre_address, n.post_address))],
                "routes": [r.to_dict() for r in sorted(
                    self.paths.routes, key=lambda r: (r.from_ref, r.to_ref))],
                "freshness_s": self.paths.freshness_s,
            }
        # §1 provenance is declared ONLY when it is not the default live/prod object —
        # same reason: a live object's blob is unchanged by the contract.
        if not is_live(self.data_class) or self.scenario_id or self.run_id:
            ctx["provenance"] = {
                "data_class": self.data_class, "environment": self.environment,
                "scenario_id": self.scenario_id, "run_id": self.run_id,
            }
        return json.dumps({
            "ranking": self.ranking.to_dict(),
            "grounding_context": ctx,
        }, separators=(",", ":"), sort_keys=True)

    def content_hash(self) -> str:
        """Change detector for versioning: hashes everything EXCEPT version/
        timestamps-of-persistence. Same evidence ⇒ same hash ⇒ no new version."""
        blob = json.dumps({
            "nodes": [n.key for n in self.nodes],
            "signals": sorted(str(s.signal_id) for n in self.nodes for s in n.signals),
            "edges": [e.to_ch_row("", "", 0) for e in self.edges],
            "hypotheses": self.hypotheses_blob(),
            "engine": self.engine_ver,
        }, separators=(",", ":"), sort_keys=True)
        return hashlib.sha256(blob.encode()).hexdigest()[:16]

    def material_hash(self) -> str:
        """Damping detector (#100 write-side): the operator-meaningful identity of
        a snapshot. A sustained incident refreshes its window every cycle — new
        signal INSTANCES of the same evidence — which legitimately moves
        content_hash (the replay pin) but changes nothing an operator acts on;
        persisting a version per cycle grew corr_objects unboundedly under storms.
        This hash collapses instances to evidence KINDS per entity, edges to their
        structure (weights drift with timing), and confidence to its customer
        bucket (confidence_label), so decay drift alone never re-versions. The
        persistence gate in main.engine_cycle only writes a new version when THIS
        moves, on a heartbeat, or on a lifecycle transition."""
        r = self.ranking
        blob = json.dumps({
            "nodes": [n.key for n in self.nodes],
            # Evidence kind AND severity per entity: a WARN→CRIT escalation of
            # the same evidence is operator-meaningful and must re-version.
            "evidence": sorted({f"{n.key}|{s.kind}|{s.severity.value}"
                                for n in self.nodes for s in n.signals}),
            "edges": sorted([e.from_node, e.to_node, e.grounding.kind, e.direction_basis]
                            for e in self.edges),
            # Owner is who the RCA routes to — an owner change re-versions.
            "ranking": [[h.template_id, h.confidence_label(), h.contradicted, h.owner]
                        for h in r.hypotheses],
            "verdict": [r.top_hypothesis, r.verdict_tier.value],
            "engine": self.engine_ver,
        }, separators=(",", ":"), sort_keys=True)
        return hashlib.sha256(blob.encode()).hexdigest()[:16]

    def top_confidence(self) -> float:
        r = self.ranking
        if r.top_hypothesis == "undetermined" or not r.hypotheses:
            return 0.0
        for h in r.hypotheses:
            if h.template_id == r.top_hypothesis:
                return h.confidence_rank
        return 0.0

    def to_object_row(self, version: int, state: str = "open", merged_into: str = "") -> dict:
        r = self.ranking
        row = {
            "tenant_id": self.tenant_id,
            "correlation_id": self.correlation_id,
            "version": version,
            "state": state,
            "window_start": _ch_dt(self.window_start),
            "window_end": _ch_dt(self.window_end),
            "trigger_signal": self.trigger_signal,
            "top_hypothesis": r.top_hypothesis,
            "top_confidence": round(self.top_confidence(), 4),
            "verdict_tier": r.verdict_tier.value,
            "hypotheses": self.hypotheses_blob(),
            "evidence_missing": json.dumps(list(r.evidence_missing), separators=(",", ":")),
            "affected": json.dumps(self.affected(), separators=(",", ":"), sort_keys=True),
            "signal_count": self.signal_count(),
            "node_count": len(self.nodes),
            "engine_version": self.engine_ver,
            "topology_version": self.topology_version,
            "catalog_version": r.catalog_version,
            # C4: the causal-layer stack for the RCA UI. A separate column (NOT in the
            # hypotheses blob), so it never enters content_hash — a pure projection of
            # the nodes can't change object identity or churn a version.
            "layer_coverage": self.layer_coverage_blob(),
            # #81 P5: named application impact + honest evidence_missing. A separate
            # column (NOT in the hypotheses blob / content_hash) — a pure projection
            # of attached identities, so it never churns a version. '{}' when none.
            "app_impact": self.app_impact_blob(),
            # Path-causality RCA P2: the on-path device attribution (design §2.4). A
            # separate column (NOT in the hypotheses blob / content_hash) — additive
            # enrichment, so it never churns a version and an un-attributed object is
            # byte-identical to pre-P2. '{}' when no on-path cause was attributed.
            "attribution": self.attribution_blob(),
        }
        if merged_into:
            row["merged_into"] = merged_into  # set ONLY on a terminal 'merged' snapshot
        return row

    def to_edge_rows(self, version: int) -> list[dict]:
        return [e.to_ch_row(self.tenant_id, self.correlation_id, version) for e in self.edges]

    def to_evidence_rows(self, version: int) -> list[dict]:
        rows = []
        for e in self.edges:
            rows.append({
                "tenant_id": self.tenant_id,
                "correlation_id": self.correlation_id,
                "version": version,
                "subject_kind": "edge",
                "subject_id": f"{e.from_node}->{e.to_node}",
                "signal_id": str(uuid.UUID(int=0)),
                "role": "supports",
                "note": (f"grounded {e.grounding.kind}:{e.grounding.ref} "
                         f"w={e.weight:.2f} (t={e.w_temporal:.2f} topo={e.w_topo:.2f} "
                         f"r={e.w_reinforce:.2f}) dir={e.direction_basis}"),
            })
        # #81 P5: one explainable supporting-evidence row per fused identity that
        # named an affected app — carrying the REAL identity signal_id (provenance)
        # and its band/state/sources. role=supports: it supports the app-impact claim.
        for s in self.identity_signals:
            attrs = s.attrs if isinstance(s.attrs, dict) else {}
            srcs = ",".join(str(x) for x in (attrs.get("sources") or [])) or "n/a"
            rows.append({
                "tenant_id": self.tenant_id,
                "correlation_id": self.correlation_id,
                "version": version,
                "subject_kind": "app",
                "subject_id": s.entity_id,
                "signal_id": str(s.signal_id),
                "role": "supports",
                "note": (f"application identity: {s.entity_id} "
                         f"band={attrs.get('band', '')} state={attrs.get('state', '')} "
                         f"via {srcs}"),
            })
        return rows


def _ch_dt(dt: datetime) -> int:
    """UTC epoch milliseconds — DateTime64(3) scaled-integer insert (S4/R1);
    integers can never be re-interpreted in the ClickHouse server timezone."""
    dt = dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    return int(dt.timestamp()) * 1000 + dt.microsecond // 1000


# ── union-find components → objects ───────────────────────────────────────────


def _identities_for(nodes: tuple[Node, ...],
                    identity_sigs: tuple[Signal, ...]) -> tuple[Signal, ...]:
    """The app-identity signals whose tokens overlap this component's node tokens —
    the honest join that lets a real-fault object NAME the app it affects. An
    identity that matches nothing is NOT attached (no app is asserted on an object
    it has no token in common with — unknown stays first-class)."""
    if not identity_sigs:
        return ()
    comp_tokens: set[str] = set()
    for n in nodes:
        comp_tokens |= n.tokens()
    matched = [
        s for s in identity_sigs
        if (set(s.entity_tokens) | {s.entity_id}) & comp_tokens
    ]
    return tuple(sorted(matched, key=lambda s: (s.ts, str(s.signal_id))))


def _components(nodes: tuple[Node, ...], edges: tuple[Edge, ...]) -> list[tuple[Node, ...]]:
    parent = {n.key: n.key for n in nodes}

    def find(k: str) -> str:
        while parent[k] != k:
            parent[k] = parent[parent[k]]
            k = parent[k]
        return k

    for e in edges:
        ra, rb = find(e.from_node), find(e.to_node)
        if ra != rb:
            parent[max(ra, rb)] = min(ra, rb)
    groups: dict[str, list[Node]] = {}
    for n in nodes:
        groups.setdefault(find(n.key), []).append(n)
    return [tuple(sorted(g, key=lambda n: n.key)) for _, g in sorted(groups.items())]


def _cap_verdict(ranking: RankingResult, reason: str) -> RankingResult:
    """Downgrade a CONFIRMED outcome to SUSPECTED with a machine-readable reason —
    on the object AND on every hypothesis (so confidence_label() can never say
    'confirmed' while the object says 'suspected'). Never upgrades anything."""
    if ranking.verdict_tier is not VerdictTier.CONFIRMED:
        return ranking
    hyps = tuple(
        replace(h, verdict_gate=GateVerdict(
            tier=VerdictTier.SUSPECTED, coverage=h.verdict_gate.coverage,
            reasons=h.verdict_gate.reasons + (reason,)))
        if h.verdict_gate.tier is VerdictTier.CONFIRMED else h
        for h in ranking.hypotheses
    )
    return replace(
        ranking, verdict_tier=VerdictTier.SUSPECTED, hypotheses=hyps,
        evidence_missing=tuple(dict.fromkeys(ranking.evidence_missing + (reason,))),
    )


# ── grounded-seam evidence in ranking + object folding (tracker 154) ──────────
#
# The seam inventory's OWNER-FINAL seam_type vocabulary (docs/design/
# cloud-ingestion.md §4.0: DX | VPN | SDWAN | DIA | CLOUD_BACKBONE) mapped onto
# the v1 NOC catalog's template seam labels (catalog.Seam — the `seams` metadata
# each signature declares). This is how a grounded seam's TYPE says which fault
# families live on it: a DX seam is the carrier-mediated private interconnect
# INTO the cloud (CARRIER_INTERCONNECT + CLOUD_APP); VPN is a WAN overlay whose
# far end is the cloud edge; SDWAN is the WAN fabric; CLOUD_BACKBONE is inside
# the provider. DIA maps to NOTHING on purpose: the NOC catalog has no ISP/DIA
# seam label, and inventing one here would fabricate affinity — a DIA-grounded
# tie stays in its existing deterministic order (honest no-op).
SEAM_TYPE_AFFINITY: dict[str, frozenset[str]] = {
    "DX": frozenset({"CARRIER_INTERCONNECT", "CLOUD_APP"}),
    "VPN": frozenset({"WAN_SDWAN", "CLOUD_APP"}),
    "SDWAN": frozenset({"WAN_SDWAN"}),
    "DIA": frozenset(),
    "CLOUD_BACKBONE": frozenset({"CLOUD_APP"}),
}


def _scoped_seams(seams: tuple[SeamView, ...], tenant: str) -> tuple[SeamView, ...]:
    """§3a default-closed: only this tenant's seams (or platform-global,
    untenanted ones) may influence ranking or folding — the inventory the
    caller passes is all-tenant."""
    return tuple(s for s in sorted(seams, key=lambda s: s.seam_id)
                 if s.tenant_id in ("", tenant))


def _grounded_seam_affine_labels(
    comp_edges: tuple[Edge, ...], seams: tuple[SeamView, ...], tenant: str,
) -> frozenset[str]:
    """Catalog seam labels affine to the seam TYPES this component actually
    GROUNDED on — authoritative (rank-2 structural membership) seam edges only;
    a token-matched (rank-7) seam edge is a name coincidence and carries no
    ranking evidence."""
    ids = {e.grounding.ref for e in comp_edges
           if e.grounding.kind == "seam" and e.grounding.authoritative}
    if not ids:
        return frozenset()
    labels: set[str] = set()
    for s in _scoped_seams(seams, tenant):
        if s.seam_id in ids:
            labels |= SEAM_TYPE_AFFINITY.get(s.seam_type.upper(), frozenset())
    return frozenset(labels)


def _break_ties_by_seam_affinity(
    ranking: RankingResult, comp_edges: tuple[Edge, ...],
    seams: tuple[SeamView, ...], tenant: str,
) -> RankingResult:
    """Grounded-seam evidence as a ranking TIE-BREAK (tracker 154a).

    When the top hypotheses tie at EQUAL confidence, the one whose declared seam
    scope (template `seams` metadata) best matches the TYPE of the seam the
    object grounded on wins — seam-level ownership is the RCA product rule, and
    the grounding edge is measured evidence the old (-confidence, -satisfied,
    id) sort ignored. Honesty constraints, all structural:

      * confidence numbers are NEVER touched — nothing is fabricated;
      * ONLY the leading equal-confidence run is re-ordered (stable sort by
        affinity, ties keep their existing specific-first order) — a
        strictly-higher-confidence hypothesis can never be displaced;
      * no grounded seam / no affine label / undetermined result ⇒ unchanged.

    Pure + deterministic (sorted inputs, stable sort) — replay-safe."""
    hyps = ranking.hypotheses
    if ranking.top_hypothesis == "undetermined" or len(hyps) < 2:
        return ranking
    labels = _grounded_seam_affine_labels(comp_edges, seams, tenant)
    if not labels:
        return ranking
    top_conf = hyps[0].confidence_rank
    k = 1
    while k < len(hyps) and hyps[k].confidence_rank == top_conf:
        k += 1
    if k < 2:
        return ranking
    tie = tuple(sorted(hyps[:k], key=lambda h: -len(labels & set(h.seams))))
    if tie == hyps[:k]:
        return ranking
    new_top = tie[0]
    # Mirror rank()'s top-specific evidence_missing for the new leader (the
    # checklist must describe the hypothesis the object now names).
    missing: tuple[str, ...] = ()
    if new_top.verdict_gate.tier is not VerdictTier.CONFIRMED:
        clause_gaps = tuple(f"{new_top.template_id}: needs {m}" for m in new_top.missing)
        gate_gaps = tuple(f"{new_top.template_id}: {r}" for r in new_top.verdict_gate.reasons)
        missing = tuple(dict.fromkeys(clause_gaps + gate_gaps))
    return replace(
        ranking,
        top_hypothesis=new_top.template_id,
        verdict_tier=new_top.verdict_gate.tier,  # rank ≠ verdict: tier still from the gate
        hypotheses=tie + hyps[k:],
        evidence_missing=missing,
    )


def _fold_seam_bridged_components(
    comps: list[tuple[Node, ...]], edges: tuple[Edge, ...],
    seams: tuple[SeamView, ...], tenant: str,
) -> list[tuple[Node, ...]]:
    """Fold components whose entity sets are connected THROUGH a shared grounded
    seam (tracker 154b, in-window half).

    Two components fold when a seam S exists such that (i) S is structurally
    GROUNDED by an authoritative rank-2 seam edge inside at least one of them
    (an OBSERVED seam membership, not a declared hope), and (ii) BOTH components
    contain a node that is a structural member of S (identity_refs ∩ endpoint
    values — the exact rank-2 membership test, never tokens). The time bound is
    the evidence window itself (the caller buffers cfg.window_s): components
    coexisting in ONE window whose halves sit on the same ownership handoff are
    the §4.4 split-brain signature across a seam — the pairwise seam edge was
    admissible and only temporal decay kept the halves apart (a cascade's cloud
    half follows its circuit half by minutes; decay must not split one handoff's
    incident in two). No edge is fabricated; the components' own edges are
    carried as they are.

    Tenant-guarded twice over: run_window windows are single-tenant by
    construction, and only this tenant's (or untenanted platform) seam views
    participate (_scoped_seams) — a foreign tenant's seam can never bridge.
    Pure + deterministic: union-find over components in sorted order, output
    groups re-sorted exactly like _components."""
    if len(comps) < 2:
        return comps
    scoped = _scoped_seams(seams, tenant)
    if not scoped:
        return comps
    evs = [s.endpoint_values() | {s.seam_id} for s in scoped]
    memb: list[frozenset[int]] = []
    grounded: list[frozenset[int]] = []
    for comp in comps:
        keys = {n.key for n in comp}
        refs = frozenset(r for n in comp for r in n.identity_refs())
        memb.append(frozenset(i for i, ev in enumerate(evs) if refs & ev))
        seam_ids = {e.grounding.ref for e in edges
                    if e.from_node in keys and e.grounding.kind == "seam"
                    and e.grounding.authoritative}
        grounded.append(frozenset(i for i, s in enumerate(scoped)
                                  if s.seam_id in seam_ids))

    parent = list(range(len(comps)))

    def find(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    for i in range(len(comps)):
        for j in range(i + 1, len(comps)):
            if (grounded[i] | grounded[j]) & memb[i] & memb[j]:
                ri, rj = find(i), find(j)
                if ri != rj:
                    parent[max(ri, rj)] = min(ri, rj)

    groups: dict[int, list[Node]] = {}
    for i, comp in enumerate(comps):
        groups.setdefault(find(i), []).extend(comp)
    return [tuple(sorted(g, key=lambda n: n.key))
            for _, g in sorted(groups.items(),
                               key=lambda kv: min(n.key for n in kv[1]))]


def run_window(
    window: tuple[Signal, ...] | list[Signal],
    catalog: Catalog,
    seams: tuple[SeamView, ...],
    cfg: EngineConfig | None = None,
    adjacency: TopologyAdjacency = NO_ADJACENCY,
    topology_stale: bool = False,
    storm_mode: bool = False,
    directed: Oracle | None = None,
    paths: PathGraphView | None = None,
    discovery: tuple[AssembledPath, ...] = (),
) -> list[ObjectSnapshot]:
    """THE pure engine function. One evaluation of one tenant's window.

    topology_stale caps grounding weight (§8) AND is declared on the snapshot;
    storm_mode is declared only (the window is already maxlen-bounded). Both are
    embedded in the snapshot so replay rehydrates them — degradation is never silent.

    `paths` is the Service Path Graph view (contract §2): endpoints, immutable path
    observations with ORDERED hops, application→endpoint bindings, NAT sessions and
    (inferred) cloud routes. It is scoped to this window's tenant HERE, before any
    lookup — §6 rule 1 / §9: cross-tenant resolution is structurally impossible.

    `discovery` is the path-causality RCA input (P1 output, design §2.3/§2.4): the
    typed causal paths the CALLER assembled for THIS window's tenant (from measured
    runs, cloud flow pairs, cloud inventory/topology and DNS via the P1 adapters).
    It drives an ADDITIVE P2 enrichment pass: for an object carrying an app symptom
    AND an on-path fault, the attribution (named cause device, segment, verdict lift,
    explained-away set, honesty-cap reason) is attached. It is NEVER read into the
    verdict/ranking/edges/content_hash — an object with no discoverable path or no
    on-path fault is byte-for-byte what it was pre-P2, so replay (which passes no
    discovery) and the golden fixtures are untouched. Empty default = no enrichment.
    """
    cfg = cfg or EngineConfig()
    sigs = tuple(sorted(window, key=lambda s: (s.ts, str(s.signal_id))))
    if not sigs:
        return []
    tenants = {s.tenant_id for s in sigs}
    if len(tenants) != 1:
        # Episodes never correlate across tenants (§7) — the caller partitions.
        raise ValueError(f"run_window requires a single-tenant window, got {sorted(tenants)}")
    tenant = sigs[0].tenant_id
    nodes = build_nodes(sigs)
    if not nodes:
        return []
    # #81 P5: the app-identity ENRICHMENT pool — excluded from build_nodes (so it can
    # never seed/extend an object), matched per-object below into an app-impact
    # projection. An identity-only window has no nodes → returns above → no object.
    identity_sigs = tuple(s for s in sigs if s.source is Source.APP_IDENTITY)
    # Wrap the direction oracle so we capture exactly the orientations the edges were
    # built on — embedded per snapshot for deterministic replay (C7), like seams.
    rec = RecordingOracle(directed) if directed is not None else None
    # §6 rule 1 / §9 — the ONLY door to the path objects, tenant-scoped at construction.
    view = (paths or PathGraphView()).for_tenant(tenant)
    path_index = PathIndex(view, tenant) if not view.is_empty() else None
    # Path-causality P2: keep ONLY this tenant's discovery paths (§3a default-closed —
    # a path with a mismatched/empty tenant can never seed an attribution). object_
    # attribution re-scopes again; this is the structural first gate.
    disc = tuple(p for p in discovery if p.tenant_id and p.tenant_id == tenant)
    edges, gap_hints = build_edges(nodes, seams, cfg, adjacency, topology_stale, rec,
                                   path_index)
    open_floor = _SEV_RANK[Severity(cfg.severity_open_floor)]
    topo_ver = seams_hash(seams)
    eng_ver = engine_version(cfg)

    snapshots = []
    # Tracker 154b: seam-bridged components are ONE incident — fold before
    # minting objects (the folded id derives from the union's earliest node, so
    # a transient split re-derives the same identity it had before splitting).
    comps = _fold_seam_bridged_components(_components(nodes, edges), edges,
                                          seams, tenant)
    for comp in comps:
        comp_keys = {n.key for n in comp}
        comp_edges = tuple(e for e in edges if e.from_node in comp_keys)
        if not comp_edges and _SEV_RANK[comp[0].peak_severity] < open_floor:
            continue  # singleton below the open floor: episode, not an object
        comp_sigs = tuple(s for n in comp for s in n.signals)
        # Tracker 154a: grounded-seam-type affinity breaks equal-confidence ties.
        ranking = _break_ties_by_seam_affinity(
            rank(catalog, comp_sigs), comp_edges, seams, tenant)
        # ── contract gates on the verdict (never on the edge's existence) ─────
        # §1: synthetic/replay/lab evidence may support, contradict or illustrate —
        # it can NEVER produce a customer-confirmed verdict.
        comp_dc = worst_data_class(
            [n.data_class() for n in comp]
            + [e.grounding.data_class for e in comp_edges])
        if not is_live(comp_dc):
            ranking = _cap_verdict(
                ranking,
                f"data_class={comp_dc}: non-live evidence can support but never "
                f"confirm a customer verdict (contract §1)")
        # §3/§4: an object whose graph rests only on rank-6 (inferred: cloud route,
        # BGP, SD-WAN policy) or rank-7 (candidate: shared token / name similarity)
        # relations has no OBSERVED relationship holding it together — it may be
        # suspected, never confirmed. A cloud route says traffic COULD go that way;
        # only an observation says it DID.
        if comp_edges and not any(e.grounding.authoritative for e in comp_edges):
            worst = min((e.grounding.rank for e in comp_edges), default=7)
            cls = ("inferred (control-plane) relationships" if worst == 6
                   else "candidate (shared-token / name-similarity) relationships")
            ranking = _cap_verdict(
                ranking,
                f"no authoritative edge: this object is held together only by {cls} — "
                f"an observed path/endpoint/flow relationship is required to confirm "
                f"(contract §3/§4)")
        # §8: an unknown hop is a FACT — it is preserved and declared, never bridged.
        unknown_hops = sorted({h for e in comp_edges if e.grounding.relation
                               for h in e.grounding.relation.unknown_hops})
        if unknown_hops:
            ranking = replace(ranking, evidence_missing=tuple(dict.fromkeys(
                ranking.evidence_missing + tuple(
                    f"path hop {h} did not respond — unknown segment preserved, not bridged"
                    for h in unknown_hops))))
        first = min(comp, key=lambda n: (n.onset, n.key))
        onset_ms = int(first.onset.timestamp() * 1000)
        cid = str(uuid.uuid5(SIGNAL_NS, f"corrobj|{tenant}|{first.key}|{onset_ms}"))
        # Component-scoped device set, for embedding the orientations + adjacency this
        # object grounded on (both replay deterministically from the snapshot).
        comp_devs = {n.device_part() for n in comp} - {None}
        orientations: tuple[tuple, ...] = ()
        if rec is not None and rec.calls:
            orientations = tuple(sorted(
                (a, b, o.verdict.value, o.source)
                for (a, b), o in rec.calls.items()
                if a in comp_devs and b in comp_devs
            ))
        adjacency_pairs = tuple(sorted(
            (lo, hi) for p in adjacency.pairs
            if p <= comp_devs for lo, hi in (tuple(sorted(p)),)
        ))
        # Path-causality P2 enrichment (ADDITIVE): name the on-path device that
        # explains this object's app symptom. None (no discovery / no symptom / no
        # on-path cause) ⇒ the object is byte-for-byte pre-P2.
        attr_result = object_attribution(tenant, comp_sigs, disc) if disc else None
        attribution, attribution_path = attr_result if attr_result is not None else (None, None)
        snapshots.append(ObjectSnapshot(
            correlation_id=cid,
            tenant_id=tenant,
            window_start=min(s.ts for s in comp_sigs),
            window_end=max(s.ts for s in comp_sigs),
            trigger_signal=str(min((s for s in comp_sigs),
                                   key=lambda s: (s.ts, str(s.signal_id))).signal_id),
            nodes=comp,
            edges=comp_edges,
            ranking=ranking,
            seams=seams,
            engine_ver=eng_ver,
            topology_version=topo_ver,
            gap_hints=gap_hints,
            topology_stale=topology_stale,
            storm_mode=storm_mode,
            orientations=orientations,
            adjacency_pairs=adjacency_pairs,
            identity_signals=_identities_for(comp, identity_sigs),
            data_class=comp_dc,
            environment=_first_attr(comp_sigs, "environment", "prod"),
            scenario_id=_first_attr(comp_sigs, "scenario_id", ""),
            run_id=_first_attr(comp_sigs, "run_id", ""),
            paths=view,
            attribution=attribution,
            attribution_path=attribution_path,
        ))
    return snapshots


def _first_attr(sigs: tuple[Signal, ...], key: str, default: str) -> str:
    """§1 provenance carried by the evidence (deterministic: first by (ts, id))."""
    for s in sorted(sigs, key=lambda s: (s.ts, str(s.signal_id))):
        if isinstance(s.attrs, dict) and s.attrs.get(key):
            return str(s.attrs[key])
    return default


# ── Object merge — de-split a cross-cycle identity drift (§4.4) ────────────────
#
# correlation_id = uuid5(tenant, earliest-node.key, onset_ms): stable while the
# incident's earliest signal stays in the sliding window, but when that signal
# ages out the SAME incident is re-keyed under a new id (split-brain — one
# incident, two objects). Merge resolves the IDENTITY split: a still-live object
# this cycle that overlaps a stale (no-longer-materializing) open object by entity
# set + time window is the same incident — the stale one is tombstoned (terminal
# state='merged', merged_into=<survivor>) and the live one continues.
#
# REPLAY-SAFE BY CONSTRUCTION: merge writes only a lifecycle state + a backlink; it
# NEVER re-keys a live object or re-ranks an ungrounded union (which would breach
# the §4.2 grounding gate AND the replay contract — replay re-runs run_window and
# would re-derive the un-merged id). Per-object replay reproduces the tombstoned
# object's content unchanged; the merged_into pointer is metadata, not content.
# Pure + deterministic: result depends only on the snapshot sets, not order/clock.

def _entity_ids(snap: ObjectSnapshot) -> frozenset[str]:
    return frozenset(n.entity_id for n in snap.nodes)


def _windows_overlap(a: ObjectSnapshot, b: ObjectSnapshot) -> bool:
    return a.window_start <= b.window_end and b.window_start <= a.window_end


def _snap_grounded_seam_ids(snap: ObjectSnapshot) -> frozenset[str]:
    """Seam ids this object's graph GROUNDED on — authoritative rank-2 seam
    edges only (a rank-7 token-matched seam edge is a name coincidence and may
    never justify a fold)."""
    return frozenset(e.grounding.ref for e in snap.edges
                     if e.grounding.kind == "seam" and e.grounding.authoritative)


def _snap_touches_seam(snap: ObjectSnapshot, view: SeamView) -> bool:
    """Structural seam membership of the OBJECT: any node whose identity_refs
    intersect the seam's endpoint values ∪ {seam_id} — the exact rank-2
    membership test resolve_grounding trusts, never free-text tokens."""
    ev = view.endpoint_values() | {view.seam_id}
    return any(n.identity_refs() & ev for n in snap.nodes)


def _seam_bridged(a: ObjectSnapshot, b: ObjectSnapshot) -> bool:
    """Tracker 154b (cross-cycle half): True when a shared GROUNDED seam bridges
    the two objects' entity sets — a seam that at least one of them holds an
    authoritative seam-grounded edge on, whose declared endpoints structurally
    contain a member of BOTH objects. Entity-set Jaccard is blind to this shape
    (a cloud half and a network half of one interconnect incident share ZERO
    entities — they share the seam), so the merge criterion admits it explicitly.

    Tenant-guarded (§3a default-closed): different tenants never bridge, and a
    seam view is consulted only when untenanted (platform) or owned by the
    objects' tenant — a foreign tenant's seam can never weld two objects. Seam
    views come from the snapshots' own embedded grounding context, so the test
    is replay-safe and needs no live inventory."""
    if a.tenant_id != b.tenant_id:
        return False
    grounded = _snap_grounded_seam_ids(a) | _snap_grounded_seam_ids(b)
    if not grounded:
        return False
    views: dict[str, SeamView] = {}
    for v in (*a.seams, *b.seams):
        if v.seam_id in grounded and v.tenant_id in ("", a.tenant_id):
            views.setdefault(v.seam_id, v)
    return any(_snap_touches_seam(a, views[sid]) and _snap_touches_seam(b, views[sid])
               for sid in sorted(views))


def find_merges(
    survivors: list[ObjectSnapshot] | tuple[ObjectSnapshot, ...],
    candidates: list[ObjectSnapshot] | tuple[ObjectSnapshot, ...],
    min_overlap: float = 0.4,
) -> list[tuple[str, str]]:
    """Which stale `candidates` should tombstone into a live `survivor`.

    A candidate merges into a survivor when their entity sets overlap by
    Jaccard ≥ min_overlap AND their time windows overlap — the signature of one
    incident re-identified across windowing (NOT two unrelated incidents: an
    entity-set overlap IS same-device containment, the §4.2 grounding the gate
    already trusts). Tracker 154b widens the SAME-incident test to the seam
    shape Jaccard is blind to: overlapping windows + entity sets bridged
    through a shared GROUNDED seam (_seam_bridged — rank-2 structural
    membership on both sides, authoritative seam edge on at least one) also
    merge; the tenant guard and every other guard below are unchanged.
    Each candidate merges into at most ONE survivor — the
    strongest overlap, tie-broken by earliest window_start then cid (deterministic;
    never depends on input order). Survivors are the live objects this cycle and are
    never merged away. Returns (merged_cid, survivor_cid) pairs, sorted.

    Tenant-guarded (§3a default-closed), exactly as its twin find_continuation is:
    the caller feeds BOTH lists from the process-global all-tenant OPEN_OBJECTS,
    so without this check two tenants that merely name their devices alike
    (leaf1/spine1 — the common case, not the exotic one) reach Jaccard ≥
    min_overlap and one tenant's live incident is tombstoned state='merged' into
    the other's, leaking a foreign correlation_id into its merged_into column.
    A candidate can never merge into another tenant's object, whatever the
    entity overlap.
    """
    surv = sorted(survivors, key=lambda s: (s.window_start, s.correlation_id))
    pairs: list[tuple[str, str]] = []
    for cand in sorted(candidates, key=lambda s: (s.window_start, s.correlation_id)):
        ce = _entity_ids(cand)
        if not ce:
            continue
        best: tuple[float, datetime, str] | None = None
        best_cid = ""
        for s in surv:
            if (s.tenant_id != cand.tenant_id
                    or s.correlation_id == cand.correlation_id
                    or not _windows_overlap(cand, s)):
                continue
            se = _entity_ids(s)
            union = ce | se
            jac = len(ce & se) / len(union) if union else 0.0
            # Tracker 154b: a shared grounded seam bridging the two entity sets
            # is the same-incident signature Jaccard can't see (disjoint halves
            # of one seam incident) — admit it alongside the overlap criterion.
            if jac < min_overlap and not _seam_bridged(cand, s):
                continue
            key = (jac, s.window_start, s.correlation_id)
            # Higher overlap wins; tie → earliest window_start, then lexical cid.
            if best is None or jac > best[0] or (jac == best[0] and (s.window_start, s.correlation_id) < (best[1], best[2])):
                best, best_cid = key, s.correlation_id
        if best_cid:
            pairs.append((cand.correlation_id, best_cid))
    return sorted(pairs)


def find_continuation(
    snap: ObjectSnapshot,
    open_snaps: list[ObjectSnapshot] | tuple[ObjectSnapshot, ...],
    min_overlap: float = 0.4,
    *,
    exclude: frozenset[str] | set[str] | tuple[str, ...] = (),
    entity_cache: dict | None = None,
) -> str:
    """Which existing OPEN object `snap` CONTINUES, if any (#111 churn fix).

    The persistence-side twin of find_merges. correlation_id derives from the
    component's earliest node + onset, so when an ongoing incident's earliest
    signal ages out of the sliding window the SAME condition re-keys under a new
    id every sweep. Pre-fix the caller minted the new object and tombstoned the
    old one into it (create-then-merge: one state='merged' tombstone per sweep —
    ~13/min on a sustained condition, ~20M corr_signals_archive rows/day). The
    caller instead ADOPTS the existing open object's identity and versions it.

    Same criterion as find_merges — entity-set Jaccard >= min_overlap AND time-
    window overlap IS one incident re-identified across windowing (or, tracker
    154b, entity sets bridged through a shared grounded seam) — and the same
    deterministic choice: strongest overlap, tie -> earliest window_start, then
    lexical cid. Tenant-guarded (§3a default-closed): a snapshot can never adopt
    another tenant's object, whatever the entity overlap. Returns the open
    object's correlation_id, or '' when snap is a genuinely new incident.

    Pure and deterministic; run_window itself is untouched (it has no memory),
    so replay — which re-runs run_window — still derives the raw windowed id;
    replay.py matches an adopted version by its trigger signal.
    """
    ce = _entity_ids(snap)
    if not ce:
        return ""
    best: tuple[float, datetime, str] | None = None
    best_cid = ""
    for s in open_snaps:
        # TRACKER 162: `exclude` and `entity_cache` are pure PERFORMANCE inputs —
        # they change which candidates are *examined*, never which one wins. The
        # caller previously rebuilt the candidate list per snapshot (O(open) per
        # snapshot, so O(snapshots x open) per cycle) and this loop recomputed
        # every candidate's entity set on every call. Excluding a cid here is
        # exactly what filtering it out of the list did; the cache holds the same
        # frozenset `_entity_ids` would return.
        if s.correlation_id in exclude:
            continue
        if (s.tenant_id != snap.tenant_id
                or s.correlation_id == snap.correlation_id
                or not _windows_overlap(snap, s)):
            continue
        if entity_cache is None:
            se = _entity_ids(s)
        else:
            se = entity_cache.get(s.correlation_id)
            if se is None:
                se = entity_cache[s.correlation_id] = _entity_ids(s)
        union = ce | se
        jac = len(ce & se) / len(union) if union else 0.0
        # Tracker 154b: same seam-bridge admission as find_merges — a re-keyed
        # seam-far half continues the incident it is bridged to, never a clone.
        if jac < min_overlap and not _seam_bridged(snap, s):
            continue
        # Strongest overlap wins; tie -> earliest window_start, then lexical cid.
        if (best is None or jac > best[0]
                or (jac == best[0] and (s.window_start, s.correlation_id) < (best[1], best[2]))):
            best, best_cid = (jac, s.window_start, s.correlation_id), s.correlation_id
    return best_cid
