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
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone

from catalog import Catalog
from directed_topology import Oracle, RecordingOracle
from directed_topology import Verdict as _Verdict
from layers import CausalLayer, layer_of, osi_label
from scoring import RankingResult, rank
from signals import SIGNAL_NS, EntityType, Severity, Signal

ENGINE_SEMVER = "2.2.0"  # 2.2.0: C7.3 live directed-topology vote #2 (NetFlow) + adjacency/orientation embedding
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
    def from_dict(cls, d: dict) -> "SeamView":
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
        be the SUBJECT (a device reporting its own interface)."""
        observers = {s.observer.observer_id for s in self.signals if s.observer.observer_id}
        toks = {self.entity_id}
        for s in self.signals:
            # entity_tokens can carry the measuring vantage (a probe's (prober, host));
            # the vantage is not a topology subject, the destination is.
            toks.update(t for t in s.entity_tokens if t not in observers)
            if s.site:
                toks.add(s.site)
        if ":" in self.entity_id:
            toks.add(self.entity_id.split(":", 1)[0])  # device-part is always a subject
        if "->" in self.entity_id:
            # Left of a probe path is the vantage (== observer); drop it. A real
            # network segment (observer is a separate agent) keeps both endpoints.
            toks.update(p for p in self.entity_id.split("->") if p and p not in observers)
        return frozenset(toks)

    def device_part(self) -> str | None:
        """The single device this node sits on, for L2/L3 adjacency grounding:
        'leaf1:Ethernet1' → 'leaf1'; a bare device id → itself; a path/segment
        ('a->b') has no single device → None."""
        eid = self.entity_id
        if "->" in eid:
            return None
        if ":" in eid:
            return eid.split(":", 1)[0]
        if self.entity_type in (EntityType.DEVICE, EntityType.INTERFACE):
            return eid
        return None


_SEV_RANK = {Severity.INFO: 0, Severity.WARN: 1, Severity.HIGH: 2, Severity.CRIT: 3}


def build_nodes(window: tuple[Signal, ...]) -> tuple[Node, ...]:
    by_key: dict[str, list[Signal]] = {}
    for s in window:
        if s.kind.endswith("_clear"):
            continue  # clears close episodes; they are not evidence nodes
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


# ── stage [4]: the grounding gate ─────────────────────────────────────────────


@dataclass(frozen=True)
class Grounding:
    kind: str   # 'seam' | 'topo'  (CH grounding_kind enum; adjacency rides 'topo')
    ref: str    # seam_id | 'shared:<token>' (containment) | 'adj:<a>--<b>' (adjacency)


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
    def from_links(links: "list[dict] | tuple[dict, ...]") -> "TopologyAdjacency":
        out: set[frozenset[str]] = set()
        for link in links or ():
            a, b = str(link.get("a") or ""), str(link.get("b") or "")
            if a and b and a != b:
                out.add(frozenset({a, b}))
        return TopologyAdjacency(frozenset(out))


def resolve_grounding(
    a: Node, b: Node, seams: tuple[SeamView, ...],
    adjacency: TopologyAdjacency = TopologyAdjacency(),
) -> Grounding | None:
    """HARD constraint (owner, e4f2236): admit ONLY seam or explicit topology
    grounding. Returns None for everything else — the caller counts a
    topology-gap hint and NEVER builds the edge. Deterministic: seams scanned in
    seam_id order; then same-device containment; then L2/L3 adjacency. First wins."""
    ta, tb = a.tokens(), b.tokens()
    for seam in sorted(seams, key=lambda s: s.seam_id):
        ev = seam.endpoint_values() | {seam.seam_id}
        if (ta & ev) and (tb & ev):
            return Grounding("seam", seam.seam_id)
    # Explicit containment: an interface/path on the same device as the peer
    # entity is a modeled topology relation, not a bare co-occurrence.
    shared = ta & tb
    if shared:
        return Grounding("topo", "shared:" + min(sorted(shared)))
    # L2/L3 adjacency: two DIFFERENT devices joined by a known link (LLDP/CDP/BGP-LS)
    # are a modeled topology relation — this is what lets a fabric link-flap or an
    # IGP adjacency fault correlate across the two ends (§4.2 'L2/L3 adjacent device').
    da, db = a.device_part(), b.device_part()
    if da and db and adjacency.adjacent(da, db):
        lo, hi = sorted((da, db))
        return Grounding("topo", f"adj:{lo}--{hi}")
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
               directed: "Oracle | None" = None) -> tuple[float, str]:
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


def build_edges(
    nodes: tuple[Node, ...], seams: tuple[SeamView, ...], cfg: EngineConfig,
    adjacency: TopologyAdjacency = TopologyAdjacency(),
    topology_stale: bool = False,
    directed: Oracle | None = None,
) -> tuple[tuple[Edge, ...], int]:
    """Returns (admitted edges, topology_gap_hints). Pairs are evaluated in
    deterministic node order; the earlier-onset node is always from_node."""
    edges: list[Edge] = []
    gap_hints = 0
    for i in range(len(nodes)):
        for j in range(i + 1, len(nodes)):
            a, b = nodes[i], nodes[j]
            if b.onset < a.onset or (b.onset == a.onset and b.key < a.key):
                a, b = b, a
            grounding = resolve_grounding(a, b, seams, adjacency)
            if grounding is None:
                gap_hints += 1
                continue
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
            if grounding.kind == "seam":
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
        return {k: sorted(v) for k, v in out.items() if v}

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
        for cl in CausalLayer:  # device(0) → application(6): the fixed bottom-up ladder
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
        return rows


def _ch_dt(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


# ── union-find components → objects ───────────────────────────────────────────


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


def run_window(
    window: tuple[Signal, ...] | list[Signal],
    catalog: Catalog,
    seams: tuple[SeamView, ...],
    cfg: EngineConfig | None = None,
    adjacency: TopologyAdjacency = TopologyAdjacency(),
    topology_stale: bool = False,
    storm_mode: bool = False,
    directed: Oracle | None = None,
) -> list[ObjectSnapshot]:
    """THE pure engine function. One evaluation of one tenant's window.

    topology_stale caps grounding weight (§8) AND is declared on the snapshot;
    storm_mode is declared only (the window is already maxlen-bounded). Both are
    embedded in the snapshot so replay rehydrates them — degradation is never silent.
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
    # Wrap the direction oracle so we capture exactly the orientations the edges were
    # built on — embedded per snapshot for deterministic replay (C7), like seams.
    rec = RecordingOracle(directed) if directed is not None else None
    edges, gap_hints = build_edges(nodes, seams, cfg, adjacency, topology_stale, rec)
    open_floor = _SEV_RANK[Severity(cfg.severity_open_floor)]
    topo_ver = seams_hash(seams)
    eng_ver = engine_version(cfg)

    snapshots = []
    for comp in _components(nodes, edges):
        comp_keys = {n.key for n in comp}
        comp_edges = tuple(e for e in edges if e.from_node in comp_keys)
        if not comp_edges and _SEV_RANK[comp[0].peak_severity] < open_floor:
            continue  # singleton below the open floor: episode, not an object
        comp_sigs = tuple(s for n in comp for s in n.signals)
        ranking = rank(catalog, comp_sigs)
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
        ))
    return snapshots


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
    already trusts). Each candidate merges into at most ONE survivor — the
    strongest overlap, tie-broken by earliest window_start then cid (deterministic;
    never depends on input order). Survivors are the live objects this cycle and are
    never merged away. Returns (merged_cid, survivor_cid) pairs, sorted.
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
            if s.correlation_id == cand.correlation_id or not _windows_overlap(cand, s):
                continue
            se = _entity_ids(s)
            union = ce | se
            jac = len(ce & se) / len(union) if union else 0.0
            if jac < min_overlap:
                continue
            key = (jac, s.window_start, s.correlation_id)
            # Higher overlap wins; tie → earliest window_start, then lexical cid.
            if best is None or jac > best[0] or (jac == best[0] and (s.window_start, s.correlation_id) < (best[1], best[2])):
                best, best_cid = key, s.correlation_id
        if best_cid:
            pairs.append((cand.correlation_id, best_cid))
    return sorted(pairs)
