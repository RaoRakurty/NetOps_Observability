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
from scoring import RankingResult, rank
from signals import SIGNAL_NS, EntityType, Severity, Signal

ENGINE_SEMVER = "2.0.0"

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
    kind: str   # 'seam' | 'topo'
    ref: str


def resolve_grounding(a: Node, b: Node, seams: tuple[SeamView, ...]) -> Grounding | None:
    """HARD constraint (owner, e4f2236): admit ONLY seam or explicit topology
    grounding. Returns None for everything else — the caller counts a
    topology-gap hint and NEVER builds the edge. Deterministic: seams are
    scanned in seam_id order; first match wins."""
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
_LAYER = {
    EntityType.DEVICE: 0, EntityType.INTERFACE: 0,
    EntityType.PREFIX: 1, EntityType.SITE: 1,
    EntityType.PATH: 2, EntityType.SEGMENT: 2,
    EntityType.SERVICE: 3,
}


def _direction(a: Node, b: Node, cfg: EngineConfig) -> tuple[float, str]:
    """2-of-3 to claim (§4.3): onset order + layer prior vote here; the
    topology up/down vote abstains until the full topology graph lands, so v0
    claims direction only when BOTH available votes agree. a precedes b."""
    votes = []
    gap = (b.onset - a.onset).total_seconds()
    if gap > a.onset_uncertainty_s + b.onset_uncertainty_s:
        votes.append("onset_order")
    la, lb = _LAYER[a.entity_type], _LAYER[b.entity_type]
    if la < lb:
        votes.append("layer_prior")
    elif la > lb:
        # Layer prior points the other way: conflict with onset order → mixed.
        return (0.0, "mixed") if votes else (0.0, "none")
    if len(votes) >= 2:
        return cfg.direction_conf, "+".join(votes)
    return 0.0, "none"


def build_edges(
    nodes: tuple[Node, ...], seams: tuple[SeamView, ...], cfg: EngineConfig,
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
            grounding = resolve_grounding(a, b, seams)
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
            w_topo = cfg.w_topo_seam if grounding.kind == "seam" else cfg.w_topo_containment
            cross = a.signals[0].modality_class is not b.signals[0].modality_class
            w_r = cfg.reinforce_cross_modality if cross else 1.0
            weight = min(w_t * w_topo * w_r, 1.0)
            if weight < cfg.attach_threshold:
                continue
            conf, basis = _direction(a, b, cfg)
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

    def signal_count(self) -> int:
        return sum(len(n.signals) for n in self.nodes)

    def affected(self) -> dict:
        out: dict[str, list[str]] = {
            "devices": [], "interfaces": [], "sites": [], "paths": [],
            "segments": [], "services": [], "prefixes": [],
        }
        bucket = {
            EntityType.DEVICE: "devices", EntityType.INTERFACE: "interfaces",
            EntityType.SITE: "sites", EntityType.PATH: "paths",
            EntityType.SEGMENT: "segments", EntityType.SERVICE: "services",
            EntityType.PREFIX: "prefixes",
        }
        for n in self.nodes:
            col = out[bucket[n.entity_type]]
            if n.entity_id not in col:
                col.append(n.entity_id)
        return {k: sorted(v) for k, v in out.items() if v}

    def hypotheses_blob(self) -> str:
        """The corr_objects.hypotheses JSON: the ranking PLUS the grounding
        context — replay rehydrates seams from here, never from live state."""
        return json.dumps({
            "ranking": self.ranking.to_dict(),
            "grounding_context": {
                "topology_version": self.topology_version,
                "seams": [s.to_dict() for s in sorted(self.seams, key=lambda s: s.seam_id)],
                "topology_gap_hints": self.gap_hints,
            },
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

    def to_object_row(self, version: int, state: str = "open") -> dict:
        r = self.ranking
        return {
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
        }

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
) -> list[ObjectSnapshot]:
    """THE pure engine function. One evaluation of one tenant's window."""
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
    edges, gap_hints = build_edges(nodes, seams, cfg)
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
        ))
    return snapshots
