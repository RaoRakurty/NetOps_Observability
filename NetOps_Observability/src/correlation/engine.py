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
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, timezone

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
from rank_memo import RankMemo, rank_key
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
    # NOTE (tracker 165): `window_s = 900.0` used to live here. It was never an
    # engine parameter — the core never read it, and its only other appearance
    # was a comment saying the CALLER buffers it. Keeping a second temporal
    # constant next to `tau_s` invited exactly the drift that shipped: a record
    # cap silently became the RCA horizon while a 900 that nothing enforced sat
    # in the config looking authoritative. Retention is the caller's concern and
    # now derives from `engine_temporal_reach_s()` below, so the two cannot
    # disagree. Removing the field changes `config_hash()` and therefore
    # `engine_version` — that is intended and visible: objects scored under the
    # old retention semantics are genuinely not equivalent to new ones, and
    # `replay.py` REPORTS the pin mismatch (`engine_pin_match`) rather than
    # failing, so historical replay still runs and says what changed.

    def config_hash(self) -> str:
        blob = json.dumps(
            {k: getattr(self, k) for k in sorted(self.__dataclass_fields__)},
            separators=(",", ":"), sort_keys=True,
        )
        return hashlib.sha256(blob.encode()).hexdigest()[:12]


def engine_version(cfg: EngineConfig) -> str:
    return f"{ENGINE_SEMVER}+cfg.{cfg.config_hash()}"


# ── temporal reach: what the SCORING semantics say is still useful ────────────
#
# tracker 165. Three mechanisms used to describe one temporal concept and none
# was derived from any other: `tau_s` (decay), `window_s` (a retention hint the
# engine never reads) and `CORR_WINDOW_BUFFER` (a record COUNT). A count bound
# cannot express a time horizon, so under load the record cap silently became
# the RCA horizon — 54.5 s of retained evidence against an engine that can still
# attach across several hundred seconds.
#
# The authority is the scoring rule itself (see `score_edges`):
#
#     w_t    = exp(-gap / tau_s)
#     weight = min(w_t * w_topo * w_r, 1.0)
#     admitted  iff  weight >= attach_threshold
#
# The `min(..., 1.0)` clamp cannot decide admission: it only ever binds when the
# product already exceeds 1.0, which is far above attach_threshold. So the
# admission boundary is exactly
#
#     exp(-gap / tau_s) * w_topo * w_r = attach_threshold
#
# and solving for gap gives the closed form below. Nothing here is a tunable —
# it is a consequence of the weights, so it cannot drift out of sync with them.

NEVER_ATTACHABLE = -1.0


def max_attachable_gap_s(cfg: EngineConfig, w_topo: float, *,
                         cross_modality: bool = False) -> float:
    """Largest event-time gap (seconds) at which a pair grounded at `w_topo`
    can still clear `attach_threshold`.

    Returns NEVER_ATTACHABLE when the grounding is too weak to admit at ANY
    gap — that is a real answer, not an error: it means retaining evidence for
    that grounding class buys nothing.
    """
    w_r = cfg.reinforce_cross_modality if cross_modality else 1.0
    product = w_topo * w_r
    if product < cfg.attach_threshold:
        return NEVER_ATTACHABLE          # weight < threshold even at gap 0
    return cfg.tau_s * math.log(product / cfg.attach_threshold)


def _grounding_weights(cfg: EngineConfig, *, topology_stale: bool = False
                       ) -> tuple[tuple[str, float], ...]:
    """The w_topo each grounding class contributes, in the same order and under
    the same §8 stale cap that `score_edges` applies."""
    weights = (
        ("containment", cfg.w_topo_containment),
        ("path", cfg.w_topo_path),
        ("seam", cfg.w_topo_seam),
        ("adjacency", cfg.w_topo_adjacency),
        ("inferred", cfg.w_topo_inferred),
        ("candidate", cfg.w_topo_candidate),
    )
    if topology_stale:
        return tuple((k, min(w, cfg.w_topo_stale_cap)) for k, w in weights)
    return weights


def temporal_reach_table(cfg: EngineConfig, *, topology_stale: bool = False
                         ) -> tuple[dict[str, object], ...]:
    """Every (grounding, modality) combination with its maximum attachable gap.

    This is the reporting form of `max_attachable_gap_s` — the operator-facing
    answer to "how far back can evidence still matter?"
    """
    rows: list[dict[str, object]] = []
    for name, w_topo in _grounding_weights(cfg, topology_stale=topology_stale):
        for cross in (False, True):
            rows.append({
                "grounding": name,
                "w_topo": w_topo,
                "cross_modality": cross,
                "w_r": cfg.reinforce_cross_modality if cross else 1.0,
                "max_gap_s": max_attachable_gap_s(cfg, w_topo, cross_modality=cross),
            })
    return tuple(rows)


def engine_temporal_reach_s(cfg: EngineConfig, *, topology_stale: bool = False) -> float:
    """The single number tracker 165 turns on: the largest event-time gap ANY
    admissible pair can span under `cfg`.

    Evidence older than this, relative to the newest signal, can no longer form
    an edge with anything — so this, not a record count and not `window_s`, is
    the floor for how much history the caller must retain. It is the ATTACH
    floor; evidence COMPLETENESS of an already-open episode is a separate and
    longer concern (an episode's own duration), which is why retention adds a
    lateness allowance on top rather than stopping here.
    """
    reaches = [max_attachable_gap_s(cfg, w, cross_modality=cross)
               for _name, w in _grounding_weights(cfg, topology_stale=topology_stale)
               for cross in (False, True)]
    return max(reaches)


def required_retention_s(cfg: EngineConfig, *, permitted_lateness_s: float = 0.0,
                         topology_stale: bool = False) -> float:
    """The retention horizon the evidence buffer must cover to preserve the
    engine's own semantics:

        retention = engine_temporal_reach + permitted_lateness

    `permitted_lateness_s` is the caller's measured allowance for evidence that
    arrives after its event time (ingestion delay, batching, replay) — it is a
    DEPLOYMENT fact, so it is supplied by the caller and never guessed here.
    """
    if permitted_lateness_s < 0:
        raise ValueError("permitted_lateness_s must be >= 0")
    return engine_temporal_reach_s(cfg, topology_stale=topology_stale) + permitted_lateness_s


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

    def membership_values(self) -> frozenset[str]:
        """`endpoint_values() | {seam_id}` — the exact token set rank-2 seam
        membership tests a node's `identity_refs()` against.

        Cached on the frozen instance (same `object.__setattr__` storage and
        recompute-on-copy rule as `ObjectSnapshot.content_hash`): the seam
        inventory is fixed for a cycle while this set is asked for once per
        (candidate pair x grounded seam) on the reconcile path, and rebuilding
        a two-element frozenset there buys nothing."""
        cached = getattr(self, "_membership_c", None)
        if cached is not None:
            return cached
        value = self.endpoint_values() | {self.seam_id}
        object.__setattr__(self, "_membership_c", value)
        return value


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
    # Storm-mode dedup (design 2026-08-28 §1): how many raw signal INSTANCES this
    # node represents. 1 in normal operation and default for every non-storm node,
    # so a healthy node is byte-identical to pre-storm. Under a declared storm the
    # node's repeated signals are collapsed to one representative per grounding
    # identity and this carries the original count — the "occurrences" the operator
    # sees. Deterministic (a pure function of the window), so replay reproduces it.
    occurrences: int = 1

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
        `site` (a physical site is a legitimate locality subject).

        TRACKER 168 — the same weld class, third instance: a node's OWN
        device-local component name. An interface name is unique only within its
        device, so a bare `GigabitEthernet0/5` token made every device in the
        estate that owns one a rank-7 candidate of every other (measured at 1K:
        48 index groups of 1,000 nodes, ~25.1M candidate pairs; reproduced as two
        unrelated devices fusing into one RCA object at weight 0.452). Producers
        no longer emit it — they qualify a device-local name as `device:name`, or
        drop it where `entity_id` already carries it. This filter is the
        STRUCTURAL backstop for that: on a device-scoped id (`device:component`)
        the bare `component` can never be a grounding subject, whatever a
        producer emits. The full id and the device part remain subjects, so
        same-interface cross-modality correlation is untouched — that relation
        runs through `device:component`, which IS globally unique."""
        observers = {s.observer.observer_id for s in self.signals if s.observer.observer_id}
        # Cloud-plane nodes: region/site is a coarse locality, not a topology subject.
        site_is_subject = self.entity_type not in (
            EntityType.APP, EntityType.CLOUD_RESOURCE, EntityType.SERVICE)
        # tracker 168: this node's own device-local component name. Never a
        # subject on its own — see the docstring. A path/segment id ('a->b') has
        # no single owning device, so it has no local component either.
        local = (self.entity_id.split(":", 1)[1]
                 if ":" in self.entity_id and "->" not in self.entity_id else None)
        toks = {self.entity_id}
        for s in self.signals:
            # entity_tokens can carry the measuring vantage (a probe's (prober, host));
            # the vantage is not a topology subject, the destination is.
            toks.update(t for t in s.entity_tokens
                        if t not in observers and t != local)
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

# ── rank-7 shared-token HUB CAP (tracker #168, Stage-2 Lever 1) ───────────────
#
# A bare shared token is the WEAKEST grounding tier (§3 rank 7, w=0.5, never
# authoritative): a coincidence detector, not a relationship. A token shared by
# MANY nodes is not a correlation signal at all — it is a non-specific HUB (a
# common interface name, a site label, a shared identifier) that welds unrelated
# devices together. #168 already ratified that a bare device-local component name
# must never weld the estate; this is the population-level backstop for the same
# weld class: a token whose group exceeds this cap emits NO all-pairs mesh.
#
# WHY THIS IS SAFE (the whole correctness argument). The cap touches ONLY the
# rank-7 bare-shared-token dimension. Every stronger relationship is carried by a
# SEPARATE index dimension and is untouched:
#   • rank 1 shared resource identity → identity_refs() overlap (a distinct set
#     that EXCLUDES free-text tokens/site — see Node.identity_refs). A device and
#     its interfaces share the device part as an identity REF, so their
#     containment edges survive even a >cap-interface device: the token cap can
#     never drop a rank-1 pair.
#   • rank 2/7 seam membership → seam-endpoint index (NOT capped).
#   • rank 3 L2/L3 adjacency → device-pair inventory (NOT capped).
#   • ranks 1–6 path/route → observation-membership + route-ref index (NOT capped).
# So a pair that shares a hub token AND any real rank-1–6 relationship is still
# generated by that dimension and still grounds at its real rank, byte-identical.
# Only pairs whose SOLE link is the hub token — the noise #168 exists to reject —
# are dropped.
#
# VALUE: 64. Conservative. A genuine bare-token correlation is a handful of nodes
# (a device + its interfaces, a small segment); 64 leaves every realistic
# small-group token correlation fully meshed while cutting the concentrated storm
# (measured: one 1,000-node hub group falls from C(1000,2)≈499,500 candidate
# pairs to 0, and total token-dimension generation becomes O(N·cap) not O(N²)).
# The rank-1 identity dimension is the safety net that lets the cap stay this low
# without losing any structural correlation. Env-overridable; deterministic (a
# pure function of group size, no clock/IO/dict-order dependence).
CORR_TOKEN_HUB_CAP = int(os.environ.get("CORR_TOKEN_HUB_CAP", "64"))

# ── per-cycle candidate ceiling — GENERAL backstop (§9 bounded, §16.1 loud) ────
#
# The hub-token cap (above) handles the ONE measured quadratic — the weak rank-7
# token dimension, which is pure noise and safe to drop. But an AUTHORITATIVE
# dimension (shared identity, seam membership, path/route observation) can also,
# in principle, form one very large all-pairs group (a seam with hundreds of
# members; a device with thousands of faulting sub-interfaces sharing its
# identity ref). Those are REAL rank-1–6 relationships — dropping them would lose
# correlations — so they are NEVER capped. Instead this ceiling is the safety
# net: if a cohort's candidate generation would exceed it, emission stops in a
# FIXED, deterministic group order (bounding the work rather than stalling), and
# the orchestration layer logs a WARNING naming the offending dimension/group and
# increments a metric. High by design — expected to essentially never fire once
# the hub cap is in; when it does, it means a genuinely pathological shape that an
# operator must SEE. A compact (non-all-pairs) representation for such a dimension
# is a deliberate FUTURE change, not something to build implicitly here.
CORR_CANDIDATE_CEILING = int(os.environ.get("CORR_CANDIDATE_CEILING", "3000000"))
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
    hub_tokens: frozenset[str] = frozenset(),
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
    # #168 Stage-2 Lever 1: hub tokens (shared by > CORR_TOKEN_HUB_CAP nodes) are
    # non-specific and never ground. A standalone caller has no window context, so
    # the default empty set means "no cap" (a single pair cannot know a token's
    # population); build_edges and the complexity reference pass the window's hub
    # set so the fast path, the reference and this gate all agree.
    shared = (ta & tb) - hub_tokens
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


class _CandidateIndex:
    """The linkable GROUPS of a retained node set, plus the reverse map from a
    node to the groups it sits in (tracker 166 Phase 4).

    `_candidate_pairs` used to build this on every transaction. It is a pure
    function of the node set, the seams, the adjacency inventory and the path
    index — none of which change inside a snapshot epoch — so it is built once
    per epoch and every cohort emits from it.

    The reverse map is what makes emission cohort-bounded rather than
    window-bounded. Without it a cohort still has to sweep every bucket in the
    window just to discover which ones it touches, which is O(retained nodes)
    however small the cohort is.

    `groups` are the sound superset's link sets in a FIXED order (token/identity
    buckets, then seam groups, then observation buckets, then the routed set) so
    emission is order-independent and replay-stable. `adj_by_node` carries the
    L2/L3 adjacency rung, which is pair-shaped rather than group-shaped."""

    __slots__ = ("adj_by_node", "adj_pairs", "group_dims", "groups", "hub_pairs_skipped",
                 "hub_tokens", "largest_dim", "largest_size", "node_groups",
                 "potential_pairs")

    def __init__(
        self,
        n: int,
        toks: list[frozenset[str]],
        refs: list[frozenset[str]],
        seam_evs: list[frozenset[str]],
        devs: list[str | None],
        adjacency: TopologyAdjacency,
        memb: list[dict] | None,
        route_hits: list[bool] | None,
        token_hub_cap: int = CORR_TOKEN_HUB_CAP,
    ) -> None:
        # The token (rank-7) and identity-ref (rank-1) dimensions are built as
        # SEPARATE buckets so the #168 hub cap can touch ONLY the token one. The
        # combined token∪ref index is still built — but exclusively for the SEAM
        # group lookup, where a seam endpoint may be matched by a structural
        # identity ref (rank 2) OR a token (rank 7) and neither is capped.
        index: dict[str, list[int]] = {}
        tok_index: dict[str, list[int]] = {}
        ref_index: dict[str, list[int]] = {}
        for i in range(n):
            for t in toks[i]:
                tok_index.setdefault(t, []).append(i)
            for r in refs[i]:
                ref_index.setdefault(r, []).append(i)
            for t in toks[i] | refs[i]:
                index.setdefault(t, []).append(i)
        # rank-7 shared-token HUB CAP: a token shared by more than the cap is a
        # non-specific hub, not a signal — its O(N²) all-pairs mesh is pure noise
        # and is dropped from candidate generation (§CORR_TOKEN_HUB_CAP; #168).
        # Deterministic: a pure function of group size.
        self.hub_tokens: frozenset[str] = frozenset(
            t for t, m in tok_index.items() if len(m) > token_hub_cap)
        # #168 Stage-2 Lever 1 audit: how many all-pairs candidates the hub cap
        # kept out of the cycle (Σ C(size,2) over the dropped hub-token groups).
        self.hub_pairs_skipped: int = sum(
            len(m) * (len(m) - 1) // 2
            for t, m in tok_index.items() if t in self.hub_tokens)

        groups: list[tuple[int, ...]] = []
        # `group_dims` labels each group's grounding dimension so the per-cycle
        # candidate-ceiling backstop can NAME the offending dimension/group in its
        # WARNING (§10 observable) instead of stalling opaquely. AUTHORITATIVE
        # dimensions (identity/seam/observation/route) are NEVER capped — a large
        # group there is a real relationship, not noise — so the ceiling is the
        # only safety net for a pathological one; only the weak rank-7 token
        # dimension is dropped outright.
        group_dims: list[str] = []
        # rank 1 — shared resource identity (identity_refs overlap): NEVER capped.
        for members in ref_index.values():
            if len(members) > 1:
                groups.append(tuple(members))
                group_dims.append("identity")
        # rank 7 — bare shared token: the ONE capped dimension. A hub token (group
        # > cap) emits no mesh; a pair whose only link was that hub token is
        # dropped (it grounds to None now — the deliberate #168 quality change),
        # while a pair with any rank-1–6 relationship is still emitted above.
        for t, members in tok_index.items():
            if len(members) > 1 and t not in self.hub_tokens:
                groups.append(tuple(members))
                group_dims.append("token")
        # seam groups: all nodes matching one seam's endpoint values / seam_id
        for ev in seam_evs:
            group = sorted({m for v in ev for m in index.get(v, ())})
            if len(group) > 1:
                groups.append(tuple(group))
                group_dims.append("seam")
        # path relations: shared observation membership
        if memb is not None:
            obs_index: dict[str, list[int]] = {}
            for i, m in enumerate(memb):
                for oid in m:
                    obs_index.setdefault(oid, []).append(i)
            for members in obs_index.values():
                if len(members) > 1:
                    groups.append(tuple(members))
                    group_dims.append("observation")
        # route-touching nodes are ONE group (the unrestricted form linked them
        # all against each other, so they behave exactly like a bucket)
        if route_hits is not None:
            routed = tuple(i for i in range(n) if route_hits[i])
            groups.append(routed)
            group_dims.append("route")
        self.groups: tuple[tuple[int, ...], ...] = tuple(groups)
        self.group_dims: tuple[str, ...] = tuple(group_dims)

        node_groups: list[list[int]] = [[] for _ in range(n)]
        for g, grp in enumerate(self.groups):
            for i in grp:
                node_groups[i].append(g)
        self.node_groups: tuple[tuple[int, ...], ...] = tuple(
            tuple(g) for g in node_groups)

        # L2/L3 adjacency: nodes on the two ends of an inventoried link. Resolved
        # to node-index pairs once; a cohort reaches them through adj_by_node so
        # it never sweeps the whole link inventory.
        dev_index: dict[str, list[int]] = {}
        for i, d in enumerate(devs):
            if d:
                dev_index.setdefault(d, []).append(i)
        adj: set[tuple[int, int]] = set()
        for pair in adjacency.pairs:
            ends = sorted(pair)
            if len(ends) != 2:
                continue
            for i in dev_index.get(ends[0], ()):
                for j in dev_index.get(ends[1], ()):
                    if i != j:
                        adj.add((i, j) if i < j else (j, i))
        self.adj_pairs: frozenset[tuple[int, int]] = frozenset(adj)
        by_node: dict[int, list[int]] = {}
        for i, j in adj:
            by_node.setdefault(i, []).append(j)
            by_node.setdefault(j, []).append(i)
        self.adj_by_node: dict[int, tuple[int, ...]] = {
            k: tuple(v) for k, v in by_node.items()}

        # Per-cycle candidate-ceiling backstop accounting (§9 bounded / §10
        # observable). `potential_pairs` is the upper bound on the candidates a
        # FULL-window emission over this snapshot could produce — Σ C(size,2) over
        # every (already hub-capped) group plus the adjacency pairs. It is a pure
        # function of the index, so the orchestration layer can compare it to
        # CORR_CANDIDATE_CEILING once per epoch and, if a NON-token dimension has
        # produced a pathological all-pairs group, log a WARNING naming that
        # dimension/group and count it — instead of the engine silently stalling.
        # `largest_dim`/`largest_size` name that offender. This is expected to
        # essentially never fire once the hub-token cap is in.
        self.largest_size: int = max((len(g) for g in self.groups), default=0)
        self.largest_dim: str = ""
        if self.groups:
            gi = max(range(len(self.groups)), key=lambda k: len(self.groups[k]))
            self.largest_dim = self.group_dims[gi]
        self.potential_pairs: int = (
            sum(len(g) * (len(g) - 1) // 2 for g in self.groups) + len(self.adj_pairs))


def _emit_candidates(
    idx: _CandidateIndex, cohort: frozenset[int] | None = None,
    ceiling: int | None = None, stats: dict | None = None,
) -> set[tuple[int, int]]:
    """The SOUND candidate superset for resolve_grounding, emitted from a
    prebuilt index: every pair NOT in this set is guaranteed to ground to None
    (each grounding rung requires one of the overlaps indexed here), so pruning
    changes operation count only — never the admitted edges or the gap-hint
    total. Derivation, rung by rung:

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

    tracker 166: when a cohort is supplied, a group only needs the pairs that
    TOUCH it. The unrestricted form is O(group²) over every group in the window,
    so filtering its output afterwards left candidate GENERATION unbounded —
    which is why bounding only the scoring phase still produced transactions
    growing 12s -> 25s -> 54s. Pairing each cohort member against the group is
    O(|group ∩ cohort| x |group|) instead, and the reverse map means only the
    groups the cohort actually sits in are visited at all.

    Pure + deterministic: derived only from the same inputs resolve_grounding
    reads; the returned pair set is order-independent.

    `ceiling` (§9 bounded) is the per-emission candidate-count backstop. It is
    NOT the hub cap — the hub cap already dropped the weak token noise. This
    bounds an AUTHORITATIVE dimension that formed a pathological all-pairs group
    (identity/seam/observation/route are never dropped): once the emitted set
    reaches the ceiling, generation stops in the FIXED group order (groups then
    adjacency), so the bound is deterministic and replay-stable. When it fires it
    records the offending dimension/group into `stats` for the orchestration
    layer to log LOUDLY (§16.1) and metric — the engine never stalls silently."""
    cand: set[tuple[int, int]] = set()

    def _link(members: tuple[int, ...]) -> None:
        # The ceiling is checked INSIDE the mesh, not only between groups: a single
        # pathological group is itself O(size²), so a between-groups check alone
        # would not bound it. Deterministic — members are in fixed ascending order.
        if cohort is None:
            for x in range(len(members)):
                for y in range(x + 1, len(members)):
                    a, b = members[x], members[y]
                    if a != b:
                        cand.add((a, b) if a < b else (b, a))
                if ceiling is not None and len(cand) >= ceiling:
                    return
            return
        hot = [m for m in members if m in cohort]
        if not hot:
            return
        for a in hot:
            for b in members:
                if a != b:
                    cand.add((a, b) if a < b else (b, a))
            if ceiling is not None and len(cand) >= ceiling:
                return

    def _hit(dim: str, size: int) -> None:
        if stats is not None and not stats.get("ceiling_hit"):
            stats["ceiling_hit"] = True
            stats["ceiling_dimension"] = dim
            stats["ceiling_group_size"] = size
            stats["ceiling_emitted"] = len(cand)

    if cohort is None:
        for gi, members in enumerate(idx.groups):
            _link(members)
            if ceiling is not None and len(cand) >= ceiling:
                _hit(idx.group_dims[gi], len(members))
                return cand
        cand |= idx.adj_pairs
        if ceiling is not None and len(cand) >= ceiling:
            _hit("adjacency", len(idx.adj_pairs))
        return cand

    # Only the groups the cohort actually sits in can contribute a pair that
    # touches the cohort — that is what the reverse map is for. Sorted so the
    # visit order is deterministic (the result is a set either way; this keeps
    # the traversal reproducible for anyone reading a profile).
    touched = sorted({g for i in cohort for g in idx.node_groups[i]})
    for g in touched:
        _link(idx.groups[g])
        if ceiling is not None and len(cand) >= ceiling:
            _hit(idx.group_dims[g], len(idx.groups[g]))
            return cand
    # Ultra #18: the ceiling record must carry what THIS branch emitted. The
    # full-window branch above emits `idx.adj_pairs` whole, so its inventory
    # size IS the emission; here only the cohort-touching pairs are generated,
    # and recording the full inventory would misattribute the ceiling to a
    # dimension size that was never on the table (a 50k-link inventory named
    # for a 12-pair cohort emission sends the investigation at the wrong
    # population). Collected in a local set so the recorded size is the
    # DISTINCT pairs this emission produced — result-identical (`cand |=` of
    # the same pairs), deterministic, and O(cohort adjacency) it already paid.
    adj_emitted: set[tuple[int, int]] = set()
    for i in cohort:
        for j in idx.adj_by_node.get(i, ()):
            adj_emitted.add((i, j) if i < j else (j, i))
    cand |= adj_emitted
    if ceiling is not None and len(cand) >= ceiling:
        _hit("adjacency", len(adj_emitted))
    return cand


def _candidate_pairs(
    n: int,
    toks: list[frozenset[str]],
    refs: list[frozenset[str]],
    seam_evs: list[frozenset[str]],
    devs: list[str | None],
    adjacency: TopologyAdjacency,
    memb: list[dict] | None,
    route_hits: list[bool] | None,
    cohort: frozenset[int] | None = None,
    token_hub_cap: int = CORR_TOKEN_HUB_CAP,
) -> set[tuple[int, int]]:
    """Build-then-emit in one call. Retained as the direct entry point (and the
    reference the complexity tests pin); the engine itself goes through
    _CandidateIndex so the build is paid once per snapshot epoch."""
    return _emit_candidates(
        _CandidateIndex(n, toks, refs, seam_evs, devs, adjacency, memb, route_hits,
                        token_hub_cap),
        cohort)


@dataclass(frozen=True)
class WindowPrep:
    """Everything about one retained-node snapshot that is a PURE FUNCTION of
    that snapshot (tracker 166 Phase 2/5).

    THE DEFECT THIS EXISTS FOR. Bounding the cohort bounded pair emission but
    not the per-transaction FIXED cost: build_edges prepared toks/refs/seam
    memberships/path memberships for ALL n retained nodes and _candidate_pairs
    built its inverted index over all of them, on EVERY transaction. Pre-166
    that was paid once per cycle; splitting a cycle into ~8 cohorts paid it ~8x.
    Measured offline at 50,000 retained nodes: 5.99 s per transaction, ~48 s
    across 8 cohorts.

    LIFECYCLE — one immutable snapshot, one prep, many bounded cohorts, discard:
    the caller builds this once at the start of a drain epoch and passes it to
    every cohort in that epoch. It is NOT a process-lifetime cache and must
    never become one; it holds a reference to the whole node set, so an epoch
    that outlives its snapshot would pin released evidence in memory.

    INVALIDATION is by OBJECT IDENTITY, deliberately. `matches` compares the
    five inputs the preparation is derived from with `is`, so a prep can never
    be silently reused for a different snapshot: two distinct tuples are never
    the same object. A false negative (equal-but-distinct inputs) rebuilds,
    which is correct and merely slower — the conservative direction."""

    nodes: tuple[Node, ...]
    seams: tuple[SeamView, ...]
    cfg: EngineConfig
    adjacency: TopologyAdjacency
    paths: PathIndex | None
    toks: list[frozenset[str]]
    refs: list[frozenset[str]]
    declared: list
    windows: list
    devs: list[str | None]
    seams_sorted: tuple[SeamView, ...]
    seam_evs: list[frozenset[str]]
    seam_ident: list[frozenset[int]]
    seam_token: list[frozenset[int]]
    memb: list[dict] | None
    route_hits: list[bool] | None
    index: _CandidateIndex
    key_index: dict[str, int]
    # run_window-level snapshot. Empty/None when the prep was built by
    # prepare_window() for build_edges alone (the internal fallback path).
    window: tuple[Signal, ...] | list[Signal] | None = None
    sigs: tuple[Signal, ...] = ()
    tenant: str = ""
    identity_sigs: tuple[Signal, ...] = ()
    path_view: PathGraphView | None = None
    scoped_view: PathGraphView | None = None
    discovery: tuple = ()
    disc: tuple = ()

    def matches(
        self, nodes: tuple[Node, ...], seams: tuple[SeamView, ...],
        cfg: EngineConfig, adjacency: TopologyAdjacency, paths: PathIndex | None,
    ) -> bool:
        """Identity guard — see the class docstring. O(1) and incapable of a
        false positive."""
        return (self.nodes is nodes and self.seams is seams and self.cfg is cfg
                and self.adjacency is adjacency and self.paths is paths)

    def matches_window(
        self, window, seams: tuple[SeamView, ...], cfg: EngineConfig,
        adjacency: TopologyAdjacency, paths, discovery,
    ) -> bool:
        """The run_window-level guard. Same identity discipline as `matches`,
        over the inputs the whole prologue (sort, build_nodes, PathIndex,
        discovery scoping) is derived from."""
        return (self.window is window and self.seams is seams and self.cfg is cfg
                and self.adjacency is adjacency and self.path_view is paths
                and self.discovery is discovery)

    def cohort_indices(self, cohort_keys: frozenset[str]) -> frozenset[int]:
        """Node keys → node indices in O(cohort), not O(retained nodes)."""
        ki = self.key_index
        return frozenset(ki[k] for k in cohort_keys if k in ki)


def prepare_window(
    nodes: tuple[Node, ...], seams: tuple[SeamView, ...], cfg: EngineConfig,
    adjacency: TopologyAdjacency = NO_ADJACENCY,
    paths: PathIndex | None = None,
) -> WindowPrep:
    """Snapshot-wide preparation. Pure: no IO, no clock, no randomness, no
    dict-order dependence. Safe to call once per epoch and reuse across every
    bounded cohort in it."""
    n = len(nodes)
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
    return WindowPrep(
        nodes=nodes, seams=seams, cfg=cfg, adjacency=adjacency, paths=paths,
        toks=toks, refs=refs, declared=declared, windows=windows, devs=devs,
        seams_sorted=seams_sorted, seam_evs=seam_evs, seam_ident=seam_ident,
        seam_token=seam_token, memb=memb, route_hits=route_hits,
        index=_CandidateIndex(n, toks, refs, seam_evs, devs, adjacency, memb,
                              route_hits),
        key_index={nd.key: i for i, nd in enumerate(nodes)},
    )


def prepare_run_window(
    window: tuple[Signal, ...] | list[Signal],
    seams: tuple[SeamView, ...],
    cfg: EngineConfig | None = None,
    adjacency: TopologyAdjacency = NO_ADJACENCY,
    paths: PathGraphView | None = None,
    discovery: tuple = (),
) -> WindowPrep | None:
    """Build the snapshot epoch for ONE tenant's retained window.

    This is run_window's entire prologue, lifted so a drain epoch pays it once
    and every bounded cohort in that epoch reuses it. Returns None when the
    window yields nothing to correlate (empty, or no nodes) — exactly the two
    cases run_window returns [] for.

    Raises ValueError on a mixed-tenant window, at the same point and with the
    same message run_window always did: episodes never correlate across tenants
    (§7) and the caller partitions. Raising HERE means a caller that builds
    epochs up front learns about it before any cohort runs.

    Pure: no IO, no clock, no randomness. The direction oracle is deliberately
    NOT part of it — RecordingOracle is stateful and belongs to a transaction."""
    cfg = cfg or EngineConfig()
    sigs = tuple(sorted(window, key=lambda s: (s.ts, str(s.signal_id))))
    if not sigs:
        return None
    tenants = {s.tenant_id for s in sigs}
    if len(tenants) != 1:
        # Episodes never correlate across tenants (§7) — the caller partitions.
        raise ValueError(f"run_window requires a single-tenant window, got {sorted(tenants)}")
    tenant = sigs[0].tenant_id
    nodes = build_nodes(sigs)
    if not nodes:
        return None
    # #81 P5: the app-identity ENRICHMENT pool — excluded from build_nodes (so it can
    # never seed/extend an object), matched per-object below into an app-impact
    # projection. An identity-only window has no nodes → returns above → no object.
    identity_sigs = tuple(s for s in sigs if s.source is Source.APP_IDENTITY)
    # §6 rule 1 / §9 — the ONLY door to the path objects, tenant-scoped at construction.
    view = (paths or PathGraphView()).for_tenant(tenant)
    path_index = PathIndex(view, tenant) if not view.is_empty() else None
    # Path-causality P2: keep ONLY this tenant's discovery paths (§3a default-closed —
    # a path with a mismatched/empty tenant can never seed an attribution). object_
    # attribution re-scopes again; this is the structural first gate.
    disc = tuple(p for p in discovery if p.tenant_id and p.tenant_id == tenant)
    prep = prepare_window(nodes, seams, cfg, adjacency, path_index)
    return replace(
        prep, window=window, sigs=sigs, tenant=tenant,
        identity_sigs=identity_sigs, path_view=paths, scoped_view=view,
        discovery=discovery, disc=disc)


def build_edges(
    nodes: tuple[Node, ...], seams: tuple[SeamView, ...], cfg: EngineConfig,
    adjacency: TopologyAdjacency = NO_ADJACENCY,
    topology_stale: bool = False,
    directed: Oracle | None = None,
    paths: PathIndex | None = None,
    *,
    since_ts: float | None = None,
    work_sink: dict | None = None,
    cohort: frozenset[int] | None = None,
    prep: WindowPrep | None = None,
) -> tuple[tuple[Edge, ...], int]:
    """Returns (admitted edges, topology_gap_hints). Pairs are evaluated in
    deterministic node order; the earlier-onset node is always from_node.

    PERFORMANCE SHAPE (the #151-adjacent perf fix): the naive form recomputed
    tokens()/identity_refs()/path memberships and re-sorted the seams for every
    PAIR (~100µs/pair ⇒ ~48s synchronous at 1k nodes). Everything node-local is
    now precomputed ONCE per node, the seams are sorted once, and only pairs the
    inverted token/identity/seam/adjacency/observation index says are plausibly
    relatable are scored at all (_emit_candidates yields a sound superset, so the
    admitted edges and the gap-hint count are byte-identical to the naive loop —
    pinned by test_engine_complexity.py against a brute-force reference).
    Purity is untouched: no IO, no clock, no dict-order dependence.

    tracker 166 Phase 5 — `prep` is a WindowPrep for THIS node set, built once
    per snapshot epoch and reused by every cohort in it. There is exactly ONE
    implementation of the preparation (`prepare_window`): supplying a prep skips
    the rebuild, it does not take a different code path, so a prepped and an
    unprepped transaction cannot drift apart. A prep that does not match these
    inputs is rebuilt rather than trusted — see WindowPrep.matches."""
    n = len(nodes)
    if n < 2:
        return (), 0
    if prep is None or not prep.matches(nodes, seams, cfg, adjacency, paths):
        prep = prepare_window(nodes, seams, cfg, adjacency, paths)
    toks = prep.toks
    refs = prep.refs
    devs = prep.devs
    seams_sorted = prep.seams_sorted
    seam_ident = prep.seam_ident
    seam_token = prep.seam_token
    memb = prep.memb
    windows = prep.windows

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
        # rank 7 — bare shared token, MINUS hub tokens (#168 Stage-2 Lever 1): a
        # token shared by > cap nodes is a non-specific hub, not a relationship, so
        # it can no longer ground an edge (and its all-pairs mesh was already
        # dropped from candidate generation). A pair whose only shared token is a
        # hub grounds to None; one that also shares a real (non-hub) token still
        # grounds to that token. Uses the SAME hub set the candidate index built,
        # so the fast path and the grounding stay consistent.
        shared = (toks[ai] & toks[bi]) - prep.index.hub_tokens
        if shared:
            tok = min(sorted(shared))
            return _shared_token_grounding(tok)
        return None

    edges: list[Edge] = []
    total_pairs = n * (n - 1) // 2
    grounded_pairs = 0
    # §9 bounded backstop: cap candidate generation at CORR_CANDIDATE_CEILING in a
    # fixed, deterministic group order. The hub cap already removed the weak-token
    # quadratic; this only ever engages on a pathological AUTHORITATIVE group, and
    # records the offender into `_ceil` for the caller to log/metric (§10). Pure —
    # the bound is a deterministic function of the snapshot, replay-stable.
    _ceil: dict = {}
    candidates = sorted(_emit_candidates(prep.index, cohort,
                                         ceiling=CORR_CANDIDATE_CEILING, stats=_ceil))
    # tracker 166 — BOUNDED COHORT EVALUATION.
    #
    # `cohort` is the set of node indices that are NEW in this engine
    # transaction. When supplied, only pairs with at least one endpoint in the
    # cohort are evaluated; pairs where BOTH endpoints predate this transaction
    # were already evaluated when the later of them was itself new.
    #
    # WHY THIS IS SOUND, and why it is not the refuted old x old optimisation:
    # edge admission is PAIR-LOCAL (resolve_grounding reads only the two nodes
    # plus the embedded seam/adjacency/path context — see build_edges' contract
    # above), so a pair's verdict does not depend on which other pairs were
    # scored alongside it. Process cohorts in arrival order and every candidate
    # pair is evaluated exactly once: a pair spanning cohorts A and B (A before
    # B) is evaluated with cohort B, because at cohort A the other endpoint did
    # not exist yet.
    #
    # What it does NOT do is skip `new x old`. A new signal is still scored
    # against every eligible retained node inside the engine's temporal reach —
    # that is precisely the evidence tracker 165 exists to keep available, and
    # omitting it would silently undo that work. The saving is that `new x new`
    # is quadratic in COHORT size rather than in however many signals happened
    # to pile up while the previous transaction was running.
    # (the cohort restriction is applied INSIDE _candidate_pairs above, so
    # generation is bounded too — filtering here would have been too late)
    # tracker 166 phase 2 — WORK ACCOUNTING, not a behaviour change.
    #
    # The question the incremental design turns on is how much of each cycle
    # re-derives relationships whose inputs did not move. `_candidate_pairs` is
    # already a sound inverted-index superset, so the waste is not naive O(N^2)
    # over the window — it is that the SAME candidate pairs are re-grounded and
    # re-scored every cycle for signals that have not changed since the last one.
    #
    # A node counts as NEW when any of its signals arrived after `since_ts`; a
    # pair is then old x old (pure recomputation), new x old (genuinely required
    # — a new signal may legitimately attach to retained evidence) or new x new.
    # Recorded via a caller-supplied sink so the pure core stays pure.
    if work_sink is not None:
        fresh = [False] * n
        if since_ts is not None:
            for idx, nd in enumerate(nodes):
                fresh[idx] = any(s.ts.timestamp() > since_ts for s in nd.signals)
        old_old = new_old = new_new = 0
        for i, j in candidates:
            if fresh[i] and fresh[j]:
                new_new += 1
            elif fresh[i] or fresh[j]:
                new_old += 1
            else:
                old_old += 1
        work_sink.update({
            "nodes": n,
            "nodes_new": sum(fresh),
            "pairs_naive": total_pairs,
            "pairs_candidate": len(candidates),
            "pairs_old_old": old_old,
            "pairs_new_old": new_old,
            "pairs_new_new": new_new,
            # #168 Stage-2 Lever 1 observability: the hub cap's activity this
            # emission, plus the candidate-ceiling backstop's verdict (§10).
            "hub_tokens_capped": len(prep.index.hub_tokens),
            "hub_pairs_skipped": prep.index.hub_pairs_skipped,
            "candidate_ceiling_hit": bool(_ceil.get("ceiling_hit")),
            "candidate_ceiling_dimension": _ceil.get("ceiling_dimension", ""),
            "candidate_ceiling_group_size": _ceil.get("ceiling_group_size", 0),
        })
    for i, j in candidates:
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
    #
    # tracker 166: under a bounded cohort only part of the window is scored, so
    # `grounded_pairs` covers this transaction alone and the window-global figure
    # is not computable without doing the very work the cohort exists to avoid.
    # The count is therefore reported over the pairs this transaction actually
    # evaluated. That is a real change of meaning and it is confined to a
    # DIAGNOSTIC: the archive-slice contract already records the window-global
    # gap-hint count as the one thing that legitimately differs on replay, and it
    # is neither diffed nor part of the stored row set.
    if cohort is not None:
        gap_hints = len(candidates) - grounded_pairs
    else:
        gap_hints = total_pairs - grounded_pairs
    return tuple(sorted(edges, key=lambda e: (e.from_node, e.to_node))), gap_hints


# ── snapshots ─────────────────────────────────────────────────────────────────


# Serialize-and-hash the big top-level lists a CHUNK at a time so the C json
# encoder never holds the GIL across the whole (100k+ edge) storm object.
#
# WHY (profiled 2026-08-28, Lever 3): content_hash/material_hash are OFFLOADED to
# a worker thread, but a single monolithic `json.dumps` over a 180k-edge object
# holds the GIL through its C loop for the entire ~1.4s encode — so the loop
# thread's aiokafka heartbeat coroutine cannot be scheduled and the broker
# expires the session (measured heartbeat gap ~1.4s inline; several concurrent →
# the 15.7s worst-case loop stall). Encoding each list in Python-level chunks
# hands the GIL back at the interpreter's switch interval between chunks, so the
# heartbeat runs (measured gap ~16ms at chunk=512, wall unchanged vs the
# monolithic path). A ProcessPool alternative was rejected: its INPUT pickle of
# the large object holds the GIL on the loop thread just as long (measured gap
# ~611ms).
#
# BYTE-IDENTITY (NON-NEGOTIABLE — this is the replay pin AND the damping
# change-detector): the output MUST equal
#     sha256(json.dumps(blob, separators=(",",":"), sort_keys=True).encode())
#             .hexdigest()[:16]
# byte-for-byte, or replay drifts and every open object re-versions once on
# deploy. It does: every element is encoded by the SAME C `json.dumps` with the
# same separators/sort_keys, and a chunk of a list is that list's own
# `json.dumps` with its outer `[`/`]` stripped — so the reproduced stream (outer
# braces, sorted `"key":` pairs, `,` element separators, `[`/`]`, each element's
# own encoding) is identical to the monolithic encoder's. Pinned by the
# byte-identical digest tests in test_engine.py against an inline reference.
_DIGEST_CHUNK = 512

# P1 cohort-touch gate (docs/design/COHORT_TOUCH_GATE_P1_2026-08-28.md §3/§5):
# how often a snapshot's two digests were actually computed vs served from the
# per-instance cache below. The P1 proof is these numbers, not a feeling — a
# `cached` count that stays at zero means the memoization is not reaching the
# reconciliation path. Advisory under thread races (run_window and _snap_call
# both execute on the executor; a lost += undercounts, it can never change a
# digest), and read-only for the engine itself: nothing here is an input to any
# hash, verdict or ordering.
#
# P2 step 0 adds a THIRD kind, "blob": the hypotheses blob is not a digest, but
# it is the most expensive serialize a version pays and it is built by BOTH
# content_hash and to_object_row, so it is counted on the same surface
# (corr_snapshot_digest{kind="blob",result=computed|cached}).
_DIGEST_CACHE_STATS: dict[str, int] = {
    "content_computed": 0, "content_cached": 0,
    "material_computed": 0, "material_cached": 0,
    "blob_computed": 0, "blob_cached": 0,
}


def digest_cache_stats() -> dict[str, int]:
    """Snapshot of the digest computed/cached counters (§10 observable)."""
    return dict(_DIGEST_CACHE_STATS)


# ── P2 step 0a: the hypotheses-blob CYCLE cache ──────────────────────────────
#
# docs/design/DECISION_EVIDENCE_SPLIT_P2_2026-08-28.md §3/§9.0, measured in
# docs/scale/P2_COHORT_PROFILE_2026-08-28.md: `hypotheses_blob` is 16.4 % of
# cohort wall and it is built TWICE per persisted version — once inside
# `content_hash` (which embeds the blob) and once by `_persist_snapshot` for the
# corr_objects row. The two builds are the SAME pure function of the SAME frozen
# snapshot, so the second one is pure waste (~7 % of cohort wall, for free).
#
# WHY NOT ON THE INSTANCE. Tracker 156: 15-25K open snapshots x 5.7 KB-MBs of
# blob is exactly the RSS that tracker fought for, and P1 §3 explicitly forbids
# caching it there. So the cache is CYCLE-SCOPED: main.engine_cycle opens it on
# the way in and drops it in a `finally` on the way out, exactly like
# _WINDOW_INDEX_CACHE / _CYCLE_ROW_CACHE. Outside a cycle the cache is None and
# every call is a plain build — nothing is retained while the engine is idle.
#
# It holds a STRONG reference to each cached snapshot alongside its blob, so
# id() cannot be recycled onto a different object while the entry lives (the
# same identity-keyed pattern as catalog._VERSION_HASH_CACHE), and it is HARD
# BOUNDED: the access pattern is build-then-immediately-reuse (reconciliation
# computes content_hash, `_persist_snapshot` writes the row a few statements
# later), so a handful of entries is all the win there is, while an unbounded
# cycle cache over a storm cohort would retain a blob per open object — the very
# RSS shape this must not reintroduce. On overflow the OLDEST entry is dropped.
#
# Bytes: identical by construction. The cache returns what `hypotheses_blob()`
# returned; the function itself is untouched.
CORR_BLOB_CYCLE_CACHE = os.environ.get(
    "CORR_BLOB_CYCLE_CACHE", "1").lower() in ("1", "true", "yes")
_BLOB_CYCLE_CACHE_MAX = max(1, int(os.environ.get("CORR_BLOB_CYCLE_CACHE_MAX", "64")))
_BLOB_CYCLE_CACHE: dict[int, tuple[ObjectSnapshot, str]] | None = None


def blob_cycle_begin() -> None:
    """Open a cycle-scoped blob cache. Idempotent; a nested call resets it."""
    global _BLOB_CYCLE_CACHE
    _BLOB_CYCLE_CACHE = {} if CORR_BLOB_CYCLE_CACHE else None


def blob_cycle_end() -> None:
    """Drop the cycle-scoped blob cache. MUST run in a `finally` — a blob held
    past its cycle is retained RSS (tracker 156)."""
    global _BLOB_CYCLE_CACHE
    _BLOB_CYCLE_CACHE = None


def blob_cycle_size() -> int:
    """Entries currently held (0 when no cycle is open). Test/observability."""
    return 0 if _BLOB_CYCLE_CACHE is None else len(_BLOB_CYCLE_CACHE)


def cycle_hypotheses_blob(snap: ObjectSnapshot) -> str:
    """`snap.hypotheses_blob()`, served from the open cycle's cache if there is
    one. Byte-identical to calling the method directly — this only decides how
    many times it runs, never what it returns.

    Advisory under thread races exactly like the digest cache: `_snap_call`
    offloads big objects to the executor, so two threads can build the same
    blob concurrently. Both build the same bytes; a lost counter increment
    undercounts and can never change a hash, a row or an ordering."""
    cache = _BLOB_CYCLE_CACHE
    if cache is None:
        _DIGEST_CACHE_STATS["blob_computed"] += 1
        return snap.hypotheses_blob()
    hit = cache.get(id(snap))
    if hit is not None and hit[0] is snap:
        _DIGEST_CACHE_STATS["blob_cached"] += 1
        return hit[1]
    _DIGEST_CACHE_STATS["blob_computed"] += 1
    value = snap.hypotheses_blob()
    if len(cache) >= _BLOB_CYCLE_CACHE_MAX:
        # FIFO by insertion order: the oldest entry is the one whose
        # build-then-reuse pair is already spent.
        del cache[next(iter(cache))]
    cache[id(snap)] = (snap, value)
    return value


def _streaming_json_digest16(blob: dict) -> str:
    h = hashlib.sha256()
    buf = bytearray()
    _FLUSH = 1 << 16  # flush at 64 KiB — above hashlib's GIL-release threshold,
    #                   so the C digest update yields too, and amortizes update().

    def emit(s: str) -> None:
        buf.extend(s.encode())
        if len(buf) >= _FLUSH:
            h.update(buf)
            buf.clear()

    def emit_bytes(b: bytes) -> None:
        buf.extend(b)
        if len(buf) >= _FLUSH:
            h.update(buf)
            buf.clear()

    first_key = True
    emit("{")
    for key in sorted(blob):
        if first_key:
            first_key = False
        else:
            emit(",")
        # str keys escape identically to the monolithic encoder's key emission.
        emit(json.dumps(key, separators=(",", ":")))
        emit(":")
        value = blob[key]
        if isinstance(value, list):
            if not value:
                emit("[]")
                continue
            emit("[")
            first_chunk = True
            for i in range(0, len(value), _DIGEST_CHUNK):
                sub = value[i:i + _DIGEST_CHUNK]
                # json.dumps(sub) == "[" + <elems joined by ","> + "]"; strip the
                # brackets and re-join chunks with "," to rebuild the full array's
                # exact byte stream. The Python-level loop yields the GIL here.
                enc = json.dumps(sub, separators=(",", ":"),
                                 sort_keys=True).encode()
                if first_chunk:
                    first_chunk = False
                else:
                    emit(",")
                emit_bytes(enc[1:-1])
            emit("]")
        else:
            emit(json.dumps(value, separators=(",", ":"), sort_keys=True))
    emit("}")
    h.update(buf)
    return h.hexdigest()[:16]


# ── P3 aggregation provenance (design AGGREGATION_PLANE_P3_2026-08-29 §5, step 3)
#
# The Aggregation plane (`aggregation.py`) forwards DELTA signals: one signal
# that stands for N raw observations of the same `AggKey`, annotated in `attrs`
# with what it collapsed. An object built from deltas must therefore be able to
# say — from its OWN persisted bytes, with no live plane and no second store —
# WHICH aggregation policy produced its evidence and HOW MUCH raw observation
# that evidence covers. That is what this projection is.
#
# THREE properties it is built for, in the order they matter:
#
#  1. PRESENT-ONLY. An object whose signals carry no `agg_key` gets NO block, so
#     its `hypotheses_blob` — hence its `content_hash`, hence its replay pin —
#     is byte-identical to pre-P3. This is the `storm_occurrences` precedent
#     (see hypotheses_blob's degradation branch) applied verbatim: a new
#     representation may not churn the objects that do not use it.
#  2. PURE PROJECTION OF THE OBJECT'S OWN SIGNALS. Nothing here reads the live
#     plane, a clock, or module state — only `attrs` that travel with each
#     Signal into `corr_signals_archive`. So `replay`, re-running `run_window`
#     over the archived slice, re-derives the IDENTICAL block; a difference is
#     real drift (a lost annotation, a truncated attrs blob, a changed policy)
#     and `replay._diff` reports it loudly instead of swallowing it.
#  3. BOUNDED. A storm object can hold ~180k signals; every field below is a
#     counter, a min/max, or a set whose cardinality is fixed by the DeltaClass
#     enum (8) or explicitly capped (partitions). Nothing grows with the object.
#
# WHY NOT INSIDE `degradation`. Storm dedup lives there because it IS
# degradation — a load-dependent, lossy-looking collapse the reader must be
# warned about. The Aggregation plane is normal, always-on, lossless operation
# (the raw rows are all in `corr_signals`; §3 "Lossless"), so filing it under
# "degradation" would misreport a healthy object as degraded and would make
# `StoredObject.degradation()` — which feeds `topology_stale`/`storm_mode`
# straight back into `run_window` — carry a flag it must not carry. It is a
# sibling PROVENANCE key of `grounding_context` instead, next to `provenance`.

# The attrs `aggregation.AggPlane._annotate` stamps. Named here rather than
# imported so `engine` keeps ZERO dependency on the plane (§2 "no hidden
# coupling"): the engine reads annotations off a Signal, it does not aggregate.
AGG_ATTR_KEY = "agg_key"
AGG_ATTR_POLICY = "agg_policy"
AGG_ATTR_CLASS = "agg_class"
AGG_ATTR_COUNT = "agg_count"
AGG_ATTR_FIRST = "agg_first_ts"
AGG_ATTR_LAST = "agg_last_ts"
AGG_ATTR_OFFSETS = "agg_offset_range"
# Partitions listed in the embedded offset range. One object's evidence comes
# from the partitions its entities hash to; the cap is the bound that keeps the
# blob's size independent of the estate, and an elision is DECLARED
# (`offsets_truncated`), never silent.
AGG_MAX_OFFSET_PARTITIONS = 16


def aggregation_block(signals: Iterable[Signal]) -> dict:
    """The `grounding_context.aggregation` provenance block, or `{}`.

    `{}` — falsy, so the caller embeds nothing — whenever NO signal carries an
    `agg_key`, which is every object on the un-aggregated path.

    THE COUNTS, exactly (the memo-§24 question "do counts reflect forwarded
    deltas or raw coverage?" answered in the bytes rather than in prose):

      `deltas`  = signals in this object that carry aggregation annotation. This
                  is the same population `ObjectSnapshot.signal_count()` counts,
                  minus any un-annotated remainder — see `unaggregated`.
      `keys`    = distinct `AggKey` tokens behind those deltas.
      `raw_signal_count` = Σ over distinct key of MAX(`agg_count`) seen for that
                  key. It is a LOWER BOUND on raw coverage, and the docstring
                  says so because the arithmetic says so:
                    * `agg_count` is the key's CUMULATIVE count at the moment
                      that delta was emitted, so SUMMING the deltas of one key
                      would count the same raw observations once per delta
                      (a key emitting FIRST at 1 and COUNT_THRESHOLD at 10 has
                      seen 10 raw events, not 11). MAX is the correct reducer.
                    * repeats that arrive AFTER a key's last delta are absorbed
                      into plane state and never re-announced, so the object
                      cannot see them. The true count for such a key is ≥ the
                      max it observed, with equality iff the last delta was the
                      key's last observation.
                  The EXACT raw ledger is the plane's own (`AggPlane.raw_count`
                  / `corr_signals`, which still holds every raw row); this field
                  is the object-local, replay-derivable share of it. The
                  equivalence suite asserts exact coverage at the KEY level
                  (test_p3_equivalence.py), which is exact, rather than
                  pretending this sum is.
      `classes` = DeltaClass histogram (≤ 8 entries, closed set).

    Deterministic: sorted keys, sorted class names, ISO strings compared as
    strings (they are UTC ISO-8601 from one formatter, so lexical order is
    chronological order).
    """
    per_key: dict[str, int] = {}
    classes: dict[str, int] = {}
    policies: set[str] = set()
    offsets: dict[int, tuple[int, int]] = {}
    first_ts = ""
    last_ts = ""
    deltas = 0
    unaggregated = 0
    for s in signals:
        attrs = s.attrs
        if not isinstance(attrs, dict):
            unaggregated += 1
            continue
        token = attrs.get(AGG_ATTR_KEY)
        if not isinstance(token, str) or not token:
            unaggregated += 1
            continue
        deltas += 1
        count = attrs.get(AGG_ATTR_COUNT)
        n = int(count) if isinstance(count, (int, float)) else 0
        if n > per_key.get(token, 0):
            per_key[token] = n
        cls = attrs.get(AGG_ATTR_CLASS)
        if isinstance(cls, str) and cls:
            classes[cls] = classes.get(cls, 0) + 1
        pol = attrs.get(AGG_ATTR_POLICY)
        if isinstance(pol, str) and pol:
            policies.add(pol)
        ft = attrs.get(AGG_ATTR_FIRST)
        if isinstance(ft, str) and ft and (not first_ts or ft < first_ts):
            first_ts = ft
        lt = attrs.get(AGG_ATTR_LAST)
        if isinstance(lt, str) and lt and lt > last_ts:
            last_ts = lt
        rng = attrs.get(AGG_ATTR_OFFSETS)
        if isinstance(rng, list):
            for item in rng:
                parsed = _parse_offset_range(item)
                if parsed is None:
                    continue
                part, lo, hi = parsed
                cur = offsets.get(part)
                if cur is None:
                    offsets[part] = (lo, hi)
                else:
                    offsets[part] = (min(cur[0], lo), max(cur[1], hi))
    if not deltas:
        return {}
    block: dict = {
        # One string, not a list: replay compares it against the running
        # `aggregation.AGG_POLICY_VERSION` and a mixed-policy object (which can
        # only happen across a policy rollout) must fail that comparison, which
        # a joined token does and a set membership test would not.
        "policy": "|".join(sorted(policies)),
        "deltas": deltas,
        "keys": len(per_key),
        "raw_signal_count": sum(per_key.values()),
        "classes": dict(sorted(classes.items())),
    }
    if first_ts:
        block["first_ts"] = first_ts
    if last_ts:
        block["last_ts"] = last_ts
    if offsets:
        ordered = sorted(offsets.items())
        block["offsets"] = [f"{p}:{lo}-{hi}"
                            for p, (lo, hi) in ordered[:AGG_MAX_OFFSET_PARTITIONS]]
        if len(ordered) > AGG_MAX_OFFSET_PARTITIONS:
            block["offsets_truncated"] = len(ordered) - AGG_MAX_OFFSET_PARTITIONS
    if unaggregated:
        # An object whose evidence is PART aggregated (a flag flip mid-window,
        # or a lane the plane does not sit on). Declared, so "deltas" is never
        # mistaken for the object's whole signal count.
        block["unaggregated"] = unaggregated
    return block


def _parse_offset_range(item: object) -> tuple[int, int, int] | None:
    """`"3:100-990"` -> `(3, 100, 990)`; None for anything else.

    Untrusted by construction (§3): the token comes off an archived attrs JSON
    that a replay may have loaded from disk, so it is PARSED, never eval'd, and
    a malformed one is skipped rather than raised — a corrupt provenance string
    must not be able to fail an object's serialization.
    """
    if not isinstance(item, str) or ":" not in item:
        return None
    part_s, _, span = item.partition(":")
    lo_s, _, hi_s = span.partition("-")
    try:
        return (int(part_s), int(lo_s), int(hi_s))
    except ValueError:
        return None


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
    # ── explicit storm mode (design 2026-08-28) — ALL default-inert so a non-storm
    # object (and a storm=False replay) is byte-identical to pre-change ────────────
    # This object IS the per-tenant "storm-noise" aggregate (§3): one bounded counter
    # object that stands in for a flood of low-value, below-floor singleton episodes
    # that would otherwise be silently skipped. False for every real correlation.
    storm_aggregate: bool = False
    # For a real storm object: the number of duplicate signal INSTANCES dedup (§1)
    # collapsed out of this object. For the aggregate object: the TOTAL occurrences
    # (raw signal instances) it counts. 0 otherwise. Embedded present-only.
    storm_occurrences: int = 0
    # Aggregate object only: how many distinct entities the noise spanned, and the
    # event-time span it covered. 0 for real objects.
    storm_distinct_entities: int = 0
    storm_window_span_s: float = 0.0
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
    # ── Tracker 155b (D1): the MATCHING-ONLY extension of this snapshot's
    # window_end, in seconds. 0.0 for EVERY snapshot `run_window` emits, so
    # `_windows_overlap` is byte-for-byte the predicate it always was for live
    # objects (pinned by the oracle in test_ownership_seed_155.py).
    #
    # It is non-zero for exactly one kind of snapshot: the tracker-155 ownership
    # SEED placeholder, which is reconstructed from a durable `corr_current` row
    # whose `window_end` is merely the last WRITTEN evidence time of a
    # still-OPEN incident — not the incident's end. The acquiring replica's own
    # window necessarily starts AFTER that (it spends the cold window
    # refilling), so a frozen end guarantees a miss of exactly the cold-window
    # duration: run ownership-155b-08310318 measured gaps of 10.1 / 18.0 /
    # 35.4 s against a frozen end and adopted 1 of 32 placeholders, the one
    # adoption landing on an inclusive-boundary touch rather than a margin.
    # The seed exists to BRIDGE that gap, so the placeholder's match window is
    # extended by how far evidence can still attach (see
    # CORR_OWNERSHIP_SEED_SLACK_S). It moves no persisted byte: a placeholder is
    # never persisted, and adoption replaces it with the ARRIVING snapshot
    # (slack 0.0).
    match_slack_s: float = 0.0
    # ── Tracker 155b (D3): this version PUBLISHED a verdict tier/hypothesis
    # CARRIED from the durable row it continues across an ownership handoff,
    # because the recomputation ran on a window that has not refilled yet.
    # These two fields record what the recomputation ACTUALLY produced, so the
    # carry is declared in the object's own bytes rather than inferred. Empty
    # for every ordinary version — the blob (hence content_hash and the replay
    # pin) is byte-identical when no carry happened, exactly like `degradation`
    # and `aggregation` above.
    carried_verdict_tier: str = ""
    carried_top_hypothesis: str = ""

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

    def agg_provenance(self) -> dict:
        """`aggregation_block` over this object's node signals, computed once.

        Cached exactly like `content_hash`/`material_hash` — same frozen-object
        argument, same `object.__setattr__` storage, same recompute-on-copy
        rule. The reason is cost, not convenience: `hypotheses_blob` is 16.4 %
        of the cohort profile (docs/scale/P2_COHORT_PROFILE_2026-08-28.md) and
        is built more than once per persisted version, and this projection walks
        every signal of an object that may hold ~180k of them. One walk per
        snapshot, not one per blob.
        """
        cached = getattr(self, "_agg_provenance_c", None)
        if cached is not None:
            return cached
        value = aggregation_block(s for n in self.nodes for s in n.signals)
        object.__setattr__(self, "_agg_provenance_c", value)
        return value

    def identity_refs(self) -> frozenset[str]:
        """REFS(x) — the union of this object's nodes' STRUCTURAL identity refs.

        `any(n.identity_refs() & ev for n in self.nodes)` and
        `bool(self.identity_refs() & ev)` are the same predicate: a union
        intersects `ev` exactly when some member does. Stating it as the union
        is what makes it CACHEABLE, and that is the whole point.

        TRACKER 185 (the 27,844 ms `reconcile.find_continuation` block). Node
        refs were rebuilt from scratch inside `_snap_touches_seam`, which
        `_seam_bridged` calls once per (candidate x grounded seam) — and
        `Node.identity_refs()` is itself O(|node.signals|) because it derives
        the observer set from the signals. So probing ONE storm aggregate (900+
        nodes, ~95k signals) against C open candidates cost O(C x Σ|signals|)
        and ran for 28 s on the event-loop thread. Computed once per snapshot it
        is O(Σ|signals|) for the whole probe, whatever C is.

        Cached exactly like `content_hash` / `agg_provenance`: stored via
        `object.__setattr__`, NOT a dataclass field (so it never enters
        __eq__/__hash__/replace()), recomputed on a copy, thread-safe by
        idempotence. It holds no new strings — every ref is already reachable
        from the node it came from — so the retained bytes are one pointer set
        per snapshot, not a second copy of the identity."""
        cached = getattr(self, "_identity_refs_c", None)
        if cached is not None:
            return cached
        out: set[str] = set()
        for n in self.nodes:
            out |= n.identity_refs()
        value = frozenset(out)
        object.__setattr__(self, "_identity_refs_c", value)
        return value

    def grounded_seam_ids(self) -> frozenset[str]:
        """G(x) — the seam ids this object holds an AUTHORITATIVE seam-grounded
        edge on (a rank-7 token-matched seam edge is a name coincidence and may
        never justify a fold).

        Cached for the same reason and in the same way as `identity_refs`: it is
        O(|edges|) and `_seam_bridged` asked for it once per candidate PAIR."""
        cached = getattr(self, "_grounded_seams_c", None)
        if cached is not None:
            return cached
        value = frozenset(e.grounding.ref for e in self.edges
                          if e.grounding.kind == "seam" and e.grounding.authoritative)
        object.__setattr__(self, "_grounded_seams_c", value)
        return value

    def signal_count(self) -> int:
        """Signals attached to this object's nodes — i.e. what the ENGINE WINDOW
        held for it, which is `corr_objects.signal_count`.

        P3 DECISION (memo §24, design §5). With the Aggregation plane ON this
        counts FORWARDED DELTAS, not raw observations, and that is deliberate:
          * the column's meaning is "how much evidence this object reasoned
            over". Node/edge/rank consume deltas, so deltas is the honest
            answer; redefining it as raw coverage would make it disagree with
            `node_count`, with the archived slice's row count, and with
            `replay`'s own `fresh.signal_count()` recomputation — the drift
            check would then fire on every aggregated object.
          * raw coverage is a DIFFERENT question with a different answer, and it
            is published separately as `grounding_context.aggregation
            .raw_signal_count` in the hypotheses blob (see `aggregation_block`).
            It goes in the blob rather than in a new `raw_signal_count` COLUMN
            because a column needs a ClickHouse migration for a number only
            aggregated objects have, and the blob is already the present-only
            home for exactly this kind of representation provenance.
          * `corr_signals` still holds every raw row, so the accounting gate
            (raw received == raw persisted) is untouched by either choice.
        """
        return sum(len(n.signals) for n in self.nodes)

    def affected(self) -> dict:
        """The blast radius: the ENTITIES this object touches, per bucket.

        P3: unchanged by the Aggregation plane and unchanged ON PURPOSE. It is a
        projection of node IDENTITY, never of signal volume, and the plane emits
        at least one delta (the FIRST) for every `AggKey` it creates — so every
        entity that produced any observation still produces at least one signal
        the engine sees. Collapsing repeats therefore cannot remove an entity
        from a blast radius; `test_p3_equivalence.py` pins that as set equality
        between the flag-OFF and flag-ON legs of the same stream.
        """
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

    def typed_edge_row_page(self, version: int, start: int, stop: int) -> list[dict]:
        """A bounded [start:stop) page of to_typed_edge_rows, in the SAME order.

        The P0 boundedness pass (docs/scale/ENGINE_DECISION_2026-08-28.md #1/#2)
        emits the child rows of a storm object in bounded pages so no single
        synchronous serialize step scales with the whole (up to ~180k-edge)
        object. Concatenating every page reproduces to_typed_edge_rows exactly —
        this is a pure slice of the SAME per-edge builder, not a second one, so
        row bytes and order are identical (pinned by test_bounded_object_paging)."""
        return [e.to_typed_row(self.tenant_id, self.correlation_id, version)
                for e in self.edges[start:stop]]

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
            deg: dict = {"topology_stale": self.topology_stale, "storm_mode": self.storm_mode}
            # Storm dedup/aggregate counts live INSIDE the degradation block and only
            # when non-zero, so a healthy or merely topology-stale object's blob (hence
            # content_hash + replay pin) is byte-identical to pre-storm-mode — the
            # counts appear exclusively on objects a declared storm actually degraded
            # (design §"Hash contract": present-only, degradation-scoped).
            if self.storm_aggregate:
                deg["storm_aggregate"] = {
                    "occurrences": self.storm_occurrences,
                    "distinct_entities": self.storm_distinct_entities,
                    "window_span_s": round(self.storm_window_span_s, 3),
                }
            elif self.storm_occurrences:
                deg["deduped"] = self.storm_occurrences
            ctx["degradation"] = deg
        # ── P3 step 3: aggregation provenance, PRESENT-ONLY ─────────────────
        # Embedded exactly like `degradation` above and for the same reason: an
        # object built from DELTA signals must carry, in its own bytes, which
        # aggregation policy produced its evidence and how much raw observation
        # that evidence stands for — otherwise a stored object is unreadable
        # without the live plane, and `replay` has nothing to check the policy
        # pin against. Absent for every un-aggregated object, so the blob (hence
        # content_hash, hence the replay pin) does not move on the flag-OFF path.
        # See `aggregation_block` for why it is NOT inside `degradation`.
        agg = self.agg_provenance()
        if agg:
            ctx["aggregation"] = agg
        # Tracker 155b (D3): the ownership-handoff verdict carry, PRESENT-ONLY
        # and for the same reason `degradation` is — a stored object must be
        # readable without the live state that produced it. The row's verdict
        # columns carry the durable FLOOR (the tier the previous owner's
        # evidence already supports); this block records the tier/hypothesis
        # this replica's partially-refilled window recomputed, and why the two
        # differ. Nothing is fabricated: signal_count / node_count / hypotheses
        # / evidence_missing remain this replica's own honest recomputation.
        if self.carried_verdict_tier or self.carried_top_hypothesis:
            ctx["ownership_handoff"] = {
                "note": ("verdict carried across ownership handoff pending "
                         "window refill"),
                "recomputed_verdict_tier": self.carried_verdict_tier,
                "recomputed_top_hypothesis": self.carried_top_hypothesis,
            }
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
        timestamps-of-persistence. Same evidence ⇒ same hash ⇒ no new version.

        P1 §3 (docs/design/COHORT_TOUCH_GATE_P1_2026-08-28.md): the digest is a
        pure function of a FROZEN dataclass, so it has exactly one value for the
        life of the instance — compute it once. The cache is stored via
        object.__setattr__ and is deliberately NOT a dataclass field, so it never
        enters __eq__/__hash__/replace(): a dc_replace copy (the continuation
        re-key) is a fresh, uncached object and recomputes, which is the
        conservative reading. Thread-safe by idempotence — a race recomputes the
        same 16 characters, it can never produce different ones."""
        cached = getattr(self, "_content_hash_c", None)
        if cached is not None:
            _DIGEST_CACHE_STATS["content_cached"] += 1
            return cached
        _DIGEST_CACHE_STATS["content_computed"] += 1
        value = self._content_hash_uncached()
        object.__setattr__(self, "_content_hash_c", value)
        return value

    def _content_hash_uncached(self) -> str:
        """content_hash's BODY, byte-for-byte unchanged (P1 §9.2). The wrapper
        above only caches what this returns — the replay pin never moves."""
        # Byte-identical to json.dumps(...,separators=(",",":"),sort_keys=True)
        # + sha256[:16], but chunk-serialized so the C encoder never holds the
        # GIL across the whole storm object (see _streaming_json_digest16). This
        # is the replay pin — its output MUST NOT move.
        return _streaming_json_digest16({
            "nodes": [n.key for n in self.nodes],
            "signals": sorted(str(s.signal_id) for n in self.nodes for s in n.signals),
            "edges": [e.to_ch_row("", "", 0) for e in self.edges],
            # P2 step 0a: the SAME hypotheses_blob(), served from the cycle
            # cache when main has one open so this version's second build (the
            # corr_objects row) is free. Bytes unchanged — the cache returns
            # what the method returned.
            "hypotheses": cycle_hypotheses_blob(self),
            "engine": self.engine_ver,
        })

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
        moves, on a heartbeat, or on a lifecycle transition.

        P1 §3: cached per instance exactly like content_hash — same frozen-object
        argument, same object.__setattr__ storage, same recompute-on-copy rule.
        The damping change-detector's BYTES are untouched (the body moved into
        _material_hash_uncached verbatim)."""
        cached = getattr(self, "_material_hash_c", None)
        if cached is not None:
            _DIGEST_CACHE_STATS["material_cached"] += 1
            return cached
        _DIGEST_CACHE_STATS["material_computed"] += 1
        value = self._material_hash_uncached()
        object.__setattr__(self, "_material_hash_c", value)
        return value

    def _material_hash_uncached(self) -> str:
        """material_hash's BODY, byte-for-byte unchanged (P1 §9.2)."""
        r = self.ranking
        # Byte-identical to the monolithic json.dumps + sha256[:16] digest, but
        # chunk-serialized so the C encoder never holds the GIL across the whole
        # storm object (see _streaming_json_digest16). This is the damping
        # change-detector — its output MUST NOT move.
        return _streaming_json_digest16({
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
        })

    def top_confidence(self) -> float:
        r = self.ranking
        if r.top_hypothesis == "undetermined" or not r.hypotheses:
            return 0.0
        for h in r.hypotheses:
            if h.template_id == r.top_hypothesis:
                return h.confidence_rank
        return 0.0

    def to_object_row(self, version: int, state: str = "open", merged_into: str = "",
                      *, hypotheses: str | None = None,
                      affected: Mapping[str, Iterable[str]] | None = None) -> dict:
        """The corr_objects row. `hypotheses` is a PASS-THROUGH of an already-built
        hypotheses_blob() (P1 §3): one persist needs the blob for the row and the
        caller has usually just built it for the content hash, and the blob is the
        single most expensive serialize on a storm object. Deliberately NOT cached
        on the instance — 15–25K open snapshots x 5.7 KB–MBs is exactly the RSS
        tracker 156 fought for. None (the default, and every existing call site)
        rebuilds it here, so the row is byte-for-byte what it always was.

        TRACKER 187. `affected` is the same kind of PASS-THROUGH, and it exists for
        exactly one caller: a TERMINAL version (closed / merged), which must publish
        the monotone union of this object's own persisted history rather than the
        live window's projection — see `AffectedHistory`. It is NORMALIZED here
        (sorted, empty buckets dropped) so the column is a deterministic function of
        the set the caller accumulated, whatever order it accumulated it in. None —
        the default, every non-terminal version, and every existing call site —
        takes `self.affected()`, byte-for-byte what it always was."""
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
            "hypotheses": self.hypotheses_blob() if hypotheses is None else hypotheses,
            "evidence_missing": json.dumps(list(r.evidence_missing), separators=(",", ":")),
            "affected": json.dumps(
                self.affected() if affected is None else _normalize_affected(affected),
                separators=(",", ":"), sort_keys=True),
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

    def edge_row_page(self, version: int, start: int, stop: int) -> list[dict]:
        """A bounded [start:stop) page of to_edge_rows, same order (P0 boundedness
        pass — see typed_edge_row_page). Concatenating every page reproduces
        to_edge_rows byte-for-byte (same per-edge builder, just sliced)."""
        return [e.to_ch_row(self.tenant_id, self.correlation_id, version)
                for e in self.edges[start:stop]]

    def _edge_evidence_row(self, e: Edge, version: int) -> dict:
        """The single corr_evidence row for one edge. Factored out (from
        to_evidence_rows) so the monolithic builder and the paged builder
        (evidence_row_page) share ONE source of truth — the paged path cannot
        drift from the byte-exact row the replay/golden suites pin."""
        return {
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
        }

    def _identity_evidence_row(self, s: Signal, version: int) -> dict:
        """The single corr_evidence row for one fused app-identity (#81 P5).
        Factored out alongside _edge_evidence_row — same single-source rationale."""
        attrs = s.attrs if isinstance(s.attrs, dict) else {}
        srcs = ",".join(str(x) for x in (attrs.get("sources") or [])) or "n/a"
        return {
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
        }

    def evidence_row_count(self) -> int:
        """Total corr_evidence rows this snapshot emits — the paging bound for
        evidence_row_page (one row per edge, then one per fused app-identity)."""
        return len(self.edges) + len(self.identity_signals)

    def to_evidence_rows(self, version: int) -> list[dict]:
        rows = [self._edge_evidence_row(e, version) for e in self.edges]
        # #81 P5: one explainable supporting-evidence row per fused identity that
        # named an affected app — carrying the REAL identity signal_id (provenance)
        # and its band/state/sources. role=supports: it supports the app-impact claim.
        rows.extend(self._identity_evidence_row(s, version)
                    for s in self.identity_signals)
        return rows

    def evidence_row_page(self, version: int, start: int, stop: int) -> list[dict]:
        """A bounded [start:stop) page over the logical evidence sequence — every
        edge row (indices [0, len(edges))) then every app-identity row — in the
        SAME order as to_evidence_rows. Concatenating every page reproduces
        to_evidence_rows byte-for-byte (P0 boundedness pass, single-source
        builders). `stop` is clamped to evidence_row_count() by the caller."""
        ne = len(self.edges)
        out: list[dict] = []
        for i in range(start, stop):
            if i < ne:
                out.append(self._edge_evidence_row(self.edges[i], version))
            else:
                out.append(self._identity_evidence_row(
                    self.identity_signals[i - ne], version))
        return out


# ── Tracker 187: an object's FINAL blast radius may not shrink below its own ──
# version history.
#
# THE DEFECT. `affected()` is a pure projection of `self.nodes`, and the nodes are
# whatever the ENGINE WINDOW still holds. That is the honest answer for an OPEN
# object — "here is what I can see right now" — and it is the wrong answer for the
# terminal version, which is the object's last word and the row every downstream
# reader (corr_current, the RCA report, the twin's `affected_includes` clause)
# treats as THE blast radius. Measured 2026-08-30 on the 2.5K P3 pair: 3-5
# `bgp_peer_flap` stories per 1,005-story leg where versions 1-4 (`open`) name the
# cause device and version 6 (`closed`) does not, because the cause's evidence aged
# out of the window before quiesce fired. Same story ids on BOTH arms — the loss is
# deterministic engine behaviour, not variance.
#
# THE RULE. A terminal version publishes the UNION of every version this object
# actually persisted, including its own. Non-terminal versions are untouched: a
# shrinking blast radius mid-flight is honest reporting of the current view, and
# only the FINAL word is claimed to be monotone.
#
# SCOPE. Strictly per-object: `AffectedHistory` is created with the registration
# and folds ONLY that object's own persisted projections. A merge does not pool
# two objects' radii (§3a stays trivially intact — one accumulator never sees a
# second object's entities, let alone a second tenant's).
#
# BOUND. One accumulator holds at most the distinct (bucket, entity_id) pairs the
# object ever PERSISTED, i.e. its lifetime entity population — which is itself
# bounded by the window (`WINDOW_BUFFER` is maxlen-capped) and by the object's
# lifetime (quiesce closes it after CORR_QUIESCE_S of silence; the 163 cap closes
# it sooner). `max_entities` makes that a declared number rather than an inherited
# one: past it the accumulator stops GROWING and counts the fact. Dropping the
# newest is the safe direction — the terminal version unions the accumulator with
# the live projection, so anything still in the window is published regardless of
# the cap, and only genuinely-aged-out history can be lost.
def _normalize_affected(affected: Mapping[str, Iterable[str]]) -> dict[str, list[str]]:
    """`affected()`'s output shape from any bucket->entities mapping: sorted
    members, empty buckets dropped. Order-independent by construction — that is
    what makes a replayed close hash and render identically."""
    return {k: sorted(v) for k, v in affected.items() if v}


class AffectedHistory:
    """Monotone accumulator of ONE object's blast radius across its persisted
    versions (tracker 187). Pure, order-independent and bounded.

    `note()` folds in one PERSISTED version's `affected()` projection; a damped or
    heartbeat-touched cycle persisted no version and contributes nothing, so the
    accumulator is exactly "the union over this object's version history" and never
    a wider claim than the history supports.
    """

    __slots__ = ("_buckets", "_size", "max_entities", "truncated")

    def __init__(self, max_entities: int = 0) -> None:
        self._buckets: dict[str, set[str]] = {}
        self._size = 0
        # <= 0 disables the cap (the accumulator is then bounded only by the
        # object's lifetime population, which is the natural bound above).
        self.max_entities = max_entities
        self.truncated = 0

    def note(self, affected: Mapping[str, Iterable[str]]) -> None:
        capped = self.max_entities > 0
        for bucket, entities in affected.items():
            col = self._buckets.get(bucket)
            if col is None:
                col = self._buckets[bucket] = set()
            for entity in entities:
                if entity in col:
                    continue
                if capped and self._size >= self.max_entities:
                    self.truncated += 1
                    continue
                col.add(entity)
                self._size += 1

    def merged_with(self, affected: Mapping[str, Iterable[str]]) -> dict[str, list[str]]:
        """The FINAL projection: this history unioned with one more version's
        (the terminal version's own). Sorted, so two replays of the same history
        in different arrival orders render byte-identical rows."""
        out: dict[str, list[str]] = {}
        # Sorted BUCKET order too, not only sorted members: the row is written
        # through json.dumps(sort_keys=True) so the bytes would be safe either
        # way, but a dict whose key order depends on set iteration is a trap for
        # every caller that compares the mapping itself (the tests below do).
        for bucket in sorted(set(self._buckets) | set(affected)):
            members = set(self._buckets.get(bucket, ()))
            members.update(affected.get(bucket, ()))
            if members:
                out[bucket] = sorted(members)
        return out

    def entity_count(self) -> int:
        """Distinct (bucket, entity) pairs retained — the accumulator's size, and
        the quantity `max_entities` bounds."""
        return self._size


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
    # tracker 166: the authoritative seam refs, bucketed by from_node in ONE
    # pass. This used to be a set-comprehension over the WHOLE edge set inside
    # the per-component loop — O(components x edges), and the carried-edge cache
    # plateaus around 384k entries live, so it was 4.5 s of a profiled 125 s
    # transaction and it ran once per cohort. Same refs, one sweep.
    seam_refs_by_from: dict[str, set[str]] = {}
    for e in edges:
        if e.grounding.kind == "seam" and e.grounding.authoritative:
            seam_refs_by_from.setdefault(e.from_node, set()).add(e.grounding.ref)
    seam_ordinal = {s.seam_id: i for i, s in enumerate(scoped)}
    memb: list[frozenset[int]] = []
    grounded: list[frozenset[int]] = []
    for comp in comps:
        refs = frozenset(r for n in comp for r in n.identity_refs())
        memb.append(frozenset(i for i, ev in enumerate(evs) if refs & ev))
        seam_ids: set[str] = set()
        for n in comp:
            seam_ids.update(seam_refs_by_from.get(n.key, ()))
        grounded.append(frozenset(seam_ordinal[r] for r in seam_ids
                                  if r in seam_ordinal))

    parent = list(range(len(comps)))

    def find(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    # tracker 166: fold BY SEAM, not by component pair. The pairwise form was
    # O(components^2 x seams). Two components fold via seam k exactly when both
    # are members of k and at least one of them GROUNDS k — so for each seam,
    # if any member also grounds it, every member of that seam joins one set.
    # Identical result: union-find always keeps the MINIMUM index as the root
    # (`parent[max] = min`), so the outcome does not depend on union order.
    members_of: list[list[int]] = [[] for _ in scoped]
    for i, ms in enumerate(memb):
        for k in ms:
            members_of[k].append(i)
    for k, member_comps in enumerate(members_of):
        if len(member_comps) < 2:
            continue
        if not any(k in grounded[i] for i in member_comps):
            continue
        base = member_comps[0]
        for other in member_comps[1:]:
            ri, rj = find(base), find(other)
            if ri != rj:
                parent[max(ri, rj)] = min(ri, rj)

    groups: dict[int, list[Node]] = {}
    for i, comp in enumerate(comps):
        groups.setdefault(find(i), []).extend(comp)
    return [tuple(sorted(g, key=lambda n: n.key))
            for _, g in sorted(groups.items(),
                               key=lambda kv: min(n.key for n in kv[1]))]


# ── explicit storm mode (design 2026-08-28) — deterministic, replay-safe, gated ──
#
# Everything below activates ONLY when run_window is called with storm_mode=True
# (the caller's _storm_state fired, or replay rehydrated a storm object). With
# storm_mode=False every path here is skipped and output is byte-identical to
# pre-change — pinned by the golden-wire/replay/166/162/168 suites. Each decision
# is a PURE function of the window content + the storm_mode flag: no wall-clock, no
# random, no dict-order. Replaying a storm object (replay passes the recorded flag)
# reproduces it byte-for-byte; re-running the SAME raw window with storm_mode=False
# reconstructs the full, non-degraded correlation (nothing was lost — the raw stays
# in the durable bus).


def _band_of(sig: Signal) -> str:
    """The app-identity band a signal carries in attrs (design §1 dedup key), '' when
    absent — pure, no default beyond the empty string."""
    return str(sig.attrs.get("band", "")) if isinstance(sig.attrs, dict) else ""


def _storm_dedup_node(node: Node) -> tuple[Node, int]:
    """§1 dedup: collapse a node's repeated signals to ONE representative per grounding
    identity + an occurrences count. Returns (possibly-rewritten node, collapsed count).

    The design's dedup identity is (entity_id, kind, severity, band); entity_id+kind
    are fixed within a node, so the intra-node key is (severity, band). We EXTEND it
    with the grounding-relevant fields (entity_tokens, site, path_id, data_class) so
    the representative is guaranteed identical in everything grounding reads — tokens(),
    identity_refs(), data_class(), peak_severity and onset are therefore byte-for-byte
    what the full node produced, and only the stored signal INSTANCE list shrinks.
    Deterministic: signals arrive sorted by (ts, signal_id), we keep the first per
    group (earliest), so the kept tuple is the same on every run and on replay."""
    if len(node.signals) <= 1:
        return node, 0
    rep: dict = {}
    for s in node.signals:  # sorted by (ts, signal_id) — first seen is the earliest
        attrs = s.attrs if isinstance(s.attrs, dict) else {}
        key = (s.severity, _band_of(s), s.entity_tokens, s.site, s.path_id,
               str(attrs.get("data_class", DataClass.LIVE.value)))
        if key not in rep:
            rep[key] = s
    kept = tuple(rep.values())  # insertion order == (ts, signal_id) order (dicts ordered)
    collapsed = len(node.signals) - len(kept)
    if collapsed == 0:
        return node, 0
    return replace(node, signals=kept, occurrences=len(node.signals)), collapsed


def _storm_dedup_comp(comp: tuple[Node, ...]) -> tuple[tuple[Node, ...], int]:
    """Dedup every node of a component. Grounding identity is preserved per node, so
    edges/ranking (computed from the ORIGINAL comp) never move — only the stored
    node.signals shrink, which cuts content_hash / evidence-row / serialization cost
    (the measured storm stall) without changing the verdict."""
    out = []
    total = 0
    for n in comp:
        dn, c = _storm_dedup_node(n)
        out.append(dn)
        total += c
    return tuple(out), total


class ComponentMemo:
    """Per-tenant, EPOCH-scoped cache of materialized objects, keyed by the
    component's node-key SET (P1 change G — docs/design/COHORT_TOUCH_GATE_P1_
    2026-08-28.md §2).

    WHY IT IS SOUND (§1 of that spec, verified against this file): within one
    drain epoch the nodes are frozen, `build_edges(cohort=…)` only ever scores
    pairs with an endpoint in the cohort, carried edges are filtered by a
    constant live-key set, and everything else a snapshot is built from (catalog,
    seams, cfg, adjacency, discovery, view, storm/stale declarations, versions) is
    per-epoch constant. So the edge set is MONOTONE inside an epoch and every
    new/replaced edge has a cohort endpoint — a component with no node key in
    `cohort_keys` therefore re-derives, bit for bit, the object the last cohort
    that touched it derived. Re-running rank + materialization for it is pure
    waste (the VERSIONS_DAMPED counter is the proof).

    KEYED ON THE NODE-KEY SET, NEVER THE CID: a component that MERGED with
    another has a different key, so it misses and is rebuilt — and it contains a
    touched node anyway, so it would not have been served from memo regardless.

    PURE DATA, caller-owned. It lives on `_EngineEpoch.memos` and is dropped in
    `_close_epoch`; cross-epoch reuse is P2 material (nodes are rebuilt after a
    prune, so the key would have to be content-addressed over signal ids) and is
    explicitly out of scope here.

    CONCURRENCY: run_window executes on the thread-pool executor, so this object
    is mutated off the loop — but access is strictly SEQUENTIAL (one awaited
    run_window per tenant per cohort, and the memo is per tenant), so no lock is
    needed. That invariant is a property of the caller; do not hand one memo to
    two concurrent run_window calls.

    §3a: one memo per TENANT. Node keys are not tenant-qualified, so two tenants
    with identically-named entities would collide in a shared memo — the caller
    keys the dict by tenant and this class never sees another tenant's data.
    """

    __slots__ = ("_by_key", "components", "hits", "misses", "touched")

    def __init__(self) -> None:
        self._by_key: dict[frozenset[str], ObjectSnapshot] = {}
        self.hits = 0          # components served from the memo
        self.misses = 0        # components MATERIALIZED (== "ranked")
        self.touched = 0       # components a cohort key actually touched
        self.components = 0    # components considered (above the open floor)

    def get(self, comp_key: frozenset[str]) -> ObjectSnapshot | None:
        return self._by_key.get(comp_key)

    def put(self, comp_key: frozenset[str], snap: ObjectSnapshot) -> None:
        self._by_key[comp_key] = snap


def run_window(
    window: tuple[Signal, ...] | list[Signal],
    catalog: Catalog,
    seams: tuple[SeamView, ...],
    cfg: EngineConfig | None = None,
    adjacency: TopologyAdjacency = NO_ADJACENCY,
    topology_stale: bool = False,
    storm_mode: bool = False,
    storm_agg_floor: str | None = None,
    directed: Oracle | None = None,
    paths: PathGraphView | None = None,
    discovery: tuple[AssembledPath, ...] = (),
    *,
    since_ts: float | None = None,
    work_sink: dict | None = None,
    cohort_keys: frozenset[str] | None = None,
    carried_edges: tuple[Edge, ...] = (),
    prep: WindowPrep | None = None,
    memo: ComponentMemo | None = None,
    rank_memo: RankMemo | None = None,
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

    `memo` is the caller-owned intra-epoch ComponentMemo (P1 change G). When it is
    present, a component NO cohort key touches is served from it instead of being
    re-ranked and re-materialized — see ComponentMemo for the soundness argument.
    `cohort_keys is None` (a full-window run: golden wire, replay, the tests) means
    EVERY component is touched, so the memo is never consulted and those paths are
    byte-for-byte unchanged. `memo=None` (the default, and CORR_COHORT_TOUCH_GATE=0)
    is exact pre-P1 behaviour.

    `rank_memo` is the caller-owned, PROCESS-lifetime level-1 memo (P2 step 2,
    `rank_memo.py`): a component whose evidence PROJECTION matches one already
    ranked — in this cohort, an earlier cohort, or an earlier epoch — skips
    `rank` and reuses its `RankingResult`. Everything else still runs: the
    snapshot is materialized for THIS epoch, and the tie-break / verdict caps /
    unknown-hop amendment are applied to the reused result exactly as they are
    to a fresh one. Gated exactly like the level-2 memo: `cohort_keys is None`
    (golden wire, replay, tests) never consults it, so those paths stay
    byte-for-byte unchanged. `rank_memo=None` (the default, CORR_RANK_MEMO=0 and
    CORR_COHORT_TOUCH_GATE=0) is exact pre-P2 behaviour.
    """
    cfg = cfg or EngineConfig()
    # tracker 166 Phase 2/5 — the whole prologue below (sort, tenant check,
    # build_nodes, identity pool, PathIndex, discovery scoping, per-node
    # preparation, candidate index) is a pure function of the retained snapshot
    # and was being paid ONCE PER COHORT. `prep` is that work, done once per
    # drain epoch by the caller. One implementation either way: an unmatched or
    # absent prep is rebuilt here, never worked around.
    if prep is None or not prep.matches_window(window, seams, cfg, adjacency,
                                               paths, discovery):
        prep = prepare_run_window(window, seams, cfg, adjacency, paths, discovery)
    if prep is None:
        return []
    tenant = prep.tenant
    nodes = prep.nodes
    identity_sigs = prep.identity_sigs
    path_index = prep.paths
    # A prep built by prepare_run_window always carries the tenant-scoped view;
    # the bare prepare_window form (build_edges' internal fallback) does not,
    # and an absent path graph is an EMPTY one, never a missing snapshot field.
    view = prep.scoped_view if prep.scoped_view is not None else PathGraphView()
    disc = prep.disc
    # Wrap the direction oracle so we capture exactly the orientations the edges were
    # built on — embedded per snapshot for deterministic replay (C7), like seams.
    # NOT part of the prep: RecordingOracle is stateful and per-transaction.
    rec = RecordingOracle(directed) if directed is not None else None
    # tracker 166: `cohort_keys` names the nodes that are new in this
    # transaction; `carried_edges` are the edges admitted for pairs that were
    # already evaluated in an earlier one. Components are built from the UNION,
    # so object formation sees the same edge set a full-window run would — the
    # bound is on what gets SCORED, never on what the engine gets to reason over.
    cohort_idx = (prep.cohort_indices(cohort_keys)
                  if cohort_keys is not None else None)
    edges, gap_hints = build_edges(nodes, seams, cfg, adjacency, topology_stale, rec,
                                   path_index, since_ts=since_ts, work_sink=work_sink,
                                   cohort=cohort_idx, prep=prep)
    if carried_edges:
        live = {n.key for n in nodes}
        fresh = {(e.from_node, e.to_node) for e in edges}
        edges = tuple(sorted(
            list(edges) + [e for e in carried_edges
                           if (e.from_node, e.to_node) not in fresh
                           and e.from_node in live and e.to_node in live],
            key=lambda e: (e.from_node, e.to_node)))
    open_floor = _SEV_RANK[Severity(cfg.severity_open_floor)]
    # §3/§5 aggregation floor: a below-`agg_floor` singleton episode (one that would
    # otherwise be silently skipped just below) is folded into the per-tenant storm
    # aggregate instead. Defaults to the open floor, so by default the aggregate
    # captures EXACTLY the below-open-floor singletons the engine already dropped —
    # never anything the severity_open_floor lets open a real object. Never above the
    # open floor: aggregation only ever touches BELOW what opens an object (§5).
    agg_floor = _SEV_RANK[Severity(storm_agg_floor)] if storm_agg_floor else open_floor
    agg_floor = min(agg_floor, open_floor)
    topo_ver = seams_hash(seams)
    eng_ver = engine_version(cfg)

    snapshots = []
    # §3 storm-noise aggregate accumulators (storm only) — the deduped low-value
    # nodes, their raw occurrence total, distinct entities and event-time span.
    _agg_nodes: list[Node] = []
    _agg_occurrences = 0
    _agg_entities: set[str] = set()
    _agg_ts_lo: datetime | None = None
    _agg_ts_hi: datetime | None = None
    _deduped_total = 0
    # Tracker 154b: seam-bridged components are ONE incident — fold before
    # minting objects (the folded id derives from the union's earliest node, so
    # a transient split re-derives the same identity it had before splitting).
    comps = _fold_seam_bridged_components(_components(nodes, edges), edges,
                                          seams, tenant)
    # tracker 166: bucket the edges by from_node ONCE. This filter used to run
    # inside the loop below — O(components x edges) — which the profiler caught
    # as 2,077,943 generator steps (4.1 s) in a single transaction, repeated for
    # every cohort. `edges` is sorted by (from_node, to_node) at every call site
    # (build_edges sorts, and the carried-edge union re-sorts by the same key),
    # so concatenating the buckets in sorted-key order reproduces the filtered
    # order exactly.
    edges_by_from: dict[str, list[Edge]] = {}
    for e in edges:
        edges_by_from.setdefault(e.from_node, []).append(e)
    for comp in comps:
        comp_keys = {n.key for n in comp}
        comp_edges = tuple(e for k in sorted(comp_keys)
                           for e in edges_by_from.get(k, ()))
        if not comp_edges and _SEV_RANK[comp[0].peak_severity] < open_floor:
            if storm_mode and _SEV_RANK[comp[0].peak_severity] < agg_floor:
                # §3: a below-agg-floor singleton episode. Non-storm it is silently
                # skipped (next line); under a declared storm it is folded into the
                # per-tenant storm-noise aggregate — ONE bounded counter object stands
                # in for the whole flood, so the noise is COUNTED and visible, never a
                # silent drop, and the O(objects×catalog) rank() cost of a flood of
                # weak singletons collapses to a single undetermined aggregate.
                for n in comp:  # a no-edge component is a single node
                    _agg_occurrences += len(n.signals)
                    _agg_entities.add(n.entity_id)
                    lo, hi = n.signals[0].ts, n.signals[-1].ts
                    _agg_ts_lo = lo if _agg_ts_lo is None else min(_agg_ts_lo, lo)
                    _agg_ts_hi = hi if _agg_ts_hi is None else max(_agg_ts_hi, hi)
                    dn, c = _storm_dedup_node(n)
                    _deduped_total += c
                    _agg_nodes.append(dn)
            continue  # singleton below the open floor: episode, not an object
        # ── P1 change G: the cohort-touch gate (spec §2) ──────────────────────
        # Everything ABOVE this point still runs every cohort: the storm-aggregate
        # branch rebuilds its counter object from ALL below-floor nodes, is O(nodes)
        # with no rank(), and must stay exactly where it is.
        #
        # From here down is the expensive part — rank() over the catalog, the
        # verdict gates, orientation/adjacency embedding, attribution, dedup and
        # the ObjectSnapshot materialization. A component no cohort key touches
        # would re-derive precisely the object the memo already holds, so it is
        # served from the memo instead. Emission ORDER is unchanged (same `comps`
        # iteration, the hit is appended in place), so the storm severity sort and
        # the non-storm order are the order they always were.
        comp_key = frozenset(comp_keys)
        touched = cohort_keys is None or not cohort_keys.isdisjoint(comp_key)
        if memo is not None:
            memo.components += 1
            if touched:
                memo.touched += 1
            else:
                hit = memo.get(comp_key)
                if hit is not None:
                    snapshots.append(hit)
                    memo.hits += 1
                    continue
            memo.misses += 1
        comp_sigs = tuple(s for n in comp for s in n.signals)
        # ── P2 step 2: the level-1 cross-epoch rank memo (spec §3) ────────────
        # `rank` is 31.8 % of cohort wall and is a pure function of the
        # evidence's kinds/entities/authorities and the catalog — never of the
        # signal INSTANCES. `rank_memo.rank_key` is exactly those inputs
        # (enumerated, with file:line refs, in that module's docstring), so a
        # component that re-appears in a later cohort or a later EPOCH with the
        # same evidence projection reuses its RankingResult instead of
        # re-scoring the whole catalog. The snapshot below is still built from
        # THIS epoch's nodes and edges; only the scoring is skipped.
        base_ranking: RankingResult | None = None
        rkey: str | None = None
        if rank_memo is not None and cohort_keys is not None:
            rkey = rank_key(tenant, catalog.version_hash(), comp_sigs)
            if rkey is None:
                rank_memo.unkeyable += 1     # fail-closed, never silent
            else:
                base_ranking = rank_memo.get(rkey)
        if base_ranking is None:
            base_ranking = rank(catalog, comp_sigs)
            if rank_memo is not None and rkey is not None:
                rank_memo.put(rkey, base_ranking)
        # Tracker 154a: grounded-seam-type affinity breaks equal-confidence ties.
        ranking = _break_ties_by_seam_affinity(
            base_ranking, comp_edges, seams, tenant)
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
        # §1 dedup: under a declared storm, store one representative per grounding
        # identity (edges/ranking above were computed from the FULL comp, so the
        # verdict never moves — only the stored instance list, hence content_hash /
        # evidence rows / serialization cost, shrinks). window_start/end/trigger stay
        # derived from the full comp_sigs so the incident's temporal extent is honest.
        store_nodes = comp
        obj_dedup = 0
        if storm_mode:
            store_nodes, obj_dedup = _storm_dedup_comp(comp)
            _deduped_total += obj_dedup
        snapshot = ObjectSnapshot(
            correlation_id=cid,
            tenant_id=tenant,
            window_start=min(s.ts for s in comp_sigs),
            window_end=max(s.ts for s in comp_sigs),
            trigger_signal=str(min((s for s in comp_sigs),
                                   key=lambda s: (s.ts, str(s.signal_id))).signal_id),
            nodes=store_nodes,
            storm_occurrences=obj_dedup,
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
        )
        snapshots.append(snapshot)
        # P1 change G: remember it for the cohorts in this epoch that do not
        # touch this component. Touched components are cached too — the next
        # cohort may well leave them alone.
        if memo is not None:
            memo.put(comp_key, snapshot)
    # §3/§5: emit the single per-tenant storm-noise aggregate for this window's
    # below-floor singleton flood. One bounded object with occurrences/distinct/span
    # replaces N weak singletons; it is marked storm_mode + storm_aggregate so replay
    # rebuilds it identically, and a storm=False re-run over the same raw window skips
    # this branch and reconstructs every underlying episode in full (nothing lost).
    if storm_mode and _agg_nodes:
        agg_nodes = tuple(_agg_nodes)
        first = min(agg_nodes, key=lambda n: (n.onset, n.key))
        agg_sigs = tuple(s for n in agg_nodes for s in n.signals)
        # The event-time bounds are set by the SAME fold loop that fills
        # _agg_nodes, so a non-empty _agg_nodes always has both. Narrowed
        # EXPLICITLY (not cast): if the two ever diverge, the aggregate falls back
        # to the bounds of the nodes it actually folded rather than claiming a
        # None window — a wrong-but-declared span beats an unhandled None, and the
        # fallback is unreachable today so no emitted object's bytes move.
        agg_lo = _agg_ts_lo if _agg_ts_lo is not None else min(s.ts for s in agg_sigs)
        agg_hi = _agg_ts_hi if _agg_ts_hi is not None else max(s.ts for s in agg_sigs)
        span = ((_agg_ts_hi - _agg_ts_lo).total_seconds()
                if _agg_ts_lo is not None and _agg_ts_hi is not None else 0.0)
        agg_dc = worst_data_class([n.data_class() for n in agg_nodes])
        # A noise counter is never a scored hypothesis — a fixed, O(1) undetermined
        # ranking (no rank() over the catalog), which is the point: the flood no
        # longer pays O(objects×catalog) scoring. Deterministic by construction.
        agg_ranking = RankingResult(
            top_hypothesis="undetermined",
            verdict_tier=VerdictTier.UNDETERMINED,
            hypotheses=(),
            evidence_missing=(),
            catalog_version=catalog.version_hash(),
        )
        # Tenant-constant id: ONE aggregate per tenant that VERSIONS across the storm
        # (find/merge/quiesce handle it like any open object) instead of churning a new
        # id each cycle. Replay recomputes the same id (pure function of tenant).
        agg_cid = str(uuid.uuid5(SIGNAL_NS, f"corrobj|{tenant}|storm-noise"))
        snapshots.append(ObjectSnapshot(
            correlation_id=agg_cid,
            tenant_id=tenant,
            window_start=agg_lo,
            window_end=agg_hi,
            trigger_signal=str(min(agg_sigs, key=lambda s: (s.ts, str(s.signal_id))).signal_id),
            nodes=agg_nodes,
            edges=(),
            ranking=agg_ranking,
            seams=seams,
            engine_ver=eng_ver,
            topology_version=topo_ver,
            gap_hints=0,
            topology_stale=topology_stale,
            storm_mode=True,
            storm_aggregate=True,
            storm_occurrences=_agg_occurrences,
            storm_distinct_entities=len(_agg_entities),
            storm_window_span_s=span,
            data_class=agg_dc,
            paths=view,
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


def _match_window_end(s: ObjectSnapshot) -> datetime:
    """The window end `_windows_overlap` matches against.

    EXACTLY `s.window_end` for every snapshot `run_window` emits — `match_slack_s`
    is 0.0 there and the branch short-circuits — so live-object matching is
    unchanged, byte for byte and object for object. See `ObjectSnapshot.
    match_slack_s` for the one snapshot that sets it (the tracker-155 ownership
    seed placeholder) and why a frozen end is a guaranteed miss for it.
    """
    return (s.window_end + timedelta(seconds=s.match_slack_s)
            if s.match_slack_s else s.window_end)


def _windows_overlap(a: ObjectSnapshot, b: ObjectSnapshot) -> bool:
    return (a.window_start <= _match_window_end(b)
            and b.window_start <= _match_window_end(a))


def _snap_grounded_seam_ids(snap: ObjectSnapshot) -> frozenset[str]:
    """Seam ids this object's graph GROUNDED on — authoritative rank-2 seam
    edges only (a rank-7 token-matched seam edge is a name coincidence and may
    never justify a fold). Thin alias for the cached accessor (tracker 185)."""
    return snap.grounded_seam_ids()


def _snap_touches_seam(snap: ObjectSnapshot, view: SeamView) -> bool:
    """Structural seam membership of the OBJECT: any node whose identity_refs
    intersect the seam's endpoint values ∪ {seam_id} — the exact rank-2
    membership test resolve_grounding trusts, never free-text tokens.

    Tracker 185: `any(n.identity_refs() & ev for n in snap.nodes)` is exactly
    `bool(REFS(snap) & ev)` — a union meets `ev` iff some member does — and the
    union form is the one that can be computed once per snapshot instead of
    once per (candidate x seam). Same answer, on identical inputs, always."""
    return bool(snap.identity_refs() & view.membership_values())


# (seams-tuple identity, tenant) -> (that tuple, seam_id -> the FIRST view of
# that id this inventory offers the tenant). See `_seam_view_index`.
_SEAM_VIEW_INDEX: dict[tuple[int, str], tuple[tuple, dict[str, SeamView]]] = {}
_SEAM_VIEW_INDEX_MAX = 4


def _seam_view_index(seams: tuple, tenant: str) -> dict[str, SeamView]:
    """seam_id -> the first view in `seams` that `tenant` may consult.

    `_seam_bridged` used to derive this by scanning `(*a.seams, *b.seams)` on
    EVERY candidate pair. `run_window` stamps the WHOLE tenant seam inventory
    into every snapshot it emits, so that scan is O(|inventory|) per pair —
    2,500 seams x thousands of pairs of pure re-derivation of a constant
    (tracker 185, and the same "the inventory is not per-object" defect the
    grounded re-keying fixed inside `ContinuationIndex`).

    Keyed by `id()` and VERIFIED by identity against the tuple held in the entry
    (plus the tenant it was filtered for), so a recycled id can never serve
    another inventory's map — the same rule `_CATALOG_PLAN_CACHE` and
    `ContinuationIndex._seam_map` follow. Hard-bounded at
    `_SEAM_VIEW_INDEX_MAX` entries (4, as `_CATALOG_PLAN_CACHE` is): the
    reconcile loop walks tenants sequentially and every candidate of a tenant
    shares one inventory, so one live entry serves a whole probe. What it
    retains is pointers into inventories every open snapshot of that cycle
    already holds — it adds no snapshot-sized state and cannot grow with the
    open-object population. On overflow the map is dropped whole and rebuilt,
    which is at worst the ONE scan the old code paid on every pair.

    Advisory under thread races, exactly like the digest caches: two threads may
    build the same map and one insertion may be lost. Both build the SAME map
    from the same frozen inventory, and the identity check means a lost or
    evicted entry can only cost a rebuild — never a wrong view."""
    key = (id(seams), tenant)
    hit = _SEAM_VIEW_INDEX.get(key)
    if hit is not None and hit[0] is seams:
        return hit[1]
    out: dict[str, SeamView] = {}
    for v in seams:
        if v.tenant_id in ("", tenant):
            out.setdefault(v.seam_id, v)
    if len(_SEAM_VIEW_INDEX) >= _SEAM_VIEW_INDEX_MAX:
        _SEAM_VIEW_INDEX.clear()
    _SEAM_VIEW_INDEX[key] = (seams, out)
    return out


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
    grounded = a.grounded_seam_ids() | b.grounded_seam_ids()
    if not grounded:
        return False
    # TRACKER 185. Identical to the previous `for v in (*a.seams, *b.seams):
    # if v.seam_id in grounded and tenant-ok: views.setdefault(v.seam_id, v)` —
    # a's inventory is consulted first and the FIRST admissible view of an id
    # wins, in both spellings — but driven from the grounded ids (a handful)
    # through a per-inventory map instead of by re-scanning both inventories
    # (thousands of views) on every candidate pair.
    a_views = _seam_view_index(a.seams, a.tenant_id)
    b_views = (a_views if b.seams is a.seams
               else _seam_view_index(b.seams, a.tenant_id))
    views: dict[str, SeamView] = {}
    for sid in grounded:
        v = a_views.get(sid)
        if v is None:
            v = b_views.get(sid)
        if v is not None:
            views[sid] = v
    return any(_snap_touches_seam(a, views[sid]) and _snap_touches_seam(b, views[sid])
               for sid in sorted(views))


def find_merges(
    survivors: list[ObjectSnapshot] | tuple[ObjectSnapshot, ...],
    candidates: list[ObjectSnapshot] | tuple[ObjectSnapshot, ...],
    min_overlap: float = 0.4,
    *,
    index: ContinuationIndex | None = None,
    entity_cache: dict | None = None,
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

    `index` and `entity_cache` are PURE PERFORMANCE inputs, exactly as
    find_continuation's are: they change which candidates are *examined* and how
    often an entity set is recomputed, never which survivor wins. `index` must
    be a ContinuationIndex built over the SAME survivor set (the winner is a
    total order on (jac desc, window_start asc, cid asc) over unique survivor
    cids, so the index's own ordering is irrelevant); it lets a caller build the
    index once and probe it over several candidate chunks. `entity_cache` holds
    the same frozensets `_entity_ids` would return, keyed by correlation_id.
    """
    surv = sorted(survivors, key=lambda s: (s.window_start, s.correlation_id))
    # TRACKER 162 PATTERN (Stage-2 Lever 2, results-preserving): index the
    # survivors so each stale candidate probes only the plausible merge targets
    # instead of the full survivor list — killing the O(survivors × stale)
    # cross-product under a storm. `find_merges`'s admission predicate is the
    # SAME (and symmetric) criterion `find_continuation` uses — entity-set
    # Jaccard ≥ min_overlap OR a shared grounded seam bridge — so the
    # ContinuationIndex superset PROVEN sound for continuation is sound here
    # too, built over the survivors and probed by the candidate. The unchanged
    # predicate then runs over the superset; the winner is a total order on
    # (jac desc, window_start asc, cid asc) with unique survivor cids, so it is
    # independent of which candidates are examined or in what order. Output is
    # byte-identical (pinned by the equivalence oracle in
    # test_find_merges_index_stage2.py).
    surv_index = ContinuationIndex(surv) if index is None else index
    pairs: list[tuple[str, str]] = []
    for cand in sorted(candidates, key=lambda s: (s.window_start, s.correlation_id)):
        ce = _entity_ids(cand)
        if not ce:
            continue
        best: tuple[float, datetime, str] | None = None
        best_cid = ""
        for s in surv_index.candidates(cand):
            if (s.tenant_id != cand.tenant_id
                    or s.correlation_id == cand.correlation_id
                    or not _windows_overlap(cand, s)):
                continue
            if entity_cache is None:
                se = _entity_ids(s)
            else:
                # Same lookup-or-fill shape find_continuation uses, so the
                # narrowing resolves to frozenset for mypy.
                cached = entity_cache.get(s.correlation_id)
                if cached is None:
                    cached = entity_cache[s.correlation_id] = _entity_ids(s)
                se = cached
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


class ContinuationIndex:
    """Tracker 162 — sub-linear candidate retrieval for `find_continuation`.

    THE PROBLEM: the caller examined EVERY open object per new snapshot —
    O(new × open) per cycle. The population premise that deferred this
    ("0-8 open objects") died at tracker 168: ~1,500 live at 1K stress, and a
    storm makes both factors large together.

    WHY ENTITY-ONLY INDEXING WAS UNSOUND (the blocker recorded on the tracker
    row): admission is `jac ≥ min_overlap OR _seam_bridged`, and the seam
    bridge admits candidates with ZERO shared entities (the cloud half and the
    network half of one interconnect incident share only the seam).

    THE SOUND SUPERSET, from the admission algebra. Write
    E(x) = entity ids, REFS(x) = ∪ node.identity_refs, G(x) = the seam ids x
    holds an AUTHORITATIVE seam-grounded edge on (`_snap_grounded_seam_ids`),
    ev(v) = v.endpoint_values ∪ {v.seam_id}, and for a snapshot x
      GEV(x) = ∪ { ev(v) : v ∈ x.seams, v.seam_id ∈ G(x) }   ("grounded ev")
      TCH(x) = { v.seam_id : v ∈ x.seams, REFS(x) ∩ ev(v) ≠ ∅ }  ("touched")

      * jac ≥ 0.4 ⟹ E(P) ∩ E(S) ≠ ∅                        → by_entity  ∩ E(P)
      * _seam_bridged(P, S) needs sid ∈ G(P) ∪ G(S) and a view v with
        v.seam_id = sid, v ∈ P.seams ∪ S.seams, REFS(P)∩ev(v) ≠ ∅ AND
        REFS(S)∩ev(v) ≠ ∅. Four sub-cases, each with its own exact lookup:
          - sid ∈ G(P), v ∈ P.seams ⟹ ev(v) ⊆ GEV(P), REFS(S)∩GEV(P) ≠ ∅
                                                     → by_ref      ∩ GEV(P)
          - sid ∈ G(S), v ∈ S.seams ⟹ ev(v) ⊆ GEV(S), REFS(P)∩GEV(S) ≠ ∅
                                                     → by_gev      ∩ REFS(P)
          - sid ∈ G(P), v ∈ S.seams ⟹ sid ∈ TCH(S)   → by_touched  ∩ G(P)
          - sid ∈ G(S), v ∈ P.seams ⟹ sid ∈ TCH(P)   → by_grounded ∩ TCH(P)
    Candidates = the union of the five lookups — a PROVEN superset of every
    admissible object, so running the unchanged exact predicate over it
    preserves winner identity by construction (pinned by the equivalence
    oracles in test_continuation_index_162.py and
    test_lifecycle_merge_storm_p1.py).

    WHY THE GROUNDED RESTRICTION IS THE WHOLE POINT (2026-08-29, the 35,690 ms
    storm-s02 loop stall). The first version keyed the two seam clauses on
    EV(x) = every seam the snapshot EMBEDS. `run_window` stamps the WHOLE
    tenant seam inventory into EVERY snapshot it emits (engine.py `seams=seams`
    in both ObjectSnapshot constructions), so EV(x) is IDENTICAL for every
    object of a tenant: `by_ev` mapped each inventory token to ALL indexed
    objects and `candidates()` returned the ENTIRE population for every probe.
    The index degenerated into the exact O(survivors × candidates) cross-product
    it existed to remove, silently, in proportion to how many devices are seam
    endpoints. Measured offline on the storm shape — 8,000 open objects, 5,000
    survivors × 2,500 candidates, one seam per device (bench_lifecycle_merge_
    storm.py, whose --legacy-index flag reproduces the defect on demand):

        seams      pairs examined     on the loop thread
            0              3,530                126 ms
          200          2,351,375              5,190 ms
        1,000          8,532,694             22,665 ms
        2,500         12,500,000             45,120 ms  ← the full cross-product

    The last two rows bracket the 35,690 ms live stall. With the grounded
    keying below, every row is 3,530 pairs and ~140 ms.

    `_seam_bridged` never consults a seam that is not in G(P) ∪ G(S), so
    keying on GEV/TCH instead of EV is not a heuristic tightening — it is the
    predicate's own precondition, and it collapses both seam clauses to nothing
    for the overwhelmingly common object that grounded on no seam at all.

    Determinism: candidates are returned in the original open-object order.

    Pure and cycle-scoped: build once per (tenant, cycle) over that cycle's
    open snapshots, discard with the cycle. `candidates_returned` counts the
    pairs this index has handed the exact predicate — the observability that
    makes a future degeneration loud instead of silent.
    """

    __slots__ = ("_by_entity", "_by_gev", "_by_grounded", "_by_ref",
                 "_by_touched", "_seam_maps", "_snaps", "candidates_returned")

    def __init__(self, open_snaps) -> None:
        self._snaps = tuple(open_snaps)
        self._by_entity: dict[str, list[int]] = {}
        self._by_ref: dict[str, list[int]] = {}
        self._by_gev: dict[str, list[int]] = {}
        self._by_touched: dict[str, list[int]] = {}
        self._by_grounded: dict[str, list[int]] = {}
        # seams-tuple identity -> (that tuple, token->seam ids, seam id->tokens).
        self._seam_maps: dict[int, tuple] = {}
        self.candidates_returned = 0
        for i, s in enumerate(self._snaps):
            for e in _entity_ids(s):
                self._by_entity.setdefault(e, []).append(i)
            refs = self._refs(s)
            for r in refs:
                self._by_ref.setdefault(r, []).append(i)
            # The seam half costs nothing for an object with no grounded seam
            # edge — which is the normal object, storm or not.
            grounded = _snap_grounded_seam_ids(s)
            ev_sids, ev_of = self._seam_map(s.seams)
            for sid in grounded:
                self._by_grounded.setdefault(sid, []).append(i)
            for t in self._gev(ev_of, grounded):
                self._by_gev.setdefault(t, []).append(i)
            for sid in self._touched(ev_sids, refs):
                self._by_touched.setdefault(sid, []).append(i)

    def _seam_map(self, seams: tuple) -> tuple[dict, dict]:
        """(token -> seam ids, seam id -> tokens) for ONE embedded inventory.

        Every snapshot of a tenant/cycle carries the SAME `seams` tuple object
        (run_window hands its argument straight to each ObjectSnapshot), so this
        is built once per distinct inventory rather than once per snapshot —
        turning the O(open × inventory) index build into O(open + inventory).
        Keyed by `id()` and VERIFIED by identity against the tuple held in the
        cache, so a recycled id can never serve another inventory's map.
        """
        hit = self._seam_maps.get(id(seams))
        if hit is not None and hit[0] is seams:
            return hit[1], hit[2]
        ev_sids: dict[str, set[str]] = {}
        ev_of: dict[str, set[str]] = {}
        for v in seams:
            toks = v.endpoint_values() | {v.seam_id}
            ev_of.setdefault(v.seam_id, set()).update(toks)
            for t in toks:
                ev_sids.setdefault(t, set()).add(v.seam_id)
        self._seam_maps[id(seams)] = (seams, ev_sids, ev_of)
        return ev_sids, ev_of

    @staticmethod
    def _gev(ev_of: dict, grounded: frozenset[str]) -> set[str]:
        """GEV(x) — the ev tokens of the seams x actually GROUNDED on."""
        out: set[str] = set()
        for sid in grounded:
            out |= ev_of.get(sid, frozenset())
        return out

    @staticmethod
    def _touched(ev_sids: dict, refs: frozenset[str]) -> set[str]:
        """TCH(x) — the ids of the embedded seams x structurally touches.

        Derived through the inventory's inverted token map, so it costs
        O(|REFS(x)|) per snapshot instead of a scan of the whole inventory."""
        out: set[str] = set()
        for r in refs:
            out |= ev_sids.get(r, frozenset())
        return out

    @staticmethod
    def _refs(snap: ObjectSnapshot) -> frozenset[str]:
        """The union of node identity_refs — the exact values
        `_snap_touches_seam` tests against a view's endpoint set.

        Tracker 185: the union now lives on the snapshot (`identity_refs`),
        cached, so the index build and every later seam-bridge probe of the same
        object share ONE O(Σ|signals|) walk. Kept as the index's own spelling of
        it because the superset proof and its oracles are written in terms of
        REFS(x)."""
        return snap.identity_refs()

    def candidates(self, snap: ObjectSnapshot) -> tuple[ObjectSnapshot, ...]:
        hits: set[int] = set()
        for e in _entity_ids(snap):
            hits.update(self._by_entity.get(e, ()))
        refs = self._refs(snap)
        grounded = _snap_grounded_seam_ids(snap)
        # The three `if` guards below are pure short-circuits over empty maps —
        # every lookup they skip would have missed. They are what makes the
        # seam half free when nothing in this population grounded on a seam.
        if grounded:
            ev_sids, ev_of = self._seam_map(snap.seams)
            for t in self._gev(ev_of, grounded):
                hits.update(self._by_ref.get(t, ()))
            if self._by_touched:
                for sid in grounded:
                    hits.update(self._by_touched.get(sid, ()))
        if self._by_gev:
            for r in refs:
                hits.update(self._by_gev.get(r, ()))
        if self._by_grounded:
            ev_sids, _ev_of = self._seam_map(snap.seams)
            for sid in self._touched(ev_sids, refs):
                hits.update(self._by_grounded.get(sid, ()))
        out = tuple(self._snaps[i] for i in sorted(hits))
        self.candidates_returned += len(out)
        return out

    def __len__(self) -> int:
        return len(self._snaps)


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
            # `.get()` widens to Optional, which the narrowing below resolves —
            # spell it as a lookup-or-fill so the type is frozenset throughout.
            cached = entity_cache.get(s.correlation_id)
            if cached is None:
                cached = entity_cache[s.correlation_id] = _entity_ids(s)
            se = cached
        # |A ∪ B| = |A| + |B| - |A ∩ B|, so the Jaccard needs the intersection
        # only. Identical value — the same two integers divided — and it drops
        # the O(|ce|) union SET that was built and thrown away once per
        # candidate: a storm aggregate has ~900 entities and thousands of
        # candidates, which is a million discarded set inserts inside the block
        # tracker 185 exists to bound. `ce` is non-empty (guarded above), so the
        # denominator can never be 0 and the old `if union else 0.0` guard has
        # nothing left to guard.
        inter = len(ce & se)
        jac = inter / (len(ce) + len(se) - inter)
        # Tracker 154b: same seam-bridge admission as find_merges — a re-keyed
        # seam-far half continues the incident it is bridged to, never a clone.
        if jac < min_overlap and not _seam_bridged(snap, s):
            continue
        # Strongest overlap wins; tie -> earliest window_start, then lexical cid.
        if (best is None or jac > best[0]
                or (jac == best[0] and (s.window_start, s.correlation_id) < (best[1], best[2]))):
            best, best_cid = (jac, s.window_start, s.correlation_id), s.correlation_id
    return best_cid
