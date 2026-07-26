"""path_assembly — path-causality RCA P1: discover & assemble the typed causal path.

The design doc's stage 3 (docs/design/path-causality-rca.md §2.3, §4): given the four
discovery sources, FUSE them with precedence into an ordered SRC→DST spine, run every
hop through the P0 segment classifier (segment_classifier.py), then COLLAPSE the hop
noise into the ESSENCE — the ordered sequence of typed segments and the KEY devices on
each. RCA (P2) walks this, not the raw hops.

This is wiring, not reinvention. It reuses:
  * segment_classifier.SegmentClassifier — classify each hop (P0 contract, unchanged).
  * path_graph.py — the evidence-bearing Relation / provenance model. Every fused edge
    is emitted as a path_graph.Relation stating its evidence; an edge that cannot state
    its evidence is not emitted (§5), exactly as path_graph already enforces.
  * path_direction.py discipline — a pair seen in BOTH orders is AMBIGUOUS (ECMP/loop),
    never an assumed single direction.

Source fusion + precedence (research Area 1 "fuse four discovery sources with explicit
precedence"):

    rank 1  MEASURED   traceroute / path_direction ordered hops   — the spine
    rank 2  FLOW       flow / NetFlow / VPC 5-tuple directed edges
    rank 3  INVENTORY  cloud-inventory edges (LB→backend, SG↔subnet↔host)
    rank 4  ROUTE      BGP / route-table inferred edges            — supporting only

A higher-rank edge SUPERSEDES a lower one for the same adjacency (it becomes the
authoritative ordering / direction); the superseded edges are kept as `supporting_refs`
so the evidence trail is never lost.

Honesty rules (inherited, non-negotiable):
  * Never invent a hop, an edge, or a segment type. Unknown stays unknown.
  * An opaque / unresponsive run (cloud core, MPLS) becomes ONE typed `unknown` segment
    WITH a reason and its `unknown_hops` populated — never a fabricated device.
  * ECMP stays an AMBIGUOUS diamond — both branches kept, order between them NOT asserted.
  * The DNS-resolved frontend is captured as the path HEAD (anycast/GeoDNS frontend
    variation is explained, not treated as a discovery failure).

Tenancy (CLAUDE.md §3a): assembly is per-tenant and DEFAULT-CLOSED. Every hop and edge
whose immutable tenant_id differs from the caller's is dropped STRUCTURALLY before any
assembly runs (mirrors PathGraphView.for_tenant); an empty tenant_id fails closed. A
path can never contain another tenant's hop.

Pure + deterministic: no IO, no wall clock, no randomness. Given the same sources it
assembles the same path — the replay contract the rest of the correlation service holds.
"""

from __future__ import annotations

import itertools
from dataclasses import dataclass, field
from enum import Enum

from path_graph import (
    Confidence as PGConfidence,
)
from path_graph import (
    DataClass,
    EdgeType,
    Relation,
    ResolutionMethod,
    Transformation,
    worst_data_class,
)
from segment_classifier import (
    Confidence,
    DeviceRole,
    SegmentClassifier,
    SegmentType,
)

# Bounded work (CLAUDE.md §9): a discovered path never grows without limit.
MAX_SPINE_HOPS = 64

# ── source precedence ────────────────────────────────────────────────────────


class SourceKind(str, Enum):
    MEASURED = "measured"     # rank 1 — traceroute / path_direction ordered hops
    FLOW = "flow"             # rank 2 — flow / NetFlow / VPC 5-tuple edges
    INVENTORY = "inventory"   # rank 3 — cloud-inventory edges (LB→backend, SG↔subnet↔host)
    ROUTE = "route"           # rank 4 — BGP / route-inferred (supporting only)


# Lower number = higher precedence. This is the FUSION authority (which source's
# ordering/direction wins for a given adjacency), independent of path_graph's internal
# RANK (which governs the emitted Relation's authority for the verdict gate).
SOURCE_PRECEDENCE: dict[str, int] = {
    SourceKind.MEASURED.value: 1,
    SourceKind.FLOW.value: 2,
    SourceKind.INVENTORY.value: 3,
    SourceKind.ROUTE.value: 4,
}

# How each discovery source is recorded in the path_graph vocabulary when its edge is
# emitted as a Relation. Measured hops and declared inventory links are OBSERVED; a
# route-table edge is INFERRED (supporting only) — matching path_graph's own semantics.
SOURCE_METHOD: dict[str, str] = {
    SourceKind.MEASURED.value: ResolutionMethod.HOP_INVENTORY.value,   # rank 3, observed
    SourceKind.FLOW.value: ResolutionMethod.FLOW_NAT_STITCH.value,     # rank 5, observed
    SourceKind.INVENTORY.value: ResolutionMethod.TOPOLOGY_LINK.value,  # rank 3, observed
    SourceKind.ROUTE.value: ResolutionMethod.CLOUD_ROUTE.value,        # rank 6, inferred
}

# Roles that are KEY devices on a segment and must be retained through the collapse
# (design §5): the on-path SERVICE devices, plus the fabric role for LAN/DC.
_SERVICE_ROLES = frozenset({
    DeviceRole.LOAD_BALANCER.value, DeviceRole.WAF.value, DeviceRole.FIREWALL.value,
    DeviceRole.DNS_RESOLVER.value, DeviceRole.HOST.value, DeviceRole.TUNNEL_GW.value,
})
_FABRIC_ROLES = frozenset({DeviceRole.ROUTER.value, DeviceRole.SWITCH.value})
_KEY_ROLES = _SERVICE_ROLES | _FABRIC_ROLES


class HopState(str, Enum):
    RESPONDING = "responding"
    MISSING = "missing"       # `* * *` — no ICMP Time Exceeded (opaque)
    FILTERED = "filtered"     # administratively blocked (opaque)


# ── inputs (the normalized shapes the four sources produce) ───────────────────


@dataclass(frozen=True)
class HopNode:
    """One node observed on the path. `address` is the hop IP; it is empty ONLY for an
    opaque (missing/filtered) hop. All classification hints are optional and pass
    straight into the P0 classifier."""

    address: str = ""
    device_role_hint: str = ""
    asn: int | None = None
    rdns: str = ""
    ttl: int | None = None
    latency: float | None = None
    key_device: str = ""                       # resolved entity/name, when known
    state: str = HopState.RESPONDING.value

    @property
    def responding(self) -> bool:
        return self.state == HopState.RESPONDING.value and bool(self.address)

    def classifier_hop(self) -> dict:
        h: dict = {"ip": self.address}
        if self.device_role_hint:
            h["device_role_hint"] = self.device_role_hint
        if self.asn is not None:
            h["asn"] = self.asn
        if self.rdns:
            h["rdns"] = self.rdns
        if self.ttl is not None:
            h["ttl"] = self.ttl
        if self.latency is not None:
            h["latency"] = self.latency
        return h


@dataclass(frozen=True)
class MeasuredRun:
    """Precedence-1 source: ONE measured traceroute / probe run — an ORDERED hop list.
    Opaque hops (state != responding) are PRESERVED in order, never dropped."""

    tenant_id: str
    hops: tuple[HopNode, ...]
    evidence_ref: str = ""
    observed_at: str = ""
    data_class: str = DataClass.LIVE.value


@dataclass(frozen=True)
class DiscoveredEdge:
    """Precedence 2-4 source: a DIRECTED adjacency upstream→downstream from a flow
    5-tuple, a cloud-inventory relation, or a route-table entry."""

    tenant_id: str
    upstream: HopNode
    downstream: HopNode
    source: str = SourceKind.FLOW.value        # FLOW | INVENTORY | ROUTE
    evidence_ref: str = ""
    observed_at: str = ""
    data_class: str = DataClass.LIVE.value


@dataclass(frozen=True)
class DnsHead:
    """The DNS-resolved frontend — the path HEAD (research Area 1.E). Explains why two
    runs hit different frontends (anycast / GeoDNS) instead of treating it as a failure."""

    tenant_id: str
    query_name: str
    resolved_address: str = ""
    cname_chain: tuple[str, ...] = ()
    evidence_ref: str = ""

    def to_dict(self) -> dict:
        return {
            "query_name": self.query_name, "resolved_address": self.resolved_address,
            "cname_chain": list(self.cname_chain), "evidence_ref": self.evidence_ref,
        }


@dataclass
class DiscoverySources:
    """The bundle of discovery evidence for ONE tenant's SRC→DST assembly."""

    measured: tuple[MeasuredRun, ...] = ()
    edges: tuple[DiscoveredEdge, ...] = ()     # flow / inventory / route
    dns_head: DnsHead | None = None


# ── outputs (the typed causal path — the ESSENCE) ─────────────────────────────


@dataclass(frozen=True)
class KeyDevice:
    address: str
    role: str
    label: str
    confidence: str

    def to_dict(self) -> dict:
        return {"address": self.address, "role": self.role,
                "label": self.label, "confidence": self.confidence}


@dataclass(frozen=True)
class TypedSegment:
    """One collapsed typed segment — consecutive same-type hops as a single element,
    with the key devices retained and honest opacity."""

    index: int
    segment_type: str
    boundary: str
    provider: str
    confidence: str
    key_devices: tuple[KeyDevice, ...]
    member_addresses: tuple[str, ...]
    hop_indices: tuple[int, ...]
    unknown_hops: tuple[int, ...] = ()
    reason: str = ""
    ambiguous: bool = False               # part of an ECMP diamond
    authoritative_source: str = ""        # the winning discovery source (precedence)
    evidence_refs: tuple[str, ...] = ()
    supporting_refs: tuple[str, ...] = ()

    def to_dict(self) -> dict:
        return {
            "index": self.index, "segment_type": self.segment_type,
            "boundary": self.boundary, "provider": self.provider,
            "confidence": self.confidence,
            "key_devices": [k.to_dict() for k in self.key_devices],
            "member_addresses": list(self.member_addresses),
            "hop_indices": list(self.hop_indices),
            "unknown_hops": list(self.unknown_hops), "reason": self.reason,
            "ambiguous": self.ambiguous,
            "authoritative_source": self.authoritative_source,
            "evidence_refs": list(self.evidence_refs),
            "supporting_refs": list(self.supporting_refs),
        }


@dataclass(frozen=True)
class AssembledPath:
    tenant_id: str
    src: str
    dst: str
    segments: tuple[TypedSegment, ...]
    head: DnsHead | None = None
    ecmp_pairs: tuple[tuple[str, str], ...] = ()
    notes: tuple[str, ...] = ()

    @property
    def ambiguous(self) -> bool:
        return bool(self.ecmp_pairs) or any(s.ambiguous for s in self.segments)

    def to_dict(self) -> dict:
        return {
            "tenant_id": self.tenant_id, "src": self.src, "dst": self.dst,
            "head": self.head.to_dict() if self.head else None,
            "segments": [s.to_dict() for s in self.segments],
            "ecmp_pairs": [list(p) for p in self.ecmp_pairs],
            "ambiguous": self.ambiguous,
            "notes": list(self.notes),
        }


# ── the internal, per-hop assembly node ───────────────────────────────────────


@dataclass
class _SpineHop:
    index: int
    node: HopNode
    seg_type: str
    device_role: str
    confidence: str
    provider: str
    boundary: str
    reason: str
    evidence_ref: str
    supporting_refs: set = field(default_factory=set)
    authoritative_source: str = ""
    ambiguous: bool = False


# ── the assembler ─────────────────────────────────────────────────────────────


class PathAssembler:
    """Assembles a typed causal path from fused discovery sources. Construct once
    (holds the P0 classifier); call assemble() per SRC→DST. Thread-safe (read-only)."""

    def __init__(self, classifier: SegmentClassifier | None = None) -> None:
        self._clf = classifier if classifier is not None else SegmentClassifier()

    # -- tenant scoping (structural, default-closed) --------------------------

    def _scoped(self, sources: DiscoverySources, tenant_id: str) -> DiscoverySources:
        """Drop every run/edge from another tenant BEFORE assembly (§3a). An empty
        tenant_id on the object fails closed (dropped) — no 'global' path evidence."""
        measured = tuple(r for r in sources.measured
                         if r.tenant_id and r.tenant_id == tenant_id)
        edges = tuple(e for e in sources.edges
                      if e.tenant_id and e.tenant_id == tenant_id)
        head = sources.dns_head
        if head is not None and (not head.tenant_id or head.tenant_id != tenant_id):
            head = None
        return DiscoverySources(measured=measured, edges=edges, dns_head=head)

    # -- ordering: build the SRC→DST spine ------------------------------------

    def _measured_spine(self, runs: tuple[MeasuredRun, ...]
                        ) -> tuple[list[HopNode], str, str, set]:
        """Choose the primary measured run (most responding hops, then evidence_ref) as
        the ordered spine, and detect ECMP: any address pair seen in BOTH orders across
        runs is ambiguous (path_direction discipline) — order between them is NOT
        asserted. Returns (ordered_hops, evidence_ref, data_class, ecmp_pairs)."""
        # `before[(a,b)]` = a observed upstream of b in some run (responding hops only).
        before: set = set()
        for r in runs:
            seq = [h.address for h in r.hops if h.responding]
            for i in range(len(seq)):
                for j in range(i + 1, len(seq)):
                    if seq[i] != seq[j]:
                        before.add((seq[i], seq[j]))
        ecmp: set = set()
        for (a, b) in before:
            if (b, a) in before and a < b:      # canonical order, count each pair once
                ecmp.add((a, b))
        primary = max(
            runs,
            key=lambda r: (sum(1 for h in r.hops if h.responding), r.evidence_ref),
        )
        return (list(primary.hops[:MAX_SPINE_HOPS]), primary.evidence_ref,
                primary.data_class, ecmp)

    def _edge_spine(self, edges: tuple[DiscoveredEdge, ...], src: str, dst: str
                   ) -> tuple[list[HopNode], set]:
        """No measured run — order the spine by walking directed edges from src→dst,
        preferring the highest-precedence out-edge at each node. Two distinct out-edges
        at the SAME precedence → an ECMP diamond (both kept, order not asserted)."""
        # directed adjacency: addr → list[(precedence, DiscoveredEdge)]
        out: dict[str, list[tuple[int, DiscoveredEdge]]] = {}
        node_by_addr: dict[str, HopNode] = {}
        for e in edges:
            a, b = e.upstream.address, e.downstream.address
            if not a or not b or a == b:
                continue
            node_by_addr.setdefault(a, e.upstream)
            node_by_addr.setdefault(b, e.downstream)
            out.setdefault(a, []).append((SOURCE_PRECEDENCE.get(e.source, 99), e))
        spine: list[HopNode] = []
        ecmp: set = set()
        seen: set = set()
        cur = src
        while cur and cur not in seen and len(spine) < MAX_SPINE_HOPS:
            seen.add(cur)
            spine.append(node_by_addr.get(cur, HopNode(address=cur)))
            if cur == dst:
                break
            candidates = out.get(cur, [])
            if not candidates:
                break
            best_prec = min(p for p, _ in candidates)
            nexts = sorted({e.downstream.address for p, e in candidates if p == best_prec})
            if len(nexts) > 1:                 # divergence at equal precedence → ECMP
                for nb in nexts:
                    if cur < nb:
                        ecmp.add((cur, nb))
                    else:
                        ecmp.add((nb, cur))
            cur = nexts[0]
        if dst and (not spine or spine[-1].address != dst):
            spine.append(node_by_addr.get(dst, HopNode(address=dst)))
        return spine[:MAX_SPINE_HOPS], ecmp

    # -- evidence fusion per adjacency ----------------------------------------

    def _fuse_hop_evidence(self, hop: HopNode, edges: tuple[DiscoveredEdge, ...],
                           measured_ref: str) -> tuple[str, str, set]:
        """For a spine hop, gather every source edge that terminates AT it and pick the
        authoritative source by precedence; the rest become supporting evidence refs.
        Returns (authoritative_source, evidence_ref, supporting_refs)."""
        contenders: list[tuple[int, str, str]] = []
        if measured_ref:
            contenders.append((SOURCE_PRECEDENCE[SourceKind.MEASURED.value],
                               SourceKind.MEASURED.value, measured_ref))
        for e in edges:
            if e.downstream.address == hop.address and e.evidence_ref:
                contenders.append((SOURCE_PRECEDENCE.get(e.source, 99), e.source,
                                   e.evidence_ref))
        if not contenders:
            return "", "", set()
        contenders.sort(key=lambda c: (c[0], c[2]))
        best = contenders[0]
        supporting = {c[2] for c in contenders[1:]}
        return best[1], best[2], supporting

    # -- classification per hop ------------------------------------------------

    def _classify(self, hop: HopNode) -> tuple[str, str, str, str, str, str]:
        """Run the P0 classifier. Opaque hops (missing/filtered/no address) are NOT
        classified as a real type — they are honestly `unknown` with a reason, never a
        guessed device. Returns (seg_type, role, confidence, provider, boundary, reason)."""
        if not hop.responding:
            return (SegmentType.UNKNOWN.value, DeviceRole.UNKNOWN.value,
                    Confidence.NONE.value, "", "UNKNOWN",
                    f"hop did not respond ({hop.state}) — opaque, hops not observed")
        c = self._clf.classify(hop.classifier_hop())
        role = c.device_role
        # A declared/known key-device NAME can carry a role hint even when the classifier
        # abstained on it — but we NEVER upgrade an unknown to a guessed role here.
        return (c.segment_type, role, c.confidence, c.provider, c.boundary, c.reason)

    # -- the public entry point -----------------------------------------------

    def assemble(self, tenant_id: str, src: str, dst: str,
                 sources: DiscoverySources) -> AssembledPath:
        if not tenant_id:
            raise ValueError("assemble requires a tenant (§3a default-closed)")
        s = self._scoped(sources, tenant_id)
        notes: list[str] = []

        # 1. ORDER — measured spine (rank 1) wins; else fall back to edge-derived order.
        ecmp: set = set()
        measured_ref = ""
        measured_dc = DataClass.LIVE.value
        if s.measured:
            ordered, measured_ref, measured_dc, ecmp = self._measured_spine(s.measured)
        elif s.edges:
            ordered, ecmp = self._edge_spine(s.edges, src, dst)
        else:
            ordered = []
            notes.append("no discovery source produced an ordered path — segment unknown")

        # 2. CLASSIFY every hop + fuse its evidence/provenance with precedence.
        ecmp_addrs = {a for pair in ecmp for a in pair}
        spine: list[_SpineHop] = []
        for i, node in enumerate(ordered):
            seg_type, role, conf, provider, boundary, reason = self._classify(node)
            src_kind, ev, supporting = self._fuse_hop_evidence(
                node, s.edges, measured_ref if s.measured else "")
            spine.append(_SpineHop(
                index=i, node=node, seg_type=seg_type, device_role=role,
                confidence=conf, provider=provider, boundary=boundary, reason=reason,
                evidence_ref=ev, supporting_refs=set(supporting),
                authoritative_source=src_kind,
                ambiguous=node.address in ecmp_addrs,
            ))

        # 3. COLLAPSE consecutive same-type hops into typed segments (the ESSENCE).
        segments = self._collapse(spine, measured_dc)

        if not segments and dst:
            segments = [TypedSegment(
                index=0, segment_type=SegmentType.UNKNOWN.value, boundary="UNKNOWN",
                provider="", confidence=Confidence.NONE.value, key_devices=(),
                member_addresses=(), hop_indices=(), unknown_hops=(),
                reason="no discovery evidence for this path — nothing observed",
            )]

        return AssembledPath(
            tenant_id=tenant_id, src=src, dst=dst, segments=tuple(segments),
            head=s.dns_head,
            ecmp_pairs=tuple(sorted(ecmp)),
            notes=tuple(notes),
        )

    # -- the collapse ----------------------------------------------------------

    def _collapse(self, spine: list[_SpineHop], base_dc: str) -> list[TypedSegment]:
        """Group consecutive hops of the same segment_type into one TypedSegment,
        keeping key devices and honest opacity. Opaque/unknown hops group together as a
        single `unknown` segment with `unknown_hops` populated and a reason."""
        segments: list[TypedSegment] = []
        run: list[_SpineHop] = []

        def flush() -> None:
            if not run:
                return
            seg_type = run[0].seg_type
            key_devices: list[KeyDevice] = []
            confidences: list[str] = []
            providers: list[str] = []
            member_addrs: list[str] = []
            hop_idx: list[int] = []
            unknown: list[int] = []
            evidence: list[str] = []
            supporting: set = set()
            reasons: list[str] = []
            sources_seen: list[str] = []
            ambiguous = False
            for h in run:
                hop_idx.append(h.index)
                confidences.append(h.confidence)
                if h.provider:
                    providers.append(h.provider)
                if h.node.responding:
                    member_addrs.append(h.node.address)
                else:
                    unknown.append(h.index)
                if h.evidence_ref:
                    evidence.append(h.evidence_ref)
                supporting |= h.supporting_refs
                if h.authoritative_source:
                    sources_seen.append(h.authoritative_source)
                if h.reason:
                    reasons.append(h.reason)
                ambiguous = ambiguous or h.ambiguous
                # KEY device retention: keep any hop carrying a real (non-unknown) role,
                # OR a declared key-device name — never fabricate one.
                if h.device_role in _KEY_ROLES:
                    key_devices.append(KeyDevice(
                        address=h.node.address, role=h.device_role,
                        label=h.node.key_device or h.node.address, confidence=h.confidence))
                elif h.node.key_device and h.node.responding:
                    key_devices.append(KeyDevice(
                        address=h.node.address, role=h.device_role,
                        label=h.node.key_device, confidence=h.confidence))
            # authoritative source for the segment = the highest-precedence among its hops.
            auth = min(sources_seen, key=lambda k: SOURCE_PRECEDENCE.get(k, 99),
                       default="")
            boundary = next((h.boundary for h in run if h.boundary), "UNKNOWN")
            is_unknown = seg_type == SegmentType.UNKNOWN.value
            reason = ""
            if is_unknown:
                reason = ("; ".join(dict.fromkeys(reasons))
                          or "segment type could not be established — unknown")
            segments.append(TypedSegment(
                index=len(segments), segment_type=seg_type, boundary=boundary,
                provider=next(iter(dict.fromkeys(providers)), ""),
                confidence=_weakest_confidence(confidences),
                key_devices=tuple(key_devices),
                member_addresses=tuple(member_addrs), hop_indices=tuple(hop_idx),
                unknown_hops=tuple(unknown), reason=reason, ambiguous=ambiguous,
                authoritative_source=auth,
                evidence_refs=tuple(dict.fromkeys(evidence)),
                supporting_refs=tuple(sorted(supporting)),
            ))
            run.clear()

        for h in spine:
            if run and run[-1].seg_type != h.seg_type:
                flush()
            run.append(h)
        flush()
        return segments

    # -- the evidence trail: path_graph relations per adjacency ---------------

    def relations(self, path: AssembledPath, sources: DiscoverySources
                  ) -> list[Relation]:
        """Emit one path_graph.Relation per adjacency between the assembled segments'
        member hops, so the fused path is expressible in the existing evidence-bearing
        relationship model. An adjacency without evidence is NOT emitted (§5).

        Directionally honest: an adjacency inside an ECMP diamond is emitted as an
        EVIDENCE_SUPPORTS relation (order not asserted), never a directed hop edge.
        """
        s = self._scoped(sources, path.tenant_id)
        addrs = [a for seg in path.segments for a in seg.member_addresses]
        ecmp = set(path.ecmp_pairs)
        # map an ordered (a,b) address pair → ALL source edges for it (every one is
        # evidence; the highest-precedence wins ordering, the rest stay supporting).
        directed: dict[tuple[str, str], list[DiscoveredEdge]] = {}
        for e in s.edges:
            directed.setdefault((e.upstream.address, e.downstream.address), []).append(e)
        measured_ref = s.measured[0].evidence_ref if s.measured else ""
        measured_dc = s.measured[0].data_class if s.measured else DataClass.LIVE.value

        rels: list[Relation] = []
        for a, b in itertools.pairwise(addrs):
            pair = (a, b) if a < b else (b, a)
            is_ecmp = pair in ecmp
            # authoritative source for this adjacency
            contenders: list[tuple[int, str, str, str]] = []
            if measured_ref:
                contenders.append((1, SourceKind.MEASURED.value, measured_ref, measured_dc))
            for key in ((a, b), (b, a)):
                for e in directed.get(key, ()):
                    if e.evidence_ref:
                        contenders.append((SOURCE_PRECEDENCE.get(e.source, 99), e.source,
                                           e.evidence_ref, e.data_class))
            if not contenders:
                continue                        # §5 — no evidence, no edge
            contenders.sort(key=lambda c: (c[0], c[2]))
            _, kind, ev, dc = contenders[0]
            supporting = tuple(sorted({c[2] for c in contenders[1:]}))
            method = SOURCE_METHOD[kind]
            edge_type = (EdgeType.EVIDENCE_SUPPORTS.value if is_ecmp
                         else EdgeType.PATH_HAS_HOP.value)
            rels.append(Relation(
                edge_type=edge_type, method=method,
                confidence=PGConfidence.STRONG.value, evidence_ref=ev,
                observation_method=kind, observed_at="",
                data_class=worst_data_class([dc]),
                ref=f"path:{a}->{b}", transformation=Transformation.NONE.value,
                supporting_refs=supporting,
            ))
        return rels


# ── confidence helper ─────────────────────────────────────────────────────────

_CONF_ORDER = {Confidence.NONE.value: 0, Confidence.WEAK.value: 1,
               Confidence.MEDIUM.value: 2, Confidence.STRONG.value: 3}


def _weakest_confidence(values: list[str]) -> str:
    """A segment is only as confident as its weakest hop (honesty)."""
    if not values:
        return Confidence.NONE.value
    return min(values, key=lambda v: _CONF_ORDER.get(v, 0))


# ── adapters — tie the assembler to the REAL ingested sources ─────────────────


def measured_run_from_observation(obs) -> MeasuredRun:
    """Adapt a path_graph.PathObservation (produced by the traceroute collector /
    path_direction lane) into a precedence-1 MeasuredRun. Missing/filtered hops are
    carried through as opaque HopNodes — never dropped."""
    hops: list[HopNode] = []
    for h in obs.ordered_hops():
        state = (HopState.RESPONDING.value if h.responding
                 else (HopState.FILTERED.value if h.state == "filtered"
                       else HopState.MISSING.value))
        hops.append(HopNode(
            address=h.observed_address if h.responding else "",
            key_device=h.resolved_entity_ref, latency=h.rtt_ms, state=state,
        ))
    return MeasuredRun(
        tenant_id=obs.tenant_id, hops=tuple(hops),
        evidence_ref=obs.evidence_ref or obs.observation_id,
        observed_at="", data_class=obs.data_class,
    )


def flow_edges_from_pairs(tenant_id: str, pairs, evidence_ref: str) -> tuple[DiscoveredEdge, ...]:
    """Adapt directed flow pairs `[(src_addr, dst_addr), ...]` (from the passive-flow
    lane / VPC flow logs, 5-tuple src→dst) into precedence-2 DiscoveredEdges."""
    out: list[DiscoveredEdge] = []
    for a, b in pairs:
        if a and b and a != b:
            out.append(DiscoveredEdge(
                tenant_id=tenant_id, upstream=HopNode(address=str(a)),
                downstream=HopNode(address=str(b)), source=SourceKind.FLOW.value,
                evidence_ref=evidence_ref))
    return tuple(out)


def inventory_edges_from_topology(tenant_id: str, topo: dict, evidence_ref: str
                                  ) -> tuple[DiscoveredEdge, ...]:
    """Adapt a cloud topology snapshot (deployment/docker/cloud-fixtures/*-topology.json)
    into precedence-3 inventory edges. Uses the declared subnet→next-hop edges: the
    next hop's `to_kind` (nva / vpc_endpoint / …) is a role hint the classifier uses.
    Only edges with resolvable private IPs on BOTH ends contribute (honest: an edge we
    can't ground is not fabricated)."""
    ip_of_node: dict[str, tuple[str, str]] = {}
    for n in topo.get("nodes", ()):
        nid, ip = n.get("id"), n.get("private_ip")
        if nid and ip:
            ip_of_node[nid] = (str(ip), str(n.get("kind") or ""))
    subnet_cidr: dict[str, str] = {sn.get("id"): sn.get("cidr", "")
                                   for sn in topo.get("subnets", ()) if sn.get("id")}
    out: list[DiscoveredEdge] = []
    for e in topo.get("edges", ()):
        to = e.get("to")
        if to not in ip_of_node:
            continue                            # next hop has no groundable IP — skip
        to_ip, to_kind = ip_of_node[to]
        # the subnet's own presence is the upstream anchor; use its CIDR network addr as
        # a stable, honest identifier only when a concrete gateway IP is unavailable.
        from_id = e.get("from_subnet")
        from_addr = subnet_cidr.get(from_id, "").split("/")[0]
        if not from_addr:
            continue
        out.append(DiscoveredEdge(
            tenant_id=tenant_id,
            upstream=HopNode(address=from_addr),
            downstream=HopNode(address=to_ip,
                               device_role_hint=e.get("to_kind") or to_kind),
            source=SourceKind.INVENTORY.value,
            evidence_ref=f"{evidence_ref}:{e.get('via_route_table', '')}",
        ))
    return tuple(out)
