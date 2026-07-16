"""path_attribution — path-causality RCA P2: on-path RCA attribution.

The blueprint's single highest-value change (docs/design/research/path-causality-rca-research.md
Area 3; docs/design/path-causality-rca.md §2.4, §1): given an app-experience symptom at a
DST and the typed causal path P1 assembled (SRC→DST), RESTRICT RCA candidates to devices ON
that path, and attribute the symptom to the on-path device whose fault best explains it —
turning "saas-experience-degraded, suspected" into "client→app broke at CLOUD/WAF, confirmed"
— while staying honest when the path is partial/opaque.

This EXTENDS the existing verdict/accounting model; it does not replace it (research Area 3
"Recommendation"). An on-path device fault is a NEW corroborating cross-plane WITNESS fed into
verdicts.assess() — the same independence gate that already turns two independent modalities
into `confirmed`. Off-path faults never become witnesses for this symptom.

The synthesized on-path attribution principles it implements (research Area 3):
  1. Candidate set = devices ON the discovered path, ONLY. An anomaly off the SRC→DST path
     cannot cause THIS symptom, regardless of severity (Sherlock/NetMedic/Shrink invariant).
  2. On-path corroboration raises confidence; off-path / wrong-locality coincidence is
     DISCOUNTED even when loudest (Groot: severity ≠ causality). A discounted fault is
     recorded WITH a reason, never silently dropped.
  3. Minimal-set-cover + priors (Occam / SCORE / Shrink). One on-path fault explaining the
     symptom beats many off-path attributions. With one symptom the minimal cover is size 1.
  4. Explaining-away, "buck stops here" (NetMedic). When several on-path devices carry faults,
     name the UPSTREAM-MOST one (a DNS failure explains the downstream app symptom; don't also
     blame the LB). Downstream faults become explained-away victims.
  5. No dependency edge ⇒ no attribution. If the device is not on the path, it is not a cause.

Honesty caps (NON-NEGOTIABLE, reuse the existing default-closed caps — research Area 3.5,
design §1/§4). An unknown path can only WEAKEN, never manufacture, attribution:
  * If the SRC→cause span crosses an `unknown`/opaque segment, an `unknown_hops` gap, or an
    ECMP diamond, the verdict is CAPPED at `suspected` with `evidence_missing` naming the
    opaque segment. Never `confirmed` when the fault localizes behind an opaque segment.
  * `confirmed` is NEVER fabricated: it is produced ONLY by verdicts.assess finding a genuine
    independent cross-modality pair over the REAL symptom + REAL on-path fault signals. This
    module cannot invent one — it only chooses WHICH faults are admissible as witnesses.

Tenancy (CLAUDE.md §3a): attribution is per-tenant and DEFAULT-CLOSED. The path is used ONLY
when its immutable tenant_id matches the caller; every symptom/fault signal from another
tenant is dropped STRUCTURALLY before any reasoning. Attribution can never rest on another
tenant's path or signal.

Pure + deterministic: no IO, no wall clock, no randomness. Given the same path + signals it
attributes the same cause and the same verdict — the replay contract the rest of the
correlation service holds.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from path_assembly import AssembledPath
from segment_classifier import Confidence, DeviceRole, SegmentType
from signals import Signal
from verdicts import EvidenceCoverage, Verdict, VerdictTier, assess

# The cloud-edge fault kinds that, when on-path, become app-witness evidence (design §2.4):
# LB 5xx, WAF block, flow REJECT, DNS NXDOMAIN. Kept here as the P2 admissibility list; each
# is a real emitted kind carrying its own ModalityClass (cloud_producers.CLOUD_KINDS), so the
# verdict lift is computed on the signal's ACTUAL modality, never a re-declared one.
CLOUD_EDGE_FAULT_KINDS = frozenset({
    "cloud_lb_log", "cloud_waf_log", "cloud_flow_log", "cloud_dns_log",
})
# The network on-path fault kinds (interface / tunnel down and their canonical spellings).
NETWORK_FAULT_KINDS = frozenset({
    "link_state_change", "if_metric_anomaly", "lldp_neighbor_change",
    "ipsec_tunnel_status", "cloud_vpn_tunnel_down", "cloud_physical_link_down",
    "lb_5xx", "lb_target_unhealthy",
})

# A DNS device sits at the HEAD of the causal chain (resolution precedes connect), so a DNS
# fault is always the upstream-most cause when present (explaining-away). Priors only break
# ties WITHIN one upstream rank — the upstream walk order dominates.
_ROLE_PRIOR: dict[str, int] = {
    DeviceRole.DNS_RESOLVER.value: 6,
    DeviceRole.WAF.value: 5,
    DeviceRole.FIREWALL.value: 4,
    DeviceRole.LOAD_BALANCER.value: 3,
    DeviceRole.TUNNEL_GW.value: 3,
    DeviceRole.ROUTER.value: 2,
    DeviceRole.SWITCH.value: 2,
    DeviceRole.HOST.value: 1,
    DeviceRole.UNKNOWN.value: 0,
}

_CONF_RANK = {Confidence.NONE.value: 0, Confidence.WEAK.value: 1,
              Confidence.MEDIUM.value: 2, Confidence.STRONG.value: 3}


# ── the on-path device set (a bounded DAG walk over the P1 path) ──────────────


@dataclass(frozen=True)
class OnPathDevice:
    """One device ON the SRC→DST path, with its segment, position and match identities.

    `upstream_rank` is its ordinal on the walk from SRC toward DST (0 = upstream-most, the
    DNS resolution head). Explaining-away names the smallest-rank fault. `identities` are the
    normalized refs a fault names its device by (address, label) — a fault is on-path iff its
    identities intersect some on-path device's identities."""

    address: str
    role: str
    label: str
    segment_index: int
    segment_type: str
    segment_confidence: str
    upstream_rank: int
    ambiguous: bool
    identities: frozenset[str]

    def to_dict(self) -> dict:
        return {
            "address": self.address, "role": self.role, "label": self.label,
            "segment_index": self.segment_index, "segment_type": self.segment_type,
            "segment_confidence": self.segment_confidence,
            "upstream_rank": self.upstream_rank, "ambiguous": self.ambiguous,
        }


def _norm(*vals: str) -> frozenset[str]:
    """Normalize identity strings for matching (lowercased, stripped, non-empty)."""
    out: set[str] = set()
    for v in vals:
        s = str(v or "").strip().lower()
        if s:
            out.add(s)
    return frozenset(out)


def on_path_devices(path: AssembledPath) -> tuple[OnPathDevice, ...]:
    """Compute the ordered on-path device set — the bounded walk from SRC toward DST over the
    P1 AssembledPath. The DNS-resolved frontend (path head) is the upstream-most element; then
    each segment's KEY devices in hop order. Opaque/unknown segments contribute NO device
    (honest: no fabricated hop), but their presence is what the honesty cap keys on later."""
    devices: list[OnPathDevice] = []
    rank = 0
    # The DNS head resolves BEFORE any connect — the upstream-most position (design §2.4:
    # "a DNS failure upstream explains the downstream app symptom").
    if path.head is not None and path.head.query_name:
        h = path.head
        devices.append(OnPathDevice(
            address=h.resolved_address, role=DeviceRole.DNS_RESOLVER.value,
            label=h.query_name, segment_index=-1, segment_type="dns_head",
            segment_confidence=Confidence.STRONG.value, upstream_rank=rank,
            ambiguous=False,
            identities=_norm(h.query_name, h.resolved_address, *h.cname_chain),
        ))
        rank += 1
    for seg in path.segments:
        for kd in seg.key_devices:
            devices.append(OnPathDevice(
                address=kd.address, role=kd.role, label=kd.label,
                segment_index=seg.index, segment_type=seg.segment_type,
                segment_confidence=seg.confidence, upstream_rank=rank,
                ambiguous=seg.ambiguous,
                identities=_norm(kd.address, kd.label),
            ))
            rank += 1
    return tuple(devices)


# ── fault identity extraction ─────────────────────────────────────────────────


def _fault_identities(sig: Signal) -> frozenset[str]:
    """The device/name refs a fault signal names its subject by — matched against the on-path
    device identities. Covers cloud (entity_id/resource_id/app + tokens) and network
    (device-scoped entity ids `dev:iface`, path endpoints `a->b`) fault shapes."""
    vals: list[str] = [sig.entity_id]
    attrs = sig.attrs if isinstance(sig.attrs, dict) else {}
    for k in ("resource_id", "app", "query_name", "name", "address", "device"):
        v = attrs.get(k)
        if v:
            vals.append(str(v))
    vals.extend(str(t) for t in sig.entity_tokens)
    # device-scoped id `leaf1:Ethernet1` → also match the device part `leaf1`.
    eid = sig.entity_id
    if ":" in eid:
        vals.append(eid.split(":", 1)[0])
    if "->" in eid:
        vals.extend(p for p in eid.split("->") if p)
    return _norm(*vals)


# ── the attribution result ─────────────────────────────────────────────────────


@dataclass(frozen=True)
class AttributedFault:
    """An on-path device fault admitted as a witness. Names the device (label + role) and the
    fault kind — the "correlix-edge-urlmap LB 5xx" the RCA hypothesis reads as."""

    device: OnPathDevice
    kind: str
    modality: str
    observers: tuple[str, ...]
    signal_ids: tuple[str, ...]

    def headline(self) -> str:
        seg = self.device.segment_type.upper()
        role = self.device.role.replace("_", " ")
        return (f"{seg}/{role} {self.device.label or self.device.address}"
                f" ({self.kind})")

    def to_dict(self) -> dict:
        return {
            "device": self.device.to_dict(), "kind": self.kind,
            "modality": self.modality, "observers": list(self.observers),
            "signal_ids": list(self.signal_ids), "headline": self.headline(),
        }


@dataclass(frozen=True)
class DiscountedFault:
    """A fault that is NOT admitted as a cause of this symptom, with the honest reason:
    off-path (Groot locality/rule discount) or off-window (not time-correlated)."""

    identity: str
    kind: str
    reason: str

    def to_dict(self) -> dict:
        return {"identity": self.identity, "kind": self.kind, "reason": self.reason}


@dataclass(frozen=True)
class Attribution:
    """The P2 outcome. `attributed` is the named upstream-most cause (None when no on-path,
    time-correlated fault exists → un-attributed baseline). `verdict` is the (possibly capped)
    verdict from verdicts.assess over symptom + the admitted on-path witness; `baseline` is
    the symptom-only verdict, so the confidence LIFT is explicit and auditable."""

    tenant_id: str
    src: str
    dst: str
    attributed: Optional[AttributedFault]
    explained_away: tuple[AttributedFault, ...]
    discounted: tuple[DiscountedFault, ...]
    verdict: Verdict
    baseline: Verdict
    capped: bool
    cap_reason: str
    on_path_device_count: int

    @property
    def confidence_lifted(self) -> bool:
        """True when admitting the on-path witness raised the tier above the symptom-only
        baseline (the "suspected → confirmed" the design targets)."""
        return _TIER_RANK[self.verdict.tier] > _TIER_RANK[self.baseline.tier]

    def headline(self) -> str:
        if self.attributed is None:
            return f"{self.src}→{self.dst}: no on-path cause attributed ({self.verdict.tier.value})"
        return (f"{self.src}→{self.dst} broke at {self.attributed.headline()} "
                f"[{self.verdict.tier.value}]")

    def to_dict(self) -> dict:
        return {
            "tenant_id": self.tenant_id, "src": self.src, "dst": self.dst,
            "attributed": self.attributed.to_dict() if self.attributed else None,
            "explained_away": [f.to_dict() for f in self.explained_away],
            "discounted": [d.to_dict() for d in self.discounted],
            "verdict": self.verdict.to_dict(),
            "baseline_verdict": self.baseline.to_dict(),
            "confidence_lifted": self.confidence_lifted,
            "capped": self.capped, "cap_reason": self.cap_reason,
            "on_path_device_count": self.on_path_device_count,
            "headline": self.headline(),
        }


_TIER_RANK = {VerdictTier.UNDETERMINED: 0, VerdictTier.SUSPECTED: 1, VerdictTier.CONFIRMED: 2}


@dataclass(frozen=True)
class AttributionConfig:
    """Tunables (kept explicit, never hidden). `window_s` is the ± tolerance around the
    symptom's activity interval within which a device fault counts as time-correlated."""

    window_s: float = 300.0


# ── the attributor ─────────────────────────────────────────────────────────────


class OnPathAttributor:
    """Restricts RCA candidates to on-path devices and attributes the symptom to the
    upstream-most on-path fault, lifting the verdict through verdicts.assess. Stateless +
    pure; construct once, call attribute() per (symptom, path)."""

    def __init__(self, cfg: Optional[AttributionConfig] = None) -> None:
        self._cfg = cfg if cfg is not None else AttributionConfig()

    # -- tenant scoping (structural, default-closed) --------------------------

    def _scoped(self, tenant_id: str, sigs: tuple[Signal, ...]) -> tuple[Signal, ...]:
        """Drop every signal from another tenant BEFORE any reasoning (§3a). An empty
        tenant_id fails closed (dropped)."""
        return tuple(s for s in sigs if s.tenant_id and s.tenant_id == tenant_id)

    def _symptom_window(self, symptom: tuple[Signal, ...]):
        lo = min(s.ts for s in symptom)
        hi = max(s.ts for s in symptom)
        return lo, hi

    def _time_correlated(self, sig: Signal, lo, hi) -> bool:
        w = self._cfg.window_s
        return (lo.timestamp() - w) <= sig.ts.timestamp() <= (hi.timestamp() + w)

    # -- the public entry point -----------------------------------------------

    def attribute(
        self, tenant_id: str, path: AssembledPath,
        symptom_signals: list[Signal] | tuple[Signal, ...],
        fault_signals: list[Signal] | tuple[Signal, ...],
    ) -> Attribution:
        if not tenant_id:
            raise ValueError("attribute requires a tenant (§3a default-closed)")
        symptom = self._scoped(tenant_id, tuple(symptom_signals))
        faults = self._scoped(tenant_id, tuple(fault_signals))

        # The symptom-only baseline — what today says ("suspected"). Everything below can
        # only RAISE it via an admissible on-path witness, never lower it.
        baseline = assess(symptom) if symptom else _no_symptom_verdict()

        # The path is admissible ONLY when it is THIS tenant's path (§3a): another tenant's
        # path can never seed an on-path set.
        on_path = on_path_devices(path) if (path is not None
                                            and path.tenant_id == tenant_id) else ()

        # No symptom, or no on-path devices ⇒ no dependency edge ⇒ NO attribution (principle
        # 5). The verdict is the baseline; discounted list still explains every fault.
        if not symptom or not on_path:
            reason = ("no symptom signal for this tenant" if not symptom
                      else "no on-path device set — no dependency edge, no attribution")
            no_edge_discounts = [DiscountedFault(_ref(f), f.kind, reason) for f in faults]
            return Attribution(
                tenant_id=tenant_id, src=path.src if path else "", dst=path.dst if path else "",
                attributed=None, explained_away=(),
                discounted=_sorted_discounts(no_edge_discounts),
                verdict=baseline, baseline=baseline, capped=False, cap_reason="",
                on_path_device_count=len(on_path))

        lo, hi = self._symptom_window(symptom)
        # index on-path devices by identity for O(1) candidacy
        by_ident: dict[str, OnPathDevice] = {}
        for d in on_path:
            for ident in d.identities:
                by_ident.setdefault(ident, d)

        # 1+2. CANDIDATE RESTRICTION + off-path / off-window DISCOUNTING.
        candidates: list[tuple[OnPathDevice, Signal]] = []
        discounted: list[DiscountedFault] = []
        for f in faults:
            match = next((by_ident[i] for i in sorted(_fault_identities(f)) if i in by_ident),
                         None)
            if match is None:
                discounted.append(DiscountedFault(
                    _ref(f), f.kind,
                    "off-path: device not on the affected SRC→DST path — "
                    "severity is not causality (discounted)"))
                continue
            if not self._time_correlated(f, lo, hi):
                discounted.append(DiscountedFault(
                    _ref(f), f.kind,
                    "off-window: fault not time-correlated with the symptom (discounted)"))
                continue
            candidates.append((match, f))

        if not candidates:
            return Attribution(
                tenant_id=tenant_id, src=path.src, dst=path.dst, attributed=None,
                explained_away=(), discounted=_sorted_discounts(discounted),
                verdict=baseline, baseline=baseline, capped=False, cap_reason="",
                on_path_device_count=len(on_path))

        # 3+4. MINIMAL-SET-COVER + EXPLAINING-AWAY. With one symptom the minimal cover is one
        # cause: the UPSTREAM-MOST on-path fault (NetMedic "buck stops here"). Downstream
        # faults are victims of it and are explained away (not independently blamed). Order:
        # smallest upstream_rank, then higher role prior, then higher severity, then id.
        faults_by_device = _group_by_device(candidates)
        ordered = sorted(
            faults_by_device.values(),
            key=lambda g: (g.device.upstream_rank, -_ROLE_PRIOR.get(g.device.role, 0),
                           -g.peak_sev_rank, g.device.label or g.device.address))
        cause = ordered[0]
        explained = tuple(_attributed_fault(g) for g in ordered[1:])
        attributed = _attributed_fault(cause)

        # confidence lift: feed symptom + the cause's on-path witness signals into the SAME
        # independence gate. A genuine independent cross-modality pair → confirmed; anything
        # less stays suspected. `confirmed` is never fabricated here.
        verdict = assess(tuple(symptom) + tuple(cause.signals))

        # HONESTY CAP: if the SRC→cause span crosses an unknown/opaque/ambiguous element, the
        # attribution cannot be confirmed — cap at suspected + evidence_missing (design §1).
        cap_reason = _span_cap_reason(path, cause.device.segment_index)
        capped = False
        if cap_reason and verdict.tier is VerdictTier.CONFIRMED:
            verdict = _cap_to_suspected(verdict, cap_reason)
            capped = True

        return Attribution(
            tenant_id=tenant_id, src=path.src, dst=path.dst,
            attributed=attributed, explained_away=explained,
            discounted=_sorted_discounts(discounted),
            verdict=verdict, baseline=baseline, capped=capped, cap_reason=cap_reason,
            on_path_device_count=len(on_path))


# ── helpers ─────────────────────────────────────────────────────────────────


@dataclass
class _DeviceFaults:
    device: OnPathDevice
    signals: list[Signal] = field(default_factory=list)

    @property
    def peak_sev_rank(self) -> int:
        order = {"info": 0, "warn": 1, "high": 2, "crit": 3}
        return max((order.get(s.severity.value, 0) for s in self.signals), default=0)


def _group_by_device(candidates: list[tuple[OnPathDevice, Signal]]) -> dict[int, _DeviceFaults]:
    groups: dict[int, _DeviceFaults] = {}
    for dev, sig in candidates:
        g = groups.setdefault(dev.upstream_rank, _DeviceFaults(dev))
        g.signals.append(sig)
    return groups


def _attributed_fault(g: _DeviceFaults) -> AttributedFault:
    sigs = sorted(g.signals, key=lambda s: (s.ts, str(s.signal_id)))
    modality = sigs[0].modality_class.value if sigs else ""
    return AttributedFault(
        device=g.device, kind=sigs[0].kind if sigs else "",
        modality=modality,
        observers=tuple(sorted({s.observer.observer_id for s in sigs})),
        signal_ids=tuple(str(s.signal_id) for s in sigs))


def _ref(sig: Signal) -> str:
    return f"{sig.kind}:{sig.entity_id}"


def _sorted_discounts(ds: list[DiscountedFault]) -> tuple[DiscountedFault, ...]:
    return tuple(sorted(ds, key=lambda d: (d.identity, d.kind, d.reason)))


def _span_cap_reason(path: AssembledPath, up_to_segment_index: int) -> str:
    """Is the SRC→cause span cleanly observed? Returns "" when clear, else a human reason.
    A cause upstream of segment 0 (the DNS head, index -1) has NO fabric span to cross — its
    resolution evidence stands alone. Otherwise every segment index ≤ the cause's must be a
    KNOWN, hop-complete, unambiguous segment; any unknown/opaque/ECMP element on the span
    means we cannot confirm the traffic reached the cause the way we claim (design §1)."""
    if up_to_segment_index < 0:
        return ""
    for seg in path.segments:
        if seg.index > up_to_segment_index:
            continue
        if seg.segment_type == SegmentType.UNKNOWN.value:
            return (f"path segment {seg.index} is unknown/opaque on the SRC→cause span — "
                    f"cannot confirm on-path causality across an unobserved segment "
                    f"({seg.reason or 'segment type not established'})")
        if seg.unknown_hops:
            return (f"path segment {seg.index} has unresponsive hop(s) {list(seg.unknown_hops)} "
                    f"on the SRC→cause span — the missing hop is preserved, not bridged")
        if seg.ambiguous:
            return (f"path segment {seg.index} is an ECMP/ambiguous diamond on the SRC→cause "
                    f"span — the traffic's actual branch is not asserted")
    return ""


def _cap_to_suspected(verdict: Verdict, reason: str) -> Verdict:
    """Downgrade a CONFIRMED verdict to SUSPECTED with the honesty reason appended. Never
    upgrades — mirrors engine._cap_verdict for the object-level ranking."""
    if verdict.tier is not VerdictTier.CONFIRMED:
        return verdict
    return Verdict(
        tier=VerdictTier.SUSPECTED, coverage=verdict.coverage,
        reasons=verdict.reasons + (f"capped to suspected: {reason}",))


def _no_symptom_verdict() -> Verdict:
    return Verdict(VerdictTier.UNDETERMINED,
                   EvidenceCoverage(frozenset(), frozenset(), None, ()),
                   ("no symptom signal for this tenant",))


# ── engine enrichment entry (path-causality RCA P2 → run_window) ──────────────

# The app-experience SYMPTOM kinds: the customer-path outcomes an on-path fault
# is asked to EXPLAIN (never the fault itself — those are CLOUD_EDGE_FAULT_KINDS /
# NETWORK_FAULT_KINDS). Synthetic DEM checks, active probes to the app, and the
# app-edge error/latency lane. Deliberately DISJOINT from the fault sets, so a
# signal is never both the symptom and its own cause.
APP_SYMPTOM_KINDS: frozenset[str] = frozenset({
    "synthetic_http_fail", "synthetic_http_5xx", "synthetic_http_4xx",
    "synthetic_http_latency_high", "synthetic_tls_fail", "synthetic_dns_fail",
    "synthetic_tcp_connect_fail", "synthetic_timeout", "synthetic_icmp_loss",
    "synthetic_tcp_probe_fail", "synthetic_cert_expired", "synthetic_cert_expiring",
    "probe_loss", "probe_rtt_anomaly",
    "app_error_rate_high", "app_latency_high",
})

# The on-path fault kinds admissible as app-witnesses — the union P2 restricts to.
ATTRIBUTABLE_FAULT_KINDS: frozenset[str] = CLOUD_EDGE_FAULT_KINDS | NETWORK_FAULT_KINDS


def object_attribution(
    tenant_id: str,
    signals: tuple[Signal, ...] | list[Signal],
    paths: tuple[AssembledPath, ...] | list[AssembledPath],
    attributor: Optional[OnPathAttributor] = None,
) -> Optional[tuple[Attribution, AssembledPath]]:
    """Engine enrichment entry (design §2.4): given ONE correlation object's signals
    and the P1-assembled typed paths for its tenant, restrict RCA candidates to the
    on-path devices and return the (attribution, winning typed path) that NAMES the
    upstream-most on-path fault explaining the app symptom — or None.

    The winning path is returned alongside the attribution so the RCA report/render
    can show the DISCOVERED typed path (segments + key devices + unknown/ambiguous +
    head) the cause sits on — the P3 contract.

    Returns None (→ the object is left byte-for-byte unchanged) when: no tenant, no
    path, no app symptom in the object, or no on-path time-correlated cause. Only a
    REAL named cause (`attributed is not None`) is returned, so an object with no
    discoverable path or an off-path fault enriches to nothing (the non-regression
    contract run_window relies on).

    Pure + deterministic + additive: it READS the object's signals, never mutates
    them, and given the same (signals, paths) always chooses the same cause + path —
    the replay contract. Bounded by len(paths) (the caller keeps the per-tenant path
    set small) × the P1/P2 bounded walks.
    """
    if not tenant_id or not paths:
        return None
    attr = attributor if attributor is not None else OnPathAttributor()
    symptom = [s for s in signals
               if s.tenant_id == tenant_id and s.kind in APP_SYMPTOM_KINDS]
    if not symptom:
        return None
    faults = [s for s in signals
              if s.tenant_id == tenant_id and s.kind in ATTRIBUTABLE_FAULT_KINDS]
    if not faults:
        return None
    best: Optional[tuple[Attribution, AssembledPath]] = None
    best_rank: tuple[int, int] = (-1, -1)
    # Deterministic: paths in (src, dst) order; a strictly higher (verdict tier,
    # on-path device count) wins, so the earliest path among equals is kept.
    for path in sorted(paths, key=lambda p: (p.src, p.dst, p.tenant_id)):
        if path.tenant_id != tenant_id:
            continue
        a = attr.attribute(tenant_id, path, symptom, faults)
        if a.attributed is None:
            continue
        rank = (_TIER_RANK[a.verdict.tier], a.on_path_device_count)
        if rank > best_rank:
            best, best_rank = (a, path), rank
    return best
