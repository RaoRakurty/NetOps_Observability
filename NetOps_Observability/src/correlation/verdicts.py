"""Evidence independence + modality coverage → verdict tier.

Pipeline stage [7] machinery of Correlation Engine v2 (#67 §4.5, owner
pre-freeze amendments + research C4). Pure functions over canonical Signals:
no IO, no wall-clock, no randomness — the same evidence set always yields the
same verdict (replay contract).

The rule being enforced
-----------------------
Every modality class has a documented blind spot, so **no single modality
confirms a data-plane verdict**; and modality diversity alone is not
corroboration — two measurements that operationally depend on the same failed
observer must never confirm each other. `confirmed` therefore requires a pair
of signals that are simultaneously:

  (a) of different modality classes (active_probe / passive_flow /
      control_plane / device_telemetry), AND
  (b) mutually independent observations (different observer, no shared
      measurement authority).

Independence model: transport vs measurement authority
-------------------------------------------------------
`collection_path` distinguishes WHO vouches for a measurement:

  * ``direct`` / ``via_aggregator`` — TRANSPORT. Telegraf/Vector relay what the
    device itself measured; the device remains the observer. Transport does not
    break independence (a dead transport loses signals, it does not forge
    agreeing ones).
  * ``via_controller[:instance]`` / ``via_cloud_api[:instance]`` — MEASUREMENT
    AUTHORITY. An SD-WAN controller reporting tunnel state, a cloud API
    reporting gateway health: the intermediary *is* the effective witness. Two
    signals sharing the same authority instance share its failure modes and
    are NOT mutually independent, whatever their nominal observers.

Instances are carried as a suffix (``via_controller:vmanage-1``). When the
instance is unknown, all signals of that authority KIND are conservatively
assumed to share one instance (fail-closed: we under-claim independence,
never over-claim it). Unrecognized collection paths are likewise treated as a
shared unknown authority — a malformed producer can weaken evidence to
`suspected`, but can never manufacture a `confirmed`.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from signals import (
    CONFIRM_AUTHORITIES,
    ModalityClass,
    ProbeAuthority,
    ProbeFate,
    ProbeScope,
    Signal,
)

# Verdict tiers — string values match the frozen corr_objects.verdict_tier Enum8.
class VerdictTier(str, Enum):
    UNDETERMINED = "undetermined"
    SUSPECTED = "suspected"
    CONFIRMED = "confirmed"


# Collection-path kinds that make the intermediary the effective witness.
# A kind not in either set is treated as an authority (fail-closed).
TRANSPORT_PATHS = frozenset({"direct", "via_aggregator"})
AUTHORITY_PATHS = frozenset({"via_controller", "via_cloud_api"})

# Gate thresholds (config-hash members; P4 replay-driven calibration re-fits).
MIN_MODALITIES = 2
MIN_OBSERVERS = 2


@dataclass(frozen=True)
class Witness:
    """The effective observation identity of one signal, after collapsing
    measurement authorities. Hashable + comparable: the independence relation
    is computed on Witnesses, never on raw strings."""

    observer_id: str
    modality: ModalityClass
    authority: str | None  # measurement-authority fate group (controller/cloud-api)
    probe_authority: ProbeAuthority | None = None  # set for active_probe witnesses
    fate: ProbeFate | None = None                  # measurement fate fingerprint (any modality)
    probe_scope: ProbeScope | None = None          # UI projection

    @property
    def trusted(self) -> bool:
        """May this witness anchor a confirmed verdict? Non-probe evidence is
        trusted; a probe is trusted only at HIGH/MEDIUM authority. LOW/DEBUG
        probes SUPPORT (→ suspected) but never CONFIRM."""
        if self.probe_authority is None:
            return True
        return self.probe_authority in CONFIRM_AUTHORITIES

    def independent_of(self, other: "Witness") -> bool:
        """Mutual independence: different observer, no shared measurement
        authority, and no shared FATE — same agent host, NAT/public egress, or
        (seam+target+schedule). Fate is checked ACROSS modalities, so a probe and
        a device-telemetry collector on the same host are NOT independent; one
        host failure would correlate both, so they cannot co-confirm."""
        if self.observer_id == other.observer_id:
            return False
        if self.authority is not None and self.authority == other.authority:
            return False
        if self.fate is not None and other.fate is not None \
                and self.fate.shares_fate_with(other.fate):
            return False
        return True


def _enum_attr(attrs: dict, key: str, enum_cls, default):  # type: ignore[no-untyped-def]
    raw = str(attrs.get(key, "")) if isinstance(attrs, dict) else ""
    try:
        return enum_cls(raw) if raw else default
    except ValueError:
        return default


def _fate_of(sig: Signal) -> ProbeFate | None:
    """Fate fingerprint from co-location metadata (any modality). None when the
    signal carries no co-location info — absence never fabricates independence
    OR dependence (two None-fate witnesses are treated as independent)."""
    a = sig.attrs if isinstance(sig.attrs, dict) else {}
    agent_host = str(a.get("agent_host", "") or a.get("agent_id", "") or a.get("host_id", ""))
    source_egress = str(a.get("source_egress", "") or a.get("egress_ip", ""))
    seam_id = str(a.get("seam_id", ""))
    schedule_id = str(a.get("schedule_id", ""))
    target = str(a.get("target", ""))
    if sig.modality_class is ModalityClass.ACTIVE_PROBE and not target:
        target = _probe_target(sig.entity_id)
    if not (agent_host or source_egress or seam_id):
        return None
    return ProbeFate(
        agent_host=agent_host, source_egress=source_egress,
        seam_id=seam_id, target=target, schedule_id=schedule_id,
    )


def _probe_target(entity_id: str) -> str:
    return entity_id.split("->", 1)[1].strip().lower() if "->" in entity_id else entity_id.strip().lower()


def witness_of(sig: Signal) -> Witness:
    """Derive the effective witness of a signal. Total function: any
    collection_path string yields a Witness; unknown forms degrade safely.

    Probe authority/independence (Step 3): an active_probe witness carries its
    DERIVED authority (high/medium/low/debug_only) and its fate fingerprint, both
    enriched at ingestion (fail-closed to LOW when unclassified). Authority gates
    confirmation; fate gates independence."""
    probe_authority: ProbeAuthority | None = None
    probe_scope: ProbeScope | None = None
    if sig.modality_class is ModalityClass.ACTIVE_PROBE:
        probe_authority = _enum_attr(sig.attrs, "probe_authority", ProbeAuthority, ProbeAuthority.LOW)
        probe_scope = _enum_attr(sig.attrs, "probe_scope", ProbeScope, ProbeScope.UNKNOWN)
    fate = _fate_of(sig)

    path = sig.observer.collection_path or "direct"
    kind, _, instance = path.partition(":")
    kind = kind.strip().lower()
    if kind in TRANSPORT_PATHS:
        authority = None
    elif kind in AUTHORITY_PATHS:
        # Unknown instance ⇒ one shared instance per kind (conservative).
        authority = f"{kind}:{instance.strip().lower()}" if instance.strip() else kind
    else:
        # Unrecognized path: fail closed — one shared bucket per unknown kind.
        authority = f"unknown:{kind}"
    return Witness(
        observer_id=sig.observer.observer_id,
        modality=sig.modality_class,
        authority=authority,
        probe_authority=probe_authority,
        fate=fate,
        probe_scope=probe_scope,
    )


@dataclass(frozen=True)
class EvidenceCoverage:
    """Explainable coverage summary for one evidence set. Every field renders
    directly into the evidence log / hypothesis JSON — explainability is the
    contract, not an afterthought."""

    modality_classes: frozenset[ModalityClass]
    observer_ids: frozenset[str]
    independent_pair: tuple[str, str] | None  # observer ids of one qualifying pair
    fate_groups: tuple[tuple[str, ...], ...]  # observers grouped by shared fate
    trusted_modalities: frozenset[ModalityClass] = frozenset()  # modalities w/ a trusted (confirm-eligible) witness
    low_authority_probe_scopes: frozenset[ProbeScope] = frozenset()  # low-authority probe scopes seen (support-only)
    excluded_debug: tuple[str, ...] = ()  # debug_only/lab probe observers EXCLUDED from the verdict

    @property
    def modality_count(self) -> int:
        return len(self.modality_classes)

    @property
    def observer_count(self) -> int:
        return len(self.observer_ids)

    def to_dict(self) -> dict:
        """JSON shape embedded in corr_objects.hypotheses (frozen contract)."""
        return {
            "modality_coverage": sorted(m.value for m in self.modality_classes),
            "observer_coverage": sorted(self.observer_ids),
            "independent_pair": list(self.independent_pair) if self.independent_pair else None,
            "fate_shared_groups": [list(g) for g in self.fate_groups],
            "trusted_modalities": sorted(m.value for m in self.trusted_modalities),
            "low_authority_probe_scopes": sorted(s.value for s in self.low_authority_probe_scopes),
            "excluded_debug_probes": list(self.excluded_debug),
        }


def coverage(signals: list[Signal] | tuple[Signal, ...]) -> EvidenceCoverage:
    """Compute modality/observer coverage and find one independent confirming
    pair (different modality AND mutually independent witnesses).

    Deterministic: results depend only on the signal set, not its order.
    Duplicate signal_ids are deduplicated first — replay reads archive ∪ hot,
    and double-counting a signal must never strengthen evidence.
    O(n²) pairwise scan with n = distinct witnesses, bounded in practice by the
    per-object node cap (200); witnesses dedup far below that.
    """
    seen: dict[str, Witness] = {}
    for sig in signals:
        seen.setdefault(str(sig.signal_id), witness_of(sig))
    all_witnesses = sorted(
        set(seen.values()),
        key=lambda w: (w.observer_id, w.modality.value, w.authority or ""),
    )

    # Decision #1: debug_only / lab probes are EXCLUDED from customer-facing
    # verdicts entirely — they never open, attach, or contribute to any tier.
    # (They still appear in the timeline/Debug view; just not here.)
    excluded_debug = tuple(sorted({
        w.observer_id for w in all_witnesses if w.probe_authority is ProbeAuthority.DEBUG_ONLY
    }))
    witnesses = [w for w in all_witnesses if w.probe_authority is not ProbeAuthority.DEBUG_ONLY]

    modalities = frozenset(w.modality for w in witnesses)
    observers = frozenset(w.observer_id for w in witnesses)
    trusted_modalities = frozenset(w.modality for w in witnesses if w.trusted)
    low_auth_scopes = frozenset(
        w.probe_scope for w in witnesses
        if w.probe_scope is not None and not w.trusted
    )

    # A confirming pair must be cross-modality, mutually independent (incl.
    # non-fate-shared), AND BOTH trusted — a low-authority or fate-shared probe
    # can never anchor a confirmed verdict.
    pair: tuple[str, str] | None = None
    for i, a in enumerate(witnesses):
        for b in witnesses[i + 1:]:
            if a.trusted and b.trusted and a.modality != b.modality and a.independent_of(b):
                lo, hi = sorted((a.observer_id, b.observer_id))
                pair = (lo, hi)
                break
        if pair:
            break

    # Fate groups for explainability: measurement-authority sharing PLUS probe
    # fate-sharing (agent host / NAT egress / seam+target+schedule), union-found.
    parent: dict[str, str] = {w.observer_id: w.observer_id for w in witnesses}

    def find(x: str) -> str:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(x: str, y: str) -> None:
        parent[find(x)] = find(y)

    auth_groups: dict[str, str] = {}
    for w in witnesses:
        if w.authority is not None:
            if w.authority in auth_groups:
                union(w.observer_id, auth_groups[w.authority])
            else:
                auth_groups[w.authority] = w.observer_id
    fated = [w for w in witnesses if w.fate is not None]
    for i, a in enumerate(fated):
        for b in fated[i + 1:]:
            if a.observer_id != b.observer_id and a.fate is not None \
                    and b.fate is not None and a.fate.shares_fate_with(b.fate):
                union(a.observer_id, b.observer_id)
    grouped: dict[str, set[str]] = {}
    for oid in parent:
        grouped.setdefault(find(oid), set()).add(oid)
    fate_groups = tuple(
        tuple(sorted(members)) for _, members in sorted(grouped.items()) if len(members) > 1
    )

    return EvidenceCoverage(
        modality_classes=modalities,
        observer_ids=observers,
        independent_pair=pair,
        fate_groups=fate_groups,
        trusted_modalities=trusted_modalities,
        low_authority_probe_scopes=low_auth_scopes,
        excluded_debug=excluded_debug,
    )


@dataclass(frozen=True)
class Verdict:
    """Tier + machine-readable reasons. Reasons feed corr_evidence notes and
    the `evidence_missing` list — "confirmed because…" / "suspected because…"
    is always derivable, never reconstructed after the fact."""

    tier: VerdictTier
    coverage: EvidenceCoverage
    reasons: tuple[str, ...]

    def to_dict(self) -> dict:
        return {
            "verdict_tier": self.tier.value,
            "reasons": list(self.reasons),
            **self.coverage.to_dict(),
        }


def assess(
    signals: list[Signal] | tuple[Signal, ...],
    required_modalities: frozenset[ModalityClass] | None = None,
) -> Verdict:
    """The verdict gate. Pure; total; monotone (adding evidence never
    downgrades a tier — guarded by test).

    required_modalities: a signature template's per-fault-class demand (e.g.
    tunnel verdicts need control_plane + active_probe). When unmet, the gate
    caps at SUSPECTED and says exactly what's missing — the `evidence_missing`
    honesty mechanism.
    """
    cov = coverage(signals)
    reasons: list[str] = []

    if not cov.observer_ids:
        # Nothing admissible. Distinguish "no evidence" from "only debug/lab
        # probes" (excluded by Decision #1) so the Inspector can say why.
        if cov.excluded_debug:
            return Verdict(VerdictTier.UNDETERMINED, cov, (
                "only debug/lab probe evidence — excluded from customer-facing "
                "verdicts; no admissible signal to assess",
            ))
        return Verdict(VerdictTier.UNDETERMINED, cov, ("no evidence signals",))

    # Required modalities must be met by a TRUSTED witness (Decision #2 + probe
    # authority): a low-authority probe does NOT satisfy an active_probe
    # requirement, so DIA cannot confirm on a self/low probe + one other modality.
    missing_required = (
        frozenset(required_modalities - cov.trusted_modalities)
        if required_modalities else frozenset()
    )
    gate_ok = (
        cov.modality_count >= MIN_MODALITIES
        and cov.observer_count >= MIN_OBSERVERS
        and cov.independent_pair is not None
        and not missing_required
    )

    if gate_ok:
        assert cov.independent_pair is not None
        reasons.append(
            f"independent confirming pair: {cov.independent_pair[0]} ⟂ {cov.independent_pair[1]} "
            f"across {cov.modality_count} modality classes (both trusted, non-fate-shared)"
        )
        return Verdict(VerdictTier.CONFIRMED, cov, tuple(reasons))

    # SUSPECTED — low-authority probes may support a suspicion but never confirm.
    if cov.low_authority_probe_scopes and not cov.trusted_modalities:
        scopes = ", ".join(sorted(s.value for s in cov.low_authority_probe_scopes))
        reasons.append(
            f"only low-authority probe evidence ({scopes}) — weak support; "
            "cannot confirm without an independent trusted modality"
        )
    if cov.modality_count < MIN_MODALITIES:
        reasons.append(
            f"single modality class ({next(iter(cov.modality_classes)).value}); "
            f"need ≥{MIN_MODALITIES} — every modality has a blind spot"
        )
    if cov.observer_count < MIN_OBSERVERS:
        reasons.append(f"single observer ({next(iter(cov.observer_ids))}); need ≥{MIN_OBSERVERS}")
    if cov.observer_count >= MIN_OBSERVERS and cov.modality_count >= MIN_MODALITIES \
            and cov.independent_pair is None:
        shared = "; ".join(",".join(g) for g in cov.fate_groups) or "shared observers"
        reasons.append(f"no independent cross-modality pair (fate-shared: {shared})")
    for m in sorted(missing_required, key=lambda x: x.value):
        present_low = m is ModalityClass.ACTIVE_PROBE and m in cov.modality_classes
        if present_low:
            reasons.append(
                "required modality active_probe present but only LOW-authority "
                "(self/internal) — needs a trusted (customer/service) probe to confirm"
            )
        else:
            reasons.append(f"required modality missing (no trusted witness): {m.value}")

    return Verdict(VerdictTier.SUSPECTED, cov, tuple(reasons))
