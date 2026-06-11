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

from signals import ModalityClass, Signal

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
    authority: str | None  # shared-fate group, None = independent observation

    def independent_of(self, other: "Witness") -> bool:
        """Mutual independence: different observer AND no shared authority.

        Symmetric by construction. Sharing an authority is disqualifying even
        across different nominal observers (the authority is the single point
        whose failure/compromise would correlate both measurements).
        """
        if self.observer_id == other.observer_id:
            return False
        if self.authority is not None and self.authority == other.authority:
            return False
        return True


def witness_of(sig: Signal) -> Witness:
    """Derive the effective witness of a signal. Total function: any
    collection_path string yields a Witness; unknown forms degrade safely."""
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
    )


@dataclass(frozen=True)
class EvidenceCoverage:
    """Explainable coverage summary for one evidence set. Every field renders
    directly into the evidence log / hypothesis JSON — explainability is the
    contract, not an afterthought."""

    modality_classes: frozenset[ModalityClass]
    observer_ids: frozenset[str]
    independent_pair: tuple[str, str] | None  # observer ids of one qualifying pair
    fate_groups: tuple[tuple[str, ...], ...]  # observers grouped by shared authority

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
    witnesses = sorted(
        set(seen.values()),
        key=lambda w: (w.observer_id, w.modality.value, w.authority or ""),
    )

    modalities = frozenset(w.modality for w in witnesses)
    observers = frozenset(w.observer_id for w in witnesses)

    pair: tuple[str, str] | None = None
    for i, a in enumerate(witnesses):
        for b in witnesses[i + 1:]:
            if a.modality != b.modality and a.independent_of(b):
                lo, hi = sorted((a.observer_id, b.observer_id))
                pair = (lo, hi)
                break
        if pair:
            break

    groups: dict[str, set[str]] = {}
    for w in witnesses:
        if w.authority is not None:
            groups.setdefault(w.authority, set()).add(w.observer_id)
    fate_groups = tuple(
        tuple(sorted(members))
        for _, members in sorted(groups.items())
        if len(members) > 1
    )

    return EvidenceCoverage(
        modality_classes=modalities,
        observer_ids=observers,
        independent_pair=pair,
        fate_groups=fate_groups,
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
        return Verdict(VerdictTier.UNDETERMINED, cov, ("no evidence signals",))

    missing_required = (
        frozenset(required_modalities - cov.modality_classes)
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
            f"across {cov.modality_count} modality classes"
        )
        return Verdict(VerdictTier.CONFIRMED, cov, tuple(reasons))

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
        reasons.append(f"required modality missing: {m.value}")

    return Verdict(VerdictTier.SUSPECTED, cov, tuple(reasons))
