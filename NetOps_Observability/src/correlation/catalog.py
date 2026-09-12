# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Failure-signature catalog — hypothesis templates as DATA (#67 §4.5).

The catalog is the engine's rule base: declarative predicates authored by
practitioners, validated on load, versioned as a content hash, and CI-gated by
per-signature replay fixtures (research C7: the catalog is a CI-tested
versioned artifact, never loose JSON).

Storage of record is Postgres ``corr_hypothesis_templates`` (tenant '' = the
built-in set below; tenants may shadow ids). This module owns the SPEC: schema
validation (a malformed template is rejected at load, never half-evaluated),
the canonical content hash that snapshots pin as ``catalog_version`` (replay
contract, research C6), and the built-in starter set.

Template anatomy (mirrors the owner's plain-English authoring format):
  requires        → the evidence chain (coverage = satisfied/total)
  discriminators  → the look-alike killers; violation tanks the score AND
                    force-evaluates the named competitor
  required_modalities → per-fault-class demand fed to the verdict gate (③)
  applies_when    → optional topology guard (seam redundancy model — groups,
                    cloud-ingestion.md §4)
  verdict         → layer + OWNER + first steps (Recommended Actions panel)
"""

from __future__ import annotations

import hashlib
import json
import os
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from signals import EntityType, ModalityClass

CATALOG_SCHEMA_VERSION = 1


class Clause(BaseModel):
    """One evidence predicate. ``kind`` accepts alternation ('qos_drops|if_discards');
    a signal satisfies the clause if its kind is one of the tokens and every
    present constraint holds."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: str = Field(min_length=1)
    entity_type: EntityType | None = None
    min_deviation: float | None = Field(default=None, ge=0)
    role: str | None = None          # topology role (primary/fallback/wan_edge) — scored when ctx known
    optional: bool = False

    @field_validator("kind")
    @classmethod
    def _kind_tokens_nonempty(cls, v: str) -> str:
        if any(not t.strip() for t in v.split("|")):
            raise ValueError(f"empty alternation token in kind {v!r}")
        return v

    def kinds(self) -> frozenset[str]:
        """The alternation tokens of ``kind``, as a set.

        MEMOISED per Clause INSTANCE (P2 step 0b, 2026-08-28). The value is a
        pure function of one immutable string on a frozen model, but it was
        recomputed on every call: the cProfile of one first-sight `run_window`
        at 2.5K shape (docs/scale/P2_COHORT_PROFILE_2026-08-28.md §8) shows
        **248,508 calls, 1.415 s cumulative of a 9.36 s run_window (~15 %)** —
        the same split+frozenset over the same ~400 clause objects, once per
        (template x object) pair. The value is unchanged; only how often it is
        built is."""
        return _clause_kinds(self)


# Keyed by IDENTITY, not by value — the same pattern (and for the same measured
# reason) as _VERSION_HASH_CACHE below and scoring._CATALOG_PLAN_CACHE: hashing a
# frozen pydantic model walks every field, so a value-keyed lru_cache would spend
# more building cache KEYS than the split it avoids. The dict holds a strong
# reference to each cached Clause, so its id() cannot be recycled onto a
# different object while the entry lives.
#
# Bounded (§9): a catalog is ~100 templates x ~4 clauses, and clauses are
# immutable for the life of the catalog that owns them, so the working set is a
# few hundred entries; a reloaded catalog is simply new entries. On overflow the
# whole map is cleared and refills — an allocation optimisation, never a
# correctness input, and the returned SET is identical either way.
CORR_CLAUSE_KINDS_CACHE = os.environ.get(
    "CORR_CLAUSE_KINDS_CACHE", "1").lower() in ("1", "true", "yes")
_CLAUSE_KINDS_CACHE: dict[int, tuple[Clause, frozenset[str]]] = {}
_CLAUSE_KINDS_CACHE_MAX = max(1, int(os.environ.get("CORR_CLAUSE_KINDS_CACHE_MAX", "4096")))
_CLAUSE_KINDS_STATS: dict[str, int] = {"computed": 0, "cached": 0}


def clause_kinds_cache_stats() -> dict[str, int]:
    """Clause.kinds computed vs served from the identity cache (§10)."""
    return dict(_CLAUSE_KINDS_STATS)


def _compute_clause_kinds(clause: Clause) -> frozenset[str]:
    """The real computation, byte-for-byte the pre-P2 body of Clause.kinds."""
    return frozenset(t.strip() for t in clause.kind.split("|"))


def _clause_kinds(clause: Clause) -> frozenset[str]:
    if not CORR_CLAUSE_KINDS_CACHE:
        _CLAUSE_KINDS_STATS["computed"] += 1
        return _compute_clause_kinds(clause)
    hit = _CLAUSE_KINDS_CACHE.get(id(clause))
    if hit is not None and hit[0] is clause:
        _CLAUSE_KINDS_STATS["cached"] += 1
        return hit[1]
    _CLAUSE_KINDS_STATS["computed"] += 1
    value = _compute_clause_kinds(clause)
    if len(_CLAUSE_KINDS_CACHE) >= _CLAUSE_KINDS_CACHE_MAX:
        _CLAUSE_KINDS_CACHE.clear()
    _CLAUSE_KINDS_CACHE[id(clause)] = (clause, value)
    return value


class Discriminator(BaseModel):
    """Look-alike killer: if the 'absent' clause IS present in evidence, this
    template is contradicted (score ×0.2) and ``else_prefer`` must be scored
    as a competitor — competing hypotheses by construction, never collapsed."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    absent: Clause                   # the thing that must NOT be in evidence
    within_s: float = Field(default=600.0, gt=0)
    else_prefer: str = Field(min_length=1)


class Verdict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    owner: Literal["netops", "carrier", "cloud_provider", "app_team",
                   "colo_provider", "isp", "sdwan_vendor"]
    layer: str = Field(min_length=1)            # "L1/L2", "L3/L4", ...
    first_steps: tuple[str, ...] = Field(min_length=1, max_length=5)


class CausalStage(BaseModel):
    """One rung of a fault family's propagation ladder (owner directive
    2026-07-13: the RCA must LIST how one failure causes the next — e.g.
    link flap → underlay down → routing protocol down → IKE/IPsec down →
    apps dark — not just name the root). The ladder is the family's KNOWN
    propagation model, declared root→impact; at score time each stage is
    marked witnessed (with the matching evidence kinds) or not. An
    unwitnessed stage stays on the ladder with ``unobserved_note`` — the
    chain never claims a stage happened without evidence.

    ``stage`` is Operator-View copy: plain operator language, no product
    branding, no schema/token jargon."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    stage: str = Field(min_length=1)             # operator label, e.g. "IKE/IPsec tunnel"
    witness: str = Field(min_length=1)           # kind alternation, Clause syntax
    unobserved_note: str = ""                    # operator copy when no witness matched
    root: bool = False                           # this rung is the template's root cause

    @field_validator("witness")
    @classmethod
    def _witness_tokens_nonempty(cls, v: str) -> str:
        if any(not t.strip() for t in v.split("|")):
            raise ValueError(f"empty alternation token in witness {v!r}")
        return v

    def kinds(self) -> frozenset[str]:
        return frozenset(t.strip() for t in self.witness.split("|"))


class AppliesWhen(BaseModel):
    """Topology guard. Unknown topology context ⇒ the template still applies
    but is marked topology_unverified — skipping hypotheses because we lack a
    seam inventory would hide real explanations (fail-open on applicability,
    fail-closed stays where it belongs: edges and verdicts)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    redundancy_model: tuple[str, ...] | None = None  # e.g. ("active_standby", "active_active")


# External seam-facing taxonomy for the v1 NOC catalog (owner spec 2026-07-02,
# docs/design/research/midnight-noc-questions.md): which of the five operational
# seams a fault family lives on, and where it can occur at all. These are
# METADATA for attribution/UX/AI narration — grounding and verdict gating stay
# with the engine's seam inventory and the independence rules (unchanged).
Seam = Literal["LAN", "WAN_SDWAN", "DC_FABRIC", "CARRIER_INTERCONNECT", "CLOUD_APP"]
DeploymentScope = Literal["onprem_only", "cloud_only", "hybrid"]


# ── structural grounding vocabulary (tracker 157) ────────────────────────────
#
# THE DEFECT. A `requires` clause is (kind, entity_type, min_deviation) shaped.
# Nothing in it can assert that the TOPOLOGY hosting the evidence has the
# structure the signature NAMES, so a role/tier-scoped family ranks in a
# topology that structurally cannot host it. Measured: with 130 leaf switches
# suffering purely LOCAL port faults and no spine device anywhere in the
# scenario, `sig.ent.fabric.spine-leaf-path-degradation` ranks TOP — satisfied
# by token co-occurrence (interface + path signals), never by any evidence a
# spine tier exists. `seams` does not help: it is a tie-break AFFINITY
# (engine.py `_break_ties_by_seam_affinity`), not a matching gate.
#
# THE FIX IS A GATE, NOT A WEIGHT. A template that names a structure declares
# it here, EXPLICITLY, in the template body — never inferred at runtime from the
# template's name. `scoring.rank` admits such a template only when the evidence
# ATTESTS that structure; otherwise it is excluded from ranking with the reason
# recorded (`corr_template_ungrounded_total`). A discount would be wrong: a
# strong symptom match would simply out-score it again.
#
# DEFAULT-CLOSED. `Catalog._checks` refuses to load a template that carries a
# clause-level `role` predicate without declaring a structural requirement, so
# "names a role but asserts no structure" is unwritable from here on.
#
# THE CLASSES. Each names a structure the EVIDENCE can attest (or provably
# cannot). What attests each one is scoring's business — `scoring
# .STRUCTURE_ATTESTING_KINDS` — because attestation is a statement about
# evidence, not about the catalog; this module owns only the declaration.
#
#   device_tier       a device attributable to a named topology TIER
#                     (spine / leaf / core). **NOTHING IN THE EVIDENCE PLANE
#                     ATTESTS A TIER TODAY** — `Signal` has no role field, and a
#                     survey of every `attrs` key across 5,345,497 archived
#                     signals (2026-08-30) found none either. The class
#                     therefore FAILS CLOSED: a template that needs a tier is
#                     suppressed until a role source exists. That is the honest
#                     behaviour — a tier the platform cannot see is a tier it
#                     must not claim.
#   redundancy_group  a device attested as a MEMBER of a redundancy or
#                     aggregation group (FHRP/HSRP/VRRP, firewall HA pair,
#                     MLAG/vPC, LACP/LAG bundle, ECMP member set, WLC cluster).
#                     Attested by the group-scoped signal kinds themselves — a
#                     device only reports FHRP state or MLAG keepalives if it is
#                     in one.
#   overlay_encap     an overlay/encapsulation structure (VXLAN/EVPN VNI, VTEP,
#                     IPsec/GRE tunnel). Attested by the overlay-scoped kinds.
#   transit_path      a MEASURED leg between two distinct endpoints — a path or
#                     segment entity the platform actually probed, not a
#                     device-local counter. Attested by the entity's own shape
#                     (`a->b`). This is the structural floor under any family
#                     that claims a fault at a hand-off or on a transit leg: no
#                     measured leg, no leg-shaped verdict.
#
# SCOPE, AND WHAT IS DELIBERATELY NOT SOLVED HERE. This is the ROLE / TIER /
# GROUP / LEG axis, all of it decided from the EVIDENCE. Ownership-SEAM scoping
# — is this specific interface really the carrier handoff? — is a different
# axis with a different source: the engine's seam inventory, which `rank` is
# deliberately pure of. So `transit_path` is the strongest honest precondition
# available for a WAN-edge claim (a measured leg exists), NOT proof that the
# congested interface faces a provider. That residual is named, not papered
# over; closing it means giving the scorer a seam/role context and re-keying
# the rank memo, which is its own piece of work.
StructureClass = Literal["device_tier", "redundancy_group", "overlay_encap",
                         "transit_path"]


class Template(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str = Field(pattern=r"^sig\.[a-z0-9_.-]+$")  # namespaced: sig.<persona>.<domain>.<name>
    title: str = Field(min_length=1)
    domain: str = Field(pattern=r"^(ent|sp)\.[a-z-]+$")
    version: int = Field(default=1, ge=1)
    enabled: bool = True
    requires: tuple[Clause, ...] = Field(min_length=1)
    discriminators: tuple[Discriminator, ...] = ()
    required_modalities: tuple[ModalityClass, ...] = ()
    applies_when: AppliesWhen | None = None
    direction_expect: str = ""
    verdict: Verdict
    # ---- v1 NOC-catalog fields (all optional — the pre-v1 templates omit them).
    seams: tuple[Seam, ...] = ()
    deployment_scope: DeploymentScope = "hybrid"
    # The voice contract (owner wording rules): a precise evidence-based line
    # for the NOC operator, and a plain-English impact line for a manager.
    # Neither may overclaim — they describe the fault FAMILY, the tier label is
    # supplied by the verdict gate at match time.
    operator_phrase: str = ""
    manager_phrase: str = ""
    blast_radius: str = ""                     # likely scope in operational terms
    false_positives: tuple[str, ...] = ()      # common look-alikes to disclose
    composition_hints: tuple[str, ...] = ()    # higher-level incidents this rolls into
    demo_priority: Literal["p0", "p1", "p2"] = "p0"
    # ---- Port-Intelligence (#94) fields.
    # score_impact: which port-health scoring dimension this family debits
    # (docs/design/port-intelligence.md weights); metadata for the P4 scorer.
    score_impact: str = ""
    next_checks: tuple[str, ...] = ()          # ordered NOC verification steps
    # Physical-layer look-alikes are rampant (dirty fiber vs bad optic vs
    # polarity…): entries with allow_root_cause_confirmed=False are CAPPED at
    # suspected even when the independence gate passes — confirmation needs
    # fiber-path validation or a human. Non-port templates keep True.
    allow_root_cause_confirmed: bool = True
    # Propagation ladder (root→impact), owner directive 2026-07-13: templates
    # whose fault family cascades across layers declare the ladder so the RCA
    # can show HOW one failure causes the next. Optional — most templates omit.
    causal_chain: tuple[CausalStage, ...] = ()
    # Structural precondition (tracker 157). The topology structures this
    # signature's CLAIM depends on and its clauses cannot assert. A GATE, not a
    # weight: `scoring.rank` refuses to rank the template unless the evidence
    # attests every class listed. Empty = the family names no structure beyond
    # what its clauses already assert, and it is untouched by the gate.
    requires_structure: tuple[StructureClass, ...] = ()

    @field_validator("requires")
    @classmethod
    def _at_least_one_mandatory(cls, v: tuple[Clause, ...]) -> tuple[Clause, ...]:
        if all(c.optional for c in v):
            raise ValueError("template needs >=1 non-optional requires clause")
        return v

    @field_validator("requires_structure")
    @classmethod
    def _structure_declared_once(
        cls, v: tuple[StructureClass, ...],
    ) -> tuple[StructureClass, ...]:
        """A repeated class is an authoring slip, and the gate is a SET test —
        it would silently mean nothing. Reject it rather than absorb it."""
        if len(set(v)) != len(v):
            dupes = sorted({c for c in v if v.count(c) > 1})
            raise ValueError(f"requires_structure repeats {dupes}")
        return v


class Catalog(BaseModel):
    model_config = ConfigDict(frozen=True)

    templates: tuple[Template, ...]

    @field_validator("templates")
    @classmethod
    def _checks(cls, v: tuple[Template, ...]) -> tuple[Template, ...]:
        ids = [t.id for t in v]
        if len(ids) != len(set(ids)):
            dupes = sorted({i for i in ids if ids.count(i) > 1})
            raise ValueError(f"duplicate template ids: {dupes}")
        # discriminator targets must resolve inside the catalog AND must not
        # form a contradiction cycle that flip-flops scoring (lint, C7).
        known = set(ids)
        for t in v:
            for d in t.discriminators:
                if d.else_prefer not in known:
                    raise ValueError(f"{t.id}: else_prefer {d.else_prefer!r} not in catalog")
                if d.else_prefer == t.id:
                    raise ValueError(f"{t.id}: discriminator prefers itself")
            # v1 NOC-catalog lint: a template that declares seams opted into the
            # voice contract — both phrasings are mandatory, and a confirmable
            # template must not be confirmable from a single evidence plane
            # (the verdict gate enforces ≥2 modalities at runtime regardless;
            # this catches an author FORGETTING to declare the second one).
            if t.seams:
                if not t.operator_phrase.strip() or not t.manager_phrase.strip():
                    raise ValueError(f"{t.id}: seam-tagged template needs operator_phrase and manager_phrase")
                if len(t.required_modalities) == 1 and len({k for c in t.requires for k in c.kinds()}) < 2:
                    raise ValueError(f"{t.id}: confirmable template needs evidence beyond a single kind/plane")
            # tracker 157, DEFAULT-CLOSED: a clause-level `role` predicate NAMES a
            # topology role, and `clause_matches` cannot enforce it (the scorer has
            # no per-signal role to test against — see its docstring). Before this
            # rule the role was decorative: two templates carried one, and both
            # ranked in topologies that had no such role. A template may still
            # declare a role, but it must now also declare the structure that role
            # belongs to, so the gate can refuse it when the evidence cannot
            # support it. An author who adds a role and forgets the structure gets
            # a load failure, not a silent overclaim.
            if any(c.role for c in t.requires) and not t.requires_structure:
                roles = sorted({c.role for c in t.requires if c.role})
                raise ValueError(
                    f"{t.id}: clause role(s) {roles} declared with no "
                    f"requires_structure — a named role needs a structural "
                    f"precondition the evidence can be tested against (tracker 157)")
        return v

    def enabled_templates(self) -> tuple[Template, ...]:
        return tuple(t for t in self.templates if t.enabled)

    def get(self, template_id: str) -> Template | None:
        for t in self.templates:
            if t.id == template_id:
                return t
        return None

    def version_hash(self) -> str:
        """Canonical content hash → ``corr_objects.catalog_version``. Stable
        across process restarts and dict ordering; changes iff an enabled
        template's content changes (replay contract).

        MEMOISED (tracker 167, 2026-08-22). This is a CONSTANT for a given
        catalog — the docstring above says so — but it was recomputed on every
        call, and `rank()` calls it once per RCA object. Profiled on the live 1K
        shape (48,000 nodes, 43,065 objects): **241.09 s of a 495.86 s
        `run_window`, 48.6 % of the whole cycle**, spent re-serialising 100
        templates through pydantic (4.3 M `to_python` calls), re-encoding them to
        JSON (100 s in `iterencode`) and re-hashing (43,067 SHA-256s) to return
        the same twelve characters every time.

        The value is unchanged; only the number of times it is computed is."""
        return _catalog_version_hash(self)


# Keyed by IDENTITY, not by value. `lru_cache` on the Catalog itself looked
# right and was measurably wrong: hashing a frozen pydantic model walks every
# field of every template, so a 43,065-object cycle spent 88 M `hash_func` calls
# (58.75 s) computing cache KEYS for a value it already had. The dict below
# holds a strong reference to each cached Catalog, so its id() cannot be
# recycled onto a different object while the entry lives; it is bounded, and a
# reloaded catalog is simply a new entry. A changed catalog therefore still
# produces a changed hash — the replay contract is untouched.
_VERSION_HASH_CACHE: dict[int, tuple[Catalog, str]] = {}
_VERSION_HASH_CACHE_MAX = 4


def _catalog_version_hash(catalog: Catalog) -> str:
    hit = _VERSION_HASH_CACHE.get(id(catalog))
    if hit is not None and hit[0] is catalog:
        return hit[1]
    value = _compute_version_hash(catalog)
    if len(_VERSION_HASH_CACHE) >= _VERSION_HASH_CACHE_MAX:
        _VERSION_HASH_CACHE.clear()
    _VERSION_HASH_CACHE[id(catalog)] = (catalog, value)
    return value


def _compute_version_hash(catalog: Catalog) -> str:
    """The real computation, once per distinct catalog."""
    canon = json.dumps(
        [t.model_dump(mode="json") for t in sorted(catalog.enabled_templates(), key=lambda t: t.id)],
        sort_keys=True, separators=(",", ":"),
    )
    digest = hashlib.sha256(f"v{CATALOG_SCHEMA_VERSION}|{canon}".encode()).hexdigest()
    return f"cat-{digest[:12]}"


def load_catalog(raw: list[dict]) -> Catalog:
    """Validate raw template dicts (from PG rows or the built-in set) into a
    Catalog. Raises pydantic.ValidationError with the offending template —
    a bad catalog never half-loads."""
    return Catalog(templates=tuple(Template(**t) for t in raw))


# ---------------------------------------------------------------------------
# Built-in starter set (tenant_id = ''). Six signatures from the design §4.5,
# namespaced per the persona/domain segmentation (owner, 2026-06-11). These
# exercise the full machinery and SHOW the authoring shape; the practitioner
# catalog replaces/extends them at P3 — same schema, hot-reloaded from PG.
# ---------------------------------------------------------------------------

# The IPsec fault family's propagation ladder (owner directive 2026-07-13):
# a VPN outage cascades link → underlay → routing → tunnel → apps, and the RCA
# must show that interconnection, marking each rung witnessed or not. Shared by
# the tunnel-down and underlay-down templates — the ROOT rung differs, the
# ladder does not. Stage labels + notes are Operator-View copy (plain language,
# no product branding, no internals).
_IPSEC_CASCADE: list[dict] = [
    {"stage": "Gateway egress link",
     "witness": "link_state_change|if_errors|if_metric_anomaly",
     "unobserved_note": "No link signals seen on the gateway egress"},
    {"stage": "Underlay path to the tunnel peer",
     "witness": "ipsec_underlay_status",
     "unobserved_note": "No underlay-path signals seen — the outer path is not implicated by any witness"},
    {"stage": "Routing over the underlay (BGP)",
     "witness": "bgp_peer_flap|bgp_state_anomaly|bgp_adjacency_change|route_count_drop",
     "unobserved_note": "No routing-protocol signals seen on this path"},
    {"stage": "IKE/IPsec tunnel",
     "witness": "ipsec_tunnel_status|ipsec_negotiation_fail|ipsec_sa_rekey_fail",
     "unobserved_note": "No tunnel-state signals seen"},
    {"stage": "Applications behind the tunnel",
     "witness": "probe_loss|probe_rtt_anomaly|synthetic_icmp_loss|cloud_health|cloud_flow_log",
     "unobserved_note": "No application-impact signals seen"},
]


def _cascade(root_stage: str) -> list[dict]:
    """The family ladder with one rung marked as this template's root."""
    return [{**s, "root": s["stage"] == root_stage} for s in _IPSEC_CASCADE]


BUILTIN_TEMPLATES: list[dict] = [
    {
        "id": "sig.ent.wan-edge.congestion",
        # tracker 157 — the `role: wan_edge` clause below names a role, and before
        # the gate it was decorative: `clause_matches` cannot test it, so
        # if_util_high on any busy link plus any loss signal satisfied this
        # signature. The role itself is NOT attestable (no evidence carries a
        # device role — see catalog.StructureClass), so the honest precondition
        # is the structural floor beneath it: a MEASURED leg must exist. No
        # probed path/segment ⇒ no edge-congestion verdict. It does not prove the
        # interface faces a provider — that needs the seam inventory, which the
        # scorer cannot see, and the gap is declared rather than pretended away.
        "requires_structure": ["transit_path"],
        "title": "WAN edge congestion",
        "domain": "ent.wan-edge",
        "requires": [
            {"kind": "if_util_high", "entity_type": "interface", "role": "wan_edge"},
            {"kind": "probe_loss|probe_latency_departure", "entity_type": "segment", "min_deviation": 3.0},
            {"kind": "qos_drops|if_discards", "entity_type": "interface", "optional": True},
        ],
        "required_modalities": ["device_telemetry", "active_probe"],
        "discriminators": [
            {"absent": {"kind": "bgp_path_change"}, "within_s": 600,
             "else_prefer": "sig.ent.wan-edge.routing-instability"},
            {"absent": {"kind": "if_errors", "min_deviation": 3.0},
             "else_prefer": "sig.ent.middle-mile.physical-degradation"},
        ],
        "direction_expect": "interface -> path -> service",
        "verdict": {
            "owner": "netops", "layer": "L3/L4",
            "first_steps": [
                "Check QoS queue drops per class on the WAN edge",
                "Compare utilization vs CIR on the affected circuit",
                "Look for a traffic shift: routing change or new top-talker",
            ],
        },
    },
    {
        "id": "sig.ent.wan-edge.routing-instability",
        "title": "Routing instability / path churn",
        "domain": "ent.wan-edge",
        "requires": [
            {"kind": "bgp_path_change|bgp_peer_flap"},
            {"kind": "probe_latency_departure|path_change", "entity_type": "segment", "optional": True},
        ],
        "required_modalities": ["control_plane"],
        "discriminators": [
            {"absent": {"kind": "if_errors", "min_deviation": 3.0},
             "else_prefer": "sig.ent.middle-mile.physical-degradation"},
        ],
        "direction_expect": "control-plane -> path -> service",
        "verdict": {
            "owner": "netops", "layer": "L3",
            "first_steps": [
                "Identify what triggered the path change (peer flap, policy push, prefix withdrawal)",
                "Check whether the new path violates latency/geo expectations",
                "Dampen or pin the route if churn is ongoing",
            ],
        },
    },
    {
        "id": "sig.ent.middle-mile.physical-degradation",
        "title": "Circuit/optics physical degradation",
        "domain": "ent.middle-mile",
        "requires": [
            {"kind": "if_errors|if_crc|optical_power_low", "entity_type": "interface", "min_deviation": 3.0},
            {"kind": "probe_loss", "entity_type": "segment", "optional": True},
        ],
        "required_modalities": ["device_telemetry"],
        "discriminators": [
            {"absent": {"kind": "if_util_high", "min_deviation": 3.0},
             "else_prefer": "sig.ent.wan-edge.congestion"},
        ],
        "direction_expect": "physical -> path -> service",
        "verdict": {
            "owner": "carrier", "layer": "L1/L2",
            "first_steps": [
                "Pull light levels / error counters on the cross-connect interface",
                "Shift traffic to a healthy group member if one exists",
                "Open the carrier ticket with timestamped error deltas",
            ],
        },
    },
    {
        "id": "sig.ent.internet.dns-impairment",
        "title": "DNS resolution impairment",
        "domain": "ent.internet",
        "requires": [
            {"kind": "dns_latency_high|dns_failure_rate"},
            {"kind": "synthetic_http_fail", "optional": True},
        ],
        "required_modalities": ["active_probe"],
        "discriminators": [
            {"absent": {"kind": "probe_loss", "min_deviation": 3.0},
             "else_prefer": "sig.ent.wan-edge.congestion"},
        ],
        "direction_expect": "dns -> service",
        "verdict": {
            "owner": "isp", "layer": "DNS/L7",
            "first_steps": [
                "Compare resolver health: local forwarder vs upstream vs public resolver",
                "Check whether failures are domain-scoped (SaaS-side) or global (resolver-side)",
                "Fail over to the secondary resolver path",
            ],
        },
    },
    {
        "id": "sig.ent.cloud.region-degradation",
        "title": "Cloud region / backbone degradation",
        "domain": "ent.cloud",
        "requires": [
            {"kind": "probe_latency_departure|probe_loss", "entity_type": "segment", "min_deviation": 3.0},
            # NOT optional: assigning cloud-provider blame without any cloud-side
            # witness is exactly the over-claim this engine refuses — probe loss
            # alone matches too many failure modes (caught by fixture battle:
            # the MTU scenario's probe_loss gave this template full coverage).
            {"kind": "lb_5xx|cloud_gw_anomaly|cloud_health_event"},
        ],
        "required_modalities": ["active_probe", "control_plane"],
        "discriminators": [
            {"absent": {"kind": "if_util_high", "min_deviation": 3.0},
             "else_prefer": "sig.ent.wan-edge.congestion"},
            {"absent": {"kind": "if_errors", "min_deviation": 3.0},
             "else_prefer": "sig.ent.middle-mile.physical-degradation"},
        ],
        "direction_expect": "cloud-seam -> service",
        "verdict": {
            "owner": "cloud_provider", "layer": "L3 (provider)",
            "first_steps": [
                "Compare probes into the same region from a second vantage (multi-site divergence)",
                "Check the provider health dashboard / personal health API for the region",
                "Shift latency-sensitive traffic to an alternate region if architecture allows",
            ],
        },
    },
    {
        # Cloud-hosted app whose own dependency broke (DB/cache/queue down, config
        # denies the dependency port). The failure is INSIDE the cloud: the tunnel
        # and the boundary are fine, the app itself cannot serve. Without this,
        # such faults grounded onto 'private-connectivity-down' (the only cloud
        # signature the lane satisfied) — correct objects, misleading label; a NOC
        # would go chase the tunnel. Discriminator: no tunnel/route change in the
        # window, and the boundary is NOT rejecting (or rejects only the app's
        # own dependency port, not the app's ingress).
        "id": "sig.ent.cloud.app-dependency-down",
        "title": "Cloud application dependency down (database / cache / queue / policy)",
        "domain": "ent.cloud",
        "requires": [
            # the impact: the app is unhealthy / its journey fails.
            {"kind": "cloud_health"},
            # optional corroboration: a boundary REJECT on the dependency port
            # (an SG/NSG denial shows up here as a rejected flow).
            {"kind": "cloud_flow_log", "optional": True},
            {"kind": "probe_loss|probe_rtt_anomaly", "optional": True},
            # the PROVIDER's own view of the resource (CloudWatch / Azure Monitor
            # status checks, CPU/network anomalies) — an observer independent of
            # our probes and of the app's own logs.
            {"kind": "cloud_resource_anomaly", "optional": True},
        ],
        # a cloud-only picture is one vantage → stays suspected until an
        # independent observer (probe inside the VPC/VNet, the underlay, or the
        # provider's resource telemetry) agrees.
        "required_modalities": ["device_telemetry"],
        # Look-alike killer: if the private link itself changed state (DX/VPN) in
        # the window, this is a CONNECTIVITY fault, not an app-dependency fault.
        "discriminators": [
            {"absent": {"kind": "cloud_change", "entity_type": "cloud_resource"}, "within_s": 600,
             "else_prefer": "sig.ent.cloud.private-connectivity-down"},
        ],
        "direction_expect": "dependency -> service",
        "verdict": {
            "owner": "app_team", "layer": "L7 (application dependency)",
            "first_steps": [
                "Check the app's data-tier dependencies (database, cache, queue) — process up, port listening",
                "Check for a recent security-group / NSG / firewall change on the dependency port",
                "Confirm the private tunnel is UP (if it is, this is NOT a connectivity fault)",
                "Check the app's readiness endpoint and its dependency spans for the failing hop",
            ],
        },
    },
    {
        # #81 — hybrid private-connectivity outage: Direct Connect / IPSec tunnel
        # between on-prem and the cloud goes down → BGP drops, routes withdraw,
        # the cloud app is unreachable FROM corporate (often still fine from the
        # internet). Matches the real cloud signal kinds (cloud_change = DX/VPN
        # state, cloud_flow_log = boundary REJECT, cloud_health = unreachable),
        # corroborated by a customer-path probe. Without this, the bare probe_loss
        # mis-matched 'dia-egress-latency' (a latency signature) — see the
        # discriminator added there.
        "id": "sig.ent.cloud.private-connectivity-down",
        "title": "Private connectivity to cloud down (Direct Connect / IPSec)",
        "domain": "ent.cloud",
        "requires": [
            # the root: a DX virtual-interface / VPN tunnel state change.
            {"kind": "cloud_change|cloud_audit"},
            # the impact: traffic rejected at the boundary, or the app unreachable.
            {"kind": "cloud_flow_log|cloud_health"},
            # independent customer-path witness (lifts to a confirmable verdict).
            {"kind": "probe_loss|probe_rtt_anomaly", "optional": True},
        ],
        # confirmation needs the control-plane change AND an independent probe —
        # a cloud-only picture (one vantage) stays suspected (verdict gate).
        "required_modalities": ["control_plane", "active_probe"],
        "direction_expect": "cloud-seam -> service",
        "verdict": {
            "owner": "carrier", "layer": "L3 (private connectivity — DX / IPSec)",
            "first_steps": [
                "Check the Direct Connect virtual interface + its BGP session (idle/withdrawn routes)",
                "Check the backup IPSec tunnel (phase-1/phase-2, DPD) to the on-prem SD-WAN edge",
                "Verify route propagation on-prem↔VPC; fail traffic to the alternate path if one exists",
                "Confirm the cloud app is reachable from the internet (isolates connectivity vs app fault)",
            ],
        },
    },
    {
        # A site-to-site IPsec tunnel DIED at the IKE/ESP layer — phase-1/2 failure,
        # DPD teardown, rekey/lifetime mismatch, SA drop, or the charon/gateway
        # process crashing — with NO cloud control-plane change to explain it. The
        # apps behind that tunnel go unreachable. This is DISTINCT from
        # private-connectivity-down (which is a DX/route CONFIG change, and requires
        # a cloud_change): here the root is the tunnel's own control plane, reported
        # by the enterprise VPN gateway itself. Because that gateway observer is
        # INDEPENDENT of the cloud API (ipsec:<gw> vs cloud:<acct>:<region>), the
        # tunnel-down control-plane evidence + an independent active probe are TWO
        # observers, so this can reach a CONFIRMED verdict — the whole reason the
        # owner asked for an IPsec↔app signature.
        "id": "sig.ent.cloud.ipsec-tunnel-down",
        "title": "IPsec tunnel down (IKE / DPD / SA) — apps behind the tunnel unreachable",
        "domain": "ent.cloud",
        "requires": [
            # the root: the VPN gateway reports the tunnel/IKE_SA down (state=down|
            # dpd_timeout|ike_failed|rekey_failed). Entity is the seam (the tunnel).
            {"kind": "ipsec_tunnel_status", "entity_type": "cloud_resource"},
            # the impact: an independent customer-path probe can't reach the apps,
            # or the apps' own health went dark behind the tunnel.
            {"kind": "probe_loss|probe_rtt_anomaly|synthetic_icmp_loss|cloud_health"},
            # optional corroboration: the flow lane sees the app's traffic vanish.
            {"kind": "cloud_flow_log", "optional": True},
        ],
        # control_plane = the IPsec-gateway tunnel state; active_probe = the
        # independent customer-path witness. Two observers → confirmable (vs the
        # cloud-only 'suspected' ceiling).
        "required_modalities": ["control_plane", "active_probe"],
        "discriminators": [
            # A cloud config CHANGE (route/DX/VPN-attribute edit) must NOT be in the
            # window: if one IS, the outage is a deliberate change, not an infra
            # tunnel death → this template is contradicted and private-connectivity-
            # down is scored as the competitor instead.
            {"absent": {"kind": "cloud_change|cloud_audit"},
             "else_prefer": "sig.ent.cloud.private-connectivity-down"},
            # The gateway's own off-tunnel check to the peer's public address must
            # NOT be reporting the outer path dead: if it IS, the root is the
            # UNDERLAY (owner directive 2026-07-13) — the tunnel/IKE death is a
            # downstream symptom and the middle-mile template wins ownership.
            {"absent": {"kind": "ipsec_underlay_status"},
             "else_prefer": "sig.ent.middle-mile.ipsec-underlay-down"},
        ],
        "direction_expect": "cloud-seam -> service",
        "causal_chain": _cascade("IKE/IPsec tunnel"),
        "verdict": {
            "owner": "netops", "layer": "L3 (IPsec tunnel — IKE/ESP)",
            "first_steps": [
                "Check the tunnel's IKE_SA on the VPN gateway (phase-1 down, AUTH failed, or peer not responding)",
                "Check DPD: did dead-peer-detection tear the SA? Is the peer answering INFORMATIONALs?",
                "Check rekey/lifetime: a phase-2 lifetime or PFS mismatch drops the SA on the clock (periodic outage)",
                "Confirm the charon/gateway process is running and the ESP SPIs match both ends (one-way SA)",
                "If a redundant tunnel exists, confirm BGP/route failover moved traffic to it",
            ],
        },
    },
    {
        # Owner directive 2026-07-13: when the OUTER path to the VPN peer is dead,
        # the underlay is the root — the IPsec tunnel (and everything above it) is
        # a downstream symptom, and a NOC chasing IKE config would be chasing the
        # wrong layer. The root witness is the gateway's own off-tunnel
        # reachability check to the peer's public address (kind=
        # ipsec_underlay_status, rides the default route, not the tunnel).
        "id": "sig.ent.middle-mile.ipsec-underlay-down",
        "title": "Underlay path to the VPN peer down — tunnel and apps behind it are downstream symptoms",
        "domain": "ent.middle-mile",
        "requires": [
            # the root: the gateway's off-tunnel check to the peer's public
            # address fails — the transport UNDER the tunnel is dead.
            {"kind": "ipsec_underlay_status", "entity_type": "cloud_resource"},
            # the downstream symptom: the gateway reports the tunnel/IKE down.
            {"kind": "ipsec_tunnel_status", "entity_type": "cloud_resource"},
            # the impact: independent customer-path probes / app health dark.
            {"kind": "probe_loss|probe_rtt_anomaly|synthetic_icmp_loss|cloud_health"},
            # optional corroboration: the flow lane sees the traffic vanish.
            {"kind": "cloud_flow_log", "optional": True},
        ],
        # control_plane = the gateway's tunnel state; active_probe = the underlay
        # check + the independent customer-path witness (different observers →
        # the independence gate can confirm).
        "required_modalities": ["control_plane", "active_probe"],
        "discriminators": [
            # A cloud config change in-window means a deliberate change, not an
            # underlay death — same guard as the tunnel-down template.
            {"absent": {"kind": "cloud_change|cloud_audit"},
             "else_prefer": "sig.ent.cloud.private-connectivity-down"},
        ],
        "direction_expect": "underlay -> cloud-seam -> service",
        "causal_chain": _cascade("Underlay path to the tunnel peer"),
        "verdict": {
            "owner": "isp", "layer": "L1-L3 (underlay / DIA path)",
            "first_steps": [
                "Check the gateway egress link and default route (local side first: link state, ARP to the next hop)",
                "Trace toward the peer's public address from the gateway — find where the outer path dies",
                "Check the peer side: is its public address reachable from a third vantage?",
                "Open the provider ticket with timestamped unreachability from the gateway's own check",
                "If a second underlay (LTE/other DIA) exists, fail the tunnel over to it",
            ],
        },
    },
    {
        "id": "sig.ent.wan-edge.tunnel-mtu-blackhole",
        "title": "Tunnel MTU blackhole",
        "domain": "ent.wan-edge",
        "requires": [
            {"kind": "tunnel_degraded|tunnel_flap", "entity_type": "path"},
            {"kind": "synthetic_http_fail|app_large_transfer_fail"},
            {"kind": "probe_loss", "entity_type": "segment", "optional": True},
        ],
        "required_modalities": ["active_probe"],
        "discriminators": [
            {"absent": {"kind": "tunnel_down"},
             "else_prefer": "sig.ent.wan-edge.routing-instability"},
        ],
        "direction_expect": "tunnel -> session -> service",
        "verdict": {
            "owner": "netops", "layer": "Tunnel/L4",
            "first_steps": [
                "Test with DF-bit pings at descending sizes across the tunnel (find the real PMTU)",
                "Check for ICMP type-3/code-4 being filtered along the underlay",
                "Clamp TCP MSS on the tunnel interface as immediate mitigation",
            ],
        },
    },
    # -----------------------------------------------------------------------
    # P3 signatures (2026-06-14) — authored from REAL observed lab objects, not
    # theory. These use the engine's actual emitted vocabulary (probe_rtt_anomaly
    # / probe_loss on path, bgp_adjacency_change / bgp_state_anomaly on device,
    # link_state_change + if_metric_anomaly on interface), so live correlation
    # objects finally match a signature instead of falling to the alphabetical
    # evidence_missing tie-break. Seeds: object 60e00be9 (DIA seam), the orphaned
    # wan-r2 BGP anomaly, and link+interface co-faults.
    # -----------------------------------------------------------------------
    {
        "id": "sig.ent.middle-mile.dia-egress-latency",
        "title": "ISP / DIA egress latency",
        "domain": "ent.middle-mile",
        "requires": [
            # Multi-vantage RTT/loss to a shared target across the DIA seam. The
            # ≥2-observer demand is enforced by the verdict gate, not the clause.
            {"kind": "probe_rtt_anomaly|probe_loss", "entity_type": "path"},
            # The corroborating WAN egress interface witness that lifts a probe-
            # only suspicion to a confirmable, second-modality verdict.
            {"kind": "if_metric_anomaly", "entity_type": "interface", "optional": True},
        ],
        "required_modalities": ["active_probe"],
        "discriminators": [
            # Routing churn at the edge is a different fault — if BGP is moving,
            # this isn't pure egress latency.
            {"absent": {"kind": "bgp_adjacency_change|bgp_state_anomaly"}, "within_s": 600,
             "else_prefer": "sig.ent.wan-edge.bgp-peer-flap"},
            # #81 — a cloud DX/VPN state change present means this isn't ISP egress
            # latency at all; it's a private-connectivity outage. Yield to it so a
            # tunnel-down (probe_loss only, no real latency) stops reading as latency.
            {"absent": {"kind": "cloud_change|cloud_audit"}, "within_s": 600,
             "else_prefer": "sig.ent.cloud.private-connectivity-down"},
        ],
        "direction_expect": "path-egress -> service",
        "verdict": {
            "owner": "isp", "layer": "L3 (DIA / provider egress)",
            "first_steps": [
                "Compare the two vantage points to the same target across the DIA boundary — shared RTT/loss departure points at the ISP egress, not the host",
                "Check the WAN egress interface for utilization/error counters in the same window",
                "Open the ISP ticket with per-target RTT/loss deltas, timestamps, and the DIA seam id",
            ],
        },
    },
    {
        # Multi-plane DIA egress fault: the customer-path probe AND an independent
        # control-plane witness (BGP flap) BOTH degrade on the same seam. This is a
        # MORE-confirmed, more-specific hypothesis than either single-plane sibling
        # (dia-egress-latency = probe only; bgp-peer-flap = control-plane only), so
        # when both planes corroborate it wins on coverage (2/2 required, no
        # contradiction) and confirms via the cross-modality pair — the trusted
        # customer-path probe corroborating the control-plane fault (decision: a
        # probe alone never confirms; here it confirms ONLY alongside the independent
        # BGP witness, which verdicts.assess enforces). When only ONE plane is
        # present this signature is half-covered and loses to its single-plane
        # siblings, so it never disturbs their behavior.
        "id": "sig.ent.middle-mile.dia-egress-corroborated",
        "title": "DIA egress fault — probe + control-plane corroborated",
        "domain": "ent.middle-mile",
        "requires": [
            {"kind": "probe_rtt_anomaly|probe_loss", "entity_type": "path"},
            {"kind": "bgp_adjacency_change|bgp_state_anomaly", "entity_type": "device"},
        ],
        "required_modalities": ["active_probe", "control_plane"],
        "direction_expect": "path-egress -> control-plane -> service",
        "verdict": {
            "owner": "isp", "layer": "L3 (DIA / provider egress)",
            "first_steps": [
                "Confirm both witnesses share the DIA seam: the probe RTT/loss departure point and the flapping BGP peer are the same provider egress",
                "Check the WAN egress interface and the peer session for the same window (hold-timer expiry vs link bounce)",
                "Open the ISP ticket with the per-target RTT/loss deltas, the BGP flap timestamps, and the DIA seam id",
            ],
        },
    },
    {
        "id": "sig.ent.wan-edge.bgp-peer-flap",
        "title": "BGP peer flap",
        "domain": "ent.wan-edge",
        "requires": [
            # Adjacency-change (syslog, control_plane) or BGP-MIB state anomaly
            # (device_telemetry) — either witnesses the flap.
            {"kind": "bgp_adjacency_change|bgp_state_anomaly", "entity_type": "device"},
            # Optional downstream impact: host pressure, route-driven loss, or a
            # co-incident link event.
            {"kind": "device_resource_anomaly|probe_loss|link_state_change", "optional": True},
            # "What changed?" — a config change on the SAME device inside the window.
            # Optional and single-plane by construction (it is the box talking about
            # itself, like the transition it corroborates), so it can raise coverage
            # but never supply the second modality a confirmation needs.
            # Today it arrives on the TRAP observer only: `syslog.config.change`
            # ships `shadow: true` until the V1 workload profile is versioned
            # (events.yaml), so on a syslog-only estate this clause is inert.
            {"kind": "device_config_change", "optional": True},
        ],
        "required_modalities": ["control_plane"],
        "discriminators": [
            # A flap with a concurrent link-down is really a link fault dragging
            # the session — prefer the L1/L2 explanation.
            {"absent": {"kind": "link_state_change"}, "within_s": 300,
             "else_prefer": "sig.ent.access.local-link-fault"},
        ],
        "direction_expect": "control-plane -> route -> service",
        "verdict": {
            "owner": "netops", "layer": "L3 (routing)",
            "first_steps": [
                "Identify the peer and the flap trigger (hold-timer expiry, interface bounce, policy push, prefix withdrawal)",
                "Check the peering interface/link state and the underlay for the same window",
                "Dampen the session or pin the route if churn continues; escalate to the peer owner if the neighbor is external",
            ],
        },
    },
    {
        "id": "sig.ent.access.local-link-fault",
        "title": "Local link fault",
        "domain": "ent.access",
        "requires": [
            # The L1/L2 state transition AND a same-interface counter anomaly —
            # two planes on one port. (Same-interface co-location is the engine's
            # grounding job; the scorer needs both kinds present.)
            {"kind": "link_state_change", "entity_type": "interface"},
            {"kind": "if_metric_anomaly", "entity_type": "interface"},
        ],
        "required_modalities": ["control_plane", "device_telemetry"],
        "direction_expect": "interface(L1/L2) -> device -> service",
        "verdict": {
            "owner": "netops", "layer": "L1/L2",
            "first_steps": [
                "Check interface counters (errors/discards/flap count) and the transceiver/cable on the affected port",
                "Correlate the link-state syslog timestamp with the interface metric anomaly on the same interface",
                "If the port is an uplink, verify the peer side and fail over to a redundant member if available",
            ],
        },
    },
    # -----------------------------------------------------------------------
    # C5 signatures (2026-06-23) — the classic L2/L3 enterprise/DC fault families
    # the design enumerates (dedicated IGP, STP/loop, FHRP failover, MAC-flap). Each
    # is a Layer-3 DROP-IN: grounding (Layer 1) and the verdict gate are unchanged;
    # the Layer-2 signal `kind`s already arrive from the syslog/trap producers
    # (ospf/isis/stp via syslog_control_signal; fhrp_state_change + mac_flap added in
    # the same change). Single-modality control-plane evidence reaches `suspected`;
    # an independent off-box/SNMP witness lifts each to `confirmed` (verdicts.assess).
    # A coincident link-down deliberately defers the IGP/FHRP cause to local-link-fault
    # (the link drags the session); MAC-flap defers to STP when topology is also churning.
    # -----------------------------------------------------------------------
    {
        "id": "sig.ent.access.ospf-adjacency-flap",
        "title": "OSPF adjacency flap",
        "domain": "ent.access",
        "requires": [
            {"kind": "ospf_adjacency_change", "entity_type": "device"},
            # Independent corroboration: host pressure, route-driven loss, an interface
            # counter anomaly, or a co-incident link event on the adjacency.
            {"kind": "if_metric_anomaly|device_resource_anomaly|probe_loss|link_state_change",
             "optional": True},
            # "What changed?" — a config change on the SAME device inside the window.
            # Optional and single-plane by construction (it is the box talking about
            # itself, like the transition it corroborates), so it can raise coverage
            # but never supply the second modality a confirmation needs.
            # Today it arrives on the TRAP observer only: `syslog.config.change`
            # ships `shadow: true` until the V1 workload profile is versioned
            # (events.yaml), so on a syslog-only estate this clause is inert.
            {"kind": "device_config_change", "optional": True},
        ],
        "required_modalities": ["control_plane"],
        "discriminators": [
            # A flap with a concurrent link-down is a link fault dragging the IGP —
            # prefer the L1/L2 explanation.
            {"absent": {"kind": "link_state_change"}, "within_s": 300,
             "else_prefer": "sig.ent.access.local-link-fault"},
        ],
        "direction_expect": "control-plane -> route -> service",
        "verdict": {
            "owner": "netops", "layer": "L3 (IGP)",
            "first_steps": [
                "Identify the OSPF neighbor and the flap trigger (dead-timer expiry, MTU mismatch, area/auth change, interface bounce)",
                "Check the adjacency interface and the underlay link for the same window",
                "If the neighbor is stuck in EXSTART/EXCHANGE, verify ip mtu on both ends; stabilize the interface if it is flapping",
            ],
        },
    },
    {
        "id": "sig.ent.fabric.isis-adjacency-flap",
        "title": "IS-IS adjacency flap (fabric IGP)",
        "domain": "ent.fabric",
        "requires": [
            {"kind": "isis_adjacency_change", "entity_type": "device"},
            # A vanished LLDP peer / interface counter anomaly / host pressure / link
            # event corroborates a real adjacency loss (LLDP is same-plane, so it
            # supports but does not by itself confirm — that needs a 2nd modality).
            {"kind": "if_metric_anomaly|device_resource_anomaly|lldp_neighbor_change|link_state_change",
             "optional": True},
            # "What changed?" — a config change on the SAME device inside the window.
            # Optional and single-plane by construction (it is the box talking about
            # itself, like the transition it corroborates), so it can raise coverage
            # but never supply the second modality a confirmation needs.
            # Today it arrives on the TRAP observer only: `syslog.config.change`
            # ships `shadow: true` until the V1 workload profile is versioned
            # (events.yaml), so on a syslog-only estate this clause is inert.
            {"kind": "device_config_change", "optional": True},
        ],
        "required_modalities": ["control_plane"],
        "discriminators": [
            {"absent": {"kind": "link_state_change"}, "within_s": 300,
             "else_prefer": "sig.ent.access.local-link-fault"},
        ],
        "direction_expect": "control-plane -> route -> service",
        "verdict": {
            "owner": "netops", "layer": "L2/L3 (IS-IS fabric IGP)",
            "first_steps": [
                "Identify the IS-IS neighbor (system-id) and the level (L1/L2) that dropped, and the trigger (hold-timer expiry, MTU mismatch, level/area mismatch, interface bounce)",
                "Check the adjacency interface and its LLDP neighbor for the same window — a vanished LLDP peer corroborates a real link event",
                "Verify level and area config match on both ends; stabilize the interface if it is flapping",
            ],
        },
    },
    {
        "id": "sig.ent.access.stp-topology-change",
        "title": "STP topology change / L2 loop",
        "domain": "ent.access",
        "requires": [
            {"kind": "stp_topology_change", "entity_type": "interface"},
            # The loop's fingerprint — a broadcast/unknown-unicast storm (interface
            # util/discards) or a co-incident MAC flap — and the independent 2nd
            # modality that lifts a lone topology change to a confirmable loop.
            {"kind": "if_metric_anomaly|if_util_high|mac_flap", "optional": True},
        ],
        "required_modalities": ["control_plane"],
        "discriminators": [
            # A topology change WITH a coincident link transition is normal STP
            # reconvergence after a real link event — prefer the link fault.
            {"absent": {"kind": "link_state_change"}, "within_s": 120,
             "else_prefer": "sig.ent.access.local-link-fault"},
        ],
        "direction_expect": "interface(L2) -> bridge-domain -> service",
        "verdict": {
            "owner": "netops", "layer": "L2 (STP)",
            "first_steps": [
                "Find the port(s) cycling root/designated and whether topology-change notifications recur (a loop, not a one-off reconvergence)",
                "Check for a broadcast/unknown-unicast storm and MAC flapping in the same VLAN/window",
                "Verify BPDU guard / root guard on edge ports; shut the offending loop port and confirm the storm clears",
            ],
        },
    },
    {
        "id": "sig.ent.access.fhrp-failover",
        # tracker 157 — the `role: fhrp_group` clause names a redundancy group, and
        # here the evidence CAN attest it: a device only emits fhrp_state_change if
        # it is a group member. Grounded ⇒ ranks exactly as before.
        "requires_structure": ["redundancy_group"],
        "title": "First-hop redundancy failover (HSRP/VRRP)",
        "domain": "ent.access",
        "requires": [
            {"kind": "fhrp_state_change", "entity_type": "device", "role": "fhrp_group"},
            # The gateway-reachability blip during the election (off-box probe), or the
            # tracked uplink's counter anomaly — the independent witness that confirms
            # real impact and distinguishes an election from a benign config event.
            {"kind": "probe_loss|probe_rtt_anomaly|if_metric_anomaly", "optional": True},
        ],
        "required_modalities": ["control_plane"],
        "discriminators": [
            # A real uplink/cable pull (link down) is a link fault, not an FHRP
            # election — prefer the L1/L2 explanation.
            {"absent": {"kind": "link_state_change"}, "within_s": 120,
             "else_prefer": "sig.ent.access.local-link-fault"},
        ],
        "direction_expect": "device -> gateway -> service",
        "verdict": {
            "owner": "netops", "layer": "L2/L3 (FHRP)",
            "first_steps": [
                "Confirm which member is Active/Master now and why the prior forwarder demoted (priority/preempt, tracked object/interface down, timer expiry)",
                "Check the standby uplink and any tracked interface for a coincident flap in the same window",
                "If failover is flapping, add priority hysteresis / fix the tracked object and verify preempt delay",
            ],
        },
    },
    {
        "id": "sig.ent.access.mac-flap",
        "title": "MAC flapping / move storm",
        "domain": "ent.access",
        "requires": [
            {"kind": "mac_flap", "entity_type": "device"},
            # The L2 instability shows up as an interface counter/util anomaly on the
            # oscillating ports — the independent second modality.
            {"kind": "if_metric_anomaly|if_util_high", "entity_type": "interface", "optional": True},
        ],
        "required_modalities": ["control_plane"],
        "discriminators": [
            # If STP is also churning, the MAC moves are a SYMPTOM of the topology
            # change — prefer the STP signature as the root.
            {"absent": {"kind": "stp_topology_change"}, "within_s": 120,
             "else_prefer": "sig.ent.access.stp-topology-change"},
        ],
        "direction_expect": "interface(L2) -> bridge-domain -> service",
        "verdict": {
            "owner": "netops", "layer": "L2 (MAC)",
            "first_steps": [
                "Identify the flapping MAC, its VLAN, and the two ports it oscillates between",
                "Determine whether it is a physical loop, a dual-homed host / NIC-teaming misconfig, or a duplicate MAC",
                "Shut or isolate one of the two ports; confirm the flap stops and MAC learning stabilizes",
            ],
        },
    },
    # -----------------------------------------------------------------------
    # P3 overlay signatures (2026-06-24, #80) — the TWO emergent DC-overlay causes
    # the fault matrix marks SIG (everything else self-describing rides generic
    # ingestion). Layer-2 kinds emitted by the P2 producer branches: vtep_state_change
    # (NX-OS %NVE BFD), evpn_mac_move (Arista dup-MAC / NX-OS HMM / L2FM VXLAN loop).
    # -----------------------------------------------------------------------
    {
        "id": "sig.ent.fabric.vtep-unreachable",
        "title": "VTEP unreachable (VXLAN underlay → overlay)",
        "domain": "ent.fabric",
        "requires": [
            {"kind": "vtep_state_change", "entity_type": "device"},
            # The emergent angle: an underlay reachability/routing loss to the remote
            # VTEP loopback, or the overlay traffic impact — an independent witness
            # (probe = active_probe, if_metric = device_telemetry) confirms real blackhole.
            {"kind": "bgp_adjacency_change|ospf_adjacency_change|isis_adjacency_change|probe_loss|if_metric_anomaly",
             "optional": True},
        ],
        "required_modalities": ["control_plane"],
        "discriminators": [
            # A local link-down dragging the VTEP is a link fault, not an overlay-
            # reachability fault — prefer the L1/L2 explanation.
            {"absent": {"kind": "link_state_change"}, "within_s": 300,
             "else_prefer": "sig.ent.access.local-link-fault"},
        ],
        "direction_expect": "underlay -> vtep -> overlay-service",
        "verdict": {
            "owner": "netops", "layer": "L3 (VXLAN underlay / VTEP)",
            "first_steps": [
                "Confirm underlay reachability to the remote VTEP loopback (ping/BFD) and which VTEP went unreachable",
                "Check the underlay IGP/BGP to that loopback and the source NVE interface in the same window",
                "If the loopback is reachable but the tunnel is down, check NVE source-interface, VNI-to-VRF mapping, and BFD-for-VXLAN config",
            ],
        },
    },
    {
        "id": "sig.ent.fabric.evpn-l2-loop",
        "title": "EVPN L2 loop / MAC-mobility storm across VTEPs",
        "domain": "ent.fabric",
        "requires": [
            {"kind": "evpn_mac_move", "entity_type": "device"},
            # The loop's fingerprint — a broadcast/util storm or tenant-path loss —
            # and the independent 2nd modality that confirms real overlay impact.
            {"kind": "if_metric_anomaly|if_util_high|probe_loss", "optional": True},
        ],
        "required_modalities": ["control_plane"],
        "direction_expect": "mac-mobility(overlay) -> bridge-domain(VNI) -> tenant-service",
        "verdict": {
            "owner": "netops", "layer": "L2 (EVPN overlay)",
            "first_steps": [
                "Identify the duplicated/blacklisted MAC, its VLAN/VNI, and the two VTEPs (or VTEP+port) it oscillates between",
                "Determine whether it is a dual-homed host / NIC-teaming or ESI multihoming misconfig, a back-door L2 path bridging two VTEPs, or a genuine duplicate MAC",
                "Break the loop (shut the back-door port / fix the ESI or multihoming config); confirm MAC mobility settles and the blacklist clears",
            ],
        },
    },
    # ------------------------------------------------------------------
    # v1 NOC catalog (owner failure-signature spec, 2026-07-02 — see
    # docs/design/research/midnight-noc-questions.md). P0 additions first;
    # entries reuse existing signal kinds wherever an equivalent exists and
    # introduce new kinds only where Layer 2 has no vocabulary yet (those
    # signatures attach as soon as the collectors emit the kind — the catalog
    # deliberately leads ingestion). Every entry carries the voice contract
    # (operator_phrase / manager_phrase) and its seam/deployment taxonomy.
    # De-duplicated against the pre-v1 set: local-link-fault, bgp-peer-flap
    # and dia-egress-latency(+corroborated) already existed and are NOT
    # re-implemented here.
    {
        "id": "sig.ent.access.vlan-trunk-mismatch",
        "title": "VLAN missing/pruned on trunk",
        "domain": "ent.access",
        "seams": ["LAN", "DC_FABRIC"],
        "deployment_scope": "onprem_only",
        "requires": [
            {"kind": "vlan_reachability_fail|arp_fail", "entity_type": "device"},
            {"kind": "mac_table_missing|config_change", "optional": True},
        ],
        "required_modalities": ["control_plane"],
        "discriminators": [
            # A full physical link down explains every VLAN — prefer the link fault.
            {"absent": {"kind": "link_state_change"}, "within_s": 300,
             "else_prefer": "sig.ent.access.local-link-fault"},
        ],
        "direction_expect": "trunk(VLAN) -> bridge-domain -> segment-service",
        "verdict": {
            "owner": "netops", "layer": "L2 (VLAN/trunk)",
            "first_steps": [
                "Compare the intended VLAN inventory against the trunk's allowed VLAN list on both ends",
                "Check ARP/MAC learning for the affected VLAN only — other VLANs on the same trunk should be clean",
                "Diff recent config changes on the trunk path (pruning, allowed-list edits, VTP)",
            ],
        },
        "operator_phrase": "Suspected VLAN/trunk mismatch. Impact is VLAN-specific while the physical path stays up — check trunk allowed lists and recent config diffs.",
        "manager_phrase": "Only a subset of network segments appears affected, suggesting a configuration or trunking issue rather than a full site outage.",
        "blast_radius": "one VLAN / segment on the shared trunk path",
        "false_positives": ["unused VLAN", "stale inventory", "endpoints moved", "STP blocking intentionally"],
        "composition_hints": ["access-segment incident when combined with STP churn on the same path"],
    },
    {
        "id": "sig.ent.access.dhcp-scope-exhaustion",
        "title": "DHCP pool exhausted or DHCP path failure",
        "domain": "ent.access",
        "seams": ["LAN"],
        "deployment_scope": "onprem_only",
        "requires": [
            {"kind": "dhcp_fail|dhcp_scope_util_high", "entity_type": "device"},
            {"kind": "client_onboarding_fail", "optional": True},
            {"kind": "dhcp_relay_fail", "optional": True},
        ],
        "required_modalities": ["control_plane"],
        "discriminators": [
            # Broad L3 loss (static clients failing too) is a path fault, not DHCP.
            {"absent": {"kind": "probe_loss"}, "within_s": 300,
             "else_prefer": "sig.ent.access.local-link-fault"},
        ],
        "direction_expect": "dhcp-service -> new-clients -> segment",
        "verdict": {
            "owner": "netops", "layer": "L2/L3 (DHCP)",
            "first_steps": [
                "Check DHCP scope utilization and lease table for the affected segment",
                "Verify relay / ip helper configuration on the first-hop gateway",
                "Compare new-client onboarding failures against existing-client health (exhaustion hits new clients first)",
            ],
        },
        "operator_phrase": "Likely DHCP exhaustion or DHCP path issue — new clients fail to onboard while existing leases keep working.",
        "manager_phrase": "The issue appears to affect new device connectivity more than existing sessions.",
        "blast_radius": "new clients on the affected segment/site",
        "false_positives": ["client supplicant issues", "NAC denial", "wireless authentication failure"],
    },
    {
        "id": "sig.ent.access.dns-local-resolver-failure",
        "title": "Local DNS resolver failure",
        "domain": "ent.access",
        "seams": ["LAN", "CLOUD_APP"],
        "deployment_scope": "hybrid",
        "requires": [
            {"kind": "dns_failure_rate|dns_latency_high", "entity_type": "device"},
            {"kind": "synthetic_http_fail|fqdn_probe_fail"},
            {"kind": "device_resource_anomaly", "optional": True},
        ],
        "required_modalities": ["active_probe"],
        "discriminators": [
            # If raw IP paths are ALSO losing packets, this is a path fault, not DNS.
            {"absent": {"kind": "probe_loss"}, "within_s": 300,
             "else_prefer": "sig.ent.internet.dns-impairment"},
        ],
        "direction_expect": "resolver -> name-resolution -> app-access",
        "verdict": {
            "owner": "netops", "layer": "L7 (DNS)",
            "first_steps": [
                "Compare FQDN probes against IP probes to the same targets — DNS-only failure means IP paths stay clean",
                "Check resolver health (CPU/memory, cache, forwarders) and SERVFAIL/NXDOMAIN rates",
                "Diff recent DNS configuration changes and confirm which client population shares the failing resolver",
            ],
        },
        "operator_phrase": "Application reachability appears DNS-related, not pure network loss — FQDN probes fail while IP paths stay comparatively clean.",
        "manager_phrase": "The application may be reachable, but name resolution is preventing users from connecting normally.",
        "blast_radius": "clients sharing the failing resolver",
        "false_positives": ["application endpoint removed", "CDN change", "split-horizon DNS expectation", "expired DNS record"],
        "composition_hints": ["DNS incident when FQDN probes fail and IP probes pass across sites"],
    },
    {
        "id": "sig.ent.wan-edge.sdwan-tunnel-degraded",
        "title": "SD-WAN tunnel loss/jitter/latency",
        "domain": "ent.wan-edge",
        "seams": ["WAN_SDWAN"],
        "deployment_scope": "hybrid",
        "requires": [
            {"kind": "tunnel_degraded|tunnel_flap", "entity_type": "path"},
            {"kind": "probe_loss|probe_rtt_anomaly"},
            {"kind": "path_change|if_errors|if_util_high", "optional": True},
            # NMS corroboration: the SD-WAN controller's own tunnel/BFD state, when
            # present, adds a management-plane witness (via_controller authority) —
            # optional so telemetry-only detection is unchanged.
            {"kind": "controller_tunnel_state|controller_bfd_down", "entity_type": "path", "optional": True},
        ],
        "required_modalities": ["active_probe", "control_plane"],
        "discriminators": [
            # Tunnel fully down is the MTU-blackhole / hard-down family.
            {"absent": {"kind": "tunnel_down"}, "within_s": 300,
             "else_prefer": "sig.ent.wan-edge.tunnel-mtu-blackhole"},
            # Large-transfer/HTTP failures with a degraded tunnel are the MTU
            # signature's fingerprint (small probes pass, big frames die).
            {"absent": {"kind": "synthetic_http_fail|app_large_transfer_fail"}, "within_s": 300,
             "else_prefer": "sig.ent.wan-edge.tunnel-mtu-blackhole"},
        ],
        "direction_expect": "underlay -> overlay-tunnel -> branch-service",
        "verdict": {
            "owner": "sdwan_vendor", "layer": "L3/L4 (SD-WAN overlay)",
            "first_steps": [
                "Check underlay circuit loss/latency for the same window — overlay SLA symptoms usually follow the underlay",
                "Review SD-WAN SLA class state and any path-steering events for the affected branch",
                "Diff recent SD-WAN policy commits before blaming the carrier",
            ],
        },
        "operator_phrase": "Likely SD-WAN path degradation — overlay SLA symptoms align with underlay loss/latency on the same path.",
        "manager_phrase": "Branch traffic appears degraded because the WAN path is unstable or has shifted to a lower-quality path.",
        "blast_radius": "branches riding the degraded tunnel/path",
        "false_positives": ["application-side slowness", "backup circuit intentionally preferred", "scheduled carrier maintenance"],
        "composition_hints": ["WAN/ISP egress incident with DIA latency + SaaS slowness on the same egress"],
    },
    {
        "id": "sig.ent.middle-mile.private-interconnect-bgp-down",
        "title": "Private cloud interconnect BGP down",
        "domain": "ent.middle-mile",
        "seams": ["CARRIER_INTERCONNECT", "CLOUD_APP"],
        "deployment_scope": "hybrid",
        "requires": [
            {"kind": "bgp_adjacency_change|bgp_state_anomaly", "entity_type": "device"},
            {"kind": "probe_loss|route_count_drop"},
            {"kind": "cloud_health|cloud_change", "optional": True},
            {"kind": "tunnel_flap", "optional": True},
        ],
        "required_modalities": ["control_plane", "active_probe"],
        "discriminators": [
            # If the session is fine and only prefixes are missing, prefer the
            # missing-prefix family (BGP up, partial reachability).
            {"absent": {"kind": "route_prefix_missing"}, "within_s": 300,
             "else_prefer": "sig.ent.middle-mile.private-interconnect-missing-prefix"},
        ],
        "direction_expect": "interconnect(control-plane) -> cloud-private-prefixes -> hybrid-service",
        "verdict": {
            "owner": "carrier", "layer": "L3 (private interconnect)",
            "first_steps": [
                "Validate BGP state on BOTH the on-prem edge and the cloud side (attachment/VIF/peering state)",
                "Check the provider circuit and VLAN attachment state plus any provider maintenance events",
                "Confirm whether a backup VPN path activated and what it is carrying",
            ],
        },
        "operator_phrase": "Likely private cloud interconnect control-plane issue — BGP/session evidence aligns with cloud private-prefix reachability loss.",
        "manager_phrase": "The private connection to the cloud appears impaired, which may affect services that depend on private cloud connectivity.",
        "blast_radius": "services on cloud private prefixes behind the interconnect",
        "false_positives": ["cloud route table issue while BGP is up", "planned maintenance", "monitoring peer mismatch"],
        "composition_hints": ["private interconnect incident with BGP flap + missing prefixes + private-probe failures"],
    },
    {
        "id": "sig.ent.middle-mile.private-interconnect-missing-prefix",
        "title": "Private interconnect missing cloud prefix",
        "domain": "ent.middle-mile",
        "seams": ["CARRIER_INTERCONNECT", "CLOUD_APP"],
        "deployment_scope": "hybrid",
        "requires": [
            {"kind": "route_prefix_missing|route_count_drop", "entity_type": "device"},
            {"kind": "probe_loss", "entity_type": "path"},
            {"kind": "cloud_change|cloud_audit", "optional": True},
            {"kind": "route_advertisement_change", "optional": True},
        ],
        "required_modalities": ["control_plane", "active_probe"],
        "discriminators": [
            # Session actually down → the bgp-down family owns it.
            {"absent": {"kind": "bgp_adjacency_change|bgp_state_anomaly"}, "within_s": 300,
             "else_prefer": "sig.ent.middle-mile.private-interconnect-bgp-down"},
        ],
        "direction_expect": "route-exchange -> affected-prefix -> cloud-subnet-service",
        "verdict": {
            "owner": "netops", "layer": "L3 (route exchange)",
            "first_steps": [
                "Compare on-prem advertised/received routes with the cloud route tables and interconnect peer routes",
                "Confirm unaffected prefixes remain reachable (partial reachability is the tell)",
                "Check cloud-side route propagation and any custom route-advertisement change in the window",
            ],
        },
        "operator_phrase": "BGP is up, but routing evidence suggests the affected cloud prefix is missing or not being advertised/installed — compare advertised and received routes on both edges.",
        "manager_phrase": "The private cloud connection is not fully down. Impact appears limited to specific cloud networks because routing information is missing or incomplete.",
        "blast_radius": "specific cloud subnets/VPCs behind the missing prefix",
        "false_positives": ["security group/NACL block", "subnet decommissioned", "overlapping route preference", "stale inventory"],
    },
    {
        "id": "sig.ent.fabric.evpn-route-missing",
        "title": "EVPN/VXLAN route missing (control-plane gap)",
        "domain": "ent.fabric",
        "seams": ["DC_FABRIC"],
        "deployment_scope": "onprem_only",
        "requires": [
            {"kind": "evpn_route_missing|vni_reachability_fail", "entity_type": "device"},
            {"kind": "bgp_adjacency_change|evpn_mac_move", "optional": True},
            {"kind": "arp_fail", "optional": True},
        ],
        "required_modalities": ["control_plane"],
        "discriminators": [
            # VTEP itself unreachable is the underlay family.
            {"absent": {"kind": "vtep_state_change"}, "within_s": 300,
             "else_prefer": "sig.ent.fabric.vtep-unreachable"},
        ],
        "direction_expect": "evpn-control-plane -> VNI/VRF -> tenant-east-west",
        "verdict": {
            "owner": "netops", "layer": "L2/L3 (EVPN overlay)",
            "first_steps": [
                "Check EVPN MAC/IP (Type-2) and prefix (Type-5) route presence for the affected VNI/VRF",
                "Verify VTEP reachability and BGP EVPN peer state — underlay clean means control-plane gap",
                "Review ARP-suppression and VNI mapping consistency on the affected leaves",
            ],
        },
        "operator_phrase": "Suspected EVPN/VXLAN control-plane gap for the affected VNI/VRF — routes missing while the underlay stays clean.",
        "manager_phrase": "The issue appears isolated to a specific data center network segment rather than the entire fabric.",
        "blast_radius": "one tenant/VRF/VNI's east-west traffic",
        "false_positives": ["tenant decommission", "stale VNI", "intended route filtering", "endpoint mobility"],
    },
    {
        "id": "sig.ent.fabric.spine-leaf-path-degradation",
        # tracker 157 — THE measured defect. Both required clauses are generic
        # (interface errors + a path probe), so ANY topology emitting them
        # satisfies this signature: with 130 leaves taking purely local port
        # faults and NO spine device in the scenario it still ranked top, and on
        # the live corpus (30 h to 2026-08-30) it was top hypothesis on 9,890
        # objects of which 6,338 implicate exactly ONE device.
        #
        # A fabric path is not a local port. It is a MULTI-PATH bundle (the
        # leaf's uplink member set toward the spines) carrying a leg BETWEEN
        # racks, and the evidence can attest both: ecmp_member_loss /
        # lacp_* / lag_* for the member set, an `a->b` path entity for the leg.
        # A device-local port fault attests neither, which is exactly the
        # difference the old clauses could not see.
        #
        # This is NOT proof that a spine TIER exists — no evidence attests a
        # tier (catalog.StructureClass) — and the residue is declared, not
        # pretended away. It IS the structure the claim rests on, and it is
        # satisfied by the family's own authored fixture
        # (fixtures/spine-leaf-path-degradation-confirmed.json: ecmp_member_loss
        # on leaf1 + the rack1->rack4 path) while the measured defect fails it.
        "requires_structure": ["redundancy_group", "transit_path"],
        "title": "Leaf/spine fabric path degradation",
        "domain": "ent.fabric",
        "seams": ["DC_FABRIC"],
        "deployment_scope": "onprem_only",
        "requires": [
            {"kind": "if_errors|if_crc|link_state_change", "entity_type": "interface"},
            # Rack-to-rack PATH probes — segment/WAN probes belong to the
            # middle-mile physical-degradation family, not the fabric.
            {"kind": "probe_loss|probe_rtt_anomaly", "entity_type": "path"},
            {"kind": "ecmp_member_loss|lldp_neighbor_change", "optional": True},
            {"kind": "bgp_adjacency_change|ospf_adjacency_change|isis_adjacency_change", "optional": True},
        ],
        "required_modalities": ["device_telemetry", "active_probe"],
        "direction_expect": "fabric-link -> leaf/spine-path -> multi-rack-services",
        "verdict": {
            "owner": "netops", "layer": "L1-L3 (fabric path)",
            "first_steps": [
                "Identify the degraded fabric link/ECMP member and confirm rack-to-rack probe loss follows the leaf/spine topology",
                "Check optics/error counters with a fresh baseline on the suspect links",
                "Verify routing adjacency stability across the affected path before draining the member",
            ],
        },
        "operator_phrase": "Likely data center fabric path degradation — impact follows leaf/spine topology, not a single application.",
        "manager_phrase": "A data center network path appears degraded, potentially affecting multiple services that share that fabric path.",
        "blast_radius": "multiple racks/services sharing the degraded fabric path",
        "false_positives": ["single server NIC issue", "app cluster imbalance", "storage latency"],
    },
    {
        "id": "sig.ent.security.fw-ha-failover-drift",
        # tracker 157 — a firewall HA PAIR. Attested by the fw_ha_* / fw_sync_fail
        # kinds the required clause already names.
        "requires_structure": ["redundancy_group"],
        "title": "Firewall HA failover or policy/session drift",
        "domain": "ent.security",
        "seams": ["LAN", "DC_FABRIC", "WAN_SDWAN", "CLOUD_APP"],
        "deployment_scope": "hybrid",
        "requires": [
            {"kind": "fw_ha_state_change|fw_sync_fail", "entity_type": "device"},
            {"kind": "fw_session_drop|probe_loss|synthetic_http_fail"},
            {"kind": "fw_policy_mismatch|nat_translation_change", "optional": True},
            {"kind": "flow_asymmetry", "optional": True},
        ],
        "required_modalities": ["control_plane"],
        "discriminators": [
            # Pure routing failure explains impact without the firewall.
            {"absent": {"kind": "bgp_adjacency_change"}, "within_s": 300,
             "else_prefer": "sig.ent.wan-edge.routing-instability"},
        ],
        "direction_expect": "fw-ha-pair -> stateful-sessions -> transiting-services",
        "verdict": {
            "owner": "netops", "layer": "L4 (firewall state)",
            "first_steps": [
                "Check HA role state and config/session sync between the pair",
                "Compare NAT translation tables and policy hit logs before vs after the failover",
                "Look for asymmetric flows — state mismatch after failover drops one direction first",
            ],
        },
        "operator_phrase": "Suspected firewall HA/state issue — traffic impact aligns with a failover or policy/session divergence between the pair.",
        "manager_phrase": "Traffic disruption appears related to firewall high-availability behavior or policy/session state after a failover or change.",
        "blast_radius": "sessions transiting the firewall pair",
        "false_positives": ["expected failover during maintenance", "app deploy", "route reconvergence", "stale firewall logs"],
        "composition_hints": ["firewall state/NAT incident with asymmetric flows + NAT change"],
    },
    {
        "id": "sig.ent.security.nat-snat-exhaustion",
        "title": "NAT/SNAT exhaustion",
        "domain": "ent.security",
        "seams": ["WAN_SDWAN", "CLOUD_APP", "DC_FABRIC"],
        "deployment_scope": "hybrid",
        "requires": [
            {"kind": "nat_alloc_fail|nat_table_high", "entity_type": "device"},
            {"kind": "synthetic_http_fail|app_conn_fail"},
            {"kind": "if_util_high|flow_drop_at_nat", "optional": True},
        ],
        "required_modalities": ["device_telemetry"],
        "discriminators": [
            # A full interface/path outage is not an exhaustion pattern.
            {"absent": {"kind": "link_state_change|tunnel_down"}, "within_s": 300,
             "else_prefer": "sig.ent.access.local-link-fault"},
        ],
        "direction_expect": "nat-boundary -> outbound-connections -> external-dependencies",
        "verdict": {
            "owner": "netops", "layer": "L4 (NAT/translation)",
            "first_steps": [
                "Check NAT/SNAT utilization and port-allocation failure counters",
                "Identify top talkers and destination concentration consuming the pool",
                "Confirm failures are connection-level (retries sometimes succeed) rather than full path-down",
            ],
        },
        "operator_phrase": "Likely NAT capacity/translation exhaustion — failures are connection-level and intermittent, not full path-down.",
        "manager_phrase": "Outbound connectivity appears constrained by translation capacity, causing intermittent failures rather than a full outage.",
        "blast_radius": "outbound connections through the exhausted NAT boundary",
        "false_positives": ["destination-side rate limiting", "proxy issue", "DNS failure", "firewall deny policy"],
    },
    {
        "id": "sig.ent.app.lb-target-health-failure",
        "title": "Load balancer targets unhealthy",
        "domain": "ent.app",
        "seams": ["CLOUD_APP", "DC_FABRIC"],
        "deployment_scope": "hybrid",
        "requires": [
            {"kind": "lb_target_unhealthy|lb_5xx", "entity_type": "service"},
            {"kind": "synthetic_http_fail|app_error_rate_high"},
            {"kind": "config_change|deploy_event", "optional": True},
            {"kind": "app_latency_high", "optional": True},
        ],
        "required_modalities": ["device_telemetry", "active_probe"],
        "discriminators": [
            # If the VIP itself is unreachable at L3, it is a path problem.
            {"absent": {"kind": "probe_loss"}, "within_s": 300,
             "else_prefer": "sig.ent.wan-edge.congestion"},
        ],
        "direction_expect": "lb-front-door -> target-pool -> application",
        "verdict": {
            "owner": "app_team", "layer": "L7 (LB/backend health)",
            "first_steps": [
                "Check target-group health and the health-check path/port the LB is probing",
                "Correlate with recent deployments or scaling events on the backend pool",
                "Verify security policy is not blocking the health-check source",
            ],
        },
        "operator_phrase": "Load balancer is reachable, but backend target health is degraded — the front door is up with an unhealthy pool behind it.",
        "manager_phrase": "The front door of the service is reachable, but the systems behind it are not healthy enough to serve traffic reliably.",
        "blast_radius": "the service behind the affected VIP/target pool",
        "false_positives": ["health-check path misconfigured", "intentional scale-in", "maintenance", "WAF blocking before target"],
        "composition_hints": ["app/backend readiness incident with empty Kubernetes endpoints"],
    },
    {
        "id": "sig.ent.app.dns-failover-wrong-target",
        "title": "DNS failover wrong target or stale record",
        "domain": "ent.app",
        "seams": ["CLOUD_APP"],
        "deployment_scope": "hybrid",
        "requires": [
            {"kind": "dns_answer_mismatch|dns_failover_event", "entity_type": "service"},
            {"kind": "synthetic_http_fail|app_error_rate_high"},
            {"kind": "config_change", "optional": True},
        ],
        "required_modalities": ["active_probe"],
        "discriminators": [
            # Resolver itself failing is the resolver family, not a wrong answer.
            {"absent": {"kind": "dns_failure_rate|dns_latency_high"}, "within_s": 300,
             "else_prefer": "sig.ent.access.dns-local-resolver-failure"},
        ],
        "direction_expect": "dns-answer -> endpoint-selection -> user-population",
        "verdict": {
            "owner": "app_team", "layer": "L7 (DNS steering)",
            "first_steps": [
                "Compare DNS answers across resolvers/regions against the intended healthy endpoint",
                "Check DNS health-check state, TTLs and any recent record change",
                "Identify whether impact follows a resolver/region/record boundary",
            ],
        },
        "operator_phrase": "Suspected DNS failover or stale record issue — resolution differs from the expected healthy endpoint for part of the user population.",
        "manager_phrase": "Some users may be sent to the wrong or unhealthy service endpoint due to DNS or failover behavior.",
        "blast_radius": "users behind the resolvers/regions receiving the wrong answer",
        "false_positives": ["client DNS cache", "ISP resolver cache", "expected geo-routing", "CDN steering"],
    },
    # ---- v1 P1 additions in the recommended initial ENABLED set ----------
    {
        "id": "sig.ent.cloud.sg-nacl-block",
        "title": "Security group/NACL blocks traffic",
        "domain": "ent.cloud",
        "seams": ["CLOUD_APP"],
        "deployment_scope": "hybrid",
        "demo_priority": "p1",
        "requires": [
            {"kind": "cloud_flow_reject|policy_diff_block", "entity_type": "service"},
            {"kind": "synthetic_http_fail|probe_loss"},
            {"kind": "cloud_change|cloud_audit|config_change", "optional": True},
        ],
        "required_modalities": ["passive_flow", "active_probe"],
        "discriminators": [
            {"absent": {"kind": "lb_target_unhealthy"}, "within_s": 300,
             "else_prefer": "sig.ent.app.lb-target-health-failure"},
        ],
        "direction_expect": "security-policy -> denied-flow -> app-path",
        "verdict": {
            "owner": "netops", "layer": "L3/L4 (cloud security policy)",
            "first_steps": [
                "Check flow logs for REJECT records on the exact failing 5-tuple",
                "Diff SG/NACL/firewall policy changes in the incident window",
                "Confirm the required ports/sources against the intended security design",
            ],
        },
        "operator_phrase": "Suspected cloud security policy block — flow or policy evidence indicates traffic is denied before reaching the service.",
        "manager_phrase": "A cloud network security rule may be blocking the affected application path.",
        "blast_radius": "the specific source/destination/port paths the rule denies",
        "false_positives": ["host firewall", "app not listening", "route table issue"],
    },
    {
        "id": "sig.ent.cloud.route-table-blackhole",
        "title": "Cloud route table blackhole",
        "domain": "ent.cloud",
        "seams": ["CLOUD_APP", "CARRIER_INTERCONNECT"],
        "deployment_scope": "hybrid",
        "demo_priority": "p1",
        "requires": [
            {"kind": "route_table_blackhole|route_missing_nexthop", "entity_type": "service"},
            {"kind": "probe_loss|cloud_flow_log"},
            {"kind": "cloud_change|route_advertisement_change", "optional": True},
        ],
        "required_modalities": ["control_plane", "active_probe"],
        "discriminators": [
            {"absent": {"kind": "cloud_flow_reject"}, "within_s": 300,
             "else_prefer": "sig.ent.cloud.sg-nacl-block"},
        ],
        "direction_expect": "route-domain -> affected-subnet -> workloads",
        "verdict": {
            "owner": "netops", "layer": "L3 (cloud routing)",
            "first_steps": [
                "Compare the affected subnet's route table (next hops, propagation) against a healthy one",
                "Check TGW/VNet attachment routes and recent route changes",
                "Run the cloud reachability/connectivity test on the failing path",
            ],
        },
        "operator_phrase": "Likely cloud route table issue — impact follows a specific subnet or route domain while others stay reachable.",
        "manager_phrase": "A cloud routing change or missing route appears to be isolating part of the environment.",
        "blast_radius": "one subnet/AZ/VPC route domain",
        "false_positives": ["security group block", "service endpoint policy", "private DNS issue"],
    },
    {
        "id": "sig.ent.cloud.k8s-service-endpoint-empty",
        "title": "Kubernetes Service has no healthy endpoints",
        "domain": "ent.cloud",
        "seams": ["CLOUD_APP", "DC_FABRIC"],
        "deployment_scope": "hybrid",
        "demo_priority": "p1",
        "requires": [
            {"kind": "k8s_endpoints_empty|k8s_pod_not_ready", "entity_type": "service"},
            {"kind": "synthetic_http_fail|lb_5xx"},
            {"kind": "deploy_event|k8s_event", "optional": True},
        ],
        "required_modalities": ["control_plane", "active_probe"],
        "discriminators": [
            {"absent": {"kind": "dns_failure_rate"}, "within_s": 300,
             "else_prefer": "sig.ent.access.dns-local-resolver-failure"},
        ],
        "direction_expect": "k8s-service -> pod-readiness -> app-path",
        "verdict": {
            "owner": "app_team", "layer": "L7 (Kubernetes readiness)",
            "first_steps": [
                "Check the Service's endpoint list and pod readiness in the affected namespace",
                "Correlate with the rollout/deploy timeline (image pull, crash loops, scale-to-zero)",
                "Verify the ingress path still selects the right Service and port",
            ],
        },
        "operator_phrase": "Kubernetes service has no healthy endpoints — the network front door is up, but no ready backend pods are available.",
        "manager_phrase": "The application routing layer is reachable, but the application instances behind it are not ready to serve traffic.",
        "blast_radius": "the workloads behind the affected Service/ingress",
        "false_positives": ["intentional scale-down", "wrong namespace", "stale service selector"],
        "composition_hints": ["app/backend readiness incident with LB target health failure"],
    },
    {
        "id": "sig.ent.security.waf-rule-false-positive",
        "title": "WAF blocks legitimate app traffic",
        "domain": "ent.security",
        "seams": ["CLOUD_APP"],
        "deployment_scope": "hybrid",
        "demo_priority": "p1",
        "requires": [
            {"kind": "waf_block_spike|waf_rule_match", "entity_type": "service"},
            {"kind": "app_error_rate_high|synthetic_http_fail"},
            {"kind": "config_change", "optional": True},
        ],
        "required_modalities": ["control_plane", "active_probe"],
        "discriminators": [
            {"absent": {"kind": "lb_target_unhealthy"}, "within_s": 300,
             "else_prefer": "sig.ent.app.lb-target-health-failure"},
        ],
        "direction_expect": "waf-rule -> blocked-requests -> user-population",
        "verdict": {
            "owner": "app_team", "layer": "L7 (WAF)",
            "first_steps": [
                "Review WAF rule matches for the affected URI/method/user-agent/source pattern",
                "Correlate the block spike with recent WAF rule updates",
                "Confirm the backend never received the blocked requests (403 at the edge, silence behind it)",
            ],
        },
        "operator_phrase": "Suspected WAF false positive — WAF logs show legitimate requests matching a blocking rule after a rule update.",
        "manager_phrase": "Some valid user requests may be blocked by an application security rule.",
        "blast_radius": "requests matching the offending rule (URI/source/user-agent subset)",
        "false_positives": ["real attack traffic", "expired auth token", "backend authorization failure"],
    },
    {
        "id": "sig.ent.app.tls-cert-expired",
        "title": "TLS certificate expired, mismatch, or SNI issue",
        "domain": "ent.app",
        "seams": ["CLOUD_APP"],
        "deployment_scope": "hybrid",
        "demo_priority": "p1",
        "requires": [
            {"kind": "tls_handshake_fail|cert_expired", "entity_type": "service"},
            {"kind": "synthetic_http_fail"},
            {"kind": "config_change|cert_expiry_warning", "optional": True},
        ],
        "required_modalities": ["active_probe"],
        "discriminators": [
            # If plain reachability is also failing, it is a path fault, not TLS.
            {"absent": {"kind": "probe_loss"}, "within_s": 300,
             "else_prefer": "sig.ent.wan-edge.congestion"},
        ],
        "direction_expect": "tls-handshake -> secure-session -> users",
        "verdict": {
            "owner": "app_team", "layer": "L6 (TLS)",
            "first_steps": [
                "Check certificate expiry, SAN/CN and chain on the failing endpoint",
                "Verify the LB listener certificate and SNI behavior after any recent rotation",
                "Confirm only HTTPS is affected while the underlying path stays clean",
            ],
        },
        "operator_phrase": "Likely TLS certificate or SNI mismatch — HTTPS negotiation fails before the application can respond, while the path itself is clean.",
        "manager_phrase": "Users may be blocked because the secure connection or certificate validation is failing.",
        "blast_radius": "HTTPS clients of the affected endpoint",
        "false_positives": ["client trust store issue", "middlebox TLS inspection", "DNS wrong target"],
    },
    # ------------------------------------------------------------------
    # Wave 2 v0 (owner spec batch 2 — failure-signature-catalog-wave2.md).
    # Every entry passes the non-overlap contract: distinct fault domain,
    # first discriminator, blast radius, contradiction set and operator
    # action vs its nearest reserved neighbor (discriminators encode the
    # owner's disambiguation table). stp.tcn-storm deduped → the existing
    # sig.ent.access.stp-topology-change already owns that family.
    {
        "id": "sig.ent.access.dupip-arp-flux",
        "title": "Duplicate IP / ARP ownership flip",
        "domain": "ent.access",
        "seams": ["LAN"],
        "deployment_scope": "onprem_only",
        "requires": [
            {"kind": "arp_ownership_flip|duplicate_ip_detected", "entity_type": "device"},
            {"kind": "mac_flap|arp_fail", "optional": True},
        ],
        "required_modalities": ["control_plane"],
        "discriminators": [
            # Link stays UP for this family — a down link is the link fault.
            {"absent": {"kind": "link_state_change"}, "within_s": 300,
             "else_prefer": "sig.ent.access.local-link-fault"},
        ],
        "direction_expect": "arp-ownership -> subnet-hosts -> gateway",
        "verdict": {
            "owner": "netops", "layer": "L2/L3 (ARP)",
            "first_steps": [
                "Compare ARP/MAC over time and identify the alternating owner of the IP",
                "Check for duplicate-IP syslog and gratuitous ARP from two sources",
                "Isolate one claimant and confirm the flapping stops",
            ],
        },
        "operator_phrase": "Suspected duplicate-IP / ARP ownership conflict on the affected subnet — the same IP maps to changing MACs while links stay up.",
        "manager_phrase": "Impact is localized to one subnet because two devices appear to claim the same address.",
        "blast_radius": "one subnet's hosts/gateway",
        "false_positives": ["VRRP/HSRP virtual MAC behavior", "load balancer shared IP", "recent host re-addressing"],
    },
    {
        "id": "sig.ent.access.portsecurity-errdisable",
        "title": "Port-security / BPDU-guard / UDLD shutdown",
        "domain": "ent.access",
        "seams": ["LAN"],
        "deployment_scope": "onprem_only",
        "requires": [
            {"kind": "errdisable_event", "entity_type": "interface"},
            {"kind": "lldp_neighbor_change|link_state_change", "optional": True},
        ],
        "required_modalities": ["control_plane"],
        "direction_expect": "protection-feature -> disabled-port -> attached-endpoints",
        "verdict": {
            "owner": "netops", "layer": "L2 (port protection)",
            "first_steps": [
                "Read the errdisable cause (BPDU guard, port-security violation, UDLD, storm-control)",
                "Check what triggered it — a loop, a rogue device, or a policy change",
                "Clear/recover the port only after the cause is addressed",
            ],
        },
        "operator_phrase": "Port is error-disabled by a local protection feature, not just physically down — read the errdisable cause before recovering it.",
        "manager_phrase": "A local protection control intentionally shut down the port to prevent a loop or policy breach.",
        "blast_radius": "the single port and its attached device/users",
        "false_positives": ["maintenance", "intentional shutdown", "duplicate monitoring alarms"],
    },
    {
        "id": "sig.ent.access.fhrp-split-brain",
        # tracker 157 — an FHRP group by definition. Attested by fhrp_dual_active /
        # fhrp_state_change, so grounded evidence ranks unchanged.
        "requires_structure": ["redundancy_group"],
        "title": "HSRP/VRRP active-active split-brain",
        "domain": "ent.access",
        "seams": ["LAN", "DC_FABRIC"],
        "deployment_scope": "onprem_only",
        "requires": [
            {"kind": "fhrp_dual_active", "entity_type": "device"},
            {"kind": "fhrp_state_change|arp_fail", "optional": True},
            {"kind": "probe_loss", "optional": True},
        ],
        "required_modalities": ["control_plane"],
        "discriminators": [
            # A clean single failover is the (existing) fhrp-failover family.
            {"absent": {"kind": "link_state_change"}, "within_s": 300,
             "else_prefer": "sig.ent.access.fhrp-failover"},
        ],
        "direction_expect": "gateway-pair -> partitioned-subnet -> hosts",
        "verdict": {
            "owner": "netops", "layer": "L2/L3 (FHRP)",
            "first_steps": [
                "Verify FHRP state on BOTH peers — two actives for one VIP is the tell",
                "Check the inter-switch/peer path that should carry FHRP hellos",
                "Restore hello reachability, then confirm a single active remains",
            ],
        },
        "operator_phrase": "Suspected FHRP split-brain — more than one gateway appears active for the same segment, partitioning the subnet.",
        "manager_phrase": "Redundant gateways are not agreeing on which device should forward for the subnet.",
        "blast_radius": "the subnet behind the split gateway pair (partitioned, not down)",
        "false_positives": ["expected dual-active designs", "monitoring seeing both contexts", "maintenance failback"],
    },
    {
        "id": "sig.ent.wan-edge.sdwan-control-connection-loss",
        "title": "SD-WAN controller/control-connection loss",
        "domain": "ent.wan-edge",
        "seams": ["WAN_SDWAN"],
        "deployment_scope": "hybrid",
        "requires": [
            {"kind": "sdwan_control_down", "entity_type": "device"},
            {"kind": "tunnel_flap|path_change", "optional": True},
            {"kind": "cert_expiry_warning", "optional": True},
            # NMS corroboration: the controller's own control-connection/OMP loss
            # (management-plane witness), optional so existing detection is unchanged.
            {"kind": "controller_control_connection_loss", "entity_type": "device", "optional": True},
        ],
        "required_modalities": ["control_plane"],
        "discriminators": [
            # Data-path SLA breach without control loss is the tunnel family.
            {"absent": {"kind": "tunnel_degraded"}, "within_s": 300,
             "else_prefer": "sig.ent.wan-edge.sdwan-tunnel-degraded"},
        ],
        "direction_expect": "controller -> control-connections -> edge-policy/steering",
        "verdict": {
            "owner": "sdwan_vendor", "layer": "control-plane (SD-WAN)",
            "first_steps": [
                "Check controller/orchestrator reachability from the affected edges",
                "Verify certificates and clock state (the classic control-connection killers)",
                "Confirm which data tunnels still forward — control loss does not mean data down",
            ],
        },
        "operator_phrase": "Control-plane connectivity to SD-WAN management has failed — data paths may not all be down, but steering and policy are stale.",
        "manager_phrase": "WAN orchestration visibility and control is impaired, which can destabilize path steering and failover.",
        "blast_radius": "policy/steering for edges that lost the controller",
        "false_positives": ["controller maintenance", "certificate rotation window", "management-plane-only outage"],
    },
    {
        "id": "sig.ent.wan-edge.ipsec-rekey-mismatch",
        "title": "IPsec/IKE rekey or crypto proposal mismatch",
        "domain": "ent.wan-edge",
        "seams": ["WAN_SDWAN", "CARRIER_INTERCONNECT"],
        "deployment_scope": "hybrid",
        "requires": [
            {"kind": "ipsec_negotiation_fail|ipsec_sa_rekey_fail", "entity_type": "device"},
            {"kind": "tunnel_flap|tunnel_down", "optional": True},
            {"kind": "probe_loss", "optional": True},
        ],
        "required_modalities": ["control_plane"],
        "discriminators": [
            # Routing adjacency churn (not IKE) is the BGP family.
            {"absent": {"kind": "bgp_adjacency_change|bgp_state_anomaly"}, "within_s": 300,
             "else_prefer": "sig.ent.wan-edge.bgp-peer-flap"},
        ],
        "direction_expect": "ike-negotiation -> encrypted-overlay -> site-traffic",
        "verdict": {
            "owner": "netops", "layer": "L3 (IPsec/IKE)",
            "first_steps": [
                "Compare phase-1/2 proposals, lifetimes and identities on both peers",
                "Check whether drops align with rekey timers (SA tear/rebuild pattern)",
                "Verify NAT-T behavior if a middlebox sits on the path",
            ],
        },
        "operator_phrase": "Likely IPsec/IKE negotiation problem around rekey or proposal mismatch — encrypted overlay fails at negotiation, not routing.",
        "manager_phrase": "Encrypted connectivity is failing because the tunnel peers are not successfully renegotiating.",
        "blast_radius": "traffic on the affected encrypted tunnels",
        "false_positives": ["planned crypto policy rollout", "peer maintenance", "one-off packet loss during rekey"],
    },
    {
        "id": "sig.ent.middle-mile.lastmile-circuit-flap",
        "title": "Last-mile / local-loop flap",
        "domain": "ent.middle-mile",
        "seams": ["WAN_SDWAN", "CARRIER_INTERCONNECT"],
        "deployment_scope": "hybrid",
        "requires": [
            {"kind": "link_state_change", "entity_type": "interface"},
            {"kind": "probe_loss|bgp_adjacency_change"},
            {"kind": "if_errors|optical_power_low", "optional": True},
        ],
        "required_modalities": ["control_plane", "active_probe"],
        "discriminators": [
            # Pure routing churn without the L1 oscillation is routing instability.
            {"absent": {"kind": "bgp_path_change"}, "within_s": 300,
             "else_prefer": "sig.ent.middle-mile.physical-degradation"},
        ],
        "direction_expect": "local-loop -> site-uplink -> whole-site",
        "verdict": {
            "owner": "carrier", "layer": "L1 (last mile)",
            "first_steps": [
                "Check demarc/NTU status and handoff interface error counters with a fresh baseline",
                "Pull the flap timeline and align it with any carrier maintenance or ticket",
                "Confirm the site recovers fully between flaps (oscillation, not degradation)",
            ],
        },
        "operator_phrase": "Likely last-mile instability at the carrier handoff or local loop — the site flaps fully and recovers, aligned with interface oscillation.",
        "manager_phrase": "The site is losing its carrier handoff intermittently rather than seeing an app-only slowdown.",
        "blast_radius": "the whole site behind the flapping circuit",
        "false_positives": ["site power events", "planned carrier work", "CPE reboot"],
    },
    {
        "id": "sig.ent.middle-mile.dx-optics-degrade",
        "title": "Interconnect optics / cross-connect degradation",
        "domain": "ent.middle-mile",
        "seams": ["CARRIER_INTERCONNECT"],
        "deployment_scope": "hybrid",
        "requires": [
            {"kind": "optical_power_low|if_crc", "entity_type": "interface"},
            {"kind": "probe_loss|probe_rtt_anomaly"},
            {"kind": "cloud_health", "optional": True},
        ],
        "required_modalities": ["device_telemetry", "active_probe"],
        "discriminators": [
            # A config/logical fault (VLAN mapping) is the tag-mismatch family.
            {"absent": {"kind": "config_change"}, "within_s": 600,
             "else_prefer": "sig.ent.middle-mile.interconnect-vlan-tag-mismatch"},
        ],
        "direction_expect": "cross-connect(L1) -> interconnect -> cloud-private-path",
        "verdict": {
            "owner": "colo_provider", "layer": "L1 (interconnect optics)",
            "first_steps": [
                "Check optics light levels and CRC counters on BOTH ends of the cross-connect",
                "Confirm packet loss precedes any BGP symptoms (physical-first ordering)",
                "Engage the colo/provider with the LOA/CFA and cross-connect id",
            ],
        },
        "operator_phrase": "Physical degradation is suspected on the private interconnect or cross-connect — loss precedes any routing symptom.",
        "manager_phrase": "The dedicated cloud/private connection appears physically degraded rather than logically misrouted.",
        "blast_radius": "all traffic on the degraded interconnect",
        "false_positives": ["one-side-only counter artifacts", "recent re-seating", "provider maintenance"],
    },
    {
        "id": "sig.ent.middle-mile.interconnect-vlan-tag-mismatch",
        "title": "VIF / subinterface VLAN tag mismatch",
        "domain": "ent.middle-mile",
        "seams": ["CARRIER_INTERCONNECT"],
        "deployment_scope": "hybrid",
        "requires": [
            {"kind": "interconnect_peer_unreachable|arp_fail", "entity_type": "device"},
            {"kind": "config_change|cloud_change"},
        ],
        "required_modalities": ["control_plane"],
        "discriminators": [
            # Physical-layer evidence wins — optics first.
            {"absent": {"kind": "optical_power_low|if_crc"}, "within_s": 300,
             "else_prefer": "sig.ent.middle-mile.dx-optics-degrade"},
        ],
        "direction_expect": "vlan-mapping -> virtual-interface -> interconnect-peering",
        "verdict": {
            "owner": "netops", "layer": "L2 (interconnect logical circuit)",
            "first_steps": [
                "Validate VLAN ID, subinterface binding and tagging mode on both sides of the handoff",
                "Confirm the peer IP placement matches the provider's VIF/attachment definition",
                "Check whether a recent config change re-mapped the subinterface",
            ],
        },
        "operator_phrase": "Physical link is up, but the private interconnect VLAN/subinterface mapping looks wrong — the peer never resolves.",
        "manager_phrase": "The dedicated connection exists, but traffic is not entering the correct logical circuit.",
        "blast_radius": "the virtual circuit on the affected VLAN/VIF",
        "false_positives": ["provider-side pending provisioning", "intentional re-homing", "stale documentation"],
    },
    {
        "id": "sig.ent.cloud.lb-probe-source-blocked",
        "title": "Cloud LB health probes blocked by policy",
        "domain": "ent.cloud",
        "seams": ["CLOUD_APP"],
        "deployment_scope": "hybrid",
        "requires": [
            {"kind": "lb_target_unhealthy", "entity_type": "service"},
            {"kind": "cloud_flow_reject|fw_probe_denied"},
            {"kind": "config_change|cloud_audit", "optional": True},
        ],
        "required_modalities": ["passive_flow"],
        "discriminators": [
            # Genuinely failing backends are the target-health family.
            {"absent": {"kind": "app_error_rate_high|synthetic_http_fail"}, "within_s": 300,
             "else_prefer": "sig.ent.app.lb-target-health-failure"},
        ],
        "direction_expect": "probe-source-ranges -> security-policy -> target-health",
        "verdict": {
            "owner": "netops", "layer": "L4 (probe path policy)",
            "first_steps": [
                "Test the backend DIRECTLY — healthy direct + unhealthy-to-LB is the fingerprint",
                "Check flow logs for rejects sourced from the provider's health-probe ranges",
                "Diff security policy changes and re-allow the documented probe source ranges",
            ],
        },
        "operator_phrase": "Backend seems healthy, but health-check probes are being blocked before they reach it — allow the provider probe source ranges.",
        "manager_phrase": "The service is likely up, but the load balancer cannot verify it because its monitoring traffic is denied.",
        "blast_radius": "the VIP whose pool is marked down by blocked probes",
        "false_positives": ["backend genuinely down", "probe path/port misconfigured", "asymmetric return path"],
    },
    {
        "id": "sig.ent.cloud.private-endpoint-dns-mismatch",
        "title": "Private endpoint DNS not overriding public name",
        "domain": "ent.cloud",
        "seams": ["CLOUD_APP", "CARRIER_INTERCONNECT"],
        "deployment_scope": "hybrid",
        "requires": [
            {"kind": "dns_answer_mismatch|private_dns_missing", "entity_type": "service"},
            {"kind": "synthetic_http_fail|probe_loss"},
            {"kind": "cloud_change|config_change", "optional": True},
        ],
        "required_modalities": ["active_probe"],
        "discriminators": [
            # Failover steering to a WRONG-but-intended-shape target is the
            # dns-failover family; here the private override is absent entirely.
            {"absent": {"kind": "dns_failover_event"}, "within_s": 300,
             "else_prefer": "sig.ent.app.dns-failover-wrong-target"},
        ],
        "direction_expect": "private-dns-zone -> resolver-path -> private-endpoint",
        "verdict": {
            "owner": "netops", "layer": "L7 (hybrid DNS)",
            "first_steps": [
                "Compare answers from the intended resolver path — a public IP for a private-endpoint name is the tell",
                "Verify the private DNS zone links/forwarders for the affected VNet/VPC",
                "Confirm the on-prem conditional forwarders target the cloud resolver correctly",
            ],
        },
        "operator_phrase": "Private connectivity is likely failing because DNS is not resolving the service to the private endpoint — the name returns the public IP.",
        "manager_phrase": "Users are being sent to the public endpoint instead of the intended private path.",
        "blast_radius": "clients that should use the private endpoint via the affected resolver path",
        "false_positives": ["intended public access", "split-horizon by design", "client cache"],
    },
    {
        "id": "sig.ent.cloud.k8s-pod-ip-exhaustion",
        "title": "Kubernetes pod/subnet IP exhaustion",
        "domain": "ent.cloud",
        "seams": ["CLOUD_APP"],
        "deployment_scope": "hybrid",
        "requires": [
            {"kind": "k8s_ip_alloc_fail|subnet_capacity_exhausted", "entity_type": "service"},
            {"kind": "k8s_pod_pending|k8s_event"},
            {"kind": "deploy_event", "optional": True},
        ],
        "required_modalities": ["control_plane"],
        "discriminators": [
            # Ready-pods-zero from readiness/rollout is the endpoint-empty family.
            {"absent": {"kind": "k8s_endpoints_empty"}, "within_s": 300,
             "else_prefer": "sig.ent.cloud.k8s-service-endpoint-empty"},
        ],
        "direction_expect": "ipam-capacity -> pod-scheduling -> service-capacity",
        "verdict": {
            "owner": "app_team", "layer": "L3 (cluster IPAM)",
            "first_steps": [
                "Check CNI/IPAM allocation errors and the subnet's free-address count",
                "Count pending pods and confirm scheduling stalls on address capacity, not resources",
                "Review pod density per node and secondary-range sizing",
            ],
        },
        "operator_phrase": "Cluster networking capacity is exhausted — new pods cannot get addresses, so scaling stalls while running pods keep working.",
        "manager_phrase": "Service degradation is tied to cluster address exhaustion rather than a path outage.",
        "blast_radius": "new/rescheduled pods across the affected cluster/subnet",
        "false_positives": ["node resource pressure", "quota limits", "image pull failures"],
    },
    {
        "id": "sig.ent.cloud.mesh-mtls-cert-rotation-failure",
        "title": "Service-mesh mTLS certificate rotation failure",
        "domain": "ent.cloud",
        "seams": ["CLOUD_APP"],
        "deployment_scope": "hybrid",
        "requires": [
            {"kind": "mesh_cert_rotation_fail|mtls_handshake_fail", "entity_type": "service"},
            {"kind": "app_error_rate_high|k8s_event"},
            {"kind": "cert_expiry_warning", "optional": True},
        ],
        "required_modalities": ["control_plane"],
        "discriminators": [
            # North-south edge certificate problems are the tls-cert family.
            {"absent": {"kind": "tls_handshake_fail"}, "within_s": 300,
             "else_prefer": "sig.ent.app.tls-cert-expired"},
        ],
        "direction_expect": "mesh-identity -> sidecar-mtls -> east-west-calls",
        "verdict": {
            "owner": "app_team", "layer": "L6 (mesh identity)",
            "first_steps": [
                "Check SDS/cert rotation state and the trust bundle on the affected workloads",
                "Confirm ONLY mesh (east-west) traffic fails while edge TLS stays healthy",
                "Review sidecar and mesh control-plane logs for rotation errors and clock skew",
            ],
        },
        "operator_phrase": "East-west traffic is failing at mesh identity/certificate rotation, not at network reachability — edge TLS stays clean.",
        "manager_phrase": "Internal service-to-service trust is broken even though the network itself may be intact.",
        "blast_radius": "workload-to-workload calls inside the mesh namespace(s)",
        "false_positives": ["network policy deny", "app auth failure", "control-plane upgrade window"],
    },
]

# v1 P1 backlog — valid, validated catalog entries shipped DISABLED (owner spec:
# "add as valid catalog entries, avoid destabilizing the engine"). Enable per
# family as Layer-2 signal kinds land for them. Kept in a separate list so the
# enabled-set version hash and the fixture-coverage test are unaffected.

# tracker 157 — structural preconditions for the COMPACT backlog lists.
#
# The lists below are comprehensions over positional tuples, so there is no
# per-entry dict to carry a `requires_structure` key; this table is that
# declaration, keyed by the same `sid` the comprehension builds the id from. It
# is the ONE place a disabled family declares its structure, and it is applied
# by every compact list, so enabling a family cannot enable it ungated.
#
# The backlog is NOT neutral with respect to the defect (tracker 157): all 46
# disabled templates declare `seams` and none carried a structural predicate, so
# every family enablement enlarged the exposed surface. The four families here
# are the ones whose CLAIM names a structure their clauses cannot assert.
_BACKLOG_STRUCTURE: dict[str, list[str]] = {
    # A LACP bundle — but the clause alternation admits a bare `if_errors`,
    # which says nothing about a bundle. The lacp_* / lag_* kinds attest it.
    "ent.fabric.lacp-member-blackhole": ["redundancy_group"],
    # An MLAG/vPC PAIR; attested by the mlag_* kinds the clause names.
    "ent.fabric.mlag-vpc-peerlink-issue": ["redundancy_group"],
    # A host bond / switch bundle pair; attested by host_bond_mismatch and
    # lacp_inconsistent.
    "ent.fabric.server-bonding-mode-mismatch": ["redundancy_group"],
    # An interconnect LAG; attested by lag_member_down / lacp_inconsistent.
    "ent.middle-mile.interconnect-lag-member-loss": ["redundancy_group"],
    # The claim is that an OVERLAY exceeds its underlay MTU, but both clauses
    # (size_dependent_loss, tcp_retransmit_high) are equally true of a plain
    # native-path MTU problem. The VXLAN/EVPN/tunnel kinds attest the overlay.
    "ent.fabric.overlay-underlay-mtu-mismatch": ["overlay_encap"],
}

P1_BACKLOG_TEMPLATES: list[dict] = [
    {
        "id": f"sig.{sid}", "title": title, "domain": domain, "enabled": False,
        "seams": list(seams), "deployment_scope": scope, "demo_priority": "p1",
        "requires": [{"kind": req} for req in reqs],
        "requires_structure": _BACKLOG_STRUCTURE.get(sid, []),
        "required_modalities": list(mods),
        "direction_expect": direction,
        "verdict": {"owner": owner, "layer": layer, "first_steps": list(steps)},
        "operator_phrase": op, "manager_phrase": mgr,
        "false_positives": list(fps),
    }
    for (sid, title, domain, seams, scope, reqs, mods, direction, owner, layer, steps, op, mgr, fps) in [
        ("ent.wan-edge.path-asymmetry-return-drop", "Asymmetric routing / return-path drop", "ent.wan-edge",
         ("WAN_SDWAN", "CARRIER_INTERCONNECT", "CLOUD_APP"), "hybrid",
         ("flow_one_directional", "return_path_drop|fw_state_mismatch"), ("passive_flow",),
         "forward-path -> return-path -> sessions", "netops", "L3/L4 (path symmetry)",
         ("Compare forward and return paths using flows, firewall state and route tables",
          "Check for a BGP path change or NAT state loss that split the paths"),
         "Suspected asymmetric routing or return-path drop — one direction of the flow succeeds while the return path does not.",
         "Traffic appears to reach part of the path, but responses are not returning correctly.",
         ("host firewall", "app not listening", "SYN rate limiting", "incomplete flow collection")),
        ("ent.wan-edge.qos-policing-drop", "QoS/policing drops", "ent.wan-edge",
         ("WAN_SDWAN",), "hybrid",
         ("qos_drops|if_discards", "probe_rtt_anomaly|probe_loss"), ("device_telemetry",),
         "qos-class -> prioritized-traffic -> voice/video", "netops", "L2/L3 (QoS)",
         ("Check QoS counters, policer drops and DSCP markings on the WAN edge",
          "Compare circuit utilization against committed rate for the affected class"),
         "Likely QoS or policing drops for the affected traffic class — data rides fine while voice/video degrades.",
         "Performance degradation appears concentrated in prioritized traffic classes such as voice or video.",
         ("endpoint codec issue", "conferencing provider issue", "Wi-Fi impairment")),
        ("ent.wan-edge.sdwan-policy-misroute", "SD-WAN policy sends traffic to wrong path", "ent.wan-edge",
         ("WAN_SDWAN", "CLOUD_APP"), "hybrid",
         ("sdwan_policy_change|path_change", "app_latency_high|probe_rtt_anomaly"), ("control_plane",),
         "sdwan-policy -> path-selection -> app-traffic", "sdwan_vendor", "L3/L4 (SD-WAN policy)",
         ("Review SD-WAN policy, app identification and path preference for the affected app class",
          "Compare the selected path's quality against the intended one"),
         "Suspected SD-WAN policy misroute — app traffic is using a different path than expected after a policy change.",
         "Traffic for the affected application may be taking a suboptimal route due to policy behavior.",
         ("DPI/app-ID misclassification", "expected failover", "provider brownout")),
        ("ent.fabric.mlag-vpc-peerlink-issue", "MLAG/vPC peer-link inconsistency", "ent.fabric",
         ("DC_FABRIC",), "onprem_only",
         ("mlag_peerlink_issue|mlag_keepalive_fail", "mac_flap|lacp_inconsistent"), ("control_plane",),
         "mlag-pair -> dual-homed-endpoints -> services", "netops", "L2 (MLAG/vPC)",
         ("Check peer-link and keepalive state plus consistency checks on the pair",
          "Look for orphan-port logs and MAC moves on dual-homed endpoints"),
         "Suspected MLAG/vPC inconsistency affecting dual-homed connectivity — intermittent impact on paired endpoints.",
         "A data center redundancy pair may be inconsistent, causing intermittent connectivity for attached systems.",
         ("server NIC teaming issue", "maintenance", "hypervisor vSwitch issue")),
        ("ent.fabric.lacp-member-blackhole", "LACP member blackholing", "ent.fabric",
         ("DC_FABRIC", "LAN"), "onprem_only",
         ("lacp_member_bad|if_errors", "probe_loss|flow_partial_loss"), ("device_telemetry",),
         "bundle-member -> hashed-flows -> partial-loss", "netops", "L2 (LACP)",
         ("Check per-member counters and LACP state on the bundle",
          "Drain the suspect member and retest the failing flows"),
         "Suspected LACP member blackhole — some flows hash onto a bad bundle member, so loss is partial and flow-dependent.",
         "A redundant link group may have one unhealthy member causing intermittent rather than total failure.",
         ("ECMP path issue", "server NIC issue", "sampling bias")),
        ("ent.fabric.storage-network-latency", "Storage/iSCSI/NFS network degradation", "ent.fabric",
         ("DC_FABRIC",), "hybrid",
         ("storage_latency_high|tcp_retransmit_high", "app_latency_high|vm_datastore_warning"), ("device_telemetry",),
         "storage-path -> datastore -> VM/app", "netops", "L2-L4 (storage network)",
         ("Check the storage VLAN/path for drops, MTU mismatch and retransmits",
          "Compare array-side latency against network path latency"),
         "Storage network path degradation is suspected — application slowness aligns with storage latency or retransmits.",
         "Application performance may be affected by storage connectivity rather than the application tier itself.",
         ("array-side IO saturation", "backup jobs", "VM snapshot consolidation")),
        ("ent.cloud.nat-gateway-route-misconfig", "Cloud NAT route/IGW issue", "ent.cloud",
         ("CLOUD_APP",), "cloud_only",
         ("cloud_egress_fail|route_missing_nexthop", "cloud_flow_log|cloud_health"), ("control_plane",),
         "private-subnet -> nat/igw -> external-dependencies", "netops", "L3 (cloud egress)",
         ("Check the subnet route table, NAT gateway and IGW path for the affected subnets",
          "Pull VPC flow logs for no-route/reject records"),
         "Suspected cloud egress routing or NAT path issue for private subnets — outbound fails while inbound may still work.",
         "Cloud workloads in private networks may be unable to reach external dependencies.",
         ("destination rate limit", "proxy requirement", "missing IAM endpoint permission")),
        ("ent.cloud.nat-connection-limit", "Cloud NAT connection exhaustion", "ent.cloud",
         ("CLOUD_APP",), "cloud_only",
         ("cloud_nat_alloc_fail", "app_conn_fail|flow_timeout"), ("control_plane",),
         "cloud-nat -> outbound-connections -> dependencies", "netops", "L4 (cloud NAT)",
         ("Check NAT allocation metrics, connection distribution and destination concentration",
          "Review scale-out options and application connection reuse"),
         "Likely cloud NAT connection exhaustion — outbound failures appear capacity-related and intermittent.",
         "Cloud workloads may be hitting outbound connection limits, causing intermittent external dependency failures.",
         ("API provider throttling", "service mesh egress policy", "DNS resolver failure")),
        ("ent.cloud.az-specific-service-impact", "AZ-local impairment", "ent.cloud",
         ("CLOUD_APP",), "cloud_only",
         ("az_health_degraded", "lb_target_unhealthy|probe_loss"), ("control_plane",),
         "one-az -> zonal-dependencies -> service", "cloud_provider", "AZ (zonal)",
         ("Compare LB target health and instance health BY availability zone",
          "Check zonal subnet routes/NAT and the provider's zonal status"),
         "Suspected AZ-local impact — one availability zone is measurably less healthy than the others.",
         "Impact appears localized to one cloud availability zone, so redundancy may reduce but not eliminate user impact.",
         ("uneven deployment", "autoscaling imbalance", "app shard issue")),
        ("ent.cloud.k8s-coredns-failure", "Kubernetes CoreDNS failure", "ent.cloud",
         ("CLOUD_APP",), "hybrid",
         ("k8s_dns_fail", "k8s_pod_restart|dns_latency_high"), ("control_plane",),
         "coredns -> service-discovery -> app-to-app", "app_team", "L7 (cluster DNS)",
         ("Check CoreDNS pod health, restarts and the kube-dns service endpoints",
          "Measure in-cluster DNS latency and SERVFAIL rates"),
         "Suspected Kubernetes DNS issue — pods are failing to resolve service or external names while workloads stay healthy.",
         "Applications may be healthy, but service discovery inside the cluster is failing.",
         ("application wrong hostname", "external DNS outage", "namespace search path issue")),
        ("ent.cloud.k8s-network-policy-deny", "Kubernetes NetworkPolicy/CNI blocks pod traffic", "ent.cloud",
         ("CLOUD_APP",), "hybrid",
         ("k8s_policy_deny|cni_deny", "k8s_event|config_change"), ("control_plane",),
         "network-policy -> pod-to-pod -> app-components", "app_team", "L3/L4 (CNI policy)",
         ("Check NetworkPolicy selectors and CNI deny logs for the affected namespace/labels",
          "Confirm pods are healthy and endpoints present while traffic is blocked"),
         "Suspected Kubernetes network policy or CNI enforcement issue — pods are healthy, but traffic between them appears blocked.",
         "An internal cluster security/network policy may be preventing application components from communicating.",
         ("wrong service selector", "app port mismatch", "pod readiness issue")),
        ("ent.app.idp-auth-dependency-failure", "Identity provider / OAuth / JWKS dependency failure", "ent.app",
         ("CLOUD_APP",), "cloud_only",
         ("auth_fail_spike|jwks_fetch_fail", "app_error_rate_high"), ("control_plane",),
         "idp-dependency -> auth/tokens -> logins", "app_team", "L7 (identity)",
         ("Check IdP status, OIDC/JWKS endpoints and the app's auth error logs",
          "Verify DNS/egress to the IdP and recent auth configuration changes"),
         "Suspected identity/auth dependency issue — the application is reachable, but login or token validation is failing.",
         "The service may be available, but users cannot authenticate due to an identity provider or auth dependency issue.",
         ("password/credential issue", "expired client secret", "conditional access policy change")),
        ("ent.app.backend-timeout", "Backend slow behind load balancer", "ent.app",
         ("CLOUD_APP", "DC_FABRIC"), "hybrid",
         ("lb_target_response_slow|app_latency_high", "app_error_rate_high|synthetic_http_fail"), ("device_telemetry",),
         "lb -> backend-response-time -> users", "app_team", "L7 (backend latency)",
         ("Check LB target response time, backend saturation and DB latency",
          "Correlate with the deployment timeline"),
         "Backend timeout is likely — the front-end path is reachable, but backend response time is exceeding limits.",
         "The service is reachable, but backend components are responding too slowly.",
         ("NAT exhaustion", "WAF block", "client-side timeout too low")),
        ("ent.app.db-dependency-saturation", "Database dependency saturation looks like network issue", "ent.app",
         ("CLOUD_APP", "DC_FABRIC"), "hybrid",
         ("db_saturation|db_latency_high", "app_error_rate_high|app_latency_high"), ("device_telemetry",),
         "db-dependency -> app-latency -> users", "app_team", "L7 (database)",
         ("Check DB CPU, connections, IO wait and slow queries against the app error timeline",
          "Confirm network probes on the DB path are cleaner than the DB metrics"),
         "Database dependency saturation is suspected — network probes are cleaner than application/database latency.",
         "The user-facing slowdown appears tied to a backend database dependency, not primarily the network.",
         ("storage network latency", "firewall idle timeout", "app memory leak")),
        ("ent.security.proxy-swg-egress-failure", "Proxy/SWG egress outage", "ent.security",
         ("WAN_SDWAN", "CLOUD_APP"), "hybrid",
         ("proxy_fail|swg_health_degraded", "synthetic_http_fail|dns_failure_rate"), ("control_plane",),
         "proxy-path -> saas/internet -> users", "netops", "L7 (secure web gateway)",
         ("Check proxy/SWG health, PAC file and TLS inspection errors",
          "Run a direct-bypass probe to separate proxy failure from SaaS/DIA failure"),
         "Suspected proxy/SWG egress issue — SaaS traffic through the proxy fails while direct-path evidence differs.",
         "Internet/SaaS access may be impaired by the security egress layer rather than the SaaS provider itself.",
         ("SaaS outage", "DNS resolver issue", "client VPN issue")),
    ]
]
BUILTIN_TEMPLATES.extend(P1_BACKLOG_TEMPLATES)

# Wave-2 v1/v2 backlog (owner spec batch 2 — failure-signature-catalog-wave2.md
# carries the full evidence contracts). Same compact disabled-entry pattern.
W2_BACKLOG_TEMPLATES: list[dict] = [
    {
        "id": f"sig.{sid}", "title": title, "domain": domain, "enabled": False,
        "seams": list(seams), "deployment_scope": scope, "demo_priority": "p2",
        "requires": [{"kind": req} for req in reqs],
        "requires_structure": _BACKLOG_STRUCTURE.get(sid, []),
        "required_modalities": list(mods),
        "direction_expect": "", "verdict": {"owner": owner, "layer": layer, "first_steps": list(steps)},
        "operator_phrase": op, "manager_phrase": mgr,
    }
    for (sid, title, domain, seams, scope, reqs, mods, owner, layer, steps, op, mgr) in [
        ("ent.access.pmtud-blackhole", "Campus PMTUD / MTU blackhole", "ent.access", ("LAN", "WAN_SDWAN"), "hybrid",
         ("size_dependent_loss", "tcp_retransmit_high|app_large_transfer_fail"), ("active_probe",), "netops", "L3 (PMTUD)",
         ("Run PMTU tests from both ends", "Inspect ICMP frag-needed handling and MSS clamp"),
         "This looks like an MTU/PMTUD blackhole rather than a full path outage — small packets pass, larger sessions hang.",
         "Some traffic works, but larger packets are being dropped on the path."),
        ("ent.access.duplex-speed-mismatch", "Speed/duplex mismatch", "ent.access", ("LAN",), "onprem_only",
         ("if_fcs_align_errors|if_errors", "lldp_neighbor_change"), ("device_telemetry",), "netops", "L1 (link settings)",
         ("Compare both ends' speed/duplex settings", "Restore auto/consistent settings"),
         "Suspected speed/duplex mismatch on the affected link — one-sided errors with poor throughput and no full outage.",
         "The link is up, but it is operating inefficiently because the ends disagree on link settings."),
        ("ent.access.nac-radius-auth-outage", "802.1X / NAC / RADIUS admission failure", "ent.access", ("LAN", "CLOUD_APP"), "hybrid",
         ("radius_auth_fail_spike", "client_onboarding_fail"), ("control_plane",), "netops", "L2 (admission control)",
         ("Check RADIUS reachability and AAA logs", "Verify cert/clock status and recent policy changes"),
         "Access failure appears tied to network admission control, not switching or routing loss — only (re)authenticating devices fail.",
         "New or reauthenticating devices cannot join the network due to an access-control dependency failure."),
        ("ent.wan-edge.bfd-false-failover", "BFD instability causing false route failover", "ent.wan-edge",
         ("WAN_SDWAN", "CARRIER_INTERCONNECT"), "hybrid",
         ("bfd_session_flap", "path_change|bgp_adjacency_change"), ("control_plane",), "netops", "L3 (BFD)",
         ("Check BFD timers, CPU and policing on the path", "Compare flap times with path switches"),
         "Fast-failure detection appears overly sensitive or unstable on this path — failovers without physical loss.",
         "Traffic is failing over too aggressively because the path-monitoring protocol is unstable."),
        ("ent.wan-edge.mpls-vrf-rt-mismatch", "MPLS VRF / route-target membership mismatch", "ent.wan-edge",
         ("WAN_SDWAN", "CARRIER_INTERCONNECT"), "hybrid",
         ("vrf_route_missing", "config_change|route_advertisement_change"), ("control_plane",), "carrier", "L3 (MPLS VPN)",
         ("Compare import/export route-targets with the provider's PE view", "Check whether prefixes landed in the wrong VRF"),
         "Reachability failure is confined to one VPN/VRF, suggesting route-target or VRF membership error.",
         "A provider or edge routing segmentation issue is isolating one business network segment."),
        ("ent.wan-edge.appid-classification-drift", "SD-WAN application-ID drift", "ent.wan-edge", ("WAN_SDWAN",), "hybrid",
         ("appid_mismatch", "path_change"), ("control_plane",), "sdwan_vendor", "L7 (app identification)",
         ("Check the app-ID match and signature version on controller and edge", "Identify the fallback class applied"),
         "Traffic is being classified differently than expected, so the wrong SLA treatment is applied.",
         "The WAN is steering the application incorrectly because it is misidentifying the traffic."),
        ("ent.fabric.anycast-gateway-inconsistency", "Distributed/anycast gateway inconsistency", "ent.fabric", ("DC_FABRIC",), "onprem_only",
         ("anycast_gw_inconsistent", "arp_fail|probe_loss"), ("control_plane",), "netops", "L3 (anycast gateway)",
         ("Compare gateway programming across the affected leaves", "Check neighbor state per leaf slice"),
         "Gateway behavior appears inconsistent across leaves, not uniformly across the fabric.",
         "One distributed gateway instance is misbehaving, affecting a subset of workloads."),
        ("ent.fabric.overlay-underlay-mtu-mismatch", "Overlay-underlay MTU mismatch", "ent.fabric", ("DC_FABRIC",), "hybrid",
         ("size_dependent_loss", "tcp_retransmit_high"), ("active_probe",), "netops", "L3 (overlay MTU)",
         ("Validate overhead-adjusted MTU across underlay and overlay", "Confirm native traffic is cleaner than encapsulated"),
         "The overlay is likely exceeding underlay MTU, causing encapsulated packet loss while native traffic stays cleaner.",
         "Virtualized tenant traffic is failing because overlay packets are too large for the transport path."),
        ("ent.fabric.tcam-fib-exhaustion", "TCAM/FIB resource exhaustion / partial programming", "ent.fabric", ("DC_FABRIC",), "onprem_only",
         ("hw_resource_exhausted", "route_programming_fail"), ("device_telemetry",), "netops", "hardware (forwarding resources)",
         ("Inspect TCAM/FIB usage and failed programming events", "Correlate with recent policy/route growth"),
         "Partial forwarding/policy programming is suspected on the affected switch — selective failure, not full outage.",
         "A network device appears to have run out of forwarding/policy resources, causing selective failure."),
        ("ent.middle-mile.expressroute-arp-unresolved", "ExpressRoute ARP unresolved / L2 adjacency issue", "ent.middle-mile",
         ("CARRIER_INTERCONNECT",), "hybrid",
         ("interconnect_peer_unreachable|arp_fail", "bgp_state_anomaly"), ("control_plane",), "netops", "L2 (ER adjacency)",
         ("Inspect the ExpressRoute ARP table for peer resolution", "Verify peer IP/VLAN and the CE handoff"),
         "Azure private interconnect may be failing at Layer 2/ARP rather than at pure BGP.",
         "The Azure private connection is present, but the local adjacency is not resolving correctly."),
        ("ent.middle-mile.gcp-proxy-arp-wrong-mac", "GCP Partner Interconnect wrong-MAC learning", "ent.middle-mile",
         ("CARRIER_INTERCONNECT",), "hybrid",
         ("arp_wrong_mac", "interconnect_peer_unreachable"), ("control_plane",), "netops", "L2 (partner interconnect)",
         ("Verify the VLAN-attachment design and on-prem L2 bridging", "Check ARP/MAC learned through the partner segment"),
         "Wrong-MAC learning through Partner Interconnect is suspected — adjacency resolves to the wrong device.",
         "The Google private connection may be learning the wrong adjacent MAC, which disrupts traffic."),
        ("ent.cloud.lb-backend-bind-mismatch", "Backend not bound to LB IP/port / guest-agent route issue", "ent.cloud",
         ("CLOUD_APP",), "cloud_only",
         ("lb_backend_not_bound", "lb_target_unhealthy"), ("control_plane",), "app_team", "L4 (backend binding)",
         ("Verify the backend's bind address/port for the LB delivery model", "Check guest agent and local LB route"),
         "Backend is running, but it is not correctly bound/routed for the load balancer delivery model — localhost works, VIP fails.",
         "The service exists, but the backend instance is not correctly set up to receive traffic from the load balancer."),
        ("ent.cloud.k8s-ingress-class-drift", "Ingress/service annotations or class drift", "ent.cloud", ("CLOUD_APP",), "hybrid",
         ("ingress_class_mismatch", "k8s_event|deploy_event"), ("control_plane",), "app_team", "L7 (ingress config)",
         ("Inspect ingress class/annotations and controller events", "Diff the object against the last working revision"),
         "Traffic path issue appears tied to ingress/controller configuration drift — the intended controller is not acting on the object.",
         "The application may be healthy, but the cluster's routing object is not being implemented as intended."),
        ("ent.wan-edge.internet-pmtud-blackhole", "Internet PMTUD blackhole", "ent.wan-edge",
         ("WAN_SDWAN", "CARRIER_INTERCONNECT"), "hybrid",
         ("size_dependent_loss", "tcp_retransmit_high"), ("active_probe",), "isp", "L3 (internet PMTUD)",
         ("Test varied packet sizes toward the failing public targets", "Inspect MSS/ICMP handling on the egress/security path"),
         "Internet-bound sessions show classic PMTUD blackhole behavior — small probes pass, large payloads stall.",
         "Public-service access is impaired for larger payloads, not fully down."),
        ("ent.fabric.mac-mobility-storm", "Excessive MAC mobility / live-migration churn", "ent.fabric", ("DC_FABRIC",), "onprem_only",
         ("evpn_mac_move", "mac_flap"), ("control_plane",), "netops", "L2 (endpoint mobility)",
         ("Correlate migration/orchestration events with MAC moves", "Check VTEP state during the churn window"),
         "The fabric is reacting to rapid endpoint movement, causing MAC instability aligned with migration windows.",
         "Workloads are moving too quickly for the network to converge cleanly."),
        ("ent.fabric.arp-nd-suppression-stale", "Stale ARP/ND suppression cache", "ent.fabric", ("DC_FABRIC",), "onprem_only",
         ("arp_suppression_stale", "arp_fail"), ("control_plane",), "netops", "L2 (ARP suppression)",
         ("Inspect neighbor-suppression/cache entries for the moved endpoint", "Refresh the cache and confirm recovery"),
         "Reachability looks blocked by stale ARP/ND suppression rather than missing routes.",
         "The network still remembers an old endpoint location and is sending traffic incorrectly."),
        ("ent.fabric.microburst-buffer-drop", "Microburst / buffer exhaustion", "ent.fabric", ("DC_FABRIC",), "onprem_only",
         ("queue_burst_drops", "app_latency_high"), ("device_telemetry",), "netops", "L2 (buffers)",
         ("Inspect queue-drop and burst telemetry on the suspect hop", "Identify top talkers during the burst windows"),
         "Short-lived queue bursts are causing loss even though average utilization is not extreme.",
         "Brief traffic spikes are overwhelming buffers on one path, degrading latency-sensitive workloads."),
        ("ent.fabric.server-bonding-mode-mismatch", "Server NIC team / host-bonding mismatch", "ent.fabric",
         ("DC_FABRIC", "LAN"), "onprem_only",
         ("host_bond_mismatch", "lacp_inconsistent"), ("control_plane",), "app_team", "L2 (host bonding)",
         ("Compare host team mode and hashing with the switch bundle config", "Confirm impact is limited to one host/cluster"),
         "Suspected host-side bonding mismatch rather than switch-side bundle failure — one host's flows misbehave.",
         "One server or host cluster is not using its redundant links correctly."),
        ("ent.fabric.adc-probe-source-block", "On-prem ADC/NVA LB probe-source blocked", "ent.fabric",
         ("DC_FABRIC", "CLOUD_APP"), "hybrid",
         ("lb_target_unhealthy", "fw_probe_denied"), ("control_plane",), "netops", "L4 (ADC monitor path)",
         ("Test from the ADC's monitor source address", "Inspect server firewall and the monitor definition"),
         "Backend looks healthy, but the ADC's monitor source is being blocked — pool marked down while direct access succeeds.",
         "The load balancer cannot verify the server because monitoring traffic is not allowed."),
        ("ent.middle-mile.interconnect-jumbo-mtu-mismatch", "Private interconnect jumbo/MTU mismatch", "ent.middle-mile",
         ("CARRIER_INTERCONNECT",), "hybrid",
         ("size_dependent_loss", "tcp_retransmit_high"), ("active_probe",), "netops", "L2/L3 (interconnect MTU)",
         ("Validate MTU across the CE/provider/cloud handoff", "Adjust MSS or jumbo settings and retest large transfers"),
         "Control plane may be fine, but the private interconnect MTU is wrong for data traffic — large transfers stall.",
         "The dedicated cloud path is available, but larger transfers are being dropped."),
        ("ent.middle-mile.tgw-route-propagation-missing", "Transit-gateway / hub route propagation missing", "ent.middle-mile",
         ("CARRIER_INTERCONNECT", "CLOUD_APP"), "hybrid",
         ("hub_route_propagation_missing", "probe_loss|cloud_flow_log"), ("control_plane",), "netops", "L3 (transit hub)",
         ("Check association vs propagation on the hub/TGW route tables", "Confirm only one attachment scope is isolated"),
         "Connectivity gap is likely in hub/transit route propagation rather than link state — the attachment exists but is not learned.",
         "A central routing hub is not advertising or learning one environment correctly."),
        ("ent.middle-mile.provider-maintenance-impact", "Provider/cloud-edge maintenance impact", "ent.middle-mile",
         ("CARRIER_INTERCONNECT",), "hybrid",
         ("provider_maintenance_overlap", "probe_loss|probe_rtt_anomaly"), ("control_plane",), "carrier", "provider (external)",
         ("Correlate symptom timestamps with provider advisories", "Verify internal fault evidence stays weak"),
         "A provider-side maintenance or platform event is the leading explanation — the window aligns and local evidence is weak.",
         "The outage is likely external to your environment and aligned with provider work."),
        ("ent.middle-mile.interconnect-lag-member-loss", "Private interconnect bundle member loss", "ent.middle-mile",
         ("CARRIER_INTERCONNECT",), "hybrid",
         ("lag_member_down|lacp_inconsistent", "flow_partial_loss"), ("device_telemetry",), "carrier", "L2 (interconnect LAG)",
         ("Check per-member counters/state on both ends", "Drain the suspect member and retest affected flows"),
         "One member of the private interconnect bundle is likely unhealthy — hash-dependent loss with the bundle still up.",
         "Redundancy hides the failure, but capacity and some flows are impaired."),
        ("ent.cloud.node-pressure-notready", "Node pressure / NotReady churn", "ent.cloud", ("CLOUD_APP",), "hybrid",
         ("k8s_node_notready|node_pressure", "k8s_pod_pending|lb_target_unhealthy"), ("control_plane",), "app_team", "node (capacity)",
         ("Inspect node conditions, evictions and pod rescheduling", "Confirm impact follows the unhealthy nodes"),
         "Cluster nodes are unhealthy, causing backend churn rather than a pure network break.",
         "Some service instances are disappearing because underlying worker nodes are unhealthy."),
        ("ent.cloud.api-rate-limit-throttling", "Dependency/API throttling masquerading as outage", "ent.cloud",
         ("CLOUD_APP",), "hybrid",
         ("api_throttle_429", "app_error_rate_high"), ("control_plane",), "app_team", "L7 (dependency quota)",
         ("Check quota metrics and 429/503 patterns toward the dependency", "Review client retry behavior and burst rates"),
         "Application failures point to dependency throttling, not to transport loss — 429/503 spikes with clean paths.",
         "The service is being limited by an upstream API capacity or quota control."),
        ("ent.cloud.secret-config-drift", "Secret / config drift after deploy", "ent.cloud", ("CLOUD_APP",), "hybrid",
         ("deploy_event|config_change", "app_error_rate_high|k8s_event"), ("control_plane",), "app_team", "L7 (release config)",
         ("Compare new vs previous config/secret versions", "Confirm rollback restores health"),
         "Backend failure appears tied to deployment configuration drift, not to the network — only the new revision fails.",
         "A recent application configuration change is preventing startup or dependency access."),
        ("ent.cloud.private-dns-forwarding-loop", "Conditional forwarder / hybrid private-DNS loop", "ent.cloud",
         ("CLOUD_APP", "CARRIER_INTERCONNECT"), "hybrid",
         ("dns_forwarding_loop|dns_failure_rate", "private_dns_missing"), ("control_plane",), "netops", "L7 (hybrid DNS)",
         ("Trace the query path across on-prem and cloud resolver rules", "Check which private zones fail vs public names"),
         "Private-name resolution appears to be looping or bouncing between resolvers — private zones fail while public stays clean.",
         "Internal/private naming is failing because DNS forwarding paths are misconfigured."),
    ]
]
BUILTIN_TEMPLATES.extend(W2_BACKLOG_TEMPLATES)

# ---------------------------------------------------------------------------
# Wave 3 (owner spec batch 3 — failure-signature-catalog-wave3.md): 7 new
# fault-boundary families ENABLED, 3 backlog promotions (owner P0), 7 new
# backlog. Uniqueness contract: every entry differs from its nearest reserved
# neighbor in fault boundary + required evidence; the neighbor is recorded
# machine-readably in the discriminator's else_prefer.
WAVE3_TEMPLATES: list[dict] = [
    {
        "id": "sig.ent.access.stp-loop-broadcast-storm",
        "title": "STP loop / broadcast storm",
        "domain": "ent.access",
        "seams": ["LAN", "DC_FABRIC"],
        "deployment_scope": "onprem_only",
        "requires": [
            {"kind": "stp_topology_change", "entity_type": "device"},
            {"kind": "broadcast_storm|mac_move_spike"},
            {"kind": "device_resource_anomaly|if_util_high", "optional": True},
        ],
        "required_modalities": ["control_plane"],
        "discriminators": [
            # A contained TC event without storm load is the existing TC family.
            {"absent": {"kind": "link_state_change"}, "within_s": 300,
             "else_prefer": "sig.ent.access.stp-topology-change"},
        ],
        "direction_expect": "l2-loop -> bridge-domain -> site/vlan-meltdown",
        "verdict": {
            "owner": "netops", "layer": "L2 (STP/loop)",
            "first_steps": [
                "Check STP change logs, root changes and storm-control counters",
                "Measure MAC move rate and broadcast pps against baseline",
                "Hunt the loop source: recent cabling, unmanaged switch, NIC bridging",
            ],
        },
        "operator_phrase": "Sudden L2 instability is consistent with an STP loop or broadcast storm — TC churn plus abnormal broadcast/MAC-move load in one bridge domain.",
        "manager_phrase": "A local network switching event is overwhelming normal traffic handling.",
        "blast_radius": "the affected VLAN/site bridge domain",
        "false_positives": ["maintenance reconvergence", "mass vMotion"],
    },
    {
        "id": "sig.ent.security.fw-aa-session-owner-mismatch",
        # tracker 157 — an active/active firewall pair; attested by the
        # fw_session_owner_mismatch / fw_ha_sync_fail kinds.
        "requires_structure": ["redundancy_group"],
        "title": "Firewall active/active session-owner mismatch",
        "domain": "ent.security",
        "seams": ["LAN", "WAN_SDWAN", "DC_FABRIC", "CLOUD_APP"],
        "deployment_scope": "hybrid",
        "requires": [
            {"kind": "fw_session_owner_mismatch|fw_ha_sync_fail", "entity_type": "device"},
            {"kind": "flow_asymmetry|fw_session_drop"},
        ],
        "required_modalities": ["control_plane"],
        "discriminators": [
            # A role CHANGE (failover) is the drift family; here both stay active.
            {"absent": {"kind": "fw_ha_state_change"}, "within_s": 300,
             "else_prefer": "sig.ent.security.fw-ha-failover-drift"},
        ],
        "direction_expect": "cluster-members -> session-ownership -> asymmetric-flows",
        "verdict": {
            "owner": "netops", "layer": "L4 (firewall cluster state)",
            "first_steps": [
                "Verify session-owner selection and sync health across the active/active members",
                "Check whether forward and return flows land on different members without synchronized state",
                "Review upstream/downstream steering (ECMP/LAG hashing) into the cluster",
            ],
        },
        "operator_phrase": "This looks like active/active session ownership or synchronization mismatch — one direction succeeds while flows pinned to the other member drop.",
        "manager_phrase": "Traffic is crossing a clustered firewall path in a way the cluster is not tracking correctly.",
        "blast_radius": "flows hashed across the misaligned cluster members",
        "false_positives": ["upstream route asymmetry without a firewall issue", "host stateful filter"],
    },
    {
        "id": "sig.ent.security.proxy-pac-wpad-failure",
        "title": "Proxy PAC/WPAD distribution failure",
        "domain": "ent.security",
        "seams": ["WAN_SDWAN", "CLOUD_APP"],
        "deployment_scope": "hybrid",
        "requires": [
            {"kind": "pac_fetch_fail|wpad_lookup_fail", "entity_type": "service"},
            {"kind": "synthetic_http_fail|app_error_rate_high"},
        ],
        "required_modalities": ["control_plane"],
        "discriminators": [
            # The proxy itself being down is the egress-outage family.
            {"absent": {"kind": "proxy_fail|swg_health_degraded"}, "within_s": 300,
             "else_prefer": "sig.ent.security.proxy-swg-egress-failure"},
        ],
        "direction_expect": "pac/wpad-delivery -> client-proxy-config -> saas-paths",
        "verdict": {
            "owner": "netops", "layer": "L7 (proxy discovery)",
            "first_steps": [
                "Validate WPAD resolution and PAC retrieval from an affected client",
                "Check the effective client proxy settings against the intended PAC",
                "Confirm the proxy itself is healthy (direct proxy test) — delivery is the fault",
            ],
        },
        "operator_phrase": "The proxy infrastructure may be healthy, but PAC or WPAD delivery is not — clients are using wrong or no proxy inconsistently.",
        "manager_phrase": "Users are not getting the right proxy instructions, so traffic is taking inconsistent paths.",
        "blast_radius": "clients depending on the failed PAC/WPAD path",
        "false_positives": ["browser cache", "client VPN split tunnel"],
    },
    {
        "id": "sig.ent.cloud.private-dns-ruleset-gap",
        "title": "Private DNS forwarding ruleset gap",
        "domain": "ent.cloud",
        "seams": ["CLOUD_APP", "CARRIER_INTERCONNECT"],
        "deployment_scope": "hybrid",
        "requires": [
            {"kind": "dns_forward_ruleset_gap", "entity_type": "service"},
            {"kind": "fqdn_probe_fail|synthetic_http_fail"},
            {"kind": "cloud_change", "optional": True},
        ],
        "required_modalities": ["control_plane"],
        "discriminators": [
            # Recursion/bouncing between resolvers is the forwarding-LOOP family.
            {"absent": {"kind": "dns_forwarding_loop"}, "within_s": 300,
             "else_prefer": "sig.ent.cloud.private-dns-forwarding-loop"},
        ],
        "direction_expect": "forwarding-ruleset -> private-zone-resolution -> app-dependencies",
        "verdict": {
            "owner": "netops", "layer": "L7 (cloud DNS forwarding)",
            "first_steps": [
                "Verify the resolver ruleset links and suffix rules for the affected VNet/VPC",
                "Confirm public names resolve while ONLY private-zone names fail",
                "Check reachability from the intended network to the forwarding targets",
            ],
        },
        "operator_phrase": "Private-name failure fits a forwarding-ruleset or link gap more than a resolver outage — public resolution works, the ruleset link is missing.",
        "manager_phrase": "Cloud systems are not forwarding certain private DNS requests to the right place.",
        "blast_radius": "private-zone lookups from the unlinked networks",
        "false_positives": ["missing private zone record", "security rule blocking DNS"],
    },
    {
        "id": "sig.ent.cloud.lb-probe-semantics-mismatch",
        "title": "LB health-check protocol / host-header mismatch",
        "domain": "ent.cloud",
        "seams": ["CLOUD_APP"],
        "deployment_scope": "hybrid",
        "requires": [
            {"kind": "lb_probe_semantics_mismatch", "entity_type": "service"},
            {"kind": "lb_target_unhealthy"},
            {"kind": "config_change", "optional": True},
        ],
        "required_modalities": ["control_plane"],
        "discriminators": [
            # Probes DENIED before evaluation is the source-blocked family.
            {"absent": {"kind": "cloud_flow_reject|fw_probe_denied"}, "within_s": 300,
             "else_prefer": "sig.ent.cloud.lb-probe-source-blocked"},
            # Backends genuinely failing is the target-health family.
            {"absent": {"kind": "app_error_rate_high|synthetic_http_fail"}, "within_s": 300,
             "else_prefer": "sig.ent.app.lb-target-health-failure"},
        ],
        "direction_expect": "probe-definition -> health-evaluation -> pool-state",
        "verdict": {
            "owner": "app_team", "layer": "L7 (probe semantics)",
            "first_steps": [
                "Compare the probe's Host header, protocol, path and port with backend vhost expectations",
                "Confirm the backend answers a DIRECT request shaped like real traffic",
                "Check named-port/target-port mappings after recent changes",
            ],
        },
        "operator_phrase": "The backend is healthy directly, but the load balancer's probe semantics (host header, protocol, path or port) do not match backend expectations.",
        "manager_phrase": "The backends work, but the platform health checks are asking the wrong question.",
        "blast_radius": "the pool behind the mis-probed VIP",
        "false_positives": ["real backend latency", "DNS failure to the backend name"],
    },
    {
        "id": "sig.ent.cloud.lb-snat-hotspot-imbalance",
        "title": "LB SNAT hot-spot imbalance",
        "domain": "ent.cloud",
        "seams": ["CLOUD_APP"],
        "deployment_scope": "cloud_only",
        "requires": [
            {"kind": "snat_member_hotspot", "entity_type": "service"},
            {"kind": "app_conn_fail|flow_timeout"},
        ],
        "required_modalities": ["control_plane"],
        "discriminators": [
            # Uniform exhaustion is the NAT-capacity family.
            {"absent": {"kind": "nat_alloc_fail|cloud_nat_alloc_fail"}, "within_s": 300,
             "else_prefer": "sig.ent.security.nat-snat-exhaustion"},
        ],
        "direction_expect": "member-snat-allocation -> outbound-flows -> dependencies",
        "verdict": {
            "owner": "app_team", "layer": "L4 (SNAT distribution)",
            "first_steps": [
                "Check per-instance/member SNAT port metrics — the fault is a skew, not a global ceiling",
                "Measure connection distribution across the pool for hot-spotting",
                "Consider outbound rules/NAT gateway or rebalancing before scaling everything",
            ],
        },
        "operator_phrase": "Outbound failures are concentrated on specific backend members, which fits SNAT hot-spot imbalance rather than pool-wide exhaustion.",
        "manager_phrase": "Only part of the backend pool is running out of outbound connection capacity.",
        "blast_radius": "outbound flows from the hot-spotted members",
        "false_positives": ["destination throttling", "app connection pool bug"],
    },
    {
        "id": "sig.ent.security.waf-body-limit-block",
        "title": "WAF body-inspection-limit block",
        "domain": "ent.security",
        "seams": ["CLOUD_APP"],
        "deployment_scope": "hybrid",
        "requires": [
            {"kind": "waf_body_limit_hit|waf_oversize_block", "entity_type": "service"},
            {"kind": "synthetic_http_fail|app_error_rate_high"},
        ],
        "required_modalities": ["control_plane"],
        "discriminators": [
            # Rule-match blocks without a size boundary are the false-positive family.
            {"absent": {"kind": "waf_block_spike"}, "within_s": 300,
             "else_prefer": "sig.ent.security.waf-rule-false-positive"},
        ],
        "direction_expect": "inspection-limit -> large-requests -> uploads/apis",
        "verdict": {
            "owner": "app_team", "layer": "L7 (WAF inspection limits)",
            "first_steps": [
                "Check the WAF body-size limit and oversize-handling action",
                "Confirm ONLY requests above the threshold fail (small POSTs pass)",
                "Review the request-size distribution against the failing endpoints",
            ],
        },
        "operator_phrase": "The WAF behavior is size-boundary or oversize-handling related, not a generic false positive — failures cluster at a body-size threshold.",
        "manager_phrase": "Larger requests are failing because the security inspection boundary is being hit.",
        "blast_radius": "uploads/API calls above the inspection threshold",
        "false_positives": ["app upload limit", "client timeout"],
    },
]
BUILTIN_TEMPLATES.extend(WAVE3_TEMPLATES)

# Wave-3 backlog (7 new disabled families).
W3_BACKLOG_TEMPLATES: list[dict] = [
    {
        "id": f"sig.{sid}", "title": title, "domain": domain, "enabled": False,
        "seams": list(seams), "deployment_scope": scope, "demo_priority": "p2",
        "requires": [{"kind": req} for req in reqs],
        "requires_structure": _BACKLOG_STRUCTURE.get(sid, []),
        "required_modalities": list(mods),
        "direction_expect": "", "verdict": {"owner": owner, "layer": layer, "first_steps": list(steps)},
        "operator_phrase": op, "manager_phrase": mgr,
    }
    for (sid, title, domain, seams, scope, reqs, mods, owner, layer, steps, op, mgr) in [
        ("ent.wan-edge.qos-marking-mismatch", "QoS marking/classification mismatch", "ent.wan-edge",
         ("WAN_SDWAN", "CARRIER_INTERCONNECT"), "hybrid",
         ("dscp_marking_mismatch", "probe_rtt_anomaly|app_latency_high"), ("control_plane",), "netops", "L2/L3 (QoS marking)",
         ("Compare DSCP markings and queue assignment before/after the WAN edge", "Check for provider or policy remarking"),
         "The impact pattern fits QoS marking or classification mismatch more than raw bandwidth exhaustion.",
         "Priority traffic is being handled incorrectly even though the circuit is still available."),
        ("ent.wan-edge.route-preference-leak", "Route preference leak / wrong egress", "ent.wan-edge",
         ("WAN_SDWAN", "CARRIER_INTERCONNECT", "CLOUD_APP"), "hybrid",
         ("route_selection_changed", "flow_egress_unexpected|path_change"), ("control_plane",), "netops", "L3 (route preference)",
         ("Compare effective/learned routes and path selection before vs after impact", "Check metric/preference changes"),
         "Routing preference has shifted traffic onto an unintended egress path while connectivity still exists.",
         "Traffic is taking the wrong path even though connectivity still exists."),
        ("ent.cloud.kube-proxy-rules-desync", "kube-proxy service rules desync", "ent.cloud",
         ("DC_FABRIC", "CLOUD_APP"), "hybrid",
         ("kube_proxy_desync", "k8s_event"), ("control_plane",), "app_team", "L4 (service proxy)",
         ("Inspect kube-proxy logs and node service rules on affected nodes", "Confirm endpoints exist and pods answer directly"),
         "Service backends exist, but the node service-proxy path appears out of sync — VIP fails while pod IPs answer.",
         "The application instances are healthy, but the cluster routing layer is not forwarding to them correctly."),
        ("ent.cloud.csi-volume-attach-conflict", "CSI volume attach/mount conflict", "ent.cloud",
         ("DC_FABRIC", "CLOUD_APP"), "hybrid",
         ("volume_attach_fail", "k8s_pod_pending|k8s_event"), ("control_plane",), "app_team", "storage (attach path)",
         ("Check VolumeAttachment objects, access mode and current holder", "Review CSI controller errors"),
         "The failure is at volume attach or mount time, not in the service network path.",
         "The workload cannot start because its storage attachment is failing."),
        ("ent.security.fw-zone-binding-drift", "Firewall zone/interface binding policy drift", "ent.security",
         ("LAN", "WAN_SDWAN", "DC_FABRIC", "CLOUD_APP"), "hybrid",
         ("fw_zone_binding_mismatch|fw_policy_mismatch", "config_change"), ("control_plane",), "netops", "L4 (policy context)",
         ("Compare policy and zone bindings before/after the interface or path change", "Check policy hit-count shifts"),
         "Policy or zone binding on the firewall does not match the current traffic path after a change.",
         "The traffic is hitting the wrong security policy context after a path or interface change."),
        ("ent.security.tls-inspection-trust-break", "TLS inspection trust break", "ent.security",
         ("WAN_SDWAN", "CLOUD_APP"), "hybrid",
         ("tls_inspection_trust_fail", "synthetic_http_fail|app_error_rate_high"), ("control_plane",), "netops", "L6 (middlebox trust)",
         ("Compare bypass vs inspected behavior for the same destinations", "Verify client trust of the inspection CA"),
         "HTTPS failure aligns with TLS inspection trust rather than the server certificate itself — bypass succeeds, inspected fails.",
         "Secure web traffic is failing because the inspection layer is not trusted correctly."),
        ("ent.cloud.private-dns-zone-shadow", "Overlapping private DNS zone shadowing", "ent.cloud",
         ("CLOUD_APP",), "cloud_only",
         ("dns_zone_shadowing", "dns_answer_mismatch"), ("control_plane",), "netops", "L7 (zone precedence)",
         ("Map overlapping zones and confirm which suffix wins per query path", "Compare answers across resolver paths"),
         "Overlapping private zones appear to be shadowing the intended DNS answer — different paths return different records.",
         "A cloud DNS precedence issue is sending requests to the wrong internal name target."),
    ]
]
BUILTIN_TEMPLATES.extend(W3_BACKLOG_TEMPLATES)

# Wave-3 backlog promotions (owner P0): these wave-2 backlog families are
# enabled now; the ExpressRoute entry gains the owner's hard-required VLAN/
# MACsec parity evidence (vendor-subtype rule: a provider variant must add a
# unique required signal). The jumbo-MTU family gets a probe alternative so
# its evidence contract is disjoint from the campus PMTUD family.
_WAVE3_PROMOTED = {
    "sig.ent.access.pmtud-blackhole",
    "sig.ent.middle-mile.interconnect-jumbo-mtu-mismatch",
    "sig.ent.middle-mile.expressroute-arp-unresolved",
}
for _t in W2_BACKLOG_TEMPLATES:
    if _t["id"] in _WAVE3_PROMOTED:
        _t["enabled"] = True
        _t["demo_priority"] = "p0"
        if _t["id"] == "sig.ent.middle-mile.expressroute-arp-unresolved":
            _t["requires"].append({"kind": "macsec_or_vlan_mismatch", "optional": True})
        if _t["id"] == "sig.ent.middle-mile.interconnect-jumbo-mtu-mismatch":
            _t["requires"] = [{"kind": "size_dependent_loss"}, {"kind": "tcp_retransmit_high|probe_loss"}]

# ---------------------------------------------------------------------------
# Port Intelligence / Physical-Layer catalog (#94, owner design
# docs/design/port-intelligence.md). SP/DC optics + fiber-path fault families
# for DC and carrier handoff. Every entry is PHYSICAL-LAYER: look-alikes are
# rampant (dirty fiber vs bad optic vs polarity vs FEC masking), so ALL carry
# allow_root_cause_confirmed=False — the scorer caps them at suspected until
# fiber-path validation or human corroboration lifts them (owner rule: no
# confirmed root cause without ≥2 independent modalities + path grounding).
# domain "ent.spdc" (service-provider / datacenter physical layer).
#
# Compact builder: (id-suffix, name, seams, scope, [required kinds],
# [supporting kinds], [contradicting kinds], required_modalities, owner, layer,
# score_impact, [first_steps/next_checks], operator_phrase, manager_phrase).
_SPDC: list[tuple] = [
    ("mpo-polarity-mismatch", "MPO polarity (Type A/B/C) mismatch",
     ("DC_FABRIC", "CARRIER_INTERCONNECT"), "onprem_only",
     ["mpo_polarity_mismatch", "link_down_no_light"], ["fiber_path_polarity_conflict", "tx_present_rx_absent"],
     ["dom_rx_power_normal", "link_up_stable"], ["device_telemetry"], "colo_provider", "L1 (fiber polarity)",
     "fiber-path consistency",
     ["Check the polarity method (Type A/B/C) recorded for the jumper/cassette path against the endpoints",
      "Confirm TX is present at one end while RX is dark at the other (crossed polarity fingerprint)",
      "Swap to the correct polarity cassette/jumper or a polarity-B patch and re-verify light"],
     "Suspected MPO polarity mismatch — one end transmits but the far-end RX sees no light, consistent with a Type A/B/C polarity error on the multifiber path.",
     "The fiber connection appears mis-wired at the connector level, so the link cannot come up despite good optics."),
    ("mpo-pinout-gender-mismatch", "MPO pinout / connector gender mismatch",
     ("DC_FABRIC",), "onprem_only",
     ["mpo_gender_mismatch", "link_down_no_light"], ["connector_pinout_conflict"],
     ["dom_rx_power_normal"], ["device_telemetry"], "colo_provider", "L1 (connector gender)",
     "fiber-path consistency",
     ["Verify male/female pin-and-socket gender at each MPO junction against the cassette design",
      "Check for a missing or extra coupler that flips gender",
      "Insert the correct-gender adapter or jumper and re-test"],
     "Suspected MPO pinout/gender mismatch — the connector pairing looks physically incompatible, so no light passes.",
     "The connector types at the ends of the cable do not match, preventing the link from establishing."),
    ("mpo-row-flip", "MPO row flip (2-row MPO16/32 mis-seat)",
     ("DC_FABRIC",), "onprem_only",
     ["mpo_row_flip", "lane_group_dark"], ["parallel_lane_map_anomaly"],
     ["all_lanes_normal"], ["device_telemetry"], "colo_provider", "L1 (multifiber rows)",
     "fiber-path consistency",
     ["Check whether an upper/lower row of a 2-row MPO is flipped (top lanes dark, bottom light or vice-versa)",
      "Compare the parallel-optic lane map against the expected row assignment",
      "Re-seat with correct row orientation"],
     "Suspected MPO row flip — one row of lanes is dark while the other is healthy, matching a flipped 2-row MPO seating.",
     "Part of the cable's fibers are connected in the wrong position, so only some channels work."),
    ("mpo-missing-fibers", "MPO missing / unpopulated fibers",
     ("DC_FABRIC", "CARRIER_INTERCONNECT"), "onprem_only",
     ["mpo_missing_fibers", "lane_rx_absent_subset"], ["parallel_lane_map_anomaly", "fiber_path_strand_count_low"],
     ["all_lanes_normal"], ["device_telemetry"], "colo_provider", "L1 (fiber count)",
     "fiber-path consistency",
     ["Identify which specific lanes/strands have no RX light",
      "Check whether the jumper is a lower-count MPO than the optic needs (e.g. MPO-8 into an MPO-12 breakout)",
      "Replace with the correct fiber-count assembly"],
     "Suspected missing fibers on the multifiber path — a specific subset of lanes has no light while others are fine.",
     "Some strands of the cable are not connected, so only part of the link's capacity is usable."),
    ("mpo-dirty-multifiber", "Dirty multifiber endface",
     ("DC_FABRIC", "CARRIER_INTERCONNECT"), "hybrid",
     ["dom_rx_power_low", "fec_corrected_rate_high"], ["rx_margin_low", "endface_contamination_suspected", "multiple_lanes_marginal"],
     ["dom_rx_power_normal", "single_lane_only"], ["device_telemetry"], "colo_provider", "L1 (endface cleanliness)",
     "DOM absolute thresholds",
     ["Inspect and clean the MPO endface (contamination hits multiple lanes together)",
      "Compare RX power across lanes — uniform low across the group points to a dirty ferrule",
      "Re-measure RX and pre-FEC BER after cleaning"],
     "Suspected dirty multifiber endface — RX power is uniformly low across lanes with rising corrected-FEC, the classic contamination pattern.",
     "The fiber connector appears dirty, weakening the signal across several channels at once."),
    ("mpo-broken-strand", "Broken / high-loss individual strand",
     ("DC_FABRIC", "CARRIER_INTERCONNECT"), "hybrid",
     ["single_lane_rx_absent", "lane_divergence_high"], ["lane_group_others_normal", "fiber_path_strand_fault"],
     ["all_lanes_low_uniform"], ["device_telemetry"], "colo_provider", "L1 (single strand)",
     "lane symmetry/divergence",
     ["Identify the single lane with absent/very-low RX while its group-mates are healthy",
      "Trace that strand through the panel/cassette/jumper path",
      "Replace the affected jumper or strand and re-verify"],
     "Suspected broken or high-loss strand — one lane is dark while its group-mates are healthy, isolating a single-fiber fault.",
     "One fiber within the cable appears damaged, degrading part of the connection."),
    ("mpo-cassette-type-mismatch", "MPO cassette type mismatch",
     ("DC_FABRIC",), "onprem_only",
     ["cassette_type_mismatch", "link_down_no_light|lane_group_dark"], ["fiber_path_polarity_conflict"],
     ["link_up_stable"], ["device_telemetry"], "colo_provider", "L1 (cassette)",
     "fiber-path consistency",
     ["Compare the installed cassette type against the polarity method the path requires",
      "Check for a Method-A cassette where Method-B is needed (or reversed)",
      "Swap to the matching cassette and re-verify"],
     "Suspected cassette type mismatch — the cassette's polarity method conflicts with the path design, breaking the light path.",
     "The connector module in the patch panel is the wrong type for this cabling scheme."),
    ("patchpanel-crossconnect-error", "Patch-panel cross-connect error",
     ("DC_FABRIC", "CARRIER_INTERCONNECT"), "onprem_only",
     ["crossconnect_endpoint_mismatch", "neighbor_unexpected|link_down_no_light"], ["lldp_neighbor_mismatch", "fiber_path_endpoint_conflict"],
     ["neighbor_as_designed"], ["control_plane"], "colo_provider", "L1 (cross-connect)",
     "fiber-path consistency",
     ["Compare the discovered neighbor against the cross-connect record for this port",
      "Trace the panel A-side/Z-side assignment for a mis-patch",
      "Re-patch to the designed endpoint and confirm the expected neighbor"],
     "Suspected patch-panel cross-connect error — the port reaches an unexpected neighbor (or none), matching a mis-patched cross-connect.",
     "The cabling appears connected to the wrong destination in the patch panel."),
    ("patchpanel-label-drift", "Patch-panel label / documentation drift",
     ("DC_FABRIC", "CARRIER_INTERCONNECT"), "hybrid",
     ["label_record_conflict"], ["lldp_neighbor_mismatch", "circuit_id_conflict"],
     ["records_match_discovery"], ["control_plane"], "netops", "L1 (records)",
     "fiber-path consistency",
     ["Compare the discovered neighbor/circuit against the documented panel label",
      "Flag the record for reconciliation (documentation drift, not necessarily a live fault)",
      "Update the source of truth once the physical path is confirmed"],
     "Suspected patch-panel label drift — discovery disagrees with the documented panel/circuit record; the physical path may be fine but the records are stale.",
     "The cabling documentation no longer matches what is actually connected."),
    ("parallel-optic-lane-swap", "Parallel-optic lane swap",
     ("DC_FABRIC",), "onprem_only",
     ["lane_map_swapped", "pcs_deskew_fault|lane_group_dark"], ["parallel_lane_map_anomaly"],
     ["lane_map_as_designed"], ["device_telemetry"], "colo_provider", "L1 (lane mapping)",
     "lane symmetry/divergence",
     ["Compare the received lane map against the expected TX→RX lane assignment",
      "Check for a jumper that swaps lane order within the parallel optic",
      "Correct the lane mapping / jumper and re-verify PCS alignment"],
     "Suspected parallel-optic lane swap — the received lane order does not match the expected map, consistent with a swapped multifiber assignment.",
     "The individual channels in a parallel optical link are connected in the wrong order."),
    ("pam4-lane-skew-excessive", "PAM4 excessive lane skew",
     ("DC_FABRIC", "CARRIER_INTERCONNECT"), "hybrid",
     ["pam4_lane_skew_high", "pcs_deskew_fault"], ["lane_divergence_high", "fec_corrected_rate_high"],
     ["lanes_aligned"], ["device_telemetry"], "netops", "L1/PCS (PAM4 skew)",
     "PCS/deskew/fault indicators",
     ["Check per-lane skew against the PCS deskew budget",
      "Compare fiber-path lengths per lane (skew grows with length delta)",
      "Verify the optic and host both support the lane count/skew envelope"],
     "Suspected excessive PAM4 lane skew — inter-lane skew exceeds the deskew budget with PCS deskew faults, so lanes cannot re-align.",
     "The high-speed channels are arriving too far out of step with each other for the link to stay clean."),
    ("pam4-lane-ber-divergence", "PAM4 per-lane BER divergence",
     ("DC_FABRIC", "CARRIER_INTERCONNECT"), "hybrid",
     ["pam4_lane_ber_divergence", "fec_corrected_rate_high"], ["lane_divergence_high", "rx_margin_low"],
     ["lanes_ber_uniform"], ["device_telemetry"], "netops", "PCS (PAM4 BER)",
     "FEC/BER behavior",
     ["Compare pre-FEC BER per lane — one or two lanes far worse than the rest is the tell",
      "Correlate the bad lane(s) with a specific fiber strand or optic lane",
      "Decide optic swap vs strand repair from which lanes diverge"],
     "Suspected PAM4 per-lane BER divergence — specific lanes carry far higher pre-FEC BER than their peers, isolating a per-lane optical or strand fault.",
     "Some of the high-speed channels are much noisier than others, pointing to a localized optical problem."),
    ("qsfpdd-single-lane-failure", "QSFP-DD single-lane failure",
     ("DC_FABRIC",), "onprem_only",
     ["single_lane_rx_absent|single_lane_tx_fail", "lane_group_others_normal"], ["dom_lane_bias_anomaly", "fec_corrected_rate_high"],
     ["all_lanes_normal"], ["device_telemetry"], "netops", "L1 (QSFP-DD lane)",
     "lane symmetry/divergence",
     ["Identify the single failed lane within the 8-lane QSFP-DD while others pass",
      "Check per-lane TX bias/power for a dead laser vs a fiber-side fault",
      "Replace the module if the fault is optic-internal (laser/driver), else trace the strand"],
     "Suspected QSFP-DD single-lane failure — one lane of the module is down while the rest are healthy, pointing at a per-lane optic or strand fault.",
     "One channel inside a high-density optic has failed, reducing the link's capacity."),
    ("osfp-incompatible-part", "OSFP incompatible / unsupported part",
     ("DC_FABRIC",), "onprem_only",
     ["transceiver_unsupported", "link_flap_on_insert|link_down_no_light"], ["part_number_not_qualified", "firmware_incompatible"],
     ["transceiver_supported"], ["device_telemetry"], "netops", "inventory (OSFP compat)",
     "inventory/config compatibility",
     ["Check the OSFP part number/OUI against the platform's qualified-optics list",
      "Look for insert-time flaps or vendor-lock rejection in logs",
      "Swap to a supported/qualified part before deeper optical debugging"],
     "Suspected incompatible OSFP part — the transceiver is unqualified for this platform, matching insert-time flaps or refusal to link.",
     "The installed optic is not a supported model for this device, which can cause unstable or failed links."),
    ("high-power-module-thermal-throttle", "High-power module thermal throttle",
     ("DC_FABRIC",), "onprem_only",
     ["dom_temperature_high", "fec_corrected_rate_high|link_flap"], ["thermal_margin_low", "dom_lane_bias_anomaly"],
     ["dom_temperature_normal"], ["device_telemetry"], "netops", "thermal (module)",
     "thermal/power envelope",
     ["Check module temperature against the high-warn threshold and airflow/slot cooling",
      "Correlate throttle/flap events with the temperature climb",
      "Improve cooling or move the high-power module to a better-cooled slot"],
     "Suspected high-power module thermal throttle — module temperature is near/over threshold with correlated FEC/flap degradation.",
     "A high-power optic is overheating, which is degrading the link until it cools."),
    ("fec-masking-highspeed", "FEC masking a degrading high-speed link",
     ("DC_FABRIC", "CARRIER_INTERCONNECT"), "hybrid",
     ["fec_corrected_rate_high", "prefec_ber_rising"], ["rx_margin_low", "postfec_ber_watch"],
     ["fec_corrected_rate_baseline"], ["device_telemetry"], "netops", "FEC (masking)",
     "FEC/BER behavior",
     ["Compare corrected-FEC rate and pre-FEC BER against baseline (rising corrected count = FEC working harder)",
      "Confirm post-FEC BER is still clean — FEC is masking, not yet failing",
      "Schedule optic/fiber remediation before pre-FEC crosses the uncorrectable threshold"],
     "Likely FEC masking a degrading link — corrected-FEC and pre-FEC BER are climbing while post-FEC stays clean; the link looks healthy but headroom is eroding.",
     "The link still works, but the error-correction is doing increasingly heavy lifting, so it is trending toward failure."),
    ("pcs-lane-deskew-failure", "PCS lane deskew failure",
     ("DC_FABRIC", "CARRIER_INTERCONNECT"), "hybrid",
     ["pcs_deskew_fault", "pcs_local_fault|pcs_remote_fault"], ["lane_divergence_high", "hi_ber_indication"],
     ["pcs_aligned"], ["device_telemetry"], "netops", "PCS (deskew)",
     "PCS/deskew/fault indicators",
     ["Check PCS alignment-marker/deskew status and local/remote fault indicators",
      "Correlate with lane skew or a hi-BER lane that breaks alignment",
      "Address the underlying lane skew/BER; PCS recovers once lanes re-align"],
     "Suspected PCS lane deskew failure — the PCS cannot align lanes (deskew fault with local/remote fault), so the logical link stays down despite lit lanes.",
     "The link's channels cannot be re-synchronized into one logical connection, so traffic will not pass."),
    ("dwdm-mux-demux-attenuation", "DWDM mux/demux attenuation",
     ("CARRIER_INTERCONNECT",), "hybrid",
     ["dom_rx_power_low", "mux_demux_insertion_loss_high"], ["fiber_path_budget_exceeded", "channel_specific_loss"],
     ["dom_rx_power_normal"], ["device_telemetry"], "carrier", "L1 (DWDM mux/demux)",
     "DOM absolute thresholds",
     ["Compare RX power against the path budget across the mux/demux stage",
      "Check whether loss is channel-specific (filter port) vs common (fiber)",
      "Engage the DWDM/line-system owner with the per-channel loss deltas"],
     "Suspected DWDM mux/demux attenuation — RX power is low with high insertion loss across the mux/demux stage, exceeding the path budget.",
     "The wavelength multiplexing equipment is weakening the signal beyond the design budget."),
    ("channel-frequency-misalignment", "Channel frequency / grid misalignment",
     ("CARRIER_INTERCONNECT",), "hybrid",
     ["carrier_freq_offset_high", "coherent_osnr_low|dom_rx_power_low"], ["optical_frequency_mismatch", "channel_specific_loss"],
     ["carrier_freq_aligned"], ["device_telemetry"], "carrier", "L1 (optical grid)",
     "coherent PM",
     ["Compare the transceiver's optical frequency/offset against the assigned DWDM channel",
      "Check for a wrong tuned channel or grid (50/75/100 GHz) mismatch vs the filter",
      "Retune to the assigned channel and re-verify OSNR/RX"],
     "Suspected channel frequency misalignment — the carrier frequency offset is high against the assigned grid channel, degrading OSNR/RX through the filter.",
     "The optical channel is tuned off its assigned frequency, so it is being filtered/attenuated by the line system."),
    ("roadm-filter-edge-impairment", "ROADM filter-edge impairment",
     ("CARRIER_INTERCONNECT",), "hybrid",
     ["roadm_filter_edge_penalty", "coherent_osnr_low|prefec_ber_rising"], ["carrier_freq_offset_high", "channel_specific_loss"],
     ["coherent_osnr_normal"], ["device_telemetry"], "carrier", "L1 (ROADM filtering)",
     "coherent PM",
     ["Check whether the channel sits near a ROADM filter edge (narrowing/cascaded-filter penalty)",
      "Correlate OSNR/pre-FEC degradation with the channel's grid position",
      "Recenter the channel or widen the passband with the line-system owner"],
     "Suspected ROADM filter-edge impairment — the channel is being penalized near a filter edge, degrading OSNR and pre-FEC through cascaded ROADMs.",
     "The optical channel is sitting at the edge of a filter in the transport network, degrading its quality."),
    ("edfa-saturation-or-gain-tilt", "EDFA saturation or gain tilt",
     ("CARRIER_INTERCONNECT",), "hybrid",
     ["edfa_gain_tilt|edfa_saturation", "coherent_osnr_low|dom_rx_power_abnormal"], ["multi_channel_power_skew", "amplifier_alarm"],
     ["edfa_gain_flat"], ["device_telemetry"], "carrier", "L1 (amplifier)",
     "DOM absolute thresholds",
     ["Check amplifier gain flatness / tilt and per-channel power skew across the band",
      "Look for saturation (added channels flattening per-channel power) or a tilt fault",
      "Rebalance amplifier gain/tilt with the line-system owner"],
     "Suspected EDFA saturation or gain tilt — per-channel power is skewed across the band with OSNR degradation, matching an amplifier gain/tilt problem.",
     "An optical amplifier in the transport path is not evenly boosting the channels, degrading some wavelengths."),
    ("coherent-osnr-degradation", "Coherent OSNR degradation",
     ("CARRIER_INTERCONNECT",), "hybrid",
     ["coherent_osnr_low", "prefec_ber_rising"], ["coherent_input_power_low", "cd_or_dgd_high", "esnr_low"],
     ["coherent_osnr_normal"], ["device_telemetry", "active_probe"], "carrier", "coherent (OSNR)",
     "coherent PM",
     ["Compare measured OSNR against the mode's min-rx-OSNR margin",
      "Check input power, CD and DGD for a co-degrading cause",
      "Open the line-system ticket with the OSNR/pre-FEC deltas and mode descriptor"],
     "Likely coherent OSNR degradation — measured OSNR is inside its margin with rising pre-FEC BER, so the coherent link is losing optical headroom.",
     "The long-haul optical signal quality is dropping toward the limit the equipment can tolerate."),
    ("cfp-osfp-vendor-interoperability-risk", "CFP/OSFP vendor interoperability risk",
     ("DC_FABRIC", "CARRIER_INTERCONNECT"), "hybrid",
     ["interop_mode_mismatch", "link_flap|prefec_ber_rising"], ["mode_descriptor_mismatch", "vendor_pair_unqualified"],
     ["interop_qualified"], ["device_telemetry"], "netops", "interop (coherent modes)",
     "inventory/config compatibility",
     ["Compare the coherent mode descriptors (baud/modulation/FEC) at both ends",
      "Check whether the two vendors' optics are a qualified interop pair for this mode",
      "Align the operating mode or use a qualified pairing"],
     "Suspected CFP/OSFP vendor interoperability risk — the two ends' coherent mode descriptors do not align, matching an unqualified cross-vendor pairing with flaps/BER.",
     "Optics from different vendors at the two ends may not be fully compatible, causing an unstable link."),
]

def _spdc_template(row: tuple) -> dict:
    (suffix, name, seams, scope, required, supporting, contra, mods,
     owner, layer, score_impact, next_checks, op, mgr) = row
    # Required clauses + the first supporting kind as an optional witness (so the
    # confidence label can reach "likely" and there's a second-modality path).
    requires = [{"kind": k, "optional": False} for k in required]
    if supporting:
        requires.append({"kind": supporting[0], "optional": True})
    return {
        "id": f"sig.ent.spdc.{suffix}", "title": name, "domain": "ent.spdc",
        "seams": list(seams), "deployment_scope": scope, "demo_priority": "p1",
        "allow_root_cause_confirmed": False,  # physical-layer look-alikes — cap at suspected
        "score_impact": score_impact,
        "requires": requires,
        "required_modalities": list(mods),
        "verdict": {"owner": owner, "layer": layer, "first_steps": tuple(next_checks[:5])},
        "next_checks": tuple(next_checks),
        "operator_phrase": op, "manager_phrase": mgr,
        "false_positives": tuple(contra),
        "composition_hints": ("physical-layer incident (attach to the RCA object as supporting/discriminating evidence)",),
    }


SPDC_TEMPLATES: list[dict] = [_spdc_template(r) for r in _SPDC]
BUILTIN_TEMPLATES.extend(SPDC_TEMPLATES)


# ---------------------------------------------------------------------------
# NMS controller-intelligence templates (P4b, design docs/design/nms-integration-
# framework.md). These consume the NORMALIZED controller_* kinds emitted by the
# vendor-controller framework — NEVER per-vendor (a Meraki and a vManage
# tunnel-down are both controller_tunnel_state, so one template covers every
# vendor). Each pairs a controller witness (management_plane, via_controller
# authority) with an OPTIONAL direct-telemetry clause: controller-alone yields
# SUSPECTED (single modality), controller + independent telemetry confirms — the
# "corroborate, don't confirm alone" rule, enforced by the existing gate.
# required_modalities is left empty on purpose: the second corroborating modality
# can be any independent plane (probe/device/control), so the general
# independence gate (≥2 modalities, independent non-fate-shared pair) decides.
# ---------------------------------------------------------------------------
NMS_TEMPLATES: list[dict] = [
    {
        "id": "sig.ent.wan-edge.sdwan-tunnel-controller-corroborated",
        "title": "SD-WAN tunnel fault (controller-witnessed)",
        "domain": "ent.wan-edge",
        "requires": [
            {"kind": "controller_tunnel_state|controller_bfd_down", "entity_type": "path"},
            {"kind": "tunnel_degraded|tunnel_flap|probe_loss|probe_latency_departure",
             "entity_type": "path", "optional": True},
        ],
        "seams": ["WAN_SDWAN"],
        "verdict": {
            "owner": "netops", "layer": "Tunnel/L4",
            "first_steps": [
                "Confirm the controller's tunnel/BFD state against direct path probes (STAMP/loss)",
                "If probes agree, treat as a real overlay fault; if they disagree, the controller view may be stale",
                "Check the underlay transport (color/circuit) carrying the affected tunnel",
            ],
        },
        "operator_phrase": "SD-WAN controller reports tunnel/BFD down on this path",
        "manager_phrase": "The SD-WAN system flagged a site-to-site link problem",
        "false_positives": ("stale controller state after a recovered flap",),
    },
    {
        "id": "sig.ent.wan-edge.controller-change-induced",
        "title": "Change-induced incident (config/policy push then fault)",
        "domain": "ent.wan-edge",
        "requires": [
            {"kind": "controller_policy_change", "entity_type": "device"},
            {"kind": "tunnel_degraded|tunnel_flap|link_state_change|bgp_adjacency_change|probe_loss|if_util_high|device_resource_anomaly",
             "optional": True},
            # The DEVICE's own record of the same push. A controller says it
            # sent a policy; `%SYS-5-CONFIG_I` / `UI_COMMIT` on the box says it
            # landed — and an on-box change with NO controller push is the
            # out-of-band edit this family exists to catch.
            # TRAP observer only today — the syslog half is shadowed (events.yaml).
            {"kind": "device_config_change", "optional": True},
        ],
        "seams": ["WAN_SDWAN"],
        "verdict": {
            "owner": "netops", "layer": "Change/Config",
            "first_steps": [
                "Correlate the controller config/policy/template push time with the fault onset",
                "Review the change (audit log) for scope: which devices/sites/policies it touched",
                "If the fault window follows the push, stage a rollback of the change as mitigation",
            ],
        },
        "operator_phrase": "A controller config/policy push preceded this fault — probable change-induced incident",
        "manager_phrase": "A recent configuration change lines up with the start of this problem",
        "composition_hints": ("what-changed timeline",),
    },
    {
        "id": "sig.ent.campus.controller-device-unreachable",
        "title": "Device unreachable (controller-reported)",
        "domain": "ent.campus",
        "requires": [
            {"kind": "controller_device_unreachable", "entity_type": "device"},
            {"kind": "link_state_change|probe_loss|device_resource_anomaly", "optional": True},
        ],
        "seams": ["LAN", "WAN_SDWAN"],
        "verdict": {
            "owner": "netops", "layer": "Reachability/L3",
            "first_steps": [
                "Confirm the controller's unreachable verdict with a direct probe / link-state check",
                "If direct telemetry agrees, treat as a real outage; if not, suspect a controller polling gap",
                "Check the management path from the controller to the device (it may be a mgmt-plane-only loss)",
            ],
        },
        "operator_phrase": "Controller reports device unreachable",
        "manager_phrase": "A managed device stopped responding to its controller",
        "false_positives": ("controller-to-device management path loss with the device still forwarding",),
    },
]
BUILTIN_TEMPLATES.extend(NMS_TEMPLATES)


# ── external SaaS / application-experience (synthetic Digital-Experience lane) ──
# Keyed on the semantic synthetic_* kinds emitted by synthetic_normalize.py from
# collectors/synthetics.go. A synthetic failure alone satisfies the one required
# clause (coverage 1.0) but is single-modality → SUSPECTED; an independent
# passive-flow collapse or an LB/app 5xx supplies the 2nd modality → CONFIRMED.
# This is EXTERNAL Digital-Experience correlation, not APM (no traces/spans/RUM).
APP_EXPERIENCE_TEMPLATES: list[dict] = [
    {
        "id": "sig.ent.app.saas-experience-degraded",
        "title": "SaaS / application experience degraded (external synthetic)",
        "domain": "ent.app",
        "seams": ["CLOUD_APP"],
        "deployment_scope": "hybrid",
        "demo_priority": "p0",
        "requires": [
            {"kind": "synthetic_http_fail|synthetic_http_5xx|synthetic_http_4xx|"
                     "synthetic_http_latency_high|synthetic_tls_fail|synthetic_dns_fail|"
                     "synthetic_tcp_connect_fail|synthetic_timeout|synthetic_icmp_loss|"
                     "synthetic_tcp_probe_fail"},
            {"kind": "flow_volume_anomaly|lb_5xx|"
                     "lb_target_unhealthy|app_error_rate_high|"
                     # the provider's own resource telemetry (CloudWatch / Azure
                     # Monitor) — independent of our probes and of the app's logs
                     "cloud_resource_anomaly", "optional": True},
            {"kind": "synthetic_cert_expired|synthetic_cert_expiring", "optional": True},
        ],
        "required_modalities": ["active_probe"],
        "discriminators": [
            # A coincident local link-down means the app symptom is collateral of a
            # network fault — defer to it rather than blaming the application.
            {"absent": {"kind": "link_state_change"}, "within_s": 300,
             "else_prefer": "sig.ent.access.local-link-fault"},
        ],
        "direction_expect": "service -> application -> users",
        "verdict": {
            "owner": "app_team", "layer": "L7 (application experience)",
            "first_steps": [
                "Confirm the synthetic failure reason (DNS / TCP / TLS / HTTP status) and the vantage site",
                "Check whether real user traffic to the app collapsed at the same time (flow)",
                "Check the app / load-balancer for 5xx or failing health checks",
            ],
        },
        "operator_phrase": "External synthetic checks to the application are failing from at least one vantage; the reason (DNS/TCP/TLS/HTTP) is classified.",
        "manager_phrase": "Users may be unable to reach this application; we are correlating whether it is the app, the network path, or the provider.",
        "blast_radius": "Users of the affected SaaS/application at the reporting site(s)",
        "false_positives": ("single-vantage local issue", "planned provider maintenance", "client-side DNS/proxy problem"),
    },
]
BUILTIN_TEMPLATES.extend(APP_EXPERIENCE_TEMPLATES)


# ── cloud edge dependency attribution (Wave 3 #9) ─────────────────────────────
# The Service Dependency Map (cloud_dependency.py) ties each edge device — DNS,
# WAF, LB, firewall/subnet — to the application in ONE request path. When an
# app-experience symptom (cloud_health) grounds TOGETHER with an on-path edge
# device's fault (they now share one correlation object via the dependency edge),
# these templates NAME the responsible tier as the probable cause — instead of the
# generic app-dependency-down. They out-rank the generic signature because they
# explain MORE of the evidence (two matched clauses vs one; the scorer's
# specificity tie-break). They fire ONLY when both the impact AND the on-path
# device fault are present in the same object — an OFF-path device fault never
# grounds into the app's object, so it is never (falsely) attributed here.
#
# Honesty of the verdict is delegated to the existing gate, NOT asserted here:
#   * inventory-only dependency edge → rank-6 inferred → object has no
#     authoritative edge → run_window caps the tier at SUSPECTED (named, not
#     confirmed): config says the device fronts the app, but we did not OBSERVE it.
#   * flow-observed dependency edge (authoritative) + an INDEPENDENT witness (a
#     customer/synthetic probe — the cloud API is a single vantage) → CONFIRMED.
# DNS is a NAME dependency, never a data-path hop, so a DNS-attributed verdict
# only leaves 'suspected' when an independent DNS probe corroborates.
CLOUD_EDGE_ATTRIBUTION_TEMPLATES: list[dict] = [
    {
        "id": "sig.ent.app.edge-lb-5xx",
        "title": "Load balancer returning 5xx on the application's edge",
        "domain": "ent.app",
        "seams": ["CLOUD_APP"],
        "deployment_scope": "hybrid",
        "requires": [
            # the impact: the application's experience is degraded.
            {"kind": "cloud_health"},
            # the on-path cause: the LB in front of this app is emitting 5xx.
            {"kind": "cloud_lb_log"},
            # an INDEPENDENT customer/synthetic witness (the cloud API is a single
            # vantage — this second, independent observer is what lifts the verdict off
            # the cloud-only suspected ceiling to CONFIRMED via the independence gate).
            {"kind": "probe_loss|probe_rtt_anomaly|synthetic_icmp_loss|synthetic_http_fail|synthetic_timeout", "optional": True},
        ],
        "direction_expect": "load-balancer -> application -> users",
        "verdict": {
            "owner": "app_team", "layer": "L7 (load balancer / app edge)",
            "first_steps": [
                "Check the load balancer's target group — are any targets healthy, or are all failing health checks?",
                "Read the LB access logs for the 5xx reason (503 no healthy targets vs 504 target timeout)",
                "Confirm the app instances behind the LB are up and passing the LB's health probe",
            ],
        },
        "operator_phrase": "The load balancer on this application's edge is returning 5xx, and it sits on the application's request path — the LB (or its targets) is the probable cause of the degraded experience.",
        "manager_phrase": "The gateway that routes users to this application is failing, so users are seeing errors; we have localised it to the load-balancer tier.",
        "blast_radius": "All users reaching the application through this load balancer",
        "false_positives": ("a brief target-group flap during a deploy", "a single unhealthy target with the rest serving"),
    },
    {
        "id": "sig.ent.app.edge-waf-block",
        "title": "WAF blocking legitimate traffic to the application",
        "domain": "ent.app",
        "seams": ["CLOUD_APP"],
        "deployment_scope": "hybrid",
        "requires": [
            {"kind": "cloud_health"},
            # the on-path cause: the web ACL in front of this app is BLOCKing.
            {"kind": "cloud_waf_log"},
            # an INDEPENDENT customer/synthetic witness (the cloud API is a single
            # vantage — this second, independent observer is what lifts the verdict off
            # the cloud-only suspected ceiling to CONFIRMED via the independence gate).
            {"kind": "probe_loss|probe_rtt_anomaly|synthetic_icmp_loss|synthetic_http_fail|synthetic_timeout", "optional": True},
        ],
        "direction_expect": "waf -> application -> users",
        "verdict": {
            "owner": "netops", "layer": "L7 (WAF / app edge)",
            "first_steps": [
                "Identify the terminating WAF rule driving the blocks (rule id + sample URI on the evidence)",
                "Check CloudTrail / change history for a recent WAF rule or rule-group change in the window",
                "Move the offending rule to COUNT to confirm it is eating legitimate traffic, then tune it",
            ],
        },
        "operator_phrase": "The web application firewall on this application's edge is blocking requests on the app's request path — a WAF rule is the probable cause of the degraded experience.",
        "manager_phrase": "A security filter in front of this application is rejecting legitimate users; we have localised it to the WAF tier.",
        "blast_radius": "Users whose requests match the blocking WAF rule",
        "false_positives": ("a genuine attack the WAF is correctly blocking", "a noisy scanner inflating block counts"),
    },
    {
        "id": "sig.ent.app.edge-firewall-reject",
        "title": "Security group / NACL rejecting traffic to the application",
        "domain": "ent.app",
        "seams": ["CLOUD_APP"],
        "deployment_scope": "hybrid",
        "requires": [
            {"kind": "cloud_health"},
            # the on-path cause: a boundary REJECT (SG/NACL drop) into the app.
            {"kind": "cloud_flow_log"},
            # an INDEPENDENT customer/synthetic witness (the cloud API is a single
            # vantage — this second, independent observer is what lifts the verdict off
            # the cloud-only suspected ceiling to CONFIRMED via the independence gate).
            {"kind": "probe_loss|probe_rtt_anomaly|synthetic_icmp_loss|synthetic_http_fail|synthetic_timeout", "optional": True},
        ],
        # Look-alike killer: a DX/VPN/route state change (cloud_change on a cloud
        # resource) in the window means the boundary REJECT is the private-
        # connectivity outage's SYMPTOM — routes withdrew, so the boundary drops
        # what it can no longer deliver — not an SG/NACL misconfiguration. That
        # story belongs to private-connectivity-down (same guard app-dependency-
        # down carries): this template is contradicted and the connectivity
        # signature is scored as the forced competitor.
        "discriminators": [
            {"absent": {"kind": "cloud_change|cloud_audit", "entity_type": "cloud_resource"},
             "within_s": 600,
             "else_prefer": "sig.ent.cloud.private-connectivity-down"},
        ],
        "direction_expect": "firewall/subnet -> application -> users",
        "verdict": {
            "owner": "netops", "layer": "L3/L4 (security group / NACL)",
            "first_steps": [
                "Check the security group / NACL on the app's subnet for a recent rule change in the window",
                "Confirm the rejected 5-tuple (src/dst/port) on the flow evidence is the app's ingress, not an unrelated port",
                "Verify the ingress rule allows the LB/health-check source ranges to the app port",
            ],
        },
        "operator_phrase": "The security group / NACL on this application's subnet is rejecting traffic on the app's request path — a boundary rule is the probable cause of the degraded experience.",
        "manager_phrase": "A network access rule in front of this application is dropping traffic; we have localised it to the firewall/subnet tier.",
        "blast_radius": "Traffic to the application through the affected subnet boundary",
        "false_positives": ("expected rejects of scanner / out-of-scope traffic", "a health-check source that was never allowed"),
    },
    {
        "id": "sig.ent.app.edge-dns-failure",
        "title": "DNS resolution failing for a name the application depends on",
        "domain": "ent.app",
        "seams": ["CLOUD_APP"],
        "deployment_scope": "hybrid",
        "requires": [
            {"kind": "cloud_health"},
            # the on-path cause: NXDOMAIN/SERVFAIL for a name the app depends on.
            {"kind": "cloud_dns_log"},
            # an INDEPENDENT customer/synthetic witness (the cloud API is a single
            # vantage — this second, independent observer is what lifts the verdict off
            # the cloud-only suspected ceiling to CONFIRMED via the independence gate).
            {"kind": "probe_loss|probe_rtt_anomaly|synthetic_icmp_loss|synthetic_http_fail|synthetic_timeout", "optional": True},
        ],
        "direction_expect": "dns-name -> application -> users",
        "verdict": {
            "owner": "netops", "layer": "L7 (DNS)",
            "first_steps": [
                "Identify the failing name + rcode (NXDOMAIN / SERVFAIL) on the DNS evidence",
                "Check the hosted zone / record and any recent failover or record change in the window",
                "Resolve the name from an independent vantage to confirm it is broken everywhere, not one resolver",
            ],
        },
        "operator_phrase": "DNS resolution is failing for a name this application depends on, on the app's request path — a DNS record / zone fault is the probable cause of the degraded experience.",
        "manager_phrase": "The naming lookup this application relies on is failing, so users cannot reach it; we have localised it to the DNS tier.",
        "blast_radius": "Users resolving the affected name for this application",
        "false_positives": ("a client-side resolver problem at one site", "a name deliberately retired but still queried"),
    },
]
BUILTIN_TEMPLATES.extend(CLOUD_EDGE_ATTRIBUTION_TEMPLATES)

# ── Wireless (#128 Phase 3, docs/Wireslessdesign.md §17) ─────────────────────
# The discriminator is the load-bearing half of every pair: each look-alike
# names its competitor, so the engine scores BOTH instead of collapsing them.
# "Wireless not the cause" is deliberately NOT a template — when wireless is
# healthy it contributes no fault signals and the authoritative edges lead
# elsewhere; the correct implementation of "don't blame wireless" is no code.
# The LAN seam tag follows the owner ruling (2026-07-26): wireless is part of
# the LAN domain. All kinds arrive on the controller lane at Phase 3 (a lone
# management-plane witness caps at suspected — the second, independent witness
# is the AP-uplink switch port telemetry, which these templates require or
# mark optional exactly where the report says it matters).
WIRELESS_TEMPLATES: list[dict] = [
    {
        "id": "sig.ent.wireless.ap-down-power",
        "title": "AP down — power/uplink path (PoE or switch port)",
        "domain": "ent.wireless",
        "requires": [
            {"kind": "wireless_ap_down", "entity_type": "access_point"},
            # The INDEPENDENT witness: the access switch reports the AP's
            # uplink port down. This is what separates power/cable from an AP
            # software fault — and what lets the verdict confirm at all (B2).
            {"kind": "link_state_change", "entity_type": "interface"},
        ],
        # The uplink witness arrives on the syslog lane (control_plane) — the
        # second modality that lets this family confirm at all (report B2).
        "required_modalities": ["management_plane", "control_plane"],
        "seams": ["LAN"],
        "verdict": {
            "owner": "netops", "layer": "L1/PoE",
            "first_steps": [
                "Check PoE power draw and errors on the AP's uplink switch port",
                "Verify the port is not err-disabled and the cable run is intact",
                "If the port is administratively fine, swap-test power injector/cable",
            ],
        },
        "operator_phrase": "AP down and its uplink switch port went down with it — power or cabling, not AP software",
        "manager_phrase": "A wireless access point lost power or its cable connection",
        "false_positives": ("a planned switch reboot taking the port down",),
    },
    {
        "id": "sig.ent.wireless.ap-software-fault",
        "title": "AP down — AP-side fault (uplink still up)",
        "domain": "ent.wireless",
        "requires": [
            {"kind": "wireless_ap_down", "entity_type": "access_point"},
            # A failing AP commonly flaps its CAPWAP join before dying —
            # supporting evidence when present, never required.
            {"kind": "wireless_ap_join_flap", "entity_type": "access_point", "optional": True},
        ],
        "required_modalities": ["management_plane"],
        "discriminators": [
            # If the uplink port ALSO went down, this is the power/path case.
            {"absent": {"kind": "link_state_change", "entity_type": "interface"},
             "within_s": 600, "else_prefer": "sig.ent.wireless.ap-down-power"},
        ],
        "seams": ["LAN"],
        "verdict": {
            "owner": "netops", "layer": "device",
            "first_steps": [
                "Confirm the uplink switch port is still up (rules out power/cable)",
                "Check the controller's AP crash/reload history for this AP",
                "Collect AP core/syslog before power-cycling so the cause isn't lost",
            ],
        },
        "operator_phrase": "AP disjoined while its uplink stayed up — AP-side software/hardware fault",
        "manager_phrase": "A wireless access point failed on its own (not power or cabling)",
    },
    {
        "id": "sig.ent.wireless.rf-co-channel-interference",
        "title": "RF congestion — co-channel interference",
        "domain": "ent.wireless",
        "requires": [
            {"kind": "wireless_channel_util_high", "entity_type": "radio"},
            {"kind": "wireless_retry_rate_high", "entity_type": "radio", "optional": True},
        ],
        "required_modalities": ["management_plane"],
        "discriminators": [
            # Low RSSI at clients says coverage hole, not airtime congestion.
            {"absent": {"kind": "wireless_coverage_low_rssi"},
             "within_s": 900, "else_prefer": "sig.ent.wireless.rf-coverage-hole"},
        ],
        "seams": ["LAN"],
        "verdict": {
            "owner": "netops", "layer": "RF",
            "first_steps": [
                "Check channel utilization on neighboring APs — same channel, same spike = co-channel",
                "Review RRM channel assignments in the affected RF neighborhood",
                "Look for a recently-added AP or a neighbor network on the channel",
            ],
        },
        "operator_phrase": "Channel utilization is saturated with normal signal strength — airtime congestion, not coverage",
        "manager_phrase": "The Wi-Fi channel is overcrowded in this area",
        "false_positives": ("a one-off burst from a large file transfer",),
    },
    {
        "id": "sig.ent.wireless.rf-coverage-hole",
        "title": "RF coverage hole (weak signal area)",
        "domain": "ent.wireless",
        "requires": [
            {"kind": "wireless_coverage_low_rssi"},
            {"kind": "wireless_retry_rate_high|wireless_roam_storm", "optional": True},
            # A hole is often OPENED by a down radio nearby — corroborating
            # when present (and the consumer of the radio-transition lane).
            {"kind": "wireless_radio_down", "entity_type": "radio", "optional": True},
        ],
        "required_modalities": ["management_plane"],
        "seams": ["LAN"],
        "verdict": {
            "owner": "netops", "layer": "RF",
            "first_steps": [
                "Map which clients report low RSSI — one client = client fault, many = coverage",
                "Check whether a nearby AP or radio recently went down (hole opened by outage)",
                "Review tx-power: RRM may have coalesced power after an AP loss",
            ],
        },
        "operator_phrase": "Clients in one area see weak signal and retries — a coverage hole, possibly opened by a down radio",
        "manager_phrase": "Wi-Fi signal is weak in part of the site",
    },
    {
        "id": "sig.ent.wireless.rf-non-wifi-interference",
        "title": "Non-Wi-Fi interference on the channel",
        "domain": "ent.wireless",
        "requires": [
            {"kind": "wireless_interference|wireless_noise_high"},
        ],
        "required_modalities": ["management_plane"],
        "discriminators": [
            # High WIFI-attributed utilization means co-channel, not non-Wi-Fi.
            {"absent": {"kind": "wireless_channel_util_high"},
             "within_s": 900, "else_prefer": "sig.ent.wireless.rf-co-channel-interference"},
        ],
        "seams": ["LAN"],
        "verdict": {
            "owner": "netops", "layer": "RF",
            "first_steps": [
                "Check the noise floor vs Wi-Fi-attributed utilization on the affected radios",
                "Look for non-Wi-Fi sources near the affected APs (microwave, BT, cameras)",
                "Change channel as mitigation; locate the interferer for the fix",
            ],
        },
        "operator_phrase": "High noise with low Wi-Fi airtime — a non-Wi-Fi interferer on the channel",
        "manager_phrase": "Something other than Wi-Fi is jamming the wireless in this area",
    },
    {
        "id": "sig.ent.wireless.capwap-instability",
        "title": "AP join/CAPWAP instability (AP↔controller path)",
        "domain": "ent.wireless",
        "requires": [
            {"kind": "wireless_ap_join_flap", "entity_type": "access_point"},
            {"kind": "probe_loss|if_util_high|if_errors", "optional": True},
        ],
        "required_modalities": ["management_plane"],
        "discriminators": [
            # If the controller itself is unreachable, that's the WLC event,
            # not per-AP tunnel instability.
            {"absent": {"kind": "controller_device_unreachable"},
             "within_s": 600, "else_prefer": "sig.ent.wireless.wlc-failover"},
        ],
        "seams": ["LAN"],
        "verdict": {
            "owner": "netops", "layer": "L2/Tunnel",
            "first_steps": [
                "Check loss/latency on the AP→controller management path (the CAPWAP path)",
                "Look for congestion or errors on the uplinks between the AP's switch and the WLC",
                "Confirm the WLC is not resource-exhausted (join storms follow WLC CPU spikes)",
            ],
        },
        "operator_phrase": "APs are joining and leaving the controller repeatedly — the AP↔controller path or the WLC is unstable",
        "manager_phrase": "Access points keep losing contact with the wireless controller",
    },
    {
        "id": "sig.ent.wireless.wlc-failover",
        # tracker 157 — a WLC CLUSTER. The clause alternation admits a bare
        # controller_device_unreachable, which is equally true of a standalone
        # controller; only wireless_wlc_member_failover attests the cluster.
        "requires_structure": ["redundancy_group"],
        "title": "Controller failover / controller loss",
        "domain": "ent.wireless",
        "requires": [
            {"kind": "wireless_wlc_member_failover|controller_device_unreachable"},
            {"kind": "wireless_ap_join_flap", "optional": True},
        ],
        "required_modalities": ["management_plane"],
        "seams": ["LAN"],
        "verdict": {
            "owner": "netops", "layer": "device",
            "first_steps": [
                "Confirm which member failed and whether the standby took over (redundancy held?)",
                "If APs re-joined the standby, this is redundancy-loss, not an outage — treat as capacity risk",
                "Check the failed member's console/crash data before restoring",
            ],
        },
        "operator_phrase": "A controller member failed over — check whether redundancy held before calling it an outage",
        "manager_phrase": "A wireless controller failed; the backup took over",
        "false_positives": ("a planned controller upgrade rebooting members in sequence",),
    },
    {
        "id": "sig.ent.wireless.onboarding-auth-radius",
        "title": "Client onboarding fails at authentication (AAA path)",
        "domain": "ent.wireless",
        "requires": [
            {"kind": "wireless_onboarding_auth_failure"},
            {"kind": "dns_failure_rate|probe_loss", "entity_type": "service", "optional": True},
        ],
        "required_modalities": ["management_plane"],
        "seams": ["LAN"],
        "verdict": {
            "owner": "netops", "layer": "L2/AAA",
            "first_steps": [
                "Check RADIUS server health and reachability from the controller",
                "Distinguish server timeout (AAA path) from reject (credential/policy) in the failure reasons",
                "If one WLAN only: compare its AAA server list against working WLANs",
            ],
        },
        "operator_phrase": "Clients fail onboarding at the 802.1X step — the AAA path, not the radio, is the suspect",
        "manager_phrase": "Users can see the Wi-Fi but can't log into it",
        "false_positives": ("a single user with expired credentials",),
    },
    {
        "id": "sig.ent.wireless.onboarding-dhcp-exhaustion",
        "title": "Client onboarding fails at addressing (DHCP scope)",
        "domain": "ent.wireless",
        "requires": [
            {"kind": "wireless_onboarding_dhcp_failure"},
            # Address-less clients cycle: disconnect/re-associate churn rides
            # along when a scope exhausts. Supporting, never required.
            {"kind": "wireless_client_disconnect_storm", "optional": True},
        ],
        "required_modalities": ["management_plane"],
        "seams": ["LAN"],
        "verdict": {
            "owner": "netops", "layer": "L3/DHCP",
            "first_steps": [
                "Check lease utilization on the scope serving the affected WLAN/VLAN",
                "Many clients on one VLAN = scope exhaustion; one client = client-side fault",
                "Verify DHCP relay from the controller/AP VLAN to the server is healthy",
            ],
        },
        "operator_phrase": "Clients associate and authenticate but get no address — the DHCP scope or relay, not wireless",
        "manager_phrase": "Users connect to Wi-Fi but never get network access",
    },
]
BUILTIN_TEMPLATES.extend(WIRELESS_TEMPLATES)



# ══ EXPOSURE STORY seed (T2b / T7 seed) ══════════════════════════════════════
#
# WHAT THESE ARE. The signature family that lets a verdict from an EVIDENCE-CLASS
# bus lane (signals.EVIDENCE_CLASSES — today: security) be folded into the same
# seam-attributed causality object the network lanes already build, instead of
# living in a parallel list. They are ordinary catalog data: no engine code knows
# they exist, and deleting them leaves every other template untouched.
#
# WHY THE SECURITY KIND IS THE **REQUIRED** CLAUSE AND THE NETWORK EVIDENCE IS
# OPTIONAL — and not the other way round. The inverse shape (network required,
# security optional) would make these templates fire on EVERY object the V1
# workload already produces, competing with the network signatures and moving
# the ranking. With the verdict as the required clause they cannot match at all
# unless an evidence-class signal is present, so a stream that carries none
# produces byte-identical decision content (`content_hash`, hypotheses blob,
# verdict tier, affected) — asserted by test_security_grounding_t2b.py. The one
# field that legitimately moves is `catalog_version`: it is the rule-base
# revision stamp and MUST move when the rule base changes.
#
# WHY THEY CANNOT OVERCLAIM. The optional clause is what an INDEPENDENTLY
# MEASURED plane (control_plane / device_telemetry / passive_flow) contributes.
# A verdict standing alone matches with ONE modality, and the runtime gate
# (verdicts.assess: >=2 independent modality classes to confirm) caps it at
# suspected — the honest "possibly because of X" reading, never a confirmed
# cause built out of a scanner's opinion. Corroboration is what promotes it, and
# corroboration can only come from a plane the verdict lane does not own.
#
# GROUNDING. Both clauses are matched on the SAME object, i.e. on evidence the
# engine already co-located by entity/token — the producer's entity_tokens
# (device:/host:/seam:) are what put the verdict on the device's node in the
# first place. Nothing here names a topology ROLE, so `requires_structure` stays
# empty and the tracker-157 structural gate is a dict lookup that cannot fire.

# The independently-measured network evidence an evidence-class verdict can be
# corroborated BY, on the same entity. One alternation, authored once: every
# member is a control-plane / device-telemetry kind a producer actually emits,
# so the clause can never be a dead template.
# Deliberately EXCLUDES the kinds coverage.INTENTIONAL_BLIND declares as
# consumed-by-no-signature (device_alarm, device_restart,
# routing_adjacency_change, lldp_neighbor_change): those declarations are a
# contract about the rule base, and quietly consuming one here would flip its
# coverage classification as a side effect of an unrelated family.
_CORROBORATING_NETWORK_EVIDENCE = (
    "bgp_adjacency_change|ospf_adjacency_change|isis_adjacency_change|"
    "link_state_change|device_resource_anomaly|if_metric_anomaly"
)

EXPOSURE_STORY_TEMPLATES: list[dict] = [
    {
        "id": "sig.ent.security.exposure-story",
        "title": "Exposed device is also failing (exposure + network fault on one node)",
        "domain": "ent.security",
        "demo_priority": "p2",
        "requires": [
            {"kind": "security_exposure"},
            {"kind": _CORROBORATING_NETWORK_EVIDENCE, "optional": True},
        ],
        "verdict": {
            "owner": "netops", "layer": "security/exposure",
            "first_steps": [
                "Open the exposure evidence (advisory + affected version) on this device",
                "Check whether the network fault on the same device started AFTER the exposure was first observed",
                "If the device sits on an internet-facing seam, isolate or ACL it before upgrading",
            ],
        },
        "operator_phrase": "This device carries a known exposure and is showing a network fault at the same time — the two are on one node, not yet proven to be one cause",
        "manager_phrase": "A device with a known security weakness is also misbehaving on the network",
        "blast_radius": "the exposed device and everything transiting it",
        "false_positives": (
            ("an exposure is a standing property, not an event — co-occurrence "
             "with an unrelated network fault is common, and is why this family "
             "cannot confirm on the verdict alone"),
        ),
    },
    {
        "id": "sig.ent.security.hardening-drift-story",
        "title": "Hardening gap on a device that is also failing (posture + network fault)",
        "domain": "ent.security",
        "demo_priority": "p2",
        "requires": [
            {"kind": "security_posture"},
            {"kind": _CORROBORATING_NETWORK_EVIDENCE, "optional": True},
            # WHEN the baseline broke. A failed hardening control is a STANDING
            # property with no onset — that is why this family cannot confirm on
            # the verdict alone. A config change on the same device inside the
            # window is the first piece of evidence that dates the drift, and it
            # is the operator's next click ("what changed?"). Optional, and
            # control-plane like the fault clause above it, so it can never be
            # the independent second plane that promotes the verdict. TRAP
            # observer only today — the syslog half is shadowed (events.yaml).
            {"kind": "device_config_change", "optional": True},
        ],
        "verdict": {
            "owner": "netops", "layer": "security/posture",
            "first_steps": [
                "Open the failed control and the exact config evidence it cites",
                "Compare the capture time of the failed control with the fault onset",
                "Check the change/maintenance window: a hardening regression outside one is itself a signal",
            ],
        },
        "operator_phrase": "A hardening control failed on this device and the device is also showing a network fault — check whether the same config change caused both",
        "manager_phrase": "A device is out of its hardening baseline and is also having problems",
        "blast_radius": "the audited device; wider if the same baseline drift is fleet-wide",
        "false_positives": (
            ("a long-standing accepted deviation will co-occur with every "
             "unrelated fault on that device"),
        ),
    },
    {
        "id": "sig.ent.security.threat-signal-story",
        "title": "Threat signal on a device that is also failing (detection + network fault)",
        "domain": "ent.security",
        "demo_priority": "p2",
        "requires": [
            {"kind": "security_signal"},
            {"kind": _CORROBORATING_NETWORK_EVIDENCE, "optional": True},
            # A behavioural detection's own measured plane: a flow anomaly on the
            # same entity is PASSIVE_FLOW, independent of the detection lane.
            {"kind": "flow_volume_anomaly", "optional": True},
        ],
        "verdict": {
            "owner": "netops", "layer": "security/detection",
            "first_steps": [
                "Open the detection's evidence reference (the rule and the observation it fired on)",
                "Check whether the network fault on this device began within the detection window",
                "Verify the device's config/audit trail for an unplanned change around the same time",
            ],
        },
        "operator_phrase": "A detection fired on this device and the device is also showing a network fault — treat as one story until the evidence separates them",
        "manager_phrase": "Suspicious activity was detected on a device that is also having network problems",
        "blast_radius": "the detected device and its immediate neighbours",
        "false_positives": (
            ("a single detection is one vantage and one rule; without an "
             "independently measured plane it stays suspected by construction"),
        ),
    },
]
BUILTIN_TEMPLATES.extend(EXPOSURE_STORY_TEMPLATES)


def builtin_catalog() -> Catalog:
    """The validated built-in set. Import-time safe: validation errors here
    are a build break, not a runtime surprise (guarded by test)."""
    return load_catalog(BUILTIN_TEMPLATES)
