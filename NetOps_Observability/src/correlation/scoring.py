"""Hypothesis scoring — pipeline stage [6]+[7] of Correlation Engine v2.

Evaluates the signature catalog over an evidence set (the signals attached to
one correlation object) and returns a ranked, explainable hypothesis list with
the object-level outcome. Pure and deterministic: no IO, no wall-clock — same
evidence + same catalog ⇒ same ranking (replay contract).

Scoring model (#67 §4.5):
    coverage        = satisfied required clauses / total required
                      (+0.1 bonus capped, from optional clauses)
    graph_support   = mean weight of edges connecting the satisfying episodes —
                      **1.0 until the graph builder (stage [5]) lands**; the
                      hook is the parameter, declared not hidden
    contradiction   = a discriminator's 'absent' clause matched evidence →
                      score ×0.2 AND the else_prefer competitor is force-listed
    confidence_rank = coverage × graph_support × direction_agreement(=1.0 v0)
    verdict tier    = verdicts.assess(satisfying signals, required_modalities)
                      — rank and verdict stay ORTHOGONAL (sacred invariant)

Structural precondition (tracker 157): a template that NAMES a role, tier or
group declares it (``Template.requires_structure``) and is admitted to ranking
only if the evidence ATTESTS that structure. A gate, not a weight — a discount
is out-scored by a strong symptom match, which is precisely how a leaf/spine
signature came to rank top in a topology with no spine.

Object outcome: rank-1 below the confidence floor ⇒ ``undetermined`` with
``evidence_missing`` derived mechanically from the nearest template's
unsatisfied clauses — no forced root cause, ever.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from functools import lru_cache

from catalog import Catalog, Clause, Template
from signals import (
    EntityType,
    ModalityClass,
    ProbeAuthority,
    Signal,
    probe_authority_of,
)
from verdicts import Verdict as GateVerdict
from verdicts import VerdictTier, assess

# Config-hash members (P4 replay-driven calibration re-fits; never tuned silently).
CONTRADICTION_PENALTY = 0.2
OPTIONAL_BONUS_PER_CLAUSE = 0.05
OPTIONAL_BONUS_CAP = 0.1
CONFIDENCE_FLOOR = 0.3   # rank-1 below this ⇒ object outcome 'undetermined'
TOP_K = 4

# Active-verification lane (RCA spec item 8). The verify engine's producer
# (verification_producer.py) emits exactly these two kinds; the backend stamps
# corroborates_kinds / refutes_kinds from its CLOSED check table — the scorer
# only ever matches those declarations against clause vocabulary, it never
# invents a mapping.
VERIFICATION_RESULT_KIND = "active_verification_result"
VERIFICATION_HEALTHY_KIND = "active_verification_healthy"


def _attr_kinds(sig: Signal, key: str) -> frozenset[str]:
    """Bounded, fail-closed read of a kinds list from attrs (zero-trust: the
    wire value is validated for shape; anything malformed is empty)."""
    attrs = sig.attrs if isinstance(sig.attrs, dict) else {}
    raw = attrs.get(key, ())
    if not isinstance(raw, (list, tuple)):
        return frozenset()
    return frozenset(str(k) for k in raw[:16] if isinstance(k, str) and k)


def _same_entity(a: Signal, b: Signal) -> bool:
    """Entity co-identity for verification matching: same entity_id or any
    shared grounding token. Absence of overlap never fabricates a match."""
    if a.entity_id and a.entity_id == b.entity_id:
        return True
    return bool(set(a.entity_tokens) & set(b.entity_tokens))


def clause_matches(clause: Clause, sig: Signal) -> bool:
    """Total predicate: signal vs one clause. Role constraints need per-signal
    topology context the scorer does not have — a role-constrained clause
    matches on the other fields and the gap is declared in the score's notes
    (honest, not silently strict or silently lax).

    That gap used to be the WHOLE story, and it was a hole: a signature could
    name a role and rank in an estate that had none. Since tracker 157 the role
    is no longer decorative — a template carrying one must declare a
    `requires_structure` class (enforced at catalog load), and `rank` refuses
    the template outright unless the evidence attests it. This function is
    unchanged and stays the CLAUSE-level predicate; the structure gate is a
    TEMPLATE-level precondition, evaluated before scoring."""
    if sig.kind not in clause.kinds():
        return False
    if clause.entity_type is not None and sig.entity_type is not clause.entity_type:
        return False
    return not (clause.min_deviation is not None and abs(sig.deviation) < clause.min_deviation)


def _verification_corroborates(clause: Clause, sig: Signal) -> bool:
    """Active-verification corroboration (spec item 8): a FAILING read-only
    check names the kinds it corroborates in attrs.corroborates_kinds (stamped
    backend-side from the closed check table). It satisfies a clause when those
    kinds intersect the clause vocabulary — the device's own answer stands in
    as a witness for the phenomenon the clause names. entity_type is still
    enforced; min_deviation is a metric-lane constraint and does not apply to a
    state observation."""
    if sig.kind != VERIFICATION_RESULT_KIND:
        return False
    if clause.entity_type is not None and sig.entity_type is not clause.entity_type:
        return False
    return bool(_attr_kinds(sig, "corroborates_kinds") & clause.kinds())


# ── ephemeral causal-chain clauses: ONE object per witness kind ──────────────
#
# THE MEASURED DEFECT (docs/scale/P2_MEMFLAT_ATTRIBUTION_2026-08-29.md §5.2).
# `score_template` and `_template_kinds` used to build a fresh
# `Clause(kind=stage.witness)` on EVERY call. `Clause.kinds()` is memoised by
# object IDENTITY (catalog.py, P2 step 0b), so each of those throwaway clauses
# took a cache slot it could never serve again — and the cache holds a STRONG
# reference, so it pinned them until the 4,096-entry bound cleared the whole
# dict. Measured at the bench's `drained` point: 2,292 pinned Clause objects the
# catalog does not own (2.56 MiB) against 426 the catalog does; the `memo_off`
# leg filled the cache to 4,095 and self-cleared mid-drain. Pure waste — the
# identity cache is excellent everywhere it applies (98.8 % served), so the fix
# is at the CALL SITE, not the cache.
#
# The fix: intern the clause by its witness STRING. A `Clause` with only `kind`
# set is a pure function of that string on a frozen model, so one shared
# instance is VALUE-IDENTICAL to a fresh one — nothing the scorer computes can
# move (pinned by the byte-identity tests in `test_p2_memflat_bounds.py`) — and
# the identity cache now sees a stable id and actually serves it.
#
# Bounded (§9): the key space is the catalog's causal-chain witness vocabulary
# (a few hundred strings, immutable for the life of the catalog). On overflow
# the whole map is cleared and refills, exactly like `_CLAUSE_KINDS_CACHE` — an
# allocation optimisation, never a correctness input.
_WITNESS_CLAUSE_CACHE: dict[str, Clause] = {}
_WITNESS_CLAUSE_CACHE_MAX = 4096


def witness_clause(kind: str) -> Clause:
    """The shared `Clause(kind=<causal-chain witness>)` for one witness kind.

    Value-keyed (the string), unlike `Clause.kinds`'s identity cache — hashing a
    short str is cheap where hashing a frozen pydantic model is not, and a
    stable identity is precisely what makes that downstream cache hit."""
    hit = _WITNESS_CLAUSE_CACHE.get(kind)
    if hit is not None:
        return hit
    clause = Clause(kind=kind)
    if len(_WITNESS_CLAUSE_CACHE) >= _WITNESS_CLAUSE_CACHE_MAX:
        _WITNESS_CLAUSE_CACHE.clear()
    _WITNESS_CLAUSE_CACHE[kind] = clause
    return clause


def _satisfying(clause: Clause, evidence: tuple[Signal, ...]) -> tuple[Signal, ...]:
    # Decision #1: a debug_only / lab probe can never satisfy a clause — it must
    # not attach as supporting evidence nor drive a customer-facing hypothesis.
    return tuple(
        s for s in evidence
        if (clause_matches(clause, s) or _verification_corroborates(clause, s))
        and probe_authority_of(s) is not ProbeAuthority.DEBUG_ONLY
    )


@dataclass(frozen=True)
class HypothesisScore:
    """One template's evaluation — every number traceable to named clauses.
    Renders into corr_objects.hypotheses and the corr_evidence log."""

    template_id: str
    title: str
    coverage: float
    confidence_rank: float
    contradicted: bool
    verdict_gate: GateVerdict
    satisfied: tuple[str, ...]            # clause kinds that matched
    missing: tuple[str, ...]              # required clause kinds that did not
    contradictions: tuple[str, ...]       # discriminator kinds found in evidence
    forced_competitors: tuple[str, ...]   # else_prefer ids that must be shown
    notes: tuple[str, ...]
    owner: str
    first_steps: tuple[str, ...]
    supporting_hit: bool = False          # >=1 optional (supporting) clause matched
    # v1 NOC-catalog narration fields, carried verbatim from the template so the
    # AI/UI never re-derive wording (the engine reasons, the AI narrates).
    seams: tuple[str, ...] = ()
    deployment_scope: str = "hybrid"
    operator_phrase: str = ""
    manager_phrase: str = ""
    blast_radius: str = ""
    false_positives: tuple[str, ...] = ()
    # Propagation ladder (owner directive 2026-07-13): the template's declared
    # cascade with each rung marked witnessed (evidence kinds cited) or not
    # (honest unobserved note). Rendered by the UI as "how one failure caused
    # the next"; empty for templates that declare no chain.
    causal_chain: tuple[dict, ...] = ()

    def confidence_label(self) -> str:
        """The lexical confidence label of the owner's taxonomy (voice contract):
        confirmed — the independence gate passed (>=2 modalities/observers,
        an independent pair, required modalities witnessed); likely — every
        required clause matched plus at least one independent supporting clause
        and no contradiction (actionable, gate not yet fully met); suspected —
        anything less. Never derived from the bare confidence number."""
        if self.verdict_gate.tier.value == "confirmed":
            return "confirmed"
        if not self.missing and self.supporting_hit and not self.contradicted:
            return "likely"
        return "suspected"

    def to_dict(self) -> dict:
        return {
            "id": self.template_id,
            "title": self.title,
            "coverage": round(self.coverage, 4),
            "confidence": round(self.confidence_rank, 4),
            "confidence_label": self.confidence_label(),
            "contradicted": self.contradicted,
            "satisfied": list(self.satisfied),
            "missing": list(self.missing),
            "contradictions": list(self.contradictions),
            "forced_competitors": list(self.forced_competitors),
            "notes": list(self.notes),
            "seams": list(self.seams),
            "deployment_scope": self.deployment_scope,
            "operator_phrase": self.operator_phrase,
            "manager_phrase": self.manager_phrase,
            "blast_radius": self.blast_radius,
            "false_positives": list(self.false_positives),
            "causal_chain": [dict(s) for s in self.causal_chain],
            "verdict": {
                "owner": self.owner,
                "first_steps": list(self.first_steps),
                **self.verdict_gate.to_dict(),
            },
        }


def score_template(
    template: Template,
    evidence: tuple[Signal, ...],
    graph_support: float = 1.0,
    direction_agreement: float = 1.0,
) -> HypothesisScore:
    satisfied: list[str] = []
    missing: list[str] = []
    notes: list[str] = []
    matched_signals: list[Signal] = []

    required = [c for c in template.requires if not c.optional]
    optional = [c for c in template.requires if c.optional]

    for clause in required:
        hits = _satisfying(clause, evidence)
        if hits:
            satisfied.append(clause.kind)
            matched_signals.extend(hits)
            if clause.role is not None:
                notes.append(f"role '{clause.role}' unverified (topology context pending stage [5])")
        else:
            missing.append(clause.kind)

    bonus = 0.0
    supporting_hit = False
    for clause in optional:
        hits = _satisfying(clause, evidence)
        if hits:
            satisfied.append(clause.kind)
            matched_signals.extend(hits)
            supporting_hit = True
            bonus = min(OPTIONAL_BONUS_CAP, bonus + OPTIONAL_BONUS_PER_CLAUSE)

    coverage = (len(required) - len(missing)) / len(required) if required else 0.0
    coverage = min(1.0, coverage + bonus)

    contradictions: list[str] = []
    forced: list[str] = []
    for disc in template.discriminators:
        if _satisfying(disc.absent, evidence):
            contradictions.append(disc.absent.kind)
            forced.append(disc.else_prefer)

    # Active-verification refutation (spec item 8): a HEALTHY read-only check
    # battery on an implicated entity is REFUTING evidence. The producer stamps
    # attrs.refutes_kinds from the closed check table; when those kinds
    # intersect a satisfied required clause AND the healthy answer came from
    # the same entity that satisfied it, the template is contradicted through
    # the SAME penalty path as a discriminator — explained-away, never silently
    # dropped (the contradiction string names the verification). Deterministic:
    # signals ordered by signal_id, refuted kinds sorted.
    for ver in sorted(
        (s for s in evidence if s.kind == VERIFICATION_HEALTHY_KIND),
        key=lambda s: str(s.signal_id),
    ):
        refutes = _attr_kinds(ver, "refutes_kinds")
        if not refutes:
            continue
        for clause in required:
            hit_kinds = clause.kinds() & refutes
            if not hit_kinds:
                continue
            hits = _satisfying(clause, evidence)
            if hits and any(_same_entity(h, ver) for h in hits):
                for k in sorted(hit_kinds):
                    tag = f"{VERIFICATION_HEALTHY_KIND}:{k}"
                    if tag not in contradictions:
                        contradictions.append(tag)

    # Propagation ladder: mark each declared rung witnessed/unobserved from the
    # SAME evidence pool (and the same probe-authority filter) the clauses use.
    # Purely descriptive — never feeds coverage or confidence: the ladder shows
    # how the failure propagated, it must not double-count evidence.
    causal_chain = tuple(
        {
            "stage": st.stage,
            "root": st.root,
            "witnessed": bool(hits),
            "kinds": sorted({s.kind for s in hits}),
            "note": "" if hits else st.unobserved_note,
        }
        for st in template.causal_chain
        for hits in (_satisfying(witness_clause(st.witness), evidence),)
    )

    confidence = coverage * graph_support * direction_agreement
    if contradictions:
        confidence *= CONTRADICTION_PENALTY

    gate = assess(
        matched_signals,
        required_modalities=frozenset(template.required_modalities) or None,
    )
    # Port-Intelligence cap (#94): physical-layer families with
    # allow_root_cause_confirmed=False never emit CONFIRMED from telemetry
    # alone — the tier is capped at SUSPECTED with the reason on the record
    # (fiber-path validation / human corroboration lifts it later).
    if gate.tier is VerdictTier.CONFIRMED and not template.allow_root_cause_confirmed:
        gate = GateVerdict(
            tier=VerdictTier.SUSPECTED,
            coverage=gate.coverage,
            reasons=gate.reasons + (
                "confirmed capped to suspected: physical-layer family requires fiber-path validation or human corroboration (allow_root_cause_confirmed=false)",),
        )

    return HypothesisScore(
        template_id=template.id,
        title=template.title,
        coverage=coverage,
        confidence_rank=confidence,
        contradicted=bool(contradictions),
        verdict_gate=gate,
        satisfied=tuple(satisfied),
        missing=tuple(missing),
        contradictions=tuple(contradictions),
        forced_competitors=tuple(forced),
        notes=tuple(notes),
        owner=template.verdict.owner,
        first_steps=template.verdict.first_steps,
        supporting_hit=supporting_hit,
        seams=tuple(template.seams),
        deployment_scope=template.deployment_scope,
        operator_phrase=template.operator_phrase,
        manager_phrase=template.manager_phrase,
        blast_radius=template.blast_radius,
        false_positives=tuple(template.false_positives),
        causal_chain=causal_chain,
    )


@dataclass(frozen=True)
class RankingResult:
    """Object-level outcome: ranked top-K (+ forced competitors always shown)
    and the headline. ``undetermined`` is a first-class result — affected-path
    confirmation and cause confirmation are independent statements."""

    top_hypothesis: str                   # template id or 'undetermined'
    verdict_tier: VerdictTier
    hypotheses: tuple[HypothesisScore, ...]
    evidence_missing: tuple[str, ...]     # what would confirm (mechanical, not prose)
    catalog_version: str

    def to_dict(self) -> dict:
        return {
            "top_hypothesis": self.top_hypothesis,
            "verdict_tier": self.verdict_tier.value,
            "hypotheses": [h.to_dict() for h in self.hypotheses],
            "evidence_missing": list(self.evidence_missing),
            "catalog_version": self.catalog_version,
        }


# ── tracker 167: the provably-inapplicable fast path ─────────────────────────
#
# THE MEASUREMENT. Post-168 the engine produces correct DEVICE-LOCAL objects
# instead of one estate-wide weld, so object count went from ~1 to ~1,000 per
# replica. `rank()` scores EVERY enabled template against EVERY object, and the
# catalog holds 100 of them. Profiled on the live shape (6,000 nodes → 1,111
# objects): `score_template` 17.98 s cumulative over 111,100 calls — 1,111
# objects x 100 templates — while `build_edges` was 4.11 s of a 29.71 s cycle.
# The dominant cost is O(objects x catalog).
#
# WHY THIS IS NOT A SKIP. `rank()` does not discard low scorers. It derives
# `evidence_missing` from `sorted(scores, key=-coverage)[:2]`, keeps forced
# competitors and contradicted look-alikes visible from `scores[TOP_K:]`, and
# `evidence_missing` is persisted and hashed. Omitting a template would change
# RCA output. So nothing is skipped — instead, a template that CANNOT match is
# scored ANALYTICALLY, because its result is fully determined:
#
#   satisfied ()  ·  missing = every required clause  ·  coverage 0.0
#   no contradictions (a discriminator needs a matching kind too)
#   no notes (the role note is only emitted on a hit)
#   confidence 0.0  ·  gate = assess((), required_modalities)
#
# The expensive part — `_satisfying` over every clause x every signal — is what
# gets skipped, not the template.
#
# SOUNDNESS. The index keys on `kind` alone. `entity_type` and `min_deviation`
# only make a clause STRICTER, so kind-intersection is a sound SUPERSET: a
# template that survives the filter falls through to the real scorer, which
# remains the sole semantic authority. False positives cost CPU; false
# negatives are impossible by construction.
#
# The effective kind set includes what an `active_verification_result` signal
# CORROBORATES (`_verification_corroborates` matches on attrs, not on the
# signal's own kind), so a verification witness can never be indexed away.


def _template_kinds(template: Template) -> frozenset[str]:
    """Every kind this template could possibly react to — required clauses,
    optional clauses, discriminator absences and causal-chain witnesses."""
    ks: set[str] = set()
    for clause in template.requires:
        ks |= clause.kinds()
    for disc in template.discriminators:
        ks |= disc.absent.kinds()
    for stage in template.causal_chain:
        ks |= witness_clause(stage.witness).kinds()
    return frozenset(ks)


# Keyed by IDENTITY, not by value. `lru_cache` on the Catalog/Template objects
# looked right and profiled badly: hashing a frozen pydantic model walks every
# field, so a 43,065-object cycle burned 88 M `hash_func` calls (58.75 s)
# computing cache KEYS. The dict holds a strong reference to the cached Catalog
# so its id() cannot be recycled onto a different object while the entry lives;
# it is bounded, and a reloaded catalog is simply a new entry — there is still
# no stale-index path.
_CATALOG_PLAN_CACHE: dict[int, tuple[Catalog, dict, dict]] = {}
_CATALOG_PLAN_CACHE_MAX = 4


def _catalog_plan(catalog: Catalog) -> tuple[dict[str, frozenset[str]],
                                             dict[str, HypothesisScore]]:
    """Everything derived from a catalog that every RCA object needs: the
    kind index, and the analytic score of each template for the case where it
    cannot match. Both are pure functions of the catalog, so both are built
    once and shared."""
    hit = _CATALOG_PLAN_CACHE.get(id(catalog))
    if hit is not None and hit[0] is catalog:
        return hit[1], hit[2]
    templates = catalog.enabled_templates()
    index = {t.id: _template_kinds(t) for t in templates}
    inapplicable = {t.id: _build_inapplicable_score(t) for t in templates}
    if len(_CATALOG_PLAN_CACHE) >= _CATALOG_PLAN_CACHE_MAX:
        _CATALOG_PLAN_CACHE.clear()
    _CATALOG_PLAN_CACHE[id(catalog)] = (catalog, index, inapplicable)
    return index, inapplicable


def _catalog_kind_index(catalog: Catalog) -> dict[str, frozenset[str]]:
    """template id → the kinds it can react to."""
    return _catalog_plan(catalog)[0]


@lru_cache(maxsize=64)
def _empty_gate(required_modalities: frozenset[ModalityClass] | None) -> GateVerdict:
    """`assess` over no matched signals — identical for every inapplicable
    template with the same modality requirement, and measured at 2.30 s across
    111,100 calls before it was memoized."""
    return assess([], required_modalities=required_modalities or None)


def _build_inapplicable_score(template: Template) -> HypothesisScore:
    """The fully-determined score of a template no signal can satisfy.

    Mirrors `score_template` exactly for that case; `test_template_index_167.py`
    pins the two against each other over the whole catalog.

    Built ONCE PER CATALOG (2026-08-22): the result depends on the TEMPLATE
    ALONE — no evidence, no object — so it is the same value for every RCA
    object in the cycle. Profiled on the live 1K shape it was 3,359,070 calls
    (43,065 objects x ~78 elided templates) costing 47.31 s. `HypothesisScore`
    is a frozen dataclass, so sharing one instance across objects is safe —
    nothing can mutate it."""
    required = [c for c in template.requires if not c.optional]
    return HypothesisScore(
        template_id=template.id,
        title=template.title,
        coverage=0.0,
        confidence_rank=0.0,
        contradicted=False,
        verdict_gate=_empty_gate(frozenset(template.required_modalities) or None),
        satisfied=(),
        missing=tuple(c.kind for c in required),
        contradictions=(),
        forced_competitors=(),
        notes=(),
        owner=template.verdict.owner,
        first_steps=template.verdict.first_steps,
        supporting_hit=False,
        seams=tuple(template.seams),
        deployment_scope=template.deployment_scope,
        operator_phrase=template.operator_phrase,
        manager_phrase=template.manager_phrase,
        blast_radius=template.blast_radius,
        false_positives=tuple(template.false_positives),
        causal_chain=tuple(
            {"stage": st.stage, "root": st.root, "witnessed": False,
             "kinds": [], "note": st.unobserved_note}
            for st in template.causal_chain),
    )


def _inapplicable_score(template: Template) -> HypothesisScore:
    """The analytic score for a template that cannot match. Retained as the
    direct entry point the equivalence oracle pins against `score_template`."""
    return _build_inapplicable_score(template)


def ungrounded_note(template: Template) -> str:
    """The refusal, in the operator's words, recorded on the suppressed
    hypothesis (tracker 157).

    A function of the TEMPLATE alone — it names what the signature REQUIRES,
    not which subset happened to be missing this time — so it is built once per
    catalog and is stable across objects. `structure_gap` is the per-evaluation
    detail for anyone who needs it."""
    needs = ", ".join(template.requires_structure)
    return (f"suppressed: this signature names a {needs} structure and no "
            f"evidence in this object attests one — a verdict the observed "
            f"topology cannot support, so it is excluded from ranking "
            f"(tracker 157)")


def _build_ungrounded_score(template: Template) -> HypothesisScore:
    """The fully-determined score of a template the evidence cannot structurally
    support.

    Byte-identical to `_build_inapplicable_score` except for the note: the
    template is not scored, so it has satisfied nothing, coverage 0.0,
    confidence 0.0, no contradictions and the empty verdict gate. Keeping it in
    the scored LIST (rather than dropping it) is what makes this a RANKING
    exclusion and not a catalog edit — `evidence_missing`'s nearest-template
    derivation and the forced-competitor / contradicted-look-alike rules all
    see the same list they always saw, at the same length and in the same
    order.

    What it does NOT do is guarantee the refusal is RENDERED. A zero-confidence
    row reaches the persisted visible set only if it lands in the top-K by the
    ordinary sort, and a suppressed template no longer contradicts anything, so
    it also stops being pulled up as a "ruled out because…" row. The refusal is
    therefore carried here and COUNTED in `corr_template_ungrounded_total`;
    surfacing it as a visible "suppressed for lack of structure" row would need
    its pre-gate score, which is exactly the work the gate avoids. Named, not
    assumed away.

    Built ONCE PER CATALOG for the same reason `_build_inapplicable_score` is:
    the value depends on the template alone, and `HypothesisScore` is frozen."""
    return replace(_build_inapplicable_score(template),
                   notes=(ungrounded_note(template),))


# Keyed by IDENTITY, exactly like `_CATALOG_PLAN_CACHE` above and for the same
# measured reason (hashing a frozen pydantic model walks every field). Kept
# SEPARATE from `_catalog_plan` rather than widening its tuple: that function's
# arity is part of the tracker-167 test surface, and the structure plan is a
# different question asked of the same catalog. Two small dicts, one identity
# check each, no shared state.
_CATALOG_STRUCTURE_CACHE: dict[int, tuple[Catalog, dict, dict]] = {}
_CATALOG_STRUCTURE_CACHE_MAX = 4


def _catalog_structure_plan(catalog: Catalog) -> tuple[dict[str, frozenset[str]],
                                                       dict[str, HypothesisScore]]:
    """Everything the structural gate needs from a catalog: each enabled
    template's declared structure as a SET (the gate is a subset test), and the
    analytic ungrounded score of every template that declares one. Both are pure
    functions of the catalog, so both are built once and shared.

    Only templates that DECLARE a structure appear in either map — a catalog
    with no declarations costs two empty dicts and one dict lookup per
    template."""
    hit = _CATALOG_STRUCTURE_CACHE.get(id(catalog))
    if hit is not None and hit[0] is catalog:
        return hit[1], hit[2]
    # `str(c)` not `c`: the field's type is the StructureClass Literal, and the
    # gate compares against the plain-str set `evidence_structure` returns.
    declared = {t.id: frozenset(str(c) for c in t.requires_structure)
                for t in catalog.enabled_templates() if t.requires_structure}
    ungrounded = {t.id: _build_ungrounded_score(t)
                  for t in catalog.enabled_templates() if t.requires_structure}
    if len(_CATALOG_STRUCTURE_CACHE) >= _CATALOG_STRUCTURE_CACHE_MAX:
        _CATALOG_STRUCTURE_CACHE.clear()
    _CATALOG_STRUCTURE_CACHE[id(catalog)] = (catalog, declared, ungrounded)
    return declared, ungrounded


def evidence_kinds(evidence: tuple[Signal, ...]) -> frozenset[str]:
    """The kinds this evidence pool can satisfy a clause with.

    Includes the kinds an active-verification RESULT corroborates: that path
    matches on `attrs.corroborates_kinds`, not on the signal's own kind, so a
    kind-only view of the pool would index the witness away (false negative —
    the one failure mode this design forbids). DEBUG_ONLY probes are excluded
    exactly as `_satisfying` excludes them."""
    ks: set[str] = set()
    for s in evidence:
        if probe_authority_of(s) is ProbeAuthority.DEBUG_ONLY:
            continue
        ks.add(s.kind)
        if s.kind == VERIFICATION_RESULT_KIND:
            ks |= _attr_kinds(s, "corroborates_kinds")
    return frozenset(ks)


# ── tracker 157: the structural grounding gate ───────────────────────────────
#
# THE DEFECT. `clause_matches` tests (kind, entity_type, min_deviation) — it
# cannot test the TOPOLOGY. So a signature that NAMES a role, tier or group
# ranks wherever those kinds co-occur, whether or not the estate has the
# structure it names. Measured on the live corpus (2026-08-30, 30 h):
# `sig.ent.fabric.spine-leaf-path-degradation` is the TOP hypothesis on 9,890
# objects of which 6,338 implicate exactly ONE device — a purely local port
# fault ranked as a leaf/spine fabric path degradation. `seams` does not stop
# it: `seams` is a tie-break AFFINITY (engine `_break_ties_by_seam_affinity`),
# not a matching gate. Catalog-wide the shape dominates: of 100 enabled
# templates exactly 2 constrained `role` at all, and 79 declared a seam with no
# structural predicate of their own.
#
# A GATE, NOT A WEIGHT. A confidence discount would be defeated by exactly the
# case that produced the bug — a strong symptom match out-scores the penalty.
# So a template that declares `requires_structure` is admitted to ranking only
# when the evidence ATTESTS every class it declares; otherwise it is scored
# ANALYTICALLY at zero with the refusal recorded in its notes (below) and
# counted into `corr_template_ungrounded_total`. Same list, same length, same
# order: the template is excluded from RANKING, never from the record.
#
# WHERE THE STRUCTURE COMES FROM, and why it is this and nothing else. `rank`
# sees one thing: the evidence. Not the seam inventory, not the adjacency map,
# not device metadata — those are engine context that `rank` is deliberately
# pure of, and the level-1 rank memo (`rank_memo.py`) is keyed on the evidence
# projection ALONE. So the gate reads the ONE structural signal the evidence
# genuinely carries: the SIGNAL KIND. A kind like `fhrp_state_change` or
# `mlag_keepalive_fail` is only ever emitted BY a member OF the group it
# describes — the device is telling us its own structure. That is an
# observation, not a config assertion, which is the bar this fix was held to.
#
# Because the gate is a pure function of `evidence_kinds(ev)` — an input the
# rank key already carries verbatim (rank_memo.py, "Per-signal inputs `rank`
# reads": `sig.kind`, first row) — the memo stays sound with NO change to its
# key. A gated verdict cannot be served from a memo entry minted under
# different structural evidence, because different attesting kinds are a
# different key.
#
# WHAT FAILS CLOSED, EXPLICITLY. `device_tier` has an EMPTY attesting set, so
# it is never attested and every template requiring it is always suppressed.
# That is not an oversight: `Signal` carries no role/tier field, and a survey of
# every `attrs` key over 5,345,497 archived signals (netops.corr_signals_archive,
# 30 h of the production mix, 2026-08-30) returned none — observer_kind, tag,
# state, interface, peer, the aggregation-plane keys, syslog fields, flow
# fields. The platform DOES classify device roles, but that lives in the Go
# topology view (`src/backend/topology/roles.go`) and never reaches the
# evidence plane. Until it does, a leaf/spine or WAN-edge claim is a claim the
# topology cannot support, and the honest answer is to withhold it. When a role
# source lands, it becomes a non-empty entry in this table and the gate opens
# with no template edit.
STRUCTURE_ATTESTING_KINDS: dict[str, frozenset[str]] = {
    # A named topology TIER. Nothing in the evidence plane attests one — see
    # above. Empty ⇒ fails closed, deliberately and visibly.
    "device_tier": frozenset(),
    # Membership of a redundancy / aggregation group. Every kind here is
    # emitted by a device ABOUT the group it belongs to: a standalone box has
    # no FHRP state, no MLAG keepalive, no LACP member and no cluster peer.
    "redundancy_group": frozenset({
        "fhrp_state_change", "fhrp_dual_active",
        "fw_ha_state_change", "fw_sync_fail", "fw_ha_sync_fail",
        "fw_session_owner_mismatch",
        "mlag_peerlink_issue", "mlag_keepalive_fail",
        "lacp_member_bad", "lacp_inconsistent", "lag_member_down",
        "host_bond_mismatch", "ecmp_member_loss",
        "wireless_wlc_member_failover",
    }),
    # An overlay / encapsulation structure over an underlay: a VXLAN-EVPN
    # fabric or a tunnel. Each kind names the encapsulation itself, so it
    # cannot be produced by a native-path fault.
    "overlay_encap": frozenset({
        "vtep_state_change", "vni_reachability_fail", "evpn_route_missing",
        "evpn_mac_move", "arp_suppression_stale", "anycast_gw_inconsistent",
        "tunnel_degraded", "tunnel_flap", "tunnel_down",
        "controller_tunnel_state",
        "ipsec_tunnel_status", "ipsec_underlay_status",
        "ipsec_negotiation_fail", "ipsec_sa_rekey_fail",
    }),
}


# The one class attested by an entity's SHAPE rather than by a kind. A path or
# segment entity is named `<near>-><far>`, both ends non-empty and distinct —
# the same decomposition `engine.Node.device_part` uses to tell a leg from a
# device-local entity (engine.py: `if "->" in eid: return None`). Every
# path/segment entity in the live corpus and in every fixture is that shape.
# The FACT it attests is modest and exact: the platform measured a leg between
# two points here. It is a floor, not a role.
STRUCTURE_ENTITY_ATTESTED: frozenset[str] = frozenset({"transit_path"})
_TRANSIT_ENTITY_TYPES = frozenset({EntityType.PATH, EntityType.SEGMENT})


def _attests_transit_leg(evidence: tuple[Signal, ...]) -> bool:
    """True iff some non-debug path/segment signal names two distinct endpoints.

    Short-circuits on the first hit: on the live shape most objects carry no
    path entity at all, so this is a type check over the evidence and nothing
    more."""
    for s in evidence:
        if s.entity_type not in _TRANSIT_ENTITY_TYPES:
            continue
        if probe_authority_of(s) is ProbeAuthority.DEBUG_ONLY:
            continue
        near, sep, far = s.entity_id.partition("->")
        if sep and near and far and near != far:
            return True
    return False


def evidence_structure(evidence: tuple[Signal, ...],
                       present: frozenset[str]) -> frozenset[str]:
    """The structural classes THIS evidence attests.

    Two mechanisms, both reading fields the rank memo's key already carries
    (`sig.kind`, `sig.entity_type`, `sig.entity_id`), so the gate needs no
    change to that key:

      * KIND-attested (`STRUCTURE_ATTESTING_KINDS`) — takes the already-computed
        `evidence_kinds(ev)`, so the DEBUG_ONLY exclusion and the
        active-verification corroboration lane are inherited exactly: a
        verification result that corroborates `fhrp_state_change` attests the
        group the same as the device's own report, and a lab probe attests
        nothing.
      * ENTITY-attested (`STRUCTURE_ENTITY_ATTESTED`) — a measured leg.

    Pure, total, and monotone: adding evidence can only add classes."""
    attested = {cls for cls, ks in STRUCTURE_ATTESTING_KINDS.items()
                if ks & present}
    if _attests_transit_leg(evidence):
        attested.add("transit_path")
    return frozenset(attested)


def structure_gap(template: Template, attested: frozenset[str]) -> tuple[str, ...]:
    """The structural classes this template declares and the evidence does NOT
    attest — empty when the template is grounded (or declares nothing). Sorted,
    so the recorded reason is deterministic."""
    return tuple(sorted(c for c in template.requires_structure if c not in attested))


# ── tracker 167: SELECTIVITY MEASUREMENT ─────────────────────────────────────
#
# The fast path above shipped unmeasured — nothing counted how many templates it
# actually elides on live evidence, so its value was an argument, not a number.
# Two plain counters (no labels) make the ratio computable from the exposition:
#
#     selectivity = corr_template_scored_total / corr_template_candidates_total
#
#   candidates — enabled templates CONSIDERED by a `rank()` call; exactly what a
#                pre-167 build would have pushed through `score_template`.
#   scored     — those that survived the kind index and were really scored.
#
# WHERE THEY COUNT, and why that is the honest decision point:
#   • Incremented ONCE per `rank()` call, from loop-local ints — the counters are
#     two module ints, so there is no per-template call and no allocation.
#   • A rank-memo HIT never reaches `rank()` (engine.py consults the memo first),
#     so a served-from-memo component contributes to NEITHER counter. That is
#     deliberate: this ratio measures the INDEX, and the memo has its own
#     `corr_rank_memo` series. Mixing them would flatter both.
#   • A retry that re-ranks the same component is a genuine second evaluation and
#     counts once per evaluation — there is no retry loop inside `rank()` itself,
#     so a single call can never double-count a template.
# Counters are monotonic process-lifetime totals; read them as a rate/ratio.
#
# MEASURED OFFLINE, 2026-08-30, before these counters ever ran live: the
# archived evidence pools of the scale-run corpus (ClickHouse
# netops.corr_signals_archive, last 24 h, 4.64 M signals grouped by
# `archived_for` into 21,197 real objects → 55 distinct kind sets) replayed
# through `rank()` and read off these counters: 419,339 / 2,119,700 =
# **19.78 %** — the index elides 80.2 % of template scorings on the
# production mix. The live counters are what keep that number honest as the
# catalog and the traffic mix move.
_TEMPLATE_SCORED_TOTAL = 0
_TEMPLATE_CANDIDATES_TOTAL = 0

# ── tracker 157: the refusal is observable ───────────────────────────────────
#
# A suppression nobody can count is indistinguishable from a bug. This counter
# is the number of (rank() x template) evaluations where a template SURVIVED the
# kind index — its evidence was there, it would have been scored — and was then
# refused because the evidence attests none of the structure it names.
#
# WHERE IT SITS RELATIVE TO THE 167 COUNTERS. `scored` and `ungrounded` are
# disjoint and 167's ratio keeps its old meaning:
#
#     candidates  = scored + ungrounded + (nothing the evidence could reach)
#     selectivity = scored / candidates      (as before — 'really scored')
#
# so the difference between a pre-157 and a post-157 `scored` is exactly this
# counter. A template that is BOTH unreachable by kind and ungrounded is
# counted in neither — the index already accounts for it, and counting a
# refusal that cost nothing would flatter the number. Read it as a rate: a
# spike means the catalog is being asked for verdicts the estate's topology
# cannot support (an inventory gap, a mis-scoped tenant), which is worth an
# operator's attention in its own right.
_TEMPLATE_UNGROUNDED_TOTAL = 0


def template_scoring_stats() -> dict[str, int]:
    """Snapshot of the template-gate counters for the metrics exposition:
    ``{"scored": …, "candidates": …, "ungrounded": …}`` (tracker 167 + 157).
    Read-only; a plain dict of ints so the caller can never reach back into the
    counters."""
    return {"scored": _TEMPLATE_SCORED_TOTAL,
            "candidates": _TEMPLATE_CANDIDATES_TOTAL,
            "ungrounded": _TEMPLATE_UNGROUNDED_TOTAL}


def template_scoring_metric_lines() -> tuple[str, ...]:
    """The two counters as Prometheus exposition lines, so the metric NAMES stay
    owned by the module that counts and `_metrics_text()` needs a single
    `*template_scoring_metric_lines(),`. Plain counters — no labels."""
    st = template_scoring_stats()
    return (
        ("# HELP corr_template_scored_total Templates actually scored by rank() "
         "(survived the tracker-167 kind index)."),
        "# TYPE corr_template_scored_total counter",
        f"corr_template_scored_total {st['scored']}",
        ("# HELP corr_template_candidates_total Enabled templates considered per "
         "rank() evaluation — what a pre-167 build would have scored. Selectivity "
         "= corr_template_scored_total / corr_template_candidates_total."),
        "# TYPE corr_template_candidates_total counter",
        f"corr_template_candidates_total {st['candidates']}",
        ("# HELP corr_template_ungrounded_total Templates refused by the "
         "tracker-157 structural gate — the evidence attests none of the "
         "role/tier/group structure the signature names, so it was excluded "
         "from ranking. Disjoint from corr_template_scored_total; counted only "
         "when the kind index would otherwise have scored the template."),
        "# TYPE corr_template_ungrounded_total counter",
        f"corr_template_ungrounded_total {st['ungrounded']}",
    )


def reset_template_scoring_stats() -> None:
    """Zero the selectivity and grounding counters. Tests and offline
    measurement runs only — the engine never calls this (a counter that resets
    in production would make the ratio unreadable)."""
    global _TEMPLATE_SCORED_TOTAL, _TEMPLATE_CANDIDATES_TOTAL
    global _TEMPLATE_UNGROUNDED_TOTAL
    _TEMPLATE_SCORED_TOTAL = 0
    _TEMPLATE_CANDIDATES_TOTAL = 0
    _TEMPLATE_UNGROUNDED_TOTAL = 0


def rank(catalog: Catalog, evidence: tuple[Signal, ...] | list[Signal]) -> RankingResult:
    """Score every enabled template; rank by confidence with deterministic
    tie-break (template id) so equal scores never flap between runs."""
    global _TEMPLATE_SCORED_TOTAL, _TEMPLATE_CANDIDATES_TOTAL
    global _TEMPLATE_UNGROUNDED_TOTAL
    ev = tuple(evidence)
    # tracker 167: score only the templates the evidence could possibly reach;
    # the rest get their fully-determined zero score analytically. Same list,
    # same order, same values — see the module note above.
    present = evidence_kinds(ev)
    index, inapplicable = _catalog_plan(catalog)
    # tracker 157: and of the templates the evidence CAN reach, admit only those
    # whose named structure the evidence attests. Both maps are empty for a
    # catalog that declares no structure, so the gate is a dict lookup that
    # cannot fire.
    declared, ungrounded_score = _catalog_structure_plan(catalog)
    attested = evidence_structure(ev, present) if declared else frozenset()
    templates = catalog.enabled_templates()
    scores: list[HypothesisScore] = []
    append = scores.append          # bound once: this loop runs catalog-sized
    scored = 0                      # per rank(), and rank() runs per component
    ungrounded = 0
    for t in templates:
        reachable = bool(index[t.id] & present)
        need = declared.get(t.id)
        if need is not None and not need <= attested:
            # The structure this signature names is not in evidence. It is
            # excluded from RANKING (analytic zero, refusal on the record) —
            # never discounted, because a strong symptom match would out-score
            # a discount and re-create the defect.
            #
            # The refusal is decided BEFORE the kind index so that the score
            # this template EMITS does not depend on whether the index elided
            # it: tracker 167's invariant is that the fast path changes no
            # byte of the output, and an index that swapped the ungrounded note
            # for a bare inapplicable score would have broken it.
            #
            # It is COUNTED only when the index would have let it through —
            # the interesting number is "would have been scored, and was
            # refused for lack of structure", not "was never going to match
            # anyway", which the index already accounts for.
            append(ungrounded_score[t.id])
            if reachable:
                ungrounded += 1
        elif reachable:
            append(score_template(t, ev))
            scored += 1
        else:
            append(inapplicable[t.id])
    _TEMPLATE_SCORED_TOTAL += scored
    _TEMPLATE_CANDIDATES_TOTAL += len(templates)
    _TEMPLATE_UNGROUNDED_TOTAL += ungrounded
    # Equal confidence → prefer the MORE SPECIFIC explanation (more matched
    # clauses = more of the evidence explained); template id only as the final
    # deterministic tie-break. Keeps a broad single-clause look-alike from
    # shadowing a multi-witness signature it ties with.
    scores.sort(key=lambda s: (-s.confidence_rank, -len(s.satisfied), s.template_id))

    # Forced competitors must appear in the visible set even if low-ranked
    # (competing hypotheses by construction — §4.5).
    visible: list[HypothesisScore] = scores[:TOP_K]
    visible_ids = {s.template_id for s in visible}
    forced_ids = {fid for s in visible for fid in s.forced_competitors}
    for s in scores[TOP_K:]:
        if s.template_id in forced_ids and s.template_id not in visible_ids:
            visible.append(s)
            visible_ids.add(s.template_id)
    # And the converse: a CONTRADICTED look-alike whose discriminator handed the
    # win to a visible template stays visible too — it is the "ruled out
    # because…" row (anti-black-box), and must not silently fall off just
    # because the catalog grew enough 0.5-scorers to fill TOP_K.
    for s in scores[TOP_K:]:
        if s.contradicted and s.template_id not in visible_ids and visible_ids & set(s.forced_competitors):
            visible.append(s)
            visible_ids.add(s.template_id)
            visible_ids.add(s.template_id)

    if not scores or scores[0].confidence_rank < CONFIDENCE_FLOOR:
        # No forced root cause. evidence_missing = the unsatisfied required
        # clauses of the NEAREST templates (best coverage first) — "what would
        # confirm", derived from data.
        nearest = sorted(scores, key=lambda s: (-s.coverage, s.template_id))[:2]
        missing = tuple(dict.fromkeys(
            f"{s.template_id}: needs {m}" for s in nearest for m in s.missing
        ))
        return RankingResult(
            top_hypothesis="undetermined",
            verdict_tier=VerdictTier.UNDETERMINED,
            hypotheses=tuple(visible),
            evidence_missing=missing,
            catalog_version=catalog.version_hash(),
        )

    top = scores[0]
    # Signature-specific evidence_missing: when a template matched but the
    # verdict can't confirm, the real gap is usually NOT an unsatisfied clause
    # (coverage may be 1.0) but the verdict gate's shortfall — a missing second
    # modality, a single observer, or a fate-shared pair. Surface both so the
    # checklist is actionable per-object, never the old catalog-wide boilerplate.
    top_missing: tuple[str, ...] = ()
    if top.verdict_gate.tier is not VerdictTier.CONFIRMED:
        clause_gaps = tuple(f"{top.template_id}: needs {m}" for m in top.missing)
        gate_gaps = tuple(f"{top.template_id}: {r}" for r in top.verdict_gate.reasons)
        top_missing = tuple(dict.fromkeys(clause_gaps + gate_gaps))
    return RankingResult(
        top_hypothesis=top.template_id,
        verdict_tier=top.verdict_gate.tier,   # rank ≠ verdict: tier comes from the gate
        hypotheses=tuple(visible),
        evidence_missing=top_missing,
        catalog_version=catalog.version_hash(),
    )
