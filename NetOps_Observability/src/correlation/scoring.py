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

Object outcome: rank-1 below the confidence floor ⇒ ``undetermined`` with
``evidence_missing`` derived mechanically from the nearest template's
unsatisfied clauses — no forced root cause, ever.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache

from catalog import Catalog, Clause, Template
from signals import ModalityClass, ProbeAuthority, Signal, probe_authority_of
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
    """Total predicate: signal vs one clause. Role constraints need topology
    context the scorer doesn't have yet — a role-constrained clause matches on
    the other fields and the gap is declared in the score's notes (honest,
    not silently strict or silently lax)."""
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


def rank(catalog: Catalog, evidence: tuple[Signal, ...] | list[Signal]) -> RankingResult:
    """Score every enabled template; rank by confidence with deterministic
    tie-break (template id) so equal scores never flap between runs."""
    ev = tuple(evidence)
    # tracker 167: score only the templates the evidence could possibly reach;
    # the rest get their fully-determined zero score analytically. Same list,
    # same order, same values — see the module note above.
    present = evidence_kinds(ev)
    index, inapplicable = _catalog_plan(catalog)
    scores = [
        score_template(t, ev) if index[t.id] & present else inapplicable[t.id]
        for t in catalog.enabled_templates()
    ]
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
