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

from catalog import Catalog, Clause, Template
from signals import ProbeAuthority, Signal, probe_authority_of
from verdicts import Verdict as GateVerdict
from verdicts import VerdictTier, assess

# Config-hash members (P4 replay-driven calibration re-fits; never tuned silently).
CONTRADICTION_PENALTY = 0.2
OPTIONAL_BONUS_PER_CLAUSE = 0.05
OPTIONAL_BONUS_CAP = 0.1
CONFIDENCE_FLOOR = 0.3   # rank-1 below this ⇒ object outcome 'undetermined'
TOP_K = 4


def clause_matches(clause: Clause, sig: Signal) -> bool:
    """Total predicate: signal vs one clause. Role constraints need topology
    context the scorer doesn't have yet — a role-constrained clause matches on
    the other fields and the gap is declared in the score's notes (honest,
    not silently strict or silently lax)."""
    if sig.kind not in clause.kinds():
        return False
    if clause.entity_type is not None and sig.entity_type is not clause.entity_type:
        return False
    if clause.min_deviation is not None and abs(sig.deviation) < clause.min_deviation:
        return False
    return True


def _satisfying(clause: Clause, evidence: tuple[Signal, ...]) -> tuple[Signal, ...]:
    # Decision #1: a debug_only / lab probe can never satisfy a clause — it must
    # not attach as supporting evidence nor drive a customer-facing hypothesis.
    return tuple(
        s for s in evidence
        if clause_matches(clause, s) and probe_authority_of(s) is not ProbeAuthority.DEBUG_ONLY
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
        for hits in (_satisfying(Clause(kind=st.witness), evidence),)
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


def rank(catalog: Catalog, evidence: tuple[Signal, ...] | list[Signal]) -> RankingResult:
    """Score every enabled template; rank by confidence with deterministic
    tie-break (template id) so equal scores never flap between runs."""
    ev = tuple(evidence)
    scores = [score_template(t, ev) for t in catalog.enabled_templates()]
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
