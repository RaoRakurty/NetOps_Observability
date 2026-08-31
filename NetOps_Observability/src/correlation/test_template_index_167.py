"""Tracker 167 — the provably-inapplicable fast path must be invisible.

WHAT CHANGED. `rank()` used to call `score_template` for all 100 catalog
templates against every RCA object. Post-168 the engine emits ~1,000 correct
device-local objects per replica instead of one estate-wide weld, so that
became 100,000+ scorings per cycle — measured at 17.98 s of a 29.71 s cycle
while `build_edges` was 4.11 s.

WHAT DID NOT CHANGE, and must not. `rank()` does not discard low scorers:
`evidence_missing` comes from `sorted(scores, key=-coverage)[:2]`, forced
competitors and contradicted look-alikes are pulled from `scores[TOP_K:]`, and
`evidence_missing` is persisted and hashed. So no template is skipped — a
template that CANNOT match is scored analytically instead of by brute force.

THE ORACLE. The exhaustive scan is kept, verbatim, as the correctness
reference. Every test below compares indexed output against it and requires
EXACT equality — not "equivalent enough".

The asymmetry that governs the design:
    false positive in the filter = wasted CPU
    false negative in the filter = changed RCA semantics
so the filter is a sound SUPERSET and `score_template` stays the only authority.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

import scoring
from catalog import Catalog, Clause, Template, builtin_catalog
from scoring import (
    _inapplicable_score,
    evidence_kinds,
    rank,
    score_template,
)
from signals import (
    EntityType,
    ModalityClass,
    Observer,
    ObserverType,
    Severity,
    Signal,
    Source,
)

T0 = datetime(2026, 8, 21, 9, 0, 0, tzinfo=timezone.utc)
CAT = builtin_catalog()
ALL_TEMPLATES = CAT.enabled_templates()


def exhaustive_rank(catalog: Catalog, evidence):
    """THE ORACLE — the pre-167 body of rank(), scoring every template."""
    ev = tuple(evidence)
    scores = [score_template(t, ev) for t in catalog.enabled_templates()]
    return scores


def sig(kind, *, entity_type=EntityType.INTERFACE, entity_id="dev-1:Gi0/1",
        offset_s=0.0, modality=ModalityClass.CONTROL_PLANE, deviation=5.0,
        attrs=None, source=Source.SYSLOG, tokens=("dev-1",)):
    return Signal(
        tenant_id="acme", ts=T0 + timedelta(seconds=offset_s), source=source,
        kind=kind, observer=Observer(observer_id="dev-1",
                                     observer_type=ObserverType.DEVICE),
        modality_class=modality, entity_type=entity_type, entity_id=entity_id,
        severity=Severity.HIGH, native_id=f"n|{kind}|{offset_s}",
        entity_tokens=tokens, deviation=deviation,
        attrs={"onset_uncertainty_s": 5.0, **(attrs or {})})


def assert_identical(evidence, why=""):
    """Full-field equality of the indexed scores against the oracle, in order."""
    ev = tuple(evidence)
    fast = [score_template(t, ev) if scoring._catalog_kind_index(CAT)[t.id]
            & evidence_kinds(ev) else _inapplicable_score(t)
            for t in ALL_TEMPLATES]
    slow = exhaustive_rank(CAT, ev)
    assert len(fast) == len(slow)
    for f, s in zip(fast, slow, strict=True):
        assert f == s, (
            f"{why}: template {s.template_id} differs\n  indexed={f}\n  oracle ={s}")
    # the persisted ranking must also survive the round trip
    assert rank(CAT, ev).to_dict() is not None
    return fast, slow


# ── the whole catalog, every template, no evidence-shape assumptions ─────────


def test_EVERY_template_scores_identically_when_nothing_matches():
    """The pure fast-path case, across all 100 templates at once."""
    ev = (sig("a_kind_no_template_declares"),)
    for t in ALL_TEMPLATES:
        assert _inapplicable_score(t) == score_template(t, ev), (
            f"analytic score diverges from the scorer for {t.id}")


def test_EVERY_template_scores_identically_against_its_OWN_first_kind():
    """The fall-through case: for each template, feed a signal of a kind it
    declares and require the indexed path to hand it to the real scorer with an
    identical result."""
    for t in ALL_TEMPLATES:
        kind = min(t.requires[0].kinds())
        ev = (sig(kind, entity_type=t.requires[0].entity_type or EntityType.INTERFACE),)
        assert scoring._catalog_kind_index(CAT)[t.id] & evidence_kinds(ev), (
            f"{t.id} was indexed away from its own declared kind {kind!r} — "
            f"this is the false negative the design forbids")
        assert_identical(ev, why=f"{t.id}/{kind}")


@pytest.mark.parametrize("kinds", [
    ("link_state_change",),
    ("link_state_change", "if_errors"),
    ("bgp_adjacency_change", "device_cpu_high", "if_util_high"),
    ("probe_loss",),
    ("device_restart", "link_state_change", "mac_flap", "if_discards"),
])
def test_multi_kind_objects_are_identical(kinds):
    ev = tuple(sig(k, offset_s=i * 3) for i, k in enumerate(kinds))
    assert_identical(ev, why=str(kinds))


def test_object_with_extra_unrelated_kinds_is_identical():
    """Adding noise must not change any template's score."""
    ev = (sig("link_state_change"), sig("totally_unrelated_kind", offset_s=5),
          sig("another_unknown", offset_s=9))
    assert_identical(ev, why="noise")


# ── the adversarial matrix (phase 15) ────────────────────────────────────────


def test_ALTERNATION_a_template_is_reachable_by_every_alternation_token():
    """`kind='qos_drops|if_discards'` must be reachable by BOTH tokens."""
    alt = [(t, c) for t in ALL_TEMPLATES for c in t.requires if "|" in c.kind]
    assert alt, "no alternation clauses in the catalog — this test is vacuous"
    for t, c in alt[:12]:
        for token in sorted(c.kinds()):
            ev = (sig(token),)
            assert scoring._catalog_kind_index(CAT)[t.id] & evidence_kinds(ev), (
                f"{t.id} unreachable via alternation token {token!r}")
            assert_identical(ev, why=f"{t.id}/alt/{token}")


def test_OPTIONAL_clause_kinds_are_indexed():
    """An optional clause grants a coverage BONUS; a template reachable only
    through one must not be filtered out."""
    opt = [(t, c) for t in ALL_TEMPLATES for c in t.requires if c.optional]
    assert opt, "no optional clauses — vacuous"
    for t, c in opt[:12]:
        for token in sorted(c.kinds()):
            ev = (sig(token),)
            assert scoring._catalog_kind_index(CAT)[t.id] & evidence_kinds(ev)
            assert_identical(ev, why=f"{t.id}/optional/{token}")


def test_DISCRIMINATOR_absence_kinds_are_indexed():
    """A discriminator makes a template CONTRADICTED — a visible 'ruled out
    because' row. Indexing it away would silently delete that row."""
    disc = [(t, d) for t in ALL_TEMPLATES for d in t.discriminators]
    assert disc, "no discriminators — vacuous"
    for t, d in disc[:12]:
        for token in sorted(d.absent.kinds()):
            ev = (sig(token),)
            assert scoring._catalog_kind_index(CAT)[t.id] & evidence_kinds(ev), (
                f"{t.id} unreachable via discriminator kind {token!r}")
            assert_identical(ev, why=f"{t.id}/disc/{token}")


def test_CAUSAL_CHAIN_witness_kinds_are_indexed():
    chain = [(t, st) for t in ALL_TEMPLATES for st in t.causal_chain]
    if not chain:
        pytest.skip("no causal_chain templates in this catalog")
    for t, st in chain:
        # `witness` is itself an alternation string, exactly like Clause.kind
        for token in sorted(Clause(kind=st.witness).kinds()):
            ev = (sig(token),)
            assert scoring._catalog_kind_index(CAT)[t.id] & evidence_kinds(ev), (
                f"{t.id} unreachable via causal-chain witness {token!r}")
            assert_identical(ev, why=f"{t.id}/chain/{token}")


def test_VERIFICATION_corroboration_is_never_indexed_away():
    """`active_verification_result` satisfies a clause through
    attrs.corroborates_kinds, NOT through its own kind. A kind-only view of the
    evidence pool would filter the template away — the exact false negative the
    design forbids."""
    target = "link_state_change"
    ev = (sig(scoring.VERIFICATION_RESULT_KIND,
              attrs={"corroborates_kinds": [target]}),)
    assert target in evidence_kinds(ev), (
        "corroborated kinds must be part of the effective evidence kind set")
    assert_identical(ev, why="verification corroboration")


def test_VERIFICATION_healthy_refutation_path_is_identical():
    ev = (sig("link_state_change"),
          sig(scoring.VERIFICATION_HEALTHY_KIND, offset_s=4,
              attrs={"refutes_kinds": ["link_state_change"]}))
    assert_identical(ev, why="verification refutation")


def test_DEBUG_ONLY_probes_are_excluded_from_the_index_exactly_as_from_scoring():
    """`_satisfying` drops DEBUG_ONLY signals; the kind view must too, or a
    template would fall through and score 0 anyway (harmless) — but the two
    must agree so the equivalence is exact."""
    ev = (sig("link_state_change", attrs={"probe_authority": "debug_only"}),)
    assert_identical(ev, why="debug-only probe")


def test_an_EMPTY_evidence_pool_is_identical():
    assert_identical((), why="empty")


# ── the persisted result, not just the score list ────────────────────────────


@pytest.mark.parametrize("kinds", [
    ("link_state_change",),
    ("link_state_change", "if_errors", "device_cpu_high"),
    ("a_kind_no_template_declares",),
])
def test_rank_result_is_byte_identical_including_evidence_missing(kinds, monkeypatch):
    """`evidence_missing` is derived from the LOWEST scorers, so it is the field
    most exposed to an over-eager filter — and it is persisted and hashed."""
    ev = tuple(sig(k, offset_s=i * 3) for i, k in enumerate(kinds))
    indexed = rank(CAT, ev)

    # force the exhaustive path by making every template look applicable.
    # Patch `_catalog_plan` — the seam rank() actually reads (it returns the
    # kind index AND the prebuilt analytic scores together).
    real_plan = scoring._catalog_plan
    monkeypatch.setattr(
        scoring, "_catalog_plan",
        lambda c: ({t.id: frozenset({"__always__"}) for t in c.enabled_templates()},
                   real_plan(c)[1]))
    monkeypatch.setattr(scoring, "evidence_kinds", lambda e: frozenset({"__always__"}))
    exhaustive = rank(CAT, ev)

    assert indexed.to_dict() == exhaustive.to_dict(), "persisted ranking differs"
    assert indexed.evidence_missing == exhaustive.evidence_missing
    assert indexed.top_hypothesis == exhaustive.top_hypothesis
    assert indexed.verdict_tier == exhaustive.verdict_tier
    assert [h.template_id for h in indexed.hypotheses] == \
           [h.template_id for h in exhaustive.hypotheses]


# ── mutants (phase 16) ───────────────────────────────────────────────────────


def test_MUTANT_A_dropping_a_kind_association_breaks_equivalence():
    """If the index forgets a legitimate kind→template link, the template is
    scored analytically as zero when it should have matched."""
    t = next(t for t in ALL_TEMPLATES if not t.requires[0].optional)
    kind = min(t.requires[0].kinds())
    ev = (sig(kind, entity_type=t.requires[0].entity_type or EntityType.INTERFACE),)
    real = score_template(t, ev)
    mutant = _inapplicable_score(t)          # what a forgotten association yields
    assert mutant != real, (
        f"{t.id}: the analytic zero equals the real score even when the clause "
        f"matches — this test cannot detect a lost association")


def test_MUTANT_C_indexing_only_the_first_signal_kind_breaks_multi_modality():
    """A filter keyed on evidence[0].kind alone would lose templates reachable
    only through a later signal."""
    idx = scoring._catalog_kind_index(CAT)
    # pick a second kind that genuinely unlocks templates the first does not
    first = "link_state_change"
    reach1 = {tid for tid, ks in idx.items() if first in ks}
    second = next(
        k for k in sorted({k for ks in idx.values() for k in ks})
        if {tid for tid, ks in idx.items() if k in ks} - reach1)
    ev = (sig(first), sig(second, offset_s=5))
    full = evidence_kinds(ev)
    first_only = frozenset({first})
    lost = [tid for tid, ks in idx.items() if (ks & full) and not (ks & first_only)]
    assert lost, "no template is reachable only via the second signal — vacuous"
    # the shipped filter uses the full set, so nothing is lost
    assert_identical(ev, why="multi-modality")


def test_MUTANT_D_intersection_instead_of_union_loses_templates():
    """The candidate set must be the UNION over the object's kinds."""
    ev = (sig("link_state_change"), sig("device_cpu_high", offset_s=5))
    idx = scoring._catalog_kind_index(CAT)
    union = evidence_kinds(ev)
    inter = frozenset({"link_state_change"}) & frozenset({"device_cpu_high"})
    assert inter == frozenset()
    reachable_union = [tid for tid, ks in idx.items() if ks & union]
    reachable_inter = [tid for tid, ks in idx.items() if ks & inter]
    assert reachable_union and not reachable_inter, (
        "intersection semantics would score nothing")


def test_MUTANT_E_a_reloaded_catalog_gets_a_fresh_index():
    """The index is cached per Catalog VALUE. A different catalog must not be
    served the previous one's index."""
    small = Catalog(templates=tuple(ALL_TEMPLATES[:3]))
    assert set(scoring._catalog_kind_index(small)) == {t.id for t in ALL_TEMPLATES[:3]}
    assert len(scoring._catalog_kind_index(CAT)) == len(ALL_TEMPLATES)
    assert set(scoring._catalog_kind_index(small)) != set(scoring._catalog_kind_index(CAT))


def test_the_empty_gate_memo_key_is_defensive_not_decorative():
    """`_empty_gate` keys on required_modalities. Today `assess([], m)` returns
    the same verdict for all 11 distinct modality sets in the catalog, so the
    key is not load-bearing — mutating it to a constant survives, correctly.

    This test PINS that assumption. If `assess` ever starts distinguishing
    modality requirements on an empty signal pool, this goes red and the memo
    key becomes load-bearing rather than silently returning a wrong gate."""
    from verdicts import assess as _assess
    mods = {frozenset(t.required_modalities) or None for t in ALL_TEMPLATES}
    assert len(mods) > 1, "catalog has only one modality shape — vacuous"
    results = {repr(_assess([], required_modalities=m)) for m in mods}
    assert len(results) == 1, (
        "assess([], m) now varies with required_modalities — _empty_gate's key "
        "is load-bearing and this test should be replaced by a real equivalence "
        "assertion per modality set")


def test_MUTANT_G_ordering_is_preserved():
    """`rank` sorts on (confidence, len(satisfied), template_id); the score list
    must stay in catalog order before that sort or ties could resolve
    differently."""
    ev = (sig("link_state_change"),)
    fast, slow = assert_identical(ev, why="ordering")
    assert [s.template_id for s in fast] == [s.template_id for s in slow]
    assert [s.template_id for s in slow] == [t.id for t in ALL_TEMPLATES]


# ── the SELECTIVITY COUNTERS (tracker 167, measurement) ──────────────────────
#
# The fast path above shipped unmeasured. `corr_template_scored_total` /
# `corr_template_candidates_total` make its live selectivity computable:
#
#     selectivity = scored / candidates
#
# Measured offline on the LIVE corpus (netops.corr_signals_archive, 24 h of the
# production-mix scale runs, 21,197 archived evidence pools reduced to their
# distinct kind sets, replayed through `rank()` and read off these counters):
# 419,339 / 2,119,700 = **19.78 %** — the index elides 80.2 % of template
# scorings. The tests below pin what the counters MEAN, not that number.


@pytest.fixture(autouse=False)
def counters():
    """Zeroed counters, and zeroed again afterwards so ordering never matters."""
    scoring.reset_template_scoring_stats()
    yield scoring.template_scoring_stats
    scoring.reset_template_scoring_stats()


def _fixture_catalog():
    """A hand-computable catalog: five ENABLED templates with declared kinds
    A · B · (A|C) · D · E, plus a DISABLED one on A.

    Every number below is countable by eye — that is the point. Nothing here
    depends on the builtin catalog's content."""
    from catalog import Verdict as CatVerdict

    def tmpl(name, kind, *, enabled=True):
        return Template(
            id=f"sig.ent.test.{name}", title=name, domain="ent.test",
            enabled=enabled, requires=(Clause(kind=kind),),
            verdict=CatVerdict(owner="netops", layer="L2",
                               first_steps=("check the thing",)))

    return Catalog(templates=(
        tmpl("a", "kind_a"),
        tmpl("b", "kind_b"),
        tmpl("ac", "kind_a|kind_c"),
        tmpl("d", "kind_d"),
        tmpl("e", "kind_e"),
        tmpl("disabled_a", "kind_a", enabled=False),
    ))


def test_counters_are_hand_computable(counters):
    """Evidence {kind_a, kind_d} over the fixture catalog:
         candidates = 5   (the ENABLED templates — the disabled one is not
                           considered, so it is not a candidate either)
         scored     = 3   (a on kind_a, ac via the alternation, d on kind_d;
                           b and e are elided)"""
    cat = _fixture_catalog()
    rank(cat, (sig("kind_a"), sig("kind_d", offset_s=5)))
    st = counters()
    # `ungrounded` (tracker 157) is 0 and must stay 0: this fixture catalog
    # declares no `requires_structure`, so the structural gate cannot fire on
    # it. A non-zero here would mean the gate fires on templates that never
    # asked for it.
    assert st == {"scored": 3, "candidates": 5, "ungrounded": 0}
    assert st["scored"] / st["candidates"] == 0.6


def test_candidates_counts_every_enabled_template_even_with_no_matches(counters):
    """The denominator is what a pre-167 build WOULD have scored — so an object
    that reaches nothing still contributes its full candidate count."""
    cat = _fixture_catalog()
    rank(cat, (sig("kind_nothing_declares"),))
    assert counters() == {"scored": 0, "candidates": 5, "ungrounded": 0}


def test_counters_accumulate_once_per_evaluation(counters):
    """Two evaluations = two candidate charges and the sum of their scored
    counts. A single `rank()` call can never charge a template twice."""
    cat = _fixture_catalog()
    rank(cat, (sig("kind_a"),))                      # scores a + ac
    rank(cat, (sig("kind_b"),))                      # scores b
    assert counters() == {"scored": 3, "candidates": 10, "ungrounded": 0}


def test_only_rank_charges_the_counters(counters):
    """`rank()` is the only writer, by design. The counters live INSIDE it, and
    engine.py consults the rank memo BEFORE calling it (`if base_ranking is
    None: rank(...)`), so a component served from the memo contributes to
    NEITHER counter — this ratio measures the INDEX, and the memo has its own
    `corr_rank_memo` series. Mixing the two would flatter both.

    Equally, the scoring primitives are not the decision point: scoring a
    template outside a `rank()` evaluation (the equivalence oracle, benches)
    must not inflate the numerator."""
    t = ALL_TEMPLATES[0]
    ev = (sig(min(t.requires[0].kinds())),)
    score_template(t, ev)
    _inapplicable_score(t)
    evidence_kinds(ev)
    assert counters() == {"scored": 0, "candidates": 0, "ungrounded": 0}
    rank(_fixture_catalog(), (sig("kind_a"),))
    assert counters() == {"scored": 2, "candidates": 5, "ungrounded": 0}


def test_the_snapshot_cannot_write_back_to_the_counters(counters):
    cat = _fixture_catalog()
    rank(cat, (sig("kind_a"),))
    snap = counters()
    snap["scored"] = 10_000
    assert counters()["scored"] == 2


def test_MUTANT_no_fast_path_drives_the_ratio_to_one(counters, monkeypatch):
    """THE MUTANT. Drop the fast path — every template reaches `score_template`
    — and the counters must say so: scored == candidates, a strictly larger
    numerator than the indexed run over the same evidence. The RANKING must be
    byte-identical either way (the fast path is invisible; only the ratio moves)."""
    ev = (sig("link_state_change"), sig("bgp_adjacency_change", offset_s=5))

    indexed = rank(CAT, ev)
    st_indexed = counters()
    assert st_indexed["candidates"] == len(ALL_TEMPLATES)
    assert 0 < st_indexed["scored"] < st_indexed["candidates"], (
        "the index elided nothing on real multi-kind evidence — vacuous mutant")

    real_plan = scoring._catalog_plan

    def no_index(catalog):
        """Every template 'reachable' from any kind — i.e. no fast path."""
        index, inapplicable = real_plan(catalog)
        every = frozenset(k for ks in index.values() for k in ks)
        return {tid: every | evidence_kinds(ev) for tid in index}, inapplicable

    scoring.reset_template_scoring_stats()
    monkeypatch.setattr(scoring, "_catalog_plan", no_index)
    exhaustive = rank(CAT, ev)
    st_mutant = counters()

    # With no index every enabled template is REACHABLE, so the two elision
    # counters must account for the whole catalog between them. The residue is
    # the tracker-157 structural gate, which is not the fast path and does not
    # go away when the fast path does — that is exactly the point of counting
    # it separately.
    assert st_mutant["candidates"] == len(ALL_TEMPLATES)
    assert st_mutant["scored"] + st_mutant["ungrounded"] == len(ALL_TEMPLATES)
    assert st_mutant["scored"] > st_indexed["scored"], (
        "dropping the fast path did not change the numerator — the counters are "
        "not measuring the fast path")
    def ratio(s: dict) -> float:
        return s["scored"] / s["candidates"]

    def reached(s: dict) -> float:
        return (s["scored"] + s["ungrounded"]) / s["candidates"]

    assert reached(st_mutant) == 1.0 and reached(st_indexed) < 1.0
    assert ratio(st_mutant) > ratio(st_indexed)
    assert indexed == exhaustive, "the fast path changed the ranking"


def test_selectivity_on_the_production_mix_is_real(counters):
    """The six classifying kinds of EVENT_MIX_REALISTIC
    (scripts/scale-miniladder.py:4934-4957) in one object — the shape the live
    measurement is dominated by. A loose band: this is a regression guard on the
    index still paying for itself as the catalog grows, not a pin on 30 %."""
    mix = ("link_state_change", "bgp_adjacency_change", "ospf_adjacency_change",
           "lldp_neighbor_change", "stp_topology_change", "device_alarm")
    rank(CAT, tuple(sig(k, offset_s=3 * i) for i, k in enumerate(mix)))
    st = counters()
    assert st["candidates"] == len(ALL_TEMPLATES)
    assert 0 < st["scored"] / st["candidates"] < 0.6, (
        f"selectivity {st} left the band the fast path was justified by")


def test_the_exposition_lines_carry_both_counters(counters):
    """The metric names live with the counters, so `_metrics_text()` needs one
    `*template_scoring_metric_lines(),` and cannot drift from what it exports."""
    rank(_fixture_catalog(), (sig("kind_a"), sig("kind_d", offset_s=5)))
    lines = scoring.template_scoring_metric_lines()
    assert "# TYPE corr_template_scored_total counter" in lines
    assert "# TYPE corr_template_candidates_total counter" in lines
    assert "corr_template_scored_total 3" in lines
    assert "corr_template_candidates_total 5" in lines
    for ln in lines:
        assert "{" not in ln, "these are plain counters — no labels"
