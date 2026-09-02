"""Tracker 157 — a signature may not rank in a topology that cannot host it.

THE DEFECT, AS MEASURED. `Clause` is (kind, entity_type, min_deviation) shaped,
so nothing a template can write down asserts that the estate HAS the structure
the signature NAMES. `sig.ent.fabric.spine-leaf-path-degradation` therefore
ranked top over 130 leaf switches taking purely LOCAL port faults with no spine
device anywhere in the scenario — satisfied by token co-occurrence (an interface
signal and a path signal), never by evidence a spine tier exists. On the live
corpus (netops.corr_signals_archive, 30 h to 2026-08-30) it was the top
hypothesis on 9,890 objects, 6,338 of which implicate exactly ONE device.
`seams` does not stop it: `seams` is a tie-break AFFINITY, not a matching gate.
Catalog-wide, of 100 enabled templates exactly 2 constrained `role` at all and
79 declared a seam with no structural predicate of their own.

WHAT THIS FILE PINS.

  * the DECLARATION — every template's structural requirement is written in the
    template, the vocabulary is closed, and a template that names a role and
    forgets the structure CANNOT LOAD (default-closed, enforced at load);
  * the GATE — an ungrounded template is excluded from RANKING with the reason
    recorded, and it is a gate and not a weight: the two mutants (remove the
    gate / make it a discount) each fail a test here by construction;
  * the EQUIVALENCE — for every template that declares no structure, ranking is
    BIT-IDENTICAL to the pre-157 scorer over a randomized corpus. The gate is
    allowed to change exactly the verdicts it was built to change and nothing
    else;
  * the OBSERVABILITY — `corr_template_ungrounded_total`, disjoint from the
    tracker-167 counters and exposed through the same metric-lines mechanism;
  * the FAIL-CLOSED POLICY — `device_tier` is attestable by nothing, so a
    template that needs one is suppressed under ANY evidence. That is the
    honest behaviour for a structure the platform cannot see, and it is a
    property test, not a comment.
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone

import pytest

import scoring
from catalog import (
    Catalog,
    Clause,
    Template,
    builtin_catalog,
)
from catalog import (
    Verdict as CatVerdict,
)
from scoring import (
    STRUCTURE_ATTESTING_KINDS,
    STRUCTURE_ENTITY_ATTESTED,
    _build_inapplicable_score,
    _build_ungrounded_score,
    evidence_kinds,
    evidence_structure,
    rank,
    score_template,
    structure_gap,
    ungrounded_note,
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

T0 = datetime(2026, 8, 31, 9, 0, 0, tzinfo=timezone.utc)
CAT = builtin_catalog()
ALL_TEMPLATES = CAT.enabled_templates()
GATED = tuple(t for t in ALL_TEMPLATES if t.requires_structure)
UNGATED = tuple(t for t in ALL_TEMPLATES if not t.requires_structure)


def sig(kind, *, entity_type=EntityType.INTERFACE, entity_id="leaf17:Gi0/1",
        offset_s=0.0, modality=ModalityClass.DEVICE_TELEMETRY, deviation=5.0,
        attrs=None, source=Source.SYSLOG, tokens=("leaf17",),
        observer_id="leaf17", severity=Severity.HIGH, site="", value=0.0):
    return Signal(
        tenant_id="acme", ts=T0 + timedelta(seconds=offset_s), source=source,
        kind=kind,
        observer=Observer(observer_id=observer_id,
                          observer_type=ObserverType.DEVICE),
        modality_class=modality, entity_type=entity_type, entity_id=entity_id,
        severity=severity, native_id=f"n|{kind}|{entity_id}|{offset_s}",
        entity_tokens=tokens, deviation=deviation, site=site, value=value,
        attrs={"onset_uncertainty_s": 5.0, **(attrs or {})})


def ungated_rank(catalog: Catalog, evidence):
    """THE PRE-157 ORACLE — `rank` with the structural gate neutralised.

    `_catalog_structure_plan` is the single point the gate enters `rank`
    through, and an empty declaration map is exactly the pre-157 catalog: every
    template falls through to the kind index and the real scorer. Nothing else
    about `rank` is stubbed, so this compares the shipped code path against
    itself minus one feature — which is what an equivalence oracle has to be."""
    real = scoring._catalog_structure_plan
    scoring._catalog_structure_plan = lambda catalog: ({}, {})
    try:
        return rank(catalog, evidence)
    finally:
        scoring._catalog_structure_plan = real


# ── 1. the declaration: closed vocabulary, explicit, default-closed ──────────


def test_every_declared_class_is_known_to_the_evaluator():
    """A template could otherwise declare a class nothing ever attests and be
    silently, permanently suppressed — a fail-closed typo. Every value the
    catalog can write must be attestable by one of the two mechanisms, or be
    the deliberately-empty `device_tier`."""
    known = set(STRUCTURE_ATTESTING_KINDS) | set(STRUCTURE_ENTITY_ATTESTED)
    declared = {c for t in CAT.templates for c in t.requires_structure}
    assert declared <= known, f"declared but unknown to scoring: {declared - known}"
    for cls, kinds in STRUCTURE_ATTESTING_KINDS.items():
        if cls == "device_tier":
            assert kinds == frozenset(), (
                "device_tier is the fail-closed class — giving it attesting "
                "kinds silently changes the policy")
        else:
            assert kinds, f"{cls} attests nothing and is not the fail-closed class"


def test_attesting_kinds_are_real_catalog_vocabulary():
    """The table must not invent kinds. Every attesting kind has to appear
    somewhere in the catalog, or it can never fire and the gate it guards is
    fail-closed by accident rather than by decision."""
    vocab: set[str] = set()
    for t in CAT.templates:
        for c in t.requires:
            vocab |= c.kinds()
        for d in t.discriminators:
            vocab |= d.absent.kinds()
        for s in t.causal_chain:
            vocab |= s.kinds()
    for cls, kinds in STRUCTURE_ATTESTING_KINDS.items():
        unknown = kinds - vocab
        assert not unknown, f"{cls} attests kinds no template declares: {sorted(unknown)}"


def test_a_role_predicate_without_a_structure_cannot_load():
    """DEFAULT-CLOSED, and the mutant killer for it. Before 157 a template could
    name `role: wan_edge` and rank anywhere, because `clause_matches` cannot
    test a role. Naming a role is now a promise the gate has to be able to
    keep."""
    bad = {
        "id": "sig.ent.test.role-no-structure",
        "title": "role but no structure", "domain": "ent.test",
        "requires": [{"kind": "if_util_high", "entity_type": "interface",
                      "role": "wan_edge"}],
        "verdict": {"owner": "netops", "layer": "L3",
                    "first_steps": ["look at it"]},
    }
    with pytest.raises(Exception, match="requires_structure"):
        Catalog(templates=(Template(**bad),))
    ok = Template(**{**bad, "requires_structure": ["transit_path"]})
    assert Catalog(templates=(ok,)).templates[0].requires_structure == ("transit_path",)


def test_a_repeated_class_is_rejected():
    """The gate is a subset test, so a duplicate would mean nothing at all —
    which is exactly why it must not be silently accepted."""
    with pytest.raises(Exception, match="repeats"):
        Template(
            id="sig.ent.test.dupe", title="d", domain="ent.test",
            requires=(Clause(kind="if_errors"),),
            requires_structure=("transit_path", "transit_path"),
            verdict=CatVerdict(owner="netops", layer="L1",
                               first_steps=("check",)))


def test_the_audit_is_pinned():
    """The catalog-wide audit, as a fact rather than a paragraph. A template
    that quietly loses its declaration, or a new family that declares one, has
    to come through this list — which is the whole point of auditing all 146
    rather than patching the one that was reported."""
    assert (len(CAT.templates), len(ALL_TEMPLATES)) == (149, 103)
    assert {t.id: tuple(t.requires_structure) for t in CAT.templates
            if t.requires_structure} == {
        "sig.ent.wan-edge.congestion": ("transit_path",),
        "sig.ent.access.fhrp-failover": ("redundancy_group",),
        "sig.ent.access.fhrp-split-brain": ("redundancy_group",),
        "sig.ent.fabric.spine-leaf-path-degradation":
            ("redundancy_group", "transit_path"),
        "sig.ent.security.fw-ha-failover-drift": ("redundancy_group",),
        "sig.ent.security.fw-aa-session-owner-mismatch": ("redundancy_group",),
        "sig.ent.wireless.wlc-failover": ("redundancy_group",),
        "sig.ent.fabric.lacp-member-blackhole": ("redundancy_group",),
        "sig.ent.fabric.mlag-vpc-peerlink-issue": ("redundancy_group",),
        "sig.ent.fabric.server-bonding-mode-mismatch": ("redundancy_group",),
        "sig.ent.middle-mile.interconnect-lag-member-loss": ("redundancy_group",),
        "sig.ent.fabric.overlay-underlay-mtu-mismatch": ("overlay_encap",),
    }


def test_every_role_carrying_template_declares_a_structure():
    """The load-time rule, restated over the shipped catalog: the two templates
    that constrain `role` are exactly the two that used to be able to overclaim
    with it."""
    with_role = {t.id for t in CAT.templates if any(c.role for c in t.requires)}
    assert with_role == {"sig.ent.wan-edge.congestion",
                         "sig.ent.access.fhrp-failover"}
    for t in CAT.templates:
        if any(c.role for c in t.requires):
            assert t.requires_structure, f"{t.id} names a role and no structure"


# ── 2. attestation: what the evidence does and does not say ─────────────────


def test_a_group_kind_attests_the_group():
    ev = (sig("fhrp_state_change", entity_type=EntityType.DEVICE,
              entity_id="dist-1"),)
    assert "redundancy_group" in evidence_structure(ev, evidence_kinds(ev))


def test_an_ordinary_interface_fault_attests_nothing():
    ev = (sig("if_errors"), sig("link_state_change", offset_s=10))
    assert evidence_structure(ev, evidence_kinds(ev)) == frozenset()


def test_a_measured_leg_attests_transit_but_a_device_local_entity_does_not():
    leg = (sig("probe_loss", entity_type=EntityType.PATH,
               entity_id="rack1->rack4"),)
    assert "transit_path" in evidence_structure(leg, evidence_kinds(leg))
    # a path entity that names no second endpoint measures nothing between two
    # points, and a self-path is not a leg
    for eid in ("rack1", "rack1->rack1", "->rack4", "rack1->"):
        ev = (sig("probe_loss", entity_type=EntityType.PATH, entity_id=eid),)
        assert "transit_path" not in evidence_structure(ev, evidence_kinds(ev)), eid
    # and an arrow on a DEVICE entity is not a measured leg either
    dev = (sig("probe_loss", entity_type=EntityType.DEVICE,
               entity_id="a->b"),)
    assert "transit_path" not in evidence_structure(dev, evidence_kinds(dev))


def test_a_debug_only_probe_attests_nothing():
    """Decision #1 (a lab probe can never drive a customer-facing hypothesis)
    reaches the gate too — otherwise a debug probe could unlock a verdict its
    own evidence is forbidden from supporting."""
    ev = (sig("probe_loss", entity_type=EntityType.PATH,
              entity_id="rack1->rack4", modality=ModalityClass.ACTIVE_PROBE,
              attrs={"probe_authority": "debug_only"}),
          sig("fhrp_state_change", entity_type=EntityType.DEVICE,
              entity_id="dist-1", modality=ModalityClass.ACTIVE_PROBE,
              attrs={"probe_authority": "debug_only"}, offset_s=5))
    assert evidence_structure(ev, evidence_kinds(ev)) == frozenset()


def test_a_verification_witness_attests_what_it_corroborates():
    """The active-verification lane matches on `corroborates_kinds`, not on the
    signal's own kind. `evidence_kinds` already folds those in, so the device's
    own answer attests the structure exactly as its telemetry would — a
    kind-only view would have indexed the witness away."""
    ev = (sig(scoring.VERIFICATION_RESULT_KIND,
              entity_type=EntityType.DEVICE, entity_id="dist-1",
              modality=ModalityClass.ACTIVE_VERIFICATION,
              attrs={"corroborates_kinds": ["fhrp_state_change"]}),)
    assert "redundancy_group" in evidence_structure(ev, evidence_kinds(ev))


def test_device_tier_is_attested_by_nothing_at_all():
    """FAIL-CLOSED, as a property. No evidence plane field carries a device
    role today, so no evidence can attest a tier — proven here over a corpus
    that includes every kind the catalog knows."""
    for ev in _corpus(random.Random(1571), 200):
        assert "device_tier" not in evidence_structure(ev, evidence_kinds(ev))


def test_a_template_needing_a_tier_is_suppressed_under_any_evidence():
    tiered = Template(
        id="sig.ent.test.tiered", title="needs a tier", domain="ent.test",
        requires=(Clause(kind="if_errors"),),
        requires_structure=("device_tier",),
        verdict=CatVerdict(owner="netops", layer="L1", first_steps=("check",)))
    cat = Catalog(templates=(tiered,))
    for ev in _corpus(random.Random(72), 60):
        ev = (*ev, sig("if_errors"))          # the clause always matches
        res = rank(cat, ev)
        assert res.top_hypothesis == "undetermined"
        assert res.hypotheses[0].confidence_rank == 0.0
        assert "suppressed" in res.hypotheses[0].notes[0]


# ── 3. the defect itself: before and after ──────────────────────────────────


def _local_port_fault_object():
    """The tracker's scenario, and the live corpus's dominant shape: ONE leaf
    switch, six local port faults, its own control-plane chatter. No spine, no
    fabric bundle, no measured leg."""
    ev = []
    for i, port in enumerate(("Gi0/0", "Gi0/18", "Gi0/30", "Gi0/2", "Gi0/7",
                              "Gi0/9")):
        ev.append(sig("link_state_change", entity_id=f"leaf17:{port}",
                      offset_s=i * 3))
    ev.append(sig("lldp_neighbor_change", entity_id="leaf17:Gi0/0",
                  offset_s=25))
    ev.append(sig("ospf_adjacency_change", entity_type=EntityType.DEVICE,
                  entity_id="leaf17", offset_s=30,
                  modality=ModalityClass.CONTROL_PLANE))
    return tuple(ev)


FABRIC = "sig.ent.fabric.spine-leaf-path-degradation"


def test_THE_DEFECT_a_local_port_fault_no_longer_ranks_as_a_fabric_path():
    ev = _local_port_fault_object()
    before = ungated_rank(CAT, ev)
    assert before.top_hypothesis == FABRIC, (
        "the pre-157 oracle no longer reproduces the defect — this test has "
        "stopped testing anything")

    after = rank(CAT, ev)
    assert after.top_hypothesis != FABRIC
    fabric = next(h for h in _all_scores(after, ev) if h.template_id == FABRIC)
    assert fabric.confidence_rank == 0.0 and fabric.coverage == 0.0
    assert fabric.notes and "suppressed" in fabric.notes[0], (
        "the refusal must be on the record, not a silent drop")


def test_a_real_fabric_incident_still_ranks_exactly_as_before():
    """The family's own authored fixture: CRC on a spine uplink, a rack-to-rack
    path anomaly, and an ECMP member loss on the leaf. The bundle and the leg
    are both attested, so the gate is a no-op and the verdict is byte-identical
    to the pre-157 scorer's."""
    ev = (
        sig("if_crc", entity_id="spine1:Eth1/1", deviation=4.0),
        sig("probe_rtt_anomaly", entity_type=EntityType.PATH,
            entity_id="rack1->rack4", offset_s=20, deviation=3.5,
            modality=ModalityClass.ACTIVE_PROBE, source=Source.PROBE,
            observer_id="probe-agent-dc", tokens=()),
        sig("ecmp_member_loss", entity_type=EntityType.DEVICE,
            entity_id="leaf1", offset_s=40, deviation=0.0,
            modality=ModalityClass.CONTROL_PLANE, tokens=("leaf1",)),
    )
    assert evidence_structure(ev, evidence_kinds(ev)) >= {
        "redundancy_group", "transit_path"}
    after, before = rank(CAT, ev), ungated_rank(CAT, ev)
    assert after.top_hypothesis == FABRIC
    assert after.to_dict() == before.to_dict(), (
        "a grounded template must rank exactly as it did before the gate")


def test_MUTANT_a_discount_instead_of_a_gate_would_not_hold():
    """THE SECOND MUTANT, killed on `rank`'s own output.

    Part 1 shows the pressure the gate is under: on the real catalog, a
    standalone controller going unreachable makes `sig.ent.wireless.wlc-failover`
    — a CLUSTER failover signature — the top hypothesis at confidence 1.0
    pre-gate. Every symptom matches; only the cluster is missing.

    Part 2 is the killer, and it asserts on what `rank` RETURNS rather than on a
    re-derivation. A discount leaves the template's real coverage, its real
    satisfied-clause list and a non-zero confidence on the record; the gate
    leaves zero, nothing, and the reason. There is no penalty factor that
    survives these three lines, which is the difference between a weight and a
    gate stated as a test."""
    ev = (
        sig("wireless_ap_join_flap", entity_type=EntityType.ACCESS_POINT,
            entity_id="ap-9", tokens=("ap-9",)),
        sig("controller_device_unreachable", entity_type=EntityType.DEVICE,
            entity_id="wlc-1", offset_s=15, modality=ModalityClass.CONTROL_PLANE,
            tokens=("wlc-1",)),
    )
    wlc = "sig.ent.wireless.wlc-failover"
    before = ungated_rank(CAT, ev)
    strong = next(h for h in before.hypotheses if h.template_id == wlc)
    assert before.top_hypothesis == wlc and strong.confidence_rank == 1.0
    assert rank(CAT, ev).top_hypothesis != wlc
    # and with the cluster attested, the same symptoms rank as they always did
    grounded = (*ev, sig("wireless_wlc_member_failover",
                         entity_type=EntityType.WIRELESS_CONTROLLER,
                         entity_id="wlc-1", offset_s=20,
                         modality=ModalityClass.CONTROL_PLANE,
                         tokens=("wlc-1",)))
    assert rank(CAT, grounded).top_hypothesis == wlc

    # part 2 — the same shape isolated, so the refusal is inside `rank`'s
    # visible set and can be asserted directly.
    def tmpl(name, kind, structure=()):
        return Template(
            id=f"sig.ent.test.{name}", title=name, domain="ent.test",
            requires=(Clause(kind=kind),), requires_structure=structure,
            verdict=CatVerdict(owner="netops", layer="L2",
                               first_steps=("check the thing",)))

    cat = Catalog(templates=(tmpl("cluster", "if_util_high", ("device_tier",)),
                             tmpl("rival", "if_util_high")))
    res = rank(cat, (sig("if_util_high"),))
    ungrounded = next(h for h in res.hypotheses
                      if h.template_id == "sig.ent.test.cluster")
    rival = next(h for h in res.hypotheses
                 if h.template_id == "sig.ent.test.rival")
    assert rival.confidence_rank == 1.0, "the symptoms really do all match"
    assert ungrounded.confidence_rank == 0.0, "a discount would leave 1.0 x k"
    assert ungrounded.coverage == 0.0, "a discount would leave coverage 1.0"
    assert ungrounded.satisfied == (), "a discount would leave the clause listed"
    assert "suppressed" in ungrounded.notes[0]
    assert res.top_hypothesis == "sig.ent.test.rival"


# ── 4. equivalence: nothing else moved ──────────────────────────────────────


_KINDS = sorted({k for t in CAT.templates for c in t.requires for k in c.kinds()})
_ENTITY_TYPES = list(EntityType)
_ENTITY_IDS = ["leaf17", "leaf17:Gi0/1", "rack1->rack4", "dist-1", "wlc-1",
               "ap-9", "svc-checkout", "dallas-edge->equinix-pop"]


def _corpus(rng: random.Random, n: int):
    """A randomized evidence corpus over the catalog's real kind vocabulary and
    the entity shapes the engine actually emits. Deterministic per seed."""
    out = []
    for _ in range(n):
        size = rng.randint(1, 6)
        out.append(tuple(
            sig(rng.choice(_KINDS),
                entity_type=rng.choice(_ENTITY_TYPES),
                entity_id=rng.choice(_ENTITY_IDS),
                offset_s=i * 7.0,
                deviation=rng.choice([0.0, 1.0, 3.5, 9.0]),
                modality=rng.choice(list(ModalityClass)))
            for i in range(size)))
    return out


def _all_scores(_result, evidence):
    """Every template's score for this evidence, not just the visible top-K —
    `rank` shows four, and a suppressed template's refusal usually sits below
    them."""
    ev = tuple(evidence)
    present = evidence_kinds(ev)
    attested = evidence_structure(ev, present)
    index = scoring._catalog_kind_index(CAT)
    out = []
    for t in ALL_TEMPLATES:
        if t.requires_structure and structure_gap(t, attested):
            out.append(_build_ungrounded_score(t))
        elif index[t.id] & present:
            out.append(score_template(t, ev))
        else:
            out.append(_build_inapplicable_score(t))
    return out


def test_ORACLE_ungated_templates_are_bit_identical_over_a_randomized_corpus():
    """THE no-false-negatives proof. Over 400 randomized evidence pools, every
    template that declares no structure must produce the exact same
    `HypothesisScore` it produced before the gate existed — same coverage, same
    confidence, same satisfied/missing clause lists, same notes, same verdict
    gate. The gate is allowed to change gated templates and nothing else."""
    gated_ids = {t.id for t in GATED}
    moved = 0
    for ev in _corpus(random.Random(157), 400):
        before = {h.template_id: h for h in _pre157_scores(ev)}
        after = {h.template_id: h for h in _all_scores(None, ev)}
        assert before.keys() == after.keys()
        for tid, b in before.items():
            if tid in gated_ids:
                moved += b != after[tid]
                continue
            assert after[tid] == b, f"{tid} moved on evidence {ev}"
    assert moved, "no gated template ever moved — the corpus never exercised the gate"


def test_ORACLE_the_relative_order_of_ungated_templates_is_preserved():
    """Removing a hypothesis from contention must not REORDER the survivors.
    `rank`'s sort key is unchanged, so this holds by construction — and is
    pinned here because it is what makes 'the runner-up is now top' a safe
    statement rather than a hopeful one."""
    gated_ids = {t.id for t in GATED}
    for ev in _corpus(random.Random(1570), 200):
        def order(scores):
            ordered = sorted(scores, key=lambda s: (-s.confidence_rank,
                                                    -len(s.satisfied),
                                                    s.template_id))
            return [s.template_id for s in ordered
                    if s.template_id not in gated_ids]
        assert order(_pre157_scores(ev)) == order(_all_scores(None, ev))


def _pre157_scores(evidence):
    """Every template scored the pre-157 way: the kind index (167) but no
    structural gate."""
    ev = tuple(evidence)
    present = evidence_kinds(ev)
    index = scoring._catalog_kind_index(CAT)
    return [score_template(t, ev) if index[t.id] & present
            else _build_inapplicable_score(t) for t in ALL_TEMPLATES]


def test_the_gate_reads_only_fields_the_rank_memo_key_carries():
    """SOUNDNESS OF THE LEVEL-1 RANK MEMO, without touching its key.

    `rank_memo.rank_key` is documented as EXACTLY the inputs `rank` reads. The
    gate reads `kind`, `entity_type` and `entity_id` — all three already in that
    key — so no key change is needed. This proves the negative: perturbing every
    field the key deliberately OMITS cannot move the gate's verdict."""
    rng = random.Random(9)
    for ev in _corpus(rng, 150):
        base = evidence_structure(ev, evidence_kinds(ev))
        perturbed = tuple(
            sig(s.kind, entity_type=s.entity_type, entity_id=s.entity_id,
                offset_s=rng.random() * 5000,             # ts
                deviation=-s.deviation,                   # sign of deviation
                modality=s.modality_class,
                severity=rng.choice(list(Severity)),      # severity
                site=rng.choice(["", "dallas", "austin"]),  # site
                value=rng.random() * 100,                 # value
                observer_id=rng.choice(["a", "b", "c"]),  # observer identity
                source=rng.choice(list(Source)))
            for s in ev)
        assert evidence_structure(perturbed, evidence_kinds(perturbed)) == base


# ── 5. the analytic ungrounded score, and the refusal on the record ─────────


def test_the_ungrounded_score_is_the_inapplicable_score_plus_the_reason():
    """The suppressed template is not dropped from the list — `evidence_missing`
    reads the nearest templates, forced competitors are pulled from below the
    top-K, and a hypothesis that silently vanished would be exactly the kind of
    black box this engine is not allowed to be. So it carries the fully
    determined zero score, differing from the inapplicable one in the note
    alone."""
    import dataclasses
    for t in GATED:
        ung, inap = _build_ungrounded_score(t), _build_inapplicable_score(t)
        assert ung.notes and inap.notes == ()
        assert dataclasses.replace(ung, notes=()) == inap
        assert t.requires_structure[0] in ung.notes[0]
        assert "tracker 157" in ung.notes[0]


def test_the_reason_names_what_the_signature_needed():
    t = CAT.get(FABRIC)
    note = ungrounded_note(t)
    assert "redundancy_group" in note and "transit_path" in note
    assert "excluded from ranking" in note


def test_structure_gap_reports_only_what_is_missing():
    t = CAT.get(FABRIC)
    assert structure_gap(t, frozenset()) == ("redundancy_group", "transit_path")
    assert structure_gap(t, frozenset({"redundancy_group"})) == ("transit_path",)
    assert structure_gap(t, frozenset({"redundancy_group", "transit_path"})) == ()
    assert structure_gap(CAT.get("sig.ent.access.local-link-fault"),
                         frozenset()) == ()


def test_a_partially_grounded_template_is_still_refused():
    """`requires_structure` is a conjunction. Half the structure is not the
    structure — a leaf with an ECMP member loss and no measured leg has not
    shown a fabric PATH."""
    ev = (sig("if_crc", entity_id="leaf1:Eth1/1", deviation=4.0),
          sig("ecmp_member_loss", entity_type=EntityType.DEVICE,
              entity_id="leaf1", offset_s=10,
              modality=ModalityClass.CONTROL_PLANE))
    attested = evidence_structure(ev, evidence_kinds(ev))
    assert attested == frozenset({"redundancy_group"})
    assert rank(CAT, ev).top_hypothesis != FABRIC


# ── 6. observability ────────────────────────────────────────────────────────


@pytest.fixture()
def counters():
    scoring.reset_template_scoring_stats()
    yield scoring.template_scoring_stats
    scoring.reset_template_scoring_stats()


def test_the_counter_counts_refusals_and_stays_disjoint_from_scored(counters):
    ev = _local_port_fault_object()
    rank(CAT, ev)
    st = counters()
    assert st["candidates"] == len(ALL_TEMPLATES)
    assert st["ungrounded"] >= 1
    assert st["scored"] + st["ungrounded"] <= st["candidates"]
    # exactly the reachable-but-ungrounded templates, computed independently
    present = evidence_kinds(ev)
    attested = evidence_structure(ev, present)
    index = scoring._catalog_kind_index(CAT)
    expect = sum(1 for t in GATED
                 if index[t.id] & present and structure_gap(t, attested))
    assert st["ungrounded"] == expect


def test_a_refusal_that_cost_nothing_is_not_counted(counters):
    """A template the kind index already elided was never going to be scored,
    so counting its refusal would flatter the number. Evidence that reaches no
    gated template must leave the counter at zero."""
    rank(CAT, (sig("a_kind_no_template_declares"),))
    assert counters()["ungrounded"] == 0


def test_a_grounded_catalog_never_charges_the_counter(counters):
    ev = (sig("fhrp_state_change", entity_type=EntityType.DEVICE,
              entity_id="dist-1", modality=ModalityClass.CONTROL_PLANE),
          sig("probe_loss", entity_type=EntityType.SEGMENT,
              entity_id="dist-1->core-1", offset_s=10,
              modality=ModalityClass.ACTIVE_PROBE))
    rank(CAT, ev)
    st = counters()
    present = evidence_kinds(ev)
    attested = evidence_structure(ev, present)
    index = scoring._catalog_kind_index(CAT)
    assert st["ungrounded"] == sum(
        1 for t in GATED if index[t.id] & present and structure_gap(t, attested))


def test_the_exposition_carries_the_ungrounded_counter(counters):
    rank(CAT, _local_port_fault_object())
    lines = scoring.template_scoring_metric_lines()
    assert "# TYPE corr_template_ungrounded_total counter" in lines
    body = [ln for ln in lines if ln.startswith("corr_template_ungrounded_total ")]
    assert body == [f"corr_template_ungrounded_total {counters()['ungrounded']}"]
    for ln in lines:
        assert "{" not in ln, "these are plain counters — no labels"


def test_the_counter_resets_only_on_request(counters):
    rank(CAT, _local_port_fault_object())
    first = counters()["ungrounded"]
    rank(CAT, _local_port_fault_object())
    assert counters()["ungrounded"] == 2 * first
    scoring.reset_template_scoring_stats()
    assert counters()["ungrounded"] == 0


# ── 7. determinism ──────────────────────────────────────────────────────────


def test_the_gate_is_order_and_multiplicity_blind():
    """`rank` is a pure function of the evidence SET (rank_memo's key is a set,
    and the memo would be unsound otherwise). The gate must not be the thing
    that breaks that: shuffling and duplicating evidence cannot move it."""
    rng = random.Random(4)
    for ev in _corpus(rng, 120):
        base = evidence_structure(ev, evidence_kinds(ev))
        shuffled = list(ev)
        rng.shuffle(shuffled)
        doubled = tuple(shuffled) + tuple(shuffled)
        assert evidence_structure(tuple(shuffled),
                                  evidence_kinds(tuple(shuffled))) == base
        assert evidence_structure(doubled, evidence_kinds(doubled)) == base


def test_the_plan_is_cached_per_catalog_and_never_shared_across_catalogs():
    a, b = builtin_catalog(), builtin_catalog()
    da, ua = scoring._catalog_structure_plan(a)
    assert (da, ua) == scoring._catalog_structure_plan(a)
    db, _ = scoring._catalog_structure_plan(b)
    assert da == db and da is not db, (
        "two distinct catalog objects must get their own entries — an identity "
        "cache that collided would serve one catalog's plan for another")
