# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""A7 — fidelity tiers weigh evidence (flag ``CORR_FIDELITY_WEIGHTING``, OFF).

THE RULE, in one sentence: a signal whose parser fidelity is ``doc_claimed``
counts toward SUPPORT and never toward CONFIRMATION. It is stated in full in the
``confirmability.py`` module header; its vocabulary lives in ``signals.py`` and
the cap is applied in ``scoring.score_template`` beside the #94 physical-layer
cap. This file is the gate on all three.

WHAT IS PINNED HERE

  * the RULE — a confirming pair that rests on a doc_claimed rule is capped at
    ``suspected`` with the gap NAMED; the same evidence still attaches, still
    scores, still supports (INVARIANTS §10a: prefer still analyzing over an
    unsupported cause, and prefer it over a silenced one too);
  * the CONVERSE — when the VALIDATED signals alone form the independent pair,
    the object confirms and the gap list is EMPTY, doc_claimed evidence and all;
  * the FLAG-OFF PATH — not one byte moves: the whole 114-fixture corpus and the
    FIXTURE_GOLDEN storm object are identical with the flag off AND on (they
    claim no fidelity), and no verdict block grows a key;
  * the 157 STRUCTURAL GATE — an ungrounded template stays refused at the
    HIGHEST fidelity. Fidelity may only ever take confirmation away;
  * the V1 EXPECTATION — every rule the V1 reference workload exercises is
    ``code`` fidelity (asserted from the baked table, read-only), which is the
    basis of the HYPOTHESIS stated in
    ``test_v1_shaped_stream_decides_identically_with_the_flag_on``.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

import main
import producers
import scoring
import signals as S
from catalog import builtin_catalog
from engine import EngineConfig, run_window
from rank_memo import rank_key
from scoring import rank, score_template
from signals import (
    EntityType,
    ModalityClass,
    Observer,
    ObserverType,
    Severity,
    Signal,
    Source,
)
from test_bounded_object_paging import FIXTURE_GOLDEN, _fixture_snapshot
from test_fixtures import fixture_files, signal_from_fixture
from verdicts import VerdictTier

T0 = datetime(2026, 9, 2, 12, 0, 0, tzinfo=timezone.utc)
CAT = builtin_catalog()

# The signature the evidence below matches, straight out of the shipped catalog
# (fixtures/bgp-peer-flap-confirmed.json is the same scenario): a control-plane
# syslog witness plus an independent device-telemetry witness — two modalities,
# two observers, no shared authority or fate. It CONFIRMS today, which is what
# makes it the right probe for a rule that can only take confirmation away.
BGP_FLAP = "sig.ent.wan-edge.bgp-peer-flap"


@pytest.fixture(autouse=True)
def _flag_off_and_counters_clean():
    """Every test starts from the shipping default (OFF) and a zero counter, and
    leaves the process there — the flag is module state, so a test that flipped
    it and returned would silently arm the next one."""
    S.set_fidelity_weighting(False)
    scoring.reset_fidelity_weighting_stats()
    yield
    S.set_fidelity_weighting(False)
    scoring.reset_fidelity_weighting_stats()


def sig(kind, entity_id, observer_id, modality, source, *, offset_s=0.0,
        entity_type=EntityType.DEVICE, deviation=0.0, fidelity="", rule_id="",
        tokens=("wan-r2",)):
    attrs: dict = {}
    if fidelity:
        attrs["fidelity"] = fidelity
    if rule_id:
        attrs["rule_id"] = rule_id
    return Signal(
        tenant_id="t1", ts=T0 + timedelta(seconds=offset_s), source=source,
        kind=kind,
        observer=Observer(observer_id=observer_id,
                          observer_type=ObserverType.DEVICE,
                          collection_path="direct"),
        modality_class=modality, entity_type=entity_type, entity_id=entity_id,
        severity=Severity.WARN, native_id=f"a7|{kind}|{entity_id}|{offset_s}",
        deviation=deviation, entity_tokens=tokens, attrs=attrs)


def bgp_syslog(fidelity: str, rule_id: str, *, observer="syslog-wan-r2",
               offset_s=0.0) -> Signal:
    return sig("bgp_adjacency_change", "wan-r2:192.168.100.5", observer,
               ModalityClass.CONTROL_PLANE, Source.SYSLOG, offset_s=offset_s,
               fidelity=fidelity, rule_id=rule_id)


def snmp_telemetry(fidelity: str = "", rule_id: str = "") -> Signal:
    return sig("device_resource_anomaly", "wan-r2", "snmp-wan-r2",
               ModalityClass.DEVICE_TELEMETRY, Source.METRIC, offset_s=4.0,
               deviation=4.0, fidelity=fidelity, rule_id=rule_id)


def top_of(result) -> scoring.HypothesisScore:
    return next(h for h in result.hypotheses
                if h.template_id == result.top_hypothesis)


def verdict_block(result) -> dict:
    return top_of(result).to_dict()["verdict"]


# ══ 1. the vocabulary (signals.py) ═══════════════════════════════════════════

def test_the_ladder_is_ordered_weakest_first_and_code_is_validated():
    """`code` — a hand-written, tested branch, and the catalog rows migrated
    from those branches — COUNTS AS VALIDATED, and sits ABOVE doc_claimed on the
    ladder. That is the position the rule takes, stated as an assertion rather
    than left in a comment."""
    assert S.FIDELITY_LADDER == ("doc_claimed", "code", "lab_validated",
                                 "live_validated")
    assert S.VALIDATED_FIDELITIES == {"code", "lab_validated", "live_validated"}
    assert S.is_validated_fidelity("code")
    assert S.is_validated_fidelity("lab_validated")
    assert S.is_validated_fidelity("live_validated")
    assert not S.is_validated_fidelity("doc_claimed")


def test_no_claim_is_not_a_doc_claim_but_an_unreadable_claim_fails_closed():
    """The two cases that are NOT the same. A metric/probe/flow signal carries
    no fidelity at all (no parser ran) and must behave exactly as it does today;
    a lane that stamps a value outside the ladder HAS made a claim we cannot
    read, and that one fails closed."""
    assert S.is_validated_fidelity("")
    assert not S.is_validated_fidelity("vendor_says_so")


def test_the_gap_names_rules_and_never_silently_drops_an_unnamed_one():
    ev = [bgp_syslog("doc_claimed", "syslog.bgp.route_churn"),
          sig("mac_flap", "wan-r2", "syslog-wan-r2", ModalityClass.CONTROL_PLANE,
              Source.SYSLOG, fidelity="doc_claimed"),
          snmp_telemetry()]
    assert S.unvalidated_rule_ids(ev) == ("<unknown rule>:doc_claimed",
                                          "syslog.bgp.route_churn")
    assert S.fidelity_min(ev) == "doc_claimed"
    assert S.fidelity_min([snmp_telemetry()]) == ""
    assert [s.kind for s in S.validated_signals(ev)] == ["device_resource_anomaly"]


# ══ 2. the rule ══════════════════════════════════════════════════════════════

def test_a_confirming_pair_that_rests_on_a_doc_claimed_rule_is_capped():
    """The core case. Control plane (doc_claimed) + device telemetry (no claim)
    confirms today; with the rule in force the validated half is one modality on
    its own, so the verdict is held at suspected and the reason NAMES the rule."""
    ev = [bgp_syslog("doc_claimed", "syslog.bgp.route_churn"), snmp_telemetry()]

    S.set_fidelity_weighting(True)
    res = rank(CAT, ev)
    assert res.top_hypothesis == BGP_FLAP
    assert res.verdict_tier is VerdictTier.SUSPECTED
    top = top_of(res)
    assert top.fidelity_gap == ("syslog.bgp.route_churn",)
    assert any("evidence from unvalidated parser rules: "
               "syslog.bgp.route_churn" in r
               for r in top.verdict_gate.reasons)
    # …and the object still says what WOULD confirm it: the cap is on the claim,
    # not on the analysis.
    assert any("unvalidated parser rules" in m for m in res.evidence_missing)


def test_doc_claimed_evidence_still_supports_everything_but_the_confirmation():
    """SUPPORT is untouched: the signal attaches, satisfies its clause, drives
    coverage and confidence, and is in the evidence log exactly as before. Only
    the tier moves."""
    ev = [bgp_syslog("doc_claimed", "syslog.bgp.route_churn"), snmp_telemetry()]
    off = score_template(next(t for t in CAT.enabled_templates()
                              if t.id == BGP_FLAP), tuple(ev))
    S.set_fidelity_weighting(True)
    on = score_template(next(t for t in CAT.enabled_templates()
                             if t.id == BGP_FLAP), tuple(ev))
    assert on.satisfied == off.satisfied
    assert on.coverage == off.coverage
    assert on.confidence_rank == off.confidence_rank
    assert on.missing == off.missing
    assert off.verdict_gate.tier is VerdictTier.CONFIRMED
    assert on.verdict_gate.tier is VerdictTier.SUSPECTED
    # the coverage block (what the evidence log renders) is unchanged: the same
    # observers, the same modalities, the same independent pair are still there.
    assert on.verdict_gate.coverage == off.verdict_gate.coverage


def test_doc_claimed_only_evidence_caps_at_suspected_and_names_every_rule():
    """Two doc_claimed witnesses of different modalities: nothing validated is
    left to confirm with, so the cap fires and BOTH rules are on the record."""
    ev = [bgp_syslog("doc_claimed", "syslog.bgp.route_churn"),
          snmp_telemetry(fidelity="doc_claimed", rule_id="syslog.mac.flap")]
    S.set_fidelity_weighting(True)
    res = rank(CAT, ev)
    assert res.verdict_tier is VerdictTier.SUSPECTED
    top = top_of(res)
    assert top.fidelity_gap == ("syslog.bgp.route_churn", "syslog.mac.flap")
    assert top.fidelity_min == "doc_claimed"


def test_mixed_evidence_confirms_when_the_validated_signals_alone_pair_up():
    """The converse, and the reason the rule is a filter on the PAIR rather than
    a penalty on the object: add an independent VALIDATED control-plane witness
    and the confirmation stands on its own feet. The gap list is then empty —
    nothing was held back — while `fidelity_min` still reports the weakest claim
    in the set, which is what the UI's confidence ladder renders."""
    ev = [bgp_syslog("doc_claimed", "syslog.bgp.route_churn"),
          bgp_syslog("code", "syslog.bgp.adjacency_change",
                     observer="syslog-wan-r3", offset_s=2.0),
          snmp_telemetry()]
    S.set_fidelity_weighting(True)
    res = rank(CAT, ev)
    assert res.verdict_tier is VerdictTier.CONFIRMED
    top = top_of(res)
    assert top.fidelity_gap == ()
    assert top.fidelity_min == "doc_claimed"
    assert scoring.fidelity_weighting_stats()["capped_objects"] == 0


def test_a_lab_or_live_validated_rule_confirms_like_code():
    for fidelity in ("code", "lab_validated", "live_validated"):
        S.set_fidelity_weighting(True)
        res = rank(CAT, [bgp_syslog(fidelity, "syslog.bgp.adjacency_change"),
                         snmp_telemetry()])
        assert res.verdict_tier is VerdictTier.CONFIRMED, fidelity
        assert top_of(res).fidelity_gap == ()
        assert top_of(res).fidelity_min == fidelity


# ══ 3. the flag-OFF path: no change at all ═══════════════════════════════════

def test_flag_off_is_todays_behaviour_on_the_evidence_the_rule_would_cap():
    """The same evidence that caps with the flag ON confirms with it OFF, and
    the ranking dict is byte-identical to the same evidence with the fidelity
    attrs stripped entirely — proof that the field is INERT while the flag is
    off, not merely unused."""
    claimed = [bgp_syslog("doc_claimed", "syslog.bgp.route_churn"),
               snmp_telemetry()]
    bare = [bgp_syslog("", ""), snmp_telemetry()]
    res = rank(CAT, claimed)
    assert res.verdict_tier is VerdictTier.CONFIRMED
    assert json.dumps(res.to_dict()) == json.dumps(rank(CAT, bare).to_dict())
    assert scoring.fidelity_weighting_stats()["capped_objects"] == 0


def test_flag_off_emits_no_fidelity_key_anywhere_in_the_verdict_block():
    """The surfaces are PRESENT-ONLY. A key that appears with the flag off would
    move every object's hypotheses blob — and with it content_hash, the replay
    pin and every open object's version."""
    res = rank(CAT, [bgp_syslog("doc_claimed", "syslog.bgp.route_churn"),
                     snmp_telemetry()])
    for h in res.hypotheses:
        assert "fidelity_min" not in h.to_dict()["verdict"]
        assert "fidelity_gap" not in h.to_dict()["verdict"]


@pytest.mark.parametrize("path", fixture_files(), ids=lambda p: p.stem)
def test_the_whole_fixture_corpus_is_byte_identical_with_the_flag_on(path):
    """The corpus proof. No fixture claims a fidelity — they are collector-shaped
    scenarios, not parser output — so the rule has nothing to weigh and every one
    of the 114 signature fixtures must produce the SAME ranking, byte for byte,
    with the flag on. This is the test that fails if the cap ever starts firing
    on evidence that made no claim."""
    data = json.loads(path.read_text())
    ev = [signal_from_fixture(s, i) for i, s in enumerate(data["signals"])]
    off = json.dumps(rank(CAT, ev).to_dict())
    S.set_fidelity_weighting(True)
    assert json.dumps(rank(CAT, ev).to_dict()) == off


def test_the_fixture_golden_content_hash_is_unmoved_with_the_flag_on():
    """FIXTURE_GOLDEN is the replay/damping pin (test_bounded_object_paging).
    Its signals carry no fidelity claim, so the flag may not move it — in either
    position."""
    assert _fixture_snapshot().content_hash() == FIXTURE_GOLDEN
    S.set_fidelity_weighting(True)
    assert _fixture_snapshot().content_hash() == FIXTURE_GOLDEN


# ══ 4. surfaces ══════════════════════════════════════════════════════════════

def test_the_verdict_block_carries_the_gap_and_the_floor_for_the_ui():
    S.set_fidelity_weighting(True)
    block = verdict_block(rank(CAT, [
        bgp_syslog("doc_claimed", "syslog.bgp.route_churn"), snmp_telemetry()]))
    assert block["fidelity_gap"] == ["syslog.bgp.route_churn"]
    assert block["fidelity_min"] == "doc_claimed"
    assert block["verdict_tier"] == "suspected"
    # the gate's own explainability block is still whole beside it
    assert block["independent_pair"] and block["modality_coverage"]


def test_the_capped_counter_reaches_metrics_and_healthz():
    """A counter nobody can scrape is not a counter (§10). The pair is exposed
    together: `corr_fidelity_capped_total` is unreadable without knowing whether
    the rule was in force."""
    S.set_fidelity_weighting(True)
    rank(CAT, [bgp_syslog("doc_claimed", "syslog.bgp.route_churn"),
               snmp_telemetry()])
    assert scoring.fidelity_weighting_stats()["capped_objects"] == 1
    text = main._metrics_text()
    assert "corr_fidelity_capped_total 1" in text
    assert "corr_fidelity_weighting_enabled 1" in text
    assert "# TYPE corr_fidelity_capped_total counter" in text
    health = main._health_payload()["fidelity_weighting"]
    assert health == {"enabled": True, "flag": "CORR_FIDELITY_WEIGHTING",
                      "capped_objects": 1}


def test_the_metric_family_is_declared_even_with_the_flag_off():
    text = main._metrics_text()
    assert "# HELP corr_fidelity_capped_total" in text
    assert "corr_fidelity_capped_total 0" in text
    assert "corr_fidelity_weighting_enabled 0" in text


def test_only_the_object_whose_tier_moved_is_counted():
    """`corr_fidelity_capped_total` counts OBJECTS, not hypotheses: a capped
    hypothesis somewhere down the ranking changed no verdict an operator sees."""
    S.set_fidelity_weighting(True)
    rank(CAT, [bgp_syslog("doc_claimed", "syslog.bgp.route_churn"),
               bgp_syslog("code", "syslog.bgp.adjacency_change",
                          observer="syslog-wan-r3", offset_s=2.0),
               snmp_telemetry()])
    assert scoring.fidelity_weighting_stats()["capped_objects"] == 0


def test_the_cap_is_monotone_adding_evidence_never_lowers_the_tier():
    """`assess` is monotone (verdicts.py, guarded there); a cap layered on top
    could break it — add a doc_claimed witness to a confirmed object and a naive
    "any unvalidated evidence caps" rule would DOWNGRADE it. This one cannot:
    it asks whether the VALIDATED signals still pair up, and adding evidence
    never removes a validated signal."""
    tiers = {VerdictTier.UNDETERMINED: 0, VerdictTier.SUSPECTED: 1,
             VerdictTier.CONFIRMED: 2}
    pool = [
        bgp_syslog("doc_claimed", "syslog.bgp.route_churn"),
        snmp_telemetry(),
        bgp_syslog("code", "syslog.bgp.adjacency_change",
                   observer="syslog-wan-r3", offset_s=2.0),
        snmp_telemetry(fidelity="doc_claimed", rule_id="syslog.mac.flap"),
    ]
    S.set_fidelity_weighting(True)
    prev = 0
    for i in range(1, len(pool) + 1):
        cur = tiers[rank(CAT, pool[:i]).verdict_tier]
        assert cur >= prev, f"adding evidence #{i} downgraded the tier"
        prev = cur


# ══ 4b. the level-1 rank memo cannot serve one fidelity's verdict for another ═

def test_the_rank_memo_key_separates_evidence_that_differs_only_in_fidelity():
    """`rank_memo.signal_projection` is "the part of a Signal `rank` can SEE",
    and with the flag on `rank` can see two more attrs keys. If the key did not
    carry them, two components identical but for their evidence's fidelity would
    share a memo entry and one would be served the other's verdict — a cached
    `confirmed` for evidence the rule caps. Pinned in both flag positions: the
    key must MOVE when the rule is in force and must NOT move when it is not
    (an unconditional change would be a needless cross-epoch miss)."""
    claimed = (bgp_syslog("doc_claimed", "syslog.bgp.route_churn"),
               snmp_telemetry())
    validated = (bgp_syslog("code", "syslog.bgp.adjacency_change"),
                 snmp_telemetry())
    catv = CAT.version_hash()

    assert rank_key("t1", catv, claimed) == rank_key("t1", catv, validated)
    S.set_fidelity_weighting(True)
    assert rank(CAT, claimed).verdict_tier is not rank(CAT, validated).verdict_tier
    assert rank_key("t1", catv, claimed) != rank_key("t1", catv, validated), (
        "the memo would serve the validated object's confirmed verdict to the "
        "doc_claimed one")


# ══ 5. the tracker-157 structural gate is untouched ══════════════════════════

def test_the_structural_gate_still_refuses_ungrounded_templates_at_top_fidelity():
    """Fidelity may only ever TAKE confirmation away. A signature that names a
    structure the evidence does not attest stays excluded from ranking even when
    every signal is `live_validated` — the 157 gate is upstream of the verdict
    and is not a weight the rule can outbid (INVARIANTS §10a)."""
    gated = next(t for t in CAT.enabled_templates() if t.requires_structure)
    ev = tuple(
        sig(clause.kind, "leaf17:Gi0/1", f"obs-{i}",
            ModalityClass.DEVICE_TELEMETRY if i % 2 else ModalityClass.CONTROL_PLANE,
            Source.SYSLOG, offset_s=float(i), deviation=9.0,
            entity_type=EntityType.INTERFACE, fidelity="live_validated",
            rule_id=f"syslog.rule.{i}", tokens=("leaf17",))
        for i, clause in enumerate(c for c in gated.requires if not c.optional))

    S.set_fidelity_weighting(True)
    before = scoring.template_scoring_stats()["ungrounded"]
    res = rank(CAT, list(ev))
    assert scoring.template_scoring_stats()["ungrounded"] > before
    assert res.top_hypothesis != gated.id
    for h in res.hypotheses:
        if h.template_id == gated.id:
            assert h.coverage == 0.0 and h.confidence_rank == 0.0
            assert any("tracker 157" in n for n in h.notes)
            assert h.fidelity_gap == () and h.fidelity_min == ""


# ══ 6. the V1 reference workload ═════════════════════════════════════════════
#
# The V1 reference capacity workload is SYSLOG-ONLY and uniform
# `%LINK-3-UPDOWN` (docs/scale/GA_WORKLOAD_CONTRACT_1K.md §"the generator emits
# 100 % %LINK-3-UPDOWN"; the s11 tail classification records the same shape:
# "the V1 workload is syslog-only"), i.e. the syslog rules that classify a link
# transition.
V1_KINDS = frozenset({"link_state_change"})


def v1_rules() -> list:
    return [r for r in producers.RULES
            if r.lane == "syslog" and r.kind in V1_KINDS]


def test_every_v1_workload_rule_is_code_fidelity():
    """Read-only against the BAKED table (`producers.RULES` ← parser_rules.py ←
    telemetry-catalog/events.yaml). If a future catalog edit demotes one of
    these rows to `doc_claimed`, this test goes red — which is the point: that
    demotion would make the flag non-neutral on the reference workload and the
    qualification leg below would no longer be a null hypothesis."""
    rules = v1_rules()
    assert rules, "no syslog rule classifies the V1 workload's link transitions"
    assert all(r.fidelity == "code" for r in rules), {
        r.rule_id: r.fidelity for r in rules if r.fidelity != "code"}
    doc_claimed = {r.rule_id for r in producers.RULES
                   if not S.is_validated_fidelity(r.fidelity)}
    assert not ({r.rule_id for r in rules} & doc_claimed)


def v1_shaped_window(n_devices: int = 4) -> list[Signal]:
    """A V1-shaped stream built by the REAL parser, so every signal carries the
    fidelity the baked table actually stamps — not one a test invented."""
    out: list[Signal] = []
    for i in range(n_devices):
        for j, state in enumerate(("down", "up")):
            ev = {
                "hostname": f"leaf{i}", "appname": "%LINK-3-UPDOWN",
                "facility": "LINK",
                "message": f"Interface Ethernet{i}, changed state to {state}",
                "timestamp": (T0 + timedelta(seconds=i * 2 + j)).isoformat(),
                "tenant_id": "t1",
            }
            s = producers.classify(ev, "syslog", "t1", T0)
            assert s is not None
            out.append(s)
    return out


def test_the_v1_stream_the_parser_produces_is_all_code_fidelity():
    window = v1_shaped_window()
    assert window
    assert {S.fidelity_of(s) for s in window} == {"code"}
    assert S.unvalidated_rule_ids(window) == ()


def test_v1_shaped_stream_decides_identically_with_the_flag_on():
    """The HYPOTHESIS (not a proven fact): because every rule the V1 reference
    workload exercises is `code` fidelity — validated, per the rule — turning
    the flag ON is expected to be ACCURACY-NEUTRAL on that workload, so a future
    qualification leg run with it on should reproduce the V1 numbers. This test
    is the in-process half of that expectation: the same window, decided twice,
    must yield the same objects, the same verdict tiers, the same top
    hypotheses, the same edges and the same evidence. It cannot stand in for the
    rig leg — only a graded run can — and it is stated here so that a change
    which breaks the premise is caught before that leg is ever scheduled.

    The hypotheses BLOB is allowed to grow the two present-only A7 keys with the
    flag on (that is the UI surface, and it is additive); the DECISION content
    around them is compared byte for byte after blinding exactly those keys."""
    window = v1_shaped_window()
    off = run_window(window, CAT, (), EngineConfig())
    S.set_fidelity_weighting(True)
    on = run_window(window, CAT, (), EngineConfig())

    assert off and len(on) == len(off)
    for a, b in zip(on, off):
        assert a.correlation_id == b.correlation_id
        assert a.ranking.verdict_tier is b.ranking.verdict_tier
        assert a.ranking.top_hypothesis == b.ranking.top_hypothesis
        assert a.ranking.evidence_missing == b.ranking.evidence_missing
        assert a.to_edge_rows(version=1) == b.to_edge_rows(version=1)
        assert a.to_evidence_rows(version=1) == b.to_evidence_rows(version=1)
        row_a, row_b = a.to_object_row(version=1), b.to_object_row(version=1)
        assert set(row_a) == set(row_b)
        differing = {k for k in row_a if row_a[k] != row_b[k]}
        assert differing <= {"hypotheses"}, differing
        assert _blind_fidelity(row_a["hypotheses"]) == row_b["hypotheses"]
        # …and nothing was capped: no gap, and the floor is the validated `code`.
        for h in json.loads(row_a["hypotheses"])["ranking"]["hypotheses"]:
            assert h["verdict"].get("fidelity_gap", []) == []
            assert h["verdict"].get("fidelity_min", "code") == "code"
    assert scoring.fidelity_weighting_stats()["capped_objects"] == 0


def _blind_fidelity(blob: str) -> str:
    """Drop the two present-only A7 keys from every hypothesis's verdict block,
    re-serialized exactly as the engine serializes it, so the REST of the blob
    can be compared byte for byte."""
    doc = json.loads(blob)
    for h in doc.get("ranking", {}).get("hypotheses", []):
        h["verdict"].pop("fidelity_min", None)
        h["verdict"].pop("fidelity_gap", None)
    return json.dumps(doc, separators=(",", ":"), sort_keys=True)
