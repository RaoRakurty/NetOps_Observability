"""Replay-driven calibration harness (C9 / design §P4) tests.

Proves the loop the design names: replay LABELED incidents through the pure engine under
candidate EngineConfigs, score against the labels, rank best-first — and that a re-fit
config bumps the config-hash pin (so replay reports the change, never silently).
"""
import json
from datetime import timedelta
from pathlib import Path

from calibration import (
    CORPUS_T0,
    NO_OBJECT,
    LabeledIncident,
    evaluate,
    grid_search,
    load_corpus,
)
from engine import EngineConfig, engine_version
from signals import (
    EntityType,
    ModalityClass,
    Observer,
    ObserverType,
    Severity,
    Signal,
    Source,
)

CORPUS = Path(__file__).parent / "examples" / "calibration-corpus.json"


def _sig(kind, etype, eid, off, *, modality=ModalityClass.DEVICE_TELEMETRY, sev=Severity.WARN):
    return Signal(
        tenant_id="", ts=CORPUS_T0 + timedelta(seconds=off),
        source=Source.METRIC, kind=kind,
        observer=Observer(observer_id=eid.split(":")[0], observer_type=ObserverType.DEVICE),
        modality_class=modality, entity_type=etype, entity_id=eid, severity=sev,
        native_id=f"t|{kind}|{eid}|{off}", attrs={"onset_uncertainty_s": 2.0})


# ── the corpus + scoring ────────────────────────────────────────────────────────

def test_loads_corpus_and_scores_the_labeled_outcomes():
    corpus = load_corpus(json.loads(CORPUS.read_text()))
    assert len(corpus) == 2
    res = evaluate(EngineConfig(), corpus)
    assert res.score == 1.0 and res.hypothesis_acc == 1.0 and res.verdict_acc == 1.0
    by = {s.name.split(" ")[0]: s for s in res.scores}
    # positive: the golden window confirms the congestion hypothesis
    pos = by["dallas-wan-congestion"]
    assert pos.correct and pos.got_hypothesis == "sig.ent.wan-edge.congestion" and pos.got_verdict == "confirmed"
    # negative: an isolated warn blip must NOT correlate (precision)
    assert by["isolated-warn-blip"].correct and by["isolated-warn-blip"].got_hypothesis == NO_OBJECT


def test_empty_grid_evaluates_base_config_only():
    corpus = load_corpus(json.loads(CORPUS.read_text()))
    results = grid_search(corpus, {})
    assert len(results) == 1 and results[0].overrides == {}


# ── ranking + discrimination (the harness must FIND the better config) ───────────

def _over_correlation_incident() -> LabeledIncident:
    # Two WARN cross-modality signals on ONE device (containment-grounded), 400 s apart.
    # weight = exp(-400/300)·w_topo_containment(0.9)·reinforce(1.25) ≈ 0.296 — between
    # attach_threshold 0.25 and 0.35. They should NOT correlate (isolated warns); a too-low
    # threshold over-correlates them into a spurious object. Label: NO_OBJECT.
    a = _sig("if_errors", EntityType.INTERFACE, "leaf1:Ethernet1", 0)
    b = _sig("bgp_adjacency_change", EntityType.DEVICE, "leaf1", 400,
             modality=ModalityClass.CONTROL_PLANE)
    return LabeledIncident(name="over-correlation", window=(a, b), expected_hypothesis=NO_OBJECT)


def test_harness_picks_the_threshold_that_avoids_over_correlation():
    inc = _over_correlation_incident()
    results = grid_search([inc], {"attach_threshold": [0.25, 0.35]})
    best = results[0]
    assert best.overrides.get("attach_threshold") == 0.35   # abstains → correct
    assert best.score == 1.0
    low = next(r for r in results if r.overrides.get("attach_threshold") == 0.25)
    assert low.score == 0.0                                 # over-correlates → wrong


def test_grid_search_is_deterministic_and_ranks_best_first():
    inc = _over_correlation_incident()
    grid = {"attach_threshold": [0.25, 0.35], "tau_s": [200.0, 300.0]}
    r1 = grid_search([inc], grid)
    r2 = grid_search([inc], grid)
    assert [x.config_hash for x in r1] == [x.config_hash for x in r2]   # deterministic
    assert all(r1[i].score >= r1[i + 1].score for i in range(len(r1) - 1))  # best-first
    # a tie is broken toward the FEWEST overrides (smallest change that fits)
    top = [r for r in r1 if r.score == r1[0].score]
    assert r1[0].overrides == min((t.overrides for t in top), key=len)


# ── the replay-contract pin (a re-fit is never silent) ───────────────────────────

def test_refit_config_bumps_the_pin():
    base = EngineConfig()
    refit = EngineConfig(attach_threshold=0.35)
    assert refit.config_hash() != base.config_hash()
    assert engine_version(refit) != engine_version(base)
    # the harness reports the candidate's pin so the owner adopts a NAMED engine_version
    res = grid_search([_over_correlation_incident()], {"attach_threshold": [0.35]})[0]
    assert res.engine_version == engine_version(refit)
