# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Owner decisions of 2026-11-11 (Fable review of the RCA engine).

Lab fact behind them: all 193 confirmed objects of the week were
`sig.ent.security.exposure-story`, every confirming pair was
`security:correlix-netrule ⟂ <device/controller>`, 16 confirmed on
management_plane + security alone, and none on network evidence only.

  D1  stage [7] verdicts: SECURITY and MANAGEMENT_PLANE witnesses support (they
      count toward coverage and required_modalities) but never anchor the
      confirming pair. Exception: a DATED security detection (security_signal
      with the `signal` subclass). Fail-closed on an unknown subclass.
  D2  stage [6] scoring.rank: a context story (`context_story`) ranks below
      every viable causal template, stays visible, is capped at suspected, and
      carries "context_story": true in the hypotheses blob.
  D3  stage [5] engine singleton rule: a component of standing security
      findings alone (posture / exposure) opens no object; counted.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

import engine as E
import main
from catalog import builtin_catalog
from engine import EngineConfig, run_window
from rank_memo import decode_result, encode_result
from scoring import CONFIDENCE_FLOOR, TOP_K, rank
from signals import (
    EntityType,
    ModalityClass,
    Observer,
    ObserverType,
    Severity,
    Signal,
    Source,
)
from verdicts import VerdictTier, assess, plane_may_anchor, witness_of

T0 = datetime(2026, 11, 11, 10, 0, 0, tzinfo=timezone.utc)
TENANT = "acme"
DEV = "edge-r1"
EXPOSURE = "sig.ent.security.exposure-story"
HARDENING = "sig.ent.security.hardening-drift-story"


def sig(kind: str, modality: ModalityClass, observer: str, *, secs: int = 0,
        path: str = "direct", etype: EntityType = EntityType.DEVICE, entity: str = DEV,
        attrs: dict | None = None, otype: ObserverType = ObserverType.DEVICE,
        source: Source = Source.SYSLOG, sev: Severity = Severity.HIGH) -> Signal:
    return Signal(
        tenant_id=TENANT, ts=T0 + timedelta(seconds=secs), source=source, kind=kind,
        observer=Observer(observer_id=observer, observer_type=otype, collection_path=path),
        modality_class=modality, entity_type=etype, entity_id=entity, severity=sev,
        native_id=f"{observer}|{kind}|{entity}|{secs}", entity_tokens=(DEV, entity),
        deviation=6.0, attrs=attrs or {})


def finding(kind: str, sub: str, *, secs: int = 0, rule: str = "r-1") -> Signal:
    return sig(kind, ModalityClass.SECURITY, "security:correlix-netrule", secs=secs,
               path="via_aggregator", otype=ObserverType.PLATFORM, source=Source.SECURITY,
               attrs={"evidence_class": "security", "evidence_subclass": sub, "raw_rule_id": rule})


def relayed(kind: str = "bgp_adjacency_change", *, secs: int = 5) -> Signal:
    return sig(kind, ModalityClass.MANAGEMENT_PLANE, "vmanage:i-lab", secs=secs,
               path="via_controller", otype=ObserverType.CONTROLLER, source=Source.CONTROLLER)


def telemetry(*, secs: int = 10, observer: str = "snmp-edge-r1") -> Signal:
    return sig("if_metric_anomaly", ModalityClass.DEVICE_TELEMETRY, observer, secs=secs,
               etype=EntityType.INTERFACE, entity=f"{DEV}:Gi1", source=Source.METRIC)


def flow(*, secs: int = 15) -> Signal:
    return sig("flow_volume_anomaly", ModalityClass.PASSIVE_FLOW, "flow-edge-r1", secs=secs,
               otype=ObserverType.FLOW_EXPORTER, source=Source.FLOW)


# ══ D1: support planes never anchor ═════════════════════════════════════════

def test_a_finding_plus_one_relayed_plane_is_not_confirmed():
    v = assess([finding("security_exposure", "exposure"), relayed()])
    assert v.tier is not VerdictTier.CONFIRMED
    assert any("supports but never anchors" in r for r in v.reasons), v.reasons


def test_a_controller_alarm_plus_posture_is_not_confirmed():
    v = assess([relayed("controller_alarm"), finding("security_posture", "posture")])
    assert v.tier is not VerdictTier.CONFIRMED
    assert v.coverage.independent_pair is None


def test_a_finding_and_a_relay_beside_one_measurement_plane_still_cannot_confirm():
    """Three planes, three observers — and one measurement plane. P-424934's shape."""
    v = assess([finding("security_exposure", "exposure"), relayed(), telemetry()])
    assert v.coverage.modality_count == 3 and v.coverage.observer_count == 3
    assert v.tier is VerdictTier.SUSPECTED


def test_device_telemetry_plus_independent_passive_flow_still_confirms():
    v = assess([telemetry(), flow()])
    assert v.tier is VerdictTier.CONFIRMED
    assert v.coverage.independent_pair == ("flow-edge-r1", "snmp-edge-r1")


def test_a_dated_firewall_policy_drop_plus_device_telemetry_may_confirm():
    """The D1 exception: a dated security event with a mechanism. A policy-drop
    detection reaches the engine as the security lane's dated class."""
    drop = finding("security_signal", "signal", rule="fw.policy-drop")
    assert plane_may_anchor(drop)
    v = assess([drop, telemetry()])
    assert v.tier is VerdictTier.CONFIRMED


@pytest.mark.parametrize("kind,sub", [
    ("security_signal", ""),            # no subclass: fail-closed
    ("security_signal", "posture"),     # a dated kind that claims a standing subclass
    ("security_signal", "bogus"),       # unknown subclass
    ("security_posture", "signal"),     # a standing kind that claims the dated subclass
    ("security_exposure", "exposure"),
    ("security_posture", "posture"),
])
def test_anything_but_the_dated_detection_never_anchors(kind, sub):
    s = finding(kind, sub)
    assert not plane_may_anchor(s)
    assert witness_of(s).support_plane
    assert assess([s, telemetry()]).tier is not VerdictTier.CONFIRMED


def test_management_plane_never_anchors_and_still_satisfies_a_requirement():
    w = witness_of(relayed())
    assert w.support_plane and w.trusted and not w.may_anchor
    v = assess([relayed(), telemetry(), flow()],
               required_modalities=frozenset({ModalityClass.MANAGEMENT_PLANE}))
    assert v.tier is VerdictTier.CONFIRMED, v.reasons
    assert "vmanage:i-lab" not in (v.coverage.independent_pair or ())


def test_support_witnesses_still_count_toward_coverage():
    v = assess([finding("security_posture", "posture"), relayed(), telemetry()])
    assert ModalityClass.SECURITY in v.coverage.modality_classes
    assert ModalityClass.MANAGEMENT_PLANE in v.coverage.trusted_modalities
    assert "security:correlix-netrule" in v.coverage.observer_ids


def test_adding_a_support_witness_never_downgrades():
    base = [telemetry(), flow()]
    assert assess(base).tier is VerdictTier.CONFIRMED
    assert assess(base + [finding("security_exposure", "exposure"), relayed()]).tier \
        is VerdictTier.CONFIRMED


# ══ D2: context stories ═════════════════════════════════════════════════════

def test_the_context_stories_are_flagged_in_the_catalog():
    flagged = {t.id for t in builtin_catalog().enabled_templates() if t.context_story}
    assert flagged == {EXPOSURE, HARDENING}
    threat = next(t for t in builtin_catalog().enabled_templates()
                  if t.id == "sig.ent.security.threat-signal-story")
    # Causal by D1: its REQUIRED clause is the dated detection.
    assert not threat.context_story
    assert [c.kind for c in threat.requires if not c.optional] == ["security_signal"]


def test_a_context_story_never_heads_a_viable_causal_template():
    ev = [finding("security_exposure", "exposure"),
          sig("bgp_adjacency_change", ModalityClass.CONTROL_PLANE, "syslog-edge-r1", secs=30)]
    res = rank(builtin_catalog(), ev)
    by_id = {h.template_id: h for h in res.hypotheses}
    assert res.top_hypothesis == "sig.ent.wan-edge.bgp-peer-flap"
    story = by_id[EXPOSURE]
    # It out-scores the leader on its own number, and still sorts after it.
    assert story.confidence_rank >= by_id[res.top_hypothesis].confidence_rank
    ids = [h.template_id for h in res.hypotheses]
    causal_viable = [h.template_id for h in res.hypotheses
                     if not h.context_story and h.confidence_rank >= CONFIDENCE_FLOOR]
    assert all(ids.index(c) < ids.index(EXPOSURE) for c in causal_viable)


def test_a_matched_context_story_stays_visible_past_top_k():
    ev = [finding("security_exposure", "exposure"),
          sig("bgp_adjacency_change", ModalityClass.CONTROL_PLANE, "syslog-edge-r1", secs=30)]
    res = rank(builtin_catalog(), ev)
    ids = [h.template_id for h in res.hypotheses]
    assert ids.index(EXPOSURE) >= TOP_K, "the fixture must push it past TOP_K to prove anything"
    assert EXPOSURE in ids


def test_a_context_story_leads_only_when_nothing_causal_is_viable_and_is_suspected():
    res = rank(builtin_catalog(), [finding("security_exposure", "exposure")])
    assert res.top_hypothesis == EXPOSURE
    assert res.verdict_tier is VerdictTier.SUSPECTED


def test_the_blob_flag_is_present_only_on_context_stories():
    ev = [finding("security_exposure", "exposure"),
          sig("bgp_adjacency_change", ModalityClass.CONTROL_PLANE, "syslog-edge-r1", secs=30)]
    for h in rank(builtin_catalog(), ev).hypotheses:
        d = h.to_dict()
        if h.template_id in (EXPOSURE, HARDENING):
            assert d["context_story"] is True
        else:
            assert "context_story" not in d, h.template_id


def test_the_rank_memo_codec_keeps_the_flag():
    ev = [finding("security_exposure", "exposure"),
          sig("bgp_adjacency_change", ModalityClass.CONTROL_PLANE, "syslog-edge-r1", secs=30)]
    res = rank(builtin_catalog(), ev)
    blob = encode_result(res)
    assert blob is not None
    back = decode_result(blob)
    assert back == res
    assert next(h for h in back.hypotheses if h.template_id == EXPOSURE).context_story


def test_the_seam_tie_break_never_lifts_a_context_story():
    """engine._break_ties_by_seam_affinity re-orders only the leading run of the
    leader's own class."""
    res = rank(builtin_catalog(), [finding("security_exposure", "exposure"),
                                   sig("bgp_adjacency_change", ModalityClass.CONTROL_PLANE,
                                       "syslog-edge-r1", secs=30)])
    leader = res.hypotheses[0]
    assert not leader.context_story
    hyps = res.hypotheses
    k = 1
    while k < len(hyps) and hyps[k].confidence_rank == leader.confidence_rank \
            and hyps[k].context_story == leader.context_story:
        k += 1
    assert all(not h.context_story for h in hyps[:k])


# ══ D3: standing findings alone open nothing ════════════════════════════════

def _window(sigs):
    return run_window(sigs, builtin_catalog(), (), EngineConfig())


def test_standing_findings_alone_open_no_object_and_are_counted():
    before = E.standing_finding_singletons_total()
    assert _window([finding("security_posture", "posture"),
                    finding("security_exposure", "exposure", secs=10)]) == []
    assert E.standing_finding_singletons_total() == before + 1


def test_one_standing_finding_alone_opens_no_object():
    assert _window([finding("security_exposure", "exposure")]) == []


def test_a_dated_detection_is_an_event_and_opens():
    assert len(_window([finding("security_signal", "signal")])) == 1


def test_a_grounded_network_fault_folds_the_findings_in_as_context():
    snaps = _window([finding("security_posture", "posture"),
                     finding("security_exposure", "exposure", secs=10),
                     sig("bgp_adjacency_change", ModalityClass.CONTROL_PLANE, "syslog-edge-r1",
                         secs=30)])
    assert len(snaps) == 1
    kinds = {s.kind for n in snaps[0].nodes for s in n.signals}
    assert {"security_posture", "security_exposure", "bgp_adjacency_change"} <= kinds
    assert snaps[0].ranking.top_hypothesis not in (EXPOSURE, HARDENING)


def test_the_counter_reaches_the_exposition():
    _window([finding("security_exposure", "exposure")])
    lines = [ln for ln in main._metrics_text().splitlines()
             if ln.startswith("corr_security_standing_finding_singletons_total ")]
    assert lines and int(lines[0].split()[1]) == E.standing_finding_singletons_total() >= 1
