# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""ENGINE_SEMVER 3.7.0, stage [6] — the confirmable-first tie-break (owner 2026-11-24).

At EXACTLY equal confidence, rank() prefers the hypothesis whose verdict the
evidence can CONFIRM over one capped at suspected, before the specificity key
(−#satisfied). It only reorders exact ties: a higher-confidence hypothesis keeps
the headline whatever either verdict is, and no confidence number moves.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from catalog import BUILTIN_TEMPLATES, builtin_catalog, load_catalog
from scoring import rank
from signals import (
    EntityType,
    ModalityClass,
    Observer,
    ObserverType,
    Severity,
    Signal,
    Source,
)
from verdicts import VerdictTier

T0 = datetime(2026, 11, 24, 10, 0, 0, tzinfo=timezone.utc)


def _sig(kind: str, modality: ModalityClass, observer: str, off: float = 0.0,
         et: EntityType = EntityType.INTERFACE, eid: str = "r1:Gi0/1") -> Signal:
    return Signal(
        tenant_id="t1", ts=T0 + timedelta(seconds=off), source=Source.SYSLOG, kind=kind,
        observer=Observer(observer_id=observer, observer_type=ObserverType.DEVICE),
        modality_class=modality, entity_type=et, entity_id=eid, severity=Severity.HIGH,
        native_id=f"t37t|{kind}|{off}", entity_tokens=("r1",))


def _template(tid: str, requires: list[dict]) -> dict:
    base = dict(BUILTIN_TEMPLATES[0])
    return dict(base, id=tid, title=tid, requires=requires, discriminators=[],
                required_modalities=[], requires_structure=[])


# A: one required clause + two optional clues — 3 satisfied, one plane (suspected).
# B: two required clauses on two planes — 2 satisfied, confirmable.
A = _template("sig.ent.test.wide-suspected", [
    {"kind": "k_control"}, {"kind": "k_extra1", "optional": True},
    {"kind": "k_extra2", "optional": True}])
B = _template("sig.ent.test.narrow-confirmable", [{"kind": "k_control"}, {"kind": "k_telemetry"}])
C = _template("sig.ent.test.lower-confirmable", [
    {"kind": "k_control"}, {"kind": "k_telemetry"}, {"kind": "k_absent"}])

EV = [_sig("k_control", ModalityClass.CONTROL_PLANE, "syslog-r1"),
      _sig("k_extra1", ModalityClass.CONTROL_PLANE, "syslog-r1", off=1),
      _sig("k_extra2", ModalityClass.CONTROL_PLANE, "syslog-r1", off=2),
      _sig("k_telemetry", ModalityClass.DEVICE_TELEMETRY, "snmp-r1", off=3)]


def _by_id(res):
    return {h.template_id: h for h in res.hypotheses}


def test_at_an_exact_tie_the_confirmable_hypothesis_leads():
    res = rank(load_catalog([A, B]), EV)
    h = _by_id(res)
    a, b = h[A["id"]], h[B["id"]]
    assert a.confidence_rank == b.confidence_rank == 1.0          # an exact tie
    assert len(a.satisfied) == 3 > len(b.satisfied) == 2          # old key preferred A
    assert a.verdict_gate.tier is not VerdictTier.CONFIRMED
    assert b.verdict_gate.tier is VerdictTier.CONFIRMED
    assert res.top_hypothesis == B["id"]
    assert res.verdict_tier is VerdictTier.CONFIRMED
    assert [x.template_id for x in res.hypotheses][:2] == [B["id"], A["id"]]


def test_a_non_tie_is_unaffected_by_verdicts():
    # C can confirm but covers 2 of 3 clauses (0.667); A is 1.0 and capped: A keeps it.
    res = rank(load_catalog([A, C]), EV)
    h = _by_id(res)
    assert h[A["id"]].confidence_rank == 1.0 > h[C["id"]].confidence_rank
    assert h[C["id"]].verdict_gate.tier is VerdictTier.CONFIRMED
    assert res.top_hypothesis == A["id"]


def test_equal_verdicts_keep_the_specificity_key():
    # Neither can confirm (telemetry absent): the 3-clause A beats B's single hit.
    ev = EV[:3]
    res = rank(load_catalog([A, B]), ev)
    h = _by_id(res)
    assert h[A["id"]].confidence_rank == 1.0 > h[B["id"]].confidence_rank  # B is 0.5 here
    assert res.top_hypothesis == A["id"]


def test_the_lab_shape_link_errors_bgp_headlines_a_confirmed_local_link_fault():
    ev = [_sig("link_state_change", ModalityClass.CONTROL_PLANE, "syslog-leaf1"),
          _sig("if_errors", ModalityClass.DEVICE_TELEMETRY, "snmp-leaf1", off=4),
          _sig("bgp_adjacency_change", ModalityClass.CONTROL_PLANE, "syslog-leaf1", off=6,
               et=EntityType.DEVICE, eid="r1")]
    res = rank(builtin_catalog(), ev)
    h = _by_id(res)
    local, last = "sig.ent.access.local-link-fault", "sig.ent.middle-mile.lastmile-circuit-flap"
    assert h[local].confidence_rank == h[last].confidence_rank == 1.0
    assert res.top_hypothesis == local and res.verdict_tier is VerdictTier.CONFIRMED
    ids = [x.template_id for x in res.hypotheses]
    assert ids.index(local) < ids.index(last)
