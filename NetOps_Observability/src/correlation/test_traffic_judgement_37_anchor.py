# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""ENGINE_SEMVER 3.7.0, stage [6] — option B (owner 2026-11-24).

`sig.ent.access.local-link-fault` requires a link-state change AND a same-port
counter anomaly. Before the anchor, a counter anomaly alone scored coverage 0.5
(>= CONFIDENCE_FLOOR 0.3) and headlined "local link fault — suspected": 1,184 of
1,186 lab objects in 7 days, with ZERO link_state_change signals on the lab. The
link-state change is now the template's anchor: without it the template is not
in the competition at all; with it alone the template keeps an honest 0.5.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from catalog import builtin_catalog
from scoring import CONFIDENCE_FLOOR, rank
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
LOCAL = "sig.ent.access.local-link-fault"
LASTMILE = "sig.ent.middle-mile.lastmile-circuit-flap"
INTERCONNECT = "sig.ent.middle-mile.private-interconnect-bgp-down"
AP_POWER = "sig.ent.wireless.ap-down-power"


def _sig(kind: str, eid: str, et: EntityType, *, off: float = 0.0,
         sev: Severity = Severity.CRIT, modality: ModalityClass = ModalityClass.DEVICE_TELEMETRY,
         source: Source = Source.METRIC, observer: str = "cedge-80") -> Signal:
    return Signal(
        tenant_id="t1", ts=T0 + timedelta(seconds=off), source=source, kind=kind,
        observer=Observer(observer_id=observer, observer_type=ObserverType.DEVICE),
        modality_class=modality, entity_type=et, entity_id=eid, severity=sev,
        native_id=f"t37a|{kind}|{eid}|{off}", entity_tokens=(eid.split(":")[0],))


def _ids(res) -> list[str]:
    return [h.template_id for h in res.hypotheses]


def test_counter_anomaly_alone_leaves_local_link_fault_out_of_the_ranking():
    ev = [_sig("if_metric_anomaly", "cedge-80:Gi4.200", EntityType.INTERFACE),
          _sig("if_metric_anomaly", "cedge-80:Gi1", EntityType.INTERFACE, off=5)]
    res = rank(builtin_catalog(), ev)
    assert LOCAL not in _ids(res)
    assert res.top_hypothesis != LOCAL


def test_link_down_alone_keeps_an_honest_half_coverage_suspected():
    ev = [_sig("link_state_change", "r1:Gi0/1", EntityType.INTERFACE,
               modality=ModalityClass.CONTROL_PLANE, source=Source.TRAP, sev=Severity.HIGH)]
    res = rank(builtin_catalog(), ev)
    by_id = {h.template_id: h for h in res.hypotheses}
    assert LOCAL in by_id
    assert by_id[LOCAL].confidence_rank >= CONFIDENCE_FLOOR
    assert abs(by_id[LOCAL].confidence_rank - 0.5) < 1e-9
    assert res.verdict_tier is not VerdictTier.CONFIRMED


def test_lab_case_shape_no_longer_headlines_a_link_fault():
    # The shape of lab object 6bce5ab0-…: octet anomalies on several cEdge ports,
    # a CPU episode, controller alarms and a flow-volume anomaly; no link change.
    ev = [
        _sig("if_metric_anomaly", "cedge-80:Gi4.200", EntityType.INTERFACE),
        _sig("if_metric_anomaly", "cedge-60:Gi4", EntityType.INTERFACE, off=3, observer="cedge-60"),
        _sig("device_resource_anomaly", "vedge-100", EntityType.DEVICE, off=8, observer="vedge-100"),
        _sig("controller_alarm", "vedge-20", EntityType.DEVICE, off=12, sev=Severity.WARN,
             modality=ModalityClass.MANAGEMENT_PLANE, source=Source.CONTROLLER, observer="vmanage"),
        _sig("flow_volume_anomaly", "192.168.222.101:if4294967295", EntityType.INTERFACE, off=20,
             modality=ModalityClass.PASSIVE_FLOW, source=Source.FLOW, observer="sampler"),
    ]
    res = rank(builtin_catalog(), ev)
    assert res.top_hypothesis != LOCAL
    assert LOCAL not in _ids(res)


DIA = "sig.ent.middle-mile.dia-egress-corroborated"


def _probe() -> Signal:
    return _sig("probe_loss", "hq->br09", EntityType.PATH, modality=ModalityClass.ACTIVE_PROBE,
                source=Source.PROBE, observer="probe-agent-hq")


def _bgp_down() -> Signal:
    return _sig("bgp_adjacency_change", "br09-edge", EntityType.DEVICE, off=5,
                modality=ModalityClass.CONTROL_PLANE, source=Source.SYSLOG, observer="syslog-br09")


def test_dia_egress_needs_both_halves_owner_2026_11_24():
    assert DIA not in _ids(rank(builtin_catalog(), [_probe()]))       # probe only: not ranked
    assert DIA not in _ids(rank(builtin_catalog(), [_bgp_down()]))    # BGP only: not ranked
    res = rank(builtin_catalog(), [_probe(), _bgp_down()])            # both: ranked
    dia = {h.template_id: h for h in res.hypotheses}.get(DIA)
    assert dia is not None and dia.confidence_rank == 1.0


def test_audited_anchors_gate_their_templates():
    # lastmile-circuit-flap: probe loss / BGP drop alone is generic evidence.
    res = rank(builtin_catalog(), [_sig("probe_loss", "p1", EntityType.PATH,
                                        modality=ModalityClass.ACTIVE_PROBE, source=Source.PROBE)])
    assert LASTMILE not in _ids(res)
    # private-interconnect-bgp-down: probe loss alone is not "BGP down".
    assert INTERCONNECT not in _ids(res)
    # ap-down-power: a lone switch-port change is a link event, not an AP down.
    res = rank(builtin_catalog(), [_sig("link_state_change", "sw1:Gi1/0/7", EntityType.INTERFACE,
                                        modality=ModalityClass.CONTROL_PLANE, source=Source.TRAP)])
    assert AP_POWER not in _ids(res)
