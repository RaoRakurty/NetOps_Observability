# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""P-424934 (lab, 2026-11-11): a standing-property story must never confirm.

Correlation 42493476-3837-5bae-b831-3c5e3a8a8a2e, tenant RETAIL-WALMART, engine
3.3.0, was persisted CONFIRMED with top `sig.ent.security.exposure-story`. The
evidence, all on cEDGE-81 as vManage names it (`ctl-vmanage-bfa81d722501`):

  * 7x controller `bgp_adjacency_change` (vManage `bgp-peer-state-change` to
    idle/active, `peer-routerid=0.0.0.0`: a neighbour that never came up);
  * `security_posture` (telnet permitted on management lines) and
    `security_exposure` (telnet reachable from an untrusted seam), both from the
    platform evaluator `security:correlix-netrule`;
  * 1x `if_metric_anomaly` on GigabitEthernet2, device telemetry via the
    controller.

The gate's reason was "independent confirming pair across 3 modality classes".
That is true and beside the point: an exposure or a failed hardening control has
no onset, so a fault measured beside it proves both facts, never one cause.

Stage [7] fix: both stories carry `allow_root_cause_confirmed=False`, so the cap
in `scoring.score_template` holds them at SUSPECTED with the reason on record.
Stage [1] (the BGP half) is test_controller_bgp_never_established.py.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from catalog import builtin_catalog
from controller_events import controller_event_to_signal
from engine import EngineConfig, run_window
from scoring import rank
from signals import (
    EntityType,
    ModalityClass,
    Observer,
    ObserverType,
    Severity,
    Signal,
    Source,
    evidence_signal_from_event,
)
from verdicts import VerdictTier

TENANT = "RETAIL-WALMART"
DEVICE = "ctl-vmanage-bfa81d722501"
PEER = "192.168.200.34"
T0 = datetime(2026, 11, 11, 9, 0, 0, tzinfo=timezone.utc)
EXPOSURE = "sig.ent.security.exposure-story"
HARDENING = "sig.ent.security.hardening-drift-story"
CAPPED = (EXPOSURE, HARDENING)


def _bgp(i: int, state: str) -> Signal:
    """One vManage report as the controller lane builds it — the 3.3.0 wire
    shape (no transition class hint), so this test isolates stage [7]."""
    ev = {
        "tenant_id": TENANT, "integration_id": "i-lab", "source_system": "vmanage",
        "vendor": "cisco", "product": "Catalyst SD-WAN Manager",
        "event_id": f"evt-{i}", "event_time": (T0 + timedelta(seconds=10 * i)).isoformat(),
        "event_type": "bgp-peer-state-change",
        "normalized_event_type": "bgp_adjacency_change", "severity": "high",
        "device_id": DEVICE, "device_name": "cEDGE-81", "peer_id": PEER,
        "message": (f"bgp-peer-state-change host-name=cEDGE-81; peer={PEER}; "
                    f"bgp-new-state={state}; local-address=0.0.0.0; "
                    "local-routerid=192.1.6.2; peer-routerid=0.0.0.0; vpn-id=200"),
        "evidence_role": "supporting",
        "correlation_hints": {"component": "VPN", "system_ip": "10.255.255.81"},
    }
    sig = controller_event_to_signal(ev, T0)
    assert sig is not None and sig.entity_id == f"{DEVICE}:{PEER}"
    return sig


def _security(kind: str, control: str, secs: int) -> Signal:
    ev = {
        "schema_version": "1", "tenant_id": TENANT,
        "ts": (T0 + timedelta(seconds=secs)).isoformat(),
        "kind": kind, "entity_id": DEVICE, "entity_type": "device",
        "entity_tokens": [DEVICE, f"device:{DEVICE}"], "severity": "high",
        "native_id": f"security|{kind}|{control}|{DEVICE}",
        "attrs": {"evidence_class": "posture", "provider_source": "correlix-netrule",
                  "control_id": control, "status": "Fail"},
    }
    sig = evidence_signal_from_event(ev, TENANT)
    assert sig.observer.observer_id == "security:correlix-netrule"
    return sig


def _if_anomaly(secs: int) -> Signal:
    ent = f"{DEVICE}:GigabitEthernet2"
    return Signal(
        tenant_id=TENANT, ts=T0 + timedelta(seconds=secs), source=Source.METRIC,
        kind="if_metric_anomaly",
        observer=Observer(observer_id=DEVICE, observer_type=ObserverType.DEVICE,
                          collection_path="via_controller"),
        modality_class=ModalityClass.DEVICE_TELEMETRY, entity_type=EntityType.INTERFACE,
        entity_id=ent, severity=Severity.HIGH, native_id=f"ep|{ent}|{secs}",
        entity_tokens=(DEVICE, ent), metric_name="device_if_in_octets",
        deviation=6.0, attrs={"peak_deviation": 6.0})


def incident() -> list[Signal]:
    states = ("idle", "active", "idle", "active", "idle", "active", "idle")
    return ([_bgp(i, s) for i, s in enumerate(states)]
            + [_security("security_posture", "AC-17", 5),
               _security("security_exposure", "telnet-untrusted-seam", 6),
               _if_anomaly(40)])


def _object_with(snaps, kind: str):
    hits = [s for s in snaps if any(sig.kind == kind for n in s.nodes for sig in n.signals)]
    assert len(hits) == 1, f"{kind} must land on exactly one object, got {len(hits)}"
    return hits[0]


def _cap_reason(hyp) -> str:
    return next((r for r in hyp.verdict_gate.reasons if r.startswith("confirmed capped")), "")


@pytest.mark.parametrize("tid", CAPPED)
def test_the_standing_property_stories_are_capped_in_the_catalog(tid):
    t = next(t for t in builtin_catalog().templates if t.id == tid)
    assert t.allow_root_cause_confirmed is False
    assert "no onset" in t.confirm_cap_reason
    assert "allow_root_cause_confirmed=false" in t.confirm_cap_reason


def test_the_incident_is_suspected_at_most_with_the_cap_on_record():
    snap = _object_with(run_window(incident(), builtin_catalog(), (), EngineConfig()),
                        "security_exposure")
    ranking = snap.ranking
    assert ranking.top_hypothesis == EXPOSURE
    assert ranking.verdict_tier is not VerdictTier.CONFIRMED
    assert ranking.verdict_tier is VerdictTier.SUSPECTED
    top = next(h for h in ranking.hypotheses if h.template_id == EXPOSURE)
    reason = _cap_reason(top)
    assert "standing property" in reason, top.verdict_gate.reasons


def test_the_gate_alone_would_have_confirmed_it():
    """The cap is what holds it: the gate still sees an independent pair across
    planes. If this stops holding, the regression above proves nothing."""
    res = rank(builtin_catalog(), incident())
    top = next(h for h in res.hypotheses if h.template_id == EXPOSURE)
    assert _cap_reason(top), "the cap must be the reason, not a missing witness"
    assert any("independent confirming pair" in r for r in top.verdict_gate.reasons), \
        top.verdict_gate.reasons


def test_the_hardening_drift_sibling_is_capped_on_the_same_evidence():
    """Without the exposure verdict the posture story leads, and stops at suspected."""
    sigs = [s for s in incident() if s.kind != "security_exposure"]
    res = rank(builtin_catalog(), sigs)
    assert res.top_hypothesis == HARDENING
    assert res.verdict_tier is VerdictTier.SUSPECTED
    top = next(h for h in res.hypotheses if h.template_id == HARDENING)
    assert "hardening control" in _cap_reason(top), top.verdict_gate.reasons


def test_the_threat_signal_story_still_confirms_with_an_independent_plane():
    """A detection is an event with an onset; the gate decides it, as before
    (fixtures/security-threat-signal-story-confirmed.json)."""
    t = next(t for t in builtin_catalog().templates
             if t.id == "sig.ent.security.threat-signal-story")
    assert t.allow_root_cause_confirmed is True


def test_engine_semver_moved():
    from engine import engine_version
    semver = engine_version(EngineConfig()).split("+", 1)[0]
    assert tuple(int(p) for p in semver.split(".")) >= (3, 3, 1)
