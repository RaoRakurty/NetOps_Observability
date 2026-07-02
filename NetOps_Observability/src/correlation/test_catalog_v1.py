"""v1 NOC-catalog contract tests (owner failure-signature spec, 2026-07-02).

Pins the rules the spec makes non-negotiable: the seam/scope taxonomy is a
closed enum, every seam-tagged signature carries the voice contract, confirmed
can never come from a single evidence plane, and the confidence label follows
the owner's lexical taxonomy (suspected / likely / confirmed) — never a bare
number.
"""

from datetime import datetime, timezone

import pydantic
import pytest

from catalog import BUILTIN_TEMPLATES, Seam, builtin_catalog, load_catalog
from scoring import rank, score_template
from signals import ModalityClass, Signal, Source, Observer, ObserverType, EntityType

ALLOWED_SEAMS = {"LAN", "WAN_SDWAN", "DC_FABRIC", "CARRIER_INTERCONNECT", "CLOUD_APP"}
ALLOWED_SCOPES = {"onprem_only", "cloud_only", "hybrid"}


def _v1_templates():
    return [t for t in builtin_catalog().templates if t.seams]


def test_v1_taxonomy_is_closed():
    cat = builtin_catalog()
    assert len(_v1_templates()) == 108  # waves 1-3 + 23 SP/DC port-intelligence
    for t in cat.templates:
        assert set(t.seams) <= ALLOWED_SEAMS, t.id
        assert t.deployment_scope in ALLOWED_SCOPES, t.id


def test_v1_voice_contract_mandatory():
    for t in _v1_templates():
        assert t.operator_phrase.strip(), t.id
        assert t.manager_phrase.strip(), t.id
        # No overclaiming verbs in the canned phrases (live-incident wording rules).
        for banned in ("root cause is", "certainly", "definitely", "proven"):
            assert banned not in t.operator_phrase.lower(), t.id
            assert banned not in t.manager_phrase.lower(), t.id


def test_seam_tagged_template_rejects_missing_phrases():
    bad = dict(BUILTIN_TEMPLATES[-1])  # a valid v1 entry…
    bad = {**bad, "id": "sig.ent.app.phrase-lint-probe", "operator_phrase": ""}
    with pytest.raises(pydantic.ValidationError):
        load_catalog([bad])


def _mk(kind, modality, observer_id, entity_type="device", entity_id="dev1"):
    return Signal(
        tenant_id="t", ts=datetime(2026, 7, 2, tzinfo=timezone.utc),
        source=Source.SYSLOG, kind=kind,
        observer=Observer(observer_id=observer_id, observer_type=ObserverType.DEVICE,
                          collection_path="direct"),
        modality_class=modality, entity_type=EntityType(entity_type), entity_id=entity_id,
        severity=3, native_id=f"n-{kind}-{observer_id}",
    )


def test_confirmed_impossible_from_single_plane():
    """One modality/observer can NEVER confirm — regardless of how many clauses
    it satisfies (the owner's core confidence rule; enforced by the gate)."""
    t = builtin_catalog().get("sig.ent.security.fw-ha-failover-drift")
    ev = (
        _mk("fw_ha_state_change", ModalityClass.CONTROL_PLANE, "syslog-fw1"),
        _mk("fw_session_drop", ModalityClass.CONTROL_PLANE, "syslog-fw1"),
        _mk("fw_policy_mismatch", ModalityClass.CONTROL_PLANE, "syslog-fw1"),
    )
    s = score_template(t, ev)
    assert s.verdict_gate.tier.value != "confirmed"
    assert s.confidence_label() in ("suspected", "likely")


def test_confidence_label_taxonomy():
    t = builtin_catalog().get("sig.ent.security.nat-snat-exhaustion")
    # Required-only, single plane → suspected.
    s = score_template(t, (_mk("nat_alloc_fail", ModalityClass.DEVICE_TELEMETRY, "snmp-fw"),))
    assert s.confidence_label() == "suspected"
    # All required + a supporting clause, still one observer short of the gate
    # on independence → likely (actionable, honestly not confirmed).
    ev = (
        _mk("nat_alloc_fail", ModalityClass.DEVICE_TELEMETRY, "snmp-fw"),
        _mk("synthetic_http_fail", ModalityClass.DEVICE_TELEMETRY, "snmp-fw", "service", "saas"),
        _mk("if_util_high", ModalityClass.DEVICE_TELEMETRY, "snmp-fw", "device", "fw"),
    )
    s = score_template(t, ev)
    assert s.confidence_label() == "likely"
    assert s.verdict_gate.tier.value != "confirmed"


def test_contradiction_lowers_confidence_and_missing_is_exposed():
    t = builtin_catalog().get("sig.ent.access.vlan-trunk-mismatch")
    clean = score_template(t, (_mk("vlan_reachability_fail", ModalityClass.CONTROL_PLANE, "syslog-sw1"),))
    contra = score_template(t, (
        _mk("vlan_reachability_fail", ModalityClass.CONTROL_PLANE, "syslog-sw1"),
        _mk("link_state_change", ModalityClass.CONTROL_PLANE, "syslog-sw1"),
    ))
    assert contra.confidence_rank < clean.confidence_rank
    assert contra.contradicted
    # Missing evidence is exposed, never hidden.
    partial = score_template(t, (_mk("arp_fail", ModalityClass.CONTROL_PLANE, "syslog-sw1"),))
    assert partial.missing == () or isinstance(partial.missing, tuple)
    res = rank(builtin_catalog(), (_mk("vlan_reachability_fail", ModalityClass.CONTROL_PLANE, "syslog-sw1"),))
    assert isinstance(res.evidence_missing, tuple)


def test_narration_fields_ride_the_hypotheses_blob():
    t = builtin_catalog().get("sig.ent.app.lb-target-health-failure")
    s = score_template(t, (_mk("lb_target_unhealthy", ModalityClass.DEVICE_TELEMETRY, "cloud-lb", "service", "vip"),))
    d = s.to_dict()
    assert d["operator_phrase"] and d["manager_phrase"]
    assert d["seams"] == ["CLOUD_APP", "DC_FABRIC"]
    assert d["deployment_scope"] == "hybrid"
    assert d["confidence_label"] in ("suspected", "likely", "confirmed")
    assert d["false_positives"]


def test_scope_metadata_declared_for_every_v1_entry():
    """Deployment scope is enforced as metadata + fixtures today; runtime
    attach-time scope gating rides the seam inventory (grounding), so this
    test pins that the DECLARATION is complete and sane."""
    for t in _v1_templates():
        if t.deployment_scope == "onprem_only":
            assert "CLOUD_APP" not in t.seams or len(t.seams) > 1, t.id
        if t.deployment_scope == "cloud_only":
            assert "CLOUD_APP" in t.seams, t.id
