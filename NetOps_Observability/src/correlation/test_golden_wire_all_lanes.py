# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""#99 R3 — golden-wire coverage for every remaining consumer lane.

One raw wire-shaped event per lane, replayed through the PRODUCTION
normalizers via golden_wire.py. Asserts the contract essentials each lane must
hold: correct semantic kind, entity grounding, modality class, and tenancy —
so a raw-boundary regression in ANY lane breaks CI, not just the three lanes
(#98) that had golden coverage before.
"""
from golden_wire import replay_fixture_through_engine
from producers import EMITTED_KINDS
from signals import EntityType, ModalityClass

FIXTURE = "all_lanes_smoke.json"


def _by_kind(signals):
    return {s.kind: s for s in signals}


def test_all_remaining_lanes_normalize_from_raw_wire_events():
    signals, _, _ = replay_fixture_through_engine(FIXTURE)
    kinds = _by_kind(signals)

    # syslog → control-plane adjacency signal
    bgp = kinds["bgp_adjacency_change"]
    assert bgp.modality_class is ModalityClass.CONTROL_PLANE
    assert bgp.tenant_id == "acme"
    assert "leaf1" in (bgp.entity_id, *bgp.entity_tokens)

    # trap (linkDown OID) → canonical link-state control signal
    trap_sig = kinds["link_state_change"]
    assert trap_sig.modality_class is ModalityClass.CONTROL_PLANE
    assert trap_sig.tenant_id == "acme"

    # metric → device-telemetry episode grounding (detection_assumed)
    metric_sig = kinds["device_resource_anomaly"]
    assert metric_sig.modality_class is ModalityClass.DEVICE_TELEMETRY
    assert metric_sig.attrs["detection_assumed"] is True
    assert "leaf1" in metric_sig.entity_id

    # cloud → cloud_health on the app entity
    cloud = kinds["cloud_health"]
    assert cloud.tenant_id == "acme" and cloud.entity_id == "billing"

    # controller → management-plane witness
    ctrl = kinds["controller_bfd_down"]
    assert ctrl.modality_class is ModalityClass.MANAGEMENT_PLANE
    assert ctrl.tenant_id == "acme"

    # app identity → enrichment (INFO, app entity, never a fault)
    ident = kinds["app_identity"]
    assert ident.entity_type is EntityType.APP
    assert ident.entity_id == "Microsoft Teams"

    # every produced fault kind is a registered producer kind (coverage honesty)
    for kind in kinds:
        if kind in ("app_identity",):
            continue
        assert kind in EMITTED_KINDS, f"{kind} produced but not registered in EMITTED_KINDS"


def test_no_lane_produces_tenant_wide_grounding():
    # R2 x R3: the grounding-token guard holds across EVERY lane's real output.
    signals, _, _ = replay_fixture_through_engine(FIXTURE)
    for sig in signals:
        for tok in sig.entity_tokens:
            assert not tok.lower().startswith(("tenant:", "org:", "global:")), (
                f"{sig.kind} emitted forbidden grounding token {tok!r}")
