"""observer_kind classification hint (evidence-accounting Phase B).

The stamp is ADDITIVE and backward-compatible; the Go per-tenant registry is
canonical at read. These tests pin the fail-closed defaults (constraint 1) and
that to_ch_row carries the hint without breaking the frozen schema."""

from datetime import datetime, timezone

from signals import (
    OBSERVER_KIND_COLLECTOR,
    OBSERVER_KIND_CONTROL_PLANE,
    OBSERVER_KIND_LOGICAL_VANTAGE,
    OBSERVER_KIND_UNKNOWN,
    EntityType,
    ModalityClass,
    Observer,
    ObserverType,
    Severity,
    Signal,
    Source,
    classify_observer_kind,
)

T0 = datetime(2026, 7, 15, 20, 25, 0, tzinfo=timezone.utc)


def test_api_is_never_logical_vantage_even_mis_stamped():
    # api mis-stamped as a high-authority vantage_agent → still never a vantage.
    k = classify_observer_kind("api", ObserverType.VANTAGE_AGENT, ModalityClass.ACTIVE_PROBE, "high")
    assert k == OBSERVER_KIND_COLLECTOR


def test_control_plane_is_control_plane_source():
    assert classify_observer_kind("ipsec:edge", ObserverType.DEVICE,
                                  ModalityClass.CONTROL_PLANE) == OBSERVER_KIND_CONTROL_PLANE


def test_trusted_vantage_probe_is_logical_vantage():
    assert classify_observer_kind("lan-vantage-1", ObserverType.VANTAGE_AGENT,
                                  ModalityClass.ACTIVE_PROBE, "high") == OBSERVER_KIND_LOGICAL_VANTAGE


def test_low_authority_probe_is_unknown_not_vantage():
    # constraint 1: unclassified/low probe → unknown, never a guessed vantage.
    assert classify_observer_kind("site-probe-2", ObserverType.VANTAGE_AGENT,
                                  ModalityClass.ACTIVE_PROBE, "low") == OBSERVER_KIND_UNKNOWN


def test_device_and_flow_are_collectors():
    assert classify_observer_kind("leaf1", ObserverType.DEVICE,
                                  ModalityClass.DEVICE_TELEMETRY) == OBSERVER_KIND_COLLECTOR
    assert classify_observer_kind("flow-exp", ObserverType.FLOW_EXPORTER,
                                  ModalityClass.PASSIVE_FLOW) == OBSERVER_KIND_COLLECTOR


def _sig(observer_id, observer_type, modality, attrs=None):
    return Signal(
        tenant_id="t1", ts=T0, source=Source.PROBE, kind="probe_loss",
        observer=Observer(observer_id=observer_id, observer_type=observer_type),
        modality_class=modality, entity_type=EntityType.PATH, entity_id="a->b",
        severity=Severity.WARN, native_id="n1", attrs=attrs or {},
    )


def test_to_ch_row_stamps_observer_kind_additively():
    import json
    row = _sig("lan-vantage-1", ObserverType.VANTAGE_AGENT, ModalityClass.ACTIVE_PROBE,
               attrs={"probe_authority": "high"}).to_ch_row()
    attrs = json.loads(row["attrs"])
    assert attrs["observer_kind"] == OBSERVER_KIND_LOGICAL_VANTAGE
    # The signal object itself is unchanged (frozen attrs not mutated in place).
    assert "attrs" in row and "observer_id" in row


def test_to_ch_row_respects_a_producer_supplied_kind():
    import json
    row = _sig("api", ObserverType.VANTAGE_AGENT, ModalityClass.ACTIVE_PROBE,
               attrs={"observer_kind": "control_plane_source"}).to_ch_row()
    assert json.loads(row["attrs"])["observer_kind"] == "control_plane_source"
