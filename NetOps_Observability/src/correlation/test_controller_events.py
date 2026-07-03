"""Tests for the NMS controller-event producer (P4)."""
from datetime import datetime, timezone

from controller_events import controller_event_to_signal
from signals import ModalityClass, ObserverType, Severity, Source, EntityType

INGEST = datetime(2026, 7, 3, 12, 0, 0, tzinfo=timezone.utc)


def _vmanage_bfd():
    return {
        "tenant_id": "t-a",
        "integration_id": "int-vm",
        "source_system": "vmanage",
        "vendor": "cisco",
        "normalized_event_type": "controller_bfd_down",
        "severity": "crit",
        "device_id": "10.1.1.1",
        "site_id": "100",
        "tunnel_id": "mpls-biz",
        "event_id": "uuid-1",
        "event_time": "2026-07-03T11:59:00Z",
        "message": "BFD session down",
        "evidence_role": "supporting",
    }


def test_maps_to_management_plane_signal():
    s = controller_event_to_signal(_vmanage_bfd(), INGEST)
    assert s is not None
    # The core mapping: controller source, management-plane modality, controller observer.
    assert s.source == Source.CONTROLLER
    assert s.modality_class == ModalityClass.MANAGEMENT_PLANE
    assert s.observer.observer_type == ObserverType.CONTROLLER
    # via_controller collection path (fate-sharing knows it's not direct-from-device).
    assert s.observer.collection_path == "via_controller"
    assert s.tenant_id == "t-a"
    assert s.severity == Severity.CRIT
    assert s.kind == "controller_bfd_down"
    # A tunnel/BFD event binds to the PATH entity.
    assert s.entity_type == EntityType.PATH
    assert s.entity_id == "mpls-biz"
    assert s.attrs["authority"] == "vendor_controller"
    assert s.attrs["source_system"] == "vmanage"


def test_device_unreachable_binds_device():
    ev = _vmanage_bfd()
    ev["normalized_event_type"] = "controller_device_unreachable"
    ev["tunnel_id"] = ""
    s = controller_event_to_signal(ev, INGEST)
    assert s.entity_type == EntityType.DEVICE
    assert s.entity_id == "10.1.1.1"


def test_policy_change_carries_role():
    ev = _vmanage_bfd()
    ev["normalized_event_type"] = "controller_policy_change"
    ev["evidence_role"] = "discriminating"
    s = controller_event_to_signal(ev, INGEST)
    assert s.attrs["evidence_role"] == "discriminating"


def test_tenant_required():
    ev = _vmanage_bfd()
    ev["tenant_id"] = ""
    assert controller_event_to_signal(ev, INGEST) is None


def test_unbindable_event_dropped():
    # No device/site/tunnel → nothing to correlate → dropped.
    ev = {"tenant_id": "t-a", "normalized_event_type": "controller_alarm", "source_system": "x"}
    assert controller_event_to_signal(ev, INGEST) is None


def test_epoch_millis_time():
    ev = _vmanage_bfd()
    ev["event_time"] = 1751540340000  # epoch millis
    s = controller_event_to_signal(ev, INGEST)
    # millis → seconds, parsed to the exact UTC instant.
    assert s.ts.timestamp() == 1751540340.0
    assert s.ts.tzinfo is not None


def test_vendor_neutral_meraki_and_versa_same_kind_same_shape():
    # A Meraki and a Versa tunnel-down normalize to the SAME kind → identical
    # signal shape (proves no per-vendor signature is needed).
    base = {
        "tenant_id": "t-a", "normalized_event_type": "controller_tunnel_state",
        "severity": "high", "device_id": "dev1", "tunnel_id": "tun1",
        "event_id": "e", "event_time": "2026-07-03T11:59:00Z",
    }
    meraki = dict(base, source_system="meraki")
    versa = dict(base, source_system="versa_director")
    sm = controller_event_to_signal(meraki, INGEST)
    sv = controller_event_to_signal(versa, INGEST)
    assert sm.kind == sv.kind == "controller_tunnel_state"
    assert sm.modality_class == sv.modality_class == ModalityClass.MANAGEMENT_PLANE
    assert sm.entity_type == sv.entity_type == EntityType.PATH


def test_controller_kinds_are_consumed_by_catalog():
    """ACCURACY GUARD (owner: 'build accurately else it won't match'): every
    actionable controller kind the transformers/producer emit must be referenced
    by at least one ENABLED catalog clause — otherwise a controller event would
    normalize fine but silently never match a signature."""
    from catalog import builtin_catalog

    actionable = {
        "controller_tunnel_state",
        "controller_bfd_down",
        "controller_control_connection_loss",
        "controller_device_unreachable",
        "controller_policy_change",
    }
    referenced: set[str] = set()
    for t in builtin_catalog().enabled_templates():
        for clause in t.requires:
            referenced |= clause.kinds()
    missing = actionable - referenced
    assert not missing, f"controller kinds not consumed by any signature: {missing}"


def test_producer_kind_matches_a_catalog_clause():
    """End-to-end: a controller event → producer signal → its kind is present in
    an enabled catalog clause (the wiring actually connects)."""
    from catalog import builtin_catalog

    ev = {
        "tenant_id": "t-a", "source_system": "vmanage",
        "normalized_event_type": "controller_tunnel_state",
        "device_id": "10.1.1.1", "tunnel_id": "t1",
        "event_id": "e1", "event_time": "2026-07-03T11:59:00Z", "severity": "crit",
    }
    sig = controller_event_to_signal(ev, INGEST)
    clause_kinds = {k for t in builtin_catalog().enabled_templates() for c in t.requires for k in c.kinds()}
    assert sig.kind in clause_kinds, f"producer kind {sig.kind} matches no catalog clause"
