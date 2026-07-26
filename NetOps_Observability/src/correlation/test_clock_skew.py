"""Clock-skew flagging (log-time standard S5 / rule R5).

A device whose syslog origin time disagrees with the pipeline receive clock —
or a cloud ingest lane delivering beyond its family envelope — must surface as
a per-device / per-lane `clock_skew` finding, never as silently misplaced
records. These tests pin the producer, the wire adapter, and the registration
that keeps the kind out of the orphan-producer CI gate while ALSO keeping it
out of the RCA evidence math (META finding: never engine-buffered).
"""
from datetime import datetime, timezone

from catalog import builtin_catalog
from cloud_producers import CLOUD_KINDS, cloud_signal_from_event
from confirmability import KIND_MODALITY
from coverage import classify_kind
from producers import EMITTED_KINDS, SYSLOG_CLOCK_SKEW_TOLERANCE_S, clock_skew_signal
from signals import EntityType, ModalityClass, Severity

NOW = datetime(2026, 7, 17, 9, 0, 0, tzinfo=timezone.utc)


def _ev(skew: object, host: str = "core-sw1") -> dict:
    return {"hostname": host, "clock_skew_s": skew,
            "timestamp": "2026-07-17T08:59:00Z", "severity": "info"}


def test_syslog_clock_skew_signal_beyond_tolerance():
    sig = clock_skew_signal(_ev(-2400.0), "acme", NOW)
    assert sig is not None
    assert sig.kind == "clock_skew"
    assert sig.entity_type is EntityType.DEVICE
    assert sig.entity_id == "core-sw1"
    assert sig.severity is Severity.WARN
    assert sig.modality_class is ModalityClass.MANAGEMENT_PLANE
    assert sig.value == -2400.0
    assert sig.attrs["direction"] == "behind"
    assert sig.attrs["lane"] == "syslog"
    assert sig.attrs["tolerance_s"] == SYSLOG_CLOCK_SKEW_TOLERANCE_S
    # The platform compared the clocks — the device is the SUBJECT, not the witness.
    assert sig.observer.observer_id == "log-pipeline"


def test_syslog_clock_skew_abstains_in_tolerance_or_garbage():
    assert clock_skew_signal(_ev(120.0), "acme", NOW) is None          # in tolerance
    assert clock_skew_signal(_ev(None), "acme", NOW) is None           # no stamp
    assert clock_skew_signal(_ev("huge"), "acme", NOW) is None         # non-numeric
    assert clock_skew_signal(_ev(True), "acme", NOW) is None           # bool ≠ number
    assert clock_skew_signal(_ev(-2400.0, host=""), "acme", NOW) is None
    assert clock_skew_signal(_ev(-2400.0, host="unknown"), "acme", NOW) is None


def test_cloud_lane_clock_skew_maps_through_the_wire_adapter():
    ev = {
        "kind": "clock_skew", "tenant_id": "acme", "provider": "aws",
        "resource_id": "aws/lb", "region": "us-east-1", "severity": "warn",
        "metric_name": "clock_skew_s", "value": -2400.0,
        "ts": "2026-07-17T08:59:00Z",
        "attrs": {"clock_skew_s": -2400.0, "tolerance_s": 900.0,
                  "direction": "behind", "lane": "lb"},
    }
    sig = cloud_signal_from_event(ev, "acme", NOW)
    assert sig.kind == "clock_skew"
    assert sig.entity_type is EntityType.SERVICE   # the LANE is the entity
    assert sig.entity_id == "aws/lb"
    assert sig.modality_class is ModalityClass.MANAGEMENT_PLANE
    assert sig.attrs["lane"] == "lb"


def test_clock_skew_is_registered_everywhere_the_gates_look():
    # Emitted-kind registry (coverage/orphan gate input).
    assert "clock_skew" in EMITTED_KINDS
    # Cloud wire-kind registry (handle_cloud dead-letters unknown kinds).
    assert "clock_skew" in CLOUD_KINDS
    # Confirmability modality map (CI-enforced completeness).
    assert KIND_MODALITY["clock_skew"] is ModalityClass.MANAGEMENT_PLANE
    # The orphan-producer gate: declared INTENTIONAL_BLIND, never "orphan".
    assert classify_kind("clock_skew", builtin_catalog()) == "intentional_blind"
