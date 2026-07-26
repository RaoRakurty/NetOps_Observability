"""classify_probe: target/observer/trust → (scope, authority).

Pins the customer-path probe model: a probe to a platform SERVICE stays internal
(hidden) no matter who issued it; a measurement vantage probing a CUSTOMER path is
customer_path and VISIBLE; its authority follows DECLARED trust — untrusted SUPPORT
(LOW, never confirm), trusted may anchor a confirmed verdict (HIGH). Fail-closed."""

from datetime import datetime, timezone

import main
from signals import (
    CONFIRM_AUTHORITIES,
    EntityType,
    ModalityClass,
    Observer,
    ObserverType,
    ProbeAuthority,
    ProbeScope,
    Severity,
    Signal,
    Source,
)


def probe(entity_id: str, observer: str) -> Signal:
    return Signal(
        tenant_id="t1",
        ts=datetime(2026, 6, 21, tzinfo=timezone.utc),
        source=Source.PROBE,
        kind="probe_loss",
        observer=Observer(observer_id=observer, observer_type=ObserverType.VANTAGE_AGENT),
        modality_class=ModalityClass.ACTIVE_PROBE,
        entity_type=EntityType.PATH,
        entity_id=entity_id,
        severity=Severity.HIGH,
        native_id=f"test|{entity_id}",
    )


def classify(entity_id: str, observer: str, ev: dict | None = None) -> Signal:
    sig = probe(entity_id, observer)
    main.classify_probe(ev or {}, sig)
    return sig


def test_probe_to_stack_service_stays_internal(monkeypatch):
    monkeypatch.setattr(main, "_INTERNAL_PROBE_TARGETS", {"nginx", "clickhouse"})
    monkeypatch.setattr(main, "_MEASUREMENT_PROBE_OBSERVERS", {"prober"})
    monkeypatch.setattr(main, "_TRUSTED_PROBE_OBSERVERS", {"prober"})  # trusted, but target wins
    sig = classify("prober->nginx", "prober")
    assert sig.attrs["probe_scope"] == ProbeScope.INTERNAL_SELF_PROBE.value
    # internal → not confirm-capable
    assert sig.attrs["probe_authority"] not in {a.value for a in CONFIRM_AUTHORITIES}


def test_untrusted_measurement_probe_to_customer_is_visible_support(monkeypatch):
    monkeypatch.setattr(main, "_INTERNAL_PROBE_TARGETS", {"nginx"})
    monkeypatch.setattr(main, "_MEASUREMENT_PROBE_OBSERVERS", {"prober"})
    monkeypatch.setattr(main, "_TRUSTED_PROBE_OBSERVERS", set())  # conservative default
    sig = classify("prober->192.0.2.120", "prober")
    # customer_path scope → shown (NOT internal/synthetic); LOW authority → supports
    # but never confirms, and is not debug_only so it stays visible.
    assert sig.attrs["probe_scope"] == ProbeScope.CUSTOMER_PATH.value
    assert sig.attrs["probe_authority"] == ProbeAuthority.LOW.value
    assert sig.attrs["probe_authority"] != ProbeAuthority.DEBUG_ONLY.value
    assert sig.attrs["probe_authority"] not in {a.value for a in CONFIRM_AUTHORITIES}


def test_trusted_measurement_probe_to_customer_can_confirm(monkeypatch):
    monkeypatch.setattr(main, "_INTERNAL_PROBE_TARGETS", {"nginx"})
    monkeypatch.setattr(main, "_MEASUREMENT_PROBE_OBSERVERS", {"prober"})
    monkeypatch.setattr(main, "_TRUSTED_PROBE_OBSERVERS", {"prober"})
    monkeypatch.setattr(main, "_TRUSTED_PROBE_VANTAGE", main.VantageType.PRIVATE_LOCATION)
    sig = classify("prober->192.0.2.120", "prober")
    assert sig.attrs["probe_scope"] == ProbeScope.CUSTOMER_PATH.value
    # trusted real vantage on a customer path → confirm-capable
    assert sig.attrs["probe_authority"] in {a.value for a in CONFIRM_AUTHORITIES}


def test_registry_fields_are_authoritative(monkeypatch):
    monkeypatch.setattr(main, "_MEASUREMENT_PROBE_OBSERVERS", {"prober"})
    monkeypatch.setattr(main, "_TRUSTED_PROBE_OBSERVERS", set())
    # the probe event explicitly declares a real enterprise vantage → trumps inference
    sig = classify("prober->192.0.2.120", "prober",
                   ev={"probe_intent": "customer_path", "vantage_type": "enterprise_agent"})
    assert sig.attrs["classification_source"] == "registry"
    assert sig.attrs["probe_authority"] in {a.value for a in CONFIRM_AUTHORITIES}


# ── RCA truthfulness epic §2/§11: lineage + declared purpose ─────────────────

def test_execution_id_and_purpose_stamped(monkeypatch):
    monkeypatch.setattr(main, "_MEASUREMENT_PROBE_OBSERVERS", {"prober"})
    monkeypatch.setattr(main, "_TRUSTED_PROBE_OBSERVERS", {"prober"})
    sig = classify("prober->10.60.10.10", "prober",
                   {"execution_id": "ex-abc123", "environment": "prod"})
    assert sig.attrs["execution_id"] == "ex-abc123"
    assert sig.attrs["signal_purpose"] == "production"
    assert sig.attrs["environment"] == "prod"


def test_validation_purpose_is_debug_only_even_with_customer_intent():
    # §11: a declared non-production purpose overrides EVERYTHING — a validation
    # canary can never arrive as a trusted customer-path witness, so it can
    # never confirm production customer impact or open production tickets.
    sig = classify("canary->portal.rca-canary.example", "prober", {
        "signal_purpose": "validation",
        "probe_intent": "customer_path",
        "vantage_type": "enterprise_agent",
    })
    assert sig.attrs["probe_authority"] == ProbeAuthority.DEBUG_ONLY.value
    assert sig.attrs["probe_scope"] == ProbeScope.SYNTHETIC_LAB_PROBE.value
    assert sig.attrs["signal_purpose"] == "validation"
    assert sig.attrs["environment"] == "validation"  # inherits purpose when undeclared
    assert sig.attrs["classification_source"] == "declared-purpose"


def test_fault_injection_and_lab_purposes_demote():
    for purpose in ("fault_injection", "lab", "debug", "demo", "staging"):
        sig = classify("prober->10.60.10.10", "prober", {"signal_purpose": purpose})
        assert sig.attrs["probe_authority"] == ProbeAuthority.DEBUG_ONLY.value, purpose


def test_production_purpose_keeps_registry_trust(monkeypatch):
    # Regression guard for the live drills: the registry-trusted prober keeps
    # its confirm-capable authority when purpose is production/absent.
    monkeypatch.setattr(main, "_INTERNAL_PROBE_TARGETS", set())
    monkeypatch.setattr(main, "_MEASUREMENT_PROBE_OBSERVERS", {"prober"})
    monkeypatch.setattr(main, "_TRUSTED_PROBE_OBSERVERS", {"prober"})
    for ev in ({}, {"signal_purpose": "production"}):
        sig = classify("prober->10.60.10.10", "prober", ev)
        assert sig.attrs["probe_authority"] in {a.value for a in CONFIRM_AUTHORITIES}
        assert sig.attrs["probe_scope"] == ProbeScope.CUSTOMER_PATH.value


def test_one_execution_yields_one_observer(monkeypatch):
    """Owner feedback: one check execution must count as ONE observer — both
    lanes of one execution share observer identity and execution lineage."""
    from datetime import datetime, timezone

    import main
    from episodes import EpisodeDetector
    from producers import probe_signals
    from synthetic_normalize import synthetic_app_signal

    monkeypatch.setattr(main, "_INTERNAL_PROBE_TARGETS", set())
    monkeypatch.setattr(main, "_MEASUREMENT_PROBE_OBSERVERS", {"prober"})
    monkeypatch.setattr(main, "_TRUSTED_PROBE_OBSERVERS", {"prober"})
    now = datetime(2026, 7, 13, tzinfo=timezone.utc)
    ev = {"kind": "http", "ok": False, "prober": "prober", "loss_pct": 100.0,
          "target": "https://portal.example/health", "ts": now.isoformat(),
          "execution_id": "ex-one"}
    sigs = probe_signals(ev, EpisodeDetector(), "t1", now)
    app = synthetic_app_signal(ev, "t1", now)
    assert app is not None
    sigs = [*sigs, app]
    for s in sigs:
        main.classify_probe(ev, s)
    observers = {s.observer.observer_id for s in sigs}
    executions = {s.attrs.get("execution_id") for s in sigs}
    assert observers == {"prober"}, "one execution must present exactly one observer"
    assert executions == {"ex-one"}, "every derived signal carries the execution lineage"
