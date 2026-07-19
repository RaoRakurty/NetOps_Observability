"""Active Verification lane (RCA spec item 8) — producer, verdict-gate and
scoring semantics.

Pins the contract of the new evidence modality:
  * producer: fail-closed intake, honest observer/trust marking, closed
    refutes/corroborates vocabulary
  * verdicts: a device answer (ssh/snmp) can be the independent second source;
    a platform reach probe (tcp) supports but never confirms; a device can
    never corroborate its own telemetry through verification
  * scoring: a failing check corroborates (satisfies a clause via
    corroborates_kinds); a healthy battery REFUTES (contradiction penalty)
"""
from __future__ import annotations

from datetime import datetime, timezone

from catalog import Clause, Template, Verdict as TemplateVerdict
from scoring import CONTRADICTION_PENALTY, score_template
from signals import (
    EntityType,
    ModalityClass,
    Observer,
    ObserverType,
    Severity,
    Signal,
    Source,
    classify_observer_kind,
)
from verdicts import VerdictTier, assess, witness_of
from verification_producer import (
    VERIFICATION_HEALTHY_KIND,
    VERIFICATION_RESULT_KIND,
    verification_signal_from_event,
)

TS = datetime(2026, 7, 19, 12, 0, 0, tzinfo=timezone.utc)


def wire_event(**over) -> dict:
    ev = {
        "tenant_id": "t1",
        "run_id": "run-1",
        "correlation_id": "9a1b2c3d-0000-0000-0000-000000000001",
        "check": "ssh_bgp",
        "method": "ssh",
        "device_id": "dev-1",
        "device_name": "edge-1",
        "target": "10.0.0.1",
        "status": "fail",
        "observed": "neighbor 10.0.0.2 Idle",
        "command": "show ip bgp summary",
        "trigger": "manual",
        "ts": "2026-07-19T12:00:00Z",
        "corroborates_kinds": ["bgp_adjacency_change"],
    }
    ev.update(over)
    return ev


# ── producer ─────────────────────────────────────────────────────────────────

def test_failing_check_becomes_corroborating_result_signal():
    sig = verification_signal_from_event(wire_event(), TS)
    assert sig is not None
    assert sig.kind == VERIFICATION_RESULT_KIND
    assert sig.source is Source.VERIFICATION
    assert sig.modality_class is ModalityClass.ACTIVE_VERIFICATION
    assert sig.severity is Severity.HIGH
    assert sig.entity_type is EntityType.DEVICE
    assert sig.entity_id == "dev-1"
    # ssh: the DEVICE is the witness
    assert sig.observer.observer_id == "dev-1"
    assert sig.observer.observer_type is ObserverType.DEVICE
    assert sig.attrs["verification_trust"] == "device_answer"
    assert sig.attrs["corroborates_kinds"] == ["bgp_adjacency_change"]
    assert sig.attrs["command"] == "show ip bgp summary"


def test_healthy_check_becomes_refuting_signal():
    sig = verification_signal_from_event(
        wire_event(status="pass", observed="all neighbors Established",
                   refutes_kinds=["bgp_adjacency_change", "routing_adjacency_change"]),
        TS,
    )
    assert sig is not None
    assert sig.kind == VERIFICATION_HEALTHY_KIND
    assert sig.severity is Severity.INFO
    assert sig.attrs["refutes_kinds"] == ["bgp_adjacency_change", "routing_adjacency_change"]
    assert "corroborates_kinds" not in sig.attrs


def test_refutes_vocabulary_is_closed():
    # zero-trust: a producer cannot smuggle arbitrary vocabulary into a claim
    sig = verification_signal_from_event(
        wire_event(status="pass", refutes_kinds=["bgp_adjacency_change", "made_up_kind", 42]),
        TS,
    )
    assert sig is not None
    assert sig.attrs.get("refutes_kinds") == ["bgp_adjacency_change"]


def test_module_check_kinds_are_admissible():
    # Troubleshooting-module vocabulary (verify_modules.go): interface deep-dive
    # and recent-change claims pass the closed-vocabulary gate; junk still drops.
    sig = verification_signal_from_event(
        wire_event(check="ssh_iface_deep", command="show interfaces",
                   observed="interface deep-dive faults: Gi0/0: 34 CRC errors (cumulative)",
                   corroborates_kinds=["link_state_change", "if_errors", "if_crc", "made_up"]),
        TS,
    )
    assert sig is not None
    assert sig.attrs["corroborates_kinds"] == ["if_crc", "if_errors", "link_state_change"]

    chg = verification_signal_from_event(
        wire_event(check="ssh_config_change", command="show system commit",
                   status="pass", refutes_kinds=["config_change"]),
        TS,
    )
    assert chg is not None
    assert chg.kind == VERIFICATION_HEALTHY_KIND
    assert chg.attrs["refutes_kinds"] == ["config_change"]


def test_fail_closed_drops():
    assert verification_signal_from_event(wire_event(tenant_id=""), TS) is None
    assert verification_signal_from_event(wire_event(status="skipped"), TS) is None
    assert verification_signal_from_event(wire_event(status="weird"), TS) is None
    assert verification_signal_from_event(wire_event(device_id="", device_name=""), TS) is None
    assert verification_signal_from_event(wire_event(check=""), TS) is None


def test_tcp_reach_probe_is_platform_witness_and_support_only():
    sig = verification_signal_from_event(
        wire_event(check="reach_tcp", method="tcp", status="unreachable",
                   command="", corroborates_kinds=[]),
        TS,
    )
    assert sig is not None
    assert sig.observer.observer_id == "verifier:api"
    assert sig.observer.observer_type is ObserverType.PLATFORM
    assert sig.attrs["verification_trust"] == "platform_probe"
    assert sig.attrs["agent_host"] == "api"  # reach probes share fate
    assert witness_of(sig).support_only is True
    assert witness_of(sig).trusted is False


def test_device_answer_is_trusted_witness():
    sig = verification_signal_from_event(wire_event(), TS)
    w = witness_of(sig)
    assert w.support_only is False
    assert w.trusted is True


def test_observed_output_is_sanitized_and_bounded():
    sig = verification_signal_from_event(
        wire_event(observed="bad\x1b[31mctl\x00chars" + "x" * 2000), TS)
    assert sig is not None
    obs = sig.attrs["observed"]
    assert len(obs) <= 500
    assert "\x1b" not in obs and "\x00" not in obs


def test_observer_kind_is_collector_never_vantage():
    assert classify_observer_kind("dev-1", "device", "active_verification") == "collector"


def test_deterministic_signal_identity():
    a = verification_signal_from_event(wire_event(), TS)
    b = verification_signal_from_event(wire_event(), TS)
    assert a is not None and b is not None
    assert a.signal_id == b.signal_id


# ── verdict gate: independence semantics ─────────────────────────────────────

def _probe(observer: str, entity: str = "path-1") -> Signal:
    return Signal(
        tenant_id="t1", ts=TS, source=Source.PROBE, kind="probe_loss",
        observer=Observer(observer_id=observer, observer_type=ObserverType.VANTAGE_AGENT),
        modality_class=ModalityClass.ACTIVE_PROBE,
        entity_type=EntityType.PATH, entity_id=entity,
        severity=Severity.HIGH, native_id=f"probe|{observer}|{entity}",
        attrs={"probe_authority": "high"},
    )


def _telemetry(observer: str, entity: str = "dev-1") -> Signal:
    return Signal(
        tenant_id="t1", ts=TS, source=Source.METRIC, kind="if_metric_anomaly",
        observer=Observer(observer_id=observer, observer_type=ObserverType.DEVICE),
        modality_class=ModalityClass.DEVICE_TELEMETRY,
        entity_type=EntityType.DEVICE, entity_id=entity,
        severity=Severity.WARN, native_id=f"metric|{observer}|{entity}",
    )


def test_device_answer_forms_independent_pair_with_probe():
    ver = verification_signal_from_event(wire_event(), TS)
    verdict = assess([_probe("agent-9"), ver])
    assert verdict.tier is VerdictTier.CONFIRMED
    assert verdict.coverage.independent_pair == ("agent-9", "dev-1")


def test_device_cannot_corroborate_its_own_telemetry_via_verification():
    ver = verification_signal_from_event(wire_event(), TS)
    verdict = assess([_telemetry("dev-1"), ver])
    assert verdict.tier is VerdictTier.SUSPECTED  # same observer → no pair


def test_platform_reach_probe_never_confirms():
    ver = verification_signal_from_event(
        wire_event(check="reach_tcp", method="tcp", status="unreachable"), TS)
    verdict = assess([_telemetry("dev-1"), ver])
    assert verdict.tier is VerdictTier.SUSPECTED
    assert verdict.coverage.independent_pair is None


# ── scoring: corroborate + refute ────────────────────────────────────────────

def _template(**over) -> Template:
    base = dict(
        id="sig.test.bgp-down",
        title="BGP session down",
        domain="ent.campus",
        requires=(Clause(kind="bgp_adjacency_change"),),
        discriminators=(),
        required_modalities=(),
        verdict=TemplateVerdict(owner="netops", layer="L3/L4", first_steps=("check peer",)),
    )
    base.update(over)
    return Template(**base)


def _syslog_bgp(observer: str = "edge-1", entity: str = "dev-1") -> Signal:
    return Signal(
        tenant_id="t1", ts=TS, source=Source.SYSLOG, kind="bgp_adjacency_change",
        observer=Observer(observer_id=observer, observer_type=ObserverType.DEVICE),
        modality_class=ModalityClass.CONTROL_PLANE,
        entity_type=EntityType.DEVICE, entity_id=entity,
        severity=Severity.HIGH, native_id=f"syslog|{observer}|{entity}",
    )


def test_failing_verification_satisfies_clause_via_corroborates_kinds():
    ver = verification_signal_from_event(wire_event(), TS)
    score = score_template(_template(), (ver,))
    assert score.satisfied == ("bgp_adjacency_change",)
    assert not score.missing
    assert not score.contradicted


def test_healthy_battery_refutes_satisfied_template():
    syslog = _syslog_bgp()
    healthy = verification_signal_from_event(
        wire_event(status="pass", refutes_kinds=["bgp_adjacency_change"]), TS)
    with_ver = score_template(_template(), (syslog, healthy))
    without = score_template(_template(), (syslog,))
    assert with_ver.contradicted is True
    assert f"{VERIFICATION_HEALTHY_KIND}:bgp_adjacency_change" in with_ver.contradictions
    assert with_ver.confidence_rank <= without.confidence_rank * CONTRADICTION_PENALTY + 1e-9
    assert without.contradicted is False


def test_healthy_battery_on_other_device_does_not_refute():
    syslog = _syslog_bgp(entity="dev-other", observer="dev-other")
    healthy = verification_signal_from_event(
        wire_event(status="pass", refutes_kinds=["bgp_adjacency_change"]), TS)
    score = score_template(_template(), (syslog, healthy))
    assert score.contradicted is False


def test_healthy_battery_with_unrelated_refutes_does_not_refute():
    syslog = _syslog_bgp()
    healthy = verification_signal_from_event(
        wire_event(status="pass", refutes_kinds=["device_restart"]), TS)
    score = score_template(_template(), (syslog, healthy))
    assert score.contradicted is False


def test_corroborating_verification_plus_probe_confirms_template():
    # the loop the spec closes: SUSPECTED (one witness) + device answer → CONFIRMED
    template = _template(requires=(
        Clause(kind="bgp_adjacency_change"),
        Clause(kind="probe_loss", optional=True),
    ))
    ver = verification_signal_from_event(wire_event(), TS)
    probe = _probe("agent-9")
    score = score_template(template, (ver, probe))
    assert score.verdict_gate.tier is VerdictTier.CONFIRMED
