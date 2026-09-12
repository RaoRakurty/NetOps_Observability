# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""End-to-end path-causality RCA in the engine (design §2.4; blueprint P2 wiring).

These tests exercise the ADDITIVE P2 enrichment through the REAL engine core
(run_window), over a REAL correlation object and a REAL P1 AssembledPath, with the
verdict lift computed by the REAL verdicts.assess independence gate — nothing about
the attribution or the verdict is mocked.

The contract, per the task:
  * ON-PATH — an app-degradation incident + an on-path cloud_lb_log 5xx (same
    tenant/scope) → the produced object names the LB as cause with a lifted verdict.
  * OFF-PATH — the SAME incident with the fault OFF the affected path → no
    attribution, and the object is BYTE-FOR-BYTE what it is with no discovery.
  * PARTIAL / OPAQUE span → attribution present but the verdict is CAPPED at
    suspected (the honesty cap the design demands).
  * NON-PATH incident (a network object) → identical output with or without
    discovery (the regression guard).
  * PER-TENANT ISOLATION — another tenant's path can never seed an attribution.
  * The RCA-report JSON column (to_object_row["attribution"]) carries the new fields.

Offline + pure: bundled provider snapshot via the P0 classifier, empty seams (the
symptom and the cloud fault ground on the shared app identity), no wall clock.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from catalog import builtin_catalog
from cloud_producers import cloud_signal
from engine import EngineConfig, run_window
from path_assembly import (
    DiscoverySources,
    HopNode,
    HopState,
    MeasuredRun,
    PathAssembler,
)
from segment_classifier import DeviceRole
from signals import (
    EntityType,
    ModalityClass,
    Observer,
    ObserverType,
    ProbeIntent,
    Severity,
    Signal,
    Source,
    VantageType,
    derive_probe_authority,
)
from verdicts import VerdictTier

CAT = builtin_catalog()
ASSEMBLER = PathAssembler()

T0 = datetime(2026, 7, 16, 12, 0, 0, tzinfo=timezone.utc)

# Public AWS addresses (S3 us-east-1 range) → classify CLOUD/aws via the snapshot.
AWS_LB = "52.216.100.5"
AWS_HOST = "52.216.100.6"
LAN_CLIENT = "10.20.30.40"

LB_NAME = "correlix-edge-urlmap"
APP = "checkout"


# ── signal builders (the incident: an app symptom + an on-path cloud LB 5xx) ──


def app_symptom(tenant: str = "acme", ts: datetime = T0) -> Signal:
    """A customer-path synthetic HTTP 5xx at the app — HIGH-authority active_probe."""
    authority = derive_probe_authority(ProbeIntent.CUSTOMER_PATH, VantageType.ENTERPRISE_AGENT)
    return Signal(
        tenant_id=tenant, ts=ts, source=Source.PROBE, kind="synthetic_http_5xx",
        observer=Observer(observer_id="vantage-nyc", observer_type=ObserverType.VANTAGE_AGENT,
                          collection_path="direct"),
        modality_class=ModalityClass.ACTIVE_PROBE, entity_type=EntityType.APP, entity_id=APP,
        severity=Severity.HIGH, native_id="symptom|1", entity_tokens=(f"app:{APP}",),
        attrs={"probe_authority": authority.value},
    )


def lb_5xx_fault(tenant: str = "acme", ts: datetime = T0 + timedelta(seconds=10)) -> Signal:
    """An AWS ALB access-log 5xx for the edge URL-map LB — a PASSIVE_FLOW cloud
    witness, observed by the cloud API (independent of the probe vantage). Grounds on
    the app identity (app=checkout), so it co-locates with the symptom on one object."""
    return cloud_signal(
        tenant, ts, "cloud_lb_log", app=APP, resource_id=LB_NAME,
        account="1234", region="us-east-1", severity=Severity.HIGH,
        attrs={"http_status": 502},
    )


# ── P1 paths (real assembly) ──────────────────────────────────────────────────


def path_with_onpath_lb(tenant: str = "acme"):
    """client(LAN) → cloud(LB, app-host). The LB `correlix-edge-urlmap` is ON path."""
    run = MeasuredRun(tenant, evidence_ref="tr", hops=(
        HopNode(LAN_CLIENT, device_role_hint="client"),
        HopNode(AWS_LB, device_role_hint="lb", key_device=LB_NAME),
        HopNode(AWS_HOST, device_role_hint="host", key_device="app-host-01"),
    ))
    return ASSEMBLER.assemble(tenant, LAN_CLIENT, AWS_HOST, DiscoverySources(measured=(run,)))


def path_without_lb(tenant: str = "acme"):
    """client(LAN) → cloud(app-host only). The LB is NOT on this path."""
    run = MeasuredRun(tenant, evidence_ref="tr", hops=(
        HopNode(LAN_CLIENT, device_role_hint="client"),
        HopNode(AWS_HOST, device_role_hint="host", key_device="app-host-01"),
    ))
    return ASSEMBLER.assemble(tenant, LAN_CLIENT, AWS_HOST, DiscoverySources(measured=(run,)))


def path_with_opaque_span_to_lb(tenant: str = "acme"):
    """client(LAN) → [opaque] → cloud(LB, app-host): the SRC→LB span crosses an
    unknown/opaque segment, so on-path causality to the LB cannot be confirmed."""
    run = MeasuredRun(tenant, evidence_ref="tr", hops=(
        HopNode(LAN_CLIENT, device_role_hint="client"),
        HopNode("", state=HopState.MISSING.value),
        HopNode("", state=HopState.FILTERED.value),
        HopNode(AWS_LB, device_role_hint="lb", key_device=LB_NAME),
        HopNode(AWS_HOST, device_role_hint="host", key_device="app-host-01"),
    ))
    return ASSEMBLER.assemble(tenant, LAN_CLIENT, AWS_HOST, DiscoverySources(measured=(run,)))


# ── network (non-path) incident — the regression guard fixture ────────────────


def network_incident(tenant: str = "acme") -> list[Signal]:
    """A control-plane fabric object (BGP adjacency down + link down on ONE device),
    with NO app symptom. Grounds by shared device identity → one object; carries no
    app-experience signal, so P2 must never touch it."""

    def s(kind: str, eid: str, off: float) -> Signal:
        return Signal(
            tenant_id=tenant, ts=T0 + timedelta(seconds=off), source=Source.SYSLOG, kind=kind,
            observer=Observer(observer_id="leaf1", observer_type=ObserverType.DEVICE,
                              collection_path="direct"),
            modality_class=ModalityClass.CONTROL_PLANE,
            entity_type=EntityType.DEVICE if kind == "bgp_adjacency_change" else EntityType.INTERFACE,
            entity_id=eid, severity=Severity.HIGH, native_id=f"{kind}|{eid}|{off}",
            entity_tokens=(eid.split(":", 1)[0],), attrs={"onset_uncertainty_s": 1.0})

    return [s("bgp_adjacency_change", "leaf1", 0), s("link_state_change", "leaf1:Ethernet1", 5)]


def _run(window, discovery=()):
    """One-object run over an empty seam inventory (the app identity grounds it)."""
    snaps = run_window(window, CAT, (), EngineConfig(), discovery=discovery)
    assert len(snaps) == 1, f"fixture must be one object, got {len(snaps)}"
    return snaps[0]


# ── 1. ON-PATH attribution: the object names the LB with a lifted verdict ─────


def test_on_path_cloud_lb_is_attributed_and_confirms_in_engine():
    disc = (path_with_onpath_lb(),)
    snap = _run([app_symptom(), lb_5xx_fault()], discovery=disc)

    a = snap.attribution
    assert a is not None, "an on-path cloud LB fault must attribute"
    assert a.attributed is not None
    assert a.attributed.device.role == DeviceRole.LOAD_BALANCER.value
    assert a.attributed.device.label == LB_NAME
    assert a.attributed.kind == "cloud_lb_log"
    # the independent cross-modality pair (probe vantage ⟂ cloud API) LIFTS to confirmed.
    assert a.verdict.tier is VerdictTier.CONFIRMED
    assert a.confidence_lifted and not a.capped
    assert LB_NAME in a.headline()


def test_attribution_is_carried_into_the_rca_report_column():
    """to_object_row['attribution'] is the P3 render contract — it must carry the
    named cause, the segments/key devices/head of the typed path, the verdict lift
    and the honesty-cap reason (empty here)."""
    snap = _run([app_symptom(), lb_5xx_fault()], discovery=(path_with_onpath_lb(),))
    blob = json.loads(snap.to_object_row(1)["attribution"])
    assert blob["attributed"]["device"]["role"] == DeviceRole.LOAD_BALANCER.value
    assert blob["attributed"]["headline"]
    assert blob["verdict"]["verdict_tier"] == "confirmed"
    assert blob["baseline_verdict"]["verdict_tier"] == "suspected"
    assert blob["confidence_lifted"] is True
    assert blob["capped"] is False
    assert blob["cap_reason"] == ""
    assert blob["on_path_device_count"] >= 1
    # the DISCOVERED typed path travels with the attribution (the render reads it):
    # ordered segments with key devices, plus src/dst — never invented.
    path = blob["path"]
    assert path["src"] == LAN_CLIENT and path["dst"] == AWS_HOST
    seg_types = [s["segment_type"] for s in path["segments"]]
    assert "cloud" in seg_types                      # the LB/host sit in a CLOUD segment
    labels = [kd["label"] for s in path["segments"] for kd in s["key_devices"]]
    assert LB_NAME in labels


# ── 2. OFF-PATH: no attribution, and the object is byte-for-byte unchanged ─────


def test_off_path_fault_yields_no_attribution_and_no_regression():
    window = [app_symptom(), lb_5xx_fault()]
    base = _run(window)                                  # no discovery at all
    off = _run(window, discovery=(path_without_lb(),))   # fault is OFF this path

    assert off.attribution is None
    # NON-REGRESSIVE: identical content hash AND identical persisted row.
    assert off.content_hash() == base.content_hash()
    assert off.to_object_row(1) == base.to_object_row(1)
    assert off.to_object_row(1)["attribution"] == "{}"


# ── 3. PARTIAL / OPAQUE span → attribution present, verdict CAPPED ────────────


def test_opaque_span_attributes_but_caps_at_suspected():
    snap = _run([app_symptom(), lb_5xx_fault()], discovery=(path_with_opaque_span_to_lb(),))
    a = snap.attribution
    assert a is not None and a.attributed is not None
    assert a.attributed.device.role == DeviceRole.LOAD_BALANCER.value   # still named
    assert a.capped and a.verdict.tier is VerdictTier.SUSPECTED         # but capped
    assert a.cap_reason
    blob = json.loads(snap.to_object_row(1)["attribution"])
    assert blob["capped"] is True and blob["verdict"]["verdict_tier"] == "suspected"
    assert any("unknown" in r or "unobserved" in r for r in blob["verdict"]["reasons"])


# ── 4. NON-PATH incident → identical output with or without discovery ─────────


def test_network_incident_is_untouched_by_discovery():
    window = network_incident()
    base = _run(window)
    # even with a (valid, tenant-matched) discovery path present, a network object
    # with NO app symptom must not be enriched — byte-for-byte identical.
    enriched = _run(window, discovery=(path_with_onpath_lb(),))
    assert enriched.attribution is None
    assert enriched.content_hash() == base.content_hash()
    assert enriched.to_object_row(1) == base.to_object_row(1)


# ── 5. PER-TENANT ISOLATION (§3a) ─────────────────────────────────────────────


def test_cross_tenant_discovery_path_never_attributes():
    # the window is acme's; the only discovery path belongs to evil → structurally
    # dropped before attribution → no cause can rest on another tenant's path.
    evil_path = path_with_onpath_lb(tenant="evil")
    snap = _run([app_symptom("acme"), lb_5xx_fault("acme")], discovery=(evil_path,))
    assert snap.attribution is None
    assert snap.to_object_row(1)["attribution"] == "{}"


def test_discovery_default_is_a_pure_no_op():
    # the default (no discovery) path must be identical to today for the app object.
    window = [app_symptom(), lb_5xx_fault()]
    a = run_window(window, CAT, ())[0]
    b = run_window(window, CAT, (), EngineConfig(), discovery=())[0]
    assert a.attribution is None and b.attribution is None
    assert a.to_object_row(1) == b.to_object_row(1)
