# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Contract tests for path_attribution (path-causality RCA P2: on-path attribution).

Correctness lives here (blueprint P2 + research Area 3). Each test holds the attributor to
one synthesized principle, over a REAL P1 AssembledPath and REAL canonical Signals fed through
the REAL verdicts.assess independence gate — nothing about the verdict is mocked, so a
`confirmed` can only arise from a genuine independent cross-modality pair.

  * ON-PATH attribution — app degradation + an on-path LB 5xx (time-correlated) → the LB is
    named AND the verdict is lifted above the symptom-only baseline (suspected → confirmed).
  * OFF-PATH non-attribution (THE key guard) — the SAME LB 5xx, but the LB is not on the
    affected path → NOT attributed, verdict stays the baseline, fault recorded as discounted.
  * EXPLAINING-AWAY — an on-path DNS NXDOMAIN upstream + a downstream LB 5xx → DNS is named
    (buck stops upstream), the LB is explained away, never independently blamed.
  * HONESTY CAP — a partial/opaque/ambiguous SRC→cause span → capped at suspected +
    evidence_missing even with an on-path, time-correlated, cross-modality fault present.
  * PER-TENANT ISOLATION — attribution never rests on another tenant's path or signal.

Offline + pure: bundled provider snapshot via the P0 classifier, no network, no wall clock.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from cloud_producers import cloud_signal
from path_assembly import (
    DiscoverySources,
    DnsHead,
    HopNode,
    HopState,
    MeasuredRun,
    PathAssembler,
)
from path_attribution import (
    AttributionConfig,
    OnPathAttributor,
    on_path_devices,
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

ASSEMBLER = PathAssembler()
ATTR = OnPathAttributor()

T0 = datetime(2026, 7, 16, 12, 0, 0, tzinfo=timezone.utc)

# Public AWS addresses (S3 us-east-1 range) → classify CLOUD/aws via the bundled snapshot.
AWS_LB = "52.216.100.5"
AWS_HOST = "52.216.100.6"
LAN_CLIENT = "10.20.30.40"

LB_NAME = "correlix-edge-urlmap"
APP = "checkout"
DNS_NAME = "checkout.example.com"


# ── signal builders ───────────────────────────────────────────────────────────


def app_symptom(tenant: str = "acme", ts: datetime = T0) -> Signal:
    """A customer-path synthetic HTTP 5xx at the app — a HIGH-authority active_probe from a
    real enterprise vantage. Alone it is single-modality/observer → suspected (today's
    "saas-experience-degraded, suspected")."""
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
    """An AWS ALB access-log 5xx for the edge URL-map LB — a PASSIVE_FLOW cloud witness,
    observed by the cloud API (an observer independent of the probe vantage)."""
    return cloud_signal(
        tenant, ts, "cloud_lb_log", app=APP, resource_id=LB_NAME,
        account="1234", region="us-east-1", severity=Severity.HIGH,
        attrs={"http_status": 502},
    )


def dns_nxdomain_fault(tenant: str = "acme",
                       ts: datetime = T0 + timedelta(seconds=5)) -> Signal:
    """A Route53 NXDOMAIN for the app's name — a PASSIVE_FLOW cloud witness upstream of the
    LB (resolution precedes connect)."""
    return cloud_signal(
        tenant, ts, "cloud_dns_log", resource_id=DNS_NAME, account="1234",
        region="us-east-1", severity=Severity.HIGH, attrs={"rcode": "NXDOMAIN"},
    )


# ── path builders (real P1 assembly) ──────────────────────────────────────────


def path_with_onpath_lb(tenant: str = "acme") -> object:
    """client(LAN) → cloud(LB, app-host). The LB `correlix-edge-urlmap` is ON the path."""
    run = MeasuredRun(tenant, evidence_ref="tr", hops=(
        HopNode(LAN_CLIENT, device_role_hint="client"),
        HopNode(AWS_LB, device_role_hint="lb", key_device=LB_NAME),
        HopNode(AWS_HOST, device_role_hint="host", key_device="app-host-01"),
    ))
    return ASSEMBLER.assemble(tenant, LAN_CLIENT, AWS_HOST, DiscoverySources(measured=(run,)))


def path_without_lb(tenant: str = "acme") -> object:
    """client(LAN) → cloud(app-host only). The LB is NOT on this path."""
    run = MeasuredRun(tenant, evidence_ref="tr", hops=(
        HopNode(LAN_CLIENT, device_role_hint="client"),
        HopNode(AWS_HOST, device_role_hint="host", key_device="app-host-01"),
    ))
    return ASSEMBLER.assemble(tenant, LAN_CLIENT, AWS_HOST, DiscoverySources(measured=(run,)))


def path_with_dns_head_and_lb(tenant: str = "acme") -> object:
    """A DNS-resolved frontend (head) + client(LAN) → cloud(LB, app-host)."""
    head = DnsHead(tenant, query_name=DNS_NAME, resolved_address=AWS_LB, evidence_ref="dns")
    run = MeasuredRun(tenant, evidence_ref="tr", hops=(
        HopNode(LAN_CLIENT, device_role_hint="client"),
        HopNode(AWS_LB, device_role_hint="lb", key_device=LB_NAME),
        HopNode(AWS_HOST, device_role_hint="host", key_device="app-host-01"),
    ))
    return ASSEMBLER.assemble(tenant, LAN_CLIENT, AWS_HOST,
                              DiscoverySources(measured=(run,), dns_head=head))


def path_with_opaque_span_to_lb(tenant: str = "acme") -> object:
    """client(LAN) → [opaque hops] → cloud(LB, app-host): the SRC→LB span crosses an
    unknown/opaque segment, so on-path causality to the LB cannot be confirmed."""
    run = MeasuredRun(tenant, evidence_ref="tr", hops=(
        HopNode(LAN_CLIENT, device_role_hint="client"),
        HopNode("", state=HopState.MISSING.value),
        HopNode("", state=HopState.FILTERED.value),
        HopNode(AWS_LB, device_role_hint="lb", key_device=LB_NAME),
        HopNode(AWS_HOST, device_role_hint="host", key_device="app-host-01"),
    ))
    return ASSEMBLER.assemble(tenant, LAN_CLIENT, AWS_HOST, DiscoverySources(measured=(run,)))


# ── on-path device set (the bounded walk) ─────────────────────────────────────


def test_on_path_device_set_is_ordered_src_to_dst():
    devs = on_path_devices(path_with_dns_head_and_lb())
    roles = [d.role for d in devs]
    # DNS head is upstream-most (rank 0), then the cloud LB, then the app host.
    assert roles[0] == DeviceRole.DNS_RESOLVER.value
    assert DeviceRole.LOAD_BALANCER.value in roles
    ranks = [d.upstream_rank for d in devs]
    assert ranks == sorted(ranks) and ranks[0] == 0
    lb = next(d for d in devs if d.role == DeviceRole.LOAD_BALANCER.value)
    host = next(d for d in devs if d.role == DeviceRole.HOST.value)
    assert lb.upstream_rank < host.upstream_rank        # LB upstream of the app host


def test_opaque_segment_contributes_no_device():
    devs = on_path_devices(path_with_opaque_span_to_lb())
    # the two opaque hops fabricate NO device; only the real LB + host remain.
    assert all(d.address for d in devs)
    assert {d.role for d in devs} == {DeviceRole.LOAD_BALANCER.value, DeviceRole.HOST.value}


# ── 1. ON-PATH attribution lifts confidence ───────────────────────────────────


def test_on_path_lb_fault_is_attributed_and_confirms():
    a = ATTR.attribute("acme", path_with_onpath_lb(), [app_symptom()], [lb_5xx_fault()])
    # the symptom-only baseline is suspected (single modality/observer)...
    assert a.baseline.tier is VerdictTier.SUSPECTED
    # ...the on-path LB fault is named as the cause...
    assert a.attributed is not None
    assert a.attributed.device.role == DeviceRole.LOAD_BALANCER.value
    assert a.attributed.device.label == LB_NAME
    assert a.attributed.kind == "cloud_lb_log"
    # ...and its independent cross-modality corroboration LIFTS the verdict to confirmed.
    assert a.verdict.tier is VerdictTier.CONFIRMED
    assert a.confidence_lifted
    assert not a.capped
    assert LB_NAME in a.headline()


def test_on_path_attribution_names_the_independent_pair():
    a = ATTR.attribute("acme", path_with_onpath_lb(), [app_symptom()], [lb_5xx_fault()])
    # the confirmed verdict rests on a real independent pair: probe vantage ⟂ cloud API.
    pair = a.verdict.coverage.independent_pair
    assert pair is not None
    assert "vantage-nyc" in pair
    assert any(p.startswith("cloud:") for p in pair)


# ── 2. OFF-PATH non-attribution (the key guard) ───────────────────────────────


def test_off_path_lb_fault_is_not_attributed():
    # SAME LB 5xx, but the LB is NOT on this path → it cannot be the cause of THIS symptom.
    a = ATTR.attribute("acme", path_without_lb(), [app_symptom()], [lb_5xx_fault()])
    assert a.attributed is None                       # no false attribution
    assert not a.confidence_lifted
    assert a.verdict.tier is VerdictTier.SUSPECTED    # stays at the baseline
    assert a.verdict.tier is a.baseline.tier
    # the off-path fault is DISCOUNTED with an honest reason, never silently dropped.
    assert len(a.discounted) == 1
    assert "off-path" in a.discounted[0].reason


def test_off_window_fault_is_discounted_not_attributed():
    # on-path LB, but the fault fired an hour before the symptom — severity ≠ causality.
    stale = lb_5xx_fault(ts=T0 - timedelta(hours=1))
    a = ATTR.attribute("acme", path_with_onpath_lb(), [app_symptom()], [stale])
    assert a.attributed is None
    assert a.verdict.tier is VerdictTier.SUSPECTED
    assert any("off-window" in d.reason for d in a.discounted)


# ── 3. EXPLAINING-AWAY (buck stops upstream) ──────────────────────────────────


def test_upstream_dns_explains_away_downstream_lb():
    a = ATTR.attribute(
        "acme", path_with_dns_head_and_lb(), [app_symptom()],
        [lb_5xx_fault(), dns_nxdomain_fault()],
    )
    # the UPSTREAM-MOST fault (DNS) is named; the LB is a downstream victim, explained away.
    assert a.attributed is not None
    assert a.attributed.device.role == DeviceRole.DNS_RESOLVER.value
    assert a.attributed.kind == "cloud_dns_log"
    explained_roles = {f.device.role for f in a.explained_away}
    assert DeviceRole.LOAD_BALANCER.value in explained_roles
    # the LB is NOT independently blamed (it appears only as explained-away).
    assert a.attributed.device.role != DeviceRole.LOAD_BALANCER.value


# ── 4. HONESTY CAP — partial/opaque span never manufactures a confirmation ────


def test_opaque_span_caps_attribution_at_suspected():
    a = ATTR.attribute("acme", path_with_opaque_span_to_lb(), [app_symptom()], [lb_5xx_fault()])
    # the LB is still on the path and still named — attribution is honest, not silent...
    assert a.attributed is not None
    assert a.attributed.device.role == DeviceRole.LOAD_BALANCER.value
    # ...but the unknown/opaque segment on the SRC→LB span CAPS the verdict at suspected,
    # even though the independent cross-modality pair exists (it WOULD confirm on a clear span).
    assert a.capped
    assert a.verdict.tier is VerdictTier.SUSPECTED
    assert a.cap_reason
    assert any("unknown" in r or "unobserved" in r for r in a.verdict.reasons)


def test_clear_span_would_confirm_same_fault():
    # control for the cap test: identical symptom + fault on a CLEAN path confirms — proving
    # the cap above is the opaque span, not a weakness of the evidence.
    clear = ATTR.attribute("acme", path_with_onpath_lb(), [app_symptom()], [lb_5xx_fault()])
    assert clear.verdict.tier is VerdictTier.CONFIRMED and not clear.capped


# ── 5. PER-TENANT ISOLATION (§3a) ─────────────────────────────────────────────


def test_cross_tenant_fault_never_attributes():
    # an on-path-NAMED fault that belongs to ANOTHER tenant is dropped before reasoning —
    # it can never confirm acme's symptom.
    evil_fault = lb_5xx_fault(tenant="evil")
    a = ATTR.attribute("acme", path_with_onpath_lb(), [app_symptom("acme")], [evil_fault])
    assert a.attributed is None
    assert a.verdict.tier is VerdictTier.SUSPECTED      # no lift from another tenant's signal
    assert a.discounted == ()                            # evil fault dropped, not even scored


def test_cross_tenant_path_is_not_used():
    # the caller is acme but the path belongs to evil → the path seeds NO on-path set.
    evil_path = path_with_onpath_lb(tenant="evil")
    a = ATTR.attribute("acme", evil_path, [app_symptom("acme")], [lb_5xx_fault("acme")])
    assert a.attributed is None
    assert a.on_path_device_count == 0


def test_cross_tenant_symptom_is_dropped():
    # a symptom belonging to evil cannot drive an attribution for acme.
    a = ATTR.attribute("acme", path_with_onpath_lb(), [app_symptom("evil")], [lb_5xx_fault()])
    assert a.attributed is None
    assert a.verdict.tier is VerdictTier.UNDETERMINED


def test_attribute_requires_tenant():
    with pytest.raises(ValueError):
        ATTR.attribute("", path_with_onpath_lb(), [app_symptom()], [lb_5xx_fault()])


# ── no on-path fault → honest baseline, no attribution ────────────────────────


def test_no_fault_yields_baseline_no_attribution():
    a = ATTR.attribute("acme", path_with_onpath_lb(), [app_symptom()], [])
    assert a.attributed is None
    assert a.verdict.tier is a.baseline.tier is VerdictTier.SUSPECTED
    assert not a.confidence_lifted


def test_no_on_path_devices_yields_no_attribution():
    # a fully-unknown path (no discovery evidence) has no on-path device set → no dependency
    # edge → no attribution (principle 5), regardless of a loud fault.
    empty = ASSEMBLER.assemble("acme", LAN_CLIENT, AWS_HOST, DiscoverySources())
    a = ATTR.attribute("acme", empty, [app_symptom()], [lb_5xx_fault()])
    assert a.attributed is None
    assert a.on_path_device_count == 0
    assert any("off-path" in d.reason or "no on-path" in d.reason for d in a.discounted)


# ── config: the time-correlation window is honoured ───────────────────────────


def test_time_window_config_admits_a_wider_correlation():
    wide = OnPathAttributor(AttributionConfig(window_s=7200.0))
    stale = lb_5xx_fault(ts=T0 - timedelta(hours=1))
    a = wide.attribute("acme", path_with_onpath_lb(), [app_symptom()], [stale])
    assert a.attributed is not None                    # within the widened window now


# ── determinism (replay contract) ─────────────────────────────────────────────


def test_attribution_is_deterministic():
    p = path_with_dns_head_and_lb()
    args = ("acme", p, [app_symptom()], [lb_5xx_fault(), dns_nxdomain_fault()])
    a = ATTR.attribute(*args).to_dict()
    b = ATTR.attribute(*args).to_dict()
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)
