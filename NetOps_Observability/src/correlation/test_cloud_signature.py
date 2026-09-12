# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""#81 — RCA signature for hybrid private-connectivity outage (Direct Connect / IPSec).

Proves the engine LABELS a DX/IPSec-tunnel-down incident as
`sig.ent.cloud.private-connectivity-down` (matching the real cloud signal kinds)
instead of the look-alike `sig.ent.middle-mile.dia-egress-latency` it fell back to
before — and that a genuine egress-latency incident (no cloud change) is UNCHANGED.
"""
from __future__ import annotations

from datetime import datetime, timezone

from catalog import builtin_catalog
from cloud_producers import cloud_signal
from scoring import rank
from signals import (
    EntityType,
    ModalityClass,
    Observer,
    ObserverType,
    Severity,
    Signal,
    Source,
)

TS = datetime(2026, 6, 26, 12, 0, 0, tzinfo=timezone.utc)


def _probe_loss(target: str, prober: str = "corp-hq-agent") -> Signal:
    return Signal(
        tenant_id="acme", ts=TS, source=Source.PROBE, kind="probe_loss",
        observer=Observer(observer_id=prober, observer_type=ObserverType.VANTAGE_AGENT),
        modality_class=ModalityClass.ACTIVE_PROBE, entity_type=EntityType.PATH,
        entity_id=f"{prober}->{target}", severity=Severity.CRIT,
        native_id=f"pl|{target}", deviation=5.0,
    )


def test_dx_down_labels_private_connectivity():
    sigs = [
        cloud_signal("acme", TS, "cloud_change", app="Workday", resource_id="dxcon-1",
                     account="a", region="r", severity=Severity.CRIT),
        cloud_signal("acme", TS, "cloud_flow_log", app="Workday", account="a",
                     region="r", severity=Severity.HIGH),
        cloud_signal("acme", TS, "cloud_health", app="Workday", account="a",
                     region="r", severity=Severity.CRIT),
        _probe_loss("Workday"),
    ]
    r = rank(builtin_catalog(), tuple(sigs))
    assert r.top_hypothesis == "sig.ent.cloud.private-connectivity-down", r.top_hypothesis


def test_pure_egress_latency_unchanged():
    # probe_loss only, NO cloud_change → the discriminator stays inactive and the
    # ISP egress-latency signature still wins (regression guard for real incidents).
    r = rank(builtin_catalog(), (_probe_loss("saas-app"),))
    assert r.top_hypothesis == "sig.ent.middle-mile.dia-egress-latency", r.top_hypothesis


def test_cloud_change_alone_does_not_overclaim():
    # a lone cloud change (no impact, no probe) must NOT confidently win — coverage
    # is partial; the engine should not assert a connectivity outage from one signal.
    r = rank(builtin_catalog(), (
        cloud_signal("acme", TS, "cloud_change", app="Workday", resource_id="dxcon-1",
                     account="a", region="r", severity=Severity.WARN),
    ))
    assert r.top_hypothesis != "sig.ent.cloud.private-connectivity-down" or \
        r.verdict_tier.value != "confirmed", (r.top_hypothesis, r.verdict_tier)
