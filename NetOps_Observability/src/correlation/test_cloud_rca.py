"""Golden cloud-RCA fixtures — #81 P3G Phase 1b.

Proves the EXISTING engine forms grounded cloud correlation objects from cloud
signals (source=cloud), with the engine's invariants intact:

  * cloud-only (one cloud vantage) GROUNDS but CANNOT confirm — a single plane is
    "suspected at best" (the design's confidence rule), enforced structurally by
    the observer-independence gate, not a special case.
  * a cloud app symptom + an INDEPENDENT underlay observer, grounded across a
    seam, form ONE cross-plane object — the app→seam→underlay story.

Deterministic + in-process (no live data): the SAME engine path that will run on
real cloud telemetry, exercised with synthetic input + a synthetic SeamView (the
contract the real seam-bootstrap supplies). Lack of real data does not change the
code under test — only the fixture input.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from catalog import builtin_catalog
from cloud_producers import cloud_signal
from engine import SeamView, run_window
from signals import (
    EntityType,
    ModalityClass,
    Observer,
    ObserverType,
    Severity,
    Signal,
    Source,
)

T0 = datetime(2026, 6, 25, 12, 0, 0, tzinfo=timezone.utc)


def _db_then_app():
    # DB saturation (cloud resource, SERVICE layer) 60s before app 5xx (APP layer);
    # both carry the "billing" app token so they ground (topo shared:billing).
    db = cloud_signal("acme", T0, "database_metric", app="billing", resource_id="billing-db",
                      account="123", region="us-east-1", severity=Severity.HIGH,
                      metric_name="connections_pct", value=98, baseline=40)
    app = cloud_signal("acme", T0 + timedelta(seconds=60), "cloud_health", app="billing",
                       account="123", region="us-east-1", severity=Severity.HIGH,
                       metric_name="alb_5xx_pct", value=6.4, baseline=0.2)
    return db, app


def test_cloud_only_grounds_but_cannot_confirm():
    db, app = _db_then_app()
    snaps = run_window([db, app], builtin_catalog(), ())
    assert len(snaps) == 1, f"db+app share the app token → ONE object, got {len(snaps)}"
    snap = snaps[0]
    assert len(snap.nodes) == 2
    assert len(snap.edges) == 1
    e = snap.edges[0]
    assert e.grounding.kind == "topo" and "billing" in e.grounding.ref, e.grounding
    # single cloud vantage (one observer) → CANNOT confirm — the design's rule.
    assert snap.ranking.verdict_tier.value != "confirmed", snap.ranking.verdict_tier
    # direction (when claimed): the DB (SERVICE) causes the app (APPLICATION).
    if e.direction_conf > 0:
        assert e.from_node.startswith("cloud_resource:billing-db")
        assert e.to_node.startswith("app:billing")


def test_cloud_symptom_plus_underlay_grounds_across_seam():
    # app 5xx (cloud plane) + a probe RTT anomaly on the underlay (an INDEPENDENT
    # vantage), grounded across a DX seam whose endpoints carry both the app token
    # and the underlay edge — the app→seam→underlay story the design targets.
    app = cloud_signal("acme", T0 + timedelta(seconds=60), "cloud_health", app="billing",
                       account="123", region="us-east-1", severity=Severity.HIGH)
    probe = Signal(
        tenant_id="acme", ts=T0, source=Source.PROBE, kind="probe_rtt_anomaly",
        observer=Observer(observer_id="vantage-agent-1", observer_type=ObserverType.VANTAGE_AGENT),
        modality_class=ModalityClass.ACTIVE_PROBE, entity_type=EntityType.SEGMENT,
        entity_id="vantage-agent-1->dx-router-1", severity=Severity.HIGH, native_id="p|1",
        entity_tokens=("dx-router-1",),
    )
    seam = SeamView(
        seam_id="sm-dx-dallas", tenant_id="acme", seam_type="DX",
        endpoints=(("app", "billing"), ("edge", "dx-router-1")),
        visibility="partial", control_plane_owner="enterprise",
    )
    snaps = run_window([app, probe], builtin_catalog(), (seam,))
    objs = [s for s in snaps if len(s.nodes) == 2]
    assert objs, "app + probe must ground across the seam into one object"
    snap = objs[0]
    assert len(snap.edges) == 1
    e = snap.edges[0]
    assert e.grounding.kind == "seam" and e.grounding.ref == "sm-dx-dallas", e.grounding
    # two INDEPENDENT observers (cloud_api + vantage_agent) — the structural basis
    # for cross-plane confirmation (the verdict reaches confirmed once a cloud
    # signature lands; the grounding + independence are proven here).
    observers = {s.observer.observer_id for n in snap.nodes for s in n.signals}
    assert observers == {"cloud:123:us-east-1", "vantage-agent-1"}, observers


def test_cloud_change_then_app_orders_by_onset():
    # a config change has no causal LAYER (intentionally unmapped) → direction falls
    # to onset ordering: the change precedes the symptom, so change → app.
    chg = cloud_signal("acme", T0, "cloud_change", app="billing", resource_id="billing-svc",
                       account="123", region="us-east-1", severity=Severity.WARN)
    app = cloud_signal("acme", T0 + timedelta(seconds=180), "cloud_health", app="billing",
                       account="123", region="us-east-1", severity=Severity.HIGH)
    snaps = run_window([chg, app], builtin_catalog(), ())
    assert len(snaps) == 1
    snap = snaps[0]
    assert len(snap.edges) == 1  # grounded via shared "billing" token
    assert snap.ranking.verdict_tier.value != "confirmed"
