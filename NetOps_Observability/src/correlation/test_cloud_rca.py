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
from engine import (
    SeamView,
    TopologyAdjacency,
    build_nodes,
    resolve_grounding,
    run_window,
)
from path_graph import EdgeType, ResolutionMethod
from signals import (
    EntityType,
    ModalityClass,
    Observer,
    ObserverType,
    Severity,
    Signal,
    Source,
)
from test_path_graph import lab_path_view
from test_path_graph import lab_signals as _lab_signals

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


def test_cloud_object_persists_blast_radius():
    # REGRESSION (caught live): the engine cycle persists via to_object_row()→
    # affected(), which buckets nodes by entity_type. APP/CLOUD_RESOURCE were
    # unmapped → KeyError crashed the WHOLE cycle (blocking every tenant's RCA).
    # run_window alone never exercised persistence, so the golden tests missed it.
    db, app = _db_then_app()
    snap = run_window([db, app], builtin_catalog(), ())[0]
    aff = snap.affected()
    assert "billing" in aff.get("apps", [])
    assert "billing-db" in aff.get("cloud_resources", [])
    # the actual prod call site must build the row without raising.
    row = snap.to_object_row(1, "open", "")
    assert row["correlation_id"] and "affected" in row


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


# ── the crux: cloud app ↔ on-prem network, with NO shared token ───────────────
# Service Path Graph contract §10. The OLD gate could never form this edge: the app
# node's tokens are application NAMES, the network node's are device names — they do
# not intersect, so cloud RCA was a 2-node silo. The NEW gate resolves the app to its
# endpoint (rank 4, the app's own deployment binding), the endpoint to a path hop
# (rank 2/3, cloud NIC inventory), and the on-prem interface to another hop of the
# SAME observed path — an explicit, time-bounded, tenant-scoped relationship chain.


def test_cloud_app_and_onprem_network_ground_with_no_shared_token():
    app, wan = _lab_signals()
    nodes = build_nodes((app, wan))
    a = next(n for n in nodes if n.entity_type is EntityType.APP)
    w = next(n for n in nodes if n.entity_type is EntityType.INTERFACE)

    # (1) THE PREMISE: not one token in common — the old gate is structurally unable
    #     to relate these two, with or without seams.
    assert not (a.tokens() & w.tokens()), a.tokens() & w.tokens()
    assert resolve_grounding(a, w, (), TopologyAdjacency()) is None

    # (2) With the explicit path objects, they ground into ONE object…
    snaps = run_window([app, wan], builtin_catalog(), (), paths=lab_path_view())
    objs = [s for s in snaps if len(s.nodes) == 2]
    assert objs, f"app + wan-edge must ground into ONE object, got {[len(s.nodes) for s in snaps]}"
    snap = objs[0]
    assert len(snap.edges) == 1
    e = snap.edges[0]
    rel = e.grounding.relation

    # (3) …via an EXPLICIT TYPED edge that states its evidence (§5).
    assert rel is not None
    assert rel.edge_type == EdgeType.CROSSES_SEAM.value, rel.edge_type
    assert rel.method == ResolutionMethod.APP_ENDPOINT_BINDING.value  # rank 4, observed
    assert rel.rank == 4 and rel.evidence_class == "observed"
    assert rel.authoritative and e.grounding.authoritative
    assert rel.evidence_ref and rel.observation_method == "traceroute_icmp"
    assert rel.observed_at and rel.data_class == "live"
    assert rel.seam_id == "sm-aws-dx"
    # the relationship did NOT come from a token: no token is shared, and the
    # relation's evidence is a path observation, not a name.
    assert rel.ref == "obs-a-1" and not rel.evidence_ref.startswith("token:")

    # (4) the unknown hop is PRESERVED, never bridged (§8).
    assert rel.unknown_hops == (5,)
    assert any("hop 5" in m for m in snap.ranking.evidence_missing), snap.ranking.evidence_missing

    # (5) the object is no longer a single-plane silo: two planes, two observers.
    assert {n.entity_type for n in snap.nodes} == {EntityType.APP, EntityType.INTERFACE}
    observers = {s.observer.observer_id for n in snap.nodes for s in n.signals}
    assert observers == {"cloud:123:us-east-1", "snmp-poller"}


def test_cloud_rca_renders_the_ordered_spine():
    """§7/§10: the backend hands the renderer an ORDERED spine — the UI never
    computes hop order. The acceptance spine, in order, with the unknown hop kept."""
    app, wan = _lab_signals()
    snap = [s for s in run_window([app, wan], builtin_catalog(), (), paths=lab_path_view())
            if len(s.nodes) == 2][0]
    spine = snap.path_spine()
    assert [e["address"] for e in spine["spine"]] == [
        "172.40.40.92", "172.40.40.1", "10.70.245.122", "10.60.1.10", "",
        "10.60.10.10", ""]
    assert [e["label"] for e in spine["spine"]][-1] == "store-api"
    assert [e["state"] for e in spine["spine"]][4] == "missing"       # preserved
    assert spine["spine"][-1]["kind"] == "service"
    assert [b["name"] for b in spine["boundaries"]] == ["LAN", "SD-WAN", "CLOUD",
                                                        "UNKNOWN", "CLOUD"]
    assert any(e["type"] == "EVIDENCE_MISSING" for e in spine["edges"])
    assert all(e["evidence"]["ref"] for e in spine["edges"])          # §5
    assert spine["edges"][-1]["type"] == "SERVICE_EXPOSED_BY_ENDPOINT"


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
