"""#98 Phase 4 — bounded per-application passive-flow attribution.

The contract under test: a flow anomaly gains app grounding ONLY when a real
attribution source names the application (explicit metadata → appid fusion →
operator prefix map), infrastructure grounding is never removed, and the
protections hold — no cross-app merge, no cross-tenant attribution, no stale
(time-expired) identity, and interface-only flow never confirms app impact.
"""
from datetime import datetime, timedelta, timezone

from catalog import builtin_catalog
from flow_app_attribution import (
    AppIdentityIndex,
    Attribution,
    normalize_app,
    resolve_flow_app,
)
from golden_wire import T0, load_fixture, normalize_flow_records, replay_fixture_through_engine
from scoring import rank
from signals import EntityType, ModalityClass
from synthetic_normalize import synthetic_app_signal
from verdicts import VerdictTier

CAT = builtin_catalog()
SIG_ID = "sig.ent.app.saas-experience-degraded"
NOW = datetime(2026, 7, 9, 9, 0, 0, tzinfo=timezone.utc)

TEAMS_FLOW = {"sampler_address": "10.40.17.1", "in_if": "3", "bytes": 42000,
              "sampling_rate": 50, "dst_addr": "52.113.194.132"}


def teams_synthetic():
    return synthetic_app_signal(
        {"kind": "http", "ok": False, "fail_class": "tls", "prober": "syn-frisco",
         "target": "https://teams.microsoft.com", "site_id": "frisco",
         "ts": NOW.isoformat()}, "acme", NOW)


def app_flow_signals(records, identities=None, tenant="acme"):
    sigs = normalize_flow_records(records, tenant, NOW, {"deviation": 4.0}, identities)
    return ([s for s in sigs if s.entity_type is EntityType.INTERFACE],
            [s for s in sigs if s.entity_type is EntityType.APP])


# ── A: explicit app metadata on the record ────────────────────────────────────
def test_flow_anomaly_with_explicit_app_metadata_gets_app_grounding():
    rec = {**TEAMS_FLOW, "app_name": "Microsoft Teams"}
    infra, app = app_flow_signals([rec])
    assert len(infra) == 1 and len(app) == 1          # BOTH groundings, one flow
    assert infra[0].entity_id == "10.40.17.1:if3"     # infra grounding preserved
    a = app[0]
    assert a.entity_id == "microsoft_teams" and a.entity_type is EntityType.APP
    assert "app:microsoft_teams" in a.entity_tokens
    assert a.attrs["attribution_source"] == "explicit_config"
    assert a.attrs["attribution_confidence"] == "high"
    assert a.modality_class is ModalityClass.PASSIVE_FLOW
    assert a.kind == "flow_volume_anomaly"            # canonical kind, no new vocabulary


# ── B: appid-fusion join by destination IP ────────────────────────────────────
def test_flow_anomaly_appid_fusion_attaches_app_token():
    identities = [{"tenant_id": "acme", "app": "Microsoft Teams",
                   "band": "authoritative", "dst_ip": "52.113.194.132",
                   "ts": NOW.isoformat()}]
    _, app = app_flow_signals([TEAMS_FLOW], identities)
    assert len(app) == 1
    assert app[0].entity_id == "microsoft_teams"
    assert app[0].attrs["attribution_source"] == "appid_fusion"
    assert app[0].attrs["attribution_confidence"] == "high"


def test_prefix_mapping_is_operator_defined(monkeypatch):
    monkeypatch.setenv("CORR_APP_PREFIX_MAP", "52.113.0.0/16=Microsoft Teams")
    att = resolve_flow_app(TEAMS_FLOW, "acme", AppIdentityIndex(), NOW)
    assert att == Attribution(app="microsoft_teams", source="prefix_mapping",
                              confidence="medium")
    assert att.confirming


# ── C: unknown app — honest infrastructure-only fallback ─────────────────────
def test_flow_anomaly_without_app_identity_remains_infrastructure_grounded():
    infra, app = app_flow_signals([TEAMS_FLOW])       # no metadata, no identity, no map
    assert len(infra) == 1 and app == []              # no fake app token, ever
    assert not any(t.startswith("app:") for t in infra[0].entity_tokens)


def test_low_confidence_fusion_band_never_creates_app_grounding():
    identities = [{"tenant_id": "acme", "app": "Microsoft Teams",
                   "band": "heuristic", "dst_ip": "52.113.194.132",
                   "ts": NOW.isoformat()}]
    att = resolve_flow_app(TEAMS_FLOW, "acme", _index(identities), NOW)
    assert att is not None and att.confidence == "low" and not att.confirming
    _, app = app_flow_signals([TEAMS_FLOW], identities)
    assert app == []                                   # low confidence must not confirm


# ── D: synthetic + app-grounded flow ⇒ CONFIRMED, one object ─────────────────
def test_synthetic_failure_plus_app_grounded_flow_confirms_app_impact():
    signals, snaps, _ = replay_fixture_through_engine("passive_flow_drop_teams_appid.json")
    fx = load_fixture("passive_flow_drop_teams_appid.json")["expect"]
    app_flow = next(s for s in signals
                    if s.kind == "flow_volume_anomaly" and s.entity_type is EntityType.APP)
    assert app_flow.entity_id == fx["app_flow_entity_id"]
    assert app_flow.attrs["attribution_source"] == fx["attribution_source"]
    app_snap = next(s for s in snaps if s.ranking.top_hypothesis == SIG_ID)
    assert app_snap.ranking.verdict_tier is VerdictTier.CONFIRMED
    assert "microsoft_teams" in app_snap.affected().get("apps", [])


# ── E: synthetic + interface-only flow does NOT confirm ───────────────────────
# NOTE: rank() scores a PRE-GROUPED evidence set (the fixture-harness entry);
# entity grounding — which is what protects against ungrounded confirmation —
# happens in run_window. These protections are therefore asserted through the
# real object-forming path.
def test_synthetic_failure_plus_interface_only_flow_does_not_confirm_app_impact():
    from engine import run_window
    infra, _ = app_flow_signals([TEAMS_FLOW])
    snaps = run_window((teams_synthetic(), *infra), CAT, ())
    app_snap = next(s for s in snaps if s.ranking.top_hypothesis == SIG_ID)
    # the interface anomaly shares no token with the app object → not attached,
    # single active_probe modality → never confirmed
    assert app_snap.ranking.verdict_tier is not VerdictTier.CONFIRMED


# ── F: cross-app protection ───────────────────────────────────────────────────
def test_cross_app_flow_does_not_confirm_wrong_application():
    from engine import run_window
    rec = {**TEAMS_FLOW, "app_name": "Salesforce"}    # flow says Salesforce
    _, app = app_flow_signals([rec])
    snaps = run_window((teams_synthetic(), *app), CAT, ())   # synthetic says Teams
    for snap in snaps:
        if snap.ranking.top_hypothesis != SIG_ID:
            continue
        affected = snap.affected().get("apps", [])
        if "microsoft_teams" in affected:
            # the Teams object must not be confirmed by Salesforce flow evidence
            assert snap.ranking.verdict_tier is not VerdictTier.CONFIRMED
            assert "salesforce" not in affected


# ── G: cross-tenant protection ────────────────────────────────────────────────
def test_flow_attribution_does_not_cross_tenants():
    identities = [{"tenant_id": "tenant-b", "app": "Microsoft Teams",
                   "band": "authoritative", "dst_ip": "52.113.194.132",
                   "ts": NOW.isoformat()}]
    # tenant A's flow must not join tenant B's identity
    att = resolve_flow_app(TEAMS_FLOW, "tenant-a", _index(identities), NOW)
    assert att is None
    _, app = app_flow_signals([TEAMS_FLOW], identities, tenant="tenant-a")
    assert app == []


# ── H: time-window protection (stale identity never attributes) ──────────────
def test_flow_attribution_requires_time_window_overlap():
    idx = AppIdentityIndex(ttl_s=3600)
    idx.observe("acme", "52.113.194.132", "Microsoft Teams", "authoritative",
                NOW - timedelta(hours=5))
    assert resolve_flow_app(TEAMS_FLOW, "acme", idx, NOW) is None


# ── index bounds / hygiene ────────────────────────────────────────────────────
def test_identity_index_is_bounded():
    idx = AppIdentityIndex(max_per_tenant=3)
    for i in range(10):
        idx.observe("acme", f"10.0.0.{i}", "app_x", "authoritative",
                    NOW + timedelta(seconds=i))
    assert len(idx._by_tenant["acme"]) == 3
    assert idx.lookup("acme", "10.0.0.9", NOW + timedelta(seconds=10)) is not None
    assert idx.lookup("acme", "10.0.0.0", NOW + timedelta(seconds=10)) is None  # evicted


def test_normalize_app_never_invents():
    assert normalize_app("Microsoft Teams") == "microsoft_teams"
    assert normalize_app("  ") == ""


def _index(identities):
    idx = AppIdentityIndex()
    for i in identities:
        idx.observe(i["tenant_id"], i["dst_ip"], i["app"], i["band"], NOW)
    return idx
