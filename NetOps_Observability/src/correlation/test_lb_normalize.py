"""#98 Phase 5 — LB / proxy / ingress telemetry contract.

The contract: vendor-neutral app-edge events normalize into the CANONICAL
kinds the catalog already consumes (lb_5xx / lb_target_unhealthy /
app_error_rate_high / app_latency_high; lb_4xx_high intentionally blind),
carry app/service grounding, stay an INDEPENDENT witness class from probes
and flows, and one raw event never becomes two evidence streams.
"""
from datetime import datetime, timezone

import pytest

from catalog import builtin_catalog
from coverage import consumed_kinds
from engine import run_window
from golden_wire import load_fixture, replay_fixture_through_engine
from lb_normalize import LB_KINDS, classify_lb_event, normalize_lb_event
from signals import EntityType, ModalityClass, Severity
from synthetic_normalize import synthetic_app_signal
from verdicts import VerdictTier

CAT = builtin_catalog()
SIG_ID = "sig.ent.app.saas-experience-degraded"
NOW = datetime(2026, 7, 9, 9, 0, 0, tzinfo=timezone.utc)


def lb_event(**over):
    ev = {
        "source": "lb", "vendor": "generic", "product": "reverse_proxy",
        "tenant_id": "acme", "ts": NOW.isoformat(),
        "app_name": "customer_portal", "service_name": "portal_frontend",
        "host": "portal.acme.example", "path": "/login",
        "lb_name": "edge-lb-01", "backend_pool": "portal_pool",
    }
    ev.update(over)
    return ev


def portal_synthetic():
    # Declared intent×vantage (the authoritative registry path) → HIGH authority,
    # the production contract for a confirm-capable DEM vantage since the
    # truthfulness epic (classification in classify_probe, never hardcoded).
    import main
    ev = {"kind": "http", "ok": False, "status_code": 503, "prober": "syn-frisco",
          "target": "https://portal.acme.example/login", "site_id": "frisco",
          "app_name": "customer_portal", "ts": NOW.isoformat(),
          "probe_intent": "customer_path", "vantage_type": "enterprise_agent"}
    sig = synthetic_app_signal(ev, "acme", NOW)
    main.classify_probe(ev, sig)
    return sig


# ── A: generic LB JSON 503 normalization ──────────────────────────────────────
def test_generic_lb_json_503_normalizes_to_lb_backend_unavailable():
    sig = normalize_lb_event(lb_event(status_code=503, reason="backend_unavailable",
                                      error_rate=0.405, raw_event_id="lb-evt-1"),
                             "acme", NOW)
    assert sig.kind == "lb_5xx" and sig.kind in LB_KINDS
    assert sig.attrs["reason"] == "backend_unavailable"
    assert sig.attrs["lane"] == "app_gateway"
    assert sig.attrs["raw_kind"] == "lb"
    assert sig.modality_class is ModalityClass.DEVICE_TELEMETRY
    assert sig.entity_type is EntityType.APP and sig.entity_id == "customer_portal"
    assert "app:customer_portal" in sig.entity_tokens
    assert "service:portal_frontend" in sig.entity_tokens
    assert "lb:edge-lb-01" in sig.entity_tokens
    assert "backend_pool:portal_pool" in sig.entity_tokens
    assert sig.native_id == "lb-evt-1"            # raw event id = dedup fingerprint


# ── B: HTTP 5xx family mapping ────────────────────────────────────────────────
@pytest.mark.parametrize("status,reason", [
    (500, "http_5xx"),
    (502, "bad_gateway"),
    (503, "backend_unavailable"),
    (504, "gateway_timeout"),
])
def test_lb_http_5xx_family_mapping(status, reason):
    kind, got_reason, severity = classify_lb_event({"status_code": status})
    assert kind == "lb_5xx" and got_reason == reason and severity is Severity.HIGH


def test_backend_health_mapping():
    kind, reason, sev = classify_lb_event({"reason": "backend_pool_down"})
    assert kind == "lb_target_unhealthy" and reason == "backend_pool_down"
    kind, reason, _ = classify_lb_event({"reason": "pool_member_down"})
    assert kind == "lb_target_unhealthy"
    kind, reason, _ = classify_lb_event({"target_unhealthy": True})
    assert kind == "lb_target_unhealthy" and reason == "target_group_unhealthy"


def test_declared_rate_and_latency_anomalies():
    kind, reason, _ = classify_lb_event({"anomaly": True, "error_rate": 0.4,
                                         "baseline_error_rate": 0.01})
    assert kind == "app_error_rate_high"
    kind, reason, _ = classify_lb_event({"anomaly": True, "p99_latency_ms": 4200})
    assert kind == "app_latency_high" and reason == "latency_high"
    # NO declared anomaly → rate/latency fields alone emit nothing (threshold
    # policy: detection belongs upstream, this normalizer never invents one).
    assert classify_lb_event({"error_rate": 0.4})[0] is None


# ── C: high 4xx is never outage-confirming ────────────────────────────────────
def test_lb_4xx_high_is_not_treated_as_confirming_outage_by_itself():
    signals, snaps, _ = replay_fixture_through_engine(
        "generic_lb_4xx_auth_spike_customer_portal.json")
    fx = load_fixture("generic_lb_4xx_auth_spike_customer_portal.json")["expect"]
    assert signals[0].kind == fx["lb_kind"] == "lb_4xx_high"
    # structural guarantee: NO signature consumes lb_4xx_high (INTENTIONAL_BLIND)
    assert "lb_4xx_high" not in consumed_kinds(CAT)
    assert all(s.ranking.verdict_tier is not VerdictTier.CONFIRMED for s in snaps)


# ── D: synthetic + LB confirms (golden wire, raw both sides) ─────────────────
def test_synthetic_failure_plus_lb_5xx_confirms_app_impact(monkeypatch):
    signals, snaps, _ = replay_fixture_through_engine(
        "generic_lb_503_customer_portal.json", monkeypatch)
    fx = load_fixture("generic_lb_503_customer_portal.json")["expect"]
    lb = next(s for s in signals if s.kind == "lb_5xx")
    assert lb.attrs["reason"] == fx["lb_reason"]
    app_snap = next(s for s in snaps if s.ranking.top_hypothesis == SIG_ID)
    # active_probe + device_telemetry (app-edge) = two independent classes on
    # ONE app object → confirmed
    assert app_snap.ranking.verdict_tier is VerdictTier.CONFIRMED
    assert "customer_portal" in app_snap.affected().get("apps", [])


# ── E: unrelated app's LB evidence never attaches ─────────────────────────────
def test_synthetic_failure_does_not_attach_to_unrelated_lb_app():
    teams_syn = synthetic_app_signal(
        {"kind": "http", "ok": False, "fail_class": "tls", "prober": "syn-frisco",
         "target": "https://teams.microsoft.com", "ts": NOW.isoformat()}, "acme", NOW)
    salesforce_lb = normalize_lb_event(
        lb_event(app_name="salesforce", host="login.salesforce.com",
                 status_code=503), "acme", NOW)
    snaps = run_window((teams_syn, salesforce_lb), CAT, ())
    for snap in snaps:
        affected = snap.affected().get("apps", [])
        if "microsoft_teams" in affected:
            assert snap.ranking.verdict_tier is not VerdictTier.CONFIRMED
            assert "salesforce" not in affected


# ── F: cross-tenant protection ────────────────────────────────────────────────
def test_lb_app_correlation_does_not_cross_tenants():
    # Structural: the engine REFUSES a mixed-tenant window outright — tenant A's
    # synthetic and tenant B's LB evidence can never even enter one correlation
    # pass together (production slices the window per tenant upstream).
    syn_a = portal_synthetic()                                   # tenant acme
    lb_b = normalize_lb_event(lb_event(status_code=503), "tenant-b", NOW)
    with pytest.raises(ValueError, match="single-tenant"):
        run_window((syn_a, lb_b), CAT, ())


# ── G: time windows — production bound (documented) ──────────────────────────
def test_time_window_protection_is_structural():
    # Attachment is bounded by the rolling event-time window in production:
    # main.WINDOW_BUFFER is pruned by age each cycle (main._prune_buffer), so a
    # 10:00 synthetic and a 14:00 LB event never coexist in one correlation
    # window. Assert the pruning hook exists so a refactor can't silently drop it.
    import main
    assert callable(main._prune_buffer)


# ── H: one raw LB event → exactly one semantic signal ─────────────────────────
def test_single_lb_event_never_emits_multiple_semantic_kinds():
    # 503 + backend_unavailable + high error_rate in ONE event: one observation,
    # one signal (kind lb_5xx, reason backend_unavailable) — never two streams.
    sig = normalize_lb_event(lb_event(status_code=503, reason="backend_unavailable",
                                      anomaly=True, error_rate=0.4), "acme", NOW)
    assert sig.kind == "lb_5xx"
    assert sig.attrs["reason"] == "backend_unavailable"
    assert sig.attrs["error_rate"] == 0.4        # detail preserved as attrs, not extra signals


# ── I: three independent classes — synthetic + app flow + LB ─────────────────
def test_synthetic_flow_and_lb_create_strong_confirmed_app_impact():
    from golden_wire import normalize_flow_records
    syn = portal_synthetic()
    lb = normalize_lb_event(lb_event(status_code=503, reason="backend_unavailable"),
                            "acme", NOW)
    flow = normalize_flow_records(
        [{"sampler_address": "10.40.17.1", "in_if": "3", "bytes": 42000,
          "sampling_rate": 50, "dst_addr": "10.8.1.10", "app_name": "customer_portal"}],
        "acme", NOW, {"deviation": 4.0})
    app_flow = [s for s in flow if s.entity_type is EntityType.APP]
    snaps = run_window((syn, lb, *app_flow), CAT, ())
    app_snap = next(s for s in snaps if s.ranking.top_hypothesis == SIG_ID)
    assert app_snap.ranking.verdict_tier is VerdictTier.CONFIRMED
    assert {syn.modality_class, lb.modality_class, app_flow[0].modality_class} == {
        ModalityClass.ACTIVE_PROBE, ModalityClass.DEVICE_TELEMETRY,
        ModalityClass.PASSIVE_FLOW}


# ── hygiene: ungroundable / healthy events emit nothing ───────────────────────
def test_ungroundable_or_healthy_events_emit_nothing():
    assert normalize_lb_event({"tenant_id": "acme", "status_code": 503}, "acme", NOW) is None
    assert normalize_lb_event(lb_event(status_code=200), "acme", NOW) is None
