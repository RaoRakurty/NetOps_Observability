# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Golden-wire tests (#98 Phase 3) — raw collector-shaped events through the
real pipeline. See golden_wire.py for the honesty contract; the tests here
assert what production ACTUALLY does today, including the gaps (interface-only
flow grounding), never what we wish it did."""

import pytest

from golden_wire import (
    GOLDEN_DIR,
    T0,
    load_fixture,
    normalize_probe_event,
    replay_fixture_through_engine,
)
from signals import EntityType, ModalityClass
from synthetic_normalize import SEMANTIC_KINDS
from verdicts import VerdictTier

SIG_ID = "sig.ent.app.saas-experience-degraded"


def semantic(signals):
    return [s for s in signals if s.kind in SEMANTIC_KINDS]


# ── A: probe-only application impact is NOT confirmed ────────────────────────
def test_golden_synthetic_http_503_teams_probe_only_not_confirmed():
    signals, snaps, _ = replay_fixture_through_engine("synthetic_http_503_teams.json")
    fx = load_fixture("synthetic_http_503_teams.json")["expect"]

    sem = semantic(signals)
    assert len(sem) == 1, "one raw check → exactly ONE semantic signal (no dual emission)"
    sig = sem[0]
    assert sig.kind == fx["semantic_kind"]
    assert sig.attrs["raw_kind"] == fx["raw_kind"]
    assert sig.attrs["reason"] == fx["reason"]
    assert sig.attrs["signal_class"] == "active_probe"
    assert sig.attrs["synthetic_source"] == "synthetic"
    assert sig.modality_class is ModalityClass.ACTIVE_PROBE
    assert sig.entity_id == fx["app"]
    assert sig.attrs["status_code"] == 503
    assert "site:frisco" in sig.entity_tokens

    # the generic probe lane coexists (backward compatibility)
    assert any(s.kind == "probe_loss" for s in signals)

    # the app-impact signature sees it — and the verdict is NOT confirmed
    app_snap = next(s for s in snaps if s.ranking.top_hypothesis == SIG_ID)
    assert app_snap.ranking.verdict_tier is not VerdictTier.CONFIRMED
    assert app_snap.ranking.verdict_tier in (VerdictTier.SUSPECTED, VerdictTier.UNDETERMINED)


def test_golden_multiple_semantic_kinds_from_one_check_cannot_conspire():
    # Even replaying the SAME raw check twice (two semantic signals, same
    # vantage, same modality) must not fabricate independence.
    fx = load_fixture("synthetic_http_503_teams.json")
    sigs = normalize_probe_event(fx["events"][0]["event"], "acme", T0)
    sigs += normalize_probe_event(fx["events"][0]["event"], "acme", T0)
    from catalog import builtin_catalog
    from scoring import rank
    r = rank(builtin_catalog(), semantic(sigs))
    assert r.verdict_tier is not VerdictTier.CONFIRMED


# ── B: synthetic + UNATTRIBUTED raw-wire flow stays interface-grounded ────────
# (the attributed/confirming variant is test_flow_app_attribution.py test D)
def test_golden_synthetic_teams_plus_interface_flow_documents_attribution_gap():
    signals, snaps, _ranking = replay_fixture_through_engine("passive_flow_drop_teams.json")
    fx = load_fixture("passive_flow_drop_teams.json")["expect"]

    flow = next(s for s in signals if s.kind == "flow_volume_anomaly")
    # REAL parsing boundary: goflow2 record fields → sampler/interface entity.
    assert flow.entity_type is EntityType.INTERFACE
    assert flow.entity_id == fx["flow_entity_id"]
    assert flow.attrs["detection_assumed"] is True
    # today: NO app token — this is the Phase 4 gap, asserted, not hidden.
    assert any(t.startswith("app:") for t in flow.entity_tokens) != (not fx["flow_has_app_token"])
    assert "microsoft_teams" not in flow.entity_tokens

    # therefore the synthetic and flow evidence do NOT co-ground on one app
    # object, and the app verdict stays unconfirmed.
    app_snap = next(s for s in snaps if s.ranking.top_hypothesis == SIG_ID)
    flow_in_app_object = any(s.kind == "flow_volume_anomaly" for s in app_snap.signals) \
        if hasattr(app_snap, "signals") else False
    assert not flow_in_app_object or app_snap.ranking.verdict_tier is not VerdictTier.CONFIRMED
    assert app_snap.ranking.verdict_tier is not VerdictTier.CONFIRMED


# ── C: generic non-Teams apps (SaaS map, customer map, internal app) ──────────
@pytest.mark.parametrize("fixture", [
    "synthetic_dns_fail_salesforce.json",
    "synthetic_tls_fail_servicenow.json",
    "synthetic_timeout_internal_app.json",
])
def test_golden_synthetic_failure_generic_app_not_teams_specific(fixture, monkeypatch):
    signals, snaps, _ = replay_fixture_through_engine(fixture, monkeypatch)
    fx = load_fixture(fixture)["expect"]
    sig = semantic(signals)[0]
    assert sig.kind == fx["semantic_kind"]
    assert sig.attrs["reason"] == fx["reason"]
    assert sig.entity_id == fx["app"]
    app_snap = next(s for s in snaps if s.ranking.top_hypothesis == SIG_ID)
    assert app_snap.ranking.verdict_tier is not VerdictTier.CONFIRMED


# ── D: failure-reason classification across the wire vocabulary ───────────────
@pytest.mark.parametrize("event,kind,reason", [
    ({"kind": "http", "ok": False, "fail_class": "dns"}, "synthetic_dns_fail", "dns_failure"),
    ({"kind": "http", "ok": False, "fail_class": "connect_timeout"}, "synthetic_timeout", "http_timeout"),
    ({"kind": "http", "ok": False, "fail_class": "connect_refused"}, "synthetic_tcp_connect_fail", "tcp_connect_refused"),
    ({"kind": "http", "ok": False, "fail_class": "tls"}, "synthetic_tls_fail", "tls_handshake_failure"),
    ({"kind": "http", "ok": False, "status_code": 503}, "synthetic_http_5xx", "http_5xx"),
    ({"kind": "http", "ok": False, "status_code": 404}, "synthetic_http_4xx", "http_4xx"),
    ({"kind": "http", "ok": True, "cert_days_to_expiry": -2.0}, "synthetic_cert_expired", "certificate_expired"),
    ({"kind": "http", "ok": True, "cert_days_to_expiry": 7.0}, "synthetic_cert_expiring", "certificate_expiring"),
    ({"kind": "icmp", "ok": False, "loss_pct": 100}, "synthetic_icmp_loss", "icmp_unreachable"),
    ({"kind": "tcp", "ok": False, "fail_class": "connect_timeout"}, "synthetic_tcp_connect_fail", "tcp_connect_timeout"),
])
def test_golden_synthetic_failure_reason_codes(event, kind, reason):
    ev = {"prober": "syn-1", "target": "https://app.example.com",
          "ts": "2026-07-09T09:00:00Z", **event}
    sem = semantic(normalize_probe_event(ev, "acme", T0))
    assert len(sem) == 1
    assert sem[0].kind == kind
    assert sem[0].attrs["reason"] == reason
    assert sem[0].attrs["raw_kind"] == event["kind"]
    assert sem[0].attrs["signal_class"] == "active_probe"


# ── E: dedup — the design is SINGLE emission, provable at the raw boundary ────
def test_golden_one_raw_event_never_emits_two_semantic_signals():
    for f in sorted(GOLDEN_DIR.glob("synthetic_*.json")):
        fx = load_fixture(f.name)
        for k, v in fx.get("env", {}).items():
            import os
            os.environ[k] = v
        try:
            for item in fx["events"]:
                if item["lane"] != "probe":
                    continue
                sem = semantic(normalize_probe_event(item["event"], "t", T0))
                assert len(sem) <= 1, f"{f.name}: dual emission would double-count"
                if sem:
                    # fingerprint present for downstream dedup
                    assert sem[0].native_id
        finally:
            for k in fx.get("env", {}):
                import os
                os.environ.pop(k, None)
