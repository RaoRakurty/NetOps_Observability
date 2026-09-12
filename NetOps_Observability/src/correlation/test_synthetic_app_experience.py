# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""External SaaS / application-experience correlation — synthetic DEM lane.

Proves the "Microsoft Teams is impacted" path end-to-end, WITHOUT turning
Correlix into APM (external synthetic + flow only; no traces/spans/RUM):

  * a synthetic HTTPS failure normalizes to a SEMANTIC app-experience kind
    (synthetic_tls_fail / synthetic_http_5xx / synthetic_dns_fail / …) that the
    sig.ent.app.* templates match — with the raw probe kind preserved;
  * synthetic evidence ALONE stays `suspected` (single active_probe modality);
  * synthetic + an independent passive-flow collapse → `confirmed`, and both
    attach to ONE application-impact object naming Microsoft Teams.

The verdict-gate rule (≥2 independent modality classes) is never relaxed here —
that is the whole point of the confirm/suspect split.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from catalog import builtin_catalog
from engine import run_window
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
from synthetic_normalize import (
    SEMANTIC_KINDS,
    classify_synthetic,
    synthetic_app_signal,
)
from verdicts import VerdictTier

T0 = datetime(2026, 7, 9, 9, 0, 0, tzinfo=timezone.utc)
CAT = builtin_catalog()
SIG_ID = "sig.ent.app.saas-experience-degraded"


def teams_http_event(*, fail_class="tls", ok=False, status_code=None, prober="syn-frisco"):
    """A raw synthetic HTTPS ProbeEvent (the netops.probes wire shape) to Teams."""
    ev = {
        "kind": "http", "ok": ok, "prober": prober, "site_id": "frisco",
        "target": "https://teams.microsoft.com", "ts": T0.isoformat(),
    }
    if fail_class:
        ev["fail_class"] = fail_class
    if status_code is not None:
        ev["status_code"] = status_code
    return ev


def teams_flow(*, offset_s=30.0, observer="flow-col-1"):
    """A passive-flow volume collapse opportunistically attributed to Teams
    (shares the `microsoft_teams` token → grounds with the synthetic signal).

    TODO(per-app-flow-attribution): production flow anomalies are per-interface
    today; the app entity/token here stands in for the appid/ fusion attribution
    that the design (P2) will supply. The independence of the two witnesses (a
    flow exporter vs a synthetic vantage) is real regardless."""
    return Signal(
        tenant_id="acme", ts=T0 + timedelta(seconds=offset_s), source=Source.FLOW,
        kind="flow_volume_anomaly",
        observer=Observer(observer_id=observer, observer_type=ObserverType.FLOW_EXPORTER,
                          collection_path="direct"),
        modality_class=ModalityClass.PASSIVE_FLOW, entity_type=EntityType.SERVICE,
        entity_id="microsoft_teams", severity=Severity.HIGH,
        native_id=f"flow|microsoft_teams|{offset_s}",
        entity_tokens=("microsoft_teams", "app:microsoft_teams"),
        attrs={"onset_uncertainty_s": 5.0},
    )


# ── Task 5.1 — normalization to a semantic app-experience kind ────────────────
def test_synthetic_teams_failure_normalizes_to_app_impact():
    sig = synthetic_app_signal(teams_http_event(fail_class="tls"), "acme", T0)
    assert sig is not None
    assert sig.kind == "synthetic_tls_fail" and sig.kind in SEMANTIC_KINDS
    assert sig.attrs["raw_kind"] == "http"          # original probe kind preserved
    assert sig.attrs["reason"] == "tls_handshake_failure"
    assert sig.modality_class is ModalityClass.ACTIVE_PROBE
    assert sig.entity_type is EntityType.APP and sig.entity_id == "microsoft_teams"
    # grounding tokens let it co-locate with app identity + app-attributed flow
    assert "microsoft_teams" in sig.entity_tokens
    assert "host:teams.microsoft.com" in sig.entity_tokens

    # a range of failure classes map to distinct, specific semantic kinds
    assert classify_synthetic(teams_http_event(status_code=503, fail_class=None))[0] == "synthetic_http_5xx"
    assert classify_synthetic(teams_http_event(fail_class="dns"))[0] == "synthetic_dns_fail"
    assert classify_synthetic({"kind": "tcp", "ok": False, "fail_class": "connect_refused"})[0] == "synthetic_tcp_connect_fail"
    # a healthy check emits NO semantic signal (anti-noise)
    assert synthetic_app_signal({"kind": "http", "ok": True, "status_code": 200,
                                 "total_ms": 12, "target": "https://teams.microsoft.com"},
                                "acme", T0) is None


# ── Task 5.2 — synthetic + independent flow ⇒ CONFIRMED, one named object ──────
def test_synthetic_probe_plus_flow_confirms_app_impact(monkeypatch):
    # The DEM vantage earns confirm capability from the observer trust registry
    # (production contract since the truthfulness epic: classification happens in
    # classify_probe, never hardcoded in the normalizer).
    import main
    monkeypatch.setattr(main, "_INTERNAL_PROBE_TARGETS", set())
    monkeypatch.setattr(main, "_MEASUREMENT_PROBE_OBSERVERS", {"syn-frisco"})
    monkeypatch.setattr(main, "_TRUSTED_PROBE_OBSERVERS", {"syn-frisco"})
    ev = teams_http_event(fail_class="tls")
    syn = synthetic_app_signal(ev, "acme", T0)
    main.classify_probe(ev, syn)
    snaps = run_window((syn, teams_flow()), CAT, ())
    assert len(snaps) == 1                                   # both attach to ONE object
    snap = snaps[0]
    assert snap.ranking.top_hypothesis == SIG_ID
    assert snap.ranking.verdict_tier is VerdictTier.CONFIRMED  # 2 independent modalities
    assert "microsoft_teams" in snap.affected().get("apps", [])

    # rank() (the fixture-harness entry) agrees
    r = rank(CAT, [syn, teams_flow()])
    assert r.top_hypothesis == SIG_ID and r.verdict_tier is VerdictTier.CONFIRMED


# ── Task 5.3 — synthetic alone is never confirmed ─────────────────────────────
def test_probe_only_app_failure_not_confirmed():
    syn = synthetic_app_signal(teams_http_event(fail_class="tls"), "acme", T0)
    snaps = run_window((syn,), CAT, ())
    assert len(snaps) == 1
    snap = snaps[0]
    assert snap.ranking.top_hypothesis == SIG_ID
    # single active_probe modality → suspected, NEVER confirmed
    assert snap.ranking.verdict_tier is not VerdictTier.CONFIRMED
    assert snap.ranking.verdict_tier in (VerdictTier.SUSPECTED, VerdictTier.UNDETERMINED)
    assert "microsoft_teams" in snap.affected().get("apps", [])


def test_confirmation_needs_independent_observer_not_two_probes():
    # two synthetic vantages both failing = still ONE modality class → not confirmed.
    a = synthetic_app_signal(teams_http_event(fail_class="tls", prober="syn-frisco"), "acme", T0)
    b = synthetic_app_signal(teams_http_event(fail_class="tls", prober="syn-dallas"), "acme", T0)
    r = rank(CAT, [a, b])
    assert r.verdict_tier is not VerdictTier.CONFIRMED


# ── genericness — Teams is only a fixture; NO app-specific logic in the code ───
def test_normalizer_is_application_agnostic(monkeypatch):
    # (1) app comes from explicit synthetic-check METADATA — an internal app with
    # no host-map entry, arbitrary URL. Classification is by outcome, not by app.
    ev = {"kind": "http", "ok": False, "status_code": 503,
          "target": "https://billing.internal.acme/health", "app_name": "acme_billing",
          "app_id": "svc-1234", "prober": "syn-dc1", "site_id": "dc1", "ts": T0.isoformat()}
    sig = synthetic_app_signal(ev, "acme", T0)
    assert sig.kind == "synthetic_http_5xx"                 # outcome, not app
    assert sig.entity_id == "acme_billing" and sig.attrs["app_name"] == "acme_billing"
    assert sig.attrs["app_id"] == "svc-1234"
    assert "app:acme_billing" in sig.entity_tokens and "site:dc1" in sig.entity_tokens

    # (2) app comes from a runtime host→app map override — no code change, no Teams.
    monkeypatch.setenv("CORR_SAAS_HOST_MAP", "status.example-erp.com=example_erp")
    ev2 = {"kind": "http", "ok": False, "fail_class": "dns",
           "target": "https://status.example-erp.com", "prober": "syn-dc1", "ts": T0.isoformat()}
    sig2 = synthetic_app_signal(ev2, "acme", T0)
    assert sig2.entity_id == "example_erp" and sig2.kind == "synthetic_dns_fail"

    # (3) unknown host with no metadata/map → honest fallback to the host itself,
    # still a valid app-experience signal (never invents a friendly name).
    ev3 = {"kind": "tcp", "ok": False, "fail_class": "connect_refused",
           "target": "mystery.example.net:8443", "prober": "syn-dc1", "ts": T0.isoformat()}
    sig3 = synthetic_app_signal(ev3, "acme", T0)
    assert sig3.kind == "synthetic_tcp_connect_fail"
    assert sig3.entity_id == "mystery.example.net" and sig3.entity_type is EntityType.SERVICE


# ── RCA truthfulness epic: unified classification + execution lineage ────────

def test_app_signal_carries_no_hardcoded_trust():
    """The normalizer must NOT stamp authority/scope — that is classify_probe's
    job (Phase 0 finding A4: the hardcode let validation canaries confirm)."""
    sig = synthetic_app_signal(teams_http_event(), "t1", T0)
    assert sig is not None
    assert "probe_authority" not in sig.attrs
    assert "probe_scope" not in sig.attrs


def test_both_lanes_share_execution_id_and_classification(monkeypatch):
    """One check execution → generic probe row + semantic app row, id-linked by
    execution_id and classified through the SAME fail-closed path (§2)."""
    import main
    from episodes import EpisodeDetector
    from producers import probe_signals

    monkeypatch.setattr(main, "_INTERNAL_PROBE_TARGETS", set())
    monkeypatch.setattr(main, "_MEASUREMENT_PROBE_OBSERVERS", {"syn-frisco"})
    monkeypatch.setattr(main, "_TRUSTED_PROBE_OBSERVERS", {"syn-frisco"})

    ev = teams_http_event()
    ev["execution_id"] = "ex-lineage-1"
    ev["loss_pct"] = 100.0

    generic = probe_signals(ev, EpisodeDetector(), "t1", T0)
    app = synthetic_app_signal(ev, "t1", T0)
    assert app is not None and generic
    for sig in [*generic, app]:
        main.classify_probe(ev, sig)
        assert sig.attrs["execution_id"] == "ex-lineage-1"
        assert sig.attrs["signal_purpose"] == "production"
    # Same execution, same vantage: identical derived authority on both lanes.
    assert app.attrs["probe_authority"] == generic[0].attrs["probe_authority"]


def test_validation_canary_app_signal_cannot_confirm(monkeypatch):
    """§11 negative test: a validation-purpose canary failure classifies as
    DEBUG_ONLY on the app lane, so it can never anchor a confirmed verdict."""
    import main
    from signals import ProbeAuthority

    ev = teams_http_event()
    ev["signal_purpose"] = "validation"
    app = synthetic_app_signal(ev, "t1", T0)
    assert app is not None
    main.classify_probe(ev, app)
    assert app.attrs["probe_authority"] == ProbeAuthority.DEBUG_ONLY.value
