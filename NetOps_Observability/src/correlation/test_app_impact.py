"""App-impact engine integration — #81 Fusion Layer P5c (golden properties).

Proves fused application identity behaves as ENRICHMENT, not a fault (AD-5):

  * identity-only window forms NO object (it can never seed one)
  * an identity matched to a real-fault object NAMES the affected app with
    provenance (band/state/sources) in app_impact + affected.apps + a supporting
    corr_evidence row carrying the REAL identity signal_id
  * naming is a PROJECTION: it does NOT change the object's content_hash (replay-
    safe, no version churn) — an object is byte-identical with or without identity
  * an impactable node with no admissible identity records honest evidence_missing
    (unknown stays first-class — never a guessed app name)
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app_producers import app_identity_signal
from catalog import builtin_catalog
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

T0 = datetime(2026, 6, 26, 9, 0, 0, tzinfo=timezone.utc)
DALLAS_SEAM = SeamView(
    seam_id="dallas-dx-equinix",
    tenant_id="acme",
    seam_type="DX",
    endpoints=(("on_prem", "dallas-edge"), ("provider_edge", "equinix-pop")),
)


def fault(kind, etype, eid, *, offset_s=0.0, observer="obs1",
          modality=ModalityClass.DEVICE_TELEMETRY, severity=Severity.HIGH):
    return Signal(
        tenant_id="acme", ts=T0 + timedelta(seconds=offset_s), source=Source.METRIC,
        kind=kind, observer=Observer(observer_id=observer, observer_type=ObserverType.DEVICE),
        modality_class=modality, entity_type=etype, entity_id=eid, severity=severity,
        native_id=f"test|{kind}|{eid}|{offset_s}", attrs={"onset_uncertainty_s": 5.0},
    )


def ident(app, *, tokens, band="authoritative", state="fused", offset_s=0.0,
          sources=("ngfw_app_id", "ip_catalog"), score=92):
    # the real producer — so the test exercises the shipped wire contract
    s = app_identity_signal(
        "acme", T0 + timedelta(seconds=offset_s), app=app, band=band, state=state,
        evidence_score=score, sources=tuple(sources), fusion_version="appfuse-1",
        entity_tokens=tuple(tokens),
    )
    return s


# a real fault that grounds into a 2-node containment object (device + its interface)
def _fault_window():
    return [
        fault("device_cpu_high", EntityType.DEVICE, "dallas-edge"),
        fault("if_errors", EntityType.INTERFACE, "dallas-edge:Gi0/1", offset_s=20),
    ]


def test_identity_only_window_forms_no_object():
    snaps = run_window((ident("Payroll", tokens=("dallas-edge",)),),
                       builtin_catalog(), ())
    assert snaps == []  # identity is enrichment — it can NEVER seed an object


def test_matched_identity_names_app_with_provenance():
    win = _fault_window() + [ident("Payroll", tokens=("dallas-edge",))]
    snaps = run_window(tuple(win), builtin_catalog(), ())
    assert len(snaps) == 1
    snap = snaps[0]
    impact = snap.app_impact()
    assert [a["app"] for a in impact["apps"]] == ["Payroll"]
    app = impact["apps"][0]
    assert app["band"] == "authoritative" and app["state"] == "fused"
    assert app["sources"] == ["ngfw_app_id", "ip_catalog"] and app["evidence_score"] == 92
    # named app surfaces in the blast radius
    assert "Payroll" in snap.affected()["apps"]
    # an explainable supporting-evidence row carrying the REAL identity signal_id
    ev = [r for r in snap.to_evidence_rows(1) if r["subject_kind"] == "app"]
    assert len(ev) == 1 and ev[0]["subject_id"] == "Payroll" and ev[0]["role"] == "supports"
    assert ev[0]["signal_id"] == str(win[-1].signal_id)
    # persisted projection column carries it
    assert "Payroll" in snap.to_object_row(1)["app_impact"]


def test_naming_does_not_change_content_hash():
    base = run_window(tuple(_fault_window()), builtin_catalog(), ())[0]
    # add a MATCHING identity → app named, but the object's identity is unchanged
    named = run_window(tuple(_fault_window() + [ident("Payroll", tokens=("dallas-edge",))]),
                       builtin_catalog(), ())[0]
    assert named.app_impact()["apps"], "sanity: the identity did match"
    assert named.content_hash() == base.content_hash(), \
        "app-impact is a projection — must NOT churn content_hash (replay-safe)"


def test_unmatched_identity_no_naming_and_no_churn():
    base = run_window(tuple(_fault_window()), builtin_catalog(), ())[0]
    # an identity that shares NO token with the fault → not attached, no app named
    win = _fault_window() + [ident("Salesforce", tokens=("some-other-host",))]
    snap = run_window(tuple(win), builtin_catalog(), ())[0]
    assert snap.app_impact().get("apps") == []
    assert snap.content_hash() == base.content_hash()


def test_unmatched_impactable_node_records_evidence_missing():
    # a seam-grounded object (interface + segment); segment fronts traffic but no
    # identity is admissible → honest evidence_missing, never a guessed app.
    win = [
        fault("if_util_high", EntityType.INTERFACE, "dallas-edge:Gi0/1"),
        fault("probe_loss", EntityType.SEGMENT, "dallas-edge->equinix-pop", offset_s=58,
              observer="probe1", modality=ModalityClass.ACTIVE_PROBE),
    ]
    snap = run_window(tuple(win), builtin_catalog(), (DALLAS_SEAM,))[0]
    impact = snap.app_impact()
    assert impact["apps"] == []
    miss = impact.get("evidence_missing", [])
    assert any("dallas-edge->equinix-pop" in m for m in miss), miss


def test_mixed_tenant_window_rejected_including_identity():
    # the single-tenant contract (§7) applies to identity too — an identity from a
    # DIFFERENT tenant in the window is a hard error, never silently partitioned.
    import pytest
    foreign = app_identity_signal(
        "evil-corp", T0, app="Exfil", band="high", state="fused",
        fusion_version="appfuse-1", entity_tokens=("dallas-edge",))
    with pytest.raises(ValueError):
        run_window(tuple(_fault_window() + [foreign]), builtin_catalog(), ())


def test_identity_enrichment_is_deterministic_under_input_shuffle():
    # determinism (the replay contract): same window, any order ⇒ identical object
    # identity AND identical app_impact projection.
    win = _fault_window() + [ident("Payroll", tokens=("dallas-edge",))]
    a = run_window(tuple(win), builtin_catalog(), ())[0]
    b = run_window(tuple(reversed(win)), builtin_catalog(), ())[0]
    assert a.content_hash() == b.content_hash()
    assert a.app_impact_blob() == b.app_impact_blob()
    assert a.to_object_row(1)["app_impact"] == b.to_object_row(1)["app_impact"]


def test_strongest_score_wins_for_duplicate_app():
    win = _fault_window() + [
        ident("Payroll", tokens=("dallas-edge",), band="medium", state="inferred", score=40),
        ident("Payroll", tokens=("dallas-edge",), band="authoritative", state="fused", score=95, offset_s=5),
    ]
    snap = run_window(tuple(win), builtin_catalog(), ())[0]
    apps = snap.app_impact()["apps"]
    assert len(apps) == 1 and apps[0]["evidence_score"] == 95 and apps[0]["band"] == "authoritative"
