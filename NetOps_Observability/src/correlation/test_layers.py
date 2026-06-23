"""Causal/OSI layer taxonomy (C4) + its use as the finer direction prior."""
import json
from datetime import datetime, timedelta, timezone

from catalog import builtin_catalog
from engine import EngineConfig, SeamView, build_edges, build_nodes, run_window
from layers import CausalLayer, layer_of, osi_label
from signals import EntityType, ModalityClass, Observer, ObserverType, Severity, Signal, Source

_SEAM = SeamView(
    seam_id="dallas-dx", tenant_id="", seam_type="DX",
    endpoints=(("on_prem", "dallas-edge"), ("provider_edge", "equinix-pop")))

T0 = datetime(2026, 6, 23, 9, 0, 0, tzinfo=timezone.utc)


def test_layer_of_maps_kinds_and_strips_clear():
    assert layer_of("link_state_change") is CausalLayer.LINK
    assert layer_of("isis_adjacency_change") is CausalLayer.NETWORK
    assert layer_of("bgp_adjacency_change") is CausalLayer.NETWORK
    assert layer_of("device_resource_anomaly") is CausalLayer.DEVICE
    assert layer_of("probe_loss") is CausalLayer.TRANSPORT
    assert layer_of("if_metric_anomaly_clear") is CausalLayer.LINK   # _clear stripped
    assert layer_of("totally_unknown_kind") is None                  # honest: no guess
    assert layer_of("") is None


def test_causal_layer_is_ordered_bottom_up():
    assert CausalLayer.DEVICE < CausalLayer.LINK < CausalLayer.NETWORK < CausalLayer.TRANSPORT
    assert osi_label(CausalLayer.LINK) == "L2"
    assert osi_label(CausalLayer.NETWORK) == "L3"
    assert osi_label(CausalLayer.DEVICE) == "device"
    assert osi_label(None) == ""


def _dev(kind, dev, off):
    return Signal(
        tenant_id="", ts=T0 + timedelta(seconds=off), source=Source.SYSLOG, kind=kind,
        observer=Observer(observer_id=dev, observer_type=ObserverType.DEVICE),
        modality_class=ModalityClass.CONTROL_PLANE, entity_type=EntityType.DEVICE,
        entity_id=dev, severity=Severity.HIGH, native_id=f"{dev}|{kind}|{off}",
        entity_tokens=(dev, "site1"), attrs={"onset_uncertainty_s": 1.0},
    )


def test_per_kind_layer_breaks_a_tie_entity_type_layer_could_not():
    # link_state (L2) then isis_adjacency (L3) on the SAME device entity-type. Old
    # behavior: both DEVICE entity → entity-type layer equal → layer vote abstains →
    # only onset (1 vote) → no direction. C4: L2 < L3 → layer vote fires → DIRECTED.
    nodes = build_nodes((_dev("link_state_change", "leaf1", 0),
                         _dev("isis_adjacency_change", "leaf1", 30)))
    edges, _ = build_edges(nodes, (), EngineConfig())
    assert len(edges) == 1
    e = edges[0]
    assert e.direction_conf > 0.0
    assert "layer_prior" in e.direction_basis and "onset_order" in e.direction_basis


def test_per_kind_layer_conflict_with_onset_is_mixed():
    # isis (L3, network) first, then link_state (L2, link): onset says isis→link but
    # layer says link(lower)→isis → conflict → mixed (no false claim).
    nodes = build_nodes((_dev("isis_adjacency_change", "leaf1", 0),
                         _dev("link_state_change", "leaf1", 30)))
    edges, _ = build_edges(nodes, (), EngineConfig())
    assert edges[0].direction_basis in ("mixed", "none")
    assert edges[0].direction_conf == 0.0


# ── C4-UI: layer_coverage projection (the RCA Layer-Stack panel's data) ─────────

def _s(kind, etype, eid, off, *, obs="obs1", modality=ModalityClass.DEVICE_TELEMETRY,
       sev=Severity.HIGH):
    return Signal(
        tenant_id="", ts=T0 + timedelta(seconds=off), source=Source.METRIC, kind=kind,
        observer=Observer(observer_id=obs, observer_type=ObserverType.DEVICE),
        modality_class=modality, entity_type=etype, entity_id=eid, severity=sev,
        native_id=f"{eid}|{kind}|{off}", attrs={"onset_uncertainty_s": 2.0})


def test_layer_coverage_shows_observed_layers_and_the_gap_between():
    # link (L2) ⟂ probe transport (L4), seam-grounded into one object. The NETWORK
    # (L3) layer between them is unobserved — the differentiator: the stack shows
    # exactly which layer the evidence is blind to, between root and impact.
    snaps = run_window((
        _s("link_state_change", EntityType.INTERFACE, "dallas-edge:Gi0/1", 0,
           modality=ModalityClass.CONTROL_PLANE),
        _s("probe_loss", EntityType.SEGMENT, "dallas-edge->equinix-pop", 40,
           obs="probe1", modality=ModalityClass.ACTIVE_PROBE),
    ), builtin_catalog(), (_SEAM,))
    assert len(snaps) == 1
    cov = snaps[0].layer_coverage()
    # the FULL bottom-up ladder, always all seven, in order:
    assert [lyr["layer"] for lyr in cov["layers"]] == [
        "device", "physical", "link", "network", "transport", "service", "application"]
    by = {lyr["layer"]: lyr for lyr in cov["layers"]}
    assert by["link"]["observed"] and by["transport"]["observed"]
    assert by["network"]["observed"] is False        # the gap, surfaced not hidden
    assert by["device"]["observed"] is False
    assert by["link"]["osi"] == "L2" and by["transport"]["osi"] == "L4"
    assert "dallas-edge:Gi0/1" in by["link"]["entities"]
    assert by["link"]["kinds"] == ["link_state_change"]
    assert by["link"]["peak_severity"] == "high"
    assert cov["root_layer"] == "link" and cov["impact_layer"] == "transport"
    assert cov["unmapped_kinds"] == []


def test_layer_coverage_surfaces_unmapped_kind_never_silently_drops_it():
    # a kind with no layer mapping must appear in unmapped_kinds (honest), and every
    # ladder row reads not-observed — we never guess a layer for it.
    snaps = run_window((
        _s("vendor_widget_anomaly", EntityType.DEVICE, "leaf9", 0, sev=Severity.CRIT),
    ), builtin_catalog(), ())
    assert len(snaps) == 1
    cov = snaps[0].layer_coverage()
    assert cov["unmapped_kinds"] == ["vendor_widget_anomaly"]
    assert all(lyr["observed"] is False for lyr in cov["layers"])
    assert cov["root_layer"] == "" and cov["impact_layer"] == ""


def test_layer_coverage_blob_round_trips_and_is_outside_content_hash():
    snaps = run_window((
        _s("link_state_change", EntityType.INTERFACE, "dallas-edge:Gi0/1", 0,
           modality=ModalityClass.CONTROL_PLANE),
        _s("probe_loss", EntityType.SEGMENT, "dallas-edge->equinix-pop", 40,
           obs="probe1", modality=ModalityClass.ACTIVE_PROBE),
    ), builtin_catalog(), (_SEAM,))
    snap = snaps[0]
    row = snap.to_object_row(1)
    assert json.loads(row["layer_coverage"]) == snap.layer_coverage()
    # the projection lives in its OWN column, never in the hashed hypotheses blob —
    # so it can never churn the object's content_hash / replay pin.
    assert "layer_coverage" not in snap.hypotheses_blob()
