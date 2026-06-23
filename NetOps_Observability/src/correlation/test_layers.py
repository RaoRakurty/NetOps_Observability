"""Causal/OSI layer taxonomy (C4) + its use as the finer direction prior."""
from datetime import datetime, timedelta, timezone

from engine import EngineConfig, build_edges, build_nodes
from layers import CausalLayer, layer_of, osi_label
from signals import EntityType, ModalityClass, Observer, ObserverType, Severity, Signal, Source

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
