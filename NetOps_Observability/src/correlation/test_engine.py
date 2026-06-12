"""Engine-core tests (#67 build ⑥) — the properties the replay contract and
the owner's grounding constraint stand on:

  * grounding gate: no seam/topology grounding ⇒ NO edge, a counted gap hint
    (the gate never relaxes — an empty inventory yields zero seam edges)
  * determinism: same window (any input order) ⇒ identical snapshot rows and
    content hash
  * direction: claimed only when both available votes agree (2-of-3 rule with
    the topology vote abstaining in v0)
  * tenancy: a mixed-tenant window is rejected, never silently partitioned
"""

import uuid
from datetime import datetime, timedelta, timezone

import pytest

from catalog import builtin_catalog
from engine import (
    EngineConfig,
    SeamView,
    build_edges,
    build_nodes,
    engine_version,
    run_window,
    seams_hash,
)
from signals import (
    EntityType,
    ModalityClass,
    Observer,
    ObserverType,
    Severity,
    Signal,
    Source,
)

T0 = datetime(2026, 6, 12, 9, 42, 0, tzinfo=timezone.utc)

DALLAS_SEAM = SeamView(
    seam_id="dallas-dx-equinix",
    tenant_id="",
    seam_type="DX",
    endpoints=(("on_prem", "dallas-edge"), ("provider_edge", "equinix-pop")),
)


def sig(kind: str, entity_type: EntityType, entity_id: str, *, offset_s: float = 0,
        observer: str = "obs1", modality: ModalityClass = ModalityClass.DEVICE_TELEMETRY,
        severity: Severity = Severity.HIGH, unc_s: float = 5.0, tenant: str = "") -> Signal:
    return Signal(
        tenant_id=tenant,
        ts=T0 + timedelta(seconds=offset_s),
        source=Source.METRIC,
        kind=kind,
        observer=Observer(observer_id=observer, observer_type=ObserverType.DEVICE),
        modality_class=modality,
        entity_type=entity_type,
        entity_id=entity_id,
        severity=severity,
        native_id=f"test|{kind}|{entity_id}|{offset_s}",
        attrs={"onset_uncertainty_s": unc_s},
    )


def test_grounding_gate_blocks_ungrounded_pairs():
    nodes = build_nodes((
        sig("if_util_high", EntityType.INTERFACE, "dallas-edge:Gi0/1"),
        sig("metric_anomaly", EntityType.DEVICE, "austin-core", offset_s=10),
    ))
    edges, gap_hints = build_edges(nodes, (), EngineConfig())
    assert edges == ()
    assert gap_hints == 1


def test_seam_grounding_admits_edge():
    nodes = build_nodes((
        sig("if_util_high", EntityType.INTERFACE, "dallas-edge:Gi0/1"),
        sig("probe_loss", EntityType.SEGMENT, "dallas-edge->equinix-pop", offset_s=58,
            observer="probe1", modality=ModalityClass.ACTIVE_PROBE),
    ))
    edges, gap_hints = build_edges(nodes, (DALLAS_SEAM,), EngineConfig())
    assert len(edges) == 1 and gap_hints == 0
    e = edges[0]
    assert (e.grounding.kind, e.grounding.ref) == ("seam", "dallas-dx-equinix")
    assert e.w_reinforce > 1.0, "cross-modality pair must reinforce"
    # interface (L0) precedes and is a lower layer than segment (L2): both
    # votes agree → direction claimed.
    assert e.direction_conf > 0 and e.direction_basis == "onset_order+layer_prior"


def test_containment_topo_grounding():
    nodes = build_nodes((
        sig("device_cpu_high", EntityType.DEVICE, "dallas-edge"),
        sig("if_errors", EntityType.INTERFACE, "dallas-edge:Gi0/1", offset_s=20),
    ))
    edges, _ = build_edges(nodes, (), EngineConfig())
    assert len(edges) == 1
    assert edges[0].grounding.kind == "topo"
    assert "dallas-edge" in edges[0].grounding.ref


def test_direction_unclaimed_on_conflict():
    # The LOWER layer onsets later: onset-order and layer-prior disagree → no claim.
    nodes = build_nodes((
        sig("probe_loss", EntityType.SEGMENT, "dallas-edge->equinix-pop",
            observer="probe1", modality=ModalityClass.ACTIVE_PROBE),
        sig("if_util_high", EntityType.INTERFACE, "dallas-edge:Gi0/1", offset_s=120),
    ))
    edges, _ = build_edges(nodes, (DALLAS_SEAM,), EngineConfig())
    assert len(edges) == 1
    assert edges[0].direction_conf == 0.0
    assert edges[0].direction_basis in ("mixed", "none")


def test_direction_unclaimed_within_uncertainty():
    # Onset gap smaller than the summed uncertainty: the order vote abstains,
    # leaving one vote — not enough to claim.
    nodes = build_nodes((
        sig("if_util_high", EntityType.INTERFACE, "dallas-edge:Gi0/1", unc_s=30),
        sig("probe_loss", EntityType.SEGMENT, "dallas-edge->equinix-pop", offset_s=10,
            observer="probe1", modality=ModalityClass.ACTIVE_PROBE, unc_s=30),
    ))
    edges, _ = build_edges(nodes, (DALLAS_SEAM,), EngineConfig())
    assert len(edges) == 1 and edges[0].direction_conf == 0.0


def test_singleton_open_floor():
    crit = run_window([sig("metric_anomaly", EntityType.DEVICE, "edge1", severity=Severity.CRIT)],
                      builtin_catalog(), ())
    warn = run_window([sig("metric_anomaly", EntityType.DEVICE, "edge2", severity=Severity.WARN)],
                      builtin_catalog(), ())
    assert len(crit) == 1, "a critical singleton episode opens an object"
    assert warn == [], "a warn singleton stays an episode, not an object"


def test_mixed_tenant_window_rejected():
    with pytest.raises(ValueError):
        run_window([sig("a", EntityType.DEVICE, "d1", tenant="t1"),
                    sig("b", EntityType.DEVICE, "d2", tenant="t2")],
                   builtin_catalog(), ())


def golden_window() -> list[Signal]:
    return [
        sig("if_util_high", EntityType.INTERFACE, "dallas-edge:Gi0/1",
            observer="dallas-edge", unc_s=15),
        sig("probe_loss", EntityType.SEGMENT, "dallas-edge->equinix-pop", offset_s=58,
            observer="probe-agent-dallas", modality=ModalityClass.ACTIVE_PROBE, unc_s=5),
        sig("qos_drops", EntityType.INTERFACE, "dallas-edge:Gi0/1", offset_s=75,
            observer="dallas-edge", severity=Severity.WARN, unc_s=15),
    ]


def test_determinism_input_order_invariance():
    cat = builtin_catalog()
    a = run_window(golden_window(), cat, (DALLAS_SEAM,))
    b = run_window(list(reversed(golden_window())), cat, (DALLAS_SEAM,))
    assert len(a) == len(b) == 1
    assert a[0].correlation_id == b[0].correlation_id
    assert a[0].content_hash() == b[0].content_hash()
    assert a[0].to_object_row(1) == b[0].to_object_row(1)
    assert a[0].to_edge_rows(1) == b[0].to_edge_rows(1)


def test_snapshot_row_contract():
    snap = run_window(golden_window(), builtin_catalog(), (DALLAS_SEAM,))[0]
    row = snap.to_object_row(1)
    uuid.UUID(row["correlation_id"])           # well-formed deterministic id
    assert row["engine_version"] == engine_version(EngineConfig())
    assert row["catalog_version"] == builtin_catalog().version_hash()
    assert row["topology_version"] == seams_hash((DALLAS_SEAM,))
    assert row["node_count"] == 3 and row["signal_count"] == 3
    for e in snap.to_edge_rows(1):
        assert e["grounding_ref"], "grounded-edges constraint: ref never empty"


def test_engine_version_pins_config():
    assert engine_version(EngineConfig()) != engine_version(EngineConfig(tau_s=999))
    assert engine_version(EngineConfig()) == engine_version(EngineConfig())
