"""Tracker 178 — the drift report must compare edge DIRECTION.

Before this, `replay._diff` diffed edges by identity only
(from_node, to_node, grounding_kind, grounding_ref). The from/to order is decided
by ONSET ORDER, never by the direction oracle, so a stored object that asserts a
directed edge (`direction_basis='onset_order+topo_updown'`, `direction_conf=0.8`)
whose embedded orientations were lost — the exact case pinned by
test_cohort_touch_gate_p1.T7 and design COHORT_TOUCH_GATE_P1 §10 item 6 — replayed
as ('none', 0.0) and STILL reported CLEAN. The stored object asserted a direction
its own replay could not reproduce, and nothing said so.

Schema v2 (replay.EDGE_COMPARISON_SCHEMA) compares (direction_basis,
direction_conf) on every edge present on both sides.

Fixture: fixtures/golden_replay/direction-drift-window.json (a SUBDIRECTORY — the
catalog gate in test_fixtures.py sweeps fixtures/*.json top-level only).
"""

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from catalog import builtin_catalog
from directed_topology import DirectedTopology
from engine import TopologyAdjacency, run_window
from flow_direction import netflow_direction_source
from replay import EDGE_COMPARISON_SCHEMA, StoredObject, replay
from signals import (
    EntityType,
    ModalityClass,
    Observer,
    ObserverType,
    Severity,
    Signal,
    Source,
)

T0 = datetime(2026, 8, 28, 9, 0, 0, tzinfo=timezone.utc)
GOLDEN = Path(__file__).parent / "fixtures" / "golden_replay" / "direction-drift-window.json"

MODALITY_SOURCE = {
    ModalityClass.ACTIVE_PROBE: Source.PROBE,
    ModalityClass.PASSIVE_FLOW: Source.FLOW,
    ModalityClass.CONTROL_PLANE: Source.TOPOLOGY,
    ModalityClass.DEVICE_TELEMETRY: Source.METRIC,
}


def load_golden() -> tuple[list[Signal], TopologyAdjacency, DirectedTopology, dict]:
    data = json.loads(GOLDEN.read_text())
    signals = []
    for i, spec in enumerate(data["signals"]):
        modality = ModalityClass(spec["modality"])
        signals.append(Signal(
            tenant_id="",
            ts=T0 + timedelta(seconds=float(spec.get("ts_offset_s", i))),
            source=MODALITY_SOURCE[modality],
            kind=spec["kind"],
            observer=Observer(observer_id=spec["observer_id"],
                              observer_type=ObserverType(spec.get("observer_type", "device"))),
            modality_class=modality,
            entity_type=EntityType(spec.get("entity_type", "device")),
            entity_id=spec["entity_id"],
            severity=Severity(spec.get("severity", "warn")),
            native_id=f"golden-dir|{i}|{spec['kind']}",
            entity_tokens=tuple(spec.get("entity_tokens", ())),
            attrs=dict(spec.get("attrs", {})),
        ))
    adjacency = TopologyAdjacency.from_links(list(data["adjacency"]))
    volumes = {(f["from"], f["to"]): float(f["bytes"]) for f in data["netflow_bytes"]}
    directed = DirectedTopology(
        sources=(("netflow", netflow_direction_source(volumes)),))
    return signals, adjacency, directed, data["expect"]


def persist_and_rehydrate(snap, signals, *, drop_orientations: bool = False):  # type: ignore[no-untyped-def]
    """Stage [8] + replay IO, exactly as test_replay.persist_and_rehydrate.

    `drop_orientations=True` reproduces the T7 damage WITHOUT the cohort machinery:
    a re-materialized untouched component embeds `orientations=()`, so the blob
    loses the key and `StoredObject.directed()` rehydrates None — while the stored
    EDGE rows still assert the direction the (now absent) oracle produced.
    """
    obj_row = snap.to_object_row(1)
    if drop_orientations:
        blob = json.loads(obj_row["hypotheses"])
        blob["grounding_context"].pop("orientations", None)
        obj_row = {**obj_row, "hypotheses": json.dumps(blob)}
    edge_rows = snap.to_edge_rows(1)
    archive_rows = []
    for s in signals:
        row = s.to_ch_row()
        row["archived_for"] = snap.correlation_id
        archive_rows.append(row)
    stored = StoredObject.from_rows(obj_row, edge_rows)
    window = [Signal.from_ch_row(r) for r in archive_rows]
    return stored, window


# ── premise ───────────────────────────────────────────────────────────────────


def test_golden_fixture_produces_one_directed_edge():
    """If this ever fails the rest of the file pins nothing."""
    signals, adj, directed, exp = load_golden()
    snaps = run_window(signals, builtin_catalog(), (), adjacency=adj, directed=directed)
    assert len(snaps) == exp["objects"]
    snap = snaps[0]
    assert snap.orientations, "fixture must be a directed object"
    assert len(snap.edges) == exp["edges"]
    e = snap.edges[0]
    assert (e.direction_basis, round(e.direction_conf, 4)) == \
           (exp["direction_basis"], exp["direction_conf"])


# ── (a) the T7 case now REPORTS drift ────────────────────────────────────────


def test_T7_case_lost_orientations_now_report_direction_drift():
    signals, adj, directed, exp = load_golden()
    snap = run_window(signals, builtin_catalog(), (), adjacency=adj, directed=directed)[0]
    stored, window = persist_and_rehydrate(snap, signals, drop_orientations=True)
    assert stored.directed() is None, "PREMISE: no oracle may rehydrate from the blob"

    report = replay(stored, window)
    assert report.engine_pin_match and report.catalog_pin_match, \
        "the pins must MATCH — otherwise the drift would be excused as evolution"
    assert not report.clean, "the stored object asserts a direction its replay cannot reproduce"
    assert len(report.direction_drift) == 1, report.direction_drift
    finding = report.direction_drift[0]
    assert exp["direction_basis"] in finding and exp["undirected_basis"] in finding, finding
    assert report.direction_drift == [d for d in report.differences if "edge direction" in d], \
        "a direction finding must ALSO be a plain difference (pre-v2 readers)"
    # The identity diff alone still sees nothing: this is drift v1 could not report.
    assert not any(d.startswith("edge in ") for d in report.differences), report.differences


def test_T7_case_serializes_the_direction_drift():
    signals, adj, directed, _ = load_golden()
    snap = run_window(signals, builtin_catalog(), (), adjacency=adj, directed=directed)[0]
    stored, window = persist_and_rehydrate(snap, signals, drop_orientations=True)
    d = replay(stored, window).to_dict()
    assert d["clean"] is False
    assert d["comparison_schema"] == EDGE_COMPARISON_SCHEMA >= 2
    assert d["direction_drift_count"] == 1 and len(d["direction_drift"]) == 1
    assert d["direction_unknown"] == 0


# ── (b) identical direction → clean ──────────────────────────────────────────


def test_identical_direction_replays_clean():
    signals, adj, directed, _ = load_golden()
    snap = run_window(signals, builtin_catalog(), (), adjacency=adj, directed=directed)[0]
    stored, window = persist_and_rehydrate(snap, signals)
    assert stored.directed() is not None, "the frozen oracle must rehydrate"
    report = replay(stored, window)
    assert report.clean, f"directed object drifted: {report.differences}"
    assert report.direction_drift == [] and report.direction_unknown == 0


# ── (c) undirected vs undirected → clean ─────────────────────────────────────


def test_undirected_vs_undirected_is_clean():
    """No oracle on either side: the edge abstains ('none', 0.0) both times. The
    widened diff must not turn 'both undirected' into a finding."""
    signals, adj, _directed, exp = load_golden()
    snap = run_window(signals, builtin_catalog(), (), adjacency=adj)[0]
    assert snap.orientations == (), "PREMISE: an object with no oracle is undirected"
    e = snap.edges[0]
    assert (e.direction_basis, e.direction_conf) == \
           (exp["undirected_basis"], exp["undirected_conf"])
    stored, window = persist_and_rehydrate(snap, signals)
    report = replay(stored, window)
    assert report.clean, f"undirected object drifted: {report.differences}"
    assert report.direction_drift == []


# ── the conf half, and the exactness justification ───────────────────────────


def test_direction_conf_alone_is_compared_exactly():
    """direction_conf is two-valued and deterministic (cfg.direction_conf | 0.0),
    persisted rounded to 4 decimals — so a changed conf on an UNCHANGED basis is
    real drift, reported with no tolerance to hide it."""
    signals, adj, directed, _ = load_golden()
    snap = run_window(signals, builtin_catalog(), (), adjacency=adj, directed=directed)[0]
    stored, window = persist_and_rehydrate(snap, signals)
    tampered_edges = [{**e, "direction_conf": 0.5} for e in stored.edges]
    tampered = StoredObject(**{**stored.__dict__, "edges": tuple(tampered_edges)})
    report = replay(tampered, window)
    assert not report.clean
    assert len(report.direction_drift) == 1 and "0.5" in report.direction_drift[0]


def test_rounding_noise_below_the_persisted_precision_is_not_drift():
    """Both sides pass through round(...,4) at persist time, so a difference the
    stored precision cannot express must not be manufactured into a finding."""
    signals, adj, directed, _ = load_golden()
    snap = run_window(signals, builtin_catalog(), (), adjacency=adj, directed=directed)[0]
    stored, window = persist_and_rehydrate(snap, signals)
    jittered = [{**e, "direction_conf": float(e["direction_conf"]) + 1e-9} for e in stored.edges]
    report = replay(StoredObject(**{**stored.__dict__, "edges": tuple(jittered)}), window)
    assert report.clean, report.differences


# ── legacy rows: not comparable is NOT drift, but is counted ─────────────────


def test_stored_row_without_direction_columns_is_counted_not_drift():
    signals, adj, directed, _ = load_golden()
    snap = run_window(signals, builtin_catalog(), (), adjacency=adj, directed=directed)[0]
    stored, window = persist_and_rehydrate(snap, signals)
    legacy = [{k: v for k, v in e.items() if not k.startswith("direction_")}
              for e in stored.edges]
    report = replay(StoredObject(**{**stored.__dict__, "edges": tuple(legacy)}), window)
    assert report.clean, report.differences
    assert report.direction_unknown == 1, "an uncomparable edge must be visible, not silent"
    assert report.direction_drift == []


# ── the report is self-describing ────────────────────────────────────────────


def test_clean_report_states_its_comparison_schema():
    signals, adj, directed, _ = load_golden()
    snap = run_window(signals, builtin_catalog(), (), adjacency=adj, directed=directed)[0]
    stored, window = persist_and_rehydrate(snap, signals)
    d = replay(stored, window).to_dict()
    assert d["clean"] is True
    assert d["comparison_schema"] == EDGE_COMPARISON_SCHEMA
    # v1 keys keep their exact meaning and their names.
    for k in ("correlation_id", "stored_version", "engine_pin_match",
              "catalog_pin_match", "clean", "differences"):
        assert k in d
