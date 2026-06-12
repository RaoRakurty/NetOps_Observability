"""Replay-contract tests (#67 build ⑥): the golden-incident fixture must
round-trip bit-clean — engine → persisted rows → rehydrate → re-run → no
drift — and a tampered store or changed pins must be REPORTED, not absorbed.
This is the CI gate the design names (§5 'Replay drift')."""

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from catalog import builtin_catalog
from engine import EngineConfig, SeamView, run_window
from replay import DriftReport, StoredObject, replay
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
GOLDEN = Path(__file__).parent / "fixtures" / "golden-dallas-window.json"

MODALITY_SOURCE = {
    ModalityClass.ACTIVE_PROBE: Source.PROBE,
    ModalityClass.PASSIVE_FLOW: Source.FLOW,
    ModalityClass.CONTROL_PLANE: Source.TOPOLOGY,
    ModalityClass.DEVICE_TELEMETRY: Source.METRIC,
}


def load_golden() -> tuple[list[Signal], tuple[SeamView, ...], dict]:
    data = json.loads(GOLDEN.read_text())
    signals = []
    for i, spec in enumerate(data["signals"]):
        modality = ModalityClass(spec["modality"])
        signals.append(Signal(
            tenant_id="",
            ts=T0 + timedelta(seconds=float(spec.get("ts_offset_s", i))),
            source=MODALITY_SOURCE[modality],
            kind=spec["kind"],
            observer=Observer(
                observer_id=spec["observer_id"],
                observer_type=ObserverType(spec.get("observer_type", "device")),
                collection_path=spec.get("collection_path", "direct"),
            ),
            modality_class=modality,
            entity_type=EntityType(spec.get("entity_type", "device")),
            entity_id=spec.get("entity_id", spec["observer_id"]),
            severity=Severity(spec.get("severity", "warn")),
            native_id=f"golden|{i}|{spec['kind']}",
            deviation=float(spec.get("deviation", 0.0)),
            attrs=dict(spec.get("attrs", {})),
        ))
    seams = tuple(SeamView.from_dict(d) for d in data.get("seams", ()))
    return signals, seams, data["expect"]


def test_golden_window_produces_expected_object():
    signals, seams, exp = load_golden()
    snapshots = run_window(signals, builtin_catalog(), seams)
    assert len(snapshots) == exp["objects"]
    snap = snapshots[0]
    assert snap.ranking.top_hypothesis == exp["top"]
    assert snap.ranking.verdict_tier.value == exp["tier"]
    assert len(snap.edges) >= exp["min_edges"]
    for e in snap.edges:
        assert (e.grounding.kind, e.grounding.ref) == ("seam", exp["all_edges_grounded_via"])
    affected = snap.affected()
    for excluded in exp["excluded_entities"]:
        for entities in affected.values():
            assert excluded not in entities, "ungrounded bystander must not join the object"
    assert snap.gap_hints >= exp["gap_hints_min"]


def persist_and_rehydrate(snap, signals):  # type: ignore[no-untyped-def]
    """Simulate stage [8] + replay IO exactly: snapshot rows + the archived
    window slice, then rehydrate both the way replay_object does from CH."""
    obj_row = snap.to_object_row(1)
    edge_rows = snap.to_edge_rows(1)
    archive_rows = []
    for s in signals:
        row = s.to_ch_row()
        row["archived_for"] = snap.correlation_id
        archive_rows.append(row)
    stored = StoredObject.from_rows(obj_row, edge_rows)
    window = [Signal.from_ch_row(r) for r in archive_rows]
    return stored, window


def test_replay_round_trip_is_clean():
    signals, seams, _ = load_golden()
    snap = run_window(signals, builtin_catalog(), seams)[0]
    stored, window = persist_and_rehydrate(snap, signals)

    report = replay(stored, window)
    assert report.engine_pin_match and report.catalog_pin_match
    assert report.clean, f"unexpected drift: {report.differences}"


def test_replay_uses_embedded_grounding_context_not_live_state():
    signals, seams, _ = load_golden()
    snap = run_window(signals, builtin_catalog(), seams)[0]
    stored, window = persist_and_rehydrate(snap, signals)
    # The snapshot must carry its seams: replay grounds against the embedded
    # context even if the live inventory has since changed or vanished.
    assert tuple(s.seam_id for s in stored.grounding_context()) == tuple(
        s.seam_id for s in sorted(seams, key=lambda s: s.seam_id))


def test_replay_reports_tampered_store():
    signals, seams, _ = load_golden()
    snap = run_window(signals, builtin_catalog(), seams)[0]
    stored, window = persist_and_rehydrate(snap, signals)
    tampered = StoredObject(**{**stored.__dict__, "top_hypothesis": "sig.ent.cloud.region-impairment"})
    report = replay(tampered, window)
    assert not report.clean
    assert any("top_hypothesis" in d for d in report.differences)


def test_replay_reports_engine_pin_mismatch():
    signals, seams, _ = load_golden()
    snap = run_window(signals, builtin_catalog(), seams)[0]
    stored, window = persist_and_rehydrate(snap, signals)
    report = replay(stored, window, cfg=EngineConfig(tau_s=999))
    assert not report.engine_pin_match
    assert any("engine pin" in d for d in report.differences)


def test_replay_reports_empty_archive():
    signals, seams, _ = load_golden()
    snap = run_window(signals, builtin_catalog(), seams)[0]
    stored, _ = persist_and_rehydrate(snap, signals)
    report = replay(stored, [])
    assert not report.clean
    assert any("archive empty" in d for d in report.differences)


def test_signal_ch_row_round_trip():
    signals, _, _ = load_golden()
    for s in signals:
        row = s.to_ch_row()
        back = Signal.from_ch_row(dict(row))
        assert back.to_ch_row() == row, "rehydration must be byte-faithful"
        assert str(back.signal_id) == row["signal_id"], "identity must survive the round trip"


def test_drift_report_serializes():
    r = DriftReport(correlation_id="x", stored_version=1,
                    engine_pin_match=True, catalog_pin_match=True)
    r.note("example")
    d = r.to_dict()
    assert d["clean"] is False and d["differences"] == ["example"]
