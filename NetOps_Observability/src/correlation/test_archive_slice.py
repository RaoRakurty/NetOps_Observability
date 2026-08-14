"""Bounded archive slices (perf defect #3 — main._archive_slice).

Every persisted version used to archive the ENTIRE tenant window (50k floor)
per object — N spray objects/cycle × full window ≈ 1M rows/30s. The slice is
now NODE-COMPLETE and bounded to the object's own span, re-archiving an
unchanged slice is damped, and the insert is chunked. These tests pin:

  * membership — nodes overlapping [window_start, window_end] are included
    WHOLE (never clipped); out-of-span nodes are excluded; in-bounds clears and
    the object's MATCHED identity signals ride along
  * replay correctness — replay.replay() over the slice reproduces the stored
    object CLEAN (node/signal/edge/verdict/confidence identical): edge
    admission is pair-local, so a node-complete slice containing the whole
    component reproduces exactly the live component
  * damping — an identical slice membership is not re-written; readers resolve
    through the existing newest-archived_version-≤-v fallback
  * chunking — a large slice lands as multiple bounded inserts
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

import pytest

import main
from catalog import builtin_catalog
from engine import EngineConfig, run_window
from replay import StoredObject, replay
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
CAT = builtin_catalog()


def run(coro):
    return asyncio.run(coro)


def sig(kind: str, entity_type: EntityType, entity_id: str, *, offset_s: float = 0,
        source: Source = Source.METRIC, severity: Severity = Severity.HIGH,
        tokens: tuple[str, ...] = ()) -> Signal:
    return Signal(
        tenant_id="t1",
        ts=T0 + timedelta(seconds=offset_s),
        source=source,
        kind=kind,
        observer=Observer(observer_id="obs1", observer_type=ObserverType.DEVICE),
        modality_class=ModalityClass.DEVICE_TELEMETRY,
        entity_type=entity_type,
        entity_id=entity_id,
        severity=severity,
        native_id=f"t|{kind}|{entity_id}|{offset_s}",
        entity_tokens=tokens,
        attrs={"onset_uncertainty_s": 5.0},
    )


def _window():
    """One tenant window with every slice-membership class present."""
    comp_dev = sig("device_cpu_high", EntityType.DEVICE, "dallas-edge")           # comp
    comp_if = sig("if_errors", EntityType.INTERFACE, "dallas-edge:Gi0/1",
                  offset_s=20)                                                    # comp
    boundary_a = sig("metric_anomaly", EntityType.DEVICE, "boundary-dev",
                     offset_s=10)                                                 # overlaps span
    boundary_b = sig("metric_anomaly", EntityType.DEVICE, "boundary-dev",
                     offset_s=400)                                                # SAME node, out of span
    far = sig("metric_anomaly", EntityType.DEVICE, "austin-core", offset_s=600)   # outside span
    clear_in = sig("if_errors_clear", EntityType.INTERFACE, "dallas-edge:Gi0/1",
                   offset_s=5)                                                    # in-bounds clear
    clear_out = sig("if_errors_clear", EntityType.INTERFACE, "austin-core:Et9",
                    offset_s=500)                                                 # out-of-bounds clear
    identity = sig("app_identity", EntityType.APP, "TeamsApp", offset_s=300,
                   source=Source.APP_IDENTITY, severity=Severity.INFO,
                   tokens=("dallas-edge",))                                       # matched, out of bounds
    window = [comp_dev, comp_if, boundary_a, boundary_b, far, clear_in,
              clear_out, identity]
    return window, {
        "comp": [comp_dev, comp_if], "boundary": [boundary_a, boundary_b],
        "far": far, "clear_in": clear_in, "clear_out": clear_out,
        "identity": identity,
    }


def _dallas_snapshot(window):
    snaps = run_window(tuple(window), CAT, (), EngineConfig())
    return next(s for s in snaps if "dallas-edge" in s.affected().get("devices", []))


def test_slice_membership_is_node_complete_and_bounded():
    window, parts = _window()
    snap = _dallas_snapshot(window)
    assert snap.window_start == parts["comp"][0].ts
    assert snap.window_end == parts["comp"][1].ts
    got = {str(s.signal_id) for s in main._archive_slice(snap, window)}
    expected = {str(s.signal_id) for s in (
        *parts["comp"],
        *parts["boundary"],      # interval overlaps the span → node included WHOLE
        parts["clear_in"],       # in-bounds clear: Inspector context, engine-inert
        parts["identity"],       # matched identity rides along (app-impact replay)
    )}
    assert got == expected
    assert str(parts["far"].signal_id) not in got, "out-of-span node must be excluded"
    assert str(parts["clear_out"].signal_id) not in got


def test_replay_over_the_slice_is_clean():
    """The replay-correctness pin: re-running the pure engine over ONLY the
    bounded slice reproduces the stored object with zero drift."""
    window, _ = _window()
    snap = _dallas_snapshot(window)
    stored = StoredObject.from_rows(snap.to_object_row(1, "open"),
                                    snap.to_edge_rows(1))
    report = replay(stored, main._archive_slice(snap, window))
    assert report.engine_pin_match and report.catalog_pin_match
    assert report.clean, f"slice replay drifted: {report.differences}"


def test_full_component_signals_always_inside_slice():
    window, _ = _window()
    snap = _dallas_snapshot(window)
    got = {str(s.signal_id) for s in main._archive_slice(snap, window)}
    comp_ids = {str(s.signal_id) for n in snap.nodes for s in n.signals}
    assert comp_ids <= got


# ── persistence: amplification, damping, chunking ────────────────────────────


class FakeCH:
    def __init__(self):
        self.calls: list[tuple[str, int]] = []
        self.rows: list[dict] = []

    async def insert(self, table, rows, dedup_token=""):
        rows = list(rows)
        self.calls.append((table, len(rows)))
        self.rows.extend({"_table": table, **r} for r in rows)
        return True


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    main._ARCHIVE_SLICE_HASH.clear()
    yield
    main._ARCHIVE_SLICE_HASH.clear()


def _archive_calls(ch):
    return [c for c in ch.calls if c[0] == "netops.corr_signals_archive"]


def test_persist_archives_the_slice_not_the_whole_window(monkeypatch):
    window, _ = _window()
    snap = _dallas_snapshot(window)
    ch = FakeCH()
    monkeypatch.setattr(main, "ch", ch)
    run(main._persist_snapshot(snap, 1, "open", window))
    archived = [r for r in ch.rows if r["_table"] == "netops.corr_signals_archive"]
    assert len(archived) == len(main._archive_slice(snap, window)) < len(window)
    assert {r["archived_for"] for r in archived} == {snap.correlation_id}
    assert {r["archived_version"] for r in archived} == {1}


def test_unchanged_slice_is_damped_on_reversion(monkeypatch):
    window, _ = _window()
    snap = _dallas_snapshot(window)
    ch = FakeCH()
    monkeypatch.setattr(main, "ch", ch)
    before = main.ARCHIVE_SLICES_DAMPED
    run(main._persist_snapshot(snap, 1, "open", window))
    n_after_v1 = len(_archive_calls(ch))
    run(main._persist_snapshot(snap, 2, "open", window))     # same membership
    assert len(_archive_calls(ch)) == n_after_v1, \
        "an unchanged slice must not be re-archived"
    assert main.ARCHIVE_SLICES_DAMPED == before + 1


def test_changed_slice_membership_re_archives(monkeypatch):
    window, _ = _window()
    snap = _dallas_snapshot(window)
    ch = FakeCH()
    monkeypatch.setattr(main, "ch", ch)
    run(main._persist_snapshot(snap, 1, "open", window))
    grown = window + [sig("if_errors", EntityType.INTERFACE, "dallas-edge:Gi0/1",
                          offset_s=15)]
    n_v1 = len(_archive_calls(ch))
    run(main._persist_snapshot(snap, 2, "open", grown))
    assert len(_archive_calls(ch)) > n_v1, "a grown window slice must re-archive"


def test_archive_insert_is_chunked(monkeypatch):
    window, _ = _window()
    snap = _dallas_snapshot(window)
    ch = FakeCH()
    monkeypatch.setattr(main, "ch", ch)
    monkeypatch.setattr(main, "CORR_ARCHIVE_CHUNK_ROWS", 2)
    slice_len = len(main._archive_slice(snap, window))
    run(main._persist_snapshot(snap, 1, "open", window))
    chunks = _archive_calls(ch)
    assert len(chunks) == (slice_len + 1) // 2
    assert all(n <= 2 for _, n in chunks)
    assert sum(n for _, n in chunks) == slice_len


def test_failed_archive_write_is_retried_not_damped(monkeypatch):
    """A slice whose insert did NOT land must not record its hash — the next
    persist retries the whole slice instead of silently damping a hole."""
    window, _ = _window()
    snap = _dallas_snapshot(window)

    class RejectArchiveCH(FakeCH):
        async def insert(self, table, rows, dedup_token=""):
            if table == "netops.corr_signals_archive":
                self.calls.append((table, len(list(rows))))
                return False
            return await super().insert(table, rows, dedup_token)

    ch = RejectArchiveCH()
    monkeypatch.setattr(main, "ch", ch)
    run(main._persist_snapshot(snap, 1, "open", window))
    assert snap.correlation_id not in main._ARCHIVE_SLICE_HASH
    n_v1 = len(_archive_calls(ch))
    run(main._persist_snapshot(snap, 2, "open", window))     # retried, not damped
    assert len(_archive_calls(ch)) == 2 * n_v1
