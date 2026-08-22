"""Component-sized archive slices (tracker 156 v2 — main._archive_slice).

History, because both steps matter: every persisted version ORIGINALLY archived
the ENTIRE tenant window per object (~1M rows/30s under spray); 156 bounded it
to nodes overlapping the object's span — which was still window-shaped under
estate-wide activity and became 98.6% of persistence time once tracker 168
multiplied objects (~1 → ~1,500; run `082201589waa`). v2 (two adversarial
reviews, 2026-08-22 — docs/scale/ARCHIVE_REDESIGN_156_2026-08-22.md) restricts
membership to the COMPONENT. These tests pin:

  * membership — every signal of every COMPONENT node is included WHOLE (never
    clipped); non-component nodes are excluded EVEN WHEN their activity
    interval overlaps the object's span (the write-amplification pin: restore
    the old overlap rule and the membership test goes red); in-bounds clears
    and the object's MATCHED identity signals ride along
  * replay correctness — replay.replay() over the component slice reproduces
    the stored object CLEAN (edge admission is pair-local, so a node-complete
    slice containing the whole component reproduces exactly the live
    component); terminal (closed, window=[]) versions replay through the
    newest-archived_version-≤-v fallback
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


def test_slice_membership_is_component_only():
    """The v2 membership pin AND the write-amplification regression test: a
    non-component node whose interval overlaps the object's span (`boundary_a`)
    was included by the old rule and MUST NOT be included now — restoring the
    overlap rule turns this red."""
    window, parts = _window()
    snap = _dallas_snapshot(window)
    assert snap.window_start == parts["comp"][0].ts
    assert snap.window_end == parts["comp"][1].ts
    got = {str(s.signal_id) for s in main._archive_slice(snap, window)}
    expected = {str(s.signal_id) for s in (
        *parts["comp"],          # every signal of every COMPONENT node
        parts["clear_in"],       # in-bounds clear rides along (engine-inert)
        parts["identity"],       # matched identity rides along (app-impact replay)
    )}
    assert got == expected
    for b in parts["boundary"]:
        assert str(b.signal_id) not in got, (
            "non-component node included — the old window-shaped overlap rule "
            "is back (write amplification, tracker 156 v2)")
    assert str(parts["far"].signal_id) not in got
    assert str(parts["clear_out"].signal_id) not in got


def test_slice_is_bounded_by_component_not_window():
    """Write-amp bound stated as a ratio: heavy ambient context must not grow
    the slice. 40 non-component boundary signals, slice size unchanged."""
    window, _ = _window()
    noise = [sig("metric_anomaly", EntityType.DEVICE, f"noise-{i}", offset_s=8 + i % 10)
             for i in range(40)]                      # all overlap the span
    grown = window + noise
    snap = _dallas_snapshot(grown)
    slice_len = len(main._archive_slice(snap, grown))
    assert slice_len == 4, f"slice grew with ambient context: {slice_len}"


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
    """v2: only a COMPONENT change re-archives. Growing the window with a
    signal that joins the dallas component (same node key) changes membership;
    the rebuilt snapshot's persist must write a fresh slice."""
    window, _ = _window()
    snap = _dallas_snapshot(window)
    ch = FakeCH()
    monkeypatch.setattr(main, "ch", ch)
    run(main._persist_snapshot(snap, 1, "open", window))
    grown = window + [sig("if_errors", EntityType.INTERFACE, "dallas-edge:Gi0/1",
                          offset_s=15)]              # joins the component's node
    snap2 = _dallas_snapshot(grown)
    assert len(main._archive_slice(snap2, grown)) > len(main._archive_slice(snap, window))
    n_v1 = len(_archive_calls(ch))
    run(main._persist_snapshot(snap2, 2, "open", grown))
    assert len(_archive_calls(ch)) > n_v1, "a grown COMPONENT slice must re-archive"


def test_window_growth_outside_the_component_is_damped(monkeypatch):
    """The v2 dividend: ambient window growth no longer re-archives. Under the
    old rule this exact scenario rewrote a window-sized slice every version."""
    window, _ = _window()
    snap = _dallas_snapshot(window)
    ch = FakeCH()
    monkeypatch.setattr(main, "ch", ch)
    before = main.ARCHIVE_SLICES_DAMPED
    run(main._persist_snapshot(snap, 1, "open", window))
    grown = window + [sig("metric_anomaly", EntityType.DEVICE, "elsewhere-dev",
                          offset_s=12)]              # overlaps span, NOT component
    n_v1 = len(_archive_calls(ch))
    run(main._persist_snapshot(snap, 2, "open", grown))
    assert len(_archive_calls(ch)) == n_v1, "ambient growth must damp, not re-archive"
    assert main.ARCHIVE_SLICES_DAMPED == before + 1


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


# ── replay through the STORED rows: terminal versions, fallback, clipping ────
#
# The tests above call replay() over in-memory Signal lists. These three go
# through the actual persisted representation — FakeCH rows → Signal.from_ch_row
# → _select_slice — because the failure modes the 2026-08-22 reviews named
# (terminal versions, damped-version resolution, clipped nodes) live in that
# path, and no test exercised it end to end before.

from replay import _select_slice  # late import: section-local helper
from signals import Signal as _Sig  # late import: section-local helper


def _stored_rows(ch):
    """FakeCH archive rows, shaped as the ClickHouse reader would return them."""
    return [{k: v for k, v in r.items() if k != "_table"}
            for r in ch.rows if r["_table"] == "netops.corr_signals_archive"]


def _replay_stored(snap, version, state, ch):
    stored = StoredObject.from_rows(snap.to_object_row(version, state),
                                    snap.to_edge_rows(version))
    rows = _select_slice(_stored_rows(ch), version)
    return replay(stored, [_Sig.from_ch_row(r) for r in rows])


def test_terminal_version_replays_via_the_fallback(monkeypatch):
    """Both 2026-08-22 reviews flagged this as untested: a closed version
    persists with window=[] and NO slice of its own; replay must resolve the
    newest slice ≤ version and come back clean."""
    window, _ = _window()
    snap = _dallas_snapshot(window)
    ch = FakeCH()
    monkeypatch.setattr(main, "ch", ch)
    run(main._persist_snapshot(snap, 1, "open", window))
    n_open = len(_archive_calls(ch))
    run(main._persist_snapshot(snap, 2, "closed", []))       # terminal: no window
    assert len(_archive_calls(ch)) == n_open, "a terminal persist must archive nothing"
    report = _replay_stored(snap, 2, "closed", ch)
    assert report.engine_pin_match and report.catalog_pin_match
    assert report.clean, f"terminal-version replay drifted: {report.differences}"


def test_damped_version_replays_via_the_fallback(monkeypatch):
    """Rollback/fallback pin: v2 damped (same membership, no rows at v2) must
    resolve v1's slice and replay clean — the property old code relies on when
    reading new-format slices."""
    window, _ = _window()
    snap = _dallas_snapshot(window)
    ch = FakeCH()
    monkeypatch.setattr(main, "ch", ch)
    run(main._persist_snapshot(snap, 1, "open", window))
    run(main._persist_snapshot(snap, 2, "open", window))     # damped: no v2 rows
    assert not [r for r in _stored_rows(ch) if r["archived_version"] == 2]
    report = _replay_stored(snap, 2, "open", ch)
    assert report.clean, f"damped-version replay drifted: {report.differences}"


def test_clipping_a_component_node_is_replay_visible(monkeypatch):
    """Node-completeness mutation pin (storage review finding 15): an archive
    that stores only 'the signals attached to the object' instead of EVERY
    signal of every component node must not replay clean. Drop one signal of a
    two-signal component node and the drift report must say so."""
    window, _ = _window()
    grown = window + [sig("if_errors", EntityType.INTERFACE, "dallas-edge:Gi0/1",
                          offset_s=15)]              # node now holds two signals
    snap = _dallas_snapshot(grown)
    full = main._archive_slice(snap, grown)
    two_sig_node = [n for n in snap.nodes if len(n.signals) > 1]
    assert two_sig_node, "fixture must contain a multi-signal component node"
    victim = two_sig_node[0].signals[-1]
    clipped = [s for s in full if s.signal_id != victim.signal_id]
    stored = StoredObject.from_rows(snap.to_object_row(1, "open"),
                                    snap.to_edge_rows(1))
    report = replay(stored, clipped)
    assert not report.clean, (
        "a clipped component node replayed clean — node-completeness is no "
        "longer enforced by the replay contract")
