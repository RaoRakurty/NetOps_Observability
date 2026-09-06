# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""P3 change A — the HEARTBEAT TOUCH: corr_current freshness without a version.

WHAT IS UNDER TEST
    `main.CORR_HEARTBEAT_TOUCH_ONLY` (default ON). When an open object's
    `content_hash` moves, its `material_hash` does NOT, and
    `CORR_VERSION_HEARTBEAT_S` has elapsed, the engine writes ONE `corr_current`
    row at the SAME version instead of a whole new `corr_objects` version with
    its edges, evidence and archive slice.

WHY THAT IS SOUND (the claims these tests pin, not assert by assumption)
    1. The narrow projection row is BYTE-IDENTICAL to the columns the full
       Decision write would have produced — proved against `to_object_row` over
       every golden fixture, not against a hand-written expectation.
    2. The triage badges are byte-identical to the ones `_current_badges`
       extracts from the hypotheses blob — same fixtures.
    3. The projected VERSION always exists in `corr_objects`, so every
       (correlation_id, version) join in correlations.go / health_score.go still
       resolves.
    4. Material movement, terminal transitions and the keepalive floor still
       write full versions.
    5. Flag off reproduces the pre-P3 behaviour exactly.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from typing import ClassVar

import pytest

import main
from catalog import builtin_catalog
from engine import run_window
from golden_wire import GOLDEN_DIR, replay_fixture_through_engine
from signals import (
    EntityType,
    ModalityClass,
    Observer,
    ObserverType,
    Severity,
    Signal,
    Source,
)
from test_fixtures import fixture_files, signal_from_fixture

GOLDEN = sorted(p.name for p in GOLDEN_DIR.glob("*.json"))
# Every per-signature scenario fixture (the catalog's own CI corpus) replayed
# into real ObjectSnapshots: the widest set of REAL object shapes the repo has
# — every verdict tier, every owner, empty and populated coverage sets.
SIGNATURE_FIXTURES = list(fixture_files())


def _snaps_from_signature_fixture(path):
    import json
    data = json.loads(path.read_text())
    signals = [signal_from_fixture(s, i) for i, s in enumerate(data["signals"])]
    return run_window(tuple(signals), builtin_catalog(), ())


def _assert_narrow_row_matches(snap, label):
    for version, state in ((1, "open"), (7, "open"), (3, "closed")):
        full = snap.to_object_row(version, state)
        expected = {k: full[k] for k in main.CORR_CURRENT_FIELDS if k in full}
        assert main._current_row_fields(snap, version, state) == expected, (
            f"{label}: narrow projection row drifted from to_object_row "
            f"at v{version}/{state}")


# ── 1 + 2: the narrow builders are byte-identical to the full row ────────────

@pytest.mark.parametrize("fixture", GOLDEN)
def test_narrow_current_row_is_byte_identical_to_the_full_object_row(fixture, monkeypatch):
    """`_current_row_fields` must equal the CORR_CURRENT_FIELDS slice of
    `to_object_row`. This is the whole safety argument for skipping the row
    build: if it drifts by one key or one rounding, the projection silently
    diverges from history."""
    _sigs, snaps, _rank = replay_fixture_through_engine(fixture, monkeypatch)
    if not snaps:
        pytest.skip(f"{fixture} forms no object")
    for snap in snaps:
        _assert_narrow_row_matches(snap, fixture)


@pytest.mark.parametrize("path", SIGNATURE_FIXTURES, ids=lambda p: p.stem)
def test_narrow_current_row_matches_across_every_signature_shape(path):
    snaps = _snaps_from_signature_fixture(path)
    if not snaps:
        pytest.skip(f"{path.stem} forms no object")
    for snap in snaps:
        _assert_narrow_row_matches(snap, path.stem)


@pytest.mark.parametrize("fixture", GOLDEN)
def test_badges_from_snapshot_equal_badges_from_the_blob(fixture, monkeypatch):
    """`_current_badges_from_snapshot` must equal `_current_badges(blob)` — the
    touch reads the source objects instead of re-parsing their rendering."""
    _sigs, snaps, _rank = replay_fixture_through_engine(fixture, monkeypatch)
    if not snaps:
        pytest.skip(f"{fixture} forms no object")
    for snap in snaps:
        assert (main._current_badges_from_snapshot(snap)
                == main._current_badges(snap.hypotheses_blob())), (
            f"{fixture}: heartbeat badges drifted from the blob-derived badges")


@pytest.mark.parametrize("path", SIGNATURE_FIXTURES, ids=lambda p: p.stem)
def test_badges_match_across_every_signature_shape(path):
    snaps = _snaps_from_signature_fixture(path)
    if not snaps:
        pytest.skip(f"{path.stem} forms no object")
    for snap in snaps:
        assert (main._current_badges_from_snapshot(snap)
                == main._current_badges(snap.hypotheses_blob())), (
            f"{path.stem}: heartbeat badges drifted from the blob-derived badges")


def test_badges_agree_on_an_empty_ranking():
    """The degenerate case `_current_badges` handles with its except clause."""

    class _Ranking:
        hypotheses: ClassVar[list] = []

    class _NoHyps:
        ranking = _Ranking
        # 197: seam_type is read off the snapshot's embedded seams, not off the
        # ranking, so the degenerate stub has to carry the field a real
        # ObjectSnapshot always carries (an ungrounded object: empty tuple).
        seams: ClassVar[tuple] = ()

    assert main._current_badges_from_snapshot(_NoHyps()) == main._current_badges("not json")


# ── the engine-cycle behaviour ───────────────────────────────────────────────

class _StubCH:
    """Records inserts; stands in for the ClickHouse client in engine_cycle."""

    def __init__(self):
        self.rows: dict = {}

    async def insert(self, table: str, rows: list, dedup_token="") -> None:
        self.rows.setdefault(table, []).extend(rows)


def _sig(kind: str, entity_id: str, *, offset_s: float, now: datetime,
         severity: Severity = Severity.CRIT) -> Signal:
    return Signal(
        tenant_id="t1", ts=now + timedelta(seconds=offset_s), source=Source.METRIC,
        kind=kind, observer=Observer(observer_id="dev1", observer_type=ObserverType.DEVICE),
        modality_class=ModalityClass.DEVICE_TELEMETRY, entity_type=EntityType.DEVICE,
        entity_id=entity_id, severity=severity,
        native_id=f"hb|{kind}|{entity_id}|{offset_s}|{severity.value}",
        attrs={"onset_uncertainty_s": 5.0},
    )


@pytest.fixture
def engine(monkeypatch):
    """A stubbed engine with damping on, the touch on and the keepalive far
    away. Yields (stub, now)."""
    stub = _StubCH()
    monkeypatch.setattr(main, "ch", stub)
    monkeypatch.setattr(main, "OPEN_OBJECTS", {})
    monkeypatch.setattr(main, "CORR_VERSION_HEARTBEAT_S", 900.0)
    monkeypatch.setattr(main, "CORR_HEARTBEAT_TOUCH_ONLY", True)
    monkeypatch.setattr(main, "CORR_VERSION_KEEPALIVE_S", 21600.0)
    main.WINDOW_BUFFER.clear()
    main._BUFFERED_IDS.clear()
    try:
        yield stub, datetime.now(timezone.utc)
    finally:
        main.WINDOW_BUFFER.clear()
        main._BUFFERED_IDS.clear()


def _open_one(now):
    main.buffer_signal(_sig("link_state_change", "core-1", offset_s=-60, now=now))
    main.buffer_signal(_sig("device_resource_anomaly", "core-1", offset_s=-55, now=now))
    asyncio.run(main.engine_cycle())


def _elapse_heartbeat(now):
    (reg,) = main.OPEN_OBJECTS.values()
    reg["last_persist"] = now - timedelta(seconds=1000)
    return reg


def test_heartbeat_writes_corr_current_only(engine):
    stub, now = engine
    _open_one(now)
    assert len(stub.rows["netops.corr_objects"]) == 1
    edges0 = len(stub.rows.get("netops.corr_edges", []))
    evid0 = len(stub.rows.get("netops.corr_evidence", []))
    arch0 = len(stub.rows.get("netops.corr_signals_archive", []))
    current0 = len(stub.rows["netops.corr_current"])

    _elapse_heartbeat(now)
    main.buffer_signal(_sig("link_state_change", "core-1", offset_s=-10, now=now))
    asyncio.run(main.engine_cycle())

    assert len(stub.rows["netops.corr_objects"]) == 1, "no new version"
    assert len(stub.rows["netops.corr_current"]) == current0 + 1, "one fresh hot row"
    assert len(stub.rows.get("netops.corr_edges", [])) == edges0, "no edge rows"
    assert len(stub.rows.get("netops.corr_evidence", [])) == evid0, "no evidence rows"
    assert len(stub.rows.get("netops.corr_signals_archive", [])) == arch0, "no slice"


def test_the_touch_row_carries_the_fresh_window_and_counts(engine):
    """The heartbeat exists to bound how stale window_end / signal_count look —
    so the touched row must actually be fresher than the one before it."""
    stub, now = engine
    _open_one(now)
    before = dict(stub.rows["netops.corr_current"][-1])
    _elapse_heartbeat(now)
    main.buffer_signal(_sig("link_state_change", "core-1", offset_s=-10, now=now))
    asyncio.run(main.engine_cycle())
    after = stub.rows["netops.corr_current"][-1]
    assert after["window_end"] > before["window_end"], \
        "the touch must carry the moved window (that is its whole purpose)"
    assert after["signal_count"] >= before["signal_count"]
    assert set(after) == set(before), "the touch row's column set must not drift"


def test_the_touched_version_always_exists_in_history(engine):
    """correlations.go / health_score.go pick (correlation_id, version) FROM
    corr_current and join corr_edges/corr_objects on it. A projected version
    with no history row renders edge_count=0 on a live incident."""
    stub, now = engine
    _open_one(now)
    for _ in range(3):
        _elapse_heartbeat(now)
        main.buffer_signal(_sig("link_state_change", "core-1", offset_s=-10, now=now))
        asyncio.run(main.engine_cycle())
    hist = {(r["correlation_id"], r["version"]) for r in stub.rows["netops.corr_objects"]}
    proj = {(r["correlation_id"], r["version"]) for r in stub.rows["netops.corr_current"]}
    assert proj <= hist, f"projection points at versions history does not have: {proj - hist}"


def test_touch_counters_are_disjoint_from_persisted_and_damped(engine):
    _stub, now = engine
    _open_one(now)
    p0, d0, t0 = (main.VERSIONS_PERSISTED, main.VERSIONS_DAMPED,
                  main.VERSIONS_HEARTBEAT_TOUCHED)
    _elapse_heartbeat(now)
    main.buffer_signal(_sig("link_state_change", "core-1", offset_s=-10, now=now))
    asyncio.run(main.engine_cycle())
    assert main.VERSIONS_HEARTBEAT_TOUCHED == t0 + 1
    assert main.VERSIONS_PERSISTED == p0, "a touch is not a persisted version"
    assert main.VERSIONS_DAMPED == d0, "a touch is not a silent damp — it wrote"


def test_touch_is_counted_as_suppression_in_the_write_amp_rollup(engine):
    """`corr_tenant_write_amp` measures corr_objects amplification, so a touch
    belongs on the suppressed side of the ratio."""
    _stub, now = engine
    main.TENANT_WA.clear()
    _open_one(now)
    _elapse_heartbeat(now)
    main.buffer_signal(_sig("link_state_change", "core-1", offset_s=-10, now=now))
    asyncio.run(main.engine_cycle())
    slot = main.TENANT_WA["t1"]
    assert slot["heartbeat_touch"] == 1
    assert slot["persisted"] == 1
    assert slot["damped"] == 0
    main.TENANT_WA.clear()


def test_material_movement_still_writes_a_full_version(engine):
    """A WARN→CRIT escalation of the same evidence moves material_hash: it must
    version even though the heartbeat has not elapsed."""
    stub, now = engine
    main.buffer_signal(_sig("link_state_change", "core-2", offset_s=-60, now=now,
                            severity=Severity.WARN))
    main.buffer_signal(_sig("device_resource_anomaly", "core-2", offset_s=-58, now=now,
                            severity=Severity.WARN))
    asyncio.run(main.engine_cycle())
    assert len(stub.rows["netops.corr_objects"]) == 1
    main.buffer_signal(_sig("link_state_change", "core-2", offset_s=-20, now=now,
                            severity=Severity.CRIT))
    asyncio.run(main.engine_cycle())
    rows = stub.rows["netops.corr_objects"]
    assert len(rows) == 2, "a material move must never be served by a touch"
    assert rows[-1]["version"] == 2
    assert len(stub.rows.get("netops.corr_edges", [])) > 0


def test_terminal_close_still_writes_a_full_version(engine, monkeypatch):
    stub, now = engine
    _open_one(now)
    main.WINDOW_BUFFER.clear()
    main._BUFFERED_IDS.clear()
    monkeypatch.setattr(main, "CORR_QUIESCE_S", 0.0)
    asyncio.run(main.engine_cycle())
    rows = stub.rows["netops.corr_objects"]
    assert len(rows) == 2 and rows[-1]["state"] == "closed", \
        "terminal transitions are never damped and never touched"
    assert stub.rows["netops.corr_current"][-1]["state"] == "closed"


def test_keepalive_forces_a_full_version_for_a_never_moving_object(engine, monkeypatch):
    """The corr_objects TTL, the 24 h app_impact decorate window and the 7-day
    drift lookback all key on corr_objects.created_at, so an open object that
    never moves materially must still land a full version eventually."""
    stub, now = engine
    monkeypatch.setattr(main, "CORR_VERSION_KEEPALIVE_S", 100.0)
    _open_one(now)
    reg = _elapse_heartbeat(now)
    reg["last_version"] = now - timedelta(seconds=1000)
    main.buffer_signal(_sig("link_state_change", "core-1", offset_s=-10, now=now))
    asyncio.run(main.engine_cycle())
    rows = stub.rows["netops.corr_objects"]
    assert len(rows) == 2, "the keepalive floor must write a REAL version"
    assert rows[-1]["version"] == 2
    assert len(stub.rows.get("netops.corr_edges", [])) > 0, \
        "a keepalive version carries its evidence like any other version"


def test_touch_does_not_reset_the_keepalive_clock(engine, monkeypatch):
    _stub, now = engine
    _open_one(now)
    (reg,) = main.OPEN_OBJECTS.values()
    opened_version_at = reg["last_version"]
    _elapse_heartbeat(now)
    main.buffer_signal(_sig("link_state_change", "core-1", offset_s=-10, now=now))
    asyncio.run(main.engine_cycle())
    (reg,) = main.OPEN_OBJECTS.values()
    assert reg["last_version"] == opened_version_at, \
        "a touch must not pretend a version landed, or the keepalive never fires"
    assert reg["last_persist"] > opened_version_at, "but it does pace the heartbeat"


def test_flag_off_reproduces_the_full_heartbeat_version(engine, monkeypatch):
    stub, now = engine
    monkeypatch.setattr(main, "CORR_HEARTBEAT_TOUCH_ONLY", False)
    _open_one(now)
    _elapse_heartbeat(now)
    main.buffer_signal(_sig("link_state_change", "core-1", offset_s=-10, now=now))
    asyncio.run(main.engine_cycle())
    rows = stub.rows["netops.corr_objects"]
    assert len(rows) == 2 and rows[-1]["version"] == 2
    assert main.VERSIONS_HEARTBEAT_TOUCHED == main.VERSIONS_HEARTBEAT_TOUCHED


def test_damping_off_is_unaffected_by_the_touch_flag(engine, monkeypatch):
    """CORR_VERSION_HEARTBEAT_S=0 is 'damping off, persist every content change'.
    The touch must never intercept it — the legacy knob keeps its meaning."""
    stub, now = engine
    monkeypatch.setattr(main, "CORR_VERSION_HEARTBEAT_S", 0.0)
    _open_one(now)
    main.buffer_signal(_sig("link_state_change", "core-1", offset_s=-10, now=now))
    asyncio.run(main.engine_cycle())
    assert len(stub.rows["netops.corr_objects"]) == 2


def test_replay_still_resolves_a_slice_for_every_projected_version(engine):
    """Replay pins on `corr_objects` versions and resolves the newest archive
    slice `<= version` (replay._select_slice). A touch mints no version, so it
    can lose no pin — but assert it, rather than assert it away."""
    from replay import _select_slice

    stub, now = engine
    _open_one(now)
    for _ in range(3):
        _elapse_heartbeat(now)
        main.buffer_signal(_sig("link_state_change", "core-1", offset_s=-10, now=now))
        asyncio.run(main.engine_cycle())
    archive = stub.rows.get("netops.corr_signals_archive", [])
    versions = [r["version"] for r in stub.rows["netops.corr_objects"]]
    assert archive, "the opening version archived its slice"
    assert {int(r["archived_version"]) for r in archive} <= set(versions), \
        "no archive slice may reference a version history does not have"
    for v in versions:
        assert _select_slice(archive, v), f"replay of v{v} resolved an empty slice"


def test_broken_source_soak_touches_instead_of_re_versioning(engine):
    """The lane-soak shape (test_lane_soak.py) with a heartbeat that actually
    elapses: ONE corr_objects version, one corr_current row per heartbeat.
    Replaces the pre-P3 `current_rows == object_rows` identity."""
    stub, now = engine
    _open_one(now)
    for i in range(6):
        _elapse_heartbeat(now)
        main.buffer_signal(_sig("link_state_change", "core-1",
                                offset_s=-50 + i * 5, now=now))
        asyncio.run(main.engine_cycle())
    objects = stub.rows["netops.corr_objects"]
    current = stub.rows["netops.corr_current"]
    assert len(objects) == 1, "6 heartbeats on unchanged material wrote 6 versions"
    assert len(current) == 7, "each heartbeat still refreshed the hot projection"
    assert {r["version"] for r in current} == {1}


def test_the_byte_identity_test_would_catch_a_drifting_narrow_row(monkeypatch):
    """MUTANT. If `_current_row_fields` silently dropped or altered a column,
    the byte-identity test above must go RED — otherwise it proves nothing."""
    _sigs, snaps, _rank = replay_fixture_through_engine(GOLDEN[0], monkeypatch)
    snap = next((s for s in snaps), None)
    if snap is None:
        pytest.skip("no object in the first golden fixture")
    real = main._current_row_fields

    def mutant(sn, version, state):
        row = real(sn, version, state)
        row["signal_count"] = row["signal_count"] + 1     # a plausible off-by-one
        return row

    monkeypatch.setattr(main, "_current_row_fields", mutant)
    with pytest.raises(AssertionError):
        _assert_narrow_row_matches(snap, "mutant")


def test_the_badge_test_would_catch_a_drifting_badge(monkeypatch):
    """MUTANT for the badge equivalence."""
    _sigs, snaps, _rank = replay_fixture_through_engine(GOLDEN[0], monkeypatch)
    snap = next((s for s in snaps), None)
    if snap is None:
        pytest.skip("no object in the first golden fixture")
    monkeypatch.setattr(main, "_current_badges_from_snapshot",
                        lambda sn: {"owner": "wrong", "plane_count": 99,
                                    "debug_excluded": 1, "low_authority": 1})
    assert (main._current_badges_from_snapshot(snap)
            != main._current_badges(snap.hypotheses_blob()))
