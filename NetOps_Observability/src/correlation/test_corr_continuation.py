"""#111 engine churn root cause — an ongoing condition must EXTEND its open
correlation object (identity adoption + version bumps), never create-then-merge
a new object each sweep. Pre-fix, every sweep after the incident's earliest
signal aged out of the sliding window minted a NEW object and tombstoned the
open one into it (state='merged', ~13/min on one sustained signature, ~20M
corr_signals_archive rows/day).

Pure half:        engine.find_continuation (the persistence-side twin of
                  find_merges — same overlap criterion, tenant-guarded).
Integration half: main.engine_cycle across sweeps under a controlled clock,
                  against the stub-CH harness (test_lane_soak pattern) —
                  ongoing condition x N sweeps => ONE open object, ZERO
                  'merged' tombstones; distinct conditions stay distinct.
Replay half:      an adopted-identity version still replays (matched by its
                  trigger signal — #101 contract preserved).
"""

import asyncio
import dataclasses
import json
from datetime import datetime, timedelta, timezone

import main
from catalog import builtin_catalog
from engine import find_continuation, run_window
from replay import StoredObject, replay
from signals import EntityType, Severity
from test_engine import _obj, sig
from test_lane_soak import _StubCH, lane_signal

# ── pure: find_continuation ───────────────────────────────────────────────────


def test_continuation_adopts_same_incident():
    # Same entities, overlapping windows: the re-keyed snapshot continues the
    # open object — its id is adopted, no new object, no tombstone.
    open_obj = _obj(["leaf1", "spine1"], "old", 0, 4)
    rekeyed = _obj(["leaf1", "spine1"], "new", 2, 7)
    assert find_continuation(rekeyed, [open_obj]) == "old"


def test_continuation_ignores_disjoint_entities():
    open_obj = _obj(["leaf1", "spine1"], "old", 0, 5)
    other = _obj(["wan1", "dmz1"], "new", 0, 5)
    assert find_continuation(other, [open_obj]) == ""  # genuinely new incident


def test_continuation_below_overlap_threshold_is_new():
    open_obj = _obj(["leaf1", "spine1", "leaf2"], "old", 0, 5)
    weak = _obj(["leaf1", "wan1", "dmz1", "dmz2"], "new", 0, 5)  # 1/6 ≈ 0.17
    assert find_continuation(weak, [open_obj]) == ""


def test_continuation_requires_window_overlap():
    open_obj = _obj(["leaf1", "spine1"], "old", 0, 5)
    later = _obj(["leaf1", "spine1"], "new", 100, 105)  # disjoint window
    assert find_continuation(later, [open_obj]) == ""


def test_continuation_never_crosses_tenants():
    # §3a default-closed: identical entities in ANOTHER tenant are never the
    # same incident — a snapshot cannot adopt a cross-tenant identity.
    foreign = dataclasses.replace(
        _obj(["leaf1", "spine1"], "old", 0, 5), tenant_id="tenant-b")
    rekeyed = _obj(["leaf1", "spine1"], "new", 2, 7)
    assert find_continuation(rekeyed, [foreign]) == ""


def test_continuation_deterministic_and_order_invariant():
    a = _obj(["leaf1", "spine1"], "aaa", 0, 5)   # earliest window
    b = _obj(["leaf1", "spine1"], "bbb", 1, 6)
    rekeyed = _obj(["leaf1", "spine1"], "new", 2, 7)
    assert (find_continuation(rekeyed, [a, b])
            == find_continuation(rekeyed, [b, a]) == "aaa")


# ── integration: engine_cycle across sweeps ───────────────────────────────────


class _Clock(datetime):
    """Controllable module clock — engine_cycle's datetime.now() under test."""

    current: datetime = datetime.now(timezone.utc)

    @classmethod
    def now(cls, tz=None):  # signature mirrors datetime.now
        return cls.current if tz is not None else cls.current.replace(tzinfo=None)


def _run_sweeps(monkeypatch, sweeps, heartbeat_s: float = 60.0):
    """Run one engine_cycle per (at, signals) sweep against a stub ClickHouse.
    Returns (stub, final OPEN_OBJECTS registry)."""
    stub = _StubCH()
    monkeypatch.setattr(main, "ch", stub)
    monkeypatch.setattr(main, "OPEN_OBJECTS", {})
    monkeypatch.setattr(main, "CORR_VERSION_HEARTBEAT_S", heartbeat_s)
    monkeypatch.setattr(main, "datetime", _Clock)
    main.WINDOW_BUFFER.clear()
    main._BUFFERED_IDS.clear()
    try:
        for at, signals in sweeps:
            _Clock.current = at
            for s in signals:
                main.buffer_signal(s)
            asyncio.run(main.engine_cycle())
        return stub, dict(main.OPEN_OBJECTS)
    finally:
        main.WINDOW_BUFFER.clear()
        main._BUFFERED_IDS.clear()


def _pair(dev: str, base: datetime, off: float) -> list:
    """The minimal object-forming evidence pair (same-device containment)."""
    return [
        lane_signal("link_state_change", dev, offset_s=off, now=base),
        lane_signal("device_resource_anomaly", dev, offset_s=off + 2, now=base),
    ]


def _h(fraction: float) -> float:
    """An offset expressed as a FRACTION of the derived retention horizon.

    These fixtures used to hard-code offsets against the retired 900 s
    `window_s` (-880 = "just inside the back of the window", +480 = "far enough
    that the onset has aged out"). Retention is now derived from the engine's
    scoring reach, so the geometry is expressed relative to
    RETENTION_REQUIRED_S and follows it automatically — pinning fresh constants
    here would just recreate the drift tracker 165 removed.
    """
    return round(fraction * main.RETENTION_REQUIRED_S, 3)


def test_ongoing_condition_is_one_object_zero_tombstones(monkeypatch):
    """The #111 storm shape: a condition that keeps emitting while its onset
    ages out of the retention horizon. Pre-fix: new object + merged tombstone
    per sweep. Post-fix: ONE object, version bumps, zero tombstones."""
    base = datetime.now(timezone.utc).replace(microsecond=0)
    sweeps = [
        # sweep 1: onset near the back of the horizon + a mid-window refresh.
        (base, _pair("churn-dev-1", base, -_h(0.978))
         + _pair("churn-dev-1", base, -_h(0.433))),
        # sweep 2: the stream has moved far enough that the onset signals are
        # expired — the SAME condition re-keys under a new windowed id. It must
        # adopt, not merge.
        (base + timedelta(seconds=_h(0.556)),
         _pair("churn-dev-1", base, _h(0.533))),
        # sweep 3: still ongoing.
        (base + timedelta(seconds=_h(0.889)),
         _pair("churn-dev-1", base, _h(0.867))),
    ]
    stub, open_objects = _run_sweeps(monkeypatch, sweeps)
    rows = stub.rows["netops.corr_objects"]
    assert all(r["state"] != "merged" for r in rows), \
        f"churn regression: merged tombstones persisted: {rows}"
    assert len({r["correlation_id"] for r in rows}) == 1, \
        "an ongoing condition must keep ONE identity across sweeps"
    assert len(open_objects) == 1
    versions = [r["version"] for r in rows]
    assert versions == sorted(set(versions)), "versions must bump monotonically"
    assert versions[-1] >= 2, "continuation must version the SAME object"
    assert all(r["state"] == "open" for r in rows)


def test_distinct_conditions_keep_distinct_objects(monkeypatch):
    """Adoption must never conflate genuinely different incidents: two devices'
    conditions stay two objects across a re-keying sweep, each keeping its own
    identity, still zero tombstones."""
    base = datetime.now(timezone.utc).replace(microsecond=0)
    sweeps = [
        (base,
         _pair("churn-dev-a", base, -_h(0.978)) + _pair("churn-dev-a", base, -_h(0.433))
         + _pair("churn-dev-b", base, -_h(0.973)) + _pair("churn-dev-b", base, -_h(0.429))),
        (base + timedelta(seconds=_h(0.556)),
         _pair("churn-dev-a", base, _h(0.533)) + _pair("churn-dev-b", base, _h(0.538))),
    ]
    stub, open_objects = _run_sweeps(monkeypatch, sweeps)
    rows = stub.rows["netops.corr_objects"]
    assert all(r["state"] != "merged" for r in rows)
    cids = {r["correlation_id"] for r in rows}
    assert len(cids) == 2, "two distinct conditions must remain two objects"
    assert len(open_objects) == 2
    # Each identity's affected devices never mix.
    devs_by_cid = {c: {d for r in rows if r["correlation_id"] == c
                       for d in json.loads(r["affected"]).get("devices", [])}
                   for c in cids}
    assert all(len(devs) == 1 for devs in devs_by_cid.values()), devs_by_cid


def test_new_incident_after_quiet_gap_is_a_new_object(monkeypatch):
    """No window overlap ⇒ no continuation: a recurrence after a real gap is a
    NEW incident (the old object quiesce-closes), not an adoption."""
    base = datetime.now(timezone.utc).replace(microsecond=0)
    gap = 2000  # > RETENTION_REQUIRED_S (~427) and > CORR_QUIESCE_S (900)
    sweeps = [
        (base, _pair("churn-dev-q", base, -60)),
        (base + timedelta(seconds=gap), _pair("churn-dev-q", base, gap - 60)),
    ]
    stub, open_objects = _run_sweeps(monkeypatch, sweeps)
    rows = stub.rows["netops.corr_objects"]
    assert all(r["state"] != "merged" for r in rows)
    assert len({r["correlation_id"] for r in rows}) == 2, \
        "a post-gap recurrence is a new incident, never an adoption"
    states = {r["correlation_id"]: [x["state"] for x in rows
                                    if x["correlation_id"] == r["correlation_id"]]
              for r in rows}
    assert any("closed" in v for v in states.values()), "old object must quiesce-close"
    assert len(open_objects) == 1


# ── replay: an adopted-identity version still replays (#101 contract) ─────────


def test_replay_matches_adopted_identity_by_trigger_signal():
    window = [
        sig("link_state_change", EntityType.DEVICE, "rp-dev-1", severity=Severity.CRIT),
        sig("device_resource_anomaly", EntityType.DEVICE, "rp-dev-1",
            severity=Severity.CRIT, offset_s=1),
    ]
    snap = run_window(window, builtin_catalog(), ())[0]
    # Persist under an ADOPTED id (what engine_cycle does for a continuation):
    # run_window over the archived window derives the raw windowed id, so the
    # id match fails — the trigger signal must re-identify the object cleanly.
    adopted = dataclasses.replace(snap, correlation_id="11111111-1111-1111-1111-111111111111")
    stored = StoredObject.from_rows(adopted.to_object_row(3), adopted.to_edge_rows(3))
    report = replay(stored, window)
    assert report.clean, f"adopted identity must replay clean, got {report.differences}"


def test_replay_still_reports_a_truly_absent_object():
    window = [
        sig("link_state_change", EntityType.DEVICE, "rp-dev-2", severity=Severity.CRIT),
        sig("device_resource_anomaly", EntityType.DEVICE, "rp-dev-2",
            severity=Severity.CRIT, offset_s=1),
    ]
    snap = run_window(window, builtin_catalog(), ())[0]
    tampered = dataclasses.replace(
        snap, correlation_id="22222222-2222-2222-2222-222222222222",
        trigger_signal="not-a-signal-in-any-recomputed-object")
    stored = StoredObject.from_rows(tampered.to_object_row(1), tampered.to_edge_rows(1))
    report = replay(stored, window)
    assert not report.clean
    assert any("none with the stored id" in d for d in report.differences)
