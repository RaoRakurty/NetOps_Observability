"""Tracker 187 — an object's FINAL `affected` may not shrink below its own
version history.

THE DEFECT, measured 2026-08-30 on the 2.5K P3 pair (docs/scale/
P3_PAIR_2P5K_VERDICT_2026-08-30.md §3 + the tracker row): 3-5 `bgp_peer_flap`
stories per 1,005-story leg where the only object touching the story names the
peer but not the cause device — and the SAME story ids fail on BOTH arms, so it
is deterministic engine behaviour, not run variance. Root read on I0169 (object
`5e0b760a`): versions 1-4 (`open`) DO name the cause device; version 6
(`closed`) drops it. Attribution is lost at CLOSE, not at formation.

THE MECHANISM: `ObjectSnapshot.affected()` is a pure projection of `self.nodes`,
and the nodes are whatever the ENGINE WINDOW still holds. Every terminal persist
(`_epoch_lifecycle`'s quiesce close, the tracker-163 count-cap close, and the
lifecycle merge tombstone) writes `reg["snapshot"]` — the LATEST snapshot, whose
nodes have already shrunk as the cause's evidence aged out of the window. An
object quiesces precisely BECAUSE its evidence stopped arriving, so the shrink
and the close are the same event.

THE RULE PINNED HERE: a terminal version publishes the union of every version
the object actually PERSISTED, including its own; non-terminal versions are
untouched (a shrinking radius mid-flight is honest reporting of the current
view, and only the FINAL word is claimed to be monotone). The union is per
OBJECT — a merge never pools two objects' radii — and it is bounded, sorted and
order-independent, so a replay renders byte-identical rows.

WHAT EACH TEST OWES THE FIX:
  * `test_quiesce_close_republishes_the_aged_out_entity` — the end-to-end
    reproduction through `main.engine_cycle`, with the PRE-FIX value computed
    in-test as its own oracle (it is the last open version's row): pre-fix the
    terminal row equals it, post-fix it is a strict superset.
  * `test_cap_close_applies_the_union` / `test_merge_close_applies_the_union` /
    the quiesce test above — one per TERMINAL PATH; all three are enumerated
    from `_epoch_lifecycle`, and `test_terminal_paths_are_the_three_covered`
    fails if a fourth ever appears.
  * `test_open_versions_are_byte_identical_to_the_projection` — the oracle
    equivalence over a randomized corpus: no non-terminal version moves.
  * `test_adoption_carries_the_accumulator` — the continuation re-key.
  * `test_terminal_row_is_the_order_independent_union_of_its_own_history` —
    determinism, against an independent oracle recomputed from the recorded
    rows; `test_override_does_not_move_content_hash` is the replay-pin half.
  * `test_accumulator_is_bounded_by_the_lifetime_population` + the cap tests —
    the stated bound, and defined behaviour at it.
"""
from __future__ import annotations

import asyncio
import json
import random
from datetime import datetime, timedelta, timezone

import pytest

import main
from engine import AffectedHistory, EngineConfig, run_window
from signals import EntityType
from test_archive_slice import CAT
from test_corr_continuation import _Clock
from test_lane_soak import _StubCH, lane_signal

T0 = datetime(2026, 8, 30, 12, 0, 0, tzinfo=timezone.utc)
IFACE = {"entity_type": EntityType.INTERFACE}


def run(coro):
    return asyncio.run(coro)


def _aff(row: dict) -> dict:
    return json.loads(row["affected"])


# ── the pure accumulator ─────────────────────────────────────────────────────


def test_history_is_monotone_and_order_independent():
    """The union is a SET operation: the same versions in any arrival order
    produce the same accumulator, and nothing ever leaves it."""
    versions = [
        {"devices": ["cause-1", "peer-1"], "interfaces": ["cause-1:Gi0/1"]},
        {"devices": ["peer-1"]},
        {"devices": ["peer-1", "peer-2"]},
    ]
    expected = {"devices": ["cause-1", "peer-1", "peer-2"],
                "interfaces": ["cause-1:Gi0/1"]}
    for order in ([0, 1, 2], [2, 1, 0], [1, 2, 0], [1, 0, 2]):
        h = AffectedHistory()
        for i in order:
            h.note(versions[i])
        assert h.merged_with({}) == expected, order


def test_history_never_pools_two_objects():
    """§3a-adjacent, and the reason the accumulator lives on the registration:
    one object's history can never widen another's blast radius."""
    a, b = AffectedHistory(), AffectedHistory()
    a.note({"devices": ["a-dev"]})
    b.note({"devices": ["b-dev"]})
    assert a.merged_with({}) == {"devices": ["a-dev"]}
    assert b.merged_with({}) == {"devices": ["b-dev"]}


def test_history_drops_empty_buckets_and_sorts_members():
    h = AffectedHistory()
    h.note({"devices": ["z", "a"], "sites": []})
    assert h.merged_with({"devices": ["m"], "paths": []}) == {"devices": ["a", "m", "z"]}


def test_history_entity_count_is_the_distinct_population():
    h = AffectedHistory()
    h.note({"devices": ["a", "b"], "interfaces": ["a:Gi0"]})
    h.note({"devices": ["a", "b", "c"]})          # 'a'/'b' are not counted twice
    assert h.entity_count() == 4


def test_history_cap_is_declared_and_counted():
    """Behaviour AT the bound is defined, never silent — and it drops the
    NEWEST, because the terminal version unions the accumulator with the live
    projection anyway, so only genuinely-aged-out history can ever be lost."""
    h = AffectedHistory(max_entities=2)
    h.note({"devices": ["a", "b", "c", "d"]})
    assert h.entity_count() == 2 and h.truncated == 2
    # the live projection still lands in the final row despite the truncation
    assert h.merged_with({"devices": ["live"]}) == {"devices": ["a", "b", "live"]}


def test_history_cap_disabled_is_unbounded_by_count():
    h = AffectedHistory(max_entities=0)
    h.note({"devices": [f"d{i}" for i in range(500)]})
    assert h.entity_count() == 500 and h.truncated == 0


# ── the row builder's pass-through ───────────────────────────────────────────


def _snap(entities: list[tuple[str, str]], *, offset: float = 0.0):
    """One real snapshot over `entities` — (kind, entity_id) device signals."""
    window = tuple(
        lane_signal(kind, ent, offset_s=offset + i, now=T0)
        for i, (kind, ent) in enumerate(entities))
    return run_window(window, CAT, (), EngineConfig())[0]


def test_to_object_row_default_is_the_live_projection():
    snap = _snap([("link_state_change", "row-dev"),
                  ("device_resource_anomaly", "row-dev")])
    row = snap.to_object_row(1, "open")
    assert _aff(row) == snap.affected()


def test_to_object_row_override_is_normalized_and_deterministic():
    """The override is sorted and empty-bucket-stripped HERE, so the column is a
    deterministic function of the accumulated SET whatever order it arrived in."""
    snap = _snap([("link_state_change", "row-dev"),
                  ("device_resource_anomaly", "row-dev")])
    a = snap.to_object_row(2, "closed",
                           affected={"devices": ["z", "a"], "sites": []})
    b = snap.to_object_row(2, "closed",
                           affected={"sites": (), "devices": ("a", "z")})
    assert a["affected"] == b["affected"] == '{"devices":["a","z"]}'


def test_override_does_not_move_content_hash():
    """`affected` is a PROJECTION column, never part of the replay pin — so the
    terminal version's new content changes the row and nothing else."""
    snap = _snap([("link_state_change", "hash-dev"),
                  ("device_resource_anomaly", "hash-dev")])
    before = snap.content_hash()
    snap.to_object_row(2, "closed", affected={"devices": ["hash-dev", "extra"]})
    assert snap.content_hash() == before


# ── the reproduction, end to end through engine_cycle ─────────────────────────

@pytest.fixture
def cycles(monkeypatch):
    """A stub-CH engine harness under a controlled clock (the test_lane_soak /
    test_corr_continuation pattern). Yields (feed, stub)."""
    stub = _StubCH()
    monkeypatch.setattr(main, "ch", stub)
    monkeypatch.setattr(main, "OPEN_OBJECTS", {})
    monkeypatch.setattr(main, "CORR_VERSION_HEARTBEAT_S", 1.0)
    monkeypatch.setattr(main, "CORR_HEARTBEAT_TOUCH_ONLY", False)
    monkeypatch.setattr(main, "datetime", _Clock)
    main.WINDOW_BUFFER.clear()
    main._BUFFERED_IDS.clear()
    main._ARCHIVE_SLICE_HASH.clear()

    def feed(at, signals=(), *, drain_window: bool = False):
        if drain_window:
            # retention has aged the whole window out: the object stops
            # materializing, which is the precondition quiesce waits on.
            main.WINDOW_BUFFER.clear()
            main._BUFFERED_IDS.clear()
        _Clock.current = at
        for s in signals:
            main.buffer_signal(s)
        run(main.engine_cycle())

    try:
        yield feed, stub
    finally:
        main.WINDOW_BUFFER.clear()
        main._BUFFERED_IDS.clear()
        main._ARCHIVE_SLICE_HASH.clear()


def _aging_incident(base, H):
    """The measured shape: an incident whose CAUSE-side evidence (the interface)
    stops arriving while the symptom side (the device) keeps refreshing, so the
    cause node ages out of the window while the object stays open and is
    ADOPTED under a re-keyed id — exactly the I0169 history."""
    return [
        (base, [
            lane_signal("link_state_change", "cause-dev:Gi0/1",
                        offset_s=-0.95 * H, now=base, **IFACE),
            lane_signal("if_errors", "cause-dev:Gi0/1",
                        offset_s=-0.60 * H, now=base, **IFACE),
            lane_signal("device_resource_anomaly", "cause-dev",
                        offset_s=-0.94 * H, now=base),
            lane_signal("link_state_change", "cause-dev",
                        offset_s=-0.30 * H, now=base),
            lane_signal("device_resource_anomaly", "cause-dev",
                        offset_s=-0.20 * H, now=base),
        ]),
        (base + timedelta(seconds=0.5 * H), [
            lane_signal("link_state_change", "cause-dev",
                        offset_s=0.45 * H, now=base),
            lane_signal("device_resource_anomaly", "cause-dev",
                        offset_s=0.46 * H, now=base),
        ]),
    ]


def test_quiesce_close_republishes_the_aged_out_entity(cycles):
    """TERMINAL PATH 1/3 — quiesce, the path the defect was measured on.

    The oracle is computed in-test and needs no fixture: the PRE-FIX terminal
    `affected` is exactly the last OPEN version's, because both render the same
    `reg["snapshot"]` projection. Pre-fix the two rows are equal; post-fix the
    terminal row is a strict superset that restores the aged-out entity.
    """
    feed, stub = cycles
    base = datetime.now(timezone.utc).replace(microsecond=0)
    H = main.RETENTION_REQUIRED_S
    for at, signals in _aging_incident(base, H):
        feed(at, signals)
    feed(base + timedelta(seconds=0.5 * H + main.CORR_QUIESCE_S + 60),
         drain_window=True)

    rows = stub.rows["netops.corr_objects"]
    assert len({r["correlation_id"] for r in rows}) == 1, \
        "the fixture must exercise ONE adopted identity, not a re-mint"
    opens = [r for r in rows if r["state"] == "open"]
    closed = [r for r in rows if r["state"] == "closed"]
    assert len(opens) >= 2 and len(closed) == 1, [r["state"] for r in rows]

    first, last_open, terminal = _aff(opens[0]), _aff(opens[-1]), _aff(closed[0])
    # the shrink is real: the cause node aged out while the object stayed open
    assert "cause-dev:Gi0/1" in first["interfaces"]
    assert "interfaces" not in last_open, \
        "fixture drift: the cause node never aged out of the window"
    # PRE-FIX ORACLE: the terminal row would be the last open row, verbatim.
    assert terminal != last_open, "the close still publishes the shrunken window"
    # POST-FIX: monotone over the object's own history, in every bucket.
    assert terminal["interfaces"] == ["cause-dev:Gi0/1"]
    for bucket, members in first.items():
        assert set(members) <= set(terminal.get(bucket, ())), bucket
    for bucket, members in last_open.items():
        assert set(members) <= set(terminal.get(bucket, ())), bucket

    # AND it must reach `corr_current`, which is what every reader of "the
    # object's blast radius" actually queries (the twin scorer's
    # `affected_includes` reads corr_current FINAL, i.e. the CURRENT version).
    # The projection is sliced from the same row, so this is a wiring pin.
    current = [r for r in stub.rows["netops.corr_current"]
               if r["state"] == "closed"]
    assert len(current) == 1
    assert _aff(current[0]) == terminal


def test_adoption_carries_the_accumulator(cycles):
    """The registration dict is what `find_continuation`'s re-key reuses
    (`OPEN_OBJECTS[cont]`), so the adopted identity keeps the history it
    accumulated under its own id. Asserted on the LIVE registry, before the
    close consumes it."""
    feed, _stub = cycles
    base = datetime.now(timezone.utc).replace(microsecond=0)
    H = main.RETENTION_REQUIRED_S
    sweeps = _aging_incident(base, H)
    feed(*sweeps[0])
    (reg,) = main.OPEN_OBJECTS.values()
    hist_obj = reg["affected_hist"]
    assert "cause-dev:Gi0/1" in hist_obj.merged_with({})["interfaces"]

    feed(*sweeps[1])
    (reg2,) = main.OPEN_OBJECTS.values()
    assert reg2["version"] > 1, "the fixture must ADOPT, not re-mint"
    assert reg2["affected_hist"] is hist_obj, \
        "the re-key must carry the accumulator, not restart it"
    assert "cause-dev:Gi0/1" in reg2["affected_hist"].merged_with({})["interfaces"], \
        "the adopted object lost the history accumulated under its own id"


def test_terminal_row_is_the_order_independent_union_of_its_own_history(cycles):
    """DETERMINISM + the union's independent oracle in one.

    The terminal row is recomputed here from the object's RECORDED open rows —
    the history, as persisted — and it must match byte-for-byte. Folded in
    forward order and in reverse it must produce the same bytes, which is the
    property that makes a replay of the same history hash identically: the
    accumulator is a set and the render is sorted.
    """
    feed, stub = cycles
    base = datetime.now(timezone.utc).replace(microsecond=0)
    H = main.RETENTION_REQUIRED_S
    for at, signals in _aging_incident(base, H):
        feed(at, signals)
    feed(base + timedelta(seconds=0.5 * H + main.CORR_QUIESCE_S + 60),
         drain_window=True)

    rows = stub.rows["netops.corr_objects"]
    opens = [r for r in rows if r["state"] == "open"]
    terminal = next(r for r in rows if r["state"] == "closed")

    forward, reverse = AffectedHistory(), AffectedHistory()
    for row in opens:
        forward.note(_aff(row))
    for row in reversed(opens):
        reverse.note(_aff(row))
    # the terminal version's OWN projection is the last open row's here (both
    # render the same reg["snapshot"]) — that is the pre-fix value.
    own = _aff(opens[-1])
    assert forward.merged_with(own) == reverse.merged_with(own)
    assert _aff(terminal) == forward.merged_with(own), \
        "the terminal row is not the union over this object's persisted history"
    assert json.dumps(_aff(terminal), separators=(",", ":"), sort_keys=True) == \
        terminal["affected"], "the column must be canonically serialized"


# ── the other two terminal paths, on the lifecycle pass ──────────────────────

def _register(cid_snaps, *, history: dict | None = None, last_seen=None):
    """Hand-built registrations, the tracker-163 test's pattern, plus the 187
    accumulator pre-loaded with a version this object once persisted."""
    main.OPEN_OBJECTS.clear()
    main._ARCHIVE_SLICE_HASH.clear()
    for i, snap in enumerate(cid_snaps):
        hist = AffectedHistory(main.CORR_AFFECTED_HISTORY_MAX)
        hist.note(snap.affected())
        if history:
            hist.note(history)
        main.OPEN_OBJECTS[snap.correlation_id] = {
            "version": 1, "hash": f"h{i}", "material": f"m{i}",
            "last_seen": (last_seen or T0) + timedelta(seconds=i),
            "last_persist": T0, "snapshot": snap, "opened_at": T0,
            "affected_hist": hist,
        }
    return list(main.OPEN_OBJECTS)


class _RecordingCH:
    def __init__(self):
        self.objects: list[dict] = []

    async def insert_detailed(self, table, rows, dedup_token=""):
        rows = list(rows)
        if table == "netops.corr_objects":
            self.objects.extend(rows)
        return main.InsertOutcome(committed=True, kind="committed", rows=len(rows))


@pytest.fixture
def lifecycle(monkeypatch):
    """An engine cycle over an EMPTY window: only the lifecycle sweeps run."""
    main.WINDOW_BUFFER.clear()
    main._BUFFERED_IDS.clear()
    main._BUFFERED_ID_ORDER.clear()
    main._PROCESSED_IDS.clear()
    main._TENANT_EDGES.clear()
    ch = _RecordingCH()
    monkeypatch.setattr(main, "ch", ch)
    monkeypatch.setattr(main, "OPEN_OBJECTS_FORCE_CLOSED", 0)
    monkeypatch.setattr(main, "_FORCE_CLOSE_LOG_LAST", 0.0)
    monkeypatch.setattr(main, "CORR_QUIESCE_S", 10 ** 9)   # off unless a test wants it
    try:
        yield ch
    finally:
        main.OPEN_OBJECTS.clear()
        main._ARCHIVE_SLICE_HASH.clear()


def test_cap_close_applies_the_union(lifecycle, monkeypatch):
    """TERMINAL PATH 2/3 — the tracker-163 count cap. It evicts in the same
    least-recently-SEEN order quiesce uses, so it closes on the same shrunken
    window and owes the same union. 163's declared degradation is fewer
    OBJECTS; it must never become a quietly narrower blast radius."""
    ch = lifecycle
    snaps = [_snap([("link_state_change", f"cap-dev-{i}"),
                    ("device_resource_anomaly", f"cap-dev-{i}")], offset=i * 10)
             for i in range(4)]
    _register(snaps, history={"devices": ["aged-out-cause"]})
    monkeypatch.setattr(main, "CORR_OPEN_OBJECTS_MAX", 1)
    run(main.engine_cycle())

    closed = [r for r in ch.objects if r["state"] == "closed"]
    assert len(closed) == 3 and main.OPEN_OBJECTS_FORCE_CLOSED == 3
    for row in closed:
        devices = _aff(row)["devices"]
        assert "aged-out-cause" in devices, \
            "a force-close dropped the object's own persisted history"
        assert devices == sorted(devices), "the union must render sorted"


def test_quiesce_close_applies_the_union_on_a_hand_built_registration(lifecycle,
                                                                     monkeypatch):
    """TERMINAL PATH 1/3 again, isolated on the lifecycle pass — the end-to-end
    reproduction above proves the shape, this one proves the PATH independently
    of how the shrink was produced."""
    ch = lifecycle
    snap = _snap([("link_state_change", "qui-dev"),
                  ("device_resource_anomaly", "qui-dev")])
    _register([snap], history={"devices": ["aged-out-cause"]},
              last_seen=datetime.now(timezone.utc) - timedelta(seconds=10_000))
    monkeypatch.setattr(main, "CORR_QUIESCE_S", 1.0)
    run(main.engine_cycle())

    closed = [r for r in ch.objects if r["state"] == "closed"]
    assert len(closed) == 1, [r["state"] for r in ch.objects]
    assert "aged-out-cause" in _aff(closed[0])["devices"]


def test_merge_close_applies_the_union(lifecycle, monkeypatch):
    """TERMINAL PATH 3/3 — the lifecycle merge tombstone. A merged-away object's
    row is its last word too (a reader resolving `merged_into` lands on it), so
    it gets the union over its OWN history — and ONLY its own: the survivor's
    entities must not appear in it."""
    ch = lifecycle
    merged = _snap([("link_state_change", "merge-away"),
                    ("device_resource_anomaly", "merge-away")])
    survivor = _snap([("link_state_change", "merge-keep"),
                      ("device_resource_anomaly", "merge-keep")], offset=50)
    _register([merged, survivor], history={"devices": ["aged-out-cause"]})

    async def _pairs(survivors, candidates, loop_yield):
        return [(merged.correlation_id, survivor.correlation_id)]

    monkeypatch.setattr(main, "_lifecycle_find_merges", _pairs)
    run(main.engine_cycle())

    tombstones = [r for r in ch.objects if r["state"] == "merged"]
    assert len(tombstones) == 1
    devices = _aff(tombstones[0])["devices"]
    assert "aged-out-cause" in devices, "the tombstone dropped its own history"
    assert "merge-keep" not in devices, \
        "cross-object leakage: a merge must never pool two blast radii"


def test_terminal_paths_are_the_three_covered():
    """A guard against a FOURTH terminal persist appearing without a union. The
    engine has exactly three (`_epoch_lifecycle`: merged, quiesce closed, cap
    closed) and every one of them is EVIDENCE_CLASS_TERMINAL; if that count
    moves, this file owes the new path a test."""
    import inspect
    src = inspect.getsource(main._epoch_lifecycle)
    assert src.count("EVIDENCE_CLASS_TERMINAL") == 3, \
        "a terminal persist was added or removed — cover it here (tracker 187)"
    assert src.count("_affected_final(") == 3, \
        "a terminal persist is not publishing the monotone union"


# ── non-terminal versions are untouched ──────────────────────────────────────

def test_open_versions_are_byte_identical_to_the_projection(cycles):
    """Oracle equivalence over a randomized corpus: for every NON-terminal
    version the row's `affected` is exactly `snap.affected()`, the live
    window's projection — the fix moves the FINAL word only."""
    feed, stub = cycles
    base = datetime.now(timezone.utc).replace(microsecond=0)
    H = main.RETENTION_REQUIRED_S
    rnd = random.Random(187)
    kinds = ("link_state_change", "device_resource_anomaly", "if_errors")
    for cycle in range(6):
        signals = []
        for _ in range(rnd.randint(2, 6)):
            dev = f"corp-dev-{rnd.randint(0, 3)}"
            if rnd.random() < 0.4:
                signals.append(lane_signal(rnd.choice(kinds), f"{dev}:Gi0/1",
                                           offset_s=cycle * 0.2 * H + rnd.random(),
                                           now=base, **IFACE))
            else:
                signals.append(lane_signal(rnd.choice(kinds), dev,
                                           offset_s=cycle * 0.2 * H + rnd.random(),
                                           now=base))
        feed(base + timedelta(seconds=cycle * 0.2 * H), signals)

    rows = [r for r in stub.rows["netops.corr_objects"] if r["state"] == "open"]
    assert rows, "the corpus produced no open versions"
    live = {}
    for reg in main.OPEN_OBJECTS.values():
        live[reg["snapshot"].correlation_id] = reg["snapshot"]
    # every open row must equal the projection of SOME snapshot of that object;
    # the newest one is the only one we still hold, so pin that.
    checked = 0
    for row in rows:
        snap = live.get(row["correlation_id"])
        if snap is None or row["version"] != main.OPEN_OBJECTS[
                row["correlation_id"]]["version"]:
            continue
        assert _aff(row) == snap.affected(), row["correlation_id"]
        checked += 1
    assert checked, "the corpus checked no live open version"


def test_open_row_ignores_the_accumulator_entirely(lifecycle):
    """The mutant guard for the clause above: even with a history that WOULD
    widen it, a non-terminal persist renders the live projection."""
    snap = _snap([("link_state_change", "open-dev"),
                  ("device_resource_anomaly", "open-dev")])
    _register([snap], history={"devices": ["aged-out-cause"]})
    reg = main.OPEN_OBJECTS[snap.correlation_id]
    run(main._persist_snapshot(snap, reg["version"] + 1, "open", []))
    row = lifecycle.objects[-1]
    assert row["state"] == "open"
    assert _aff(row) == snap.affected()
    assert "aged-out-cause" not in _aff(row)["devices"]


# ── boundedness ──────────────────────────────────────────────────────────────

def test_accumulator_is_bounded_by_the_lifetime_population(cycles):
    """The stated bound: one accumulator holds at most the distinct
    (bucket, entity) pairs the object ever PERSISTED — never more, and in
    particular never one entry per VERSION."""
    feed, _stub = cycles
    base = datetime.now(timezone.utc).replace(microsecond=0)
    H = main.RETENTION_REQUIRED_S
    for cycle in range(8):
        feed(base + timedelta(seconds=cycle * 0.2 * H), [
            lane_signal("link_state_change", "bound-dev",
                        offset_s=cycle * 0.2 * H, now=base),
            lane_signal("device_resource_anomaly", "bound-dev",
                        offset_s=cycle * 0.2 * H + 1, now=base),
        ])
    assert main.OPEN_OBJECTS
    for reg in main.OPEN_OBJECTS.values():
        hist = reg["affected_hist"]
        lifetime = sum(len(v) for v in hist.merged_with({}).values())
        assert hist.entity_count() == lifetime <= 2, \
            "the accumulator grew with VERSIONS, not with entities"
        assert hist.truncated == 0


def test_cap_is_wired_from_the_env_knob(cycles, monkeypatch):
    """The bound is DECLARED (CORR_AFFECTED_HISTORY_MAX), reaches the
    accumulator, and its breach is counted rather than silent."""
    feed, _stub = cycles
    monkeypatch.setattr(main, "CORR_AFFECTED_HISTORY_MAX", 1)
    monkeypatch.setattr(main, "AFFECTED_HISTORY_TRUNCATED", 0)
    base = datetime.now(timezone.utc).replace(microsecond=0)
    feed(base, [
        lane_signal("link_state_change", "cap-dev:Gi0/1", offset_s=0,
                    now=base, **IFACE),
        lane_signal("if_errors", "cap-dev:Gi0/1", offset_s=1, now=base, **IFACE),
        lane_signal("device_resource_anomaly", "cap-dev", offset_s=2, now=base),
        lane_signal("link_state_change", "cap-dev", offset_s=3, now=base),
    ])
    (reg,) = main.OPEN_OBJECTS.values()
    assert reg["affected_hist"].max_entities == 1
    assert reg["affected_hist"].entity_count() == 1
    assert main.AFFECTED_HISTORY_TRUNCATED >= 1, \
        "a truncated accumulator must be counted (§10: never silent)"


def test_metrics_expose_the_bound():
    """§10: the bound and its breach are observable, with a TYPE line each."""
    text = main._metrics_text()
    for name, kind in (("corr_affected_history_truncated_total", "counter"),
                       ("corr_affected_history_entities_max", "gauge")):
        assert f"# TYPE {name} {kind}" in text, name
        assert any(line.startswith(name + " ") for line in text.splitlines()), name
