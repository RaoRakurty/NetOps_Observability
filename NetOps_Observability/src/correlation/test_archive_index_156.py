# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Tracker 156 — the memoisation and the shared window index must change nothing.

The fix removed work, not behaviour:
  * `Signal.signal_id` / `signal_id_str` / `to_ch_row` are memoised on a frozen
    dataclass (pure functions of frozen fields).
  * `_archive_slice` no longer rebuilds the window's loose-signal grouping and
    sort ordinals per object; `_window_index` builds them once per cycle and
    every object shares them. (v2, 2026-08-22: membership is the COMPONENT'S
    nodes — the reference below implements the v2 rule naively.)

Both are only safe if the OUTPUT is identical, so every test here compares
against a reference that does the work the old way. `test_archive_slice.py`
already pins replay exactness; this file pins the equivalence of the rewrite.
"""
from __future__ import annotations

import dataclasses
import sys
from datetime import datetime, timedelta, timezone

import pytest

import main
from signals import (
    EntityType,
    ModalityClass,
    Observer,
    ObserverType,
    Severity,
    Signal,
    Source,
)

T0 = datetime(2026, 8, 19, 12, 0, 0, tzinfo=timezone.utc)


def _sig(i: int, *, kind: str = "if_errors", ent: str = "", src: Source = Source.SYSLOG,
         secs: int = 0) -> Signal:
    return Signal(
        tenant_id="acme", ts=T0 + timedelta(seconds=secs or i), source=src, kind=kind,
        observer=Observer(observer_id=f"obs{i%3}", observer_type=ObserverType.DEVICE,
                          location="lab", trust_domain="lab", collection_path="syslog",
                          clock_quality="ntp"),
        modality_class=ModalityClass.DEVICE_TELEMETRY, entity_type=EntityType.INTERFACE,
        entity_id=ent or f"leaf{i % 7}:Gi0/{i % 4}", severity=Severity.WARN,
        native_id=f"nat-{i}", entity_tokens=(f"tok{i%5}", "shared"),
    )


def _reference_slice(snap, window):
    """The v2 membership rule, implemented the naive way: component signals +
    in-bounds loose (+ matched identities), no shared index, sorted fresh."""
    ws, we = snap.window_start, snap.window_end
    matched = {str(s.signal_id) for s in snap.identity_signals}
    keep = []
    for s in window:
        if ((s.kind.endswith("_clear") or s.source is Source.APP_IDENTITY)
                and ((ws <= s.ts <= we) or str(s.signal_id) in matched)):
            keep.append(s)
    for node in snap.nodes:
        keep.extend(node.signals)
    keep.sort(key=lambda s: (s.ts, str(s.signal_id)))
    return keep


class _Node:
    """Minimal engine.Node stand-in — _archive_slice reads only .signals."""
    def __init__(self, signals):
        self.signals = tuple(signals)


def _nodes_for(window, keep_keys):
    """Group `window` exactly as engine.build_nodes keys nodes, keep a subset."""
    by_node = {}
    for s in window:
        if s.kind.endswith("_clear") or s.source is Source.APP_IDENTITY:
            continue
        by_node.setdefault(f"{s.entity_type.value}:{s.entity_id}:{s.kind}", []).append(s)
    return [_Node(by_node[k]) for k in sorted(by_node) if k in keep_keys]


def _node_keys(window):
    return sorted({f"{s.entity_type.value}:{s.entity_id}:{s.kind}" for s in window
                   if not s.kind.endswith("_clear") and s.source is not Source.APP_IDENTITY})


class _Snap:
    """Minimal ObjectSnapshot stand-in — _archive_slice reads only these."""
    def __init__(self, ws, we, ident=(), nodes=()):
        self.window_start, self.window_end = ws, we
        self.identity_signals = list(ident)
        self.nodes = tuple(nodes)
        self.correlation_id = "cid-test"


@pytest.fixture(autouse=True)
def _clear_index():
    main._WINDOW_INDEX_CACHE.clear()
    yield
    main._WINDOW_INDEX_CACHE.clear()


# --- memoisation equivalence ----------------------------------------------

def test_signal_id_is_deterministic_across_instances():
    assert _sig(1).signal_id == _sig(1).signal_id
    assert _sig(1).signal_id != _sig(2).signal_id


def test_signal_instances_are_never_memoised_in_place():
    """Pins the measurement that decided the design (tracker 156).

    Signal is a ~25-field dataclass, so its instances use a key-sharing dict.
    Writing non-field keys into __dict__ converts that to a standalone dict —
    measured at +944 bytes PER SIGNAL, ~47 MB across the 50k window, in a
    service whose failure mode is RSS. So the archive path memoises per CYCLE
    (main._window_index / main._CYCLE_ROW_CACHE) and never on the signal. This
    test fails the moment someone reintroduces an instance-level cache.
    """
    s = _sig(1)
    baseline = sys.getsizeof(_sig(2).__dict__)
    for _ in range(3):
        _ = s.signal_id, s.signal_id_str, s.to_ch_row()
    assert sys.getsizeof(s.__dict__) == baseline, (
        "Signal.__dict__ grew after property access — something is memoising on "
        "the instance. That costs ~944 bytes per signal across the whole window; "
        "cache per cycle instead.")
    assert not [k for k in s.__dict__ if k.startswith("_") and k.endswith("memo")]


def test_signal_id_str_matches_str_of_signal_id():
    s = _sig(2)
    assert s.signal_id_str == str(s.signal_id)


def test_replace_does_not_inherit_a_stale_memo():
    """dataclasses.replace makes a DIFFERENT signal; it must recompute."""
    s = _sig(3)
    _ = s.signal_id
    other = dataclasses.replace(s, native_id="nat-changed")
    assert other.signal_id != s.signal_id
    assert other.signal_id_str != s.signal_id_str


def test_memo_is_invisible_to_eq_hash_and_replace():
    a, b = _sig(4), _sig(4)
    _ = a.signal_id, a.to_ch_row()          # populate a's memos only
    assert a == b, "a populated memo must not change equality"
    assert dataclasses.asdict(a).keys() == dataclasses.asdict(b).keys()
    # Signal carries a dict field (attrs), so it has never been hashable —
    # asserted here so this test documents the real contract rather than a
    # hoped-for one.
    with pytest.raises(TypeError):
        hash(a)
    assert "_signal_id_memo" not in {f.name for f in dataclasses.fields(a)}


def test_to_ch_row_matches_a_freshly_computed_row():
    s = _sig(5)
    memoised = s.to_ch_row()
    fresh = _sig(5).to_ch_row()
    assert memoised == fresh


def test_to_ch_row_returns_a_fresh_dict_every_call():
    """The archive path stamps archived_for/version onto what it gets back.

    NOTE the priming call. Mutating the FIRST result proves nothing: the build
    path returns a copy whether or not the memo path does, so a test that only
    mutates r1 passes even when the memo is handed out by reference. Mutation
    testing caught exactly that — the check must run against a MEMO HIT.
    """
    s = _sig(6)
    s.to_ch_row()                      # prime the memo; every call below is a hit
    r1 = s.to_ch_row()
    r1["archived_for"] = "cid-1"
    r1["entity_tokens"].append("MUTATED")
    r2 = s.to_ch_row()
    assert "archived_for" not in r2, "memo leaked a caller's mutation"
    assert "MUTATED" not in r2["entity_tokens"], "entity_tokens list was shared"
    assert r1 is not r2
    assert r2 == _sig(6).to_ch_row(), "memo drifted from a freshly built row"


def test_to_ch_row_memo_survives_many_mutating_consumers():
    """The real archive loop: one signal, many objects, each stamping its own."""
    s = _sig(7)
    for version, cid in enumerate(("cid-a", "cid-b", "cid-c", "cid-d")):
        row = s.to_ch_row()
        row["archived_for"] = cid
        row["archived_version"] = version
        row["entity_tokens"].append(f"junk-{version}")
    clean = s.to_ch_row()
    assert "archived_for" not in clean and "archived_version" not in clean
    assert clean["entity_tokens"] == list(_sig(7).entity_tokens)


# --- shared window index equivalence --------------------------------------

@pytest.mark.parametrize("n_objects", [1, 3, 12])
def test_archive_slice_matches_the_reference_for_every_object(n_objects):
    window = [_sig(i) for i in range(240)]
    window += [_sig(500 + i, kind="if_errors_clear", secs=10 + i) for i in range(12)]
    keys = _node_keys(window)
    snaps = [_Snap(T0 + timedelta(seconds=k * 7), T0 + timedelta(seconds=40 + k * 11),
                   nodes=_nodes_for(window, set(keys[k::max(1, n_objects)])))
             for k in range(n_objects)]
    for snap in snaps:
        got = main._archive_slice(snap, window)
        want = _reference_slice(snap, window)
        assert [s.signal_id_str for s in got] == [s.signal_id_str for s in want]
        assert [s.to_ch_row() for s in got] == [s.to_ch_row() for s in want]


def test_index_is_built_once_and_shared_across_objects():
    """The whole point: N objects, ONE grouping pass."""
    window = [_sig(i) for i in range(120)]
    calls = {"n": 0}
    real = main._window_index.__wrapped__ if hasattr(main._window_index, "__wrapped__") else None
    assert real is None  # plain function; we count via the cache instead
    main._WINDOW_INDEX_CACHE.clear()
    for k in range(8):
        main._archive_slice(_Snap(T0, T0 + timedelta(seconds=200)), window)
        calls["n"] = len(main._WINDOW_INDEX_CACHE)
    assert calls["n"] == 1, "index cache should hold exactly one entry for one window"


def test_a_different_window_gets_a_different_index():
    w1 = [_sig(i) for i in range(30)]
    w2 = [_sig(i, ent="other:Gi9/9") for i in range(40)]
    span = (T0, T0 + timedelta(seconds=500))
    snap1 = _Snap(*span, nodes=_nodes_for(w1, set(_node_keys(w1))))
    snap2 = _Snap(*span, nodes=_nodes_for(w2, set(_node_keys(w2))))
    s1 = main._archive_slice(snap1, w1)
    s2 = main._archive_slice(snap2, w2)
    assert [s.signal_id_str for s in s1] != [s.signal_id_str for s in s2]
    assert s2 == _reference_slice(snap2, w2)
    assert len(main._WINDOW_INDEX_CACHE) == 2


def test_index_length_guard_rejects_a_recycled_id():
    """id() reuse must not serve a stale index for a different window."""
    window = [_sig(i) for i in range(20)]
    snap = _Snap(T0, T0 + timedelta(seconds=500),
                 nodes=_nodes_for(window, set(_node_keys(window))))
    main._archive_slice(snap, window)
    key = id(window)
    stale_len, idx = main._WINDOW_INDEX_CACHE[key]
    main._WINDOW_INDEX_CACHE[key] = (stale_len + 1, idx)   # simulate a mismatch
    rebuilt = main._archive_slice(snap, window)
    assert rebuilt == _reference_slice(snap, window)
    assert main._WINDOW_INDEX_CACHE[key][0] == len(window)


def test_engine_cycle_clears_both_per_cycle_caches():
    """The caches are within-cycle sharing mechanisms, never stores."""
    import asyncio
    main._WINDOW_INDEX_CACHE[12345] = (1, main._WindowIndex(
        nodes=(), loose=(), sid={}, ordinal={}))
    main._CYCLE_ROW_CACHE[424242] = {"tenant_id": "old"}
    main.ch = None
    asyncio.run(main.engine_cycle())
    assert 12345 not in main._WINDOW_INDEX_CACHE
    assert 424242 not in main._CYCLE_ROW_CACHE


def test_per_cycle_caches_are_empty_after_a_cycle_not_just_before():
    """Held between cycles, a 50k base-row cache would BE the RSS problem."""
    import asyncio
    main.ch = None
    asyncio.run(main.engine_cycle())
    assert not main._CYCLE_ROW_CACHE and not main._WINDOW_INDEX_CACHE


def test_caches_are_cleared_even_when_the_cycle_raises():
    """finally, not a happy-path clear."""
    import asyncio

    async def boom(epoch=None):
        main._CYCLE_ROW_CACHE[777] = {"x": 1}
        main._WINDOW_INDEX_CACHE[999] = (1, main._WindowIndex(
            nodes=(), loose=(), sid={}, ordinal={}))
        raise RuntimeError("cycle blew up")

    original = main._engine_cycle_inner
    main._engine_cycle_inner = boom
    try:
        with pytest.raises(RuntimeError):
            asyncio.run(main.engine_cycle())
        assert not main._CYCLE_ROW_CACHE, "a raising cycle leaked its row cache"
        assert not main._WINDOW_INDEX_CACHE, "a raising cycle leaked its index"
    finally:
        main._engine_cycle_inner = original


def test_archive_row_reuses_the_base_but_stamps_per_object():
    """Same signal, many objects: one base row, distinct stamps, no bleed."""
    main._CYCLE_ROW_CACHE.clear()
    s = _sig(11)
    r1 = main._archive_row(s, "cid-a", 1)
    r2 = main._archive_row(s, "cid-b", 7)
    assert len(main._CYCLE_ROW_CACHE) == 1, "base row should be built once"
    assert (r1["archived_for"], r1["archived_version"]) == ("cid-a", 1)
    assert (r2["archived_for"], r2["archived_version"]) == ("cid-b", 7)
    assert r1 is not r2
    r1["entity_tokens"].append("MUT")
    assert "MUT" not in r2["entity_tokens"]
    assert "MUT" not in main._archive_row(s, "cid-c", 9)["entity_tokens"]
    base = {k: v for k, v in r2.items() if k not in ("archived_for", "archived_version")}
    fresh = _sig(11).to_ch_row()
    assert base == fresh, "cached base row drifted from a freshly built row"
    main._CYCLE_ROW_CACHE.clear()
