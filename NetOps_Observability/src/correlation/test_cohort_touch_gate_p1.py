# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""P1 — cohort-touch gate, digest memoization, epoch-cadence lifecycle.

Spec: docs/design/COHORT_TOUCH_GATE_P1_2026-08-28.md (T1-T10 below are its §6).

THE CLAIM UNDER TEST: within one drain epoch the nodes are frozen, every new or
replaced edge has a cohort endpoint, and everything else a snapshot is built from
is per-epoch constant — so a component NO cohort key touches re-derives exactly
the object the last touching cohort derived, and re-ranking + re-materializing it
is pure waste. These tests hold that claim to account from both sides: the gate
must serve an untouched component from the memo, and it must NEVER serve a
touched one (T2/T3 are mutant-style — they seed the memo with a snapshot that is
deliberately wrong, so a gate that consulted it would be caught).

T7 pins a latent replay-fidelity defect the gate fixes as a side effect. See its
docstring for what is — and, honestly, what is NOT — observable about it.
"""
from __future__ import annotations

import asyncio
import json
from dataclasses import replace as dc_replace
from datetime import datetime, timedelta, timezone

import pytest

import main
from catalog import builtin_catalog
from directed_topology import DirectedTopology
from engine import (
    ComponentMemo,
    EngineConfig,
    ObjectSnapshot,
    TopologyAdjacency,
    build_nodes,
    digest_cache_stats,
    run_window,
)
from flow_direction import netflow_direction_source
from replay import replay
from signals import (
    EntityType,
    ModalityClass,
    Observer,
    ObserverType,
    Severity,
    Signal,
    Source,
)
from test_replay import persist_and_rehydrate

CAT = builtin_catalog()
CFG = EngineConfig()
T0 = datetime(2026, 8, 28, 10, 0, 0, tzinfo=timezone.utc)


# ── fixtures ─────────────────────────────────────────────────────────────────

def sig(kind: str, entity_id: str, *, offset_s: float = 0.0,
        modality: ModalityClass = ModalityClass.DEVICE_TELEMETRY,
        tokens: tuple[str, ...] = (), tenant: str = "t1",
        severity: Severity = Severity.HIGH) -> Signal:
    return Signal(
        tenant_id=tenant, ts=T0 + timedelta(seconds=offset_s), source=Source.METRIC,
        kind=kind,
        observer=Observer(observer_id="obs1", observer_type=ObserverType.DEVICE),
        modality_class=modality, entity_type=EntityType.INTERFACE,
        entity_id=entity_id, severity=severity,
        native_id=f"p1|{tenant}|{kind}|{entity_id}|{offset_s}",
        entity_tokens=tokens, attrs={"onset_uncertainty_s": 5.0})


def component(i: int, *, tenant: str = "t1",
              tokens: tuple[str, ...] = ()) -> list[Signal]:
    """One two-node component: same interface, two kinds, cross-modality.

    Identity-grounded (shared:dev<i>) so the pair always edges. The HIGH node is
    the EARLIER one, so the component's correlation_id (uuid5 of the earliest
    node + onset) is the same whether the cohort has edged the pair yet or not —
    no mid-epoch identity drift, which is the case the lifecycle-hoist tests need
    (the spec's two documented deltas are exactly the drifting case). The later
    node is WARN so it never opens an object of its own as a singleton."""
    return [
        sig("if_util_high", f"dev{i}:Gi0/1", offset_s=i * 0.1, tenant=tenant),
        sig("if_errors_high", f"dev{i}:Gi0/1", offset_s=i * 0.1 + 5,
            modality=ModalityClass.CONTROL_PLANE, tenant=tenant, tokens=tokens,
            severity=Severity.WARN),
    ]


def mixed_window(n: int = 8, *, tenant: str = "t1") -> list[Signal]:
    return [s for i in range(n) for s in component(i, tenant=tenant)]


def keys_of(sigs) -> frozenset[str]:
    return frozenset(n.key for n in build_nodes(tuple(sigs)))


def drain(window, cohorts, *, memo: ComponentMemo | None,
          **kw) -> list[list[ObjectSnapshot]]:
    """Drive K cohorts over ONE frozen window, exactly as an epoch does: the
    window and every static input are identical every cohort, only `cohort_keys`
    and the carried edges advance."""
    out: list[list[ObjectSnapshot]] = []
    carried: dict[tuple[str, str], object] = {}
    for cohort in cohorts:
        snaps = run_window(window, CAT, (), CFG, cohort_keys=cohort,
                           carried_edges=tuple(carried.values()), memo=memo, **kw)
        for s in snaps:
            for e in s.edges:
                carried[(e.from_node, e.to_node)] = e
        out.append(snaps)
    return out


def same_but_gap_hints(a: ObjectSnapshot, b: ObjectSnapshot) -> bool:
    """Equal on EVERY dataclass field except gap_hints — the one field the spec
    (§1) allows to differ, because it is run_window's transaction-global
    diagnostic and the archive/replay contract already records it as the one
    thing that legitimately differs. The cached digests are not dataclass
    fields, so they cannot mask a difference here."""
    return dc_replace(a, gap_hints=0) == dc_replace(b, gap_hints=0)


# ═══ T1 ══════════════════════════════════════════════════════════════════════

@pytest.mark.parametrize("k", [2, 3, 5, 8])
def test_T1_memo_on_equals_memo_off_over_k_cohorts(k):
    """The equivalence the whole change rests on: for K cohorts over one frozen
    window, the gate must produce the same objects, in the same order, as the
    full re-derivation it replaces."""
    window = mixed_window(8)
    comps = [component(i) for i in range(8)]
    # K cohorts, each touching a contiguous slice of the components.
    per = max(1, (8 + k - 1) // k)
    cohorts = [keys_of([s for c in comps[i:i + per] for s in c])
               for i in range(0, 8, per)][:k]

    memo = ComponentMemo()
    with_memo = drain(window, cohorts, memo=memo)
    without = drain(window, cohorts, memo=None)

    assert memo.hits > 0, "the fixture never exercised the gate"
    for n, (on, off) in enumerate(zip(with_memo, without), start=1):
        assert [s.correlation_id for s in on] == [s.correlation_id for s in off], (
            f"cohort {n}: the gate changed the emission ORDER or the object set")
        for a, b in zip(on, off):
            assert same_but_gap_hints(a, b), (
                f"cohort {n}: memoized object {a.correlation_id[:8]} differs from "
                f"the re-derived one on a field other than gap_hints")
            # Undirected fixture ⇒ orientations empty both ways ⇒ the replay pin
            # is byte-identical, which is the §9.2 acceptance criterion.
            assert a.content_hash() == b.content_hash()
            assert a.material_hash() == b.material_hash()


# ═══ T2 (mutant) ═════════════════════════════════════════════════════════════

def test_T2_a_touched_component_is_never_served_from_the_memo():
    """MUTANT. The memo is seeded with a deliberately WRONG snapshot for a
    component the cohort touches. A gate that consulted the memo for a touched
    component would return the seeded object; the correct gate rebuilds and the
    caller sees the real ranking."""
    window = mixed_window(3)
    all_keys = keys_of(window)
    comp0 = keys_of(component(0))

    # A truthful pass first, so we have a real snapshot to corrupt.
    memo = ComponentMemo()
    first = run_window(window, CAT, (), CFG, cohort_keys=all_keys, memo=memo)
    real = next(s for s in first if set(comp0) <= {n.key for n in s.nodes})
    poisoned = dc_replace(real, ranking=dc_replace(
        real.ranking, top_hypothesis="sig.ent.MUTANT", evidence_missing=("mutant",)))
    memo.put(comp0, poisoned)
    hits_before = memo.hits

    # cohort 2 TOUCHES comp0 → it must be rebuilt, never served.
    second = run_window(window, CAT, (), CFG, cohort_keys=comp0,
                        carried_edges=tuple(e for s in first for e in s.edges),
                        memo=memo)
    got = next(s for s in second if set(comp0) <= {n.key for n in s.nodes})
    assert got is not poisoned
    assert got.ranking.top_hypothesis == real.ranking.top_hypothesis != "sig.ent.MUTANT"
    assert memo.hits == hits_before + (len(second) - 1), (
        "exactly the UNTOUCHED components may be served from the memo")

    # The control: re-seed the poison (the rebuild above overwrote it, which is
    # itself the correct behaviour) and run a cohort that does NOT touch comp0 —
    # it comes back poisoned, proving the memo really is consulted and that the
    # assertions above are not passing for the trivial reason that it never is.
    memo.put(comp0, poisoned)
    third = run_window(window, CAT, (), CFG, cohort_keys=frozenset(),
                       carried_edges=tuple(e for s in first for e in s.edges),
                       memo=memo)
    assert any(s is poisoned for s in third), (
        "the untouched path did not consult the memo — T2 proves nothing")


def test_T2b_a_new_signal_on_a_touched_component_changes_the_ranking():
    """The second half of T2: when a touched component's evidence really has
    changed, the caller sees the NEW ranking (the object is rebuilt from the
    current window, not replayed from the memo)."""
    base = mixed_window(2)
    memo = ComponentMemo()
    run_window(base, CAT, (), CFG, cohort_keys=keys_of(base), memo=memo)

    # A new epoch's window: dev0 also reports a loss episode (a different
    # signature). Its node key is in the cohort, so the component is touched.
    extra = sig("if_input_errors", "dev0:Gi0/1", offset_s=6,
                modality=ModalityClass.CONTROL_PLANE)
    grown = [*base, extra]
    after = run_window(grown, CAT, (), CFG,
                       cohort_keys=frozenset({build_nodes((extra,))[0].key}),
                       memo=memo)
    dev0 = next(s for s in after if any(n.key.startswith("interface:dev0") for n in s.nodes))
    assert len(dev0.nodes) == 3, (
        "the touched component was served stale from the memo — it must be "
        "rebuilt from the current node set")


# ═══ T3 ══════════════════════════════════════════════════════════════════════

def test_T3_a_bridging_edge_rebuilds_the_merged_component():
    """A cohort whose new edge bridges two previously-separate components must
    rebuild the MERGED component (a new node-key set ⇒ a memo miss) and must not
    return either half from the memo."""
    win = component(0, tokens=("bridge-tok",)) + component(1, tokens=("bridge-tok",))
    half_a = keys_of(component(0, tokens=("bridge-tok",)))
    half_b = keys_of(component(1, tokens=("bridge-tok",)))
    util_keys = frozenset(k for k in half_a | half_b if k.endswith("if_util_high"))
    err0 = frozenset(k for k in half_a if k.endswith("if_errors_high"))

    memo = ComponentMemo()
    # Cohort 1 scores only the pairs the two util nodes touch — the bridging
    # errors↔errors pair has NEITHER endpoint in the cohort, so it is unscored
    # and the window still holds two separate components.
    first = run_window(win, CAT, (), CFG, cohort_keys=util_keys, memo=memo)
    assert len(first) == 2 and all(len(s.nodes) == 2 for s in first)
    assert memo.get(half_a) is not None and memo.get(half_b) is not None

    # Cohort 2 admits dev0's errors node → the bridge is scored → ONE component.
    second = run_window(win, CAT, (), CFG, cohort_keys=err0,
                        carried_edges=tuple(e for s in first for e in s.edges),
                        memo=memo)
    assert len(second) == 1 and len(second[0].nodes) == 4
    assert memo.hits == 0, "a merged component must never be served from the memo"
    assert second[0] is not memo.get(half_a) and second[0] is not memo.get(half_b)
    assert memo.get(half_a | half_b) is second[0], (
        "the merged component must be memoized under its OWN (union) key")


# ═══ T4 ══════════════════════════════════════════════════════════════════════

def test_T4_the_memo_dies_with_the_epoch(_stack):
    """The memo holds materialized objects (nodes, edges, evidence). Keeping it
    past the snapshot it describes would pin evidence the 165 horizon released —
    so cohort 1 of the NEXT epoch must start from zero hits."""
    _stack.setattr(main, "CORR_ENGINE_COHORT_SIZE", 2)
    _load(mixed_window(4))

    async def drive():
        first = await main._begin_epoch(datetime.now(timezone.utc))
        try:
            await main.engine_cycle(first)
            await main.engine_cycle(first)
            hits = sum(m.hits for m in first.memos.values())
        finally:
            main._close_epoch(first)
        assert first.memos == {}, "the epoch leaked its component memo"
        second = await main._begin_epoch(datetime.now(timezone.utc))
        try:
            await main.engine_cycle(second)
            return hits, sum(m.hits for m in second.memos.values())
        finally:
            main._close_epoch(second)

    epoch1_hits, epoch2_first_cohort_hits = asyncio.run(drive())
    assert epoch1_hits > 0, "the fixture never exercised the gate"
    assert epoch2_first_cohort_hits == 0, (
        "cohort 1 of a new epoch served objects from a previous epoch's memo — "
        "cross-epoch reuse is P2 material and unsound here (nodes are rebuilt "
        "after a prune)")


# ═══ T5 ══════════════════════════════════════════════════════════════════════

def test_T5_a_full_window_run_never_consults_the_memo():
    """cohort_keys=None is the golden-wire / replay / test path: every component
    is touched by definition, so the memo must never be read — those paths stay
    byte-for-byte what they were."""
    window = mixed_window(3)
    memo = ComponentMemo()
    truth = run_window(window, CAT, (), CFG, cohort_keys=None, memo=memo)
    # Poison every component's entry, then run the full window again.
    for s in truth:
        memo.put(frozenset(n.key for n in s.nodes),
                 dc_replace(s, trigger_signal="MUTANT"))
    again = run_window(window, CAT, (), CFG, cohort_keys=None, memo=memo)
    assert memo.hits == 0
    assert memo.touched == memo.components == 2 * len(truth)
    assert all(s.trigger_signal != "MUTANT" for s in again)
    assert [s.correlation_id for s in again] == [s.correlation_id for s in truth]


# ═══ T6 ══════════════════════════════════════════════════════════════════════

def test_T6_digest_cache_is_byte_identical_and_copies_recompute():
    snap = run_window(mixed_window(1), CAT, (), CFG)[0]
    before = digest_cache_stats()

    c1, m1 = snap.content_hash(), snap.material_hash()
    assert c1 == snap._content_hash_uncached()
    assert m1 == snap._material_hash_uncached()
    c2, m2 = snap.content_hash(), snap.material_hash()
    assert (c1, m1) == (c2, m2)

    after = digest_cache_stats()
    assert after["content_computed"] == before["content_computed"] + 1
    assert after["content_cached"] >= before["content_cached"] + 1
    assert after["material_computed"] == before["material_computed"] + 1

    # The cache is NOT a dataclass field: equality, hashing and replace() ignore
    # it, so a dc_replace copy (the continuation re-key) is fresh and recomputes.
    copy = dc_replace(snap, correlation_id="re-keyed")
    assert getattr(copy, "_content_hash_c", None) is None
    assert copy.content_hash() == copy._content_hash_uncached()
    assert dc_replace(snap, gap_hints=snap.gap_hints) == snap, (
        "the digest cache leaked into __eq__")


def test_T6b_to_object_row_passthrough_is_byte_identical():
    snap = run_window(mixed_window(2), CAT, (), CFG)[0]
    blob = snap.hypotheses_blob()
    for state, merged in (("open", ""), ("merged", "other-cid"), ("closed", "")):
        plain = snap.to_object_row(3, state, merged)
        passed = snap.to_object_row(3, state, merged, hypotheses=blob)
        assert plain == passed
        assert json.dumps(plain, sort_keys=True) == json.dumps(passed, sort_keys=True)
    assert snap.to_object_row(1)["hypotheses"] == blob


# ═══ T7 ══════════════════════════════════════════════════════════════════════

def _directed_fixture():
    def rsig(dev, off):
        return Signal(
            tenant_id="", ts=T0 + timedelta(seconds=off), source=Source.TOPOLOGY,
            kind="bgp_adjacency_change",
            observer=Observer(observer_id=dev, observer_type=ObserverType.DEVICE),
            modality_class=ModalityClass.CONTROL_PLANE, entity_type=EntityType.DEVICE,
            entity_id=dev, severity=Severity.HIGH, native_id=f"r|{dev}",
            entity_tokens=(dev,), attrs={"onset_uncertainty_s": 1.0})

    win = [rsig("leaf1", 0), rsig("spine1", 20)]
    adj = TopologyAdjacency.from_links([{"a": "leaf1", "b": "spine1"}])
    directed = DirectedTopology(sources=(("netflow", netflow_direction_source(
        {("leaf1", "spine1"): 1000.0, ("spine1", "leaf1"): 50.0})),))
    return win, adj, directed


def test_T7_an_untouched_directed_component_keeps_its_embedded_orientations():
    """The latent replay-fidelity defect the gate fixes as a side effect.

    RecordingOracle is per run_window call, so on a cohort that does not touch a
    directed component nothing re-orients its (carried) pairs: the re-materialized
    snapshot carries orientations=() and its blob DROPS the embedded orientations
    that let a directed edge replay deterministically. The memoized snapshot keeps
    them.

    What the defect costs is pinned below: the stored object claims a DIRECTED
    edge (direction_basis onset_order+topo_updown, direction_conf 0.8) that a
    replay of that same stored object cannot reproduce (it recomputes
    ('none', 0.0)), plus a content_hash that moves every cohort.

    (Originally this test also recorded an HONEST LIMIT: replay()'s DriftReport
    did NOT flag it, because `_diff` compared edge KEYS only
    (from,to,grounding_kind,ref) and the from/to order is decided by onset order,
    never by the oracle. Tracker 178 widened `_diff` to compare direction — the
    assertion below now pins the finding rather than the blind spot.)
    """
    win, adj, directed = _directed_fixture()
    keys = keys_of(win)
    memo = ComponentMemo()
    first = run_window(win, CAT, (), CFG, adjacency=adj, directed=directed,
                       cohort_keys=keys, memo=memo)[0]
    assert first.orientations, "fixture must be a directed object"

    # ── pre-P1 form (gate off): cohort 2 does not touch it ───────────────────
    stale = run_window(win, CAT, (), CFG, adjacency=adj, directed=directed,
                       cohort_keys=frozenset(), carried_edges=first.edges,
                       memo=None)[0]
    assert stale.orientations == (), (
        "PREMISE: an untouched directed component re-materialized on cohort 2 "
        "must lose its orientations — if this ever fails, T7 is pinning nothing")
    assert "orientations" not in json.loads(stale.hypotheses_blob())["grounding_context"]
    assert stale.content_hash() != first.content_hash(), (
        "the dropped orientations move the replay pin — pure version churn")
    stored, window = persist_and_rehydrate(stale, win)
    assert stored.directed() is None, "no oracle can be rehydrated from the blob"
    stale_edge = stale.edges[0]
    assert (stale_edge.direction_basis, round(stale_edge.direction_conf, 2)) == \
           ("onset_order+topo_updown", 0.8)
    recomputed = run_window(window, CAT, (), CFG, adjacency=stored.adjacency(),
                            directed=stored.directed())[0].edges[0]
    assert (recomputed.direction_basis, recomputed.direction_conf) == ("none", 0.0), (
        "THE DEFECT: the stored object asserts a direction its own replay cannot "
        "reproduce")
    # tracker 178 (drift-report schema v2) closed the limit this line used to
    # document: _diff now compares (direction_basis, direction_conf) too, so the
    # defect above is REPORTED instead of absorbed. The rest of T7 is unchanged.
    stale_report = replay(stored, window)
    assert not stale_report.clean and stale_report.direction_drift, (
        "tracker 178: the drift report must flag the unreproducible direction")

    # ── P1 form (gate on): the memoized object keeps them ────────────────────
    kept = run_window(win, CAT, (), CFG, adjacency=adj, directed=directed,
                      cohort_keys=frozenset(), carried_edges=first.edges,
                      memo=memo)[0]
    assert kept is first and memo.hits == 1
    assert kept.orientations == first.orientations
    assert kept.content_hash() == first.content_hash()
    stored2, window2 = persist_and_rehydrate(kept, win)
    assert stored2.directed() is not None, "the frozen oracle must rehydrate"
    re2 = run_window(window2, CAT, (), CFG, adjacency=stored2.adjacency(),
                     directed=stored2.directed())[0].edges[0]
    assert (re2.direction_basis, re2.direction_conf) == \
           (kept.edges[0].direction_basis, kept.edges[0].direction_conf)
    report = replay(stored2, window2)
    assert report.clean, f"directed object drifted on replay: {report.differences}"


# ═══ main.py-level fixtures (T4, T8, T9, T10) ════════════════════════════════

class _StubCH:
    """Records what the lifecycle actually persisted."""

    def __init__(self):
        self.rows: dict = {}

    async def insert(self, table, rows, **kw):
        self.rows.setdefault(table, []).extend(rows)
        return True

    def states(self) -> list[tuple[str, str, int]]:
        return [(r["correlation_id"], r["state"], r["version"])
                for r in self.rows.get("netops.corr_objects", [])]


def _load(sigs) -> None:
    for s in sigs:
        sid = str(s.signal_id)
        main.WINDOW_BUFFER.append(s)
        main._BUFFERED_ID_ORDER.append(sid)
        main._BUFFERED_IDS.add(sid)
        main._advance_watermark(s, 0.0)


@pytest.fixture
def _stack(monkeypatch):
    main.WINDOW_BUFFER.clear(); main._BUFFERED_IDS.clear()
    main._BUFFERED_ID_ORDER.clear(); main._PROCESSED_IDS.clear()
    main.TENANT_WATERMARK.clear(); main._TENANT_EDGES.clear()
    main._ARCHIVE_SLICE_HASH.clear()
    monkeypatch.setattr(main, "ch", _StubCH())
    monkeypatch.setattr(main, "OPEN_OBJECTS", {})
    monkeypatch.setattr(main, "COHORT_MEMO_HITS_TOTAL", 0)
    monkeypatch.setattr(main, "COHORT_COMPONENTS_TOTAL", 0)
    monkeypatch.setattr(main, "COHORT_COMPONENTS_TOUCHED_TOTAL", 0)
    monkeypatch.setattr(main, "COHORT_COMPONENTS_RANKED_TOTAL", 0)
    monkeypatch.setattr(main, "LIFECYCLE_PASSES_TOTAL", 0)
    # COHORTS_PROCESSED is module-global and monotonic: without this reset a
    # later test's "we drained K cohorts" condition is already satisfied by an
    # earlier one, which would let T8c break out of its poll too early.
    monkeypatch.setattr(main, "COHORTS_PROCESSED", 0)
    monkeypatch.setattr(main, "COHORT_SIGNALS_TOTAL", 0)
    monkeypatch.setattr(main, "CORR_COHORT_TOUCH_GATE", True)
    monkeypatch.setattr(main, "CORR_LIFECYCLE_EPOCH_CADENCE", True)
    yield monkeypatch
    main.WINDOW_BUFFER.clear(); main._BUFFERED_IDS.clear()
    main._BUFFERED_ID_ORDER.clear(); main._PROCESSED_IDS.clear()
    main._TENANT_EDGES.clear(); main._ARCHIVE_SLICE_HASH.clear()


async def _epoch_of(k: int):
    """K cohorts against one epoch, WITHOUT the lifecycle pass (the drain loop's
    shape, stopped just before it)."""
    epoch = await main._begin_epoch(datetime.now(timezone.utc))
    for _ in range(k):
        await main.engine_cycle(epoch)
    return epoch


# ═══ T8 ══════════════════════════════════════════════════════════════════════

def test_T8_lifecycle_runs_once_per_epoch_with_the_same_outcomes(_stack):
    """The hoist: three cohorts, then ONE merge/quiesce/cap pass, must decide
    exactly what the per-cohort form decided — for a fixture with no mid-epoch
    continuation, which is the case the spec's two documented deltas exclude."""
    _stack.setattr(main, "CORR_ENGINE_COHORT_SIZE", 2)
    _stack.setattr(main, "CORR_QUIESCE_S", 0)   # every unseen object quiesces
    _load(mixed_window(3))
    # An object from a previous cycle that nothing re-materializes: the quiesce
    # pass must close it, once, whichever cadence runs.
    stale = run_window(mixed_window(1, tenant="t9"), CAT, (), CFG)[0]

    def _register():
        main.OPEN_OBJECTS[stale.correlation_id] = {
            "version": 1, "hash": "h", "material": "m",
            "last_seen": T0 - timedelta(seconds=3600), "last_persist": T0,
            "snapshot": stale, "opened_at": T0}

    async def per_epoch():
        _register()
        epoch = await _epoch_of(3)
        try:
            assert main.LIFECYCLE_PASSES_TOTAL == 0, (
                "a cohort inside a drain sweep must NOT run the lifecycle pass")
            await main._epoch_lifecycle(epoch, main._make_loop_yield()[0])
        finally:
            main._close_epoch(epoch)
        return sorted(main.ch.states()), dict(main.OPEN_OBJECTS)

    async def per_cohort():
        _register()
        epoch = await _epoch_of(3)
        try:
            return sorted(main.ch.states()), dict(main.OPEN_OBJECTS)
        finally:
            main._close_epoch(epoch)

    hoisted, open_after = asyncio.run(per_epoch())
    assert main.LIFECYCLE_PASSES_TOTAL == 1, "exactly ONE pass per epoch"
    assert stale.correlation_id not in open_after
    assert (stale.correlation_id, "closed", 2) in hoisted

    # Same fixture, flag off → the pre-P1 per-cohort cadence.
    main.OPEN_OBJECTS.clear(); main.ch.rows.clear()
    main._PROCESSED_IDS.clear(); main._TENANT_EDGES.clear()
    main._ARCHIVE_SLICE_HASH.clear()
    _stack.setattr(main, "LIFECYCLE_PASSES_TOTAL", 0)
    _stack.setattr(main, "CORR_LIFECYCLE_EPOCH_CADENCE", False)
    per_cohort_states, per_cohort_open = asyncio.run(per_cohort())
    assert main.LIFECYCLE_PASSES_TOTAL == 3, "flag off ⇒ a pass after every cohort"
    assert sorted(c for c, _s, _v in per_cohort_states) == \
           sorted(c for c, _s, _v in hoisted)
    assert {c for c, s, _v in per_cohort_states if s == "closed"} == \
           {c for c, s, _v in hoisted if s == "closed"}
    assert set(per_cohort_open) == set(open_after)


def test_T8b_a_failing_cohort_runs_no_lifecycle_pass(_stack):
    """A cohort that raises means no lifecycle pass this epoch — OPEN_OBJECTS is
    left exactly as it was (today a failing cohort also skipped its own pass)."""
    _stack.setattr(main, "CORR_QUIESCE_S", 0)
    _load(mixed_window(2))
    snap = run_window(mixed_window(1, tenant="t9"), CAT, (), CFG)[0]
    main.OPEN_OBJECTS[snap.correlation_id] = {
        "version": 1, "hash": "h", "material": "m",
        "last_seen": T0 - timedelta(seconds=3600), "last_persist": T0,
        "snapshot": snap, "opened_at": T0}

    def boom(*a, **kw):
        raise RuntimeError("scoring failed")

    _stack.setattr(main, "run_window", boom)
    with pytest.raises(RuntimeError, match="scoring failed"):
        asyncio.run(main.engine_cycle())
    assert main.LIFECYCLE_PASSES_TOTAL == 0
    assert snap.correlation_id in main.OPEN_OBJECTS, (
        "a failed cohort must not close anything")
    assert main.ch.states() == []


def test_T8c_the_drain_sweep_itself_runs_exactly_one_pass(_stack):
    """The call site, not a re-implementation of it: one real engine_loop sweep
    over a backlog of several cohorts must run the lifecycle pass ONCE."""
    _stack.setattr(main, "CORR_ENGINE_COHORT_SIZE", 2)
    _stack.setattr(main, "CORR_SIGNALS_ENABLED", True)
    _stack.setattr(main, "CORR_ENGINE_ENABLED", True)
    _stack.setattr(main, "CORR_ENGINE_INTERVAL_S", 3600.0)  # one sweep, then park
    _load(mixed_window(6))

    async def drive():
        task = asyncio.create_task(main.engine_loop())
        for _ in range(2000):
            if main.LIFECYCLE_PASSES_TOTAL >= 1 and main.COHORTS_PROCESSED >= 3:
                break
            await asyncio.sleep(0.002)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    asyncio.run(drive())
    assert main.COHORTS_PROCESSED >= 3, "the sweep did not drain several cohorts"
    assert main.LIFECYCLE_PASSES_TOTAL == 1, (
        f"{main.COHORTS_PROCESSED} cohorts ran "
        f"{main.LIFECYCLE_PASSES_TOTAL} lifecycle passes — the hoist is not in "
        f"effect at the drain-loop call site")


# ═══ T9 ══════════════════════════════════════════════════════════════════════

def test_T9_memos_are_per_tenant_and_keys_never_cross(_stack):
    """§3a. Node keys are NOT tenant-qualified: two tenants with identically
    named entities produce identical component keys. One shared memo would serve
    tenant B's cohort with tenant A's object — a cross-tenant leak."""
    _stack.setattr(main, "CORR_ENGINE_COHORT_SIZE", 2)
    _load(mixed_window(2, tenant="alpha") + mixed_window(2, tenant="beta"))

    async def drive():
        epoch = await main._begin_epoch(datetime.now(timezone.utc))
        try:
            await main.engine_cycle(epoch)
            await main.engine_cycle(epoch)
            await main.engine_cycle(epoch)
            # Copy the mapping, not the memos: _close_epoch clears the dict, but
            # the ComponentMemo objects themselves stay inspectable.
            return dict(epoch.memos), dict(main.OPEN_OBJECTS)
        finally:
            main._close_epoch(epoch)

    memos, open_objects = asyncio.run(drive())
    assert set(memos) == {"alpha", "beta"}, "memos must be keyed by TENANT"
    a_keys = set(memos["alpha"]._by_key)
    b_keys = set(memos["beta"]._by_key)
    assert a_keys and a_keys == b_keys, (
        "the fixture must produce colliding component keys, or T9 proves nothing")
    for k in a_keys:
        a, b = memos["alpha"].get(k), memos["beta"].get(k)
        assert a.tenant_id == "alpha" and b.tenant_id == "beta"
        assert a.correlation_id != b.correlation_id
        assert a is not b
    tenants = {reg["snapshot"].tenant_id for reg in open_objects.values()}
    assert tenants == {"alpha", "beta"}
    assert len({c for c in open_objects}) == len(open_objects)


# ═══ T10 ═════════════════════════════════════════════════════════════════════

def test_T10_both_flags_off_reproduce_pre_p1_behaviour(_stack):
    """The A/B knobs. Gate off ⇒ no memo exists and no hit counter moves; cadence
    off ⇒ a lifecycle pass per cohort. The objects are the same either way."""
    _stack.setattr(main, "CORR_ENGINE_COHORT_SIZE", 2)
    _load(mixed_window(4))

    async def run_epoch(k):
        epoch = await _epoch_of(k)
        try:
            if main.CORR_LIFECYCLE_EPOCH_CADENCE:
                await main._epoch_lifecycle(epoch, main._make_loop_yield()[0])
            return (dict(epoch.memos),
                    sorted((c, r["version"]) for c, r in main.OPEN_OBJECTS.items()))
        finally:
            main._close_epoch(epoch)

    memos_on, objects_on = asyncio.run(run_epoch(3))
    hits_on = main.COHORT_MEMO_HITS_TOTAL
    assert memos_on and hits_on > 0

    # Reset and re-run the identical fixture with both flags OFF.
    main.OPEN_OBJECTS.clear(); main.ch.rows.clear()
    main._PROCESSED_IDS.clear(); main._TENANT_EDGES.clear()
    main._ARCHIVE_SLICE_HASH.clear()
    main.WINDOW_BUFFER.clear(); main._BUFFERED_IDS.clear()
    main._BUFFERED_ID_ORDER.clear(); main.TENANT_WATERMARK.clear()
    _load(mixed_window(4))
    _stack.setattr(main, "CORR_COHORT_TOUCH_GATE", False)
    _stack.setattr(main, "CORR_LIFECYCLE_EPOCH_CADENCE", False)
    _stack.setattr(main, "COHORT_MEMO_HITS_TOTAL", 0)
    _stack.setattr(main, "COHORT_COMPONENTS_TOTAL", 0)
    _stack.setattr(main, "LIFECYCLE_PASSES_TOTAL", 0)
    memos_off, objects_off = asyncio.run(run_epoch(3))

    assert memos_off == {}, "gate off must allocate no memo at all"
    assert main.COHORT_MEMO_HITS_TOTAL == 0
    assert main.COHORT_COMPONENTS_TOTAL == 0, (
        "the component counters are memo-derived; with the gate off they stay 0")
    assert main.LIFECYCLE_PASSES_TOTAL == 3
    assert objects_off == objects_on, (
        "flags off changed which objects are open, or their versions")


# ═══ counters (spec §5) ══════════════════════════════════════════════════════

def test_the_p1_counters_reach_both_state_and_metrics(_stack):
    """§5/§10: the P1 proof is these numbers, so they must actually be exposed —
    on the engine state dict AND on /metrics, with the spec's names."""
    _stack.setattr(main, "CORR_ENGINE_COHORT_SIZE", 2)
    _load(mixed_window(4))

    async def drive():
        epoch = await _epoch_of(3)
        try:
            await main._epoch_lifecycle(epoch, main._make_loop_yield()[0])
        finally:
            main._close_epoch(epoch)

    asyncio.run(drive())
    st = main.epoch_state()
    assert st["cohort_components_memo_hits_total"] > 0
    assert st["cohort_components_total"] == (
        st["cohort_components_memo_hits_total"] + st["cohort_components_ranked_total"])
    assert st["cohort_components_touched_total"] > 0
    assert st["lifecycle_passes_total"] == 1
    assert st["open_objects_epoch_peak"] >= st["cohort_open_objects"] > 0
    assert st["snapshot_digest"]["content_cached"] > 0
    assert st["cohort_touch_gate"] is True and st["lifecycle_epoch_cadence"] is True

    text = main._metrics_text()
    for name in ("corr_cohort_components_total",
                 "corr_cohort_components_touched_total",
                 "corr_cohort_components_memo_hits_total",
                 "corr_cohort_components_ranked_total",
                 "corr_lifecycle_passes_total",
                 "corr_open_objects_epoch_peak",
                 "corr_cohort_open_objects",
                 "corr_cohort_touched"):
        assert any(line.startswith(f"{name} ") for line in text.splitlines()), name
    for kind in ("content", "material"):
        for result in ("computed", "cached"):
            assert f'corr_snapshot_digest{{kind="{kind}",result="{result}"}} ' in text
