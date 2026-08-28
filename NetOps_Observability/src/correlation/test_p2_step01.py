"""P2 delivery steps 0 and 1 — byte-neutral caches + the epoch budget.

Spec: docs/design/DECISION_EVIDENCE_SPLIT_P2_2026-08-28.md §3 (the three
byte-neutral caches), §4 "Epoch budget", §9 items 0-1. Measured brief:
docs/scale/P2_COHORT_PROFILE_2026-08-28.md §8.

THE CLAIM UNDER TEST, and it is one claim in two halves:

  Step 0 — three caches that must be INVISIBLE. `hypotheses_blob` (16.4 % of
  cohort wall) is built twice per version, `Clause.kinds()` re-splits the same
  ~400 immutable strings 248 k times per cohort, and `Signal.signal_id`
  re-derives the same uuid5 66.8 k times. Caching all three must leave
  content_hash, material_hash, the blob and every persisted row BYTE-IDENTICAL —
  only the number of times the work happens may change. Every test below that
  asserts identity is a byte-identity pin; every test that asserts a COUNTER is
  the mutant check that the cache is really in the path (turn the cache off and
  the counter says so; a cache that silently stopped working would be caught by
  the counter, not by the bytes).

  Step 1 — the epoch budget. It changes only HOW MANY cohorts one epoch drains.
  A cohort that has started always finishes (the check is BETWEEN cohorts), the
  lifecycle pass still runs at epoch end, and the rows the drained cohorts wrote
  are byte-identical to the ones the unbounded sweep wrote.

The tracker-156 RSS rule is pinned explicitly: the blob is NEVER held on the
snapshot, and the cycle cache's strong reference dies with the cycle (weakref
check in test_A4).
"""
from __future__ import annotations

import asyncio
import gc
import json
import weakref
from dataclasses import replace as dc_replace
from datetime import datetime, timedelta, timezone

import pytest

import catalog as C
import engine as E
import main
import signals as S
from catalog import builtin_catalog
from engine import EngineConfig, ObjectSnapshot, run_window

CAT = builtin_catalog()
CFG = EngineConfig()
T0 = datetime(2026, 8, 28, 10, 0, 0, tzinfo=timezone.utc)


# ── fixtures ─────────────────────────────────────────────────────────────────

def sig(kind: str, entity_id: str, *, offset_s: float = 0.0,
        modality: S.ModalityClass = S.ModalityClass.DEVICE_TELEMETRY,
        tokens: tuple[str, ...] = (), tenant: str = "t1",
        severity: S.Severity = S.Severity.HIGH) -> S.Signal:
    return S.Signal(
        tenant_id=tenant, ts=T0 + timedelta(seconds=offset_s), source=S.Source.METRIC,
        kind=kind,
        observer=S.Observer(observer_id="obs1", observer_type=S.ObserverType.DEVICE),
        modality_class=modality, entity_type=S.EntityType.INTERFACE,
        entity_id=entity_id, severity=severity,
        native_id=f"p2|{tenant}|{kind}|{entity_id}|{offset_s}",
        entity_tokens=tokens, attrs={"onset_uncertainty_s": 5.0})


def component(i: int, *, tenant: str = "t1") -> list[S.Signal]:
    """One two-node component (the P1 fixture shape: identity-grounded pair)."""
    return [
        sig("if_util_high", f"dev{i}:Gi0/1", offset_s=i * 0.1, tenant=tenant),
        sig("if_errors_high", f"dev{i}:Gi0/1", offset_s=i * 0.1 + 5,
            modality=S.ModalityClass.CONTROL_PLANE, tenant=tenant,
            severity=S.Severity.WARN),
    ]


def mixed_window(n: int = 8, *, tenant: str = "t1") -> list[S.Signal]:
    return [s for i in range(n) for s in component(i, tenant=tenant)]


def storm_window(low: int = 24, crit: int = 3) -> tuple[S.Signal, ...]:
    """A window that, under a DECLARED storm, produces the below-floor AGGREGATE
    object as well as ordinary ones — the representative snapshot whose blob
    carries the degradation block, i.e. the one whose bytes a blob cache would
    be most able to move (design §6 "storm-aggregate branch untouched")."""
    def s(entity, i, sev, off=None):
        return S.Signal(
            tenant_id="acme", ts=T0 + timedelta(seconds=i if off is None else off),
            source=S.Source.SYSLOG, kind="link_state_change",
            observer=S.observer_of(entity, S.ObserverType.DEVICE,
                                   collection_path="direct", clock_quality="unknown"),
            modality_class=S.ModalityClass.CONTROL_PLANE,
            entity_type=S.EntityType.DEVICE, entity_id=entity, severity=sev,
            native_id=f"storm-{entity}-{i}", entity_tokens=(entity,))
    return tuple(
        [s("critdev", i, S.Severity.CRIT) for i in range(crit)]
        + [s(f"low{j}", 0, S.Severity.WARN) for j in range(low)])


def representative_snapshots() -> list[ObjectSnapshot]:
    """The snapshot shapes step 0 must be byte-neutral on: ordinary correlated
    objects AND the storm aggregate (its blob carries the degradation block)."""
    plain = run_window(tuple(mixed_window(4)), CAT, (), CFG)
    stormy = run_window(storm_window(), CAT, (), CFG, storm_mode=True)
    agg = [s for s in stormy if s.storm_aggregate]
    assert agg, "the storm fixture produced no aggregate object — it proves nothing"
    return list(plain) + list(stormy)


@pytest.fixture(autouse=True)
def _no_open_cycle():
    """No test may leak an open blob cycle into the next one."""
    E.blob_cycle_end()
    yield
    E.blob_cycle_end()


def _blob_stats() -> tuple[int, int]:
    d = E.digest_cache_stats()
    return d["blob_computed"], d["blob_cached"]


# ═══ step 0a — the hypotheses-blob cycle cache ═══════════════════════════════

def test_A1_blob_cycle_cache_moves_no_bytes():
    """BYTE-IDENTITY PIN. Same window, run twice into two independent sets of
    snapshot instances: one set digested with a cycle cache open, one without.
    content_hash, material_hash, the blob and the corr_objects row must be
    identical, for ordinary objects AND for the storm aggregate."""
    off = representative_snapshots()
    E.blob_cycle_begin()
    on = representative_snapshots()
    try:
        assert E.blob_cycle_size() == 0, "nothing built yet"
        assert [s.correlation_id for s in on] == [s.correlation_id for s in off]
        for a, b in zip(on, off):
            assert a.hypotheses_blob() == b.hypotheses_blob()
            assert E.cycle_hypotheses_blob(a) == b.hypotheses_blob()
            assert a.content_hash() == b.content_hash()
            assert a.material_hash() == b.material_hash()
            for state, merged in (("open", ""), ("merged", "other"), ("closed", "")):
                assert (json.dumps(a.to_object_row(7, state, merged), sort_keys=True)
                        == json.dumps(b.to_object_row(7, state, merged), sort_keys=True))
        assert E.blob_cycle_size() > 0, "the cache was never populated — A1 is vacuous"
    finally:
        E.blob_cycle_end()


def test_A2_the_blob_is_built_exactly_once_per_cycle_per_snapshot():
    """The saving itself. Inside one cycle, content_hash (which EMBEDS the blob)
    and the corr_objects row builder must share ONE build. Off-cycle the same
    sequence pays for two — that difference is the whole of P2 §9.0a."""
    snap = run_window(tuple(mixed_window(2)), CAT, (), CFG)[0]

    E.blob_cycle_begin()
    try:
        c0, h0 = _blob_stats()
        chash = snap.content_hash()          # build 1 (embeds the blob)
        blob = E.cycle_hypotheses_blob(snap)  # must be a HIT
        row = snap.to_object_row(1, "open", "", hypotheses=blob)
        c1, h1 = _blob_stats()
    finally:
        E.blob_cycle_end()
    assert c1 - c0 == 1, "the blob was built more than once inside one cycle"
    assert h1 - h0 == 1, "the second call did not hit the cycle cache"

    # MUTANT: no cycle open ⇒ the same sequence pays for two builds, and the
    # bytes are the same either way (so only the counter can catch a regression).
    fresh = run_window(tuple(mixed_window(2)), CAT, (), CFG)[0]
    c2, h2 = _blob_stats()
    assert fresh.content_hash() == chash
    assert E.cycle_hypotheses_blob(fresh) == blob
    c3, h3 = _blob_stats()
    assert c3 - c2 == 2, "off-cycle must NOT be caching (that is what makes A2 real)"
    assert h3 == h2
    assert row == fresh.to_object_row(1, "open", "")


def test_A3_the_cache_is_identity_keyed_and_bounded():
    """A recycled id() must never serve another object's blob (the strong ref
    makes that unreachable), and the cache is hard-bounded so a storm cohort
    cannot retain a blob per open object — the tracker-156 shape."""
    snaps = run_window(tuple(mixed_window(6)), CAT, (), CFG)
    assert len(snaps) >= 4
    E.blob_cycle_begin()
    try:
        for s in snaps:
            assert E.cycle_hypotheses_blob(s) == s.hypotheses_blob()
        assert E.blob_cycle_size() == len(snaps)
        for s in snaps:      # every entry still answers for ITS OWN object
            assert E.cycle_hypotheses_blob(s) == s.hypotheses_blob()
    finally:
        E.blob_cycle_end()
    assert E._BLOB_CYCLE_CACHE_MAX >= 1


def test_A3b_the_cache_never_grows_past_its_bound(monkeypatch):
    monkeypatch.setattr(E, "_BLOB_CYCLE_CACHE_MAX", 2)
    snaps = run_window(tuple(mixed_window(6)), CAT, (), CFG)
    E.blob_cycle_begin()
    try:
        for s in snaps:
            assert E.cycle_hypotheses_blob(s) == s.hypotheses_blob()
            assert E.blob_cycle_size() <= 2
    finally:
        E.blob_cycle_end()


def test_A4_nothing_is_retained_after_the_cycle(monkeypatch):
    """TRACKER 156. Two properties in one weakref: while the cycle is open the
    cache holds a STRONG reference (so id() cannot be recycled onto a different
    snapshot), and when the cycle ends NOTHING — not the snapshot, not its
    blob — survives. Plus the rule itself: the blob is never stored ON the
    snapshot."""
    snap = run_window(tuple(mixed_window(1)), CAT, (), CFG)[0]
    fields_before = set(vars(snap))
    E.blob_cycle_begin()
    E.cycle_hypotheses_blob(snap)
    assert not [a for a in set(vars(snap)) - fields_before if "blob" in a or "hypoth" in a], (
        "the blob was cached ON the snapshot — the exact RSS shape tracker 156 forbids")
    ref = weakref.ref(snap)
    del snap
    gc.collect()
    assert ref() is not None, "the cycle cache must hold a STRONG ref while open"
    E.blob_cycle_end()
    gc.collect()
    assert ref() is None, "the snapshot (and its blob) outlived the cycle"


def test_A5_engine_cycle_opens_and_closes_the_cycle_cache(_stack):
    """The caller side: main.engine_cycle opens the cache on the way in and
    drops it in its `finally` — including when the cycle raises."""
    _stack.setattr(main, "CORR_ENGINE_COHORT_SIZE", 4)
    _load(mixed_window(4))
    seen: list[int] = []
    real = main._engine_cycle_inner

    async def spy(epoch):
        seen.append(1 if E._BLOB_CYCLE_CACHE is not None else 0)
        await real(epoch)
    _stack.setattr(main, "_engine_cycle_inner", spy)

    asyncio.run(main.engine_cycle())
    assert seen == [1], "the cycle body ran without an open blob cache"
    assert E._BLOB_CYCLE_CACHE is None, "the cache outlived engine_cycle"

    async def boom(epoch):
        raise RuntimeError("cohort failed")
    _stack.setattr(main, "_engine_cycle_inner", boom)
    with pytest.raises(RuntimeError):
        asyncio.run(main.engine_cycle())
    assert E._BLOB_CYCLE_CACHE is None, "a failing cycle leaked its blob cache"


def test_A6_flag_off_reproduces_the_pre_p2_build_count():
    """A/B knob. CORR_BLOB_CYCLE_CACHE=0 ⇒ blob_cycle_begin opens nothing, the
    hit counter never moves, and the bytes are unchanged (mutant: the ONLY
    observable difference between on and off is the counter)."""
    snap = run_window(tuple(mixed_window(2)), CAT, (), CFG)[0]
    prev = E.CORR_BLOB_CYCLE_CACHE
    try:
        E.CORR_BLOB_CYCLE_CACHE = False
        E.blob_cycle_begin()
        assert E._BLOB_CYCLE_CACHE is None
        c0, h0 = _blob_stats()
        a = E.cycle_hypotheses_blob(snap)
        b = E.cycle_hypotheses_blob(snap)
        c1, h1 = _blob_stats()
    finally:
        E.blob_cycle_end()
        E.CORR_BLOB_CYCLE_CACHE = prev
    assert a == b == snap.hypotheses_blob()
    assert c1 - c0 == 2 and h1 == h0


# ═══ step 0b — Clause.kinds() ════════════════════════════════════════════════

def test_B1_clause_kinds_is_the_same_set_and_is_served_from_the_cache():
    """Equality first (the bytes: `kinds()` feeds catalog validation, the kind
    index and every score), then the counter that proves the cache is in path."""
    clauses = [c for t in CAT.templates for c in t.requires]
    assert len(clauses) > 20, "the built-in catalog got smaller — re-check B1"
    for c in clauses:
        assert c.kinds() == C._compute_clause_kinds(c)
        assert c.kinds() == frozenset(t.strip() for t in c.kind.split("|"))

    probe = C.Clause(kind=" a | b|c ")
    assert probe.kinds() == frozenset({"a", "b", "c"})
    s0 = C.clause_kinds_cache_stats()
    for _ in range(50):
        assert probe.kinds() == frozenset({"a", "b", "c"})
    s1 = C.clause_kinds_cache_stats()
    assert s1["cached"] - s0["cached"] == 50
    assert s1["computed"] == s0["computed"], "a cached clause was recomputed"


def test_B2_a_different_clause_instance_never_reuses_another_s_kinds():
    """MUTANT-style: the cache is identity-keyed, so a NEW Clause with a
    different `kind` must compute its own set. If the key were anything looser
    (or the strong ref were dropped so an id() could be recycled) this returns
    the wrong kinds and the catalog would score the wrong templates."""
    a = C.Clause(kind="alpha")
    assert a.kinds() == frozenset({"alpha"})
    b = C.Clause(kind="beta|gamma")
    assert b.kinds() == frozenset({"beta", "gamma"})
    # model_copy(update=...) is the pydantic "replace": a NEW instance, so it
    # must recompute from ITS OWN kind, never inherit a's cached set.
    c = a.model_copy(update={"kind": "delta"})
    assert c is not a and c.kinds() == frozenset({"delta"})
    assert a.kinds() == frozenset({"alpha"}), "the original clause was corrupted"


def test_B3_flag_off_recomputes_and_the_value_is_identical():
    probe = C.Clause(kind="x|y")
    prev = C.CORR_CLAUSE_KINDS_CACHE
    try:
        C.CORR_CLAUSE_KINDS_CACHE = False
        s0 = C.clause_kinds_cache_stats()
        for _ in range(5):
            assert probe.kinds() == frozenset({"x", "y"})
        s1 = C.clause_kinds_cache_stats()
    finally:
        C.CORR_CLAUSE_KINDS_CACHE = prev
    assert s1["computed"] - s0["computed"] == 5
    assert s1["cached"] == s0["cached"]


def test_B4_the_catalog_version_hash_is_unaffected():
    """`kinds()` is read by catalog validation; version_hash is the replay pin.
    A cache that leaked into the model's serialized form would move it."""
    cat = builtin_catalog()
    before = cat.version_hash()
    for t in cat.templates:
        for c in t.requires:
            c.kinds()
    assert builtin_catalog().version_hash() == before
    assert cat.model_dump(mode="json") == builtin_catalog().model_dump(mode="json"), (
        "Clause.kinds' cache leaked into the pydantic model's serialized form")


# ═══ step 0c — Signal.signal_id ══════════════════════════════════════════════

def _derive(s: S.Signal):
    """signal_id's derivation, independent of the instance cache."""
    import uuid as _uuid
    if s.stored_signal_id:
        return _uuid.UUID(s.stored_signal_id)
    ts_ms = int(s.ts.timestamp() * 1000)
    return _uuid.uuid5(S.SIGNAL_NS, f"{s.source.value}|{s.native_id}|{ts_ms}")


def test_C1_signal_id_is_unchanged_and_cached_on_the_instance():
    for s in mixed_window(3) + list(storm_window(4, 2)):
        assert "_signal_id_c" not in vars(s), "cached before anyone asked"
        first = s.signal_id
        assert first == _derive(s)
        assert vars(s)["_signal_id_c"] is first
        assert s.signal_id is first, "the second call re-derived a new UUID"
        assert s.signal_id_str == str(_derive(s))


def test_C2_a_replaced_copy_recomputes_from_its_own_fields():
    """MUTANT. The cache is NOT a dataclass field, so dc_replace yields a fresh,
    uncached instance. If the cache travelled with the copy, a re-keyed signal
    would keep the WRONG id — the identity contract replay depends on."""
    s = sig("if_errors_high", "dev9:Gi0/1")
    original = s.signal_id
    for changed in (dc_replace(s, native_id="different"),
                    dc_replace(s, ts=s.ts + timedelta(seconds=1)),
                    dc_replace(s, source=S.Source.SYSLOG)):
        assert "_signal_id_c" not in vars(changed), (
            "the cache survived dataclasses.replace — a copy would serve a stale id")
        assert changed.signal_id == _derive(changed)
        assert changed.signal_id != original

    # A replace that touches no identity field re-derives the SAME id (freshly).
    same = dc_replace(s, tenant_id="other")
    assert "_signal_id_c" not in vars(same)
    assert same.signal_id == original


def test_C3_the_cache_stays_out_of_equality_and_the_stored_id_wins():
    a = sig("if_util_high", "dev5:Gi0/1")
    b = dc_replace(a)
    assert a.signal_id is not None   # populate a's cache only
    assert a == b, "the signal_id cache leaked into __eq__"

    stored = dc_replace(a, stored_signal_id="00000000-0000-0000-0000-0000000000ff")
    assert str(stored.signal_id) == "00000000-0000-0000-0000-0000000000ff"
    assert str(stored.signal_id) == str(_derive(stored))


def test_C4_flag_off_writes_no_cache_and_returns_the_same_id():
    s = sig("if_util_high", "dev6:Gi0/1")
    prev = S.CORR_SIGNAL_ID_CACHE
    try:
        S.CORR_SIGNAL_ID_CACHE = False
        first = s.signal_id
        assert "_signal_id_c" not in vars(s)
        assert first == s.signal_id == _derive(s)
    finally:
        S.CORR_SIGNAL_ID_CACHE = prev


def test_C5_a_rehydrated_signal_round_trips_its_identity():
    """to_ch_row/from_ch_row is the replay identity round-trip: the cache must
    not change which id a stored row rehydrates to."""
    s = sig("if_errors_high", "dev7:Gi0/1")
    row = s.to_ch_row()
    back = S.Signal.from_ch_row(row)
    assert str(back.signal_id) == row["signal_id"] == str(s.signal_id)
    assert back.to_ch_row()["signal_id"] == row["signal_id"]


# ═══ the whole of step 0, end to end ═════════════════════════════════════════

def test_D1_all_three_caches_together_move_no_row_bytes(_stack):
    """The acceptance pin for §9.0: drive real cohorts through main with the
    caches ON, then again with all three OFF, and compare EVERY persisted row.
    This is the test that would go red if any cache changed a byte."""
    def drive() -> dict:
        _reset_stack()
        _load(mixed_window(4))
        asyncio.run(main.engine_cycle())
        return {t: list(rows) for t, rows in main.ch.rows.items()}

    _stack.setattr(main, "CORR_ENGINE_COHORT_SIZE", 8)
    on = drive()
    prev = (E.CORR_BLOB_CYCLE_CACHE, C.CORR_CLAUSE_KINDS_CACHE, S.CORR_SIGNAL_ID_CACHE)
    try:
        E.CORR_BLOB_CYCLE_CACHE = False
        C.CORR_CLAUSE_KINDS_CACHE = False
        S.CORR_SIGNAL_ID_CACHE = False
        C._CLAUSE_KINDS_CACHE.clear()
        off = drive()
    finally:
        (E.CORR_BLOB_CYCLE_CACHE, C.CORR_CLAUSE_KINDS_CACHE,
         S.CORR_SIGNAL_ID_CACHE) = prev
    assert set(on) == set(off) and on.get("netops.corr_objects")
    for table in on:
        assert json.dumps(on[table], sort_keys=True, default=str) == \
               json.dumps(off[table], sort_keys=True, default=str), (
            f"{table} rows differ with the P2 step-0 caches on vs off")


def test_D2_the_blob_counters_reach_state_and_metrics(_stack):
    """§10: a cache whose counter is not exposed cannot be proven in production.
    corr_snapshot_digest gains kind="blob" alongside content/material."""
    _stack.setattr(main, "CORR_ENGINE_COHORT_SIZE", 4)
    _load(mixed_window(3))
    c0, h0 = _blob_stats()
    asyncio.run(main.engine_cycle())
    c1, h1 = _blob_stats()
    st = main.epoch_state()
    assert st["snapshot_digest"]["blob_computed"] == c1 > c0
    # DELTA, not a running total: the counters are process-monotonic, so only a
    # per-cycle delta can prove that THIS cycle's persists reused their blobs.
    assert h1 - h0 > 0, (
        "no version reused its blob in this cycle — either engine_cycle opened "
        "no cache or _persist_snapshot is not asking it for the blob")
    assert c1 - c0 <= h1 - h0 + 1, (
        "more blobs were built than versions persisted — the double build is back")
    text = main._metrics_text()
    for result in ("computed", "cached"):
        assert f'corr_snapshot_digest{{kind="blob",result="{result}"}} ' in text


# ═══ step 1 — the epoch budget ═══════════════════════════════════════════════

class _StubCH:
    def __init__(self):
        self.rows: dict = {}

    async def insert(self, table, rows, **kw):
        self.rows.setdefault(table, []).extend(rows)
        return True


def _load(sigs) -> None:
    for s in sigs:
        sid = str(s.signal_id)
        main.WINDOW_BUFFER.append(s)
        main._BUFFERED_ID_ORDER.append(sid)
        main._BUFFERED_IDS.add(sid)
        main._advance_watermark(s, 0.0)


def _reset_stack() -> None:
    main.WINDOW_BUFFER.clear(); main._BUFFERED_IDS.clear()
    main._BUFFERED_ID_ORDER.clear(); main._PROCESSED_IDS.clear()
    main.TENANT_WATERMARK.clear(); main._TENANT_EDGES.clear()
    main._ARCHIVE_SLICE_HASH.clear()
    main.OPEN_OBJECTS.clear()
    main.ch.rows.clear()


@pytest.fixture
def _stack(monkeypatch):
    main.WINDOW_BUFFER.clear(); main._BUFFERED_IDS.clear()
    main._BUFFERED_ID_ORDER.clear(); main._PROCESSED_IDS.clear()
    main.TENANT_WATERMARK.clear(); main._TENANT_EDGES.clear()
    main._ARCHIVE_SLICE_HASH.clear()
    monkeypatch.setattr(main, "ch", _StubCH())
    monkeypatch.setattr(main, "OPEN_OBJECTS", {})
    monkeypatch.setattr(main, "LIFECYCLE_PASSES_TOTAL", 0)
    monkeypatch.setattr(main, "EPOCH_BUDGET_EXITS_TOTAL", 0)
    monkeypatch.setattr(main, "COHORTS_PROCESSED", 0)
    monkeypatch.setattr(main, "COHORT_SIGNALS_TOTAL", 0)
    monkeypatch.setattr(main, "CORR_COHORT_TOUCH_GATE", True)
    monkeypatch.setattr(main, "CORR_LIFECYCLE_EPOCH_CADENCE", True)
    monkeypatch.setattr(main, "CORR_ENGINE_DRAIN_COHORTS", 5)
    yield monkeypatch
    main.WINDOW_BUFFER.clear(); main._BUFFERED_IDS.clear()
    main._BUFFERED_ID_ORDER.clear(); main._PROCESSED_IDS.clear()
    main._TENANT_EDGES.clear(); main._ARCHIVE_SLICE_HASH.clear()


def _expire_budget_after(monkeypatch, n: int) -> list:
    """Make the epoch look older than its budget once N cohorts have drained.
    The clock is moved, not the code: `epoch.started` is monotonic, so winding
    it back is exactly 'the epoch has been running that long'."""
    real = main.engine_cycle
    drained: list = []

    async def spy(epoch=None):
        await real(epoch)
        drained.append(epoch)
        if len(drained) == n and epoch is not None:
            epoch.started -= 10_000.0
    monkeypatch.setattr(main, "engine_cycle", spy)
    return drained


def test_E1_a_sweep_ends_on_its_budget_and_still_runs_the_lifecycle(_stack):
    """THE step-1 behaviour. Five cohorts of work, a budget that expires after
    the second: exactly two cohorts drain, the exit is counted, and the epoch's
    ONE merge/quiesce/cap pass still runs — an early exit is the SAME exit."""
    _stack.setattr(main, "CORR_ENGINE_COHORT_SIZE", 2)
    _stack.setattr(main, "CORR_ENGINE_EPOCH_BUDGET_S", 300.0)
    _load(mixed_window(8))          # 16 signals ⇒ 8 cohorts of work
    _expire_budget_after(_stack, 2)

    drained = asyncio.run(main._drain_epoch_sweep())
    assert drained == 2, "the budget did not end the sweep between cohorts"
    assert main.EPOCH_BUDGET_EXITS_TOTAL == 1
    assert main.LIFECYCLE_PASSES_TOTAL == 1, (
        "the lifecycle pass must still run at epoch end — that is the point")
    assert main.COHORTS_PROCESSED == 2
    assert len(main.pending_signals()) > 0, (
        "the fixture ran dry, so E1 proves nothing about the budget")


def test_E2_budget_zero_is_unbounded(_stack):
    """0 = off (the A/B arm). The sweep drains to CORR_ENGINE_DRAIN_COHORTS even
    though the epoch is 'old' from its very first cohort."""
    _stack.setattr(main, "CORR_ENGINE_COHORT_SIZE", 2)
    _stack.setattr(main, "CORR_ENGINE_EPOCH_BUDGET_S", 0.0)
    _load(mixed_window(8))
    _expire_budget_after(_stack, 1)

    drained = asyncio.run(main._drain_epoch_sweep())
    assert drained == main.CORR_ENGINE_DRAIN_COHORTS == 5
    assert main.EPOCH_BUDGET_EXITS_TOTAL == 0
    assert main.LIFECYCLE_PASSES_TOTAL == 1


def test_E3_the_budget_never_cuts_a_cohort_in_half(_stack):
    """MUTANT-adjacent: the epoch is ALREADY over budget when the sweep starts.
    The check is between cohorts, so the first cohort still runs to completion
    (drained == 1, never 0) and its objects are persisted whole."""
    _stack.setattr(main, "CORR_ENGINE_COHORT_SIZE", 2)
    _stack.setattr(main, "CORR_ENGINE_EPOCH_BUDGET_S", 1.0)
    _load(mixed_window(8))
    real_begin = main._begin_epoch

    async def old_epoch(now):
        ep = await real_begin(now)
        ep.started -= 10_000.0
        return ep
    _stack.setattr(main, "_begin_epoch", old_epoch)

    drained = asyncio.run(main._drain_epoch_sweep())
    assert drained == 1, "a started cohort must always finish"
    assert main.EPOCH_BUDGET_EXITS_TOTAL == 1
    assert main.COHORTS_PROCESSED == 1
    assert main.ch.rows.get("netops.corr_objects"), (
        "the first cohort was cut short — it persisted nothing")


def test_E4_a_budget_exit_changes_no_cohort_output(_stack):
    """§4: 'this changes scheduling, not any object's content'. The rows the two
    drained cohorts write under a budget must be BYTE-IDENTICAL to the rows the
    same two cohorts write in an unbounded sweep."""
    def rows_for(budget: float, expire_after: int | None) -> list[dict]:
        _reset_stack()
        _load(mixed_window(8))
        main.CORR_ENGINE_EPOCH_BUDGET_S = budget
        mp = pytest.MonkeyPatch()
        try:
            if expire_after is not None:
                _expire_budget_after(mp, expire_after)
            main._drain_sweep_result = asyncio.run(main._drain_epoch_sweep())
        finally:
            mp.undo()
        return list(main.ch.rows.get("netops.corr_objects", []))

    _stack.setattr(main, "CORR_ENGINE_COHORT_SIZE", 2)
    _stack.setattr(main, "CORR_ENGINE_DRAIN_COHORTS", 2)
    unbounded = rows_for(0.0, None)
    assert main._drain_sweep_result == 2
    _stack.setattr(main, "CORR_ENGINE_DRAIN_COHORTS", 5)
    bounded = rows_for(300.0, 2)
    assert main._drain_sweep_result == 2

    assert unbounded, "the fixture persisted nothing"
    assert json.dumps(bounded, sort_keys=True, default=str) == \
           json.dumps(unbounded, sort_keys=True, default=str), (
        "the budget changed what a cohort produced, not just how many ran")


def test_E5_an_empty_epoch_still_exits_without_charging_the_budget(_stack):
    """The 'ran dry' exit must not be mistaken for a budget exit."""
    _stack.setattr(main, "CORR_ENGINE_COHORT_SIZE", 100)
    _stack.setattr(main, "CORR_ENGINE_EPOCH_BUDGET_S", 300.0)
    _load(mixed_window(2))
    _expire_budget_after(_stack, 1)
    drained = asyncio.run(main._drain_epoch_sweep())
    assert drained == 1 and main.EPOCH_BUDGET_EXITS_TOTAL == 0
    assert main.LIFECYCLE_PASSES_TOTAL == 1


def test_E6_the_budget_counter_reaches_state_and_metrics(_stack):
    _stack.setattr(main, "CORR_ENGINE_COHORT_SIZE", 2)
    _stack.setattr(main, "CORR_ENGINE_EPOCH_BUDGET_S", 300.0)
    _load(mixed_window(8))
    _expire_budget_after(_stack, 2)
    asyncio.run(main._drain_epoch_sweep())

    st = main.epoch_state()
    assert st["epoch_budget_s"] == 300.0
    assert st["epoch_budget_exits_total"] == 1
    text = main._metrics_text()
    assert "corr_engine_epoch_budget_exits_total 1" in text


def test_E7_removing_the_budget_check_is_caught(_stack):
    """MUTANT. The guard IS the feature: with CORR_ENGINE_EPOCH_BUDGET_S set and
    the epoch over it, a sweep that ignored the check would drain all five
    cohorts. E1 asserts 2; this asserts the mutant's 5 is what 'no check' looks
    like, so the two together cannot both pass on a broken build."""
    _stack.setattr(main, "CORR_ENGINE_COHORT_SIZE", 2)
    _load(mixed_window(8))
    _expire_budget_after(_stack, 1)
    # The mutant: budget disabled == the check removed.
    _stack.setattr(main, "CORR_ENGINE_EPOCH_BUDGET_S", 0.0)
    assert asyncio.run(main._drain_epoch_sweep()) == 5
