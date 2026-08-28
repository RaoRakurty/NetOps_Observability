"""Explicit storm mode — the design's REQUIRED test plan (design
docs/design/CORRELATION_STORM_MODE_DESIGN_2026-08-28.md §"Test plan").

Storm mode adds four DETERMINISTIC, replay-safe, GATED behaviors that fire only
when the detector declares a storm: (1) dedup repeats, (2) prioritize critical
evidence, (3) aggregate below-floor low-value repeats into ONE per-tenant counter
object, (4) preserve raw for replay (severity-aware eviction, never a critical
while a low-value exists; nothing dropped from the durable bus).

╔═══════════════════════════════════════════════════════════════════════════╗
║ NEW REFERENCE — OWNER REVIEW. Tests 2/3/4/5/6 assert the DELIBERATE semantic ║
║ change UNDER STORM (like Stage-2 Lever 1). With the detector OFF, output is  ║
║ byte-identical to pre-change — pinned here (test 1) AND by the unchanged     ║
║ golden-wire/replay/166/162/168 suites. These are the intended new reference. ║
╚═══════════════════════════════════════════════════════════════════════════╝
"""
from __future__ import annotations

import asyncio
import time
import uuid
from datetime import datetime, timedelta, timezone

import main
import signals as S
from catalog import builtin_catalog
from engine import _SEV_RANK, run_window
from replay import replay
from test_replay import persist_and_rehydrate

T0 = datetime(2026, 8, 28, 12, 0, 0, tzinfo=timezone.utc)
CAT = builtin_catalog()


def sig(entity: str, i: int, *, severity=S.Severity.WARN, kind="link_state_change",
        tenant="acme", tokens=None, ts_off=None) -> S.Signal:
    """One signal on `entity`. Distinct entities carry a unique token so they never
    weld — a low-value flood is N independent singleton episodes."""
    return S.Signal(
        tenant_id=tenant, ts=T0 + timedelta(seconds=i if ts_off is None else ts_off),
        source=S.Source.SYSLOG, kind=kind,
        observer=S.observer_of(entity, S.ObserverType.DEVICE,
                               collection_path="direct", clock_quality="unknown"),
        modality_class=S.ModalityClass.CONTROL_PLANE,
        entity_type=S.EntityType.DEVICE, entity_id=entity,
        severity=severity, native_id=f"nat-{entity}-{i}-{uuid.uuid4().hex[:8]}",
        entity_tokens=tokens if tokens is not None else (entity,))


def _blob_has_degradation(snap) -> bool:
    import json
    return "degradation" in json.loads(snap.hypotheses_blob())["grounding_context"]


def _aggregate_of(snaps):
    """The single storm-noise aggregate object in a run_window result."""
    return next(s for s in snaps if s.storm_aggregate)


# ── Test 1 — GATED byte-identical (the safety pin) ──────────────────────────

def test_1_detector_off_is_byte_identical_and_inert():
    """With storm OFF, none of the four behaviors run: no aggregate object, no
    degradation block, no dedup — and the hash is stable run-to-run. (The real
    byte-identical pin is the unchanged golden-wire/replay/166/162/168 suites;
    this asserts the local invariants on a window that WOULD trigger storm.)"""
    window = tuple(
        [sig("critdev", i, severity=S.Severity.CRIT) for i in range(3)]
        + [sig(f"low{j}", 0, severity=S.Severity.WARN) for j in range(20)])
    a = run_window(window, CAT, (), storm_mode=False)
    b = run_window(window, CAT, (), storm_mode=False)
    assert [s.content_hash() for s in a] == [s.content_hash() for s in b]
    assert not any(s.storm_aggregate for s in a), "no aggregate object off-storm"
    assert not any(s.storm_mode for s in a)
    assert not any(_blob_has_degradation(s) for s in a), "no degradation block off-storm"
    # The 20 below-floor WARN singletons are skipped (episodes), exactly as before:
    # only the one CRIT object exists.
    assert len(a) == 1 and a[0].signal_count() == 3


# ── Test 2 — Dedup: K identical repeats → 1 representative + occurrences=K ───

def test_2_dedup_collapses_identical_repeats_deterministically():
    K = 25
    window = tuple(sig("critdev", i, severity=S.Severity.CRIT) for i in range(K))
    off = run_window(window, CAT, (), storm_mode=False)
    on = run_window(window, CAT, (), storm_mode=True)
    assert len(off) == 1 and len(on) == 1
    (o_off,), (o_on,) = off, on
    # Off-storm keeps every instance; storm collapses to ONE representative.
    assert o_off.signal_count() == K
    assert o_on.signal_count() == 1, "dedup did not collapse identical repeats"
    assert o_on.nodes[0].occurrences == K, "occurrences count lost"
    assert o_on.storm_occurrences == K - 1, "collapsed count not recorded"
    # occurrences embedded in the degradation-scoped context (present-only).
    import json
    deg = json.loads(o_on.hypotheses_blob())["grounding_context"]["degradation"]
    assert deg["storm_mode"] is True and deg["deduped"] == K - 1
    # Deterministic + replay-safe: same window + storm flag ⇒ byte-identical hash.
    assert o_on.content_hash() == run_window(window, CAT, (), storm_mode=True)[0].content_hash()
    # Grounding UNCHANGED for the representative: the verdict is the same as off-storm
    # (dedup shrinks the stored instances, never the evidence kinds it was scored on).
    assert o_on.ranking.top_hypothesis == o_off.ranking.top_hypothesis
    assert o_on.material_hash() == o_off.material_hash(), "dedup moved the damping identity"


# ── Test 3 — Aggregate: N low-value → 1 counter, criticals untouched ────────

def test_3_low_value_flood_aggregates_criticals_still_full_objects():
    N = 40
    lows = [sig(f"low{j}", 0, severity=S.Severity.WARN) for j in range(N)]
    crits = [sig("crit-a", 0, severity=S.Severity.CRIT),
             sig("crit-b", 0, severity=S.Severity.CRIT)]
    window = tuple(lows + crits)

    off = run_window(window, CAT, (), storm_mode=False)
    on = run_window(window, CAT, (), storm_mode=True)

    # Off-storm: the N WARN singletons are skipped; only the 2 CRIT objects exist.
    assert len(off) == 2 and not any(s.storm_aggregate for s in off)

    aggs = [s for s in on if s.storm_aggregate]
    fulls = [s for s in on if not s.storm_aggregate]
    assert len(aggs) == 1, f"expected exactly ONE storm-noise aggregate, got {len(aggs)}"
    agg = aggs[0]
    assert agg.storm_occurrences == N, "aggregate occurrences != flood size"
    assert agg.storm_distinct_entities == N, "distinct-entity count wrong"
    assert agg.storm_mode is True and agg.ranking.top_hypothesis == "undetermined"
    # NOT N objects — one aggregate replaces the flood.
    assert len(on) == 3, "flood should collapse to 1 aggregate + the 2 criticals"
    # Criticals in the SAME window still get their full objects, unchanged.
    crit_ids = {s.correlation_id for s in fulls}
    assert crit_ids == {s.correlation_id for s in off}
    # Aggregate is per-tenant, stamped from the window tenant (§3a) — no cross-tenant.
    assert agg.tenant_id == "acme"
    # Deterministic id + content (byte-identical aggregate on a re-run).
    agg2 = _aggregate_of(run_window(window, CAT, (), storm_mode=True))
    assert agg.correlation_id == agg2.correlation_id
    assert agg.content_hash() == agg2.content_hash()


def test_3b_aggregate_is_tenant_scoped_no_cross_tenant_mixing():
    """Two tenants' floods must never share an aggregate (§3a)."""
    win_a = tuple(sig(f"a{j}", 0, severity=S.Severity.WARN, tenant="acme") for j in range(5))
    win_b = tuple(sig(f"b{j}", 0, severity=S.Severity.WARN, tenant="beta") for j in range(7))
    agg_a = _aggregate_of(run_window(win_a, CAT, (), storm_mode=True))
    agg_b = _aggregate_of(run_window(win_b, CAT, (), storm_mode=True))
    assert agg_a.tenant_id == "acme" and agg_a.storm_distinct_entities == 5
    assert agg_b.tenant_id == "beta" and agg_b.storm_distinct_entities == 7
    assert agg_a.correlation_id != agg_b.correlation_id


# ── Test 4 — Prioritize: critical persists before low-severity ──────────────

class _StubCH:
    async def insert_detailed(self, table, rows, dedup_token=""):
        return main.InsertOutcome(committed=True, kind="committed", rows=len(list(rows)))


def _drive_cycle(monkeypatch, window, *, storm: bool):
    """Run ONE real engine cycle over `window`, recording the order in which
    objects are persisted (their peak severity)."""
    main.WINDOW_BUFFER.clear(); main._BUFFERED_IDS.clear()
    main._BUFFERED_ID_ORDER.clear(); main._PROCESSED_IDS.clear()
    main._TENANT_EDGES.clear()
    for s in window:
        main.WINDOW_BUFFER.append(s)
        main._BUFFERED_ID_ORDER.append(str(s.signal_id))
        main._BUFFERED_IDS.add(str(s.signal_id))
    order: list[int] = []

    async def _rec(snap, version, state, win, merged_into="", loop_yield=None):
        if state == "open":
            order.append(max((_SEV_RANK[n.peak_severity] for n in snap.nodes), default=0))

    monkeypatch.setattr(main, "ch", _StubCH())
    monkeypatch.setattr(main, "OPEN_OBJECTS", {})
    monkeypatch.setattr(main, "_persist_snapshot", _rec)
    monkeypatch.setattr(main, "_STORM_ACTIVE", False)
    monkeypatch.setattr(main, "STORM_BUFFER_FRACTION", 0.0 if storm else 1.1)
    monkeypatch.setattr(main, "STORM_EXIT_FRACTION", -0.1 if storm else 0.45)
    monkeypatch.setattr(main, "CORR_STORM_BACKLOG_AGE_S", 0.0)  # isolate the buffer arm
    asyncio.run(main.engine_cycle())
    main.WINDOW_BUFFER.clear(); main._BUFFERED_IDS.clear()
    main._BUFFERED_ID_ORDER.clear(); main._PROCESSED_IDS.clear()
    main._TENANT_EDGES.clear()
    return order


def test_4_storm_persists_criticals_before_low_severity(monkeypatch):
    # A mix of HIGH (low-severity OBJECTS) and CRIT objects, all opening singletons.
    window = tuple(
        [sig(f"high{j}", 0, severity=S.Severity.HIGH) for j in range(6)]
        + [sig(f"crit{j}", 0, severity=S.Severity.CRIT) for j in range(4)])
    order = _drive_cycle(monkeypatch, window, storm=True)
    # Every CRIT (rank 3) is persisted before every HIGH (rank 2): no critical is
    # ever deferred behind a lower-severity object under the per-cycle budget.
    assert order, "no objects persisted"
    first_high = next((i for i, r in enumerate(order) if r == 2), len(order))
    last_crit = max((i for i, r in enumerate(order) if r == 3), default=-1)
    assert last_crit < first_high, f"a critical persisted after a low object: {order}"
    # Determinism: reversing the input order yields the SAME persist order.
    order2 = _drive_cycle(monkeypatch, tuple(reversed(window)), storm=True)
    assert order == order2, "prioritized order is not deterministic"


# ── Test 5 — Preserve / replay + severity-aware eviction ────────────────────

def test_5a_storm_object_replays_byte_for_byte_and_full_offstorm():
    """A storm object reproduces byte-for-byte on replay (same window + recorded
    flag), and re-running the SAME raw window OFF-storm reconstructs the full,
    non-degraded correlation — nothing was lost, the raw is all still present."""
    K = 12
    window = tuple(sig("critdev", i, severity=S.Severity.CRIT) for i in range(K))
    storm_obj = run_window(window, CAT, (), storm_mode=True)[0]

    # (1) determinism pin: replay passes the RECORDED storm flag ⇒ identical bytes.
    stored, replay_window = persist_and_rehydrate(storm_obj, window)
    assert len(replay_window) == K, "raw window count changed — evidence lost"
    report = replay(stored, replay_window)
    assert report.engine_pin_match and report.clean, report.differences

    # (2) preserve: OFF-storm re-run of the SAME raw reconstructs FULL correlation.
    full = run_window(window, CAT, (), storm_mode=False)[0]
    assert full.signal_count() == K, "off-storm replay did not recover every instance"
    assert not full.storm_mode and not _blob_has_degradation(full)
    assert storm_obj.signal_count() == 1, "storm object should be the degraded (deduped) form"


def test_5b_severity_aware_eviction_never_drops_a_critical_when_low_value_exists(monkeypatch):
    """§4: under a declared storm, a full window evicts the LOWEST-severity signal in
    the oldest-scan window — a critical at the head is spared while a low-value exists."""
    monkeypatch.setattr(main, "_STORM_ACTIVE", True)
    monkeypatch.setattr(main, "CORR_STORM_EVICT_SCAN", 512)
    main.WINDOW_BUFFER.clear(); main._BUFFERED_IDS.clear()
    main._BUFFERED_ID_ORDER.clear(); main._PROCESSED_IDS.clear()
    main.TENANT_WATERMARK.clear()
    maxlen = main.WINDOW_BUFFER.maxlen
    # Fill: a CRITICAL at the very head (oldest), then low-value WARN noise to full.
    crit = sig("crit-head", 0, severity=S.Severity.CRIT)
    main.buffer_signal(crit)
    for j in range(1, maxlen):
        main.buffer_signal(sig(f"warn{j}", 0, severity=S.Severity.WARN, ts_off=j))
    assert len(main.WINDOW_BUFFER) == maxlen
    shed_before = main.STORM_SHED_LOWVALUE
    # One more signal forces an eviction. The victim MUST be a WARN, not the CRIT.
    main.buffer_signal(sig("newer", 0, severity=S.Severity.WARN, ts_off=maxlen))
    ids = {str(s.signal_id) for s in main.WINDOW_BUFFER}
    assert str(crit.signal_id) in ids, "severity-aware eviction dropped the CRITICAL"
    assert main.STORM_SHED_LOWVALUE == shed_before + 1
    assert main.STORM_SHED_CRITICAL_SPARED >= 1, "did not record sparing the critical"
    # Lockstep invariant preserved (the tracker-156 desync guard).
    assert len(main.WINDOW_BUFFER) == len(main._BUFFERED_ID_ORDER) == maxlen
    assert {str(s.signal_id) for s in main.WINDOW_BUFFER} == set(main._BUFFERED_ID_ORDER)
    main.WINDOW_BUFFER.clear(); main._BUFFERED_IDS.clear()
    main._BUFFERED_ID_ORDER.clear(); main._PROCESSED_IDS.clear()


# ── Test 6 — Throughput: per-cycle WORK drops at the storm shape ────────────

def test_6_storm_shape_reduces_per_cycle_work(capsys):
    """The 2.5k storm shape, synthetic: a flood of repeated low-value signals plus a
    few criticals. Storm mode must do LESS per-cycle correlation work than the
    fa4857a5-only (storm=False) path — fewer stored signal instances to hash/serialize
    (the measured GIL stall) and a bounded object count instead of a flood of weak
    episodes — while every critical is still fully correlated."""
    # 200 entities each repeating a low-value signal 30× (6,000 noise instances) +
    # 3 criticals repeating 20× each.
    window = []
    for d in range(200):
        for r in range(30):
            window.append(sig(f"noise{d}", r, severity=S.Severity.WARN, ts_off=r))
    for c in range(3):
        for r in range(20):
            window.append(sig(f"crit{c}", r, severity=S.Severity.CRIT, ts_off=r))
    window = tuple(window)

    t0 = time.perf_counter()
    off = run_window(window, CAT, (), storm_mode=False)
    t_off = time.perf_counter() - t0
    t0 = time.perf_counter()
    on = run_window(window, CAT, (), storm_mode=True)
    t_on = time.perf_counter() - t0

    # The per-cycle WORK that scales badly (the measured GIL stall) is content_hash /
    # material_hash / to_evidence_rows serialization, which is O(signal instances) on
    # each PERSISTED real object. Dedup cuts that on the objects that actually persist.
    crit_off = [s for s in off if not s.storm_aggregate]
    crit_on = [s for s in on if not s.storm_aggregate]
    real_stored_off = sum(s.signal_count() for s in crit_off)   # 3 crit × 20 = 60
    real_stored_on = sum(s.signal_count() for s in crit_on)     # 3 crit × 1  = 3
    assert len(crit_off) == len(crit_on) == 3, "criticals must stay fully correlated"
    assert real_stored_on < real_stored_off, (real_stored_on, real_stored_off)

    # The 6,000-instance / 200-entity noise flood collapses to ONE bounded aggregate
    # object that COUNTS it (occurrences), instead of scaling object/serialize work
    # with the flood — the per-cycle work stays bounded no matter how broad the storm.
    agg = _aggregate_of(on)
    assert agg.storm_occurrences == 6000, "aggregate must count the whole noise flood"
    assert agg.storm_distinct_entities == 200
    # Determinism of the whole storm cycle (byte-identical re-run).
    assert [s.content_hash() for s in on] == [
        s.content_hash() for s in run_window(window, CAT, (), storm_mode=True)]

    print(f"\n[throughput] real-object stored-signals off={real_stored_off} "
          f"on={real_stored_on} (x{real_stored_off/max(1,real_stored_on):.1f} fewer to "
          f"hash/serialize)  noise flood: {6000} instances / 200 entities -> 1 bounded "
          f"aggregate (occurrences={agg.storm_occurrences})  cycle time off={t_off*1000:.1f}ms "
          f"on={t_on*1000:.1f}ms")
