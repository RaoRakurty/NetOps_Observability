"""P2 delivery step 4a — the LIFECYCLE COHORT WINDOW.

Spec: `docs/design/COHORT_TOUCH_GATE_P1_2026-08-28.md` §4 (the hoist this
repairs) and `docs/scale/P2_STEPS012_2P5K_VERDICT_2026-08-29.md` §4.2 (the
measured regression):

    "With CORR_ENGINE_EPOCH_BUDGET_S=300 and a cohort costing ~1,000 s, every
     epoch drained exactly one cohort, so the epoch-cadence merge/quiesce/cap
     pass sees ONE cohort's `seen` set — the per-cohort lifecycle P1 replaced —
     and the 378 merges P1 found fell back to 11."

THE CLAIM UNDER TEST: `find_merges` can only fold a quiet object into a LIVE
one, and "live" was defined as "materialized in this EPOCH". Once an epoch is
one cohort wide that definition collapses, and an object that materialized two
cohorts ago stops being a merge TARGET. Keeping the last K cohorts' seen sets in
a deque that outlives the epoch restores the candidate space P1 measured,
independently of where the epoch boundaries fall.

SCOPE — and this is the one place these notes depart from the brief. The window
widens ONLY the survivor/stale partition handed to `find_merges`. Quiesce and
the 163 count cap keep the EPOCH's own set, and `test_L4` pins that. The reason
is in `main.CORR_LIFECYCLE_COHORT_WINDOW`: `seen` is also how quiesce says
"don't age this object", and a cohort can be ~1,000 s wide at 2.5K, so K
cohorts of history would hold objects open for hours past CORR_QUIESCE_S and
push the population onto the 163 cap instead of closing it. P1's own protection
was bounded — one epoch of a FROZEN `now` — not unbounded. `last_seen` +
CORR_QUIESCE_S is the time-bounded rule that already does that job correctly,
and the measured regression (§4.2) is a MERGE regression.

Mutant checks:
  * **L1/L1b** the regression shape itself — 5 epochs x 1 cohort, the merge
    target materializes in cohort 1 and the quiet twin arrives later. With the
    window the merge is found; with `CORR_LIFECYCLE_COHORT_WINDOW=0` (the
    shipped P1 shape) it is NOT. Delete the window and L1 goes red.
  * **L2** the window is a BOUND: a target that has rolled off K cohorts is no
    longer a survivor. Make the deque unbounded and L2 goes red.
  * **L3** the deque is fed per COHORT and outlives the epoch.
  * **L4** quiesce and the cap are NOT widened (the deviation above, pinned).
  * **L5** a cohort that raises contributes nothing to the window.
  * **L6** the counters reach `epoch_state()` and /metrics.
"""
from __future__ import annotations

import asyncio
import uuid
from collections import deque
from dataclasses import replace as dc_replace
from datetime import datetime, timedelta, timezone

import pytest

import main
from catalog import builtin_catalog
from engine import EngineConfig, ObjectSnapshot, run_window
from signals import (
    EntityType,
    ModalityClass,
    Observer,
    ObserverType,
    Severity,
    Signal,
    Source,
)

CAT = builtin_catalog()
CFG = EngineConfig()
T0 = datetime(2026, 8, 29, 10, 0, 0, tzinfo=timezone.utc)


# ── fixtures ─────────────────────────────────────────────────────────────────

def sig(kind: str, entity_id: str, *, offset_s: float = 0.0,
        modality: ModalityClass = ModalityClass.DEVICE_TELEMETRY,
        tenant: str = "t1", severity: Severity = Severity.HIGH,
        now: datetime | None = None) -> Signal:
    base = T0 if now is None else now
    return Signal(
        tenant_id=tenant, ts=base + timedelta(seconds=offset_s), source=Source.METRIC,
        kind=kind,
        observer=Observer(observer_id="obs1", observer_type=ObserverType.DEVICE),
        modality_class=modality, entity_type=EntityType.INTERFACE,
        entity_id=entity_id, severity=severity,
        native_id=f"p2lw|{tenant}|{kind}|{entity_id}|{offset_s}|{base.timestamp()}",
        attrs={"onset_uncertainty_s": 5.0})


def component(dev: str, *, now: datetime | None = None) -> list[Signal]:
    """One two-node, identity-grounded component on `dev` (the pair always edges)."""
    return [
        sig("if_util_high", f"{dev}:Gi0/1", offset_s=-60, now=now),
        sig("if_errors_high", f"{dev}:Gi0/1", offset_s=-55,
            modality=ModalityClass.CONTROL_PLANE, severity=Severity.WARN, now=now),
    ]


class _StubCH:
    def __init__(self) -> None:
        self.rows: dict[str, list[dict]] = {}

    async def insert(self, table, rows, **kw):
        self.rows.setdefault(table, []).extend(dict(r) for r in rows)
        return True

    def merges(self) -> list[tuple[str, str]]:
        return [(r["correlation_id"], r.get("merged_into", ""))
                for r in self.rows.get("netops.corr_objects", [])
                if r["state"] == "merged"]


def _load(sigs) -> None:
    for s in sigs:
        sid = str(s.signal_id)
        main.WINDOW_BUFFER.append(s)
        main._BUFFERED_ID_ORDER.append(sid)
        main._BUFFERED_IDS.add(sid)
        main._advance_watermark(s, 0.0)


def _clear_stream() -> None:
    main.WINDOW_BUFFER.clear(); main._BUFFERED_IDS.clear()
    main._BUFFERED_ID_ORDER.clear(); main._PROCESSED_IDS.clear()
    main.TENANT_WATERMARK.clear(); main._TENANT_EDGES.clear()


def _reset() -> None:
    _clear_stream()
    main._ARCHIVE_SLICE_HASH.clear()
    main._LIFECYCLE_SEEN_WINDOW.clear()
    main.OPEN_OBJECTS.clear()


@pytest.fixture
def _stack(monkeypatch):
    _reset()
    monkeypatch.setattr(main, "OPEN_OBJECTS", {})
    monkeypatch.setattr(main, "_EVIDENCE_QUEUE", None)
    monkeypatch.setattr(main, "_EVIDENCE_TASK", None)
    monkeypatch.setattr(main, "_EVIDENCE_LOOP", None)
    monkeypatch.setattr(main, "ch", _StubCH())
    monkeypatch.setattr(main, "CORR_COHORT_TOUCH_GATE", True)
    monkeypatch.setattr(main, "CORR_LIFECYCLE_EPOCH_CADENCE", True)
    monkeypatch.setattr(main, "CORR_ENGINE_COHORT_SIZE", 50)
    # Nothing may quiesce-close during these tests: the subject is the MERGE
    # candidate space, and a close would remove the object under test.
    monkeypatch.setattr(main, "CORR_QUIESCE_S", 10_000_000.0)
    monkeypatch.setattr(main, "LIFECYCLE_PASSES_TOTAL", 0)
    # A FRESH deque per test, restored on teardown: `_regression_run` rebinds it
    # to set the K under test, and a leaked maxlen would silently shrink every
    # later test's window (it did, on the first run of this file).
    monkeypatch.setattr(
        main, "_LIFECYCLE_SEEN_WINDOW",
        deque(maxlen=main.CORR_LIFECYCLE_COHORT_WINDOW or 1))
    yield monkeypatch
    _reset()


def _register_twin(target: ObjectSnapshot, now: datetime) -> str:
    """A QUIET duplicate of `target`: same entities, same window, different cid.

    This is the shape `find_merges` exists for — one incident re-identified after
    its earliest signal aged out of the window (#111 / §4.4). It is never
    materialized by any cohort, so it is always a merge CANDIDATE and never a
    survivor; whether it can merge depends entirely on whether its target counts
    as live."""
    twin_cid = str(uuid.uuid5(uuid.NAMESPACE_URL, f"twin|{target.correlation_id}"))
    twin = dc_replace(target, correlation_id=twin_cid)
    main.OPEN_OBJECTS[twin_cid] = {
        "version": 1, "hash": "h", "material": "m",
        "last_seen": now, "last_persist": now, "snapshot": twin, "opened_at": now,
    }
    return twin_cid


async def _one_cohort_epoch(now: datetime, *, lifecycle: bool = True):
    """ONE epoch holding ONE cohort — the budget-bounded shape of §4.2."""
    epoch = await main._begin_epoch(now)
    try:
        await main.engine_cycle(epoch)
        epoch.cohorts = 1
        if lifecycle:
            await main._epoch_lifecycle(epoch, main._make_loop_yield()[0])
        # A COPY: `_close_epoch` (the finally below) empties the epoch's own set,
        # and returning the live object would hand the caller an empty one.
        return set(epoch.seen)
    finally:
        main._close_epoch(epoch)
        await main.evidence_drain(30.0)


async def _regression_run(window_k: int,
                          twin_after: int = 1) -> tuple[_StubCH, str, str]:
    """The §4.2 regression shape, driven end to end.

    Five epochs, ONE cohort each. Cohort 1 materializes the merge TARGET; the
    later cohorts materialize other devices and the target's evidence is gone
    from the window, so from epoch 2 on the target is not in any epoch's `seen`.
    The quiet twin is registered after cohort `twin_after` — moving that later
    is how L2 pushes the target out of a SHORT window while leaving it inside a
    long one. The question every pass asks is the one the regression broke: is
    an object that materialized several cohorts ago still a merge target?
    """
    now = datetime.now(timezone.utc).replace(microsecond=0)
    main.CORR_LIFECYCLE_COHORT_WINDOW = window_k
    main._LIFECYCLE_SEEN_WINDOW.clear()
    main._LIFECYCLE_SEEN_WINDOW = type(main._LIFECYCLE_SEEN_WINDOW)(
        maxlen=window_k or 1)

    # Cohort 1: the target materializes.
    _load(component("merge-target", now=now))
    await _one_cohort_epoch(now)
    target_cid = next(iter(main.OPEN_OBJECTS))
    target = main.OPEN_OBJECTS[target_cid]["snapshot"]
    twin_cid = ""
    if twin_after <= 1:
        twin_cid = _register_twin(target, now)

    # Cohorts 2..5: other devices only. The target's evidence is gone from the
    # window, so it materializes in none of them.
    for k in range(2, 6):
        _clear_stream()
        _load(component(f"other-{k}", now=now + timedelta(seconds=k)))
        seen = await _one_cohort_epoch(now + timedelta(seconds=k))
        assert target_cid not in seen, "the target must be quiet from cohort 2 on"
        if k == twin_after:
            twin_cid = _register_twin(target, now)
    assert twin_cid, "twin_after must name a cohort this fixture actually runs"
    return main.ch, target_cid, twin_cid


# ═══ L1 — the regression shape ═══════════════════════════════════════════════

def test_L1_the_window_restores_the_merge_the_budget_lost(_stack):
    """WITH the window (K = 20 = CORR_ENGINE_DRAIN_COHORTS) the quiet twin folds
    into the target that materialized in cohort 1."""
    ch, target_cid, twin_cid = asyncio.run(_regression_run(20))
    assert ch.merges() == [(twin_cid, target_cid)], (
        "the twin must merge into the target that was live K cohorts ago")
    assert twin_cid not in main.OPEN_OBJECTS
    assert target_cid in main.OPEN_OBJECTS, "a survivor is never merged away"


def test_L1b_MUTANT_without_the_window_the_merge_is_lost(_stack):
    """The same fixture on the shipped P1 shape (`CORR_LIFECYCLE_COHORT_WINDOW=0`
    ⇒ the epoch's own seen set): every pass sees ONE cohort, the target is not in
    it, and the merge is never found. This is run `p2-s012d`'s 378 -> 11."""
    ch, _target_cid, twin_cid = asyncio.run(_regression_run(0))
    assert ch.merges() == [], (
        "without the window a one-cohort epoch has no live merge target — if "
        "this ever passes, L1 is proving nothing")
    assert twin_cid in main.OPEN_OBJECTS


# ═══ L2 — the window is a BOUND ══════════════════════════════════════════════

def test_L2_a_target_that_rolled_off_K_cohorts_is_no_longer_a_survivor(_stack):
    """The twin arrives after cohort 3, so the target's cohort-1 sighting is two
    entries deep. With K=2 it has rolled off and the merge is NOT found; with
    K=20 the same fixture finds it. A deque that grew without bound would find
    it either way — and would be a memory leak besides."""
    ch, _target, twin_cid = asyncio.run(_regression_run(2, twin_after=3))
    assert ch.merges() == [], "the deque's maxlen must actually bound it"
    assert twin_cid in main.OPEN_OBJECTS
    assert len(main._LIFECYCLE_SEEN_WINDOW) == 2

    _reset()
    main.ch = _StubCH()
    ch2, target2, twin2 = asyncio.run(_regression_run(20, twin_after=3))
    assert ch2.merges() == [(twin2, target2)], (
        "the SAME fixture under a long enough window must find the merge — "
        "otherwise L2 is measuring the fixture, not the bound")


# ═══ L3 — the deque is fed per cohort and outlives the epoch ═════════════════

def test_L3_the_window_is_fed_per_cohort_and_survives_epoch_boundaries(_stack):
    """Three one-cohort epochs ⇒ three entries, each holding that cohort's ids.
    `_close_epoch` must NOT touch it — outliving the epoch is the whole point."""
    async def go():
        now = datetime.now(timezone.utc).replace(microsecond=0)
        seen_per_cohort = []
        for k in range(3):
            _clear_stream()
            _load(component(f"dev-{k}", now=now + timedelta(seconds=k)))
            seen_per_cohort.append(
                set(await _one_cohort_epoch(now + timedelta(seconds=k))))
        return seen_per_cohort

    _stack.setattr(main, "CORR_LIFECYCLE_COHORT_WINDOW", 20)
    per_cohort = asyncio.run(go())
    assert len(main._LIFECYCLE_SEEN_WINDOW) == 3
    assert list(main._LIFECYCLE_SEEN_WINDOW) == per_cohort
    assert main.LIFECYCLE_PASSES_TOTAL == 3


def test_L3b_the_epochs_own_set_is_always_included(_stack):
    """A cohort that has not yet been appended (the pass runs before the next
    append, and a raising cohort never appends) must still count as seen."""
    async def go():
        now = datetime.now(timezone.utc).replace(microsecond=0)
        _load(component("dev-a", now=now))
        epoch = await main._begin_epoch(now)
        try:
            await main.engine_cycle(epoch)
            main._LIFECYCLE_SEEN_WINDOW.clear()      # nothing in the deque
            assert epoch.seen
            assert main._lifecycle_merge_seen(epoch) == epoch.seen
        finally:
            main._close_epoch(epoch)
            await main.evidence_drain(30.0)
    _stack.setattr(main, "CORR_LIFECYCLE_COHORT_WINDOW", 20)
    asyncio.run(go())


# ═══ L4 — quiesce and the cap are NOT widened ════════════════════════════════

def test_L4_quiesce_still_closes_an_object_the_window_remembers(_stack):
    """The documented deviation, pinned. An object in the merge window but not
    in this epoch's `seen` must still age out on CORR_QUIESCE_S — otherwise the
    window would silently disable the quiesce rule for K cohorts, which at 2.5K
    is hours."""
    async def go():
        now = datetime.now(timezone.utc).replace(microsecond=0)
        _load(component("quiet-dev", now=now))
        await _one_cohort_epoch(now)
        cid = next(iter(main.OPEN_OBJECTS))
        assert list(main._LIFECYCLE_SEEN_WINDOW) == [{cid}], (
            "the object must be IN the merge window for this test to mean "
            "anything")
        # Its evidence is gone and quiesce is immediate: the next epoch must
        # close it, window membership notwithstanding.
        _clear_stream()
        main.CORR_QUIESCE_S = 0.0
        await _one_cohort_epoch(now + timedelta(seconds=1))
        assert cid not in main.OPEN_OBJECTS, (
            "the merge window must not protect an object from quiesce")
        states = [(r["correlation_id"], r["state"])
                  for r in main.ch.rows["netops.corr_objects"]]
        assert (cid, "closed") in states
    _stack.setattr(main, "CORR_LIFECYCLE_COHORT_WINDOW", 20)
    asyncio.run(go())


def test_L4b_the_count_cap_still_evicts_an_object_the_window_remembers(_stack):
    """Same deviation, the 163 cap arm: the cap is a BOUND and a bound that
    yields to a K-cohort memory is not a bound."""
    async def go():
        now = datetime.now(timezone.utc).replace(microsecond=0)
        for k in range(3):
            _clear_stream()
            _load(component(f"capdev-{k}", now=now + timedelta(seconds=k)))
            await _one_cohort_epoch(now + timedelta(seconds=k))
        assert len(main.OPEN_OBJECTS) == 3
        assert len(main._LIFECYCLE_SEEN_WINDOW) == 3
        main.CORR_OPEN_OBJECTS_MAX = 1
        _clear_stream()
        _load(component("capdev-new", now=now + timedelta(seconds=9)))
        await _one_cohort_epoch(now + timedelta(seconds=9))
        assert len(main.OPEN_OBJECTS) <= 1, (
            "the cap must hold whatever the merge window remembers")
    _stack.setattr(main, "CORR_LIFECYCLE_COHORT_WINDOW", 20)
    _stack.setattr(main, "CORR_OPEN_OBJECTS_MAX", 1000)
    asyncio.run(go())


# ═══ L5 — a failing cohort contributes nothing ═══════════════════════════════

def test_L5_a_cohort_that_raises_never_widens_a_later_pass(_stack):
    """`_LIFECYCLE_SEEN_WINDOW` is appended AFTER the cohort has committed its
    versions, so a cohort that raised leaves no ids behind — the same rule P1
    applied to the epoch's own pass."""
    async def go():
        now = datetime.now(timezone.utc).replace(microsecond=0)
        _load(component("boom-dev", now=now))
        epoch = await main._begin_epoch(now)
        real = main._persist_snapshot

        async def boom(*a, **kw):
            raise RuntimeError("persist exploded")

        main._persist_snapshot = boom
        try:
            with pytest.raises(RuntimeError):
                await main.engine_cycle(epoch)
        finally:
            main._persist_snapshot = real
            main._close_epoch(epoch)
        assert len(main._LIFECYCLE_SEEN_WINDOW) == 0
    _stack.setattr(main, "CORR_LIFECYCLE_COHORT_WINDOW", 20)
    asyncio.run(go())


# ═══ L6 — observability ══════════════════════════════════════════════════════

def test_L6_the_window_is_visible_in_epoch_state_and_metrics(_stack):
    """§10: the invariant an operator reads is `cohorts_last` = 1 (a
    budget-bounded epoch) while `lifecycle_seen_window_cohorts` = K."""
    async def go():
        now = datetime.now(timezone.utc).replace(microsecond=0)
        for k in range(3):
            _clear_stream()
            _load(component(f"obs-{k}", now=now + timedelta(seconds=k)))
            await _one_cohort_epoch(now + timedelta(seconds=k))
    _stack.setattr(main, "CORR_LIFECYCLE_COHORT_WINDOW", 20)
    asyncio.run(go())
    st = main.epoch_state()
    assert st["lifecycle_cohort_window"] == 20
    assert st["lifecycle_seen_window_cohorts"] == 3
    assert st["lifecycle_seen_window_ids"] == 3
    text = main._metrics_text()
    assert "corr_lifecycle_seen_window_cohorts 3" in text
    assert "corr_lifecycle_seen_window_ids 3" in text


def test_L6b_the_flag_reverts_the_window_on_one_image(_stack):
    """`CORR_LIFECYCLE_COHORT_WINDOW=0` ⇒ the P1 shape: nothing is appended and
    the candidate space is exactly the epoch's own set."""
    async def go():
        now = datetime.now(timezone.utc).replace(microsecond=0)
        _load(component("ab-dev", now=now))
        epoch = await main._begin_epoch(now)
        try:
            await main.engine_cycle(epoch)
            assert len(main._LIFECYCLE_SEEN_WINDOW) == 0
            assert main._lifecycle_merge_seen(epoch) is epoch.seen
        finally:
            main._close_epoch(epoch)
            await main.evidence_drain(30.0)
    _stack.setattr(main, "CORR_LIFECYCLE_COHORT_WINDOW", 0)
    asyncio.run(go())


def test_L6c_the_per_cohort_cadence_ignores_the_window_entirely(_stack):
    """`CORR_LIFECYCLE_EPOCH_CADENCE=0` is the pre-P1 A/B arm: the pass runs
    after EVERY cohort against THAT cohort's set, and an explicit `seen` must
    never be widened by the window."""
    async def go():
        now = datetime.now(timezone.utc).replace(microsecond=0)
        _load(component("pc-dev", now=now))
        epoch = await main._begin_epoch(now)
        try:
            await main.engine_cycle(epoch)
        finally:
            main._close_epoch(epoch)
            await main.evidence_drain(30.0)
        cid = next(iter(main.OPEN_OBJECTS))
        target = main.OPEN_OBJECTS[cid]["snapshot"]
        twin = _register_twin(target, now)
        # An explicit (empty) seen set: no survivors ⇒ no merge, whatever the
        # window remembers.
        epoch2 = await main._begin_epoch(now + timedelta(seconds=1))
        try:
            await main._epoch_lifecycle(epoch2, main._make_loop_yield()[0],
                                        seen=set())
        finally:
            main._close_epoch(epoch2)
            await main.evidence_drain(30.0)
        assert twin in main.OPEN_OBJECTS and cid in main.OPEN_OBJECTS
        assert main.ch.merges() == []
    _stack.setattr(main, "CORR_LIFECYCLE_COHORT_WINDOW", 20)
    _stack.setattr(main, "CORR_LIFECYCLE_EPOCH_CADENCE", False)
    asyncio.run(go())


# ═══ a sanity check on the fixture itself ════════════════════════════════════

def test_L0_the_twin_really_is_a_mergeable_duplicate(_stack):
    """If the twin could not merge under ANY cadence, L1/L1b would both pass for
    the wrong reason. Prove the predicate accepts it when the target is live."""
    from engine import find_merges
    win = component("sanity-dev")
    target = run_window(win, CAT, (), CFG)[0]
    twin_cid = str(uuid.uuid5(uuid.NAMESPACE_URL, f"twin|{target.correlation_id}"))
    twin = dc_replace(target, correlation_id=twin_cid)
    assert find_merges([target], [twin]) == [(twin_cid, target.correlation_id)]
    assert find_merges([], [twin]) == [], "no survivor, no merge"
