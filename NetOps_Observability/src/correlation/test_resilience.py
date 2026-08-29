"""Load / resilience bounds (gap-report #10, §9 'all queues bounded'). The engine's
working memory must stay bounded and correct under a signal flood and at-least-once
Kafka redelivery — no unbounded growth, no silently-dropped fresh signals."""

import asyncio
import time
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


def run(coro):
    return asyncio.run(coro)


T0 = datetime(2026, 6, 22, 9, 0, 0, tzinfo=timezone.utc)


def mk(i: int, *, ts: datetime | None = None) -> Signal:
    return Signal(
        tenant_id="t1", ts=ts or (T0 + timedelta(seconds=i % 100)), source=Source.METRIC,
        kind="if_util_high", observer=Observer(observer_id="o", observer_type=ObserverType.DEVICE),
        modality_class=ModalityClass.DEVICE_TELEMETRY, entity_type=EntityType.INTERFACE,
        entity_id=f"d:Gi0/{i}", severity=Severity.HIGH, native_id=f"n{i}", attrs={},
    )


@pytest.fixture(autouse=True)
def _clean_buffer():
    """Isolate the shared module globals between tests."""
    main.WINDOW_BUFFER.clear()
    main._BUFFERED_IDS.clear()
    yield
    main.WINDOW_BUFFER.clear()
    main._BUFFERED_IDS.clear()


def test_window_buffer_is_maxlen_bounded():
    assert main.WINDOW_BUFFER.maxlen is not None, "the window buffer MUST be bounded (§9)"


def test_dedup_set_never_exceeds_the_buffer_under_flood():
    # Push well past maxlen — a flood the engine must survive without leaking memory.
    n = main.WINDOW_BUFFER.maxlen + 5_000
    for i in range(n):
        main.buffer_signal(mk(i))
    assert len(main.WINDOW_BUFFER) == main.WINDOW_BUFFER.maxlen
    # The dedup set must track the buffer, NOT the total ingested count.
    assert len(main._BUFFERED_IDS) == len(main.WINDOW_BUFFER), "dedup set leaked past the buffer"


def test_at_least_once_redelivery_is_deduped_within_the_window():
    for _ in range(3):  # same signal delivered 3×
        main.buffer_signal(mk(1))
    assert len(main.WINDOW_BUFFER) == 1
    assert len(main._BUFFERED_IDS) == 1


def test_an_evicted_signal_is_not_falsely_deduped_after_overflow():
    # signal 0 is evicted once the buffer overflows; if its stale id lingered in the
    # dedup set, a genuine redelivery would be wrongly dropped. Lockstep prevents that.
    for i in range(main.WINDOW_BUFFER.maxlen + 1):
        main.buffer_signal(mk(i))
    evicted = str(mk(0).signal_id)
    assert evicted not in main._BUFFERED_IDS, "evicted signal's id must leave the dedup set"
    before = len(main.WINDOW_BUFFER)
    main.buffer_signal(mk(0))  # redelivery of the evicted signal
    # It re-enters (not falsely deduped); buffer stays at maxlen (one more eviction).
    assert str(mk(0).signal_id) in main._BUFFERED_IDS
    assert len(main.WINDOW_BUFFER) == before == main.WINDOW_BUFFER.maxlen


def test_prune_ages_out_old_signals_and_their_ids():
    old = mk(1, ts=T0)
    fresh_ts = T0 + timedelta(seconds=main.RETENTION_REQUIRED_S + 10_000)
    fresh = mk(2, ts=fresh_ts)
    main.buffer_signal(old)
    main.buffer_signal(fresh)
    run(main._prune_buffer(fresh_ts))
    ids = {str(s.signal_id) for s in main.WINDOW_BUFFER}
    assert str(old.signal_id) not in ids, "aged-out signal pruned from buffer"
    assert str(old.signal_id) not in main._BUFFERED_IDS, "aged-out id pruned from dedup set"
    assert str(fresh.signal_id) in main._BUFFERED_IDS
    # Invariant after pruning: dedup set and buffer agree exactly.
    assert len(main._BUFFERED_IDS) == len(main.WINDOW_BUFFER)


# ── H14: a device clock years ahead must not freeze window pruning ────────────
def test_h14_far_future_ts_cannot_freeze_pruning_for_everyone():
    """A +5y device timestamp must not be able to distort retention.

    The failure mode CHANGED with tracker 165 and got sharper, so this test now
    guards the new one as well as the old:

      * pre-165 (wall-clock left-pop): one far-future ts at the HEAD stopped
        pruning for every tenant until restart — head-of-line freeze.
      * post-165 (stream-time): the head cannot block anything (survivors are
        filtered, not popped), but an unclamped +5y ts would POISON THE TENANT
        WATERMARK and instantly expire every legitimate signal behind it. That
        is the worse failure: silent mass eviction instead of no eviction.

    The H14 clamp is what prevents both, so it is asserted first."""
    now = datetime.now(timezone.utc)
    future_ts = now + timedelta(days=5 * 365)
    before = main.EVENT_TS_FUTURE_CLAMPED
    main.buffer_signal(mk(1, ts=future_ts))
    assert main.EVENT_TS_FUTURE_CLAMPED == before + 1, "clamp must be counted (§10)"
    head = main.WINDOW_BUFFER[0]
    assert head.ts <= now + timedelta(seconds=main.METRIC_FUTURE_SKEW_S + 60), \
        "future ts must be clamped to arrival time"
    # Identity survives the clamp: the corr_signals row, window dedup and the
    # archive slice all keep comparing the SAME id.
    assert str(head.signal_id) == str(mk(1, ts=future_ts).signal_id)
    for i in range(2, 7):
        main.buffer_signal(mk(i, ts=now))

    # (a) the watermark was NOT poisoned: it sits at ~now, not five years out.
    wm_ts, _ = main.TENANT_WATERMARK[head.tenant_id]
    assert wm_ts <= now.timestamp() + main.METRIC_FUTURE_SKEW_S + 60, \
        "a clamped signal must not push the tenant's stream clock into the future"

    # (b) so nothing is expired yet — every signal is current in stream time,
    # and wall-clock age is now irrelevant to retention by design.
    run(main._prune_buffer(now + timedelta(hours=2)))
    assert len(main.WINDOW_BUFFER) == 6, \
        "stream time has not advanced, so nothing may be evicted by wall clock"

    # (c) and when the STREAM really does move on, the clamped head ages out
    # with everything else — no head-of-line freeze.
    main.TENANT_WATERMARK[head.tenant_id] = (
        now.timestamp() + main.RETENTION_REQUIRED_S + 60, time.monotonic())
    run(main._prune_buffer(now))
    assert len(main.WINDOW_BUFFER) == 0, \
        "a clamped head must age out once the stream passes it"
    assert len(main._BUFFERED_IDS) == 0


def test_h14_past_stale_ts_is_counted_but_never_restamped():
    """The PAST direction is deliberately NOT re-stamped (fabricated freshness
    would corrupt cause/effect order) — the arrival-ordered deque ages a stale
    head out on the next prune. But it IS counted, so a device stuck in the
    past is visible instead of silently never correlating."""
    now = datetime.now(timezone.utc)
    stale = mk(1, ts=now - timedelta(hours=3))  # past METRIC_MAX_AGE_S
    before = main.EVENT_TS_PAST_STALE
    main.buffer_signal(stale)
    assert main.EVENT_TS_PAST_STALE == before + 1
    assert main.WINDOW_BUFFER[0].ts == stale.ts, "honest event time is kept"
    # A device stuck 3 hours in the past does not advance the stream clock past
    # itself, so on its own it is not expired — correct: with no other traffic
    # for that tenant there is nothing to say its evidence is obsolete. The
    # moment any CURRENT signal arrives the stream moves and the stale one goes.
    run(main._prune_buffer(now))
    assert len(main.WINDOW_BUFFER) == 1
    main.buffer_signal(mk(2, ts=now))
    run(main._prune_buffer(now))
    assert [s.native_id for s in main.WINDOW_BUFFER] == [mk(2, ts=now).native_id], \
        "a stale signal ages out as soon as the tenant's stream moves past it"


# ── C2: #76 — debug_only / platform-self-check probes never form objects ──────
def test_debug_only_probe_is_searchable_but_never_buffered_into_an_object():
    """A platform-self-check probe (e.g. prober->netbox) is DEBUG_ONLY: it stays in
    corr_signals (searchable) but must never open or attach to a correlation object —
    RCA is the customer's network, not the platform's own stack (decision #76)."""
    debug = mk(1)
    debug.attrs["probe_authority"] = "debug_only"
    main.buffer_signal(debug)
    assert len(main.WINDOW_BUFFER) == 0, "debug_only probe must NOT enter object formation"

    customer = mk(2)  # a normal customer signal (no debug_only authority)
    main.buffer_signal(customer)
    assert len(main.WINDOW_BUFFER) == 1, "a customer signal must still buffer normally"


def test_internal_self_probe_never_buffers():
    """Decision #76 (engine-side): a LOW-authority internal_self_probe (platform
    self-monitoring, e.g. prober->clickhouse) stays searchable in corr_signals but must
    never enter object formation — customer RCA reflects the monitored network only.
    A LOW-authority CUSTOMER probe (no internal scope) still buffers normally."""
    internal = mk(1)
    internal.attrs["probe_authority"] = "low"
    internal.attrs["probe_scope"] = "internal_self_probe"
    main.buffer_signal(internal)
    assert len(main.WINDOW_BUFFER) == 0, "internal_self_probe must NOT enter object formation"

    customer = mk(2)
    customer.attrs["probe_authority"] = "low"
    customer.attrs["probe_scope"] = "customer_path"
    main.buffer_signal(customer)
    assert len(main.WINDOW_BUFFER) == 1, "a low-authority CUSTOMER probe must still buffer"


def test_low_authority_probe_still_buffers():
    """Only DEBUG_ONLY is excluded — a LOW-authority probe is support evidence and
    must still form/attach to objects (it just can't anchor a confirmed verdict)."""
    low = mk(3)
    low.attrs["probe_authority"] = "low"
    main.buffer_signal(low)
    assert len(main.WINDOW_BUFFER) == 1


# ── #100 write-side version damping under a sustained storm ───────────────────
# A dead target keeps the same incident alive for hours; every cycle the window
# refreshes with NEW instances of the SAME evidence. Persisting a version per
# cycle grew corr_objects without bound (the 2026-07-09 read-path incident's
# write side). The engine_cycle persistence gate must write only on material
# change, heartbeat, or lifecycle transition.


class _StubCH:
    """Records inserts; stands in for the ClickHouse client in engine_cycle."""

    def __init__(self):
        self.rows: dict = {}

    async def insert(self, table: str, rows: list, dedup_token="") -> None:
        self.rows.setdefault(table, []).extend(rows)


def _storm_sig(kind: str, entity_id: str, *, offset_s: float, now: datetime) -> Signal:
    return Signal(
        tenant_id="t1", ts=now + timedelta(seconds=offset_s), source=Source.METRIC,
        kind=kind, observer=Observer(observer_id="dev1", observer_type=ObserverType.DEVICE),
        modality_class=ModalityClass.DEVICE_TELEMETRY, entity_type=EntityType.DEVICE,
        entity_id=entity_id, severity=Severity.CRIT,
        native_id=f"storm|{kind}|{entity_id}|{offset_s}",
        attrs={"onset_uncertainty_s": 5.0},
    )


def test_version_damping_suppresses_instance_refresh_persists(monkeypatch):
    stub = _StubCH()
    monkeypatch.setattr(main, "ch", stub)
    monkeypatch.setattr(main, "OPEN_OBJECTS", {})
    monkeypatch.setattr(main, "CORR_VERSION_HEARTBEAT_S", 900.0)
    now = datetime.now(timezone.utc)

    # cycle 1: two CRIT signals on one device → an open object, v1 persisted
    main.buffer_signal(_storm_sig("link_state_change", "core-1", offset_s=-60, now=now))
    main.buffer_signal(_storm_sig("device_resource_anomaly", "core-1", offset_s=-55, now=now))
    asyncio.run(main.engine_cycle())
    assert len(stub.rows.get("netops.corr_objects", [])) == 1, "first sighting persists v1"

    # cycle 2: NEW instances of the SAME evidence (storm refresh) → damped, no write
    main.buffer_signal(_storm_sig("link_state_change", "core-1", offset_s=-30, now=now))
    main.buffer_signal(_storm_sig("device_resource_anomaly", "core-1", offset_s=-25, now=now))
    damped_before = main.VERSIONS_DAMPED
    asyncio.run(main.engine_cycle())
    assert len(stub.rows["netops.corr_objects"]) == 1, \
        "an instance refresh of unchanged evidence must NOT persist a new version"
    assert main.VERSIONS_DAMPED == damped_before + 1, "the damped persist is counted"

    # heartbeat elapsed → P3 change A: the object is TOUCHED, not re-versioned.
    # `corr_current` (what bounds UI staleness) gets a fresh row at the SAME
    # version; `corr_objects` gets nothing, because the material did not move.
    (reg,) = main.OPEN_OBJECTS.values()
    reg["last_persist"] = now - timedelta(seconds=1000)
    touched_before = main.VERSIONS_HEARTBEAT_TOUCHED
    current_before = len(stub.rows.get("netops.corr_current", []))
    main.buffer_signal(_storm_sig("link_state_change", "core-1", offset_s=-10, now=now))
    asyncio.run(main.engine_cycle())
    assert len(stub.rows["netops.corr_objects"]) == 1, \
        "an unchanged-material heartbeat must NOT write a corr_objects version"
    assert len(stub.rows["netops.corr_current"]) == current_before + 1, \
        "the heartbeat still refreshes the hot projection (UI staleness bound)"
    assert stub.rows["netops.corr_current"][-1]["version"] == 1, \
        "the touch keeps pointing at a version corr_edges/corr_objects HAVE"
    assert main.VERSIONS_HEARTBEAT_TOUCHED == touched_before + 1


def test_heartbeat_touch_off_restores_the_full_heartbeat_version(monkeypatch):
    """CORR_HEARTBEAT_TOUCH_ONLY=0 must restore the pre-P3 behaviour exactly:
    an elapsed heartbeat writes a whole new corr_objects version."""
    stub = _StubCH()
    monkeypatch.setattr(main, "ch", stub)
    monkeypatch.setattr(main, "OPEN_OBJECTS", {})
    monkeypatch.setattr(main, "CORR_VERSION_HEARTBEAT_S", 900.0)
    monkeypatch.setattr(main, "CORR_HEARTBEAT_TOUCH_ONLY", False)
    now = datetime.now(timezone.utc)
    main.buffer_signal(_storm_sig("link_state_change", "core-1", offset_s=-60, now=now))
    main.buffer_signal(_storm_sig("device_resource_anomaly", "core-1", offset_s=-55, now=now))
    asyncio.run(main.engine_cycle())
    assert len(stub.rows["netops.corr_objects"]) == 1
    (reg,) = main.OPEN_OBJECTS.values()
    reg["last_persist"] = now - timedelta(seconds=1000)
    main.buffer_signal(_storm_sig("link_state_change", "core-1", offset_s=-10, now=now))
    asyncio.run(main.engine_cycle())
    assert len(stub.rows["netops.corr_objects"]) == 2, "heartbeat bounds UI staleness"
    assert stub.rows["netops.corr_objects"][-1]["version"] == 2


def test_version_damping_off_restores_legacy_per_change_persistence(monkeypatch):
    """CORR_VERSION_HEARTBEAT_S=0 must restore the pre-#100 behavior exactly:
    every content_hash change persists."""
    stub = _StubCH()
    monkeypatch.setattr(main, "ch", stub)
    monkeypatch.setattr(main, "OPEN_OBJECTS", {})
    monkeypatch.setattr(main, "CORR_VERSION_HEARTBEAT_S", 0.0)
    now = datetime.now(timezone.utc)
    main.buffer_signal(_storm_sig("link_state_change", "core-1", offset_s=-60, now=now))
    main.buffer_signal(_storm_sig("device_resource_anomaly", "core-1", offset_s=-55, now=now))
    asyncio.run(main.engine_cycle())
    main.buffer_signal(_storm_sig("link_state_change", "core-1", offset_s=-30, now=now))
    asyncio.run(main.engine_cycle())
    assert len(stub.rows["netops.corr_objects"]) == 2, \
        "damping disabled ⇒ every content change persists (legacy)"
