"""Tracker 196 — the tenant-idle backstop must be able to PROVE levelness.

THE DEFECT. `_consumer_caught_up` returned False whenever ANY assigned
partition had never been read by this process
(`CONSUMER_LAG_UNKNOWN_PARTITIONS > 0`). On the lab that count is 17 and 18 on
the two correlation replicas — quiet topics this member owns but never fetches
a record from — so the veto was PERMANENT: `_tenant_idle` could never return
True, `idle_tenant_evictions == 0` on both replicas, and 155c objects were
still `open` 2 h 15 m after their last signal.

THE INVARIANT THAT MUST SURVIVE (tracker 165): evidence may be shed only when
"no unprocessed record can still advance this tenant's clock" is PROVEN. A
partition we are genuinely BEHIND on still vetoes. What changed is only that
"assigned but never read" is now resolved — empty, already-consumed, or truly
behind — instead of being assumed behind forever.

Every test below is either "the veto still holds where it must" or "the veto
lifts where it provably can", plus the §3a isolation property that eviction is
per tenant.
"""
from __future__ import annotations

import asyncio
import time
from datetime import datetime, timedelta, timezone

import pytest

import main
from test_prune_buffer_156 import T0, mk


class _TP:
    """A TopicPartition stand-in: aiokafka's is a NamedTuple of (topic, partition)."""

    def __init__(self, topic: str, partition: int) -> None:
        self.topic, self.partition = topic, partition

    def __hash__(self) -> int:
        return hash((self.topic, self.partition))

    def __eq__(self, other: object) -> bool:
        return (self.topic, self.partition) == (other.topic, other.partition)  # type: ignore[attr-defined]

    def __repr__(self) -> str:
        return f"TP({self.topic},{self.partition})"


class FakeConsumer:
    """Assignment + local watermarks + the two BROKER calls the probe makes.

    `highwater` is the consumer's local view (None until a fetch response has
    carried one). `end_offsets`/`position` are the bounded round trips
    `_probe_unread_partitions` uses to resolve a never-read partition.
    """

    def __init__(self, highwater: dict, ends: dict | None = None,
                 positions: dict | None = None, fail: BaseException | None = None) -> None:
        self._hw = dict(highwater)
        self._ends = dict(ends if ends is not None else highwater)
        self._pos = dict(positions or {})
        self._fail = fail
        self.end_offset_calls = 0
        self.position_calls = 0

    def assignment(self):
        return set(self._hw)

    def highwater(self, tp):
        return self._hw.get(tp)

    async def end_offsets(self, tps):
        self.end_offset_calls += 1
        if self._fail is not None:
            raise self._fail
        return {tp: self._ends[tp] for tp in tps if tp in self._ends}

    async def position(self, tp):
        self.position_calls += 1
        return self._pos.get(tp)


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    """Every test starts from a cold, deterministic lag/eviction state."""
    main.WINDOW_BUFFER.clear(); main._BUFFERED_IDS.clear()
    main._BUFFERED_ID_ORDER.clear(); main._PROCESSED_IDS.clear()
    main.TENANT_WATERMARK.clear()
    main._LAST_OFFSET.clear()
    main._UNREAD_PROBE.clear()
    monkeypatch.setattr(main, "_UNREAD_PROBE_TASK", None)
    monkeypatch.setattr(main, "_LAG_SAMPLED_AT", 0.0)
    monkeypatch.setattr(main, "CONSUMER_LAG_TOTAL", None)
    monkeypatch.setattr(main, "CONSUMER_LAG_AT", 0.0)
    monkeypatch.setattr(main, "CONSUMER_LAG_UNKNOWN_PARTITIONS", 0)
    monkeypatch.setattr(main, "CONSUMER_LAG_UNRESOLVED_PARTITIONS", 0)
    monkeypatch.setattr(main, "CONSUMER_LAG_PROVEN_PARTITIONS", 0)
    monkeypatch.setattr(main, "CONSUMER_LAG_UNREAD_TOTAL", 0)
    monkeypatch.setattr(main, "ENGINE_LAST_SWEEP_MONO", time.monotonic())
    yield
    main.WINDOW_BUFFER.clear(); main._BUFFERED_IDS.clear()
    main._BUFFERED_ID_ORDER.clear(); main._PROCESSED_IDS.clear()
    main.TENANT_WATERMARK.clear(); main._LAST_OFFSET.clear()
    main._UNREAD_PROBE.clear()


def _sample(consumer, now=None):
    """One lag sample, rate limiter reset (it runs per message in production)."""
    now = time.monotonic() if now is None else now
    main._LAG_SAMPLED_AT = 0.0
    main._refresh_consumer_lag(consumer, now)
    return now


def _probe(consumer, tps):
    """Run the probe pass the sampler would have scheduled (no loop in a
    sync unit test, so `_schedule_unread_probe` deliberately does nothing)."""
    asyncio.run(main._probe_unread_partitions(consumer, tuple(tps)))


def _silent_window(n=50, tenant="acme"):
    """A window whose tenant's stream clock froze longer ago than the threshold."""
    for i in range(n):
        s = main.dc_replace(mk(i, i), tenant_id=tenant)
        main.WINDOW_BUFFER.append(s)
        main._BUFFERED_ID_ORDER.append(str(s.signal_id))
        main._BUFFERED_IDS.add(str(s.signal_id))
    main.TENANT_WATERMARK[tenant] = (
        (T0 + timedelta(seconds=100)).timestamp(),
        time.monotonic() - main.CORR_TENANT_IDLE_EVICT_S - 60,
    )


# ── (i) everything read, no lag → provably level → the backstop may act ─────

def test_all_partitions_read_and_level_evicts_the_idle_tenant():
    read_a, read_b = _TP("netops.syslog", 0), _TP("netops.snmp_traps", 0)
    main._LAST_OFFSET[("netops.syslog", 0)] = 99
    main._LAST_OFFSET[("netops.snmp_traps", 0)] = 41
    now = _sample(FakeConsumer({read_a: 100, read_b: 42}))

    assert main.CONSUMER_LAG_TOTAL == 0
    assert main.CONSUMER_LAG_UNRESOLVED_PARTITIONS == 0
    assert main.caught_up_reason(now) == main.CAUGHT_UP_LEVEL
    assert main._consumer_caught_up(now) is True

    _silent_window()
    assert main._tenant_idle("acme", now) is True
    before = main.IDLE_TENANT_EVICTIONS
    asyncio.run(main._prune_buffer(datetime.now(timezone.utc)))
    assert len(main.WINDOW_BUFFER) == 0, "a provably silent tenant's evidence survived"
    assert main.IDLE_TENANT_EVICTIONS == before + 50


# ── (ii) real lag → NOT level → nothing is shed (the 165 invariant) ─────────

def test_real_lag_on_a_read_partition_still_vetoes_eviction():
    read = _TP("netops.syslog", 0)
    main._LAST_OFFSET[("netops.syslog", 0)] = 99
    now = _sample(FakeConsumer({read: 5_000}))

    assert main.CONSUMER_LAG_TOTAL == 4_900
    assert main.caught_up_reason(now) == main.CAUGHT_UP_BEHIND
    assert main._consumer_caught_up(now) is False

    _silent_window()
    assert main._tenant_idle("acme", now) is False, (
        "the backstop fired while records were still unread — wall-clock "
        "delay destroying event-time-valid evidence, tracker 165's defect")
    asyncio.run(main._prune_buffer(datetime.now(timezone.utc)))
    assert len(main.WINDOW_BUFFER) == 50


def test_a_never_read_partition_with_PROVEN_backlog_still_vetoes():
    """The safety property the original clause protected, stated exactly.

    Resolving a partition is not the same as excusing it: end offset 5,000
    against a position of 10 is real, unread work, so levelness stays unproven
    and the backstop must keep holding."""
    read, never = _TP("netops.syslog", 0), _TP("netops.wireless_events", 3)
    main._LAST_OFFSET[("netops.syslog", 0)] = 99
    consumer = FakeConsumer({read: 100, never: 5_000}, positions={never: 10})

    now = _sample(consumer)
    assert main.CONSUMER_LAG_UNRESOLVED_PARTITIONS == 1
    _probe(consumer, [never])
    now = _sample(consumer)

    assert main.CONSUMER_LAG_UNREAD_TOTAL == 4_990
    assert main.CONSUMER_LAG_UNRESOLVED_PARTITIONS == 0
    assert main.caught_up_reason(now) == main.CAUGHT_UP_BEHIND
    assert main._consumer_caught_up(now) is False


# ── (iii) assigned but EMPTY / already consumed → level ─────────────────────

def test_an_empty_never_read_partition_does_not_veto():
    """hw == 0: the partition has never held a record, so nothing can be
    waiting on it. Provable with no broker round trip at all."""
    read = _TP("netops.syslog", 0)
    empties = [_TP(f"netops.quiet{i}", 0) for i in range(18)]   # the lab's 17-18
    main._LAST_OFFSET[("netops.syslog", 0)] = 99
    hw = {read: 100}
    hw.update({tp: 0 for tp in empties})
    consumer = FakeConsumer(hw)

    now = _sample(consumer)
    assert main.CONSUMER_LAG_UNKNOWN_PARTITIONS == 18, (
        "the pre-196 counter must keep its meaning — tracker 172 reads it")
    assert main.CONSUMER_LAG_PROVEN_PARTITIONS == 18
    assert main.CONSUMER_LAG_UNRESOLVED_PARTITIONS == 0
    assert main.caught_up_reason(now) == main.CAUGHT_UP_LEVEL
    assert consumer.end_offset_calls == 0, "an empty partition needs no probe"

    _silent_window()
    assert main._tenant_idle("acme", now) is True


def test_a_never_read_partition_whose_watermark_equals_our_position_is_level():
    """The lab's real shape: a topic with history that this member owns but has
    consumed nothing NEW from — the group's committed position is already the
    end offset, so there is nothing there for us."""
    read, quiet = _TP("netops.syslog", 0), _TP("netops.wireless_events", 3)
    main._LAST_OFFSET[("netops.syslog", 0)] = 99
    consumer = FakeConsumer({read: 100, quiet: 50_000}, positions={quiet: 50_000})

    now = _sample(consumer)
    assert main.caught_up_reason(now) == main.CAUGHT_UP_UNRESOLVED, (
        "before the probe answers, an unread partition MUST still veto")

    _probe(consumer, [quiet])
    now = _sample(consumer)
    assert main.CONSUMER_LAG_UNRESOLVED_PARTITIONS == 0
    assert main.CONSUMER_LAG_UNREAD_TOTAL == 0
    assert main.caught_up_reason(now) == main.CAUGHT_UP_LEVEL
    assert main._consumer_caught_up(now) is True

    _silent_window()
    assert main._tenant_idle("acme", now) is True


def test_the_lab_shape_is_no_longer_permanently_inert():
    """The measured failure, reproduced and then fixed: 17 never-read
    partitions against a tiny drained lag. Pre-196 this could NEVER be caught
    up; post-196 it is, once the partitions are resolved."""
    read = _TP("netops.syslog", 0)
    quiet = [_TP(f"netops.quiet{i}", 0) for i in range(17)]
    main._LAST_OFFSET[("netops.syslog", 0)] = 99
    hw = {read: 100}
    hw.update({tp: 4_096 for tp in quiet})
    consumer = FakeConsumer(hw, positions={tp: 4_096 for tp in quiet})

    now = _sample(consumer)
    assert main.CONSUMER_LAG_UNKNOWN_PARTITIONS == 17
    assert main._consumer_caught_up(now) is False       # pre-196 forever

    _probe(consumer, quiet)
    now = _sample(consumer)
    assert main._consumer_caught_up(now) is True
    assert consumer.end_offset_calls == 1, "one bounded round trip for the batch"


# ── (iv) the probe cannot answer → still not level, and it SAYS so ──────────

def test_a_failing_probe_leaves_the_partition_unresolved_and_says_why(caplog):
    read, quiet = _TP("netops.syslog", 0), _TP("netops.wireless_events", 3)
    main._LAST_OFFSET[("netops.syslog", 0)] = 99
    consumer = FakeConsumer({read: 100, quiet: 50_000},
                            fail=OSError("coordinator unavailable"))
    before = main.CONSUMER_UNREAD_PROBE_FAILURES

    with caplog.at_level("WARNING"):
        _probe(consumer, [quiet])
    now = _sample(consumer)

    assert main.CONSUMER_UNREAD_PROBE_FAILURES == before + 1
    assert main.CONSUMER_LAG_UNRESOLVED_PARTITIONS == 1
    assert main.caught_up_reason(now) == main.CAUGHT_UP_UNRESOLVED
    assert main._consumer_caught_up(now) is False
    assert any("probe failed" in r.getMessage() for r in caplog.records), (
        "a probe that cannot answer must never be a silent fallthrough (§10)")

    _silent_window()
    assert main._tenant_idle("acme", now) is False


def test_a_partition_with_no_watermark_at_all_is_unresolved_not_ignored():
    """Pre-196 `highwater() is None` fell through silently and vetoed NOTHING.
    It is now counted as unresolved — fail-SAFE for the backstop — while
    staying out of `CONSUMER_LAG_UNKNOWN_PARTITIONS`, which tracker 172's
    fail-OPEN sweep decision reads."""
    read, dark = _TP("netops.syslog", 0), _TP("netops.flows", 2)
    main._LAST_OFFSET[("netops.syslog", 0)] = 99
    main._LAST_OFFSET[("netops.flows", 2)] = 7
    consumer = FakeConsumer({read: 100, dark: None})

    now = _sample(consumer)
    assert main.CONSUMER_LAG_UNKNOWN_PARTITIONS == 0
    assert main.CONSUMER_LAG_UNRESOLVED_PARTITIONS == 1
    assert main.caught_up_reason(now) == main.CAUGHT_UP_UNRESOLVED
    assert main._ingest_priority_decision(now)[1] != "lag-partitions-unknown", (
        "tracker 172's fail-open decision must not change behaviour")


# ── the closed reason set is complete and observable ───────────────────────

def test_every_uncertain_state_names_itself():
    now = time.monotonic()
    main.CONSUMER_LAG_TOTAL = None
    assert main.caught_up_reason(now) == main.CAUGHT_UP_NEVER_MEASURED
    main.CONSUMER_LAG_TOTAL = 0
    main.CONSUMER_LAG_AT = now - 10_000
    assert main.caught_up_reason(now) == main.CAUGHT_UP_STALE
    main.CONSUMER_LAG_AT = now
    main.CONSUMER_LAG_UNRESOLVED_PARTITIONS = 3
    assert main.caught_up_reason(now) == main.CAUGHT_UP_UNRESOLVED
    main.CONSUMER_LAG_UNRESOLVED_PARTITIONS = 0
    main.CONSUMER_LAG_UNREAD_TOTAL = 5
    assert main.caught_up_reason(now) == main.CAUGHT_UP_BEHIND
    main.CONSUMER_LAG_UNREAD_TOTAL = 0
    assert main.caught_up_reason(now) == main.CAUGHT_UP_LEVEL
    assert set(main.CAUGHT_UP_REASONS) == {
        main.CAUGHT_UP_LEVEL, main.CAUGHT_UP_NEVER_MEASURED, main.CAUGHT_UP_STALE,
        main.CAUGHT_UP_UNRESOLVED, main.CAUGHT_UP_BEHIND}


def test_the_reason_is_exported_on_metrics_and_healthz():
    read = _TP("netops.syslog", 0)
    main._LAST_OFFSET[("netops.syslog", 0)] = 99
    _sample(FakeConsumer({read: 100}))
    text = main._metrics_text()
    for reason in main.CAUGHT_UP_REASONS:
        assert f'corr_consumer_caught_up{{reason="{reason}"}}' in text
    assert f'corr_consumer_caught_up{{reason="{main.CAUGHT_UP_LEVEL}"}} 1' in text
    assert "corr_consumer_lag_unresolved_partitions " in text
    assert "corr_consumer_lag_proven_partitions " in text
    assert "corr_consumer_unread_probe_total " in text
    assert main.retention_state()["consumer_caught_up_reason"] == main.CAUGHT_UP_LEVEL


# ── cache hygiene: bounded, TTL'd, invalidated on rebalance ────────────────

def test_the_probe_batch_is_bounded(monkeypatch):
    monkeypatch.setattr(main, "CORR_LAG_PROBE_MAX_PARTITIONS", 4)
    tps = tuple(_TP("netops.syslog", i) for i in range(40))
    seen = {}

    class _Loop:
        def create_task(self, coro):
            coro.close()
            return _Done()

    class _Done:
        def done(self):
            return True

    def _fake_probe(consumer, batch):
        seen["n"] = len(batch)

        async def _noop():
            return None
        return _noop()

    monkeypatch.setattr(main, "_probe_unread_partitions", _fake_probe)
    monkeypatch.setattr(main.asyncio, "get_running_loop", lambda: _Loop())
    main._schedule_unread_probe(FakeConsumer({}), tps)
    assert seen["n"] == 4, "an unbounded probe batch is an unbounded broker ask (§9)"


def test_a_stale_proof_expires(monkeypatch):
    monkeypatch.setattr(main, "CORR_LAG_PROBE_TTL_S", 10.0)
    now = time.monotonic()
    main._UNREAD_PROBE[("netops.quiet", 0)] = (500, 500, now - 11.0)
    assert main._unread_partition_lag("netops.quiet", 0, 500, now) is None
    main._UNREAD_PROBE[("netops.quiet", 0)] = (500, 500, now - 1.0)
    assert main._unread_partition_lag("netops.quiet", 0, 500, now) == 0


def test_a_rebalance_drops_every_cached_proof():
    """Positions move when partitions do. A proof earned under the previous
    assignment is the one way this mechanism could shed evidence it should
    have kept, so the cache is dropped wholesale."""
    main._UNREAD_PROBE[("netops.syslog", 0)] = (10, 10, time.monotonic())

    class _C:
        def partitions_for_topic(self, topic):
            return {0}

    asyncio.run(main._AssignmentLogger(_C()).on_partitions_assigned(
        [_TP(t, 0) for t in main.TOPICS]))
    assert main._UNREAD_PROBE == {}


def test_probe_single_flight(monkeypatch):
    """A pass already in flight owns the refresh: the per-message sampler must
    never be able to stack broker round trips."""
    class _Running:
        def done(self):
            return False

    monkeypatch.setattr(main, "_UNREAD_PROBE_TASK", _Running())
    calls = []
    monkeypatch.setattr(main.asyncio, "get_running_loop",
                        lambda: calls.append(1) or None)
    main._schedule_unread_probe(FakeConsumer({}), (_TP("netops.syslog", 0),))
    assert calls == [], "a second probe was scheduled while one was in flight"


# ── §3a: eviction is per TENANT ────────────────────────────────────────────

def test_evicting_a_silent_tenant_never_touches_another_tenants_evidence():
    """CLAUDE.md §3a. The backstop resolves idleness per tenant; tenant B going
    quiet must not cost tenant A a single signal."""
    read = _TP("netops.syslog", 0)
    main._LAST_OFFSET[("netops.syslog", 0)] = 99
    now = _sample(FakeConsumer({read: 100}))
    assert main._consumer_caught_up(now) is True

    for i in range(20):
        for tenant in ("tenant-a", "tenant-b"):
            # Distinct native_id per tenant: `signal_id` is a uuid5 over the
            # observation, not over the tenant, so two tenants sharing one
            # native_id would share an id and the dedup-set assertion below
            # would be measuring the fixture, not the isolation.
            s = main.dc_replace(mk(i, i), tenant_id=tenant,
                                native_id=f"nat-{tenant}-{i}")
            main.WINDOW_BUFFER.append(s)
            main._BUFFERED_ID_ORDER.append(str(s.signal_id))
            main._BUFFERED_IDS.add(str(s.signal_id))
    # A is live (its clock advanced a moment ago); B has been silent for hours.
    main.TENANT_WATERMARK["tenant-a"] = (
        (T0 + timedelta(seconds=100)).timestamp(), time.monotonic())
    main.TENANT_WATERMARK["tenant-b"] = (
        (T0 + timedelta(seconds=100)).timestamp(),
        time.monotonic() - main.CORR_TENANT_IDLE_EVICT_S - 60)

    assert main._tenant_idle("tenant-a", now) is False
    assert main._tenant_idle("tenant-b", now) is True
    asyncio.run(main._prune_buffer(datetime.now(timezone.utc)))

    left = {s.tenant_id for s in main.WINDOW_BUFFER}
    assert left == {"tenant-a"}, f"cross-tenant eviction leak: {left}"
    assert len(main.WINDOW_BUFFER) == 20, "tenant A lost evidence to tenant B's silence"
    assert all(sid in main._BUFFERED_IDS for sid in main._BUFFERED_ID_ORDER)
