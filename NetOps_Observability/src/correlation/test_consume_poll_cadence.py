# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""P1 max-poll rebalance thrash — run: python3 -m pytest test_consume_poll_cadence.py

Pins the 2026-08-16 G2 mini-ladder failure: under a 24k-event backlog the
consumer entered a session-expiry rebalance loop (78x UnknownMemberIdError,
9x CommitFailedError, 3 supervisor restarts; drain collapsed ~1k/s -> ~40/s
and consumer lag never returned to baseline). The container logs showed
17-second event-loop stalls — longer than the 10s session_timeout default —
so the broker ejected the member, the next commit raised CommitFailedError,
the uncommitted batch replayed, and the loop repeated.

Guarantees under test, each a deterministic operation-count assertion (no
wall-clock thresholds — suite convention):

  1. POLL CADENCE — aiokafka's fetcher returns already-buffered records
     without yielding to the event loop (fetcher.next_record's fast path),
     and a handler whose awaits all complete synchronously never yields
     either. The consume loop must hand the loop back on a bounded cadence
     (CORR_CONSUME_YIELD_EVERY_N) so the heartbeat task always runs, and the
     engine's window evaluation must never block polls (run_window in an
     executor — the original defect ran it synchronously on the loop).
  2. REVOKE COMMIT DISCIPLINE (F-38) — on_partitions_revoked flushes then
     commits EXACTLY the handled ledger: a revoke firing mid-handle can never
     acknowledge the in-flight message, and a failed flush blocks the commit
     entirely (never acknowledge an offset whose rows are still buffered).
  3. REPLAY DEDUP — a member ejected between a batch flush and the offset
     commit gets its messages redelivered; the batcher's commit guard makes
     the re-added rows a no-op so corr_signals (plain MergeTree — no content
     dedup) never receives duplicate causal rows.
"""

from __future__ import annotations

import asyncio
import json
import time
from typing import ClassVar

from aiokafka.errors import CommitFailedError

import main
from main import TopicPartition

TP_METRICS = TopicPartition("netops.metrics", 0)


class FakeCH:
    """Insert recorder standing in for main.ch."""

    def __init__(self) -> None:
        self.rows: list[dict] = []
        self.tokens: list[str] = []

    async def insert(self, table, rows, dedup_token=""):
        self.rows.extend(rows)
        self.tokens.append(dedup_token)
        return True


class FakeConsumer:
    """Scriptable AIOKafkaConsumer stand-in (same shape as the supervisor
    suite's): build_consumer() must be able to subscribe with a listener."""

    created: ClassVar[list] = []

    def __init__(self, *topics, **kwargs):
        type(self).created.append(self)
        self.index = len(type(self).created)
        self.kwargs = kwargs
        self.subscribed: tuple = ()
        self.commits: list = []

    def subscribe(self, topics=(), pattern=None, listener=None):
        self.subscribed = (tuple(topics), listener)

    def partitions_for_topic(self, topic):
        return {0}

    async def start(self):
        return None

    async def stop(self):
        return None

    async def commit(self, offsets=None):
        self.commits.append(offsets)

    def __aiter__(self):
        return self

    async def __anext__(self):
        await asyncio.sleep(3600)


def _msg(offset: int, topic: str = "netops.metrics"):
    class Msg:
        pass

    m = Msg()
    m.topic = topic
    m.partition = 0
    m.offset = offset
    m.value = json.dumps({"off": offset}).encode()
    return m


async def _cancel(task: asyncio.Task) -> None:
    task.cancel()
    try:
        await asyncio.wait_for(task, timeout=1.0)
    except (asyncio.CancelledError, asyncio.TimeoutError):
        pass


# ── 1. poll cadence ─────────────────────────────────────────────────────────

def test_backlog_drain_yields_to_the_event_loop(monkeypatch):
    """The starvation shape, deterministically: 300 buffered messages served
    with ZERO awaits (aiokafka's fast path) into a handler with ZERO pending
    awaits, and a commit cadence that never fires. Pre-fix the consume task
    monopolizes the loop for the whole drain — a concurrent ticker task (the
    heartbeat's stand-in) gets no turns. The yield cadence must hand it the
    loop at least every CORR_CONSUME_YIELD_EVERY_N messages."""
    monkeypatch.setattr(main, "CONSUMER_STOP_TIMEOUT_S", 0.2)
    monkeypatch.setattr(main, "CONSUMER_START_TIMEOUT_S", 0.3)
    monkeypatch.setattr(main, "CORR_COMMIT_EVERY_N", 10**9)   # commit path silent
    monkeypatch.setattr(main, "CORR_COMMIT_EVERY_S", 10**9)
    monkeypatch.setattr(main, "CORR_CONSUME_YIELD_EVERY_N", 20)

    n_msgs = 300

    async def fake_handle(topic, event):
        # pure sync work: no pending awaits, exactly like the CH batcher
        # below its flush thresholds.
        sum(range(50))

    monkeypatch.setattr(main, "handle", fake_handle)

    async def scenario() -> int:
        done = asyncio.Event()
        started = asyncio.Event()

        class Scripted(FakeConsumer):
            created: ClassVar[list] = []

            async def __anext__(self):
                started.set()
                if not hasattr(self, "sent"):
                    self.sent = 0
                if self.sent >= n_msgs:
                    done.set()
                    await asyncio.sleep(3600)
                self.sent += 1
                return _msg(self.sent - 1)  # buffered fast path: NO await

        monkeypatch.setattr(main, "AIOKafkaConsumer", Scripted)
        ticks = 0

        async def ticker():
            nonlocal ticks
            await started.wait()
            while not done.is_set():
                ticks += 1
                await asyncio.sleep(0)

        consume_task = asyncio.create_task(main.consume())
        ticker_task = asyncio.create_task(ticker())
        await asyncio.wait_for(done.wait(), timeout=5.0)
        await _cancel(consume_task)
        await _cancel(ticker_task)
        return ticks

    ticks = asyncio.run(scenario())
    # 300 messages / yield-every-20 = 15 mandatory hand-backs. Pre-fix: 0.
    assert ticks >= 10, (
        f"consume loop starved the event loop during a buffered drain: the "
        f"heartbeat stand-in ran only {ticks} times across {n_msgs} messages")


def test_polls_continue_while_engine_digests_backlog(monkeypatch):
    """The original defect class: run_window on a storm window is seconds-to-
    minutes of pure CPU, and it once ran synchronously on the loop hosting the
    consumer — polls stopped for the whole evaluation and the broker ejected
    the member. Pin the executor offload: polls recorded while engine_cycle
    chews a monkeypatched CPU-burning run_window must continue (>0 during the
    burn). A regression to sync-on-loop makes the interleaved count 0."""
    from datetime import datetime, timezone

    from signals import (
        EntityType,
        ModalityClass,
        Observer,
        ObserverType,
        Severity,
        Signal,
        Source,
    )

    monkeypatch.setattr(main, "ch", FakeCH())
    monkeypatch.setattr(main, "CORR_COMMIT_EVERY_N", 10**9)
    monkeypatch.setattr(main, "CORR_COMMIT_EVERY_S", 10**9)
    monkeypatch.setattr(main, "CORR_CONSUME_YIELD_EVERY_N", 5)

    now = datetime.now(timezone.utc)
    sig = Signal(
        tenant_id="t_poll",
        ts=now,
        source=Source.METRIC,
        kind="metric_anomaly",
        observer=Observer(observer_id="obs1", observer_type=ObserverType.DEVICE),
        modality_class=ModalityClass.DEVICE_TELEMETRY,
        entity_type=EntityType.DEVICE,
        entity_id="core-sw1",
        severity=Severity.HIGH,
        native_id="pollcadence|t_poll|core-sw1",
        attrs={"onset_uncertainty_s": 5.0},
    )
    buf = main.deque(maxlen=1000)
    buf.append(sig)
    monkeypatch.setattr(main, "WINDOW_BUFFER", buf)

    markers: list[str] = []  # appended from both the loop and the executor thread

    def burning_run_window(*args, **kwargs):
        markers.append("engine_start")
        t0 = time.perf_counter()
        while time.perf_counter() - t0 < 0.4:  # storm-window CPU stand-in
            sorted((i * 2654435761) % 4093 for i in range(4000))
        markers.append("engine_end")
        return ()

    monkeypatch.setattr(main, "run_window", burning_run_window)

    async def fake_handle(topic, event):
        sum(range(50))

    monkeypatch.setattr(main, "handle", fake_handle)

    async def scenario() -> list[str]:
        class Scripted(FakeConsumer):
            created: ClassVar[list] = []

            async def __anext__(self):
                markers.append("poll")
                return _msg(len(markers))  # unlimited buffered backlog

        monkeypatch.setattr(main, "AIOKafkaConsumer", Scripted)
        consume_task = asyncio.create_task(main.consume())
        engine_task = asyncio.create_task(main.engine_cycle())
        await asyncio.wait_for(engine_task, timeout=10.0)
        await _cancel(consume_task)
        return markers

    result = asyncio.run(scenario())
    assert "engine_start" in result and "engine_end" in result
    inside = result[result.index("engine_start"):result.index("engine_end")]
    interleaved = inside.count("poll")
    assert interleaved > 0, (
        "no polls during the engine's window evaluation — run_window is "
        "blocking the event loop again (the max-poll rebalance defect)")


def test_build_consumer_sets_membership_tuning(monkeypatch):
    """The explicit group-membership contract (arithmetic in main.py at
    CORR_SESSION_TIMEOUT_MS): the values must come from the env-tunable
    constants, not silent defaults.

    RAISED to 60s/5s 2026-08-29 after run storm-s03 ejected the member on two
    ~26 s stalls under the 30 s session — a member that is SLOW (a 26 s quiesce
    pass is hundreds of closes of wall clock, not one 26 s block; see
    `main.sync_record`) was being treated as a member that is dead. This changes
    WHEN a slow member is ejected and nothing else: no byte, token, row,
    version or ordering decision depends on the group contract."""
    FakeConsumer.created = []
    monkeypatch.setattr(main, "AIOKafkaConsumer", FakeConsumer)
    consumer = main.build_consumer()
    kw = consumer.kwargs
    assert kw["session_timeout_ms"] == main.CORR_SESSION_TIMEOUT_MS == 60000
    assert kw["heartbeat_interval_ms"] == main.CORR_HEARTBEAT_INTERVAL_MS == 5000
    assert kw["max_poll_interval_ms"] == main.CORR_MAX_POLL_INTERVAL_MS == 300000
    assert kw["rebalance_timeout_ms"] == main.CORR_REBALANCE_TIMEOUT_MS == 60000
    # heartbeat <= session/3 (Kafka's own guidance) — a misconfigured override
    # must fail the suite, not eject members in production.
    assert kw["heartbeat_interval_ms"] * 3 <= kw["session_timeout_ms"]
    # …and the session must stay INSIDE the poll interval: a member the broker
    # has already expired must not keep polling as if it were still in the group.
    assert kw["session_timeout_ms"] < kw["max_poll_interval_ms"]

    # the listener wiring point the revoke hook depends on
    assert consumer._corr_listener is consumer.subscribed[1]


# ── 2. revoke commit discipline (F-38) ──────────────────────────────────────

def _drive_revoke(monkeypatch, *, flush_fails: bool, flush_hangs: bool = False):
    """Run consume() until message offset 2 is IN FLIGHT (handler blocked),
    fire on_partitions_revoked, and return (commits, order) observed."""
    monkeypatch.setattr(main, "CONSUMER_STOP_TIMEOUT_S", 1.0)
    monkeypatch.setattr(main, "CONSUMER_START_TIMEOUT_S", 1.0)
    monkeypatch.setattr(main, "CORR_COMMIT_EVERY_N", 10**9)
    monkeypatch.setattr(main, "CORR_COMMIT_EVERY_S", 10**9)

    order: list = []

    async def recording_flush():
        if flush_hangs:
            order.append("flush_hanging")
            await asyncio.sleep(3600)   # a wedged ClickHouse
        if flush_fails:
            order.append("flush_failed")
            raise RuntimeError("clickhouse transport down")
        order.append("flush")

    monkeypatch.setattr(main.SIGNAL_BATCH, "flush", recording_flush)

    async def scenario():
        in_flight = asyncio.Event()
        release = asyncio.Event()

        async def fake_handle(topic, event):
            if event["off"] == 2:
                in_flight.set()
                await release.wait()

        monkeypatch.setattr(main, "handle", fake_handle)

        class Scripted(FakeConsumer):
            created: ClassVar[list] = []

            async def commit(self, offsets=None):
                order.append("commit")
                self.commits.append(offsets)

            async def __anext__(self):
                if not hasattr(self, "sent"):
                    self.sent = 0
                if self.sent >= 3:
                    await asyncio.sleep(3600)
                self.sent += 1
                return _msg(self.sent - 1)

        monkeypatch.setattr(main, "AIOKafkaConsumer", Scripted)
        consume_task = asyncio.create_task(main.consume())
        await asyncio.wait_for(in_flight.wait(), timeout=5.0)
        consumer = Scripted.created[0]
        listener = consumer._corr_listener
        ok_before = main.CONSUMER_REVOKE_COMMITS
        fail_before = main.CONSUMER_REVOKE_COMMIT_FAILURES
        # must never raise — a raise here kills the rejoin inside aiokafka
        await listener.on_partitions_revoked([TP_METRICS])
        release.set()
        await _cancel(consume_task)
        return (consumer.commits, order,
                main.CONSUMER_REVOKE_COMMITS - ok_before,
                main.CONSUMER_REVOKE_COMMIT_FAILURES - fail_before)

    return asyncio.run(scenario())


def test_revoke_mid_batch_commits_only_handled_offsets(monkeypatch):
    """Messages 0 and 1 handled, message 2 in flight when the revoke fires:
    the hook must flush FIRST, then commit exactly {tp: 2} — never the
    in-flight offset 2's acknowledgement (offset 3). F-38 across ejection."""
    commits, order, ok_delta, fail_delta = _drive_revoke(monkeypatch, flush_fails=False)
    assert order[:2] == ["flush", "commit"], (
        f"flush must precede the revoke commit, got {order}")
    assert commits == [{TP_METRICS: 2}], (
        f"revoke hook must commit exactly the handled ledger, got {commits}")
    assert ok_delta == 1 and fail_delta == 0


def test_revoke_flush_failure_blocks_commit(monkeypatch):
    """A failed flush means buffered rows are NOT durably landed — the revoke
    hook must not acknowledge any offset (the supervisor replays; dedup
    absorbs), must count the failure, and must not raise into aiokafka."""
    commits, order, ok_delta, fail_delta = _drive_revoke(monkeypatch, flush_fails=True)
    assert commits == [], f"offsets committed past an unflushed batch: {commits}"
    assert "commit" not in order
    assert ok_delta == 0 and fail_delta == 1


def test_revoke_is_tightly_bounded_and_never_costs_a_rebalance_timeout(monkeypatch):
    """AMPLIFIER GUARD. The revoke callback runs INSIDE the rejoin, so every
    second it spends is a second the group is not re-forming. The first version
    capped the whole hook at rebalance_timeout (60s), which let one slow
    ClickHouse flush add a full rebalance timeout of latency PER REVOKE —
    plausibly making the thrash loop self-sustaining (starve -> revoke -> 60s of
    flush I/O -> re-revoke). Live counters from the thrash window fit that
    reading: correlation-1 logged 20 rebalances against 17 hook runs, 6 FAILED.

    With a wedged flush the hook must (a) return inside its small budget,
    (b) NOT commit — F-38 is preserved by not acknowledging, never by waiting
    longer — and (c) count the skip."""
    monkeypatch.setattr(main, "CORR_REVOKE_BUDGET_S", 0.2)
    before = main.CONSUMER_REVOKE_SKIPPED
    t0 = time.monotonic()
    commits, order, _ok, _fail = _drive_revoke(
        monkeypatch, flush_fails=False, flush_hangs=True)
    elapsed = time.monotonic() - t0

    assert "flush_hanging" in order
    assert commits == [], f"committed despite an unfinished flush: {commits}"
    assert main.CONSUMER_REVOKE_SKIPPED == before + 1, "the skip must be counted"
    # The whole drive (including consumer startup) must finish far inside the old
    # 60s bound; the hook itself is capped at 2x budget = 0.4s.
    assert elapsed < 10.0, (
        f"revoke path took {elapsed:.1f}s — it is not bounded by "
        f"CORR_REVOKE_BUDGET_S any more")


def test_revoke_budget_is_a_small_fraction_of_the_rebalance_timeout():
    """The arithmetic that keeps the hook from becoming the amplifier: two legs
    (flush + commit) at CORR_REVOKE_BUDGET_S each, with a 2x backstop, must stay
    well inside rebalance_timeout — otherwise a revoke can cost the group its
    whole rejoin window."""
    worst_hook_s = 2 * main.CORR_REVOKE_BUDGET_S
    assert worst_hook_s * 3 <= main.CORR_REBALANCE_TIMEOUT_MS / 1000, (
        f"revoke budget {worst_hook_s}s is not a small fraction of "
        f"rebalance_timeout {main.CORR_REBALANCE_TIMEOUT_MS / 1000}s")


# ── 3. replay dedup (flushed-but-uncommitted rows) ──────────────────────────

def test_redelivered_rows_after_flush_do_not_duplicate(monkeypatch):
    """Batcher-level: rows flushed under token T, then the offset commit dies
    (member ejected). Redelivery re-adds the same rows to a FRESH batch whose
    content-hash token differs — pre-fix ClickHouse could not dedup and the
    plain-MergeTree corr_signals table got duplicates. The commit guard must
    absorb the re-add; a successful offset commit clears it."""
    fake = FakeCH()
    monkeypatch.setattr(main, "ch", fake)
    deduped_before = main.BATCH_ROWS_REPLAY_DEDUPED

    async def scenario():
        b = main.CHBatcher()
        row_a = {"signal_id": "sig-A", "tenant_id": "t1"}
        row_b = {"signal_id": "sig-B", "tenant_id": "t1"}
        await b.add("netops.corr_signals", dict(row_a))
        await b.add("netops.corr_signals", dict(row_b))
        await b.flush()
        assert len(fake.rows) == 2
        # ejection between flush and commit -> redelivery re-runs the handlers
        await b.add("netops.corr_signals", dict(row_a))
        await b.add("netops.corr_signals", dict(row_b))
        await b.flush()
        assert len(fake.rows) == 2, "redelivered rows duplicated after flush"
        # offsets committed -> guard clears; genuinely new data still lands
        b.note_committed()
        await b.add("netops.corr_signals", {"signal_id": "sig-C", "tenant_id": "t1"})
        await b.flush()
        assert [r["signal_id"] for r in fake.rows] == ["sig-A", "sig-B", "sig-C"]

    asyncio.run(scenario())
    assert main.BATCH_ROWS_REPLAY_DEDUPED - deduped_before == 2


def test_consume_redelivery_end_to_end_no_duplicate_rows(monkeypatch):
    """The full thrash round-trip through the REAL consume loop: five messages
    handled and their corr_signals rows flushed, the offset commit raises
    CommitFailedError (the measured ejection), the supervisor restarts the
    consumer, all five messages are REDELIVERED — and ClickHouse must end up
    with exactly five rows, not ten."""
    fake = FakeCH()
    monkeypatch.setattr(main, "ch", fake)
    monkeypatch.setattr(main, "CONSUMER_STOP_TIMEOUT_S", 0.2)
    monkeypatch.setattr(main, "CONSUMER_START_TIMEOUT_S", 0.3)
    monkeypatch.setattr(main, "CORR_COMMIT_EVERY_N", 5)
    monkeypatch.setattr(main, "CORR_COMMIT_EVERY_S", 10**9)
    monkeypatch.setattr(main, "CORR_BATCH_MAX_ROWS", 2)  # flush during the drain

    async def fake_handle(topic, event):
        await main.batch_signal(
            {"signal_id": f"sig-{event['off']}", "tenant_id": "t1"})

    monkeypatch.setattr(main, "handle", fake_handle)

    async def scenario():
        done = asyncio.Event()

        class Scripted(FakeConsumer):
            created: ClassVar[list] = []

            async def commit(self, offsets=None):
                if self.index == 1:
                    raise CommitFailedError()  # broker ejected this member
                self.commits.append(offsets)
                done.set()

            async def __anext__(self):
                if not hasattr(self, "sent"):
                    self.sent = 0
                if self.sent >= 5:
                    await asyncio.sleep(3600)
                self.sent += 1
                return _msg(self.sent - 1)

        monkeypatch.setattr(main, "AIOKafkaConsumer", Scripted)
        consume_task = asyncio.create_task(main.consume())
        # supervision round 1 fails its commit, backs off 1s, round 2 redelivers
        await asyncio.wait_for(done.wait(), timeout=10.0)
        await _cancel(consume_task)

    asyncio.run(scenario())
    ids = [r["signal_id"] for r in fake.rows]
    assert sorted(ids) == [f"sig-{i}" for i in range(5)], (
        f"redelivery after a failed commit duplicated rows: {sorted(ids)}")
