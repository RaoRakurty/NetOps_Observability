# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Consume-loop ClickHouse batching (perf defect #2 — main.CHBatcher).

The per-event single-row corr_signals inserts (wait_end_of_query=1, one HTTP
round-trip per row in the sequential consume loop) are replaced by per-table
row accumulation. These tests pin the contract:

  * size trigger — a batch flushes as ONE insert at CORR_BATCH_MAX_ROWS
  * age trigger — due() fires at CORR_BATCH_MAX_S (deterministic clock arg)
  * bounded queue — CORR_BATCH_QUEUE_MAX forces a flush (backpressure: the
    sequential caller awaits it)
  * at-least-once — the consume loop flushes BEFORE every offset commit; a
    transport failure aborts the commit, retains the rows, and the retry of an
    unchanged batch carries the SAME content-hash dedup token
  * rejection — a positively-rejected batch preserves EVERY row in the durable
    dead-letter file (never acknowledge a write that neither committed nor was
    durably kept) and consumption continues
  * shutdown — cancellation force-commits, which drains the batch first
"""

from __future__ import annotations

import asyncio
import json
import os
import time
from typing import ClassVar

import pytest

import main


def run(coro):
    return asyncio.run(coro)


class RecordingCH:
    def __init__(self):
        self.batches: list[tuple[str, list[dict], str]] = []

    async def insert(self, table, rows, dedup_token=""):
        self.batches.append((table, list(rows), dedup_token))
        return True


class FailingOnceCH(RecordingCH):
    def __init__(self):
        super().__init__()
        self.fail_next = True
        self.tokens: list[str] = []

    async def insert(self, table, rows, dedup_token=""):
        self.tokens.append(dedup_token)
        if self.fail_next:
            self.fail_next = False
            raise TimeoutError("clickhouse unreachable")
        return await super().insert(table, rows, dedup_token)


class RejectingCH(RecordingCH):
    async def insert(self, table, rows, dedup_token=""):
        return False


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    main.SIGNAL_BATCH.drop_pending()
    main.CH_INSERT_FAILURES.clear()
    main._CH_FAIL_LOG_LAST.clear()
    main.QUARANTINE.clear()
    yield
    main.SIGNAL_BATCH.drop_pending()
    main.CH_INSERT_FAILURES.clear()
    main.QUARANTINE.clear()


# ── unit: triggers ───────────────────────────────────────────────────────────


def test_batch_flushes_as_one_insert_at_max_rows(monkeypatch):
    ch = RecordingCH()
    monkeypatch.setattr(main, "ch", ch)
    monkeypatch.setattr(main, "CORR_BATCH_MAX_ROWS", 5)

    async def scenario():
        for i in range(4):
            await main.batch_signal({"signal_id": f"s{i}"})
        assert ch.batches == []                      # below threshold: buffered
        assert main.SIGNAL_BATCH.pending() == 4
        await main.batch_signal({"signal_id": "s4"})  # 5th row → flush

    run(scenario())
    assert len(ch.batches) == 1, "5 rows must land as ONE insert, not 5"
    table, rows, token = ch.batches[0]
    assert table == "netops.corr_signals"
    assert [r["signal_id"] for r in rows] == ["s0", "s1", "s2", "s3", "s4"]
    assert token.startswith("batch:")
    assert main.SIGNAL_BATCH.pending() == 0


def test_due_fires_by_age_deterministically(monkeypatch):
    monkeypatch.setattr(main, "ch", RecordingCH())
    run(main.batch_signal({"signal_id": "s0"}))
    now = time.monotonic()
    assert not main.SIGNAL_BATCH.due(now)                       # fresh
    assert main.SIGNAL_BATCH.due(now + main.CORR_BATCH_MAX_S)   # aged past 2s


def test_bounded_queue_forces_flush(monkeypatch):
    ch = RecordingCH()
    monkeypatch.setattr(main, "ch", ch)
    monkeypatch.setattr(main, "CORR_BATCH_QUEUE_MAX", 3)

    async def scenario():
        for i in range(3):
            await main.batch_signal({"signal_id": f"s{i}"})

    run(scenario())
    assert len(ch.batches) == 1 and len(ch.batches[0][1]) == 3
    assert main.SIGNAL_BATCH.pending() == 0


# ── unit: failure semantics ──────────────────────────────────────────────────


def test_transport_failure_retains_rows_and_retry_token_is_stable(monkeypatch):
    ch = FailingOnceCH()
    monkeypatch.setattr(main, "ch", ch)

    async def scenario():
        await main.batch_signal({"signal_id": "s0"})
        await main.batch_signal({"signal_id": "s1"})
        with pytest.raises(TimeoutError):
            await main.SIGNAL_BATCH.flush()
        # rows RETAINED (at-least-once), loss counted
        assert main.SIGNAL_BATCH.pending() == 2
        assert main.CH_INSERT_FAILURES == {"netops.corr_signals": 1}
        await main.SIGNAL_BATCH.flush()              # retry lands

    run(scenario())
    assert len(ch.batches) == 1
    assert [r["signal_id"] for r in ch.batches[0][1]] == ["s0", "s1"]
    # identical retained batch ⇒ identical content-hash token ⇒ ClickHouse-side
    # dedup absorbs the case where the first attempt actually landed.
    assert len(ch.tokens) == 2 and ch.tokens[0] == ch.tokens[1]
    assert main.SIGNAL_BATCH.pending() == 0


def test_rejected_batch_preserves_every_row_durably(monkeypatch, tmp_path):
    monkeypatch.setattr(main, "ch", RejectingCH())
    monkeypatch.setattr(main, "CORR_DLQ_DIR", str(tmp_path))
    before = main.BATCH_ROWS_QUARANTINED

    async def scenario():
        await main.batch_signal({"signal_id": "s0", "kind": "link_down"})
        await main.batch_signal({"signal_id": "s1", "kind": "link_down"})
        await main.SIGNAL_BATCH.flush()              # rejection does NOT raise

    run(scenario())
    assert main.SIGNAL_BATCH.pending() == 0          # batch dropped, not retried
    assert main.CH_INSERT_FAILURES == {"netops.corr_signals": 1}
    assert main.BATCH_ROWS_QUARANTINED == before + 2
    # every row is individually replayable from the durable DLQ file
    lines = [json.loads(line) for line in
             (tmp_path / "corr-deadletter.ndjson").read_text().splitlines()]
    payload_ids = [json.loads(rec["payload"])["signal_id"]
                   for rec in lines if rec.get("payload")]
    assert payload_ids == ["s0", "s1"]
    # ONE ring summary (a 500-row batch must not wipe the 200-slot ring)
    ring = [r for r in main.QUARANTINE if r["topic"] == "chbatch:netops.corr_signals"]
    assert len(ring) == 1 and "2 rows" in ring[0]["error"]


# ── consume loop: flush-before-commit is the at-least-once anchor ────────────


class _Msg:
    def __init__(self, topic, value, partition=0, offset=0):
        self.topic, self.value = topic, value
        self.partition, self.offset = partition, offset


class _NConsumer:
    """Yields `count` metric messages, then idles. Records commit ordering."""

    count: ClassVar[int] = 3
    events: ClassVar[list] = []

    def __init__(self, *topics, **kw):
        self._msgs = iter(
            _Msg("netops.metrics", json.dumps({"i": i}).encode(), offset=i)
            for i in range(type(self).count))

    def subscribe(self, topics=(), pattern=None, listener=None):
        # Scale P0: build_consumer() subscribes with a rebalance listener.
        self.subscribed = (tuple(topics), listener)

    def partitions_for_topic(self, topic):
        return {0}

    async def start(self):
        return None

    async def stop(self):
        return None

    async def commit(self):
        type(self).events.append("commit")

    def __aiter__(self):
        return self

    async def __anext__(self):
        try:
            return next(self._msgs)
        except StopIteration:
            await asyncio.sleep(3600)
            raise StopAsyncIteration from None


class _OrderCH(RecordingCH):
    async def insert(self, table, rows, dedup_token=""):
        _NConsumer.events.append(f"insert:{len(list(rows))}")
        return await super().insert(table, rows, dedup_token)


async def _drive_consume(seconds=0.3):
    task = asyncio.create_task(main.consume())
    await asyncio.sleep(seconds)
    task.cancel()
    try:
        await asyncio.wait_for(task, timeout=1.0)
    except (asyncio.CancelledError, asyncio.TimeoutError):
        pass


def test_commit_only_after_the_batch_flushed(monkeypatch):
    _NConsumer.events = []
    _NConsumer.count = 3
    monkeypatch.setattr(main, "AIOKafkaConsumer", _NConsumer)
    monkeypatch.setattr(main, "ch", _OrderCH())
    monkeypatch.setattr(main, "CORR_COMMIT_EVERY_N", 3)
    monkeypatch.setattr(main, "CORR_COMMIT_EVERY_S", 3600.0)
    monkeypatch.setattr(main, "CONSUMER_START_TIMEOUT_S", 1.0)

    async def fake_handle(topic, event):
        await main.batch_signal({"signal_id": f"sig-{event['i']}"})

    monkeypatch.setattr(main, "handle", fake_handle)
    run(_drive_consume())

    commits = [e for e in _NConsumer.events if e == "commit"]
    assert commits, "the commit threshold was reached — a commit must happen"
    first_commit = _NConsumer.events.index("commit")
    inserts_before = [e for e in _NConsumer.events[:first_commit]
                      if e.startswith("insert:")]
    assert inserts_before == ["insert:3"], (
        f"rows must land as ONE batch BEFORE the offset commit, got {_NConsumer.events}")


class _DownCH:
    async def insert(self, table, rows, dedup_token=""):
        raise TimeoutError("clickhouse down")


def test_flush_failure_aborts_the_commit(monkeypatch):
    """ClickHouse down: rows buffered, flush at the commit point raises → NO
    offset is acknowledged and the supervisor takes over (replay, not loss)."""
    _NConsumer.events = []
    _NConsumer.count = 2
    monkeypatch.setattr(main, "AIOKafkaConsumer", _NConsumer)
    monkeypatch.setattr(main, "ch", _DownCH())
    monkeypatch.setattr(main, "CORR_COMMIT_EVERY_N", 2)
    monkeypatch.setattr(main, "CORR_COMMIT_EVERY_S", 3600.0)
    monkeypatch.setattr(main, "CONSUMER_START_TIMEOUT_S", 1.0)

    async def fake_handle(topic, event):
        await main.batch_signal({"signal_id": f"sig-{event['i']}"})

    monkeypatch.setattr(main, "handle", fake_handle)
    run(_drive_consume())

    assert "commit" not in _NConsumer.events, \
        "an offset was acknowledged past rows that never landed"
    assert main.SIGNAL_BATCH.pending() == 2, "the unflushed rows must be retained"
    assert main.CH_INSERT_FAILURES.get("netops.corr_signals", 0) >= 1


def test_dlq_unset_note_is_env_documented():
    """CORR_BATCH_* knobs must be env-tunable (ops contract, §16)."""
    assert main.CORR_BATCH_MAX_ROWS == int(os.environ.get("CORR_BATCH_MAX_ROWS", "500"))
    assert main.CORR_BATCH_MAX_S == float(os.environ.get("CORR_BATCH_MAX_S", "2.0"))
    assert main.CORR_BATCH_QUEUE_MAX == int(os.environ.get("CORR_BATCH_QUEUE_MAX", "5000"))


# ── H12: replayed rows must not double-land through a retained batch ─────────


def test_h12_replayed_rows_collapse_into_the_retained_batch(monkeypatch):
    """A flush transport failure retains the rows AND escapes to the supervisor
    → consumer restart → Kafka redelivers the uncommitted messages → their
    handlers re-add the SAME rows. Pre-fix those joined the retained batch, so
    the next flush landed every row twice (and the doubled membership changed
    the content-hash token, defeating server-side dedup). Identity dedup by
    signal_id makes the replayed adds no-ops and keeps the retry token stable."""
    ch = FailingOnceCH()
    monkeypatch.setattr(main, "ch", ch)

    async def scenario():
        await main.batch_signal({"signal_id": "s0"})
        await main.batch_signal({"signal_id": "s1"})
        with pytest.raises(TimeoutError):
            await main.SIGNAL_BATCH.flush()
        # supervisor restart + redelivery: the same handlers re-add the same rows
        await main.batch_signal({"signal_id": "s0"})
        await main.batch_signal({"signal_id": "s1"})
        assert main.SIGNAL_BATCH.pending() == 2, "replayed rows must collapse"
        await main.SIGNAL_BATCH.flush()

    run(scenario())
    landed = [r["signal_id"] for _, rows, _ in ch.batches for r in rows]
    assert sorted(landed) == ["s0", "s1"], f"duplicated rows landed: {landed}"
    # identical membership ⇒ identical token across the failed attempt + retry.
    assert len(ch.tokens) == 2 and ch.tokens[0] == ch.tokens[1]


def test_h12_new_rows_never_merge_into_the_batch_being_retried(monkeypatch):
    """Rows added while a failed batch awaits retry (the engine task runs
    concurrently with the consume loop) must flush as their OWN batch — merging
    them changed the retried batch's token, so a first attempt that had
    actually landed server-side was re-inserted under a fresh token and
    duplicated."""
    ch = FailingOnceCH()
    monkeypatch.setattr(main, "ch", ch)

    async def scenario():
        await main.batch_signal({"signal_id": "s0"})
        with pytest.raises(TimeoutError):
            await main.SIGNAL_BATCH.flush()
        await main.batch_signal({"signal_id": "s-new"})  # e.g. an engine episode
        await main.SIGNAL_BATCH.flush()

    run(scenario())
    # retry of [s0] under its ORIGINAL token, then [s-new] separately.
    assert len(ch.tokens) == 3 and ch.tokens[0] == ch.tokens[1]
    assert [[r["signal_id"] for r in rows] for _, rows, _ in ch.batches] \
        == [["s0"], ["s-new"]]
    assert main.SIGNAL_BATCH.pending() == 0


class _FailOnceRecordingCH(RecordingCH):
    """First insert transport-fails; everything after lands (records batches)."""

    def __init__(self):
        super().__init__()
        self.fail_next = True

    async def insert(self, table, rows, dedup_token=""):
        if self.fail_next:
            self.fail_next = False
            raise TimeoutError("clickhouse unreachable")
        return await super().insert(table, rows, dedup_token)


def test_h12_consumer_replay_after_flush_failure_lands_unique_signal_ids(monkeypatch):
    """End-to-end shape of the finding: CH fails once at the commit-point flush,
    the supervisor restarts the consumer past its backoff, Kafka redelivers the
    uncommitted messages, and the rows still land exactly once."""
    _NConsumer.events = []
    _NConsumer.count = 2
    ch = _FailOnceRecordingCH()
    monkeypatch.setattr(main, "AIOKafkaConsumer", _NConsumer)
    monkeypatch.setattr(main, "ch", ch)
    monkeypatch.setattr(main, "CORR_COMMIT_EVERY_N", 2)
    monkeypatch.setattr(main, "CORR_COMMIT_EVERY_S", 3600.0)
    monkeypatch.setattr(main, "CONSUMER_START_TIMEOUT_S", 1.0)

    async def fake_handle(topic, event):
        await main.batch_signal({"signal_id": f"sig-{event['i']}"})

    monkeypatch.setattr(main, "handle", fake_handle)
    # 2.5s: past the supervisor's initial 1s backoff, so the replay round runs.
    run(_drive_consume(seconds=2.5))

    landed = [r["signal_id"] for _, rows, _ in ch.batches for r in rows]
    assert sorted(landed) == ["sig-0", "sig-1"], f"duplicated rows landed: {landed}"
    assert "commit" in _NConsumer.events, "the replay round must have committed"
