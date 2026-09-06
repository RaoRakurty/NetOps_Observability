# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""P2 step 4c/4d — CROSS-VERSION EVIDENCE BATCHING and the DECISION-write offload.

Measured briefs:
  * `docs/scale/P2_CLICKHOUSE_MEMFLAT_2026-08-29.md` §3(a) — run `p2-s04b-08290858`
    issued **63,701 Evidence-table INSERTs** in 75 minutes at 16.9 / 16.9 / 4.8
    rows each because `_emit_child_rows` batches only WITHIN one object version.
    Every one is a level-0 part; folding that trickle into the accumulated part
    re-wrote the same bytes over and over — 1.40 GiB inserted against **337.6 GiB
    merged (≈241x write amplification)**, merge memory peaking at 83 % of
    `max_server_memory_usage` and the server at 95.2 % of it.
  * `docs/scale/P2_STEP4B_2P5K_VERDICT_2026-08-29.md` §3/§4 — `persist.decision`
    max **64 s** on a single storm object, "whose blob/rows are built on the loop
    thread — the `_offload` threshold for the Decision write needs the same
    treatment the archive chunk got".

THE CLAIM UNDER TEST, in one sentence: batching changes WHICH INSERT a row
travels in and nothing else — not the row, not its bytes, not its order within
its table, not whether an item is counted — while the Decision write stops
holding the loop thread for a storm-sized stretch.

Every test below is one of six mutant checks:

  * **row identity** (B1, B1b) — the same rows and the same bytes per table,
    each VERSION's own rows in the same order and never interleaved with
    another version's; only the grouping into INSERT statements differs, and it
    differs by ≥5x. The cross-version SEQUENCE is compared as a multiset
    (E1's rule) because the queue is a priority heap drained concurrently with
    production, not a global sort — see B1's docstring.
  * **the block token** (B2, B2b, B2c, B2d, B2e) — one token per block,
    `"batch:" + sha256(member keys in flush order)`, a pure function of the
    block's content and order, so `ch_insert`'s retry re-sends the identical
    list under the identical token. MUTANT: `test_B2c` shows an
    arrival-reordered key list produces a DIFFERENT token, so B2b/B2d cannot
    pass vacuously.
  * **the three triggers** (B3, B3b, B3c, B3d) — members, estimated bytes and
    the age of the oldest buffered row each flush ON THEIR OWN, and nothing
    flushes before its trigger. B3d drives the age trigger through the LIVE
    flusher task, which is the only thing that bounds a trickle.
  * **failure accounting** (B4, B4b) — a failed block counts every member item
    once, names their tokens in the log, and reverts the optimistic
    archive-slice hash exactly as the unbatched path does.
  * **nothing is left buffered** (B5, B5b) — the shutdown drain and
    `evidence_drain` flush partial blocks; an idle queue is not a written queue.
  * **the Decision write is off the loop** (B10, B10b, B10c) — with a 50k-signal
    window the loop-lag WATCHDOG sees no stall above 500 ms, and the mutant
    (`CORR_DECISION_OFFLOAD=0`) sees a 1-second one.

The Decision-plane batching flag (`CORR_DECISION_BATCH`) is DEFAULT OFF and
B9/B9b pin both halves of that: off by default, and correct when forced on.
"""
from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import gc
import json
import logging
import time
from datetime import timedelta

import pytest

import main
import timing_gate
from evidence_plane import EvidenceItem, RowBatcher, batch_token
from signals import EntityType, Severity
from test_engine import T0 as ENGINE_T0
from test_engine import sig as engine_sig
from test_p2_evidence_async import (
    DECISION_TABLES,
    EVIDENCE_TABLES,
    _drain_cohorts,
    _load,
    _RecCH,
    _reset_engine_state,
    mixed_window,
)

ARCHIVE = "netops.corr_signals_archive"
EDGES = "netops.corr_edges"


# ── fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture
def _stack(monkeypatch):
    """A clean engine + a clean Evidence plane with BATCHING ON (the default)."""
    _reset_engine_state()
    monkeypatch.setattr(main, "OPEN_OBJECTS", {})
    monkeypatch.setattr(main, "_EVIDENCE_QUEUE", None)
    monkeypatch.setattr(main, "_EVIDENCE_TASK", None)
    monkeypatch.setattr(main, "_EVIDENCE_LOOP", None)
    monkeypatch.setattr(main, "_EVIDENCE_BATCHER", None)
    monkeypatch.setattr(main, "_EVIDENCE_FLUSHER", None)
    monkeypatch.setattr(main, "EVIDENCE_ITEMS_MATERIALIZED", 0)
    monkeypatch.setattr(main, "EVIDENCE_ITEMS_FAILED", 0)
    monkeypatch.setattr(main, "EVIDENCE_ITEMS_LOST", 0)
    monkeypatch.setattr(main, "CORR_EVIDENCE_ASYNC", True)
    monkeypatch.setattr(main, "CORR_EVIDENCE_BATCH", True)
    monkeypatch.setattr(main, "CORR_DECISION_BATCH", False)
    monkeypatch.setattr(main, "CORR_EVIDENCE_QUEUE_MAX", 5000)
    monkeypatch.setattr(main, "CORR_EVIDENCE_QUEUE_BYTES_MAX", 512 * 1024 * 1024)
    monkeypatch.setattr(main, "CORR_EVIDENCE_DRAIN_ON_STOP_S", 30.0)
    monkeypatch.setattr(main, "CORR_COHORT_TOUCH_GATE", True)
    monkeypatch.setattr(main, "CORR_LIFECYCLE_EPOCH_CADENCE", True)
    # Same discipline as test_p2_evidence_async's fixture: every module global a
    # helper assigns directly is registered at its current value first, so
    # teardown restores it whatever the test did.
    for _name in ("CORR_ENGINE_COHORT_SIZE", "CORR_ENGINE_DRAIN_COHORTS",
                  "CORR_ENGINE_EPOCH_BUDGET_S", "CORR_STORM_COHORT_SIZE",
                  "CORR_QUIESCE_S", "CORR_OPEN_OBJECTS_MAX",
                  "CORR_LIFECYCLE_COHORT_WINDOW", "CORR_ARCHIVE_CHUNK_ROWS",
                  "CORR_ROW_PAGE_SIZE", "CORR_PROFILE_STAGES",
                  "CORR_EVIDENCE_BATCH_ITEMS", "CORR_EVIDENCE_BATCH_BYTES",
                  "CORR_EVIDENCE_BATCH_MS", "CORR_EVIDENCE_HOLD_MAX_S",
                  "CORR_DECISION_OFFLOAD", "CORR_DECISION_BATCH_MS",
                  "CORR_DECISION_CURRENT_BATCH_MS", "CORR_LOOP_LAG_SAMPLE_S",
                  "CORR_LOOP_LAG_WARN_MS", "LOOP_LAG_STALLS", "LOOP_LAG_MAX_MS",
                  "ch", "_persist_snapshot", "_offload", "_LIFECYCLE_SEEN_WINDOW"):
        monkeypatch.setattr(main, _name, getattr(main, _name))
    yield monkeypatch
    _reset_engine_state()


def _calls_of(ch: _RecCH, table: str) -> int:
    """INSERT STATEMENTS issued for one table — the part-count currency."""
    return sum(1 for t, _rows, _tok in ch.writes if t == table)


def _run_leg(monkeypatch, *, batch: bool, components: int = 6, cohorts: int = 3,
             cohort_size: int = 4, reject: tuple[str, ...] = (),
             decision_batch: bool = False) -> _RecCH:
    """One leg of the A/B: the SAME fixture and schedule, only the batching flag
    differs. Everything a leg could carry over is reset first."""
    _reset_engine_state()
    ch = _RecCH(reject=reject)
    monkeypatch.setattr(main, "ch", ch)
    monkeypatch.setattr(main, "OPEN_OBJECTS", {})
    monkeypatch.setattr(main, "_EVIDENCE_QUEUE", None)
    monkeypatch.setattr(main, "_EVIDENCE_TASK", None)
    monkeypatch.setattr(main, "_EVIDENCE_LOOP", None)
    monkeypatch.setattr(main, "_EVIDENCE_BATCHER", None)
    monkeypatch.setattr(main, "_EVIDENCE_FLUSHER", None)
    monkeypatch.setattr(main, "CORR_EVIDENCE_ASYNC", True)
    monkeypatch.setattr(main, "CORR_EVIDENCE_BATCH", batch)
    monkeypatch.setattr(main, "CORR_DECISION_BATCH", decision_batch)
    monkeypatch.setattr(main, "CORR_ENGINE_COHORT_SIZE", cohort_size)
    main.EVIDENCE_ITEMS_MATERIALIZED = 0
    main.EVIDENCE_ITEMS_FAILED = 0
    main.EVIDENCE_ITEMS_LOST = 0
    _load(mixed_window(components))
    asyncio.run(_drain_cohorts(cohorts, cohort_size))
    return ch


def _rows_json(ch: _RecCH, table: str) -> list[str]:
    return [json.dumps(r, sort_keys=True, default=str) for r in ch.rows_of(table)]


# ═══ B1 — the rows do not move, only their grouping ══════════════════════════

def _item_key(table: str, row: dict) -> tuple:
    """Which persisted VERSION a row belongs to, per table's own column names."""
    if table == ARCHIVE:
        return (row["archived_for"], row["archived_version"])
    return (row["correlation_id"], row["version"])


def _by_item(ch: _RecCH, table: str) -> dict[tuple, list[str]]:
    """A table's rows grouped by version, each group in write order."""
    out: dict[tuple, list[str]] = {}
    for row in ch.rows_of(table):
        out.setdefault(_item_key(table, row), []).append(
            json.dumps(row, sort_keys=True, default=str))
    return out


def _groups_are_contiguous(ch: _RecCH, table: str) -> bool:
    """No version's rows are interleaved with another version's in this table."""
    seen: set[tuple] = set()
    last = None
    for row in ch.rows_of(table):
        key = _item_key(table, row)
        if key != last:
            if key in seen:
                return False
            seen.add(key)
            last = key
    return True


def test_B1_batching_moves_no_row_only_its_grouping(_stack):
    """THE test the step stands on.

    Per table: the same rows with the same bytes, each VERSION's rows in the
    same order and never interleaved with another version's — and strictly
    fewer INSERT statements.

    Why the cross-version sequence is compared as a MULTISET (E1's rule) and not
    as a list: the Evidence queue is a bounded priority heap drained
    concurrently with production, not a global sort, so which item is popped
    next legitimately depends on what had arrived by then. Batching changes the
    consumer's await pattern and therefore that interleaving. What may NOT move
    is any row, any byte, or the order INSIDE a version — which is what the
    per-item comparison below pins, and what a batcher that spliced two items'
    pages together would break."""
    off = _run_leg(_stack, batch=False)
    on = _run_leg(_stack, batch=True)

    assert off.writes, "the fixture must actually persist something"
    assert off.tables() == on.tables(), (
        f"a table appeared or vanished: {off.tables() ^ on.tables()}")
    # The Decision plane is untouched: identical rows in identical ORDER.
    for table in DECISION_TABLES:
        assert _rows_json(off, table) == _rows_json(on, table), (
            f"{table} rows moved under batching")
    for table in EVIDENCE_TABLES:
        assert sorted(_rows_json(off, table)) == sorted(_rows_json(on, table)), (
            f"{table} rows moved under batching")
        assert (sum(len(r) for r in _rows_json(off, table))
                == sum(len(r) for r in _rows_json(on, table))), \
            f"{table} bytes moved under batching"
        assert _by_item(off, table) == _by_item(on, table), (
            f"{table}: a version's own rows changed order under batching")
        assert _groups_are_contiguous(on, table), (
            f"{table}: two versions' rows were interleaved inside a block")


def test_B1b_the_evidence_tables_take_at_least_5x_fewer_inserts(_stack):
    """The point of the exercise, stated as the number ClickHouse feels: INSERT
    STATEMENTS, which is level-0 PARTS. The Decision tables must NOT move — they
    are not batched by default and this is where that is proven."""
    off = _run_leg(_stack, batch=False)
    on = _run_leg(_stack, batch=True)
    for table in EVIDENCE_TABLES:
        o, n = _calls_of(off, table), _calls_of(on, table)
        assert o >= 5, f"{table} baseline too small to measure ({o} inserts)"
        assert n * 5 <= o, (
            f"{table}: batching cut {o} inserts to {n} — under the 5x the "
            f"measured brief projects (63,701 -> ~5,900)")
    for table in DECISION_TABLES:
        assert _calls_of(off, table) == _calls_of(on, table), (
            f"{table} is the operator's verdict and is NOT batched by default")


# ═══ B2 — the block dedup token ══════════════════════════════════════════════

def test_B2_the_block_token_is_a_pure_function_of_its_members(_stack):
    """`ch_insert`'s in-process retry re-sends the IDENTICAL list, so the token
    must be identical too — hence content- and order-derived, never timing- or
    counter-derived."""
    keys = ["obj:a:v1:open:aa:edges:0", "obj:b:v1:open:bb:edges:0"]
    tok = batch_token(keys)
    assert tok == batch_token(list(keys)), "the token must be deterministic"
    assert tok.startswith("batch:") and len(tok) == len("batch:") + 32
    assert batch_token([]) == "", (
        "no members, no token — an empty block must behave like today's "
        "untokened insert rather than inventing an identity")


def test_B2b_a_flushed_block_carries_exactly_that_token(_stack):
    """The wiring half: what reaches `ch_insert` is `batch_token` over the
    member keys the block actually collected, in flush order."""
    seen: list[tuple[str, list, str]] = []

    async def sink(table, rows, token, ctx):
        seen.append((table, list(rows), token))
        return True

    async def go():
        b = RowBatcher(insert=sink, default=(2, 1 << 30, 1e9))
        m1, m2 = _member("obj:a:v1:open:aa"), _member("obj:b:v1:open:bb")
        await b.add(EDGES, [{"r": 1}], member=m1, dedup_token="obj:a:v1:open:aa:edges:0")
        await b.add(EDGES, [{"r": 2}], member=m2, dedup_token="obj:b:v1:open:bb:edges:0")
        return b

    asyncio.run(go())
    assert len(seen) == 1, "two members with a bound of 2 must be ONE block"
    _table, rows, token = seen[0]
    assert rows == [{"r": 1}, {"r": 2}], "rows must keep their arrival order"
    assert token == batch_token(["obj:a:v1:open:aa:edges:0",
                                 "obj:b:v1:open:bb:edges:0"])


def test_B2c_MUTANT_an_arrival_ordered_key_would_change_the_token(_stack):
    """B2b would pass vacuously if the token ignored order. It does not: the
    same members in the other order hash differently, which is exactly why a
    RETRY (same order) dedups and a re-composed block (different order) does
    not pretend to be the same write."""
    a, b = "obj:a:v1:open:aa:edges:0", "obj:b:v1:open:bb:edges:0"
    assert batch_token([a, b]) != batch_token([b, a])


def test_B2d_the_token_is_stable_under_a_resend_of_the_same_block(_stack):
    """The retry contract, at the level where it is actually true.

    `ch_insert` retries by re-sending the SAME list, so the token must be a pure
    function of the block — re-running the identical adds must mint the
    identical token, and changing the membership must change it.

    What is deliberately NOT asserted: that two RUNS of the same fixture produce
    the same block composition. They do not, and the measured brief says so — a
    block is whatever the consumer had drained when a trigger fired, which is a
    runtime condition. That is why cross-RESTART replay dedup is not preserved
    (step 4 gave it up already: a failed Evidence item is lost and loud, never
    replayed) and why in-process retry dedup is."""
    async def block(keys: list[str]) -> str:
        got: list[str] = []

        async def sink(table, rows, token, ctx):
            got.append(token)
            return True

        b = RowBatcher(insert=sink, default=(len(keys), 1 << 30, 1e9))
        for k in keys:
            await b.add(EDGES, [{"k": k}], member=_member(k), dedup_token=k)
        # `add` no longer awaits the INSERT (the block is written by its own
        # task, off the batcher lock), so the sink is read after a quiesce.
        await b.quiesce()
        return got[0]

    keys = ["obj:a:v1:open:aa:edges:0", "obj:b:v1:open:bb:edges:0"]
    first = asyncio.run(block(list(keys)))
    assert first == asyncio.run(block(list(keys))), (
        "the same block re-sent must carry the same token, or ClickHouse cannot "
        "dedup `ch_insert`'s retry")
    assert first != asyncio.run(block([*keys, "obj:c:v1:open:cc:edges:0"])), (
        "a different membership must be a different write")


def test_B2e_every_batched_evidence_insert_carries_a_batch_token(_stack):
    """The wiring, end to end: no batched block may reach ClickHouse untokened —
    including `corr_signals_archive`, which is written untokened today and gains
    a content-derived block token here."""
    ch = _run_leg(_stack, batch=True)
    for table in EVIDENCE_TABLES:
        toks = ch.tokens_of(table)
        assert toks, f"{table} was never written"
        assert all(t.startswith("batch:") for t in toks), (
            f"{table} block(s) without a batch token: "
            f"{[t for t in toks if not t.startswith('batch:')]}")
        assert len(set(toks)) == len(toks), f"{table} reused a block token"


# ═══ B3 — the three triggers, each on its own ════════════════════════════════

class _Member:
    __slots__ = ("tok",)

    def __init__(self, tok: str) -> None:
        self.tok = tok


def _member(tok: str) -> _Member:
    return _Member(tok)


class _Sink:
    def __init__(self, fail: tuple[str, ...] = ()) -> None:
        self.calls: list[tuple[str, list, str, dict]] = []
        self.fail = set(fail)

    async def __call__(self, table, rows, token, ctx):
        self.calls.append((table, list(rows), token, dict(ctx)))
        return table not in self.fail


def test_B3_the_member_count_trigger_flushes_and_not_before(_stack):
    sink = _Sink()

    async def go():
        b = RowBatcher(insert=sink, default=(3, 1 << 30, 1e9))
        for i in range(2):
            await b.add(EDGES, [{"i": i}], member=_member(f"m{i}"))
        assert not sink.calls, "two members under a bound of three must not flush"
        await b.add(EDGES, [{"i": 2}], member=_member("m2"))
        await b.quiesce()
        assert len(sink.calls) == 1, "the third member must flush the block"
        assert len(sink.calls[0][1]) == 3

    asyncio.run(go())


def test_B3b_the_byte_trigger_flushes_independently_of_the_member_count(_stack):
    """A single huge version must not sit in a buffer waiting for 199 friends."""
    sink = _Sink()
    fat = [{"blob": "x" * 4096} for _ in range(64)]     # ~256 KiB

    async def go():
        b = RowBatcher(insert=sink, default=(1 << 20, 200 * 1024, 1e9))
        await b.add(EDGES, fat[:8], member=_member("m0"))
        assert not sink.calls, "32 KiB is under the 200 KiB bound"
        await b.add(EDGES, fat, member=_member("m0"))
        await b.quiesce()
        assert len(sink.calls) == 1, "the byte bound must flush on its own"

    asyncio.run(go())


def test_B3c_the_age_trigger_flushes_a_trickle(_stack):
    """The clause that binds live: at 11.6 versions/s neither size trigger is
    reached, and without the age clause a trickle would never be written."""
    sink = _Sink()

    async def go():
        b = RowBatcher(insert=sink, default=(1 << 20, 1 << 30, 0.05))
        await b.add(EDGES, [{"i": 0}], member=_member("m0"))
        await b.flush_due()
        assert not sink.calls, "a fresh block must not age out"
        await asyncio.sleep(0.08)
        await b.flush_due()
        await b.quiesce()
        assert len(sink.calls) == 1, "the oldest row aged past the bound"
        assert b.stats()["batch_age_seconds_max"] >= 0.05

    asyncio.run(go())


def test_B3d_the_LIVE_flusher_task_ages_a_partial_block_out(_stack):
    """B3c drives `flush_due` by hand; this proves something actually calls it.

    A queued item is written by the consumer into a partial block and NOTHING
    else happens — no drain, no shutdown, no second item. The rows must still
    reach ClickHouse, because on a live trickle they always will be a partial
    block."""
    ch = _RecCH()
    _stack.setattr(main, "ch", ch)
    _stack.setattr(main, "CORR_EVIDENCE_BATCH_MS", 60.0)

    async def go():
        q = main._evidence_ensure_consumer()
        assert q is not None
        snap = _small_snapshot()
        await q.put(EvidenceItem(
            correlation_id="c1", tenant_id="t1", version=1, state="open",
            tok="obj:c1:v1:open:aa", snap=snap, priority_class=0,
            window_start_ts=ENGINE_T0.timestamp()))
        for _ in range(400):            # bounded wait: the flusher, not a drain
            await asyncio.sleep(0.01)
            if ch.rows_of(EDGES):
                break
        await main._evidence_stop()

    asyncio.run(go())
    assert ch.rows_of(EDGES), (
        "a partial block was never aged out — a trickle would sit in memory "
        "until shutdown, which is the one way batching can lose a row")
    assert main.EVIDENCE_ITEMS_MATERIALIZED == 1


# ═══ B4 — failure accounting, per MEMBER ITEM ════════════════════════════════

def test_B4_a_failed_block_counts_every_member_and_names_their_tokens(_stack,
                                                                     caplog):
    """From the consumer there is no cohort to retry (step 4's stated trade), so
    the block's failure must be attributed to every VERSION it carried, with the
    member tokens in the log — they are the only way to find which rows are
    missing from the table."""
    caplog.set_level(logging.ERROR, logger="correlation")
    ch = _run_leg(_stack, batch=True, reject=(EDGES,), components=4, cohorts=1,
                  cohort_size=8)
    persisted = main.EVIDENCE_ITEMS_FAILED + main.EVIDENCE_ITEMS_MATERIALIZED
    assert persisted >= 4, "the fixture must persist several versions"
    assert main.EVIDENCE_ITEMS_MATERIALIZED == 0, (
        "every version's edges were in the rejected block, so no item may be "
        "counted materialized")
    assert main.EVIDENCE_ITEMS_FAILED == persisted, (
        "outcome=failed must be counted ONCE PER MEMBER ITEM, not once per block")
    blocked = [r for r in caplog.records
               if "evidence batch block FAILED" in r.getMessage()]
    assert blocked, "a failed block must be logged"
    assert "member_tokens=" in blocked[0].getMessage()
    assert "obj:" in blocked[0].getMessage(), (
        "the log must name the members, not just count them")
    assert _calls_of(ch, EDGES) >= 1


def test_B4b_a_failed_archive_block_reverts_its_optimistic_hash(_stack):
    """The damping record is written before the rows land, so a failed archive
    write must REVERT it — the same rule as the unbatched path (E5b), now
    decided by the BLOCK's outcome rather than the item's return value."""
    _run_leg(_stack, batch=True, reject=(ARCHIVE,), components=3, cohorts=1,
             cohort_size=8)
    assert main._ARCHIVE_SLICE_HASH == {}, (
        "a slice that did not land whole must leave no damping record behind")
    assert main.EVIDENCE_ITEMS_FAILED >= 3


def test_B4c_a_successful_run_counts_every_item_exactly_once(_stack):
    """The other half of B4: deferred settlement must not lose or double-count
    an item. Batched and unbatched legs must agree exactly."""
    _run_leg(_stack, batch=False)
    off = (main.EVIDENCE_ITEMS_MATERIALIZED, main.EVIDENCE_ITEMS_FAILED,
           main.EVIDENCE_ITEMS_LOST)
    _run_leg(_stack, batch=True)
    on = (main.EVIDENCE_ITEMS_MATERIALIZED, main.EVIDENCE_ITEMS_FAILED,
          main.EVIDENCE_ITEMS_LOST)
    assert off == on, f"item accounting moved under batching: {off} -> {on}"
    assert off[0] > 0 and off[1] == 0 and off[2] == 0


# ═══ B5 — nothing may be left buffered ═══════════════════════════════════════

def _small_snapshot():
    from catalog import builtin_catalog
    from engine import EngineConfig, run_window
    from test_p2_evidence_async import mixed_window as _mw
    return run_window(_mw(2), builtin_catalog(), (), EngineConfig())[0]


def test_B5_shutdown_flushes_a_partial_block(_stack):
    """`_evidence_stop` must leave nothing in a buffer: a block nobody will ever
    flush is indistinguishable from a lost row."""
    ch = _RecCH()
    _stack.setattr(main, "ch", ch)
    _stack.setattr(main, "CORR_EVIDENCE_BATCH_MS", 1e6)   # the age clause cannot fire

    async def go():
        q = main._evidence_ensure_consumer()
        assert q is not None
        snap = _small_snapshot()
        for v in range(1, 4):
            await q.put(EvidenceItem(
                correlation_id=f"c{v}", tenant_id="t1", version=v, state="open",
                tok=f"obj:c{v}:v{v}:open:aa", snap=snap, priority_class=0,
                window_start_ts=ENGINE_T0.timestamp()))
        while not q.idle():
            await asyncio.sleep(0.005)
        assert main._EVIDENCE_BATCHER is not None
        buffered_before = main._EVIDENCE_BATCHER.buffered()
        await main._evidence_stop()
        return buffered_before

    buffered = asyncio.run(go())
    assert buffered > 0, "the fixture must actually leave a partial block"
    assert ch.rows_of(EDGES), "shutdown did not flush the partial block"
    assert main.EVIDENCE_ITEMS_MATERIALIZED == 3
    assert main.EVIDENCE_ITEMS_LOST == 0


def test_B5b_evidence_drain_means_the_rows_are_written(_stack):
    """Every caller of `evidence_drain` — the shutdown path, `engine_cycle`'s
    one-shot finally, every test that asserts on Evidence rows — reads it as
    "the rows are in ClickHouse". An idle QUEUE is not a written queue once a
    buffer exists, so the drain flushes."""
    ch = _RecCH()
    _stack.setattr(main, "ch", ch)
    _stack.setattr(main, "CORR_EVIDENCE_BATCH_MS", 1e6)

    async def go():
        q = main._evidence_ensure_consumer()
        assert q is not None
        await q.put(EvidenceItem(
            correlation_id="c1", tenant_id="t1", version=1, state="open",
            tok="obj:c1:v1:open:aa", snap=_small_snapshot(), priority_class=0,
            window_start_ts=ENGINE_T0.timestamp()))
        left = await main.evidence_drain(10.0)
        assert left == 0
        assert ch.rows_of(EDGES), "drain returned with rows still buffered"
        assert main._EVIDENCE_BATCHER.buffered() == 0
        await main._evidence_stop()

    asyncio.run(go())


# ═══ B6 — observability ══════════════════════════════════════════════════════

def test_B6_the_batch_counters_reach_metrics_and_stats(_stack):
    """§10: the number to read is rows_per_flush — it IS the part-count divisor."""
    _run_leg(_stack, batch=True)
    st = main.evidence_stats()
    assert st["flushes"] > 0
    assert st["rows_per_flush_mean"] > 1.0, (
        "batching that produces one row per flush is not batching")
    assert st["buffered_rows"] == 0, "the drain must leave nothing buffered"
    text = main._metrics_text()
    assert f'corr_evidence_flushes_total{{table="{EDGES}"}}' in text
    assert "corr_evidence_rows_per_flush " in text
    assert "corr_evidence_batch_age_seconds_max " in text
    assert "corr_evidence_batch_blocks_failed_total 0" in text


def test_B6c_the_flush_insert_is_its_own_profiler_stage(_stack):
    """Batching moves the INSERT out of `persist.evidence` and into a flush a
    different item may have triggered. Without its own span the profiler would
    simply lose those seconds — the §12.10(b) mistake, which is why nothing in
    that profile explained the pinned queue."""
    _stack.setattr(main, "CORR_PROFILE_STAGES", True)
    main._STAGE_STATS.pop("persist.batch_flush", None)
    _run_leg(_stack, batch=True)
    assert main._STAGE_STATS.get("persist.batch_flush"), (
        "the batched INSERT is not timed anywhere")


def test_B6b_the_stats_key_set_is_identical_with_batching_off(_stack):
    """The rank-memo lesson (§12.5): a key that appears and disappears with a
    flag reads as a zero on the day it matters."""
    _run_leg(_stack, batch=True)
    on = set(main.evidence_stats())
    _stack.setattr(main, "CORR_EVIDENCE_BATCH", False)
    _stack.setattr(main, "_EVIDENCE_BATCHER", None)
    off = set(main.evidence_stats())
    assert on == off, f"key set moved with the flag: {on ^ off}"


# ═══ B9 — the DECISION plane's batching is OFF, and correct when forced on ═══

def test_B9_decision_batching_is_off_by_default(_stack):
    """It trades T1 TTUR directly, so it ships off. This is the pin that says
    somebody has to mean it."""
    import os
    assert main.CORR_DECISION_BATCH is False
    assert os.environ.get("CORR_DECISION_BATCH") is None
    on = _run_leg(_stack, batch=True)
    assert _calls_of(on, "netops.corr_objects") == len(on.rows_of("netops.corr_objects")), \
        "corr_objects must still be one row per INSERT with the flag off"


def test_B9b_forced_on_it_moves_no_row_and_keeps_the_token_construction(_stack):
    """When somebody does mean it: the same verdict rows, in the same order,
    and a block token that is the ordered hash of the members' own
    content-derived `obj:<cid>:v<n>:<state>:<hash16>:objects` keys."""
    off = _run_leg(_stack, batch=True, decision_batch=False)
    on = _run_leg(_stack, batch=True, decision_batch=True)
    for table in DECISION_TABLES:
        assert _rows_json(off, table) == _rows_json(on, table), f"{table} rows moved"
        assert _calls_of(on, table) < _calls_of(off, table), (
            f"{table} was not actually batched")
    for table, suffix in (("netops.corr_objects", "objects"),
                          ("netops.corr_current", "current")):
        for t, rows, tok in on.writes:
            if t != table:
                continue
            assert tok == batch_token(
                [f"obj:{r['correlation_id']}:v{r['version']}:{r['state']}:"
                 f"{_hash16_of(off, r)}:{suffix}" for r in rows]), (
                f"{table} block token is not the ordered hash of its members")


def _hash16_of(ch: _RecCH, row: dict) -> str:
    """Recover a row's content-hash suffix from the UNBATCHED leg's token, which
    is `obj:<cid>:v<n>:<state>:<hash16>:objects` — so B9b compares the batched
    token against keys built from tokens the other leg actually emitted, not
    against a re-derivation of the hash."""
    want = f"obj:{row['correlation_id']}:v{row['version']}:{row['state']}:"
    for _t, _rows, tok in ch.writes:
        if tok.startswith(want) and tok.endswith((":objects", ":current")):
            return tok[len(want):].rsplit(":", 1)[0]
    raise AssertionError(f"no unbatched token for {row['correlation_id']}")


# ═══ B10 — the Decision write is off the loop thread (step 4d) ═══════════════

def _storm_fixture(*, nodes: int, edges: int, ambient: int):
    """A storm-shaped snapshot plus the window it was computed from.

    Two knobs because the Decision write has two independent size drivers: the
    OBJECT (its blob, its badges, its byte estimate) and the WINDOW (the archive
    slice's `_window_index`, which the FIRST object of a cycle pays however small
    that object is — that is the case a snapshot-sized threshold would miss).
    """
    from catalog import builtin_catalog
    from engine import run_window

    cat = builtin_catalog()

    def one(d):
        return run_window(
            [engine_sig("link_state_change", EntityType.DEVICE, d,
                        severity=Severity.CRIT),
             engine_sig("device_resource_anomaly", EntityType.DEVICE, d,
                        severity=Severity.CRIT, offset_s=1)], cat, ())[0]

    base = one("dev0")
    ns = tuple(n for i in range(nodes) for n in one(f"dev{i}").nodes)
    proto = base.edges[0]
    keys = [n.key for n in ns]
    es: list = []
    i = 0
    while len(es) < edges:
        a, b = keys[i % len(keys)], keys[(i * 7 + 3) % len(keys)]
        i += 1
        if a != b:
            es.append(dataclasses.replace(proto, from_node=a, to_node=b))
    snap = dataclasses.replace(
        base, correlation_id="storm", nodes=ns, edges=tuple(es),
        window_start=ENGINE_T0, window_end=ENGINE_T0 + timedelta(minutes=180))
    window = [s for n in snap.nodes for s in n.signals]
    window.extend(engine_sig("if_util_high", EntityType.DEVICE,
                             f"amb{k % 2000}", offset_s=k * 0.01)
                  for k in range(ambient))
    return snap, window


# The live-sized window, and the STARTING size for B10's mutant only: the
# `_window_index` build the mutant runs on the loop thread is linear in the
# window (measured on the lab box: 21 ms per 1,000 signals, 1,086 ms at 50k;
# the hosted runner did the same 50k in ~407 ms and could not witness the
# 500 ms defect). `timing_gate` grows the AMBIENT count — never the object,
# which must stay two nodes for the slice to be what is isolated.
_B10_AMBIENT = 50_000
_B10_MAX_AMBIENT = 400_000     # ~8 s of grind on the lab box; the cap
_LOOP_BUDGET_MS = 500.0        # §4's budget: the number the watchdog warns at


@pytest.fixture(scope="module")
def wide_window():
    """A TINY object against a live-sized 50k-signal window — the shape that
    isolates the archive slice, because everything else in the Decision write is
    proportional to the object and this object is two nodes."""
    return _storm_fixture(nodes=1, edges=1, ambient=_B10_AMBIENT)


async def _watchdog_lag_while(work) -> float:
    """Run `work()` under main's REAL loop-lag watchdog; return the worst lag."""
    main.LOOP_LAG_STALLS = 0
    main.LOOP_LAG_MAX_MS = 0.0
    task = asyncio.create_task(main.loop_lag_watchdog())
    await asyncio.sleep(main.CORR_LOOP_LAG_SAMPLE_S * 3)
    await work()
    await asyncio.sleep(main.CORR_LOOP_LAG_SAMPLE_S * 3)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    return main.LOOP_LAG_MAX_MS


def _persist_under_watchdog(_stack, snap, window, *, offload: bool) -> float:
    _stack.setattr(main, "CORR_DECISION_OFFLOAD", offload)
    _stack.setattr(main, "CORR_LOOP_LAG_SAMPLE_S", 0.02)
    _stack.setattr(main, "CORR_LOOP_LAG_WARN_MS", _LOOP_BUDGET_MS)
    _stack.setattr(main, "ch", _RecCH())
    main._WINDOW_INDEX_CACHE.clear()
    main._ARCHIVE_SLICE_HASH.clear()

    async def go():
        async def work():
            await main._persist_snapshot(snap, 1, "open", window)
        return await _watchdog_lag_while(work)

    return asyncio.run(go())


def test_B10_the_decision_write_never_holds_the_loop_past_the_budget(_stack,
                                                                    wide_window):
    """The §4 target, pinned by the watchdog that would have to see it live:
    no single loop-thread stretch above 500 ms inside the Decision write.

    MUTANT (`CORR_DECISION_OFFLOAD=0`) — the shipped-before state: `_archive_slice`
    builds `_window_index` over a 50,000-signal window on the loop thread, one
    uninterruptible ~1 s stretch, and the watchdog counts a stall.

    THE WINDOW IS SIZED TO THE MACHINE (timing_gate.py). 500 ms is the budget
    the FIXED leg is held to — that is the design SLO and it is absolute. The
    same number on the mutant leg is not an SLO, it is the proof that the
    workload was big enough to make the SLO assertion mean something, and a
    hosted runner on 2026-09-03 ground the 50k window in 407 ms and so proved
    nothing. Only the ambient window count moves; the object stays two nodes."""
    built = {_B10_AMBIENT: wide_window}

    def grind(ambient: int) -> float:
        if ambient not in built:
            built[ambient] = _storm_fixture(nodes=1, edges=1, ambient=ambient)
        return _persist_under_watchdog(_stack, *built[ambient], offload=False)

    gate = timing_gate.calibrated_stall(
        grind, size=_B10_AMBIENT, floor=_LOOP_BUDGET_MS,
        max_size=_B10_MAX_AMBIENT,
        name="Decision write with the window index on the loop thread")
    assert gate.ok, gate.report()
    mutant = gate.value
    snap, window = built[gate.size]
    assert len(window) >= 50_000
    assert main.LOOP_LAG_STALLS >= 1, "the watchdog must count the mutant's stall"
    # The FIXED leg runs against the SAME window the mutant breached on.
    fixed = _persist_under_watchdog(_stack, snap, window, offload=True)
    assert fixed < _LOOP_BUDGET_MS, (
        f"the Decision write still froze the loop for {fixed:.0f} ms over "
        f"{len(window)} signals — the window-sized work is back on the event "
        f"loop")
    assert main.LOOP_LAG_STALLS == 0
    assert fixed < mutant / 2


def test_B10b_every_size_unbounded_decision_step_goes_to_the_executor(_stack):
    """The loop-lag instrument cannot separate the OBJECT-sized steps from each
    other (an offloaded `content_hash` holds the GIL, so the ticker sees tens to
    hundreds of ms whatever the other steps do). What CAN be asserted exactly is
    the dispatch: on a storm-shaped object the badges parse, the slice+hash and
    the byte estimate all run in the executor — and with the flag off they do
    not. Measured on this shape: 489 ms, 1,267 ms and 317 ms respectively."""
    snap, window = _storm_fixture(nodes=8, edges=4000, ambient=4000)
    seen: list[str] = []
    real = main._offload

    async def spy(fn, /, *a, **k):
        seen.append(getattr(fn, "__name__", repr(fn)))
        return await real(fn, *a, **k)

    _stack.setattr(main, "_offload", spy)
    _stack.setattr(main, "ch", _RecCH())

    async def go():
        main._WINDOW_INDEX_CACHE.clear()
        main._ARCHIVE_SLICE_HASH.clear()
        q = main._evidence_ensure_consumer()
        assert q is not None
        # Held, so the Evidence consumer cannot interleave its own offloads into
        # the spy while the Decision write is being measured.
        async with main._evidence_cohort_hold():
            await main._persist_snapshot(snap, 1, "open", window)
        decision = list(seen)
        await main._evidence_stop()
        return decision

    _stack.setattr(main, "CORR_DECISION_OFFLOAD", True)
    on = asyncio.run(go())
    seen.clear()
    _stack.setattr(main, "CORR_DECISION_OFFLOAD", False)
    off = asyncio.run(go())

    for name in ("_current_badges", "_archive_slice_and_hash", "estimate_bytes"):
        assert name in on, f"{name} still runs on the loop thread"
        assert name not in off, (
            f"{name} was offloaded with CORR_DECISION_OFFLOAD=0 — the A/B flag "
            f"does not actually revert the change")
    # The step-4 offloads are unchanged by this flag: it adds work to the
    # executor, it never takes any away.
    assert "cycle_hypotheses_blob" in on and "cycle_hypotheses_blob" in off


def test_B10c_a_small_object_and_a_small_window_stay_inline(_stack):
    """The threshold must not send every tiny object through a thread — a hop
    costs more than the work below CORR_OFFLOAD_MIN_ELEMENTS, and that is as
    true for the three new calls as for the six old ones."""
    snap, window = _storm_fixture(nodes=1, edges=1, ambient=10)
    assert main._snap_elements(snap) < main.CORR_OFFLOAD_MIN_ELEMENTS
    assert len(window) < main.CORR_OFFLOAD_MIN_ELEMENTS
    seen: list[str] = []
    real = main._offload

    async def spy(fn, /, *a, **k):
        seen.append(getattr(fn, "__name__", repr(fn)))
        return await real(fn, *a, **k)

    _stack.setattr(main, "_offload", spy)
    _stack.setattr(main, "ch", _RecCH())

    async def go():
        main._WINDOW_INDEX_CACHE.clear()
        main._ARCHIVE_SLICE_HASH.clear()
        await main._persist_snapshot(snap, 1, "open", window)

    asyncio.run(go())
    for name in ("_current_badges", "_archive_slice_and_hash", "estimate_bytes"):
        assert name not in seen, f"{name} paid an executor hop it did not need"


# ═══ B11 — the batcher's own bookkeeping ═════════════════════════════════════

def test_B11_a_flush_reports_every_member_and_the_rows_in_order(_stack):
    """The callback contract the accounting rests on."""
    reports: list[tuple] = []
    sink = _Sink()

    def on_flush(table, rows, keys, members, ok, exc):
        reports.append((table, [dict(r) for r in rows], list(keys),
                        [m.tok for m in members], ok, exc))

    async def go():
        b = RowBatcher(insert=sink, on_flush=on_flush, default=(2, 1 << 30, 1e9))
        m1, m2 = _member("a"), _member("b")
        await b.add(EDGES, [{"i": 0}], member=m1)
        await b.add(EDGES, [{"i": 1}], member=m1)   # same member, two chunks
        assert not reports, "one member must not trip a bound of two"
        await b.add(EDGES, [{"i": 2}], member=m2)

    asyncio.run(go())
    assert len(reports) == 1
    table, rows, keys, toks, ok, exc = reports[0]
    assert table == EDGES and ok is True and exc is None
    assert rows == [{"i": 0}, {"i": 1}, {"i": 2}]
    assert toks == ["a", "b"], "members are DISTINCT items, in arrival order"
    assert keys == [f"a:{EDGES}:0", f"a:{EDGES}:1", f"b:{EDGES}:0"], (
        "an untokened chunk must derive a deterministic key from its member")


def test_B11b_a_raising_sink_is_reported_not_propagated(_stack):
    """A flush can be triggered by a producer with nothing to do with the block
    being written, so an exception must not surface as THAT producer's failure.
    It is captured and handed to `on_flush` with the block's members."""
    reports: list[tuple] = []

    async def boom(table, rows, token, ctx):
        raise main.CHInsertRejected("nope")

    async def go():
        b = RowBatcher(insert=boom,
                       on_flush=lambda t, r, k, m, ok, e: reports.append((t, ok, e)),
                       default=(1, 1 << 30, 1e9))
        await b.add(EDGES, [{"i": 0}], member=_member("a"))   # must not raise
        await b.quiesce()
        assert b.stats()["blocks_failed_total"] == 1

    asyncio.run(go())
    assert reports and reports[0][1] is False
    assert isinstance(reports[0][2], main.CHInsertRejected)


# ═══ B12/B13 — the STORM AGGREGATE: the object every size gate under-read ════
#
# Live regression, run t-storm-2.5k (2026-08-29 17:17 UTC, replica
# netops-correlation-4): `corr_loop_lag_max_ms` 114,848 — one 115-second
# event-loop stall — with `persist.decision` max 23,655 ms and
# `persist.batch_flush` max 116,507 ms, beginning immediately after the storm
# aggregate `bb1e46d6` (tenant-constant cid, `storm_aggregate=True`) was
# persisted as v9 with 922 nodes. On the nominal runs `persist.batch_flush` max
# was 3.6-4.9 s.
#
# THE SHAPE, and why it defeated every threshold on the persist path: a
# storm-noise aggregate is emitted with `edges=()` (engine.py:3040) and one node
# per folded below-floor entity, so `_snap_elements` (nodes + edges) reads ~950
# for the object that holds the entire below-floor flood — tens of thousands of
# signals. Every gate keyed on it therefore said "small" and ran
# `content_hash`, `material_hash`, `to_object_row` and `estimate_bytes` INLINE,
# on the event-loop thread, over all of them. `_snap_cost` counts the signals;
# the block ROW cap bounds what one member can hand a single INSERT.

@pytest.fixture(scope="module")
def storm_aggregate():
    """A storm-NOISE aggregate: ~950 nodes, NO edges, ~85k signals — and the
    window those signals came from, so the archive slice is the whole flood."""
    return _aggregate_fixture()


# The shipped sizer, captured at import: every leg that installs the mutant's
# `_snap_elements` needs something to put back, and by the time a leg runs
# `main._snap_cost` may already be the mutant's.
_SHIPPED_SNAP_COST = main._snap_cost

# The live aggregate's shape: 950 folded entities (`bb1e46d6` had 922) carrying
# 90 signals each. The NODE COUNT is load-bearing and must never be the growth
# axis — `_snap_elements` is `len(nodes) + len(edges)` and the whole defect is
# that it reads BELOW `CORR_OFFLOAD_MIN_ELEMENTS` (2,000) for the costliest
# object in the process. Measured: at 2,375 nodes the mutant's worst lag fell
# from 2,418 ms to 339 ms, because past the threshold the mutant sizer offloads
# too and there is no mutant left. SIGNALS PER NODE is the axis that grows the
# serialize-and-hash cost while keeping the shape (B12 calibrates on it).
_AGG_NODES = 950
_AGG_SIGNALS_PER_NODE = 90
_AGG_MAX_SIGNALS_PER_NODE = 360


def _aggregate_fixture(per_node: int = _AGG_SIGNALS_PER_NODE):
    """`_AGG_NODES` folded entities carrying `per_node` signals each, plus the
    window those signals came from, so the archive slice is the whole flood.

    Deliberately built by hand rather than driven through `run_window`'s storm
    branch: the fixture has to pin the SHAPE (edges=(), mass in node signals)
    that the sizing defect turns on, and building it explicitly is what makes
    that shape visible to the next reader."""
    from catalog import builtin_catalog
    from engine import run_window
    cat = builtin_catalog()
    base = run_window(
        [engine_sig("link_state_change", EntityType.DEVICE, "dev0",
                    severity=Severity.CRIT),
         engine_sig("device_resource_anomaly", EntityType.DEVICE, "dev0",
                    severity=Severity.CRIT, offset_s=1)], cat, ())[0]
    proto = base.nodes[0]
    nodes, window = [], []
    for i in range(_AGG_NODES):
        sigs = tuple(engine_sig("link_state_change", EntityType.DEVICE, f"agg{i}",
                                severity=Severity.WARN, offset_s=j * 0.25 + i * 0.001)
                     for j in range(per_node))
        nodes.append(dataclasses.replace(
            proto, key=f"device:agg{i}:link_state_change", entity_id=f"agg{i}",
            signals=sigs, onset=sigs[0].ts, peak_severity=Severity.WARN,
            occurrences=per_node))
        window.extend(sigs)
    snap = dataclasses.replace(
        base, correlation_id="a1b2c3d4-0000-0000-0000-00000000000f",
        nodes=tuple(nodes), edges=(), storm_mode=True, storm_aggregate=True,
        storm_occurrences=len(window), storm_distinct_entities=len(nodes),
        window_start=ENGINE_T0 - timedelta(seconds=1),
        window_end=ENGINE_T0 + timedelta(minutes=180))
    return snap, window


def _aggregate_stack(_stack, *, batch: bool = True) -> _RecCH:
    """A clean engine + Evidence plane for one aggregate leg."""
    _reset_engine_state()
    ch = _RecCH()
    _stack.setattr(main, "ch", ch)
    _stack.setattr(main, "OPEN_OBJECTS", {})
    _stack.setattr(main, "_EVIDENCE_QUEUE", None)
    _stack.setattr(main, "_EVIDENCE_TASK", None)
    _stack.setattr(main, "_EVIDENCE_LOOP", None)
    _stack.setattr(main, "_EVIDENCE_BATCHER", None)
    _stack.setattr(main, "_EVIDENCE_FLUSHER", None)
    _stack.setattr(main, "CORR_EVIDENCE_ASYNC", True)
    _stack.setattr(main, "CORR_EVIDENCE_BATCH", batch)
    _stack.setattr(main, "CORR_DECISION_OFFLOAD", True)
    main._WINDOW_INDEX_CACHE.clear()
    main._ARCHIVE_SLICE_HASH.clear()
    main._CYCLE_ROW_CACHE.clear()
    return ch


async def _persist_and_drain(snap, window) -> None:
    q = main._evidence_ensure_consumer()
    assert q is not None, "the aggregate legs must run through the CONSUMER"
    await main._persist_snapshot(snap, 1, "open", window)
    await main._evidence_stop()


def _aggregate_lag(_stack, snap, window, *, cost_gate: bool) -> float:
    """Worst loop-lag sample while the aggregate is persisted AND drained.

    `cost_gate=False` restores the shipped-before sizer (`_snap_elements`) and
    is the MUTANT: it is the one-line difference between "the largest object in
    the process is protected by the offload threshold" and "it is not".

    THE CYCLE COLLECTOR IS TURNED OFF INSIDE THE MEASURED WINDOW, and that is
    not a convenience. A gen-2 collection runs on whatever thread trips the
    allocation threshold, holds the GIL for the whole sweep, and is sized by the
    PROCESS heap — nothing this module allocates and nothing `_offload` can
    move. Measured on this fixture: 319 ms worst lag on a clean heap, 1,773 ms
    with a 3M-object ballast retained, 185 ms with the same ballast and the
    collector off. Left on, this test would be measuring the heap the rest of
    the suite happens to be holding rather than the stretch it names — and the
    GC stall is a REAL finding about the live 115 s stall, tracked separately;
    it is simply not the thing this assertion is about.
    """
    _aggregate_stack(_stack, batch=True)
    _stack.setattr(main, "CORR_LOOP_LAG_SAMPLE_S", 0.02)
    _stack.setattr(main, "CORR_LOOP_LAG_WARN_MS", _LOOP_BUDGET_MS)
    # The SIZER is the variable here, so the OTHER offload gate is held off in
    # BOTH legs: `_snap_call`'s projected-milliseconds rule (CORR_SYNC_OFFLOAD,
    # 2026-08-29) would also route the aggregate to the executor — it is the
    # belt to this sizer's braces and has its own witness in
    # test_sync_stretch_bound_p1.py. Left on, it would rescue the mutant and
    # this test would silently stop proving anything about `_snap_cost`.
    _stack.setattr(main, "CORR_SYNC_OFFLOAD", False)
    _stack.setattr(main, "_SYNC_RATE", {})
    # Set on BOTH legs, explicitly. `monkeypatch.setattr` does not undo between
    # calls inside one test, so `if not cost_gate: setattr(...)` left the mutant
    # sizer installed for the FIXED leg that ran after it — the "fixed" number
    # was a warm-cache re-run of the mutant (302 ms against the mutant's
    # 1,321 ms, where the genuinely fixed path measures 94 ms on the same box),
    # and `fixed < budget` was not asserting what it names. B12b's `leg()`
    # already restored it this way; this is that fix in the lag harness.
    _stack.setattr(main, "_snap_cost",
                   _SHIPPED_SNAP_COST if cost_gate else main._snap_elements)
    # The digests are memoized on the frozen snapshot, so a second leg over the
    # same module-scoped fixture would measure a cache hit, not the serialize.
    for attr in ("_content_hash_c", "_material_hash_c"):
        with contextlib.suppress(AttributeError):
            object.__delattr__(snap, attr)

    async def go():
        async def work():
            await _persist_and_drain(snap, window)
        return await _watchdog_lag_while(work)

    gc.collect()
    was_enabled = gc.isenabled()
    gc.disable()
    try:
        return asyncio.run(go())
    finally:
        if was_enabled:
            gc.enable()


def test_B12_the_storm_aggregate_never_holds_the_loop_past_the_budget(
        _stack, storm_aggregate):
    """The regression, pinned by the watchdog that saw it live.

    MUTANT (`_snap_cost` = `_snap_elements`, the shipped-before sizer): the
    aggregate's ~85k signals are serialized and hashed on the loop thread and
    the watchdog counts a stall above the 500 ms budget.

    THE FLOOD IS SIZED TO THE MACHINE (timing_gate.py). `fixed < 500 ms` is the
    §4 budget and stays absolute; the same number on the mutant leg is only the
    proof that the flood was big enough for that budget to be a real test, and
    a hosted runner on 2026-09-03 serialized this one in 466 ms and so proved
    nothing. Signals per node is the only axis grown — see `_aggregate_fixture`
    for why the node count must not be."""
    built = {_AGG_SIGNALS_PER_NODE: storm_aggregate}

    def grind(per_node: int) -> float:
        if per_node not in built:
            built[per_node] = _aggregate_fixture(per_node)
        snap, window = built[per_node]
        assert len(snap.nodes) >= 900 and not snap.edges, (
            "fixture must be an aggregate")
        assert snap.signal_count() >= 50_000, "fixture must carry the flood"
        assert main._snap_elements(snap) < main.CORR_OFFLOAD_MIN_ELEMENTS, (
            "the graph-sized reading must be BELOW the threshold — that is the "
            "defect")
        assert _SHIPPED_SNAP_COST(snap) >= main.CORR_OFFLOAD_MIN_ELEMENTS
        return _aggregate_lag(_stack, snap, window, cost_gate=False)

    gate = timing_gate.calibrated_stall(
        grind, size=_AGG_SIGNALS_PER_NODE, floor=_LOOP_BUDGET_MS,
        max_size=_AGG_MAX_SIGNALS_PER_NODE,
        name="storm aggregate serialized on the loop thread")
    assert gate.ok, gate.report()
    mutant = gate.value
    assert main.LOOP_LAG_STALLS >= 1, "the watchdog must count the mutant's stall"

    # The FIXED leg runs against the SAME flood the mutant breached on.
    snap, window = built[gate.size]
    fixed = _aggregate_lag(_stack, snap, window, cost_gate=True)
    assert fixed < _LOOP_BUDGET_MS, (
        f"a storm aggregate still froze the loop for {fixed:.0f} ms over "
        f"{snap.signal_count()} signals — its signal-sized work is back on the "
        f"event loop")
    assert main.LOOP_LAG_STALLS == 0
    assert fixed < mutant / 2


def test_B12b_the_aggregates_signal_sized_steps_go_to_the_executor(
        _stack, storm_aggregate):
    """The exact half of B12: WHICH calls are dispatched off the loop.

    Timing alone cannot separate them (an offloaded serialize still holds the
    GIL, so the ticker sees tens of ms whatever else happens — B10b's rule).
    The dispatch is exact: on an aggregate every signal-sized step runs in the
    executor under `_snap_cost`, and NONE of them does under `_snap_elements`."""
    snap, window = storm_aggregate
    seen: list[str] = []
    real = main._offload
    real_cost = main._snap_cost

    async def spy(fn, /, *a, **k):
        seen.append(getattr(fn, "__name__", repr(fn)))
        return await real(fn, *a, **k)

    def leg(*, cost_gate: bool) -> list[str]:
        _aggregate_stack(_stack, batch=True)
        _stack.setattr(main, "_offload", spy)
        # See `_aggregate_lag`: the projected-milliseconds gate is held off in
        # both legs so the DISPATCH being asserted is the sizer's, not its.
        _stack.setattr(main, "CORR_SYNC_OFFLOAD", False)
        _stack.setattr(main, "_SYNC_RATE", {})
        _stack.setattr(main, "_snap_cost",
                       real_cost if cost_gate else main._snap_elements)
        for attr in ("_content_hash_c", "_material_hash_c"):
            with contextlib.suppress(AttributeError):
                object.__delattr__(snap, attr)
        seen.clear()

        async def go():
            assert main._evidence_ensure_consumer() is not None
            # Held, so the consumer cannot interleave its own offloads into the
            # spy while the Decision write is being measured (B10b's rule).
            async with main._evidence_cohort_hold():
                await main._persist_snapshot(snap, 1, "open", window)
            got = list(seen)
            await main._evidence_stop()
            return got

        return asyncio.run(go())

    on = leg(cost_gate=True)
    off = leg(cost_gate=False)
    # `material_hash` takes the same route (`_snap_call`) but is computed by
    # engine_cycle's damping gate, not by `_persist_snapshot`, so it is not
    # observable here — B12's timing leg is what covers it.
    for name in ("cycle_hypotheses_blob", "to_object_row", "content_hash"):
        assert name in on, f"{name} still runs on the loop thread for an aggregate"
        assert name not in off, (
            f"{name} was offloaded by the SHIPPED-BEFORE sizer too — B12 would "
            f"then be proving something other than this change")
    # The byte estimate is charged by the object AND the slice hanging off the
    # item, so it is offloaded on this shape either way — asserted so the
    # widened sizing cannot silently regress to the object alone.
    assert "estimate_bytes" in on


def test_B12c_the_aggregate_writes_the_same_rows_and_bytes_batched_or_not(
        _stack, storm_aggregate):
    """B1's identity claim, on the shape that forced the fix: the same rows, the
    same bytes and the SAME ORDER — one item, so nothing may be reordered at
    all — with the block row cap splitting the slice into bounded INSERTs."""
    snap, window = storm_aggregate

    def leg(*, batch: bool) -> _RecCH:
        ch = _aggregate_stack(_stack, batch=batch)
        asyncio.run(_persist_and_drain(snap, window))
        return ch

    off = leg(batch=False)
    on = leg(batch=True)
    assert off.tables() == on.tables()
    for table in off.tables():
        assert _rows_json(off, table) == _rows_json(on, table), (
            f"{table}: a row moved between the batched and unbatched aggregate")
    assert len(off.rows_of(ARCHIVE)) >= 50_000, "the slice must be the flood"
    # Every block is inside the cap, and the cap actually bit (>1 archive block).
    blocks = [len(rows) for t, rows, _tok in on.writes if t == ARCHIVE]
    assert len(blocks) > 1 and max(blocks) <= main.CORR_EVIDENCE_BATCH_ROWS, (
        f"archive blocks {blocks} — one member must never exceed the row cap "
        f"({main.CORR_EVIDENCE_BATCH_ROWS})")
    toks = [tok for t, _rows, tok in on.writes if t == ARCHIVE]
    assert all(t.startswith("batch:") for t in toks)
    assert len(set(toks)) == len(toks), (
        "two archive blocks of ONE member hashed to the same block token — "
        "ClickHouse would drop the second the day the table gets a dedup window")


# ═══ B13 — the ROW cap: a giant member is split, in order, distinctly ════════

def test_B13_the_row_cap_splits_one_member_in_order_with_distinct_tokens():
    """`add` checks members/bytes/age AFTER the append, so before the cap ONE
    chunk landed whole however big it was. Split: same rows, same order, one
    block per cap-worth, and a DIFFERENT token per block."""
    seen: list[tuple[str, list, str]] = []
    joins: list[str] = []

    async def sink(table, rows, token, ctx):
        seen.append((table, list(rows), token))
        return True

    def go(cap: int) -> list[tuple[str, list, str]]:
        seen.clear()
        joins.clear()

        async def run():
            b = RowBatcher(insert=sink, on_join=lambda t, m: joins.append(m.tok),
                           default=(1000, 1 << 30, 1e9), max_rows=cap)
            await b.add(ARCHIVE, [{"i": i} for i in range(10)],
                        member=_member("obj:a:v1:open:aa"))
            await b.flush_all()

        asyncio.run(run())
        return list(seen)

    blocks = go(4)
    assert [len(rows) for _t, rows, _k in blocks] == [4, 4, 2], (
        "a 10-row chunk under a 4-row cap must be three bounded blocks")
    assert [r for _t, rows, _k in blocks for r in rows] == [{"i": i} for i in range(10)], \
        "splitting must preserve row order exactly"
    toks = [k for _t, _r, k in blocks]
    assert len(set(toks)) == 3 and all(t.startswith("batch:") for t in toks), (
        "each part must present its own key list, or two blocks of the same "
        "member hash to the same dedup token and ClickHouse drops one")
    assert joins == ["obj:a:v1:open:aa"] * 3, (
        "the member joined three blocks and must be counted waiting on three")
    assert go(4) == blocks, "the split, its keys and its tokens must be deterministic"

    # MUTANT: the pre-fix batcher (no cap) takes the whole member in one block.
    uncapped = go(0)
    assert len(uncapped) == 1 and len(uncapped[0][1]) == 10


def test_B13b_the_cap_never_splits_a_chunk_that_fits():
    """The un-split path must be untouched — same single key, same token as
    before the cap existed, so B2b/B2d keep meaning what they meant."""
    seen: list[tuple[str, list, str]] = []

    async def sink(table, rows, token, ctx):
        seen.append((table, list(rows), token))
        return True

    async def run():
        b = RowBatcher(insert=sink, default=(1, 1 << 30, 1e9), max_rows=1000)
        await b.add(EDGES, [{"i": 0}, {"i": 1}], member=_member("a"),
                    dedup_token="obj:a:v1:open:aa:edges:0")

    asyncio.run(run())
    assert len(seen) == 1
    assert seen[0][2] == batch_token(["obj:a:v1:open:aa:edges:0"]), (
        "a chunk that fits must keep exactly the key it had before the cap")


def test_B13c_the_evidence_batcher_is_built_with_the_row_cap(_stack):
    """The wiring: the shipped batcher carries the env-configured cap, and the
    Evidence plane reports it."""
    _stack.setattr(main, "CORR_EVIDENCE_BATCH_ROWS", 12_345)
    _stack.setattr(main, "CORR_EVIDENCE_BATCH_INFLIGHT", 7)
    b = main._make_row_batcher()
    assert b.rows_for(ARCHIVE) == 12_345
    assert b.stats()["block_rows_max"] == 12_345
    assert b.stats()["blocks_inflight_max"] == 7
    assert main.evidence_stats()["batch_rows_max"] == 12_345
    assert main.evidence_stats()["batch_inflight_max"] == 7


# ═══ B14 — the INSERT is not issued under the batcher lock ═══════════════════
#
# `persist.batch_flush` max 116,507 ms on run t-storm-2.5k was ONE block
# retrying behind a struggling ClickHouse — and for those 116 seconds
# `_flush_locked` held the batcher's single lock, so no producer could append a
# row and no other table could flush. The block is now taken out under the lock
# and written by its own task, ordered per TABLE by a ticket gate.

EVIDENCE = "netops.corr_evidence"


class _StallSink:
    """A sink that hangs on one table until released, and records the ORDER in
    which blocks started and finished."""

    def __init__(self, stall_table: str) -> None:
        self.stall_table = stall_table
        self.gate = asyncio.Event()
        self.started: list[tuple[str, str]] = []
        self.done: list[tuple[str, str]] = []

    async def __call__(self, table, rows, token, ctx):
        self.started.append((table, token))
        if table == self.stall_table:
            await self.gate.wait()
        self.done.append((table, token))
        return True


def test_B14_a_stalled_block_blocks_neither_producers_nor_other_tables():
    """The claim, stated as the two things the old lock made false.

    While a `corr_edges` INSERT is hung: a `corr_evidence` block still flushes
    end to end, and a producer's `add` still returns. MUTANT: the shipped-before
    shape is `add` awaiting the insert under the lock — modelled here by
    awaiting the same sink directly, which never returns until the gate opens."""
    sink = _StallSink(EDGES)

    async def go():
        b = RowBatcher(insert=sink, default=(1, 1 << 30, 1e9))
        # Hangs inside its write task; `add` must come straight back.
        await asyncio.wait_for(
            b.add(EDGES, [{"i": 0}], member=_member("a"), dedup_token="a:edges:0"),
            timeout=2.0)
        await asyncio.sleep(0)          # let the write task reach the sink
        assert sink.started == [(EDGES, batch_token(["a:edges:0"]))]
        assert not sink.done, "the fixture must actually be stalled"

        # A DIFFERENT table, start to finish, while corr_edges is hung.
        await asyncio.wait_for(
            b.add(EVIDENCE, [{"i": 1}], member=_member("a"),
                  dedup_token="a:evidence:0"),
            timeout=2.0)
        await asyncio.wait_for(b.quiesce(EVIDENCE), timeout=2.0)
        assert (EVIDENCE, batch_token(["a:evidence:0"])) in sink.done, (
            "a stalled corr_edges block held up corr_evidence — the INSERT is "
            "still being awaited under the shared lock")

        # And more producing on the STALLED table still returns (under the
        # in-flight bound), because only its WRITE is queued behind the stall.
        for i in range(3):
            await asyncio.wait_for(
                b.add(EDGES, [{"i": 10 + i}], member=_member(f"b{i}"),
                      dedup_token=f"b{i}:edges:0"),
                timeout=2.0)
        assert sink.done == [(EVIDENCE, batch_token(["a:evidence:0"]))], (
            "no later corr_edges block may overtake the stalled one")
        sink.gate.set()
        await asyncio.wait_for(b.flush_all(), timeout=5.0)
        return b

    asyncio.run(go())

    # MUTANT — the shipped-before shape, modelled exactly: ONE lock held across
    # the insert. The corr_edges write takes the lock and hangs; a corr_evidence
    # add can then never even reach its own table, which is the 116 seconds.
    stuck = _StallSink(EDGES)

    async def old_shape():
        lock = asyncio.Lock()

        async def old_add(table):
            async with lock:                       # `_flush_locked`, pre-fix
                await stuck(table, [{"i": 0}], "t", {})

        hung = asyncio.create_task(old_add(EDGES))
        await asyncio.sleep(0)
        with pytest.raises(asyncio.TimeoutError):
            await asyncio.wait_for(old_add(EVIDENCE), timeout=0.2)
        hung.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await hung

    asyncio.run(old_shape())


def test_B14b_a_tables_blocks_are_written_in_the_order_they_were_taken():
    """Per-table ORDER is the one thing the lock was buying, and the ticket gate
    is what replaces it: concatenating a table's blocks must still reproduce the
    row sequence the unbatched path writes, so block N may never be inserted
    before block N-1 however long N-1 takes."""
    order: list[str] = []

    async def sink(table, rows, token, ctx):
        # Every block sleeps a DIFFERENT time, longest first: without the gate
        # the later, faster blocks would finish first and the rows would land
        # out of order.
        await asyncio.sleep(0.05 / (rows[0]["i"] + 1))
        order.append(f"{table}#{rows[0]['i']}")
        return True

    async def go():
        b = RowBatcher(insert=sink, default=(1, 1 << 30, 1e9), max_inflight=16)
        for i in range(6):
            table = EDGES if i % 2 == 0 else EVIDENCE
            await b.add(table, [{"i": i}], member=_member(f"m{i}"),
                        dedup_token=f"m{i}")
        await b.flush_all()

    asyncio.run(go())
    assert [o for o in order if o.startswith(EDGES)] == [
        f"{EDGES}#0", f"{EDGES}#2", f"{EDGES}#4"]
    assert [o for o in order if o.startswith(EVIDENCE)] == [
        f"{EVIDENCE}#1", f"{EVIDENCE}#3", f"{EVIDENCE}#5"]
    # ...and the two tables INTERLEAVED, which is the proof they ran
    # concurrently rather than one table draining before the other started.
    assert order != [f"{EDGES}#0", f"{EDGES}#2", f"{EDGES}#4",
                     f"{EVIDENCE}#1", f"{EVIDENCE}#3", f"{EVIDENCE}#5"]


def test_B14c_the_in_flight_bound_is_what_stops_unbounded_buffering():
    """Writes no longer block their producer, so something else has to stop a
    stalled table from letting the consumer build blocks forever with every
    one of their rows resident. At the bound the producers OF THAT TABLE wait;
    B14 already pinned that no other table does."""
    sink = _StallSink(EDGES)

    async def go():
        b = RowBatcher(insert=sink, default=(1, 1 << 30, 1e9), max_inflight=2)
        for i in range(2):
            await asyncio.wait_for(
                b.add(EDGES, [{"i": i}], member=_member(f"m{i}")), timeout=2.0)
        assert b.inflight_for(EDGES) == 2
        with pytest.raises(asyncio.TimeoutError):
            await asyncio.wait_for(
                b.add(EDGES, [{"i": 2}], member=_member("m2")), timeout=0.2)
        assert b.stats()["writer_waits_total"] >= 1
        sink.gate.set()
        await asyncio.wait_for(b.flush_all(), timeout=5.0)
        assert b.inflight_for(EDGES) == 0

    asyncio.run(go())


def test_B14d_the_block_tokens_are_unchanged_by_the_writer_split():
    """The token is a pure function of the member keys in flush order, and
    moving the INSERT into a task moved neither. Same fixture as B2b."""
    seen: list[tuple[str, list, str]] = []

    async def sink(table, rows, token, ctx):
        seen.append((table, list(rows), token))
        return True

    async def go():
        b = RowBatcher(insert=sink, default=(2, 1 << 30, 1e9))
        await b.add(EDGES, [{"r": 1}], member=_member("obj:a:v1:open:aa"),
                    dedup_token="obj:a:v1:open:aa:edges:0")
        await b.add(EDGES, [{"r": 2}], member=_member("obj:b:v1:open:bb"),
                    dedup_token="obj:b:v1:open:bb:edges:0")
        await b.quiesce()

    asyncio.run(go())
    assert len(seen) == 1
    assert seen[0][1] == [{"r": 1}, {"r": 2}]
    assert seen[0][2] == batch_token(["obj:a:v1:open:aa:edges:0",
                                      "obj:b:v1:open:bb:edges:0"])


def test_B14e_a_stalled_evidence_block_does_not_stall_the_queue_put(_stack):
    """The end-to-end shape of B14, on the live wiring: with `corr_edges` hung,
    the Decision plane's `put` into the Evidence queue still returns promptly.
    That is the property the 116 s flush destroyed — `persist.backpressure_wait`
    is supposed to measure a FULL QUEUE, never a slow INSERT."""
    ch = _RecCH()
    ch.slow_tables[EDGES] = 30.0            # a block that never comes back
    _stack.setattr(main, "ch", ch)
    _stack.setattr(main, "OPEN_OBJECTS", {})
    _stack.setattr(main, "CORR_EVIDENCE_ASYNC", True)
    _stack.setattr(main, "CORR_EVIDENCE_BATCH", True)
    _stack.setattr(main, "CORR_EVIDENCE_BATCH_ITEMS", 1)
    snap, window = _storm_fixture(nodes=2, edges=4, ambient=10)

    async def go():
        _reset_engine_state()
        main._WINDOW_INDEX_CACHE.clear()
        main._ARCHIVE_SLICE_HASH.clear()
        assert main._evidence_ensure_consumer() is not None
        t0 = time.monotonic()
        for v in range(1, 4):
            await asyncio.wait_for(
                main._persist_snapshot(snap, v, "open", window), timeout=5.0)
        elapsed = time.monotonic() - t0
        # Let the consumer drain what it can while corr_edges is hung.
        await asyncio.sleep(0.2)
        got = {t for t, _rows, _tok in ch.writes}
        with contextlib.suppress(asyncio.TimeoutError):
            await asyncio.wait_for(main._evidence_stop(), timeout=1.0)
        return elapsed, got

    elapsed, got = asyncio.run(go())
    assert elapsed < 3.0, (
        f"the Decision writes waited {elapsed:.1f}s on a hung Evidence INSERT")
    assert "netops.corr_objects" in got and EDGES in got
    assert ARCHIVE in got or EVIDENCE in got, (
        f"a hung {EDGES} block stopped every other Evidence table: {sorted(got)}")


# ═══ B15 — the CYCLE COLLECTOR, the second residual ══════════════════════════
#
# B12 disables the collector inside its measured window on purpose: a gen-2
# sweep runs on whichever thread trips the threshold, holds the GIL for its
# whole duration and is sized by the PROCESS heap, so leaving it on would make
# that test measure the heap the rest of the suite happens to hold. This is the
# test for the collector itself — the flag ON, the collector ENABLED, and a
# retained heap standing in for the 15-25k open objects the live replica holds.

@pytest.fixture
def _gc_restore():
    """Every global this touches, put back — a leaked `gc.freeze()` or a raised
    threshold would silently change every test that runs after it."""
    thresholds = gc.get_threshold()
    enabled = gc.isenabled()
    tuned, frozen = main._GC_TUNED, main.GC_FROZEN_OBJECTS
    pause_max, pause_total = main.GC_PAUSE_MAX_S, main.GC_PAUSE_TOTAL_S
    counts = list(main.GC_COLLECTIONS)
    yield
    gc.unfreeze()
    gc.set_threshold(*thresholds)
    (gc.enable if enabled else gc.disable)()
    main._GC_TUNED, main.GC_FROZEN_OBJECTS = tuned, frozen
    main.GC_PAUSE_MAX_S, main.GC_PAUSE_TOTAL_S = pause_max, pause_total
    main.GC_COLLECTIONS[:] = counts
    if main._gc_probe in gc.callbacks:
        gc.callbacks.remove(main._gc_probe)


def _gc_leg(_stack, snap, window, *, tune: bool, ballast: list) -> tuple[float, list]:
    """One persist+drain of the aggregate with the collector ENABLED."""
    assert ballast, "the heap the collector has to walk must actually exist"
    _aggregate_stack(_stack, batch=True)
    _stack.setattr(main, "CORR_LOOP_LAG_SAMPLE_S", 0.02)
    _stack.setattr(main, "CORR_LOOP_LAG_WARN_MS", _LOOP_BUDGET_MS)
    _stack.setattr(main, "CORR_GC_TUNE", tune)
    for attr in ("_content_hash_c", "_material_hash_c"):
        with contextlib.suppress(AttributeError):
            object.__delattr__(snap, attr)
    # Both legs start from a fully collected, promoted heap so the A/B measures
    # the RUN and not whoever paid for the first full sweep.
    gc.set_threshold(700, 10, 10)
    gc.unfreeze()
    gc.enable()
    gc.collect()
    main._GC_TUNED = False
    main.gc_tune_startup()
    main.GC_PAUSE_MAX_S = 0.0
    main.GC_COLLECTIONS[:] = [0, 0, 0]
    assert gc.isenabled(), "the policy must NEVER disable the collector"

    async def go():
        async def work():
            await _persist_and_drain(snap, window)
        return await _watchdog_lag_while(work)

    return asyncio.run(go()), list(main.GC_COLLECTIONS)


def test_B15_the_aggregate_stays_inside_the_budget_with_the_collector_on(
        _stack, storm_aggregate, _gc_restore):
    """The §4 budget, with the collector RUNNING and a heap for it to walk.

    MEASURED on this fixture with a 3,000,000-object retained heap (harness
    `measure_gc.py`, two reps each): worst loop-lag sample 128 / 145 ms with
    the policy off and 107 / 168 ms with it on, `corr_gc_pause_seconds_max`
    29-31 ms off and 43-45 ms on. Both inside the budget — the multi-second
    collector stall that motivated this policy does not survive the sizing fix
    plus a settled heap. What the policy is worth is stated by B15c."""
    snap, window = storm_aggregate
    ballast = [{"a": i, "b": str(i)} for i in range(300_000)]
    lag, _counts = _gc_leg(_stack, snap, window, tune=True, ballast=ballast)
    assert gc.isenabled()
    assert lag < _LOOP_BUDGET_MS, (
        f"the aggregate held the loop for {lag:.0f} ms with the collector on "
        f"(gc pause max {main.GC_PAUSE_MAX_S * 1000:.0f} ms) — read those two "
        f"together: a stall with a matching gc pause is the heap, one without "
        f"is our code")
    del ballast


def test_B15b_the_policy_cuts_the_collection_count_without_disabling_anything(
        _stack, storm_aggregate, _gc_restore):
    """What the tuning actually buys, measured rather than asserted by faith:
    the same work, an order of magnitude fewer collections, and the collector
    still enabled. Harness numbers over 3 persists on a 3M-object heap:
    1,113-1,226 gen-0 + 101-111 gen-1 collections and 1,010-1,112 ms total in
    the collector, against 39-40 gen-0 / 0 gen-1 and 709-755 ms with the
    policy on."""
    snap, window = storm_aggregate
    ballast = [{"a": i, "b": str(i)} for i in range(300_000)]
    _lag_off, off = _gc_leg(_stack, snap, window, tune=False, ballast=ballast)
    _lag_on, on = _gc_leg(_stack, snap, window, tune=True, ballast=ballast)
    assert gc.isenabled(), "never disabled, on either leg"
    assert off[0] >= 50, f"the untuned leg must actually collect ({off})"
    assert on[0] * 5 <= off[0], (
        f"the policy cut gen-0 collections from {off[0]} to {on[0]} — under the "
        f"order of magnitude the measured thresholds give")
    assert on[1] <= off[1] and on[2] <= off[2]
    del ballast


def test_B15c_the_flag_off_leaves_the_collector_exactly_as_it_found_it(_gc_restore):
    """`CORR_GC_TUNE=0` must touch nothing — no freeze, no thresholds — while
    the PROBE stays installed, because 'is the collector the stall?' is the
    question and a flag that hides the answer when it is off makes the A/B
    unreadable."""
    gc.set_threshold(700, 10, 10)
    gc.unfreeze()
    main._GC_TUNED = False
    main.CORR_GC_TUNE = False
    main.gc_tune_startup()
    assert gc.get_threshold() == (700, 10, 10), "the flag-off leg tuned anyway"
    assert gc.get_freeze_count() == 0, "the flag-off leg froze anyway"
    assert main._GC_TUNED is False
    assert main._gc_probe in gc.callbacks, "the measurement is not flag-gated"

    main.CORR_GC_TUNE = True
    main.gc_tune_startup()
    assert gc.get_threshold() == (main.CORR_GC_GEN0, main.CORR_GC_GEN1,
                                  main.CORR_GC_GEN2)
    assert gc.get_freeze_count() > 0 and main._GC_TUNED is True
    assert gc.isenabled(), "the policy must NEVER disable the collector"
    # Idempotent: a second call must not re-freeze or re-walk.
    before = gc.get_freeze_count()
    main.gc_tune_startup()
    assert gc.get_freeze_count() == before


def test_B15d_the_gc_metrics_are_exposed(_gc_restore):
    """§10: the residual stall has to be ATTRIBUTABLE on the next run, which
    means the pause is a series next to `corr_loop_lag_max_ms`."""
    main._GC_TUNED = False
    main.CORR_GC_TUNE = True
    main.gc_tune_startup()
    gc.collect()                      # at least one timed collection
    body = asyncio.run(main.metrics_exposition()).body.decode()
    for series in ('corr_gc_collections_total{generation="0"}',
                   'corr_gc_collections_total{generation="1"}',
                   'corr_gc_collections_total{generation="2"}',
                   "corr_gc_pause_seconds_max",
                   "corr_gc_pause_seconds_total",
                   "corr_gc_frozen_objects",
                   "corr_gc_tuned"):
        assert series in body, f"{series} is not exposed"
    assert "corr_loop_lag_max_ms" in body, "the gauge it explains must be there too"
    st = main.gc_stats()
    assert st["enabled"] is True and st["tuned"] is True
    assert st["collections"][2] >= 1 and st["pause_seconds_max"] > 0
    assert list(st["thresholds"]) == [main.CORR_GC_GEN0, main.CORR_GC_GEN1,
                                      main.CORR_GC_GEN2]
