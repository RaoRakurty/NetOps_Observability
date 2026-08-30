"""Tracker 166 secondary defect — one slow ClickHouse insert must not discard a
whole cohort.

THE DEFECT. `_persist_snapshot` writes ~8 rows-sets per RCA object through
`ch_insert`, which had NO retry of any kind: the first non-committed outcome on
an RCA-critical table raised `CHInsertRejected`, which propagates out of
`engine_cycle` before `_mark_processed`. Tracker 160's durability contract then
does exactly what it promises — the cohort stays pending and is retried WHOLE.

That is correct per-object behaviour and catastrophic per-cohort behaviour once
tracker 168 corrected the identity model: with `k` objects in a cohort,
`P(cohort commits) = (1 - p)^k`. At ~1,000 objects even a tiny `p` makes the
frontier immovable, which is the measured "pending completely FLAT for all
2,160 s" in `docs/scale/ARCHIVE_PERSISTENCE_BOTTLENECK_2026-08-22.md`.

`p` was NOT tiny. The httpx client timeout was hard-coded to 10.0 s while a
measured `corr_objects` insert took 14,395 ms server-side, so the client hung up
on inserts ClickHouse was still committing and reported the UNKNOWN outcome as a
refusal.

THE FIX, and what these tests pin:
  * `ch_insert` now honours the same tracker-160 delivery contract the batcher
    already had — bounded retries, exponential backoff + full jitter, re-sent
    under the SAME dedup token;
  * a retry is attempted ONLY where re-sending provably cannot duplicate a row
    (`CH_DEDUP_SAFE_TABLES` — each entry backed by its DDL in init.sql);
  * a transport failure is reported as `transport`, not miscounted `rejected`;
  * the client timeout is configurable and no longer shorter than a measured
    commit.

Every guard below has a mutation test: disabling the retry must turn it red.
"""
from __future__ import annotations

import asyncio

import pytest

import main


def run(coro):
    return asyncio.run(coro)


# ── sinks ────────────────────────────────────────────────────────────────────

class ScriptedCH:
    """A detailed sink that replays a scripted list of outcomes, recording every
    attempt so retry COUNT and token STABILITY are both observable."""

    def __init__(self, outcomes=()):
        self.outcomes = list(outcomes)
        self.calls: list[dict] = []

    async def insert_detailed(self, table, rows, dedup_token=""):
        self.calls.append({"table": table, "rows": list(rows), "token": dedup_token})
        if self.outcomes:
            return self.outcomes.pop(0)
        return main.InsertOutcome(committed=True, kind="committed", rows=len(rows))

    def attempts(self, table):
        return [c for c in self.calls if c["table"] == table]


def _ok(rows=1):
    return main.InsertOutcome(committed=True, kind="committed", rows=rows)


def _transport():
    return main.InsertOutcome(committed=False, kind="transport",
                              error="ReadTimeout", rows=1)


def _rejected(code):
    return main.InsertOutcome(committed=False, kind="rejected", status=500,
                              ch_code=code, query_id="q-1", rows=1)


SAFE = "netops.corr_objects"          # dedup window in init.sql
UNSAFE = "netops.corr_signals"        # critical, but plain MergeTree, no window
ARCHIVE = "netops.corr_signals_archive"   # not critical, not dedup-safe


@pytest.fixture(autouse=True)
def _isolated(monkeypatch):
    """No real sleeping, and counters/rate-limiters start clean."""
    monkeypatch.setattr(main, "CORR_CH_RETRY_BASE_S", 0.0)
    monkeypatch.setattr(main, "CORR_CH_RETRY_MAX_S", 0.0)
    monkeypatch.setattr(main, "CH_RETRIES_ATTEMPTED", 0)
    monkeypatch.setattr(main, "CH_RETRIES_RECOVERED", 0)
    monkeypatch.setattr(main, "CH_RETRIES_EXHAUSTED", 0)
    main.CH_INSERT_FAILURES.clear()
    main._CH_FAIL_LOG_LAST.clear()
    yield
    main.CH_INSERT_FAILURES.clear()
    main._CH_FAIL_LOG_LAST.clear()


def _row(i=1):
    return {"signal_id": f"sig-{i}", "tenant_id": "acme"}


# ── the fix: a transient failure is survived, not escalated ──────────────────

def test_a_read_timeout_is_retried_and_recovers(monkeypatch):
    """THE defect. One ReadTimeout used to raise CHInsertRejected straight out
    of _persist_snapshot; it must now be retried and commit."""
    ch = ScriptedCH([_transport(), _ok()])
    monkeypatch.setattr(main, "ch", ch)
    assert run(main.ch_insert(SAFE, [_row()], dedup_token="obj:c1:v1:open:abcd")) is True
    assert len(ch.attempts(SAFE)) == 2, "the timeout was not retried"
    assert main.CH_RETRIES_RECOVERED == 1


def test_the_retry_reuses_the_same_dedup_token(monkeypatch):
    """The retry is only safe because ClickHouse dedups the re-sent block. A
    fresh token per attempt would duplicate the causal row instead."""
    ch = ScriptedCH([_transport(), _transport(), _ok()])
    monkeypatch.setattr(main, "ch", ch)
    run(main.ch_insert(SAFE, [_row()], dedup_token="obj:c1:v1:open:abcd"))
    tokens = {c["token"] for c in ch.attempts(SAFE)}
    assert tokens == {"obj:c1:v1:open:abcd"}, f"token drifted across retries: {tokens}"


def test_retries_are_bounded_then_it_still_raises(monkeypatch):
    """Bounded, per §9. Exhausting the budget must NOT silently succeed — the
    tracker 160 boundary still holds and the cohort still stays pending."""
    monkeypatch.setattr(main, "CORR_CH_RETRY_ATTEMPTS", 3)
    ch = ScriptedCH([_transport()] * 10)
    monkeypatch.setattr(main, "ch", ch)
    with pytest.raises(main.CHInsertRejected):
        run(main.ch_insert(SAFE, [_row()], dedup_token="obj:c1:v1:open:abcd"))
    assert len(ch.attempts(SAFE)) == 3, "retry budget not honoured"
    assert main.CH_RETRIES_EXHAUSTED == 1


def test_a_permanent_rejection_is_not_retried(monkeypatch):
    """Retrying a schema/parse error cannot succeed and only delays the loss
    while the backlog grows — code 60 (UNKNOWN_TABLE) is not in the allowlist."""
    ch = ScriptedCH([_rejected(60), _ok()])
    monkeypatch.setattr(main, "ch", ch)
    with pytest.raises(main.CHInsertRejected):
        run(main.ch_insert(SAFE, [_row()], dedup_token="obj:c1:v1:open:abcd"))
    assert len(ch.attempts(SAFE)) == 1
    assert main.CH_RETRIES_ATTEMPTED == 0


def test_a_retryable_server_code_is_retried(monkeypatch):
    """241 MEMORY_LIMIT_EXCEEDED — the code measured live on 2026-08-19."""
    ch = ScriptedCH([_rejected(241), _ok()])
    monkeypatch.setattr(main, "ch", ch)
    assert run(main.ch_insert(SAFE, [_row()], dedup_token="t")) is True
    assert len(ch.attempts(SAFE)) == 2


# ── the safety bound: never retry where a retry could duplicate ──────────────

def test_a_table_without_a_dedup_guarantee_is_never_retried(monkeypatch):
    """corr_signals is RCA-critical but plain MergeTree with no dedup window, so
    a re-sent block would DUPLICATE a causal row. It must fail on attempt one."""
    ch = ScriptedCH([_transport(), _ok()])
    monkeypatch.setattr(main, "ch", ch)
    with pytest.raises(main.CHInsertRejected):
        run(main.ch_insert(UNSAFE, [_row()], dedup_token="whatever"))
    assert len(ch.attempts(UNSAFE)) == 1, "retried an insert that can duplicate"
    assert main.CH_RETRIES_EXHAUSTED == 0, "an un-retryable insert is not 'exhausted'"


def test_the_archive_is_not_retried_and_does_not_raise(monkeypatch):
    """The archive is not RCA-critical: it returns False (the caller's `all_ok`
    retries the slice whole on the next persist) and is not dedup-safe, so it
    must neither retry nor escalate."""
    ch = ScriptedCH([_transport(), _ok()])
    monkeypatch.setattr(main, "ch", ch)
    assert run(main.ch_insert(ARCHIVE, [_row()])) is False
    assert len(ch.attempts(ARCHIVE)) == 1


def test_no_token_means_no_retry(monkeypatch):
    """A retry without a stable token cannot dedup server-side, so it is not a
    retry — it is a second row."""
    ch = ScriptedCH([_transport(), _ok()])
    monkeypatch.setattr(main, "ch", ch)
    with pytest.raises(main.CHInsertRejected):
        run(main.ch_insert(SAFE, [_row()], dedup_token=""))
    assert len(ch.attempts(SAFE)) == 1


def test_every_dedup_safe_table_is_rca_critical_or_replacing():
    """The set is a claim about DDL. Keep it honest: nothing may be added
    without the guarantee.

    netops.findings joined on 2026-08-29 and is the one member that is NOT
    RCA-critical: it carries the same non_replicated_deduplication_window (see
    tests/test_clickhouse_corr_storage.py, which asserts the DDL) and every
    insert carries finding_dedup_token, so the DDL claim holds — but a
    non-committing findings write must not raise CHInsertRejected, because
    nothing upstream can replay it. It is durably spooled instead
    (CH_DLQ_ON_LOSS_TABLES); see test_findings_dedup_retry.py.
    """
    assert main.CH_DEDUP_SAFE_TABLES <= (
        main.CH_CRITICAL_TABLES | {"netops.corr_current", "netops.findings"})
    assert "netops.corr_signals" not in main.CH_DEDUP_SAFE_TABLES
    assert "netops.corr_signals_archive" not in main.CH_DEDUP_SAFE_TABLES
    # A dedup-safe table that is neither RCA-critical nor a ReplacingMergeTree
    # has no upstream replay, so it MUST have a durable fallback.
    for t in main.CH_DEDUP_SAFE_TABLES - main.CH_CRITICAL_TABLES - {"netops.corr_current"}:
        assert t in main.CH_DLQ_ON_LOSS_TABLES, (
            f"{t} can neither raise nor be replayed — it needs a DLQ fallback")


# ── the outcome is reported truthfully ───────────────────────────────────────

def test_a_transport_failure_is_counted_as_transport_not_rejected(monkeypatch):
    """"Rejected" and "timed out" want different operator responses; the old
    code hard-coded the former for both."""
    seen: list[str] = []
    monkeypatch.setattr(main, "_note_ch_failure",
                        lambda table, reason, ctx: seen.append(reason))
    monkeypatch.setattr(main, "CORR_CH_RETRY_ATTEMPTS", 1)
    monkeypatch.setattr(main, "ch", ScriptedCH([_transport()]))
    with pytest.raises(main.CHInsertRejected):
        run(main.ch_insert(SAFE, [_row()], dedup_token="t"))
    assert seen == ["transport"], f"failure kind misreported as {seen}"


def test_the_failure_note_carries_the_clickhouse_evidence(monkeypatch):
    """A dead write must say WHY — code and query id — not be an
    unclassifiable blob (§10: no silent failures)."""
    seen: list[dict] = []
    monkeypatch.setattr(main, "_note_ch_failure",
                        lambda table, reason, ctx: seen.append(ctx))
    monkeypatch.setattr(main, "CORR_CH_RETRY_ATTEMPTS", 1)
    monkeypatch.setattr(main, "ch", ScriptedCH([_rejected(241)]))
    with pytest.raises(main.CHInsertRejected):
        run(main.ch_insert(SAFE, [_row()], dedup_token="t", corr_id="c1"))
    assert seen[0]["ch_code"] == 241
    assert seen[0]["query_id"] == "q-1"
    assert seen[0]["corr_id"] == "c1", "caller context must survive"


def test_the_client_timeout_is_not_shorter_than_a_measured_commit():
    """A 10.0 s timeout against a measured 14,395 ms commit is a guaranteed
    false 'failure'. Pin the floor, not the exact value."""
    assert main.CORR_CH_TIMEOUT_S >= 15.0


# ── mutation: the retry must be load-bearing ─────────────────────────────────

def test_mutation_without_retry_the_timeout_escalates(monkeypatch):
    """The guard proof. Set the retry budget to 1 — the pre-fix behaviour — and
    the very first test's scenario must go red again. A retry that cannot change
    an outcome is not a retry."""
    monkeypatch.setattr(main, "CORR_CH_RETRY_ATTEMPTS", 1)
    ch = ScriptedCH([_transport(), _ok()])
    monkeypatch.setattr(main, "ch", ch)
    with pytest.raises(main.CHInsertRejected):
        run(main.ch_insert(SAFE, [_row()], dedup_token="obj:c1:v1:open:abcd"))
    assert len(ch.attempts(SAFE)) == 1


# ── the cohort-level consequence, end to end ─────────────────────────────────

def _load_object_forming_window():
    """A window that actually produces RCA objects, so `_persist_snapshot` runs
    for real. Borrowed from the archive-slice fixture rather than re-derived —
    a cohort test whose cohort persists nothing proves nothing."""
    import test_archive_slice as tas
    window, _parts = tas._window()
    for s in window:
        main.WINDOW_BUFFER.append(s)
        main._BUFFERED_ID_ORDER.append(str(s.signal_id))
        main._BUFFERED_IDS.add(str(s.signal_id))
    return window


@pytest.fixture
def _engine_state(monkeypatch):
    main.WINDOW_BUFFER.clear(); main._BUFFERED_IDS.clear()
    main._BUFFERED_ID_ORDER.clear(); main._PROCESSED_IDS.clear()
    main.TENANT_WATERMARK.clear(); main._TENANT_EDGES.clear()
    main._ARCHIVE_SLICE_HASH.clear()
    monkeypatch.setattr(main, "OPEN_OBJECTS", {})
    monkeypatch.setattr(main, "COHORTS_PROCESSED", 0)
    yield
    main.WINDOW_BUFFER.clear(); main._BUFFERED_IDS.clear()
    main._BUFFERED_ID_ORDER.clear(); main._PROCESSED_IDS.clear()
    main._TENANT_EDGES.clear(); main._ARCHIVE_SLICE_HASH.clear()


class FlakyOnceCH(ScriptedCH):
    """Commits everything except the FIRST insert to `table`, which times out."""

    def __init__(self, table):
        super().__init__()
        self.flaky_table = table
        self.tripped = False

    async def insert_detailed(self, table, rows, dedup_token=""):
        rows = list(rows)
        self.calls.append({"table": table, "rows": rows, "token": dedup_token})
        if table == self.flaky_table and not self.tripped:
            self.tripped = True
            return _transport()
        return _ok(len(rows))


def test_one_slow_insert_no_longer_discards_the_whole_cohort(monkeypatch, _engine_state):
    """P(cohort commits) = (1 - p)^objects was the shape of the bug: ONE timed-out
    object insert took the entire cohort's frontier advance with it, which is why
    live pending sat FLAT at 129,220 for the whole 2,160 s budget."""
    _load_object_forming_window()
    pending_before = len(main.pending_signals())
    assert pending_before > 0
    ch = FlakyOnceCH("netops.corr_objects")
    monkeypatch.setattr(main, "ch", ch)

    run(main.engine_cycle())

    assert ch.tripped, "the flaky sink never fired — the test proves nothing"
    assert main.COHORTS_PROCESSED == 1, "the cohort did not complete"
    assert main.pending_signals() == [], (
        "a single transient ClickHouse timeout still discarded the cohort")


def test_mutation_without_retry_the_cohort_is_lost(monkeypatch, _engine_state):
    """Pre-fix behaviour, pinned: with the retry budget at 1 the same single
    timeout must again strand every signal in the cohort. If this passes with
    retries enabled, the retry is decorative."""
    monkeypatch.setattr(main, "CORR_CH_RETRY_ATTEMPTS", 1)
    _load_object_forming_window()
    pending_before = len(main.pending_signals())
    monkeypatch.setattr(main, "ch", FlakyOnceCH("netops.corr_objects"))

    with pytest.raises(main.CHInsertRejected):
        run(main.engine_cycle())

    assert main.COHORTS_PROCESSED == 0
    assert len(main.pending_signals()) == pending_before, (
        "tracker 160's durability boundary must still strand a truly failed cohort")


def test_the_retry_budget_can_never_be_zero(monkeypatch):
    """A budget of 0 must still make one ATTEMPT. Zero would mean "never insert
    at all", not "never retry", and would leave the loop with no outcome to act
    on — a latent AttributeError under `python -O`, where the assert that
    documents the invariant is stripped."""
    monkeypatch.setattr(main, "CORR_CH_RETRY_ATTEMPTS", 0)
    ch = ScriptedCH([_ok()])
    monkeypatch.setattr(main, "ch", ch)
    assert run(main.ch_insert(SAFE, [_row()], dedup_token="t")) is True
    assert len(ch.attempts(SAFE)) == 1, "a zero budget skipped the insert entirely"


def test_the_env_read_clamps_too():
    """Belt and braces: the module-level budget is never below one."""
    assert main.CORR_CH_RETRY_ATTEMPTS >= 1


# ── definite-rejection retries on NON-dedup-safe tables (2026-08-24) ─────────
# Live one-off during the post-deploy T-nominal gate: a 7-row
# corr_signals_archive slice was lost to a transient ClickHouse code-241
# memory rejection. The archive's retry exclusion protects against UNKNOWN
# outcomes (transport — the server may have committed); a DEFINITE rejection
# with a CH error code did not commit (single-block inserts are atomic), so
# one retry recovers it with no duplication risk.

def test_archive_definite_rejection_retries_and_recovers(monkeypatch):
    sink = ScriptedCH([_rejected(241), _ok()])
    monkeypatch.setattr(main, "ch", sink)
    monkeypatch.setattr(main, "CORR_CH_RETRY_ATTEMPTS", 3)
    monkeypatch.setattr(main, "ch_retry_delay", lambda a, rnd=None: 0.0)
    ok = run(main.ch_insert("netops.corr_signals_archive", [{"r": 1}]))
    assert ok is True
    assert len(sink.attempts("netops.corr_signals_archive")) == 2


def test_archive_transport_failure_still_never_retries(monkeypatch):
    """The duplication guard stands: an UNKNOWN outcome on a non-dedup-safe
    table must not be re-sent — the original exclusion, still load-bearing."""
    sink = ScriptedCH([_transport(), _ok()])
    monkeypatch.setattr(main, "ch", sink)
    monkeypatch.setattr(main, "CORR_CH_RETRY_ATTEMPTS", 3)
    monkeypatch.setattr(main, "ch_retry_delay", lambda a, rnd=None: 0.0)
    ok = run(main.ch_insert("netops.corr_signals_archive", [{"r": 1}]))
    assert ok is False
    assert len(sink.attempts("netops.corr_signals_archive")) == 1


def test_rejection_without_a_ch_code_stays_permanent(monkeypatch):
    """A bare False from a bool-only sink (no code) proves nothing about
    whether the server committed — it must not be retried on an unsafe table."""
    outcome = main.InsertOutcome(committed=False, kind="rejected", rows=1)
    sink = ScriptedCH([outcome, _ok()])
    monkeypatch.setattr(main, "ch", sink)
    monkeypatch.setattr(main, "CORR_CH_RETRY_ATTEMPTS", 3)
    monkeypatch.setattr(main, "ch_retry_delay", lambda a, rnd=None: 0.0)
    ok = run(main.ch_insert("netops.corr_signals_archive", [{"r": 1}]))
    assert ok is False
    assert len(sink.attempts("netops.corr_signals_archive")) == 1


def test_mutation_reverting_to_idempotent_only_loses_the_archive_slice(monkeypatch):
    """Both-direction proof: force the OLD gate (idempotent-only) and the
    definite-rejection recovery disappears — the new lane is load-bearing."""
    sink = ScriptedCH([_rejected(241), _ok()])
    monkeypatch.setattr(main, "ch", sink)
    monkeypatch.setattr(main, "CORR_CH_RETRY_ATTEMPTS", 3)
    monkeypatch.setattr(main, "ch_retry_delay", lambda a, rnd=None: 0.0)
    monkeypatch.setattr(main, "CH_RETRYABLE_CODES", frozenset())  # kills code-based retry
    ok = run(main.ch_insert("netops.corr_signals_archive", [{"r": 1}]))
    assert ok is False
    assert len(sink.attempts("netops.corr_signals_archive")) == 1
