"""netops.findings joins the tracker-166 delivery contract (storm-s03, 2026-08-29).

THE DEFECT. At 22:17:43 UTC on replica-3 of storm-s03 a single findings insert
ended in an UNKNOWN outcome::

    clickhouse insert transport failure table=netops.findings err=ReadError
    clickhouse write LOST table=netops.findings reason=transport lost_total=1 ...

and the ladder's accounting phase failed on
``correlation ClickHouse insert failures: {'netops.findings': 1}``.

"transport" means the server may well have committed — the client simply never
heard. Tracker 166 already retries exactly that class, but ONLY for tables in
``CH_DEDUP_SAFE_TABLES``, and findings was not one: it had no dedup window and
its inserts carried no token, so a re-send could have appended a second row.
The write was therefore counted lost rather than retried — and, findings being
neither RCA-critical (nothing raises, so the consumer never quarantines the
event) nor reconstructable (``emit`` has already reset the z-score sample /
syslog bucket that produced it), "lost" meant *gone*, with no durable copy.

THE FIX, and what this file pins:

  * ``finding_dedup_token`` — a deterministic token (source message coordinate
    + row content hash) so a re-sent block is dropped server-side;
  * the finding ``id`` derived from that token, so one finding has one id no
    matter how many times it is written;
  * ``netops.findings`` in ``CH_DEDUP_SAFE_TABLES``, so bounded backoff+jitter
    retries apply (§9);
  * ``CH_DLQ_ON_LOSS_TABLES`` — when the retries are finally exhausted the row
    is spooled to CORR_DLQ_DIR under an explicit reason and counted there, and
    ``lost_total`` is reserved for rows that have no durable copy at all (§10).

Each guard has its mutation: removing the token, or the table from the safe
set, or the DLQ fallback, must turn one of these red.
"""
from __future__ import annotations

import asyncio
import json

import pytest

import main

FINDINGS = "netops.findings"


def run(coro):
    return asyncio.run(coro)


class ScriptedCH:
    """Replays scripted outcomes and records every attempt (token + rows)."""

    def __init__(self, outcomes=()):
        self.outcomes = list(outcomes)
        self.calls: list[dict] = []

    async def insert_detailed(self, table, rows, dedup_token=""):
        self.calls.append({"table": table, "rows": [dict(r) for r in rows],
                           "token": dedup_token})
        if self.outcomes:
            return self.outcomes.pop(0)
        return main.InsertOutcome(committed=True, kind="committed", rows=len(rows))


class ServerSideDedup(ScriptedCH):
    """A sink that behaves like ClickHouse with a dedup window: a block whose
    insert_deduplication_token it has already COMMITTED is dropped."""

    def __init__(self, outcomes=()):
        super().__init__(outcomes)
        self.committed_tokens: set[str] = set()
        self.stored: list[dict] = []

    async def insert_detailed(self, table, rows, dedup_token=""):
        out = await super().insert_detailed(table, rows, dedup_token)
        if out.committed:
            if dedup_token and dedup_token in self.committed_tokens:
                return out            # deduped: nothing stored
            if dedup_token:
                self.committed_tokens.add(dedup_token)
            self.stored.extend(dict(r) for r in rows)
        return out


def _ok(rows=1):
    return main.InsertOutcome(committed=True, kind="committed", rows=rows)


def _read_error():
    """The exact live outcome: kind=transport, status=0, ch_code=0."""
    return main.InsertOutcome(committed=False, kind="transport", status=0,
                              ch_code=0, error="ReadError", rows=1, nbytes=363)


@pytest.fixture(autouse=True)
def _isolated(monkeypatch, tmp_path):
    monkeypatch.setattr(main, "CORR_CH_RETRY_BASE_S", 0.0)
    monkeypatch.setattr(main, "CORR_CH_RETRY_MAX_S", 0.0)
    monkeypatch.setattr(main, "CORR_CH_RETRY_ATTEMPTS", 4)
    monkeypatch.setattr(main, "CH_RETRIES_EXHAUSTED", 0)
    monkeypatch.setattr(main, "CORR_DLQ_DIR", str(tmp_path))
    monkeypatch.setattr(main, "QUARANTINE_WRITE_FAILURES", 0)
    main.CH_INSERT_FAILURES.clear()
    main.CH_ROWS_DLQ_SPOOLED.clear()
    main._CH_FAIL_LOG_LAST.clear()
    main.set_dedup_coord("metrics", 3, 4242)
    yield
    main.CH_INSERT_FAILURES.clear()
    main.CH_ROWS_DLQ_SPOOLED.clear()
    main._CH_FAIL_LOG_LAST.clear()


def _finding(**over):
    row = {"kind": "anomaly", "severity": "warning", "score": 6.5,
           "device": "mlx-08292148kdz4-01681", "component": "ifInErrors",
           "summary": "ifInErrors on eth0 z=6.5", "description": "d",
           "labels": {"metric": "ifInErrors"}, "tenant_id": "acme"}
    row.update(over)
    return row


def _dlq_lines(tmp_path) -> list[dict]:
    path = tmp_path / "corr-deadletter.ndjson"
    if not path.exists():
        return []
    return [json.loads(ln) for ln in path.read_text().splitlines() if ln.strip()]


# ── the token ────────────────────────────────────────────────────────────────

def test_the_token_is_deterministic_for_the_same_message_and_row():
    """Re-running the same handler on a redelivered message must produce the
    SAME token — that is the only thing that lets ClickHouse recognise the
    re-send. Nothing random (uuid4, time, id()) may enter it."""
    row = _finding()
    main.set_dedup_coord("metrics", 3, 4242)
    first = main.finding_dedup_token(row)
    main.set_dedup_coord("metrics", 3, 4242)
    second = main.finding_dedup_token(row)
    assert first == second, "the token is not reproducible across a redelivery"
    assert first.startswith("finding:metrics:3:4242:")


def test_the_token_separates_different_messages_and_different_content():
    """Unique per logical insert, or a legitimately new finding is silently
    swallowed as a 'duplicate'."""
    row = _finding()
    main.set_dedup_coord("metrics", 3, 4242)
    a = main.finding_dedup_token(row)
    main.set_dedup_coord("metrics", 3, 4243)      # next message
    b = main.finding_dedup_token(row)
    main.set_dedup_coord("metrics", 3, 4242)
    c = main.finding_dedup_token(_finding(score=9.1, summary="z=9.1"))
    main.set_dedup_coord("metrics", 3, 4242)
    d = main.finding_dedup_token(_finding(tenant_id="globex"))
    assert len({a, b, c, d}) == 4, "distinct findings collided on one token"


def test_a_second_finding_from_one_message_gets_its_own_token():
    """The per-message sequence disambiguates them; without it the second
    finding would be dropped by the server as a duplicate of the first."""
    main.set_dedup_coord("syslog", 0, 7)
    first = main.finding_dedup_token(_finding())
    second = main.finding_dedup_token(_finding())
    assert first != second


def test_the_token_is_still_unique_without_a_consumer_coordinate(monkeypatch):
    """Outside a consumer message there is no redelivery to be idempotent
    against, but two findings must still never share a token."""
    monkeypatch.setattr(main, "_dedup_coord", "")
    a = main.finding_dedup_token(_finding())
    b = main.finding_dedup_token(_finding())
    assert a != b and a.startswith("finding:local:")


def test_the_id_is_derived_from_the_token_not_random(monkeypatch):
    """One finding, one id — however many times it is written. The UI keys its
    rows on `id` (Findings.tsx rowKey) and the reports COUNT them."""
    ch = ScriptedCH()
    monkeypatch.setattr(main, "ch", ch)
    monkeypatch.setattr(main, "tenant_for", lambda d: "acme")
    for _ in range(2):
        main.set_dedup_coord("metrics", 3, 4242)
        run(main.emit(kind="anomaly", severity="warning", score=6.5,
                      device="mlx-1", component="ifInErrors", summary="s",
                      description="d", labels={}, tenant_id="acme"))
    ids = [c["rows"][0]["id"] for c in ch.calls]
    assert ids[0] == ids[1], "a redelivery minted a second id for one finding"
    assert ids[0] == str(main.uuid.uuid5(main.FINDING_ID_NS, ch.calls[0]["token"]))


# ── the fix: an ambiguous ReadError is retried, and cannot duplicate ─────────

def test_a_read_error_is_retried_and_recovers(monkeypatch):
    """THE storm-s03 defect: one ReadError was counted LOST with no retry."""
    ch = ScriptedCH([_read_error(), _ok()])
    monkeypatch.setattr(main, "ch", ch)
    assert run(main.ch_insert(FINDINGS, [_finding()], dedup_token="finding:t")) is True
    assert len(ch.calls) == 2, "the ambiguous transport outcome was not retried"
    assert main.CH_INSERT_FAILURES == {}, "a recovered write is not a lost write"


def test_the_retry_reuses_the_token_so_one_row_lands(monkeypatch):
    """The retry is safe only because the server drops the re-sent block. This
    is the end-to-end proof through `emit`: transient ReadError, then success,
    and the store holds exactly ONE row."""
    ch = ServerSideDedup([_read_error(), _ok()])
    monkeypatch.setattr(main, "ch", ch)
    monkeypatch.setattr(main, "tenant_for", lambda d: "acme")
    run(main.emit(kind="anomaly", severity="warning", score=6.5, device="mlx-1",
                  component="ifInErrors", summary="s", description="d",
                  labels={}, tenant_id="acme"))
    assert len(ch.calls) == 2
    assert len({c["token"] for c in ch.calls}) == 1, "token drifted across the retry"
    assert len(ch.stored) == 1, "the retry duplicated the finding"


def test_mutant_without_a_token_the_same_retry_duplicates(monkeypatch):
    """The mutation that proves the guard: drop the token and the identical
    ReadError-then-success sequence appends a SECOND row — which is precisely
    why the table was excluded from the retry set before it had one."""
    ch = ServerSideDedup([_read_error(), _ok()])
    monkeypatch.setattr(main, "ch", ch)
    monkeypatch.setattr(main, "finding_dedup_token", lambda row: "")
    monkeypatch.setattr(main, "tenant_for", lambda d: "acme")
    run(main.emit(kind="anomaly", severity="warning", score=6.5, device="mlx-1",
                  component="ifInErrors", summary="s", description="d",
                  labels={}, tenant_id="acme"))
    # No token -> ch_insert refuses to retry at all (the pre-fix behaviour),
    # so the row is LOST rather than duplicated...
    assert len(ch.calls) == 1
    assert ch.stored == []
    # ...and had it retried anyway, the untokened re-send would have stored two.
    run(ch.insert_detailed(FINDINGS, [_finding()], ""))
    run(ch.insert_detailed(FINDINGS, [_finding()], ""))
    assert len(ch.stored) == 2, "an untokened re-send must be able to duplicate"


def test_the_table_is_in_the_retry_set_with_its_ddl_guarantee():
    """The set is a claim about DDL (init.sql + the ConvergeStmts ALTER)."""
    assert FINDINGS in main.CH_DEDUP_SAFE_TABLES
    assert FINDINGS not in main.CH_CRITICAL_TABLES, (
        "findings must not raise CHInsertRejected — nothing upstream can replay it")


# ── the floor: retries exhausted means DURABLY KEPT, never silently lost ─────

def test_retries_exhausted_spools_the_row_to_the_dlq(monkeypatch, tmp_path):
    """§10: no silent failures. The row that survived neither the insert nor
    the retries must still exist somewhere replayable, with a reason."""
    monkeypatch.setattr(main, "CORR_CH_RETRY_ATTEMPTS", 3)
    ch = ScriptedCH([_read_error()] * 10)
    monkeypatch.setattr(main, "ch", ch)
    assert run(main.ch_insert(FINDINGS, [_finding()], dedup_token="finding:t")) is False
    assert len(ch.calls) == 3, "retry budget not honoured (§9: bounded)"
    assert main.CH_RETRIES_EXHAUSTED == 1

    lines = _dlq_lines(tmp_path)
    assert len(lines) == 1, "the give-up path kept no durable copy"
    rec = lines[0]
    assert rec["reason"] == "ch_insert_transport", "an unclassifiable record is the 160 defect"
    assert rec["table"] == FINDINGS
    assert rec["topic"] == f"chinsert:{FINDINGS}"
    assert rec["retries_exhausted"] is True
    assert rec["ch"]["error"] == "ReadError"
    assert json.loads(rec["payload"])["device"] == "mlx-08292148kdz4-01681"
    assert main.CH_ROWS_DLQ_SPOOLED == {FINDINGS: 1}
    assert main.CH_INSERT_FAILURES == {}, (
        "a row with a durable copy is not a LOST write — lost_total is for "
        "rows that exist nowhere")


def test_a_row_with_no_durable_home_is_still_counted_lost(monkeypatch):
    """The honest half: with CORR_DLQ_DIR unset the quarantine is memory-only
    and does not survive a restart, so the row IS lost and lost_total must say
    so. A 'durably kept' claim that is not true is the 238k-payload incident."""
    monkeypatch.setattr(main, "CORR_DLQ_DIR", "")
    monkeypatch.setattr(main, "CORR_CH_RETRY_ATTEMPTS", 1)
    monkeypatch.setattr(main, "ch", ScriptedCH([_read_error()]))
    assert run(main.ch_insert(FINDINGS, [_finding()], dedup_token="finding:t")) is False
    assert main.CH_INSERT_FAILURES == {FINDINGS: 1}
    assert main.CH_ROWS_DLQ_SPOOLED == {}


def test_a_failed_dlq_write_is_counted_lost_not_kept(monkeypatch, tmp_path):
    """_dlq_append never raises (quarantine must not kill the consumer), so a
    write failure would otherwise look like a successful spool."""
    monkeypatch.setattr(main, "CORR_CH_RETRY_ATTEMPTS", 1)
    monkeypatch.setattr(main, "ch", ScriptedCH([_read_error()]))

    def _boom(_record):
        main.QUARANTINE_WRITE_FAILURES += 1

    monkeypatch.setattr(main, "_dlq_append", _boom)
    assert run(main.ch_insert(FINDINGS, [_finding()], dedup_token="finding:t")) is False
    assert main.CH_INSERT_FAILURES == {FINDINGS: 1}
    assert main.CH_ROWS_DLQ_SPOOLED == {}


def test_the_spooled_rows_are_exposed_as_a_metric(monkeypatch, tmp_path):
    """A counter nobody can scrape is a silent failure with extra steps."""
    monkeypatch.setattr(main, "CORR_CH_RETRY_ATTEMPTS", 1)
    monkeypatch.setattr(main, "ch", ScriptedCH([_read_error()]))
    run(main.ch_insert(FINDINGS, [_finding()], dedup_token="finding:t"))
    body = main._metrics_text()
    assert f'corr_ch_rows_dlq_spooled_total{{table="{FINDINGS}"}} 1' in body
    assert "# TYPE corr_ch_rows_dlq_spooled_total counter" in body
