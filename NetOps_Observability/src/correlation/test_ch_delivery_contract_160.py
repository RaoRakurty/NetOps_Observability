# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Tracker 160 — the ClickHouse delivery contract.

BEFORE: a positively-rejected batch was counted, quarantined, and _insert_batch
RETURNED. flush() therefore succeeded and the consumer committed the offset.
There was no retry of any kind, and CH.insert folded transport failures into the
same `False`, so a momentary ClickHouse blip permanently removed rows from
corr_signals. Measured live on 2026-08-19: 95 lost corr_signals rows and a
ch_code=241 (MEMORY_LIMIT_EXCEEDED) — the textbook transient case.

THE CONTRACT these tests pin:
  committed            -> offsets may advance
  retryable failure    -> bounded retries, exponential backoff + FULL JITTER,
                          same content-hash token so a retry cannot duplicate
  permanent failure,
  or retries exhausted -> every row durably spooled WITH its reason and the
                          ClickHouse verdict, and only then may offsets advance
"""
from __future__ import annotations

import asyncio

import pytest

import main


def run(coro):
    return asyncio.run(coro)


class FakeCH:
    """A sink that can be told exactly how to fail, and counts attempts."""

    def __init__(self, outcomes):
        self.outcomes = list(outcomes)
        self.calls = []

    async def insert_detailed(self, table, rows, dedup_token=""):
        self.calls.append({"table": table, "rows": list(rows), "token": dedup_token})
        return (self.outcomes.pop(0) if self.outcomes
                else main.InsertOutcome(committed=True, kind="committed"))


def _ok():
    return main.InsertOutcome(committed=True, kind="committed", rows=1)


def _rejected(code):
    return main.InsertOutcome(committed=False, kind="rejected", status=500,
                              ch_code=code, query_id="q-1", rows=1)


def _transport():
    return main.InsertOutcome(committed=False, kind="transport",
                              error="ConnectError", rows=1)


@pytest.fixture(autouse=True)
def _fast_and_isolated(monkeypatch, tmp_path):
    monkeypatch.setattr(main, "CORR_CH_RETRY_BASE_S", 0.0)
    monkeypatch.setattr(main, "CORR_CH_RETRY_MAX_S", 0.0)
    monkeypatch.setattr(main, "CORR_DLQ_DIR", str(tmp_path))
    main.SIGNAL_BATCH.drop_pending()
    yield
    main.SIGNAL_BATCH.drop_pending()


def _row(i=1):
    return {"signal_id": f"sig-{i}", "tenant_id": "acme", "entity_id": f"e{i}"}


# --- retry classification ---------------------------------------------------

@pytest.mark.parametrize("code", sorted(main.CH_RETRYABLE_CODES))
def test_named_transient_codes_are_retryable(code):
    assert main.ch_retryable(_rejected(code))


@pytest.mark.parametrize("code", [16, 27, 47, 60, 62])
def test_schema_and_parse_errors_are_not_retryable(code):
    """Retrying these cannot succeed; it only delays the loss."""
    assert not main.ch_retryable(_rejected(code))


def test_transport_failures_are_retryable():
    assert main.ch_retryable(_transport())


def test_a_committed_insert_is_never_retryable():
    assert not main.ch_retryable(_ok())


def test_an_unexplained_failure_is_treated_as_permanent():
    """No code, no kind we recognise -> do not retry on a guess."""
    assert not main.ch_retryable(main.InsertOutcome(committed=False, kind="rejected"))


# --- backoff ---------------------------------------------------------------

def test_backoff_grows_exponentially_and_is_capped(monkeypatch):
    monkeypatch.setattr(main, "CORR_CH_RETRY_BASE_S", 1.0)
    monkeypatch.setattr(main, "CORR_CH_RETRY_MAX_S", 4.0)
    full = [main.ch_retry_delay(a, rnd=lambda: 1.0) for a in range(1, 6)]
    assert full == [1.0, 2.0, 4.0, 4.0, 4.0], full


def test_backoff_is_jittered_not_fixed(monkeypatch):
    """Full jitter: without it every replica retries the same batch at the same
    instant against the server that just said it was out of memory."""
    monkeypatch.setattr(main, "CORR_CH_RETRY_BASE_S", 1.0)
    monkeypatch.setattr(main, "CORR_CH_RETRY_MAX_S", 4.0)
    assert main.ch_retry_delay(3, rnd=lambda: 0.0) == 0.0
    assert main.ch_retry_delay(3, rnd=lambda: 0.5) == 2.0
    assert main.ch_retry_delay(3, rnd=lambda: 1.0) == 4.0


# --- the batch path --------------------------------------------------------

def test_a_transient_rejection_is_retried_and_recovers(monkeypatch):
    fake = FakeCH([_rejected(241), _rejected(241), _ok()])
    monkeypatch.setattr(main, "ch", fake)
    before = main.CH_RETRIES_RECOVERED
    run(main.SIGNAL_BATCH.add("netops.corr_signals", _row()))
    run(main.SIGNAL_BATCH.flush())
    assert len(fake.calls) == 3, "241 must be retried, not quarantined at once"
    assert main.CH_RETRIES_RECOVERED == before + 1


def test_retries_reuse_the_same_dedup_token(monkeypatch):
    """A retry after an unknown outcome must dedup server-side, not duplicate."""
    fake = FakeCH([_rejected(241), _rejected(241), _ok()])
    monkeypatch.setattr(main, "ch", fake)
    run(main.SIGNAL_BATCH.add("netops.corr_signals", _row()))
    run(main.SIGNAL_BATCH.flush())
    tokens = {c["token"] for c in fake.calls}
    assert len(tokens) == 1, f"token changed across retries: {tokens}"


class NeverRecovers:
    """Rejects with a RETRYABLE code forever. The bound is the only thing that
    can stop it, so a test using a sink that eventually succeeds cannot tell a
    bounded retry from an unbounded one."""

    def __init__(self):
        self.calls = []

    async def insert_detailed(self, table, rows, dedup_token=""):
        self.calls.append(dedup_token)
        if len(self.calls) > 200:
            raise AssertionError("unbounded retry: the attempt cap is not enforced")
        return _rejected(241)


def test_retries_are_bounded(monkeypatch):
    monkeypatch.setattr(main, "CORR_CH_RETRY_ATTEMPTS", 3)
    sink = NeverRecovers()
    monkeypatch.setattr(main, "ch", sink)
    run(main.SIGNAL_BATCH.add("netops.corr_signals", _row()))
    run(main.SIGNAL_BATCH.flush())
    assert len(sink.calls) == 3, (
        f"retry must stop at the cap; made {len(sink.calls)} attempts")


def test_an_endlessly_failing_sink_still_terminates(monkeypatch):
    """The retry loop must not storm a server that never recovers."""
    monkeypatch.setattr(main, "CORR_CH_RETRY_ATTEMPTS", 5)
    sink = NeverRecovers()
    monkeypatch.setattr(main, "ch", sink)
    run(main.SIGNAL_BATCH.add("netops.corr_signals", _row()))
    run(main.SIGNAL_BATCH.flush())
    assert len(sink.calls) == 5
    assert len(set(sink.calls)) == 1, "token must be stable across every attempt"


def test_a_permanent_rejection_is_not_retried(monkeypatch):
    fake = FakeCH([_rejected(16)] * 10)     # NO_SUCH_COLUMN
    monkeypatch.setattr(main, "ch", fake)
    run(main.SIGNAL_BATCH.add("netops.corr_signals", _row()))
    run(main.SIGNAL_BATCH.flush())
    assert len(fake.calls) == 1, "a schema error must quarantine immediately"


# --- durability of what is given up ----------------------------------------

def _dlq_records(tmp_path):
    import json
    recs = []
    for f in tmp_path.iterdir():
        for line in f.read_text().splitlines():
            if line.strip():
                recs.append(json.loads(line))
    return recs


def test_exhausted_retries_spool_every_row_with_its_reason(monkeypatch, tmp_path):
    monkeypatch.setattr(main, "CORR_DLQ_DIR", str(tmp_path))
    monkeypatch.setattr(main, "CORR_CH_RETRY_ATTEMPTS", 2)
    fake = FakeCH([_rejected(241)] * 10)
    monkeypatch.setattr(main, "ch", fake)
    for i in range(3):
        run(main.SIGNAL_BATCH.add("netops.corr_signals", _row(i)))
    run(main.SIGNAL_BATCH.flush())
    recs = [r for r in _dlq_records(tmp_path) if r.get("topic", "").startswith("chbatch")]
    assert len(recs) == 3, "every row of the batch must be spooled"
    for r in recs:
        assert r["reason"] == "ch_insert_rejected", "an unclassifiable record is the 160 defect"
        assert r["ch"]["ch_code"] == 241
        assert r["ch"]["query_id"] == "q-1"
        assert r["retries_exhausted"] is True
        assert r["payload_truncated"] is False


def test_spooled_payload_is_replayable(monkeypatch, tmp_path):
    """The durable copy must parse back into the row it replaces."""
    import json
    monkeypatch.setattr(main, "CORR_DLQ_DIR", str(tmp_path))
    fake = FakeCH([_rejected(16)])
    monkeypatch.setattr(main, "ch", fake)
    row = _row(7)
    run(main.SIGNAL_BATCH.add("netops.corr_signals", row))
    run(main.SIGNAL_BATCH.flush())
    recs = [r for r in _dlq_records(tmp_path) if r.get("topic", "").startswith("chbatch")]
    assert recs, "nothing was spooled"
    assert json.loads(recs[0]["payload"]) == row


def test_truncation_is_declared_not_hidden(monkeypatch, tmp_path):
    """A record that claims recoverability it does not have is worse than one
    that admits the gap."""
    monkeypatch.setattr(main, "CORR_DLQ_DIR", str(tmp_path))
    monkeypatch.setattr(main, "CORR_QUARANTINE_PAYLOAD_CHARS", 50)
    fake = FakeCH([_rejected(16)])
    monkeypatch.setattr(main, "ch", fake)
    run(main.SIGNAL_BATCH.add("netops.corr_signals",
                              {"signal_id": "s", "blob": "x" * 500}))
    run(main.SIGNAL_BATCH.flush())
    recs = [r for r in _dlq_records(tmp_path) if r.get("topic", "").startswith("chbatch")]
    assert recs[0]["payload_truncated"] is True


def test_tenant_identity_survives_into_the_dead_letter(monkeypatch, tmp_path):
    import json
    monkeypatch.setattr(main, "CORR_DLQ_DIR", str(tmp_path))
    fake = FakeCH([_rejected(16)])
    monkeypatch.setattr(main, "ch", fake)
    run(main.SIGNAL_BATCH.add("netops.corr_signals",
                              {"signal_id": "s9", "tenant_id": "acme", "entity_id": "e9"}))
    run(main.SIGNAL_BATCH.flush())
    recs = [r for r in _dlq_records(tmp_path) if r.get("topic", "").startswith("chbatch")]
    payload = json.loads(recs[0]["payload"])
    assert payload["tenant_id"] == "acme"
    assert payload["signal_id"] == "s9"


def test_a_bool_only_sink_is_treated_as_permanent(monkeypatch):
    """Never retry on an unexplained failure."""
    class BoolOnly:
        def __init__(self): self.n = 0
        async def insert(self, table, rows, dedup_token=""):
            self.n += 1
            return False
    sink = BoolOnly()
    monkeypatch.setattr(main, "ch", sink)
    run(main.SIGNAL_BATCH.add("netops.corr_signals", _row()))
    run(main.SIGNAL_BATCH.flush())
    assert sink.n == 1
