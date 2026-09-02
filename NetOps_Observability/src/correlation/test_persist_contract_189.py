"""Tracker 189 — every correlation-written table under ONE delivery contract.

THE DEFECT (audit after the tracker-160 fix, first live evidence 2026-08-31).
Tracker 160 gave `corr_signals` a real contract: bounded retries with
exponential backoff + full jitter, a stable content-hash token across those
retries, and a replayable dead-letter record on give-up. Six other tables the
correlation engine writes stayed OUTSIDE it:

  netops.corr_signals_archive        transport failure -> `lost_total++`, silent;
                                     recovered only if the same object happened
                                     to persist another version
  netops.corr_tenant_write_amp       one insert carries a WHOLE per-tenant
                                     accounting window; a timer flush is never
                                     redelivered, so the window was dropped
  netops.wireless_sessions           the bool return is ignored at all four call
  netops.wireless_roams              sites, so a rejected insert was a dropped
  netops.wireless_mlo_links          session / roam / link / episode with
  netops.wireless_onboarding_episodes `lost_total++` as the only trace

On the 10k documentation rung (`ladder-s10k-08311849`) 12 archive batches —
~357 rows — were lost inside the accounting window, every one a ReadError
against a ClickHouse raising MEMORY_LIMIT_EXCEEDED 906x in the same span. The
sibling tables retried without loss. The archive lane was the only
fire-and-forget path, exactly as the row predicted.

THE CONTRACT these tests pin, per table:
  committed             -> counted flushed
  retryable failure     -> bounded retries, backoff + FULL jitter, the SAME
                           token every attempt (no duplicate on recovery)
  permanent failure, or
  retries exhausted     -> every row durably spooled with `reason`, `ch_code`,
                           `query_id` and `table`, replayable from the file
  nothing kept anywhere -> and ONLY then does `lost_total` move

`lost_total` (CH_INSERT_FAILURES / corr_ch_insert_failures_total) is not
removed — the ladder's accounting phase gates on it. It is made unreachable
from any path that keeps nothing: `_ch_give_up` spools FIRST and counts a loss
only when the durable copy could not be made.
"""
from __future__ import annotations

import asyncio
import json
import re
from datetime import datetime, timezone
from pathlib import Path

import pytest

import main

# NetOps_Observability/ (src/correlation/ -> src/ -> project root)
_ROOT = Path(__file__).resolve().parents[2]
_INIT_SQL = _ROOT / "deployment" / "docker" / "clickhouse" / "init.sql"
_CORR_SCHEMA_GO = (_ROOT / "src" / "backend" / "internal" / "chschema"
                   / "corr_schema.go")

ARCHIVE = "netops.corr_signals_archive"
WRITE_AMP = "netops.corr_tenant_write_amp"
WIRELESS = (
    "netops.wireless_sessions",
    "netops.wireless_onboarding_episodes",
    "netops.wireless_roams",
    "netops.wireless_mlo_links",
)
# The six tables named by tracker 189, in the order the row names them.
TABLES_189 = (ARCHIVE, WRITE_AMP) + WIRELESS


def run(coro):
    return asyncio.run(coro)


# ── sinks (controlled injection, the tracker-160 style) ──────────────────────

class ScriptedCH:
    """Replays a scripted list of outcomes, recording every attempt so retry
    COUNT, token STABILITY and row IDENTITY are all observable."""

    def __init__(self, outcomes=()):
        self.outcomes = list(outcomes)
        self.calls: list[dict] = []

    async def insert_detailed(self, table, rows, dedup_token=""):
        rows = list(rows)
        self.calls.append({"table": table, "rows": rows, "token": dedup_token})
        if self.outcomes:
            return self.outcomes.pop(0)
        return main.InsertOutcome(committed=True, kind="committed", rows=len(rows))


class NeverRecovers:
    """Rejects with a RETRYABLE code forever. The bound is the only thing that
    can stop it, so a sink that eventually succeeds cannot tell a bounded retry
    from an unbounded one."""

    def __init__(self):
        self.calls: list[str] = []

    async def insert_detailed(self, table, rows, dedup_token=""):
        self.calls.append(dedup_token)
        if len(self.calls) > 200:
            raise AssertionError("unbounded retry: the attempt cap is not enforced")
        return _rejected(241)


def _ok(n=1):
    return main.InsertOutcome(committed=True, kind="committed", rows=n)


def _rejected(code, n=1):
    return main.InsertOutcome(committed=False, kind="rejected", status=500,
                              ch_code=code, query_id="q-189", rows=n)


def _transport(n=1):
    return main.InsertOutcome(committed=False, kind="transport",
                              error="ReadError", rows=n)


@pytest.fixture(autouse=True)
def _fast_and_isolated(monkeypatch, tmp_path):
    """No real backoff, a private dead-letter dir, and clean counters — the
    module-level accounting is what several of these tests assert on."""
    monkeypatch.setattr(main, "CORR_CH_RETRY_BASE_S", 0.0)
    monkeypatch.setattr(main, "CORR_CH_RETRY_MAX_S", 0.0)
    monkeypatch.setattr(main, "CORR_DLQ_DIR", str(tmp_path))
    main.CH_INSERT_FAILURES.clear()
    main.CH_ROWS_DLQ_SPOOLED.clear()
    main.CH_TABLE_OUTCOMES.clear()
    main._CH_FAIL_LOG_LAST.clear()
    main.QUARANTINE.clear()
    yield
    main.CH_INSERT_FAILURES.clear()
    main.CH_ROWS_DLQ_SPOOLED.clear()
    main.CH_TABLE_OUTCOMES.clear()
    main._CH_FAIL_LOG_LAST.clear()
    main.QUARANTINE.clear()


def _dlq_records(tmp_path, table=None):
    recs = []
    for f in sorted(tmp_path.iterdir()):
        if not f.is_file():
            continue
        for line in f.read_text().splitlines():
            if line.strip():
                rec = json.loads(line)
                if table is None or rec.get("table") == table:
                    recs.append(rec)
    return recs


def _row_for(table, i=1):
    """A minimally realistic row: every natural-key column of its table, plus a
    payload field, so the token derivation is exercised as it runs live."""
    if table == ARCHIVE:
        return {"tenant_id": "acme", "signal_id": f"sig-{i}",
                "ts": f"2026-09-02 10:00:0{i}.000", "entity_id": f"dev-{i}",
                "archived_for": "c-1", "archived_version": 3}
    if table == WRITE_AMP:
        return {"tenant_id": f"t-{i}", "window_start": 1756800000000,
                "window_s": 300, "raw_seen": 10 * i, "persisted": i,
                "damped": 9 * i}
    if table == "netops.wireless_sessions":
        return {"tenant_id": "acme", "session_id": f"s-{i}",
                "client_mac": f"aa:bb:cc:00:00:0{i}", "bssid": "de:ad:be:ef:00:01"}
    if table == "netops.wireless_onboarding_episodes":
        return {"tenant_id": "acme", "episode_id": f"ep-{i}",
                "client_mac": f"aa:bb:cc:00:00:0{i}", "terminal_outcome": "failure"}
    if table == "netops.wireless_roams":
        return {"tenant_id": "acme", "roam_id": f"r-{i}",
                "client_mac": f"aa:bb:cc:00:00:0{i}", "to_bssid": "de:ad:be:ef:00:02"}
    if table == "netops.wireless_mlo_links":
        return {"tenant_id": "acme", "session_ref": f"s-{i}", "link_id": f"s-{i}|0",
                "link_index": 0, "band": "6g"}
    raise AssertionError(f"no fixture row for {table}")


# ═══════════════════════════════════════════════════════════════════════════
# 1. The claims about DDL and about the sets, made load-bearing
# ═══════════════════════════════════════════════════════════════════════════

@pytest.mark.parametrize("table", TABLES_189)
def test_every_named_table_is_under_the_dlq_contract(table):
    """The row's six tables must all have a durable give-up path. Without this
    the fix is one refactor away from silently regressing to fire-and-forget."""
    assert table in main.CH_DLQ_ON_LOSS_TABLES


@pytest.mark.parametrize("table", WIRELESS)
def test_the_wireless_tables_are_replacing_mergetree_on_their_natural_key(table):
    """The retry-set membership of the four wireless tables is a claim about
    DDL, so it is checked against the DDL — not asserted in prose.

    ReplacingMergeTree(ingest_ts) ordered by the natural key means a re-sent row
    COLLAPSES on merge, which is what makes a retry after an UNKNOWN outcome
    safe with no schema change (the corr_current justification).
    """
    assert table in main.CH_DEDUP_SAFE_TABLES
    assert table in main.CH_REPLACING_TABLES
    sql = _INIT_SQL.read_text()
    name = table.split(".", 1)[1]
    m = re.search(
        rf"CREATE TABLE IF NOT EXISTS netops\.{name}\s*\((.*?)\)\s*"
        r"ENGINE\s*=\s*(\w+)\(([^)]*)\).*?ORDER BY\s*\(([^)]*)\)",
        sql, re.DOTALL)
    assert m, f"{table} not found in init.sql — the DDL claim cannot be checked"
    assert m.group(2) == "ReplacingMergeTree", (
        f"{table} is {m.group(2)}, not ReplacingMergeTree: it can no longer be "
        "in CH_DEDUP_SAFE_TABLES")
    assert m.group(3).strip() == "ingest_ts"
    order_by = tuple(c.strip() for c in m.group(4).split(","))
    assert order_by == main.CH_NATURAL_KEY_COLUMNS[table], (
        f"{table} ORDER BY {order_by} no longer matches the natural key "
        f"{main.CH_NATURAL_KEY_COLUMNS[table]} the dedup token is built from")


def test_archive_and_write_amp_stay_out_of_the_retry_set_and_the_ddl_says_why():
    """The comment corrected by this tracker, asserted rather than believed.

    Neither table has a `non_replicated_deduplication_window`, in init.sql or in
    the boot-converge ALTER list, so a token is inert on them and re-sending
    after a TRANSPORT-unknown outcome could duplicate rows in a plain MergeTree.
    They get DLQ-on-loss instead of transport retries.
    """
    for table in (ARCHIVE, WRITE_AMP):
        assert table not in main.CH_DEDUP_SAFE_TABLES
        name = table.split(".", 1)[1]
        sql = _INIT_SQL.read_text()
        m = re.search(rf"CREATE TABLE IF NOT EXISTS netops\.{name}\b(.*?);", sql, re.DOTALL)
        assert m, f"{table} not found in init.sql"
        assert "non_replicated_deduplication_window" not in m.group(1), (
            f"{table} gained a dedup window — it can now join "
            "CH_DEDUP_SAFE_TABLES, and this guard should say so")
        assert f"netops.{name} MODIFY SETTING non_replicated_deduplication_window" \
            not in _CORR_SCHEMA_GO.read_text()


def test_corr_signals_does_have_a_dedup_window_the_old_comment_denied():
    """The stale comment tracker 189 corrects: `CH_DEDUP_SAFE_TABLES` used to
    say corr_signals had no dedup window. The boot converge adds one; the real
    reason it stays out of the set is token stability across re-batching."""
    assert ("ALTER TABLE netops.corr_signals MODIFY SETTING "
            "non_replicated_deduplication_window = 1000") in _CORR_SCHEMA_GO.read_text()
    assert "netops.corr_signals" not in main.CH_DEDUP_SAFE_TABLES


# ═══════════════════════════════════════════════════════════════════════════
# 2. The token: stable across retries, unique per logical insert
# ═══════════════════════════════════════════════════════════════════════════

@pytest.mark.parametrize("table", (WRITE_AMP,) + WIRELESS)
def test_the_natural_key_token_is_deterministic(table):
    rows = [_row_for(table)]
    assert main.natural_key_token(table, rows) == main.natural_key_token(table, list(rows))
    assert main.natural_key_token(table, rows).startswith("nk:")


@pytest.mark.parametrize("table", (WRITE_AMP,) + WIRELESS)
def test_a_different_natural_key_is_a_different_token(table):
    assert (main.natural_key_token(table, [_row_for(table, 1)])
            != main.natural_key_token(table, [_row_for(table, 2)]))


def test_an_updated_replacing_row_is_not_mistaken_for_a_duplicate():
    """A ReplacingMergeTree row is legitimately rewritten in place — a session
    gains `assoc_end` when it closes. A KEY-ONLY token would make that update a
    duplicate of the original the moment the table gained a dedup window, and
    ClickHouse would drop it silently: the exact failure class this tracker
    exists to remove, reintroduced by its own fix."""
    table = "netops.wireless_sessions"
    opened = _row_for(table)
    closed = dict(opened, assoc_end=1756800300000, end_reason="deauth")
    assert (main.natural_key_token(table, [opened])
            != main.natural_key_token(table, [closed]))


def test_a_table_with_no_natural_key_gets_no_token():
    assert main.natural_key_token("netops.corr_objects", [{"a": 1}]) == ""
    assert main.natural_key_token("netops.wireless_roams", []) == ""


# ═══════════════════════════════════════════════════════════════════════════
# 3. Transport failure then recovery: the rows land ONCE, under ONE token
# ═══════════════════════════════════════════════════════════════════════════

@pytest.mark.parametrize("table", WIRELESS)
def test_a_transport_failure_recovers_without_duplicating(table, monkeypatch):
    """The four wireless tables are dedup-safe by DDL AND now carry a stable
    token, so an UNKNOWN outcome is retried instead of dropped."""
    sink = ScriptedCH([_transport(), _ok()])
    monkeypatch.setattr(main, "ch", sink)
    row = _row_for(table)
    assert run(main.ch_insert(table, [row], lane="wireless")) is True
    assert len(sink.calls) == 2, "a transport-unknown outcome must be retried"
    tokens = {c["token"] for c in sink.calls}
    assert len(tokens) == 1 and tokens != {""}, (
        f"token must be stable and non-empty across the retry: {tokens}")
    assert [c["rows"] for c in sink.calls] == [[row], [row]], (
        "the retry must re-send the same membership, or the token is a lie")
    assert main.CH_INSERT_FAILURES == {}
    assert main.CH_TABLE_OUTCOMES[table] == {"retried": 1, "flushed": 1}


@pytest.mark.parametrize("table", TABLES_189)
def test_a_transient_rejection_recovers_on_every_named_table(table, monkeypatch):
    """A DEFINITE rejection is retry-safe on ANY table (single-block inserts are
    atomic, so nothing committed) — including the two plain-MergeTree ones."""
    sink = ScriptedCH([_rejected(241), _rejected(241), _ok()])
    monkeypatch.setattr(main, "ch", sink)
    assert run(main.ch_insert(table, [_row_for(table)])) is True
    assert len(sink.calls) == 3
    assert len({c["token"] for c in sink.calls}) == 1, "token moved across retries"
    assert main.CH_INSERT_FAILURES == {}
    assert main.CH_TABLE_OUTCOMES[table]["flushed"] == 1


def test_the_archive_does_not_retry_a_transport_unknown(monkeypatch):
    """corr_signals_archive is a plain MergeTree with NO dedup window: a
    re-send after an unknown outcome would duplicate a replay row. It must
    spool instead — durability, not a second copy."""
    sink = ScriptedCH([_transport()] * 5)
    monkeypatch.setattr(main, "ch", sink)
    assert run(main.ch_insert(ARCHIVE, [_row_for(ARCHIVE)],
                              dedup_token="tok:archive:0")) is False
    assert len(sink.calls) == 1, "an unknown outcome on the archive is not retryable"
    assert main.CH_ROWS_DLQ_SPOOLED == {ARCHIVE: 1}
    assert main.CH_INSERT_FAILURES == {}


# ═══════════════════════════════════════════════════════════════════════════
# 4. Permanent rejection and exhaustion: a replayable dead-letter, never a
#    silent lost_total
# ═══════════════════════════════════════════════════════════════════════════

@pytest.mark.parametrize("table", TABLES_189)
def test_a_permanent_rejection_dead_letters_with_every_field(table, monkeypatch, tmp_path):
    sink = ScriptedCH([_rejected(16)] * 5)          # NO_SUCH_COLUMN
    monkeypatch.setattr(main, "ch", sink)
    row = _row_for(table)
    assert run(main.ch_insert(table, [row])) is False
    assert len(sink.calls) == 1, "a schema error must not be retried"
    recs = _dlq_records(tmp_path, table)
    assert len(recs) == 1, f"{table}: the row was not preserved"
    rec = recs[0]
    assert rec["reason"] == "ch_insert_rejected"
    assert rec["table"] == table
    assert rec["ch"]["ch_code"] == 16
    assert rec["ch"]["query_id"] == "q-189"
    assert rec["payload_truncated"] is False
    assert json.loads(rec["payload"]) == row


@pytest.mark.parametrize("table", TABLES_189)
def test_exhausted_retries_dead_letter_and_lost_total_never_moves(
        table, monkeypatch, tmp_path):
    monkeypatch.setattr(main, "CORR_CH_RETRY_ATTEMPTS", 3)
    sink = NeverRecovers()
    monkeypatch.setattr(main, "ch", sink)
    row = _row_for(table)
    assert run(main.ch_insert(table, [row])) is False
    assert len(sink.calls) == 3, f"retry must stop at the cap: {len(sink.calls)}"
    assert len(set(sink.calls)) == 1, "token must be stable across every attempt"
    recs = _dlq_records(tmp_path, table)
    assert len(recs) == 1
    assert recs[0]["retries_exhausted"] is True
    assert recs[0]["ch"]["ch_code"] == 241
    assert main.CH_INSERT_FAILURES == {}, (
        "lost_total moved for a row that is sitting in the dead-letter file")
    assert main.CH_TABLE_OUTCOMES[table] == {"retried": 2, "deadlettered": 1}


@pytest.mark.parametrize("table", TABLES_189)
def test_the_dead_lettered_row_replays_back_into_the_table(table, monkeypatch, tmp_path):
    """Replayability is the whole point of the durable copy, so it is exercised
    end to end: spool the row, read it back off disk, re-insert it through the
    SAME path, and assert it lands — under the same token the failed attempt
    used, so a replay of an insert that had actually committed dedups rather
    than duplicating wherever the DDL supports it."""
    failing = ScriptedCH([_rejected(16)])
    monkeypatch.setattr(main, "ch", failing)
    row = _row_for(table)
    run(main.ch_insert(table, [row]))
    original_token = failing.calls[0]["token"]

    recs = _dlq_records(tmp_path, table)
    replayed = json.loads(recs[0]["payload"])
    healthy = ScriptedCH()
    monkeypatch.setattr(main, "ch", healthy)
    # The archive's token is its member_key, supplied by the caller; every other
    # table derives its own from the row, so a replay reproduces it unaided.
    kwargs = {"dedup_token": original_token} if table == ARCHIVE else {}
    assert run(main.ch_insert(table, [replayed], **kwargs)) is True
    assert healthy.calls[0]["rows"] == [row], "the replayed row is not the row"
    assert healthy.calls[0]["token"] == original_token, (
        "a replay under a different token cannot dedup server-side")


def test_a_row_with_no_durable_home_is_still_counted_lost(monkeypatch):
    """The honest half. With CORR_DLQ_DIR unset the quarantine is memory-only
    and does not survive a restart, so the row IS lost and lost_total must say
    so — a 'durably kept' claim that is not true is the 238k-payload incident."""
    monkeypatch.setattr(main, "CORR_DLQ_DIR", "")
    monkeypatch.setattr(main, "CORR_CH_RETRY_ATTEMPTS", 1)
    monkeypatch.setattr(main, "ch", ScriptedCH([_rejected(16)]))
    assert run(main.ch_insert(ARCHIVE, [_row_for(ARCHIVE)])) is False
    assert main.CH_INSERT_FAILURES == {ARCHIVE: 1}
    assert main.CH_ROWS_DLQ_SPOOLED == {}
    assert main.CH_TABLE_OUTCOMES[ARCHIVE] == {"lost": 1}


def test_a_failed_dead_letter_write_is_counted_lost_not_kept(monkeypatch):
    """`_dlq_append` never raises (quarantine must not kill the consumer), so a
    write failure would otherwise look like a successful spool."""
    monkeypatch.setattr(main, "CORR_CH_RETRY_ATTEMPTS", 1)
    monkeypatch.setattr(main, "ch", ScriptedCH([_rejected(16)]))

    def _boom(_record):
        main.QUARANTINE_WRITE_FAILURES += 1

    monkeypatch.setattr(main, "_dlq_append", _boom)
    assert run(main.ch_insert("netops.wireless_roams",
                              [_row_for("netops.wireless_roams")])) is False
    assert main.CH_INSERT_FAILURES == {"netops.wireless_roams": 1}
    assert main.CH_ROWS_DLQ_SPOOLED == {}


class Exploding:
    async def insert_detailed(self, table, rows, dedup_token=""):
        raise TimeoutError("clickhouse unreachable")


@pytest.mark.parametrize("table", TABLES_189)
def test_a_raising_sink_also_keeps_the_rows(table, monkeypatch, tmp_path):
    """A sink that RAISES is still an insert that will not be attempted again.
    It is re-raised (a consumer-driven write also quarantines its source
    message) but the rows are kept first."""
    monkeypatch.setattr(main, "ch", Exploding())
    with pytest.raises(TimeoutError):
        run(main.ch_insert(table, [_row_for(table)]))
    assert len(_dlq_records(tmp_path, table)) == 1
    assert main.CH_INSERT_FAILURES == {}


# ═══════════════════════════════════════════════════════════════════════════
# 5. The two lanes with a shape of their own
# ═══════════════════════════════════════════════════════════════════════════

def test_the_archive_sink_sends_the_member_key_as_its_token(monkeypatch):
    """`_ch_emit` is the unbatched Evidence sink. The archive chunk carries no
    token of its own, so the sink promotes the content-derived `member_key` the
    BATCHED sink already uses — one identity for the chunk on both legs."""
    sink = ScriptedCH()
    monkeypatch.setattr(main, "ch", sink)
    rows = [_row_for(ARCHIVE)]
    run(main._ch_emit(ARCHIVE, rows, "",
                      {"corr_id": "c-1", "version": 3, "row_count": 1,
                       "member_key": "tok-abc:archive:0"}))
    assert sink.calls[0]["token"] == "tok-abc:archive:0"


def test_the_whole_write_amp_window_is_kept_when_the_insert_fails(
        monkeypatch, tmp_path):
    """One insert carries every tenant's accounting for the window and nothing
    redelivers a timer flush, so a dropped insert used to be a hole in the
    storm-attribution query with no counter to name it."""
    monkeypatch.setattr(main, "CORR_CH_RETRY_ATTEMPTS", 1)
    monkeypatch.setattr(main, "ch", ScriptedCH([_rejected(16)] * 3))
    monkeypatch.setattr(main, "CORR_WA_FLUSH_S", 0.0)
    monkeypatch.setattr(main, "TENANT_WA", {})
    monkeypatch.setattr(main, "_WA_WINDOW_START",
                        datetime(2026, 9, 2, 10, 0, tzinfo=timezone.utc))
    for tenant in ("acme", "globex", "initech"):
        main._wa_note_raw(_FakeSignal(tenant))
        main._wa_note_outcome(tenant, "persisted")

    run(main._flush_tenant_write_amp(datetime(2026, 9, 2, 10, 5,
                                              tzinfo=timezone.utc)))

    recs = _dlq_records(tmp_path, WRITE_AMP)
    assert len(recs) == 3, "every tenant's window row must be preserved"
    tenants = {json.loads(r["payload"])["tenant_id"] for r in recs}
    assert tenants == {"acme", "globex", "initech"}
    assert main.CH_INSERT_FAILURES == {}
    # The flush still resets the window and never backpressures the engine.
    assert main.TENANT_WA == {}


class _FakeSignal:
    """Only what `_wa_note_raw` reads."""

    def __init__(self, tenant):
        self.tenant_id = tenant
        self.kind = "link_down"
        self.entity_id = f"dev-{tenant}"


# ═══════════════════════════════════════════════════════════════════════════
# 6. Bounded memory under sustained failure (§9 / INVARIANTS §10a)
# ═══════════════════════════════════════════════════════════════════════════

def test_sustained_failure_does_not_grow_memory(monkeypatch, tmp_path):
    """Backpressure, not growth. 400 consecutive give-ups must leave the
    in-memory ring at its maxlen, the accounting dicts at one entry per table,
    and the durable spool inside its byte cap (it ROTATES at the cap — one
    prior generation, never an unbounded file)."""
    monkeypatch.setattr(main, "CORR_CH_RETRY_ATTEMPTS", 1)
    monkeypatch.setattr(main, "CORR_DLQ_MAX_BYTES", 16 * 1024)
    monkeypatch.setattr(main, "ch", ScriptedCH([_rejected(16)] * 10_000))
    for i in range(400):
        for table in TABLES_189:
            run(main.ch_insert(table, [_row_for(table, i % 7)]))

    assert len(main.QUARANTINE) <= main.CORR_QUARANTINE_MAX
    assert main.QUARANTINE.maxlen == main.CORR_QUARANTINE_MAX
    assert set(main.CH_TABLE_OUTCOMES) == set(TABLES_189), (
        "the per-table series must not grow a key per failure")
    for outcomes in main.CH_TABLE_OUTCOMES.values():
        assert set(outcomes) <= set(main.CH_OUTCOMES)
    files = [f for f in tmp_path.iterdir() if f.is_file()]
    assert {f.name for f in files} <= {"corr-deadletter.ndjson",
                                       "corr-deadletter.ndjson.1"}
    for f in files:
        assert f.stat().st_size <= main.CORR_DLQ_MAX_BYTES * 2, (
            "the dead-letter file grew past its rotation cap")
    assert main.CH_INSERT_FAILURES == {}, "nothing was lost; nothing may say so"


# ═══════════════════════════════════════════════════════════════════════════
# 7. Observability (§10): the outcome of every table is scrapeable
# ═══════════════════════════════════════════════════════════════════════════

def test_metrics_text_carries_the_per_table_outcomes(monkeypatch):
    sink = ScriptedCH([_rejected(241), _ok(),          # retried then flushed
                       _rejected(16)])                  # dead-lettered
    monkeypatch.setattr(main, "ch", sink)
    run(main.ch_insert("netops.wireless_roams", [_row_for("netops.wireless_roams")]))
    run(main.ch_insert(ARCHIVE, [_row_for(ARCHIVE)]))

    text = main._metrics_text()
    assert "# TYPE corr_ch_table_writes_total counter" in text
    for expect in (
        'corr_ch_table_writes_total{table="netops.wireless_roams",outcome="flushed"} 1',
        'corr_ch_table_writes_total{table="netops.wireless_roams",outcome="retried"} 1',
        f'corr_ch_table_writes_total{{table="{ARCHIVE}",outcome="deadlettered"}} 1',
    ):
        assert expect in text, f"missing from /metrics: {expect}"


def test_the_spooled_rows_stay_visible_on_the_existing_family(monkeypatch):
    """corr_ch_rows_dlq_spooled_total is what tells an operator rows are
    waiting in the file — the six new tables must reach it too."""
    monkeypatch.setattr(main, "CORR_CH_RETRY_ATTEMPTS", 1)
    monkeypatch.setattr(main, "ch", ScriptedCH([_rejected(16)] * 10))
    for table in TABLES_189:
        run(main.ch_insert(table, [_row_for(table)]))
    text = main._metrics_text()
    for table in TABLES_189:
        assert f'corr_ch_rows_dlq_spooled_total{{table="{table}"}} 1' in text
