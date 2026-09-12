# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Integration tests for the Python ClickHouse writer against a REAL server.

Phase 6 — the Python side of what the Go chhttp integration test already does.
The unit tests prove CH.insert's logic; these prove ClickHouse actually behaves
the way that logic assumes, on the pinned 24.8.

Gated on CH_TEST_URL so the default `pytest` run stays hermetic:

    docker run -d --rm --name chpy -e CLICKHOUSE_USER=drill -e CLICKHOUSE_PASSWORD=drillpw \
      -v "$PWD/../../deployment/docker/clickhouse/custom-settings.xml:/etc/clickhouse-server/config.d/custom-settings.xml:ro" \
      clickhouse/clickhouse-server:24.8-alpine@sha256:b002e56ed5c16e224c312527f6fcba7e77216fec5d7a88a7828f59efc614feb5
    CH_TEST_URL=http://localhost:8123 python -m pytest test_clickhouse_integration.py -v
    docker rm -f chpy

This file is NOT a claim about ClickHouse transaction semantics — it verifies
wire-level behaviour and the Phase 3 dedup guarantee.
"""
import asyncio
import os
import uuid

import pytest

import main

CH_URL = os.environ.get("CH_TEST_URL", "")
pytestmark = pytest.mark.skipif(not CH_URL, reason="CH_TEST_URL not set (see file header)")

USER = os.environ.get("CH_TEST_USER", "drill")
PASS = os.environ.get("CH_TEST_PASSWORD", "drillpw")


# One persistent loop for the whole module: httpx.AsyncClient pools connections
# bound to the loop it was created on, so a fresh loop per call would orphan them.
_LOOP = asyncio.new_event_loop()


def run(coro):
    return _LOOP.run_until_complete(coro)


@pytest.fixture()
def ch():
    c = main.CH(CH_URL, USER, PASS)
    run(_ddl(c, "CREATE DATABASE IF NOT EXISTS itest"))
    yield c
    run(_ddl(c, "DROP DATABASE IF EXISTS itest"))



async def _ddl(ch, sql):
    """Run a DDL/exec statement (no JSON result) directly — CH.query parses JSON
    and would choke on an empty DDL response."""
    r = await ch.client.post(ch.base, params={"tenant_scope": "__all__"}, content=sql, auth=ch.auth)
    assert r.status_code < 300, f"DDL failed {r.status_code}: {r.text[:200]}"


def _tbl():
    return "itest.t_" + uuid.uuid4().hex[:8]


def test_insert_and_readback(ch):
    t = _tbl()
    run(_ddl(ch, f"CREATE TABLE {t} (id String, n UInt32) ENGINE=MergeTree ORDER BY id"))
    assert run(ch.insert(t, [{"id": "a", "n": 1}, {"id": "b", "n": 2}])) is True
    rows = run(ch.query(f"SELECT count() c FROM {t}"))
    assert rows and int(rows[0]["c"]) == 2


def test_unknown_column_is_rejected_not_silent(ch):
    # input_format_skip_unknown_fields=1 (which CH.insert sends) DROPS an unknown
    # field — so the row lands with the known columns. That is the intended
    # tolerance (F-56). The row must still be present.
    t = _tbl()
    run(_ddl(ch, f"CREATE TABLE {t} (id String) ENGINE=MergeTree ORDER BY id"))
    assert run(ch.insert(t, [{"id": "x", "ghost": "boo"}])) is True
    rows = run(ch.query(f"SELECT count() c FROM {t}"))
    assert int(rows[0]["c"]) == 1


def test_type_mismatch_fails_loudly(ch):
    # A genuinely bad row (wrong type for a declared column) must be REJECTED,
    # not silently dropped — CH.insert returns False.
    t = _tbl()
    run(_ddl(ch, f"CREATE TABLE {t} (id String, n UInt32) ENGINE=MergeTree ORDER BY id"))
    ok = run(ch.insert(t, [{"id": "x", "n": "not-a-number"}]))
    assert ok is False, "a type-mismatched row must be reported as a failed insert"


def test_dedup_token_prevents_retry_duplicate(ch):
    # Phase 3, end to end through CH.insert: the SAME token dropped on retry,
    # a DIFFERENT token lands. Mirrors the RCA-critical-table guarantee.
    t = _tbl()
    run(_ddl(ch,
        f"CREATE TABLE {t} (id String) ENGINE=MergeTree ORDER BY id "
        f"SETTINGS non_replicated_deduplication_window=1000"))
    tok = "probes:0:104857:" + t + ":0"
    for _ in range(3):  # simulate 3 retries of the same logical insert
        assert run(ch.insert(t, [{"id": "sig-1"}], dedup_token=tok)) is True
    n = int(run(ch.query(f"SELECT count() c FROM {t}"))[0]["c"])
    assert n == 1, f"3 same-token inserts must dedup to 1, got {n}"
    # different token lands
    assert run(ch.insert(t, [{"id": "sig-2"}], dedup_token=tok[:-1] + "9")) is True
    n = int(run(ch.query(f"SELECT count() c FROM {t}"))[0]["c"])
    assert n == 2


def test_multi_partition_insert(ch):
    # One insert spanning multiple partitions must land wholly. corr_* tables
    # partition by (tenant, date), so a batch legitimately spans partitions.
    t = _tbl()
    run(_ddl(ch,
        f"CREATE TABLE {t} (tenant String, d Date, id String) "
        f"ENGINE=MergeTree PARTITION BY (tenant, d) ORDER BY id"))
    rows = [{"tenant": f"t{i%3}", "d": f"2026-07-{10+i:02d}", "id": str(i)} for i in range(9)]
    assert run(ch.insert(t, rows)) is True
    parts = run(ch.query(
        f"SELECT count() c FROM (SELECT DISTINCT _partition_id FROM {t})"))
    assert int(parts[0]["c"]) >= 3, "multi-partition batch should create ≥3 partitions"
    assert int(run(ch.query(f"SELECT count() c FROM {t}"))[0]["c"]) == 9


def test_materialized_view_receives_the_insert(ch):
    # 5 MVs exist in the real schema; verify an MV populates from a base insert
    # (an MV that silently doesn't fire is a data-completeness bug).
    base, mv, dst = _tbl(), _tbl(), _tbl()
    run(_ddl(ch, f"CREATE TABLE {base} (id String, n UInt32) ENGINE=MergeTree ORDER BY id"))
    run(_ddl(ch, f"CREATE TABLE {dst} (id String, n UInt32) ENGINE=MergeTree ORDER BY id"))
    run(_ddl(ch, f"CREATE MATERIALIZED VIEW {mv} TO {dst} AS SELECT id, n FROM {base}"))
    assert run(ch.insert(base, [{"id": "a", "n": 5}])) is True
    got = run(ch.query(f"SELECT n FROM {dst} WHERE id='a'"))
    assert got and int(got[0]["n"]) == 5, "the MV did not propagate the insert"


def test_too_many_parts_is_reported(ch):
    # Induce a parts-pressure condition with an aggressively low parts_to_throw.
    # The insert(s) past the ceiling must be REPORTED (False), never silently lost.
    t = _tbl()
    run(_ddl(ch,
        f"CREATE TABLE {t} (id String) ENGINE=MergeTree ORDER BY id "
        f"SETTINGS parts_to_throw_insert=1, max_parts_in_total=1"))
    results = []
    for i in range(6):  # each single-row insert makes a new part
        results.append(run(ch.insert(t, [{"id": str(i)}])))
    assert False in results, (
        "with parts_to_throw_insert=1 a later insert must hit TOO_MANY_PARTS and "
        "be reported as False, not silently succeed")
