# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Recovery wording for every stateful store (FMEA 2026-09-15, T1 residual b).

compose_up waits through a dependency that is still healing and tells the
operator WHY it is waiting. Until now only postgres' crash-recovery wording was
recognised; Kafka, ClickHouse and OpenSearch recovering after the same unclean
stop were reported as a bare "unhealthy", which reads like a failure.

Every fixture below was RECORDED (read-only `docker logs` / the ClickHouse
server log) from the Correlix lab stack's own containers — apache/kafka 4.1.1,
clickhouse-server 24.8, opensearch 2.16, postgres 16 — except where marked
CONSTRUCTED. Negative fixtures prove a crash is never dressed up as progress.

No docker: the log text and the container states are injected.
Run:  python3 -m pytest tests/test_install_selfheal_signatures.py -v
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import install

# ── recorded log lines ───────────────────────────────────────────────────────

KAFKA_UNFLUSHED = (  # netops-kafka-1, 2026-08-28, the start after an unclean host stop
    "[2026-08-28 18:03:26,154] INFO [LogLoader partition=__cluster_metadata-0, "
    "dir=/var/lib/kafka/data] Recovering unflushed segment 1209847. 0 recovered for "
    "__cluster_metadata-0. (org.apache.kafka.storage.internals.log.LogLoader)")
CLICKHOUSE_METADATA = (  # netops-clickhouse-1 server log, 2026-09-06
    "2026.09.06 00:43:20.380574 [ 7 ] {} <Information> Application: Loading metadata "
    "from /var/lib/clickhouse/")
CLICKHOUSE_ASYNC_START = (
    "2026.09.06 00:43:22.980093 [ 7 ] {} <Information> loadMetadata: Start asynchronous "
    "loading of databases")
CLICKHOUSE_ASYNC_PROGRESS = (
    "2026.09.05 01:04:41.047923 [ 785 ] {} <Information> AsyncLoader: Processed: 37.5%")
# CONSTRUCTED: the debug-level wording of the same phase, in the recorded 24.8
# line format (the lab server logs at information level, so it never emits it).
CLICKHOUSE_DATA_PARTS = (
    "2026.09.06 00:43:24.101112 [ 770 ] {} <Debug> netops.flows "
    "(6d3c0f4e-1a2b-4c5d-8e9f-001122334455): Loading data parts")
OPENSEARCH_GATEWAY = (  # netops-opensearch-1, 2026-09-13
    "[2026-09-13T05:09:19,992][INFO ][o.o.g.GatewayService     ] [opensearch] "
    "recovered [70] indices into cluster_state")
OPENSEARCH_RED = (  # netops-opensearch-1, 2026-09-14
    "[2026-09-14T05:12:19,641][INFO ][o.o.c.r.a.AllocationService] [opensearch] "
    "Cluster health status changed from [RED] to [GREEN] (reason: [shards started "
    "[[security-auditlog-2026.08.19][0], [security-auditlog-2026.08.17][0], "
    "[.kibana_1][0]]]).")
POSTGRES_RECOVERY = (  # netops-postgres-1, 2026-08-28
    "2026-08-28 18:08:11.983 UTC [50] LOG:  database system was not properly shut "
    "down; automatic recovery in progress")

# Negative, recorded: the flood-stage crash loop (memory 2026-09-05). "state not
# recovered" is a startup FAILURE, never recovery progress.
OPENSEARCH_STARTUP_CRASH = (
    "org.opensearch.bootstrap.StartupException: ClusterManagerNotDiscoveredException["
    "ClusterBlockException[index [.opensearch-observability] blocked by: "
    "[SERVICE_UNAVAILABLE/1/state not recovered / initialized];]]")
# Negative, recorded: routine daily-index health change on a healthy node.
OPENSEARCH_ROUTINE = (
    "[2026-09-13T00:08:34,954][INFO ][o.o.c.r.a.AllocationService] [opensearch] "
    "Cluster health status changed from [YELLOW] to [GREEN] (reason: [shards started "
    "[[netops-syslog-untagged-2026.09.13][0]]]).")
# Negative, recorded: Kafka's clean-start producer-state line.
KAFKA_ROUTINE = (
    "[2026-08-28 18:03:43,108] INFO [LogLoader partition=__cluster_metadata-0, "
    "dir=/var/lib/kafka/data] Producer state recovery took 2ms for snapshot load and "
    "0ms for segment recovery from offset 2082415 "
    "(org.apache.kafka.storage.internals.log.UnifiedLog)")


@pytest.mark.parametrize("line,store", [
    (KAFKA_UNFLUSHED, "Kafka"),
    (CLICKHOUSE_METADATA, "ClickHouse"),
    (CLICKHOUSE_ASYNC_START, "ClickHouse"),
    (CLICKHOUSE_ASYNC_PROGRESS, "ClickHouse"),
    (CLICKHOUSE_DATA_PARTS, "ClickHouse"),
    (OPENSEARCH_GATEWAY, "OpenSearch"),
    (OPENSEARCH_RED, "OpenSearch"),
])
def test_each_store_recovery_line_is_named_as_recovery(line, store):
    reason = install._progress_reason("some earlier line\n" + line + "\n")
    assert store in reason, f"{store} recovery not recognised in: {line}"


def test_postgres_recovery_wording_is_unchanged():
    assert "recovering from an unclean stop" in install._progress_reason(POSTGRES_RECOVERY)


@pytest.mark.parametrize("line", [OPENSEARCH_STARTUP_CRASH, OPENSEARCH_ROUTINE, KAFKA_ROUTINE])
def test_crashes_and_routine_lines_are_not_called_recovery(line):
    assert install._progress_reason(line) == ""


# ── the wording reaches the operator while compose_up waits ──────────────────

class FakeOps:
    def __init__(self, ups, states, logs):
        self.ups, self.states, self.log_text = list(ups), dict(states), logs
        self.up_calls = 0

    def up(self, build_flag):
        self.up_calls += 1
        return self.ups.pop(0) if len(self.ups) > 1 else self.ups[0]

    def inspect(self, name):
        seq = self.states[name]
        return seq.pop(0) if len(seq) > 1 else seq[0]

    def logs(self, name, n=40):
        return self.log_text


def _state(health):
    return {"state": {"Status": "running", "Restarting": False, "ExitCode": 0,
                      "Health": {"Status": health}}, "restarts": 0}


@pytest.mark.parametrize("svc,log,word", [
    ("kafka", KAFKA_UNFLUSHED, "Kafka is recovering"),
    ("clickhouse", CLICKHOUSE_ASYNC_PROGRESS, "ClickHouse is loading"),
    ("opensearch", OPENSEARCH_GATEWAY, "OpenSearch is recovering"),
])
def test_compose_up_names_the_store_that_is_healing(tmp_path, capsys, svc, log, word):
    name = f"netops-{svc}-1"
    ops = FakeOps(ups=[(1, f"dependency failed to start: container {name} is unhealthy\n"),
                       (0, "")],
                  states={name: [_state("unhealthy")] * 10 + [_state("healthy")]},
                  logs=log)
    clock = {"t": 0.0}

    def sleep(s):
        clock["t"] += max(s, 0.001)

    install.compose_up(tmp_path, offline=True, root=tmp_path, ops=ops, sleep=sleep,
                       clock=lambda: clock["t"], budget_s=900)
    out = capsys.readouterr().out
    assert word in out and "converged on pass 2" in out
