#!/usr/bin/env bash
# ch-query-budget-check.sh (#100 hardening) — enforce per-endpoint ClickHouse
# read budgets against the LIVE stack.
#
# Every API-issued ClickHouse query is stamped with log_comment=api:<path>
# (proxyClickHouse / chRows); background jobs are worker:*. This script sweeps
# system.query_log for the last WINDOW_MIN minutes and FAILS if any hot
# (api:*) endpoint breached its budget:
#
#   MEM_BUDGET_MB   max memory_usage of any single query   (default 100 MiB)
#   P95_BUDGET_MS   p95 query duration per endpoint        (default 1000 ms)
#   KILLED          any MEMORY_LIMIT_EXCEEDED kill at all  (always a failure)
#
# The incident rule this enforces: every user-facing read is bounded in rows,
# columns, time, and memory — a hot query drifting toward the 2026-07-09 shape
# (wide blob through a fold, whole-table decorate) shows up here as a memory/
# latency breach long before it becomes a platform outage.
#
# Usage: ch-query-budget-check.sh [--quiet]        (cron-able; exit 1 on breach)
# Env:   WINDOW_MIN=60 MEM_BUDGET_MB=100 P95_BUDGET_MS=1000 COMPOSE_DIR=...
set -u

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_DIR="${COMPOSE_DIR:-$DIR/../deployment/docker}"
WINDOW_MIN="${WINDOW_MIN:-60}"
MEM_BUDGET_MB="${MEM_BUDGET_MB:-100}"
P95_BUDGET_MS="${P95_BUDGET_MS:-1000}"
QUIET="${1:-}"

log()  { [ "$QUIET" = "--quiet" ] || echo "[ch-budget] $*"; }
ch() {
    docker compose --project-directory "$COMPOSE_DIR" exec -T clickhouse \
        clickhouse-client -q "$1" 2>/dev/null
}

fail=0

# 1) Per-endpoint budgets over api:* tagged queries.
BREACHES=$(ch "
SELECT log_comment,
       count()                                   AS n,
       max(memory_usage)                         AS max_mem,
       round(quantile(0.95)(query_duration_ms))  AS p95_ms
  FROM system.query_log
 WHERE event_time >= now() - INTERVAL ${WINDOW_MIN} MINUTE
   AND type = 'QueryFinish'
   AND log_comment LIKE 'api:%'
 GROUP BY log_comment
HAVING max_mem > ${MEM_BUDGET_MB} * 1048576 OR p95_ms > ${P95_BUDGET_MS}
 ORDER BY max_mem DESC
 FORMAT TSV")
if [ -n "$BREACHES" ]; then
    fail=1
    echo "[ch-budget] BUDGET BREACH (endpoint / count / max_mem_bytes / p95_ms):" >&2
    echo "$BREACHES" >&2
fi

# 2) Memory-killed queries are ALWAYS a failure — one killed query means the
#    per-query cap fired, i.e. something regressed toward the incident shape.
KILLED=$(ch "
SELECT count() FROM system.query_log
 WHERE event_time >= now() - INTERVAL ${WINDOW_MIN} MINUTE
   AND type = 'ExceptionWhileProcessing'
   AND exception_code = 241")
if [ "${KILLED:-0}" -gt 0 ] 2>/dev/null; then
    fail=1
    echo "[ch-budget] ${KILLED} MEMORY_LIMIT_EXCEEDED kill(s) in the last ${WINDOW_MIN}m" >&2
    ch "SELECT log_comment, substring(replaceRegexpAll(query,'\\\\s+',' '),1,100) AS q
          FROM system.query_log
         WHERE event_time >= now() - INTERVAL ${WINDOW_MIN} MINUTE
           AND type='ExceptionWhileProcessing' AND exception_code = 241
         ORDER BY event_time DESC LIMIT 5 FORMAT TSV" >&2
fi

# 3) Informational: top hot readers (helps spot drift before it breaches).
if [ "$QUIET" != "--quiet" ]; then
    log "top api:* readers, last ${WINDOW_MIN}m (endpoint / n / max_mem / p95_ms):"
    ch "SELECT log_comment, count(), formatReadableSize(max(memory_usage)),
               round(quantile(0.95)(query_duration_ms))
          FROM system.query_log
         WHERE event_time >= now() - INTERVAL ${WINDOW_MIN} MINUTE
           AND type='QueryFinish' AND log_comment LIKE 'api:%'
         GROUP BY log_comment ORDER BY max(memory_usage) DESC LIMIT 8 FORMAT TSV"
fi

if [ "$fail" -eq 0 ]; then
    log "OK — all api:* queries within budget (mem<${MEM_BUDGET_MB}MiB, p95<${P95_BUDGET_MS}ms, 0 kills)"
    exit 0
fi
exit 1
