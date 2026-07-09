#!/usr/bin/env bash
# ch-cold-restore.sh (#101) — restore cold Parquet history into an ISOLATED
# side database, without disturbing hot production.
#
# Why a side database (netops_restore) and never the live tables:
#   1. Hot tables carry retention TTLs — restored rows are older than the
#      horizon BY DEFINITION, so ClickHouse would re-drop them on the next
#      TTL check (a restore into netops.* silently evaporates).
#   2. Hot tables serve Command Center under read budgets; a multi-month
#      restore insert + the follow-up analyst queries belong in a workload
#      that cannot touch those budgets.
#   3. An analyst/auditor can be granted the side DB without any risk of
#      writing to production history (append-only truth stays truthful).
#
# Tenant granularity is native: the corr tables are partitioned by
# (tenant_id, month), so every cold Parquet file is ONE tenant's ONE month —
# single-tenant restore is file selection, not row filtering.
#
# Usage:
#   ch-cold-restore.sh --table corr_signals_archive [--tenant acme] [--month 202606] [--drop]
#   --tenant  restore only this tenant's partitions ('' = platform/untagged)
#   --month   restore only this YYYYMM
#   --drop    drop + recreate the side table first (clean slate)
#   Omitting both filters restores every exported partition of the table.
#
# The side table netops_restore.<table> is created LIKE the live table but
# WITHOUT TTL (SET ttl = '') so restored history persists until you drop it.
# Query it like any table; when done: DROP TABLE netops_restore.<table>.
#
# Scenarios (docs/runbooks/correlation-retention-cold-archive.md):
#   single-tenant restore:   --table corr_objects --tenant acme
#   single-month restore:    --table corr_signals_archive --month 202606
#   calibration-only:        no restore needed — read the Parquet directly
#                            (clickhouse-local/DuckDB); restore only if the
#                            calibration job needs SQL against the cluster.
#   replay from cold:        restore the object's months of
#                            corr_signals_archive (+ corr_objects for the
#                            snapshot row), then run the replay tooling
#                            against netops_restore.
set -u

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_DIR="${COMPOSE_DIR:-$DIR/../deployment/docker}"
COLD_DIR="${COLD_DIR:-$DIR/../data/clickhouse-cold}"

TABLE="" TENANT="__any__" MONTH="" DROP=0
while [ $# -gt 0 ]; do
    case "$1" in
        --table)  TABLE="$2"; shift 2 ;;
        --tenant) TENANT="$2"; shift 2 ;;
        --month)  MONTH="$2"; shift 2 ;;
        --drop)   DROP=1; shift ;;
        *) echo "usage: $0 --table <corr_table> [--tenant t] [--month YYYYMM] [--drop]" >&2; exit 2 ;;
    esac
done
case "$TABLE" in
    corr_signals_archive|corr_objects|corr_edges|corr_evidence) ;;
    *) echo "[cold-restore] --table must be one of the exported corr tables" >&2; exit 2 ;;
esac

ch() {
    docker compose --project-directory "$COMPOSE_DIR" exec -T clickhouse \
        clickhouse-client -q "$1" </dev/null
}

# Map (tenant, month) filters to partition_ids via LIVE metadata when the
# partition still exists hot; otherwise fall back to restoring every file and
# filtering rows by tenant/ts after load. Simplest robust path: restore every
# candidate file, filter tenant/month at INSERT time (Parquet is columnar —
# the filter is cheap).
FILES=$(find "$COLD_DIR/$TABLE" -name '*.parquet' 2>/dev/null | sort)
if [ -z "$FILES" ]; then
    echo "[cold-restore] no Parquet files under $COLD_DIR/$TABLE" >&2
    exit 1
fi

ch "CREATE DATABASE IF NOT EXISTS netops_restore" || exit 1
if [ "$DROP" = "1" ]; then
    ch "DROP TABLE IF EXISTS netops_restore.${TABLE}"
fi
# LIKE the live table, minus TTL (restored history must not re-expire).
ch "CREATE TABLE IF NOT EXISTS netops_restore.${TABLE} AS netops.${TABLE}" || exit 1
ch "ALTER TABLE netops_restore.${TABLE} REMOVE TTL" 2>/dev/null || true

TS_COL="ts"; case "$TABLE" in corr_objects) TS_COL="window_start";; corr_edges|corr_evidence) TS_COL="created_at";; esac
COND="1"
[ "$TENANT" != "__any__" ] && COND="$COND AND tenant_id = '$(echo "$TENANT" | tr -d "'\\\\")'"
[ -n "$MONTH" ] && COND="$COND AND toYYYYMM(${TS_COL}) = ${MONTH}"

docker compose --project-directory "$COMPOSE_DIR" exec -T clickhouse \
    mkdir -p /var/lib/clickhouse/user_files/coldrestore </dev/null

restored=0
for f in $FILES; do
    # file() is sandboxed to user_files — stage the Parquet there, remove after.
    base="/var/lib/clickhouse/user_files/coldrestore/$(basename "$f")"
    docker cp "$f" "$(docker compose --project-directory "$COMPOSE_DIR" ps -q clickhouse)":"$base" </dev/null || { echo "[cold-restore] copy failed: $f" >&2; exit 1; }
    # Column names/order match the export exactly (UUIDs travel as strings;
    # ClickHouse parses them back into UUID columns on insert).
    if ch "INSERT INTO netops_restore.${TABLE}
           SELECT * FROM file('${base}', Parquet) WHERE ${COND}
           SETTINGS tenant_scope='__all__'"; then
        restored=$((restored+1))
    else
        echo "[cold-restore] insert failed for $f" >&2
        exit 1
    fi
    ch "SELECT 1" >/dev/null 2>&1  # keepalive/no-op
    docker compose --project-directory "$COMPOSE_DIR" exec -T clickhouse rm -f "$base" </dev/null
done

ROWS=$(ch "SELECT count() FROM netops_restore.${TABLE} WHERE ${COND} SETTINGS tenant_scope='__all__'")
echo "[cold-restore] netops_restore.${TABLE}: ${ROWS} rows matching (tenant=${TENANT}, month=${MONTH:-any}) from ${restored} file(s)"
echo "[cold-restore] query it via netops_restore.${TABLE}; DROP TABLE it when done"
