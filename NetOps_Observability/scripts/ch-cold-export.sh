#!/usr/bin/env bash
# ch-cold-export.sh (#101) — TTL-to-cold for the correlation history tables.
#
# Exports CLOSED partitions (strictly older than the current one) of the
# correlation history tables to Parquet under data/clickhouse-cold/, so
# hot ClickHouse retention (corr_retention.go TTLs) deletes nothing that has
# not already been tiered. Idempotent: a partition already exported is skipped
# (its Parquet file is only replaced with --force).
#
# The cold tier is the durable input for calibration (#67 P4), audit, offline
# replay and model evaluation. Parquet is deliberately vendor-neutral: read it
# back with clickhouse-local, DuckDB, pandas, Spark… Restore into hot CH:
#   clickhouse-client -q "INSERT INTO netops.corr_signals_archive
#     SELECT * FROM file('cold/corr_signals_archive/<part>.parquet', Parquet)"
# (see docs/runbooks/correlation-retention-cold-archive.md).
#
# Cron this AHEAD of the TTL horizon. The corr_* tables are partitioned DAILY
# (toYYYYMMDD of each table's TTL column — see init.sql "STORAGE SHAPE"), so run
# it DAILY; a monthly cron would leave up to a month of days untiered:
#   17 2 * * * /path/to/scripts/ch-cold-export.sh --quiet
# The 6-digit month form is still handled, so a deployment that has not run the
# corr_repartition boot migration yet keeps exporting correctly.
#
# Usage: ch-cold-export.sh [--quiet] [--force]
# Env:   COMPOSE_DIR=… COLD_DIR=… TABLES="corr_signals_archive corr_objects corr_edges corr_evidence"
set -u

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_DIR="${COMPOSE_DIR:-$DIR/../deployment/docker}"
COLD_DIR="${COLD_DIR:-$DIR/../data/clickhouse-cold}"
TABLES="${TABLES:-corr_signals_archive corr_objects corr_edges corr_evidence}"
QUIET=0; FORCE=0
for a in "$@"; do
    case "$a" in
        --quiet) QUIET=1 ;;
        --force) FORCE=1 ;;
        *) echo "usage: $0 [--quiet] [--force]" >&2; exit 2 ;;
    esac
done
log() { [ "$QUIET" = "1" ] || echo "[cold-export] $*"; }

ch() {
    # tenant_scope=__all__: the export must carry EVERY tenant's rows (row
    # policies otherwise filter the SELECT). Runs as the CH default user inside
    # the container, same trust domain as the budget checker.
    docker compose --project-directory "$COMPOSE_DIR" exec -T clickhouse \
        clickhouse-client -q "$1" 2>/dev/null
}

fail=0
# Two buckets, because a fleet mid-upgrade has both: DAILY partitions
# (toYYYYMMDD, 8 digits) since the P2 storage-shape fix, and MONTHLY ones
# (toYYYYMM, 6 digits) on tables the re-partition migration has not reached.
# Comparing an 8-digit day against a 6-digit month would classify every day of
# the current month as "closed" (20260803 >= 202608) and export a partition
# that is still being written to.
current_day=$(date -u +%Y%m%d)
current_month=$(date -u +%Y%m)

# ClickHouse 24.8 cannot write UUID columns to Parquet (Code 50 UNKNOWN_TYPE):
# export them as strings. Restore round-trips — CH parses strings back into
# UUID columns on INSERT.
uuid_replace() {
    case "$1" in
        corr_objects) echo " REPLACE (toString(correlation_id) AS correlation_id, toString(trigger_signal) AS trigger_signal, toString(merged_into) AS merged_into)" ;;
        corr_edges) echo " REPLACE (toString(correlation_id) AS correlation_id)" ;;
        corr_evidence) echo " REPLACE (toString(correlation_id) AS correlation_id, toString(signal_id) AS signal_id)" ;;
        corr_signals_archive) echo " REPLACE (toString(signal_id) AS signal_id, toString(archived_for) AS archived_for)" ;;
        *) echo "" ;;
    esac
}

for table in $TABLES; do
    mkdir -p "$COLD_DIR/$table" || { echo "[cold-export] cannot create $COLD_DIR/$table" >&2; exit 1; }
    # Closed partitions only. NOTE: with a tuple PARTITION BY the partition_id
    # is a HASH — the date bucket must come from the human-readable `partition`
    # tuple text (e.g. ('tenant', 20260803) daily, ('tenant', 202606) monthly);
    # the WHERE below still filters by _partition_id. Export per full partition
    # so restore granularity matches drop granularity.
    # The capture is ANCHORED after the tuple's comma on purpose: the naive
    # '(\\d{6,8})' matched the FIRST run of digits anywhere in the tuple text, so a
    # tenant id like 'tenant123456' exported under its own name's digits instead
    # of its date (verified live: naive -> 123456, anchored -> 20260803).
    parts=$(ch "SELECT DISTINCT partition_id, extract(partition, ',\\\\s*(\\\\d{6,8})\\\\)') AS bucket
                  FROM system.parts
                 WHERE database='netops' AND table='${table}' AND active
                 ORDER BY partition_id FORMAT TSV")
    while IFS=$'\t' read -r pid bucket; do
        [ -z "$pid" ] && continue
        [ -z "$bucket" ] && continue                    # undated partition: skip
        case "${#bucket}" in
            8) [ "$bucket" -ge "$current_day" ] && continue ;;    # still-open day
            6) [ "$bucket" -ge "$current_month" ] && continue ;;  # still-open month
            *) echo "[cold-export] SKIPPED ${table} partition ${pid}: unrecognised date bucket '${bucket}' (expected YYYYMMDD or YYYYMM)" >&2
               fail=1; continue ;;
        esac
        out="$COLD_DIR/$table/${pid}.parquet"
        if [ -s "$out" ] && [ "$FORCE" = "0" ]; then
            continue
        fi
        tmp="${out}.tmp"
        # </dev/null: docker compose exec would otherwise eat the while-read
        # loop's remaining stdin lines (only the first partition would export).
        if ch "SELECT *$(uuid_replace "$table") FROM netops.${table} WHERE _partition_id = '${pid}'
               SETTINGS tenant_scope='__all__' FORMAT Parquet" </dev/null > "$tmp" && [ -s "$tmp" ]; then
            mv "$tmp" "$out"
            log "exported ${table} partition ${pid} ($(stat -c%s "$out") bytes)"
        else
            rm -f "$tmp"
            echo "[cold-export] FAILED: ${table} partition ${pid}" >&2
            fail=1
        fi
    done <<< "$parts"
done

if [ "$fail" = "0" ]; then
    log "OK — cold tier is current at $COLD_DIR"
    exit 0
fi
exit 1
