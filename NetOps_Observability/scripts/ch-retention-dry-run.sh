#!/usr/bin/env bash
# ch-retention-dry-run.sh (#101) — preview EXACTLY what the correlation
# retention contract would drop, before (or after) enabling it. Read-only.
#
# Retention is applied by the API boot converge (corr_retention.go) as
# metadata-only TTLs with ttl_only_drop_parts=1: whole month-partitions age
# out when their NEWEST row passes the horizon. This script mirrors that rule
# against system.parts and reports, per table:
#   - configured TTL (from ClickHouse metadata, i.e. what is actually live)
#   - parts/rows/bytes already past the horizon (would drop on next TTL check)
#   - the next partition to expire and when
#   - cold-export coverage: whether data/clickhouse-cold has a Parquet file
#     for every month-partition inside the drop horizon (see ch-cold-export.sh)
#
# Usage: ch-retention-dry-run.sh
# Env:   COMPOSE_DIR=… COLD_DIR=…  (defaults match the standard layout)
set -u

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_DIR="${COMPOSE_DIR:-$DIR/../deployment/docker}"
COLD_DIR="${COLD_DIR:-$DIR/../data/clickhouse-cold}"

ch() {
    docker compose --project-directory "$COMPOSE_DIR" exec -T clickhouse \
        clickhouse-client -q "$1" 2>/dev/null
}

echo "== live TTL metadata (what the converge actually applied) =="
ch "SELECT name, engine_full LIKE '%TTL%' AS has_ttl,
           extract(create_table_query, 'TTL ([^S]+?)(?: SETTINGS|$)') AS ttl_expr
      FROM system.tables
     WHERE database='netops' AND name LIKE 'corr%' AND engine LIKE '%MergeTree%'
     ORDER BY name FORMAT PrettyCompact"

echo
echo "== per-table expiry preview (part-level, mirrors ttl_only_drop_parts) =="
for spec in "corr_objects:created_at" "corr_edges:created_at" "corr_evidence:created_at" "corr_signals_archive:ts" "corr_tenant_write_amp:window_start"; do
    table="${spec%%:*}"
    # ClickHouse normalizes "INTERVAL 90 DAY" to "toIntervalDay(90)" in metadata.
    ttl_days=$(ch "SELECT extract(create_table_query, 'toIntervalDay\\\\((\\\\d+)\\\\)') FROM system.tables WHERE database='netops' AND name='${table}'")
    if [ -z "${ttl_days}" ]; then
        echo "-- ${table}: NO TTL configured (grows until one is set — see corr_retention.go)"
        continue
    fi
    echo "-- ${table}: TTL ${ttl_days}d — parts whose newest row is already past the horizon:"
    ch "SELECT partition, rows, formatReadableSize(bytes_on_disk) AS size,
               max_time AS newest_row
          FROM system.parts
         WHERE database='netops' AND table='${table}' AND active
           AND max_time < now() - INTERVAL ${ttl_days} DAY
         ORDER BY partition FORMAT PrettyCompact"
    ch "SELECT count() AS parts_past_horizon, sum(rows) AS rows_past_horizon,
               formatReadableSize(sum(bytes_on_disk)) AS would_free
          FROM system.parts
         WHERE database='netops' AND table='${table}' AND active
           AND max_time < now() - INTERVAL ${ttl_days} DAY FORMAT PrettyCompact"
    echo "   next to expire:"
    ch "SELECT partition, max_time AS newest_row,
               toString(max_time + INTERVAL ${ttl_days} DAY) AS drops_after
          FROM system.parts
         WHERE database='netops' AND table='${table}' AND active
         GROUP BY partition, max_time
         ORDER BY max_time ASC LIMIT 1 FORMAT PrettyCompact"
done

echo
echo "== cold-export coverage (Parquet must lead the TTL horizon) =="
if [ -d "$COLD_DIR" ]; then
    find "$COLD_DIR" -name '*.parquet' -printf '%P\t%s bytes\n' | sort
else
    echo "NO cold export directory at $COLD_DIR — run scripts/ch-cold-export.sh"
    echo "(or accept that expired partitions are deleted, not tiered — see"
    echo " docs/runbooks/correlation-retention-cold-archive.md)"
fi
