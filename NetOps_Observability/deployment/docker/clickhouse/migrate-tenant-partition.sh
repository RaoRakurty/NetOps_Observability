#!/usr/bin/env sh
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

# migrate-tenant-partition.sh — #20 Phase 3 (ClickHouse at-rest separation).
#
# Rebuilds the live netops.{flows,findings,tunnels} tables so tenant_id leads the
# PARTITION BY key (matching clickhouse/init.sql for fresh installs). Each tenant's
# data then lives in its own physical parts — independently droppable, backup-able,
# and per-tenant encryptable (ties into #16).
#
# Safe + idempotent:
#   * Skips a table that is already keyed on tenant_id (re-run = no-op).
#   * Preserves data: copies into a v2 table, then EXCHANGE TABLES (atomic swap),
#     then drops the old. Row policies are keyed by table NAME, so they survive the
#     swap; the Go API also self-heals them on start (ensureCHRowPolicies).
#   * Derives DDL from SHOW CREATE TABLE, so it can't drift from the real schema —
#     only the PARTITION BY clause and table name are rewritten.
#
# Run it against the live stack (data is 30-day-TTL ephemeral telemetry, so the
# rebuild is low-risk):
#   docker compose exec -T clickhouse sh -s < clickhouse/migrate-tenant-partition.sh
#
# Or from inside the container: sh /path/to/migrate-tenant-partition.sh
set -eu

DB="${CLICKHOUSE_DB:-netops}"
CH="clickhouse-client"
# Auth, if the image enforces it (init.sql runs as default; creds come from env).
[ -n "${CLICKHOUSE_USER:-}" ] && CH="$CH --user ${CLICKHOUSE_USER}"
[ -n "${CLICKHOUSE_PASSWORD:-}" ] && CH="$CH --password ${CLICKHOUSE_PASSWORD}"

q() { $CH --database "$DB" -q "$1"; }

for tbl in flows findings tunnels; do
  exists=$(q "EXISTS TABLE ${DB}.${tbl}" || echo 0)
  if [ "$exists" != "1" ]; then
    echo "migrate: ${tbl} — table absent, skipping (init.sql will create it correctly)"
    continue
  fi

  pk=$(q "SELECT partition_key FROM system.tables WHERE database='${DB}' AND name='${tbl}'")
  case "$pk" in
    *tenant_id*)
      echo "migrate: ${tbl} — already keyed on tenant_id, skipping"
      continue
      ;;
  esac

  echo "migrate: ${tbl} — rebuilding with PARTITION BY (tenant_id, toYYYYMMDD(ts))"
  # Clean up any leftover v2 from an aborted run.
  q "DROP TABLE IF EXISTS ${DB}.${tbl}_v2 SYNC"

  # Take the current DDL, retarget it to <tbl>_v2 and prepend tenant_id to the
  # partition key. SHOW CREATE renders the old key as `PARTITION BY toYYYYMMDD(ts)`.
  # TabSeparatedRaw keeps the real newlines (default TSV escapes them to literal \n,
  # which then fails to parse when fed back).
  ddl=$($CH --database "$DB" --format TabSeparatedRaw -q "SHOW CREATE TABLE ${DB}.${tbl}" \
    | sed "s/CREATE TABLE ${DB}\\.${tbl}/CREATE TABLE ${DB}.${tbl}_v2/" \
    | sed "s/PARTITION BY toYYYYMMDD(ts)/PARTITION BY (tenant_id, toYYYYMMDD(ts))/")
  echo "$ddl" | $CH --database "$DB" --multiquery

  # Reading the source table triggers its tenant row policy (USING
  # getSetting('tenant_scope')); set the scope to __all__ so the copy sees every
  # tenant's rows (and so an unset custom setting isn't an UNKNOWN_SETTING error).
  q "INSERT INTO ${DB}.${tbl}_v2 SELECT * FROM ${DB}.${tbl} SETTINGS tenant_scope='__all__'"
  q "EXCHANGE TABLES ${DB}.${tbl} AND ${DB}.${tbl}_v2"
  q "DROP TABLE ${DB}.${tbl}_v2 SYNC"
  echo "migrate: ${tbl} — done"
done

echo "migrate: tenant-partition migration complete."
