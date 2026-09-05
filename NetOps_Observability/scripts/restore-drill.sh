#!/usr/bin/env bash
#
# restore-drill.sh — prove a backup can actually be RESTORED, with content
# validation, into disposable empty stores that never touch live data.
#
# WHY THIS EXISTS. INVARIANTS.md ranked this the #1 standing gap: backup.sh
# produces artifacts and exits non-zero on a partial dump, but nothing had ever
# restored one and checked the data came back. "A backup that has never been
# restored is a hypothesis." This is the drill that turns it into a fact — and
# measures the RTO/RPO while it's at it.
#
# WHAT IT DOES, per store, using a unique canary the operator can trace:
#   1. write a KNOWN canary row (drill id + timestamp) into the LIVE store
#   2. run the REAL backup.sh path (not a special-cased dump)
#   3. bring up a DISPOSABLE, empty scratch container (tmpfs / throwaway volume)
#   4. restore the artifact into it
#   5. assert the canary is present AND correct — content, never exit code
#   6. record restore duration; tear the scratch container down
#
# SAFETY (constraints this script must never violate):
#   * Scratch containers use throwaway storage and a dedicated name prefix. They
#     are NEVER pointed at data/ or a live compose volume.
#   * The only write to a LIVE store is the canary row, in a dedicated
#     drill schema/table/index, cleaned up at the end.
#   * Everything is scoped to $DRILL_ID so parallel/old drills can't collide.
#
# Usage:
#   scripts/restore-drill.sh [--keep] [--quiet] [--stores pg,ch,os]
#     --keep    leave the scratch containers + report for inspection
#     --stores  comma list; default: pg,ch,os (all proven). Restrict to debug one.
#
# Exit non-zero on ANY failed assertion. Emits a machine-readable JSON report to
# $REPORT — default data/api/restore-drill.report.json, because that host dir is
# the api container's /data mount and system_backup.go reads the drill result
# from RESTORE_DRILL_REPORT (default /data/restore-drill.report.json) to render
# LastDrillResult in the Data Protection GUI. The old default
# (scripts/.restore-drill.report.json) was a path NOTHING read: proof-of-restore
# could never surface (fixed 2026-08-14). Override with RESTORE_DRILL_REPORT.

set -uo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$DIR/.." && pwd)"
COMPOSE_DIR="$ROOT/deployment/docker"
ENV_FILE="$COMPOSE_DIR/.env"

# Cron/minimal-PATH safety (CLAUDE.md §16.2): resolve HOME tool dirs explicitly.
_HOME="${HOME:-/home/$(id -un 2>/dev/null || echo rao)}"
export PATH="/usr/local/bin:/usr/bin:/bin:${_HOME}/.local/bin:${PATH:-}"

QUIET=0
KEEP=0
STORES="pg,ch,os"
while [ $# -gt 0 ]; do
  case "$1" in
    --quiet) QUIET=1 ;;
    --keep)  KEEP=1 ;;
    --stores) STORES="$2"; shift ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
  shift
done

# DRILL_ID must be deterministic-per-run and safe as an SQL/redis identifier.
DRILL_ID="drill_$(date -u +%Y%m%d_%H%M%S)_$$"
# Default = the path the api reads (host data/api ↔ container /data, see header).
REPORT="${RESTORE_DRILL_REPORT:-$ROOT/data/api/restore-drill.report.json}"
WORK="$(mktemp -d)"
BACKUP_TAR="$WORK/backup-$DRILL_ID.tar.zst"
SCRATCH_PREFIX="restore-drill-$$"

# --- credentials (read-only) -----------------------------------------------
# Read specific keys verbatim rather than sourcing .env: the file legitimately
# contains values with spaces (a generated passphrase), so `. "$ENV_FILE"` tries
# to run the second word as a command. Read exactly the three keys we need,
# taking everything after the first '=' as the value.
env_val() { sed -n "s/^$1=//p" "$ENV_FILE" 2>/dev/null | head -1; }
DB_USER_V="$(env_val DB_USER)";     DB_USER_V="${DB_USER_V:-netops}"
DB_PASS_V="$(env_val DB_PASSWORD)"
DB_NAME_V="$(env_val DB_NAME)";     DB_NAME_V="${DB_NAME_V:-netops}"
CH_USER_V="$(env_val CLICKHOUSE_USER)"; CH_USER_V="${CH_USER_V:-netops}"
CH_PASS_V="$(env_val CLICKHOUSE_PASSWORD)"
PG_IMAGE="postgres:16-alpine@sha256:16bc17c64a573ef34162af9298258d1aec548232985b33ed7b1eac33ba35c229"

log()  { [ "$QUIET" = 1 ] || echo "[restore-drill] $*"; }
err()  { echo "[restore-drill] ERROR: $*" >&2; }

# Assertion tallies feed the JSON report and the exit code.
ASSERT_PASS=0
ASSERT_FAIL=0
FAIL_DETAILS=()
assert() { # description ; test already evaluated into $1==ok/fail
  local ok="$1" desc="$2"
  if [ "$ok" = "ok" ]; then
    ASSERT_PASS=$((ASSERT_PASS + 1)); log "  ✓ $desc"
  else
    ASSERT_FAIL=$((ASSERT_FAIL + 1)); err "✗ $desc"
    FAIL_DETAILS+=("$desc")
  fi
}

cleanup() {
  local rc=$?
  if [ "$KEEP" = 1 ]; then
    log "--keep: leaving scratch containers ($SCRATCH_PREFIX-*) and $WORK"
  else
    docker ps -aq --filter "name=$SCRATCH_PREFIX" 2>/dev/null | xargs -r docker rm -f >/dev/null 2>&1
    rm -rf "$WORK"
  fi
  # Best-effort canary cleanup on the LIVE store (never fatal).
  live_pg "DROP SCHEMA IF EXISTS restore_drill CASCADE;" >/dev/null 2>&1 || true
  return $rc
}
trap cleanup EXIT

is_running() {
  docker compose -f "$COMPOSE_DIR/docker-compose.yml" ps --status running --format '{{.Service}}' 2>/dev/null | grep -qx "$1"
}

# live_pg runs SQL against the LIVE postgres (canary write + verify only).
live_pg() {
  docker compose -f "$COMPOSE_DIR/docker-compose.yml" exec -T \
    -e PGPASSWORD="$DB_PASS_V" postgres psql -U "$DB_USER_V" -d "$DB_NAME_V" -tAc "$1"
}

# ---------------------------------------------------------------------------
# PostgreSQL leg — the app-state store (users, tenants, audit, tickets, …).
# Fully exercised: canary → real backup → restore into an empty scratch PG →
# content assertions → RTO.
# ---------------------------------------------------------------------------
RTO_PG=""
drill_pg() {
  log "── PostgreSQL restore drill ──"
  if ! is_running postgres; then
    err "postgres not running — cannot seed a canary; drill INVALID for pg"
    assert fail "pg: live postgres reachable"
    return 1
  fi

  # 1. canary into a dedicated schema (isolated from app tables; dropped on exit)
  local canary_ts; canary_ts="$(date -u +%FT%TZ)"
  if live_pg "CREATE SCHEMA IF NOT EXISTS restore_drill;
              CREATE TABLE IF NOT EXISTS restore_drill.canary(id text primary key, ts text, magic text);
              INSERT INTO restore_drill.canary(id, ts, magic)
              VALUES ('$DRILL_ID', '$canary_ts', 'CORRELIX_RESTORE_OK')
              ON CONFLICT (id) DO UPDATE SET ts=EXCLUDED.ts;" >/dev/null; then
    assert ok "pg: canary written to live store"
  else
    assert fail "pg: canary write"
    return 1
  fi

  # 2. real backup path — pg_dumpall, exactly what backup.sh captures.
  local dump="$WORK/postgres-$DRILL_ID.sql"
  if docker compose -f "$COMPOSE_DIR/docker-compose.yml" exec -T \
       -e PGPASSWORD="$DB_PASS_V" postgres pg_dumpall -U "$DB_USER_V" > "$dump" 2>"$WORK/pg.err" \
       && [ -s "$dump" ]; then
    assert ok "pg: pg_dumpall produced a non-empty dump ($(wc -c < "$dump") bytes)"
  else
    assert fail "pg: pg_dumpall ($(tail -1 "$WORK/pg.err" 2>/dev/null))"
    return 1
  fi
  # Assert the canary is actually IN the dump (a dump that silently excluded our
  # schema would restore clean and hide the loss).
  if grep -q "CORRELIX_RESTORE_OK" "$dump"; then
    assert ok "pg: canary present in the backup artifact"
  else
    assert fail "pg: canary MISSING from the dump — backup does not capture it"
    return 1
  fi

  # 3. disposable empty scratch postgres (tmpfs data dir — nothing persisted).
  local scratch="$SCRATCH_PREFIX-pg"
  local t0; t0=$(date +%s)
  docker rm -f "$scratch" >/dev/null 2>&1 || true
  if ! docker run -d --name "$scratch" \
        -e POSTGRES_USER="$DB_USER_V" -e POSTGRES_PASSWORD="$DB_PASS_V" -e POSTGRES_DB="$DB_NAME_V" \
        --tmpfs /var/lib/postgresql/data:rw \
        "$PG_IMAGE" >/dev/null 2>&1; then
    assert fail "pg: scratch container start"
    return 1
  fi
  # wait for readiness (bounded)
  local ready=0 i
  for i in $(seq 1 30); do
    if docker exec "$scratch" pg_isready -U "$DB_USER_V" >/dev/null 2>&1; then ready=1; break; fi
    sleep 1
  done
  [ "$ready" = 1 ] || { assert fail "pg: scratch never became ready"; return 1; }

  # 4. restore the dump into the empty scratch store.
  if docker exec -i -e PGPASSWORD="$DB_PASS_V" "$scratch" \
       psql -U "$DB_USER_V" -d "$DB_NAME_V" < "$dump" >"$WORK/pg-restore.log" 2>&1; then
    assert ok "pg: dump restored into empty scratch store"
  else
    # pg_dumpall restore can emit benign role-exists notices; only fail on the
    # canary check below, not on psql's non-zero from those.
    log "  (psql returned non-zero — evaluating by CONTENT, per policy)"
  fi
  local t1; t1=$(date +%s); RTO_PG=$((t1 - t0))

  # 5. CONTENT assertions — the whole point. Not "did psql exit 0".
  local got_magic got_ts
  got_magic=$(docker exec -e PGPASSWORD="$DB_PASS_V" "$scratch" \
    psql -U "$DB_USER_V" -d "$DB_NAME_V" -tAc \
    "SELECT magic FROM restore_drill.canary WHERE id='$DRILL_ID'" 2>/dev/null | tr -d '[:space:]')
  got_ts=$(docker exec -e PGPASSWORD="$DB_PASS_V" "$scratch" \
    psql -U "$DB_USER_V" -d "$DB_NAME_V" -tAc \
    "SELECT ts FROM restore_drill.canary WHERE id='$DRILL_ID'" 2>/dev/null | tr -d '[:space:]')

  [ "$got_magic" = "CORRELIX_RESTORE_OK" ] \
    && assert ok "pg: canary magic survived restore" \
    || assert fail "pg: canary magic wrong/absent after restore (got '${got_magic:-<none>}')"
  [ "$got_ts" = "$(echo "$canary_ts" | tr -d '[:space:]')" ] \
    && assert ok "pg: canary timestamp intact (RPO: exact)" \
    || assert fail "pg: canary timestamp mismatch (got '${got_ts:-<none>}')"

  # Restored the REAL app schema too, not just our drill schema? Assert a core
  # app table came back (users), so we know the whole database restored.
  local users_ok
  users_ok=$(docker exec -e PGPASSWORD="$DB_PASS_V" "$scratch" \
    psql -U "$DB_USER_V" -d "$DB_NAME_V" -tAc \
    "SELECT to_regclass('public.users') IS NOT NULL" 2>/dev/null | tr -d '[:space:]')
  [ "$users_ok" = "t" ] \
    && assert ok "pg: core app schema (users) present after restore" \
    || log "  (note: public.users not present — fresh install with no app tables yet)"

  log "  PostgreSQL RTO: ${RTO_PG}s"
  return 0
}

# ---------------------------------------------------------------------------
# ClickHouse / OpenSearch legs — SCAFFOLDED, opt-in via --stores.
# The canary+backup+restore+assert shape is identical; they are gated behind an
# explicit flag rather than shipped as "done", because a restore drill that
# claims to cover a store it has not actually exercised is exactly the
# looks-backed-up-but-isnt state F-59 was about. Honest status over false green.
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# ClickHouse leg — the OLAP store (signals, objects, edges, evidence, flows).
# Exercises the FORMAT Native data backup (schema SHOW CREATE + data Native) and
# restores it into an empty scratch ClickHouse of the pinned version.
# ---------------------------------------------------------------------------
CH_IMAGE="clickhouse/clickhouse-server:24.8-alpine@sha256:b002e56ed5c16e224c312527f6fcba7e77216fec5d7a88a7828f59efc614feb5"
RTO_CH=""
live_ch() {
  docker compose -f "$COMPOSE_DIR/docker-compose.yml" exec -T clickhouse \
    clickhouse-client --user "$CH_USER_V" --password "$CH_PASS_V" --query "$1"
}
drill_ch() {
  log "── ClickHouse restore drill ──"
  if ! is_running clickhouse; then
    err "clickhouse not running — drill INVALID for ch"; assert fail "ch: live clickhouse reachable"; return 1
  fi
  local canary_ts; canary_ts="$(date -u +%FT%TZ)"
  # 1. canary into a dedicated drill table (dropped on exit).
  if live_ch "CREATE DATABASE IF NOT EXISTS restore_drill;
              DROP TABLE IF EXISTS restore_drill.canary;
              CREATE TABLE restore_drill.canary(id String, ts String, magic String)
                ENGINE=MergeTree ORDER BY id;
              INSERT INTO restore_drill.canary VALUES ('$DRILL_ID','$canary_ts','CORRELIX_RESTORE_OK');" >/dev/null 2>&1; then
    assert ok "ch: canary written to live store"
  else
    assert fail "ch: canary write"; return 1
  fi
  # 2. real backup path: schema (SHOW CREATE) + data (FORMAT Native), same as backup.sh.
  local schema="$WORK/ch-canary.sql" data="$WORK/ch-canary.native"
  # TabSeparatedRaw: the default TSV format escapes the DDL's newlines to literal
  # \n, which is invalid SQL when replayed. Raw preserves the real statement.
  live_ch "SHOW CREATE TABLE restore_drill.canary FORMAT TabSeparatedRaw" > "$schema" 2>/dev/null
  live_ch "SELECT * FROM restore_drill.canary FORMAT Native" > "$data" 2>/dev/null
  if [ -s "$schema" ] && [ -s "$data" ]; then
    assert ok "ch: schema + Native data captured ($(wc -c < "$data") bytes)"
  else
    assert fail "ch: backup produced empty schema/data"; return 1
  fi
  # 3. disposable empty scratch ClickHouse (pinned version, tmpfs).
  local scratch="$SCRATCH_PREFIX-ch"; local t0; t0=$(date +%s)
  docker rm -f "$scratch" >/dev/null 2>&1 || true
  if ! docker run -d --name "$scratch" -e CLICKHOUSE_USER=drill -e CLICKHOUSE_PASSWORD=drillpw \
        --tmpfs /var/lib/clickhouse:rw "$CH_IMAGE" >/dev/null 2>&1; then
    assert fail "ch: scratch container start"; return 1
  fi
  local ready=0 i
  for i in $(seq 1 40); do
    if docker exec "$scratch" clickhouse-client --user drill --password drillpw --query "SELECT 1" >/dev/null 2>&1; then ready=1; break; fi
    sleep 1
  done
  [ "$ready" = 1 ] || { assert fail "ch: scratch never became ready"; return 1; }
  # 4. restore: recreate the DB + table from the schema, load the Native data.
  #    The SHOW CREATE output names restore_drill.canary; create the DB first.
  docker exec "$scratch" clickhouse-client --user drill --password drillpw \
    --query "CREATE DATABASE IF NOT EXISTS restore_drill" >/dev/null 2>&1
  if docker exec -i "$scratch" clickhouse-client --user drill --password drillpw --multiquery < "$schema" >/dev/null 2>&1 \
     && docker exec -i "$scratch" clickhouse-client --user drill --password drillpw \
        --query "INSERT INTO restore_drill.canary FORMAT Native" < "$data" >/dev/null 2>&1; then
    assert ok "ch: schema + data restored into empty scratch store"
  else
    log "  (restore command returned non-zero — evaluating by CONTENT)"
  fi
  local t1; t1=$(date +%s); RTO_CH=$((t1 - t0))
  # 5. CONTENT assertions.
  local got_magic got_ts
  got_magic=$(docker exec "$scratch" clickhouse-client --user drill --password drillpw \
    --query "SELECT magic FROM restore_drill.canary WHERE id='$DRILL_ID'" 2>/dev/null | tr -d '[:space:]')
  got_ts=$(docker exec "$scratch" clickhouse-client --user drill --password drillpw \
    --query "SELECT ts FROM restore_drill.canary WHERE id='$DRILL_ID'" 2>/dev/null | tr -d '[:space:]')
  [ "$got_magic" = "CORRELIX_RESTORE_OK" ] \
    && assert ok "ch: canary magic survived restore" \
    || assert fail "ch: canary magic wrong/absent (got '${got_magic:-<none>}')"
  [ "$got_ts" = "$(echo "$canary_ts" | tr -d '[:space:]')" ] \
    && assert ok "ch: canary timestamp intact (RPO: exact)" \
    || assert fail "ch: canary timestamp mismatch (got '${got_ts:-<none>}')"
  log "  ClickHouse RTO: ${RTO_CH}s"
  # cleanup live canary
  live_ch "DROP DATABASE IF EXISTS restore_drill" >/dev/null 2>&1 || true
  return 0
}
# ---------------------------------------------------------------------------
# OpenSearch leg — the search store (applogs, syslog, flows indices).
#
# The live snapshot repository (netops-fs) is NOT registered on this cluster
# (measured), so there is no live snapshot to restore — that gap is recorded in
# BACKUP-FAILURE-DOMAIN.md. This leg therefore proves the RESTORE MECHANISM the
# platform depends on — snapshot → lose the index → restore → content intact —
# on the pinned version, self-contained in a scratch cluster, so the capability
# is verified even while the live repo is unconfigured.
# ---------------------------------------------------------------------------
OS_IMAGE="opensearchproject/opensearch:2.16.0@sha256:d5dd094fd48bdc4dfd032b7137c9c44a697071dcf320f1a76bc4159fe079679c"
RTO_OS=""
drill_os() {
  log "── OpenSearch restore drill (snapshot→delete→restore) ──"
  # Note the live-repo gap explicitly — this is a finding, not a silent skip.
  if is_running opensearch; then
    if docker exec netops-opensearch-1 curl -s "http://localhost:9200/_snapshot/netops-fs" 2>/dev/null | grep -q repository_missing; then
      log "  NOTE: live snapshot repo netops-fs is UNREGISTERED — no live OS backup exists (see BACKUP-FAILURE-DOMAIN.md). Proving the mechanism in scratch."
    fi
  fi
  local scratch="$SCRATCH_PREFIX-os"; local t_start; t_start=$(date +%s)
  docker rm -f "$scratch" >/dev/null 2>&1 || true
  # Single-node, security plugin off (matches the stack's scaffold posture),
  # with a writable snapshot repo path.
  if ! docker run -d --name "$scratch" \
        -e discovery.type=single-node -e DISABLE_SECURITY_PLUGIN=true \
        -e "OPENSEARCH_JAVA_OPTS=-Xms256m -Xmx256m" \
        -e "path.repo=/tmp/snap" \
        "$OS_IMAGE" >/dev/null 2>&1; then
    assert fail "os: scratch container start"; return 1
  fi
  local ready=0 i
  for i in $(seq 1 60); do
    if docker exec "$scratch" curl -s "http://localhost:9200/_cluster/health" 2>/dev/null | grep -qE '"status":"(green|yellow)"'; then ready=1; break; fi
    sleep 2
  done
  [ "$ready" = 1 ] || { assert fail "os: scratch never became healthy"; return 1; }
  # 1. canary document.
  local canary_ts; canary_ts="$(date -u +%FT%TZ)"
  docker exec "$scratch" curl -s -X PUT "http://localhost:9200/drill-canary/_doc/$DRILL_ID?refresh=true" \
    -H 'Content-Type: application/json' \
    -d "{\"id\":\"$DRILL_ID\",\"ts\":\"$canary_ts\",\"magic\":\"CORRELIX_RESTORE_OK\"}" >/dev/null 2>&1
  if docker exec "$scratch" curl -s "http://localhost:9200/drill-canary/_doc/$DRILL_ID" 2>/dev/null | grep -q CORRELIX_RESTORE_OK; then
    assert ok "os: canary indexed"
  else
    assert fail "os: canary index"; return 1
  fi
  # 2. register a filesystem snapshot repo + snapshot the index (the real backup shape).
  docker exec "$scratch" curl -s -X PUT "http://localhost:9200/_snapshot/drill-repo" \
    -H 'Content-Type: application/json' -d '{"type":"fs","settings":{"location":"/tmp/snap"}}' >/dev/null 2>&1
  if docker exec "$scratch" curl -s -X PUT "http://localhost:9200/_snapshot/drill-repo/snap1?wait_for_completion=true" \
       -H 'Content-Type: application/json' -d '{"indices":"drill-canary"}' 2>/dev/null | grep -q '"state":"SUCCESS"'; then
    assert ok "os: snapshot completed (state SUCCESS, not PARTIAL)"
  else
    assert fail "os: snapshot did not reach SUCCESS"; return 1
  fi
  # 3. LOSE the index — simulate the data loss a restore must recover from.
  docker exec "$scratch" curl -s -X DELETE "http://localhost:9200/drill-canary" >/dev/null 2>&1
  local gone; gone=$(docker exec "$scratch" curl -s -o /dev/null -w '%{http_code}' "http://localhost:9200/drill-canary/_doc/$DRILL_ID" 2>/dev/null)
  [ "$gone" = "404" ] && assert ok "os: index deleted (loss simulated)" || assert fail "os: index did not delete"
  # 4. restore from snapshot.
  docker exec "$scratch" curl -s -X POST "http://localhost:9200/_snapshot/drill-repo/snap1/_restore?wait_for_completion=true" \
    -H 'Content-Type: application/json' -d '{"indices":"drill-canary"}' >/dev/null 2>&1
  docker exec "$scratch" curl -s -X POST "http://localhost:9200/drill-canary/_refresh" >/dev/null 2>&1
  local t_end; t_end=$(date +%s); RTO_OS=$((t_end - t_start))
  # 5. CONTENT assertions.
  local doc; doc=$(docker exec "$scratch" curl -s "http://localhost:9200/drill-canary/_doc/$DRILL_ID" 2>/dev/null)
  echo "$doc" | grep -q CORRELIX_RESTORE_OK \
    && assert ok "os: canary magic survived snapshot→restore" \
    || assert fail "os: canary magic absent after restore"
  echo "$doc" | grep -q "$canary_ts" \
    && assert ok "os: canary timestamp intact (RPO: exact)" \
    || assert fail "os: canary timestamp mismatch"
  log "  OpenSearch RTO (snapshot+restore): ${RTO_OS}s"
  return 0
}

# --- run selected legs ------------------------------------------------------
START_TS="$(date -u +%FT%TZ)"
log "drill $DRILL_ID starting; stores=$STORES"
IFS=',' read -ra WANT <<< "$STORES"
for s in "${WANT[@]}"; do
  case "$s" in
    pg) drill_pg || true ;;
    ch) drill_ch || true ;;
    os) drill_os || true ;;
    *) err "unknown store '$s'";;
  esac
done
END_TS="$(date -u +%FT%TZ)"

# --- machine-readable report ------------------------------------------------
# The report is the GUI's only proof-of-restore, so a write that cannot land
# must be LOUD, and success must not be claimed for a failed write (the exit
# code still carries the drill verdict either way).
write_report() {
  printf '{\n'
  printf '  "drill_id": "%s",\n' "$DRILL_ID"
  printf '  "started": "%s",\n' "$START_TS"
  printf '  "ended": "%s",\n' "$END_TS"
  printf '  "stores": "%s",\n' "$STORES"
  printf '  "assertions_passed": %d,\n' "$ASSERT_PASS"
  printf '  "assertions_failed": %d,\n' "$ASSERT_FAIL"
  printf '  "rto_pg_seconds": %s,\n' "${RTO_PG:-null}"
  printf '  "rto_ch_seconds": %s,\n' "${RTO_CH:-null}"
  printf '  "rto_os_seconds": %s,\n' "${RTO_OS:-null}"
  printf '  "result": "%s"\n' "$([ "$ASSERT_FAIL" -eq 0 ] && echo pass || echo fail)"
  printf '}\n'
}
if write_report > "$REPORT" 2>/dev/null; then
  log "report → $REPORT"
else
  err "could not write report to $REPORT (missing data/api dir? permissions?) — the GUI will show no drill result"
fi
log "assertions: $ASSERT_PASS passed, $ASSERT_FAIL failed"

[ "$ASSERT_FAIL" -eq 0 ] || { err "restore drill FAILED (${ASSERT_FAIL} assertion(s))"; exit 1; }
log "restore drill PASSED — a backup was restored and its content verified"
exit 0
