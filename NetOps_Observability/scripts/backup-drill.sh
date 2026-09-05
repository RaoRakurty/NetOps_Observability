#!/usr/bin/env bash
#
# backup-drill.sh — prove that a BUNDLE ARTIFACT restores.
#
# ---------------------------------------------------------------------------
# WHY THIS EXISTS, AND HOW IT DIFFERS FROM restore-drill.sh
#
# scripts/restore-drill.sh proves the MECHANISM: it writes a canary into the
# live stores, dumps them the way backup.sh dumps them, restores into scratch
# containers and checks the canary came back. That is a real proof and it stays.
#
# It is not the proof an operator needs at 02:00 after losing the host. At that
# moment they hold ONE FILE — correlix-YYYYMMDD.tar.zst — and the only question
# is whether that file, the one that actually exists, restores. Nothing had ever
# opened a bundle and put it back. Every coverage row said so in as many words:
# "no restorability proof: nothing in this product has restored a pg_dumpall
# from a bundle and compared it to the live database."
#
# This script is that proof, per store, against a real artifact:
#
#   postgres         extract postgres.sql -> restore into a DISPOSABLE scratch
#                    Postgres -> compare the restored table set and row counts
#                    against the LIVE database
#   clickhouse       extract the schema + per-table FORMAT Native dumps ->
#                    replay both into a DISPOSABLE scratch ClickHouse ->
#                    compare row counts against the LIVE database
#   victoriametrics  extract the VictoriaMetrics snapshot -> start a THROWAWAY
#                    vmsingle on top of it -> read the metric names back out and
#                    query one series
#   sealed_material  decrypt the custody envelope with BACKUP_SEALED_PASSPHRASE
#                    -> verify every file against the sha256 manifest that
#                    shipped beside it
#
# EVERY temporary is deleted: scratch containers by name prefix, the extraction
# tree by path. --keep suspends that for debugging and says so.
#
# SAFETY (constraints this script must never violate, §16.3):
#   * It NEVER writes to a live store. The live stores are read for COUNTS only.
#   * Scratch containers use throwaway storage (tmpfs / a directory under the
#     work dir) and a dedicated name prefix. They are never pointed at data/.
#   * It never prints BACKUP_SEALED_PASSPHRASE, and never writes it to a file.
#     The passphrase reaches openssl through the ENVIRONMENT, never argv.
#
# HONEST VERDICTS (§16.1). A leg that could not run is "skip", never "pass".
# The exit code is non-zero when any leg FAILED; a run made entirely of skips
# exits non-zero too, because a drill that proved nothing is not a passing
# drill — it is a drill that did not happen.
#
# Usage:
#   scripts/backup-drill.sh [--bundle <file.tar.zst>] [--legs pg,ch,vm,sealed]
#                           [--keep] [--quiet] [--report <path>]
#
# Report: $BACKUP_DRILL_REPORT, default data/api/backup-drill.report.json —
# the host side of the api container's /data mount, which is where
# internal/dataprotect reads it from (Deps.BackupDrillReportPath) to fill each
# engine's last_verified on the Data Protection page.
# ---------------------------------------------------------------------------

# NOT -e: a failing assertion must be RECORDED and the remaining legs must still
# run, exactly as restore-drill.sh does. Failures are tallied and become the
# exit code at the end.
set -uo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$DIR/.." && pwd)"
COMPOSE_DIR="$ROOT/deployment/docker"
ENV_FILE="$COMPOSE_DIR/.env"

# §16.2 — cron gives PATH=/usr/bin:/bin only, and docker/zstd live in
# /usr/local/bin on most hosts. HOME may be unset.
_HOME="${HOME:-$(getent passwd "$(id -u)" 2>/dev/null | cut -d: -f6)}"
_HOME="${_HOME:-/tmp}"
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:${_HOME}/.local/bin"

# Everything this run writes is operator-only: it stages a pg_dumpall and a
# DECRYPTED custody tree on disk.
umask 077

QUIET=0
KEEP=0
LEGS="pg,ch,vm,sealed"
BUNDLE=""
REPORT="${BACKUP_DRILL_REPORT:-$ROOT/data/api/backup-drill.report.json}"
while [ $# -gt 0 ]; do
  case "$1" in
    --bundle) BUNDLE="${2:-}"; shift ;;
    --legs)   LEGS="${2:-}";   shift ;;
    --report) REPORT="${2:-}"; shift ;;
    --keep)   KEEP=1 ;;
    --quiet)  QUIET=1 ;;
    -h|--help)
      sed -n '2,60p' "${BASH_SOURCE[0]}"
      exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
  shift
done

DRILL_ID="backup-drill_$(date -u +%Y%m%d_%H%M%S)_$$"
SCRATCH_PREFIX="backup-drill-$$"
WORK="$(mktemp -d -t netops-backup-drill-XXXXXX)"
EXTRACT="$WORK/bundle"

log() { [ "$QUIET" = 1 ] || echo "[backup-drill] $*"; }
err() { echo "[backup-drill] ERROR: $*" >&2; }

# --- pinned scratch images -------------------------------------------------
# Digest-pinned, and the SAME digests the stack itself runs: a drill that proves
# a restore into a different engine version has proved something about that
# version, not about this deployment.
PG_IMAGE="postgres:16-alpine@sha256:16bc17c64a573ef34162af9298258d1aec548232985b33ed7b1eac33ba35c229"
CH_IMAGE="clickhouse/clickhouse-server:24.8-alpine@sha256:b002e56ed5c16e224c312527f6fcba7e77216fec5d7a88a7828f59efc614feb5"
VM_IMAGE="victoriametrics/victoria-metrics:v1.101.0@sha256:91d0456cc064e195869175074ced2a6849d72531613b320492698e5fe935d10a"

# --- credentials (READ-ONLY, never echoed) ---------------------------------
# Read specific keys verbatim rather than sourcing .env: the file legitimately
# contains values with spaces, so `. "$ENV_FILE"` would try to execute them.
env_val() { sed -n "s/^$1=//p" "$ENV_FILE" 2>/dev/null | head -1; }
DB_USER_V="$(env_val DB_USER)";           DB_USER_V="${DB_USER_V:-netops}"
DB_PASS_V="$(env_val DB_PASSWORD)"
DB_NAME_V="$(env_val DB_NAME)";           DB_NAME_V="${DB_NAME_V:-netops}"
CH_USER_V="$(env_val CLICKHOUSE_USER)";   CH_USER_V="${CH_USER_V:-netops}"
CH_PASS_V="$(env_val CLICKHOUSE_PASSWORD)"
# The custody passphrase: environment wins, .env is the cron fallback — the same
# precedence backup.sh uses. NEVER printed, never written to a file.
if [ -z "${BACKUP_SEALED_PASSPHRASE:-}" ]; then
  BACKUP_SEALED_PASSPHRASE="$(env_val BACKUP_SEALED_PASSPHRASE)"
fi

# --- assertion + leg bookkeeping -------------------------------------------
ASSERT_PASS=0
ASSERT_FAIL=0
LEG_KEYS=()
LEG_RESULTS=()
LEG_DETAILS=()
LEG_SECONDS=()

assert() { # <ok|fail> <description>
  if [ "$1" = "ok" ]; then
    ASSERT_PASS=$((ASSERT_PASS + 1)); log "  PASS $2"
  else
    ASSERT_FAIL=$((ASSERT_FAIL + 1)); err "FAIL $2"
  fi
}
record_leg() { # <key> <pass|fail|skip> <detail> <seconds>
  LEG_KEYS+=("$1"); LEG_RESULTS+=("$2"); LEG_DETAILS+=("$3"); LEG_SECONDS+=("${4:-0}")
  log "  -> leg $1: $2 ($3)"
}

# json_str — the report is machine-read by the api; a value that breaks the
# parse blinds the Data Protection page, so quotes/backslashes are removed and
# control characters collapse to spaces.
json_str() { printf '%s' "$1" | tr -d '\042\134' | tr -s '[:cntrl:]' ' ' | cut -c1-600; }

# shellcheck disable=SC2329  # invoked indirectly by `trap cleanup EXIT` below
cleanup() {
  local rc=$?
  # Scratch containers ALWAYS go, even with --keep off the table for the tree:
  # a leaked container holds a port, a name and a few hundred MB of RAM.
  local names
  names="$(docker ps -aq --filter "name=$SCRATCH_PREFIX" 2>/dev/null)"
  if [ -n "$names" ]; then
    if [ "$KEEP" = 1 ]; then
      log "--keep: leaving scratch containers ($SCRATCH_PREFIX-*) for inspection"
    else
      # A container we cannot remove is a leak the operator must know about.
      # shellcheck disable=SC2086
      docker rm -f $names >/dev/null 2>"$WORK/cleanup.err" \
        || err "could not remove scratch container(s) [$names]: $(tail -1 "$WORK/cleanup.err" 2>/dev/null) — remove them by hand"
    fi
  fi
  if [ "$KEEP" = 1 ]; then
    log "--keep: leaving the extraction tree at $WORK (it contains a DECRYPTED custody copy — delete it when done)"
  elif ! rm -rf -- "$WORK" 2>/dev/null; then
    # A scratch container may have left files owned by another uid inside the
    # tree. Retry through a root helper with ONLY this directory mounted — the
    # work tree can hold a decrypted custody copy, so "remove it by hand later"
    # is not an acceptable resting state. The path is a mktemp -d we created, so
    # there is nothing here that could be pointed at a live volume.
    if docker run --rm --user 0:0 -v "$WORK:/work" "${BACKUP_DRILL_HELPER_IMAGE:-alpine:3.20}"          sh -c 'rm -rf /work/..?* /work/.[!.]* /work/*' >/dev/null 2>&1 && rm -rf -- "$WORK" 2>/dev/null; then
      log "cleaned the extraction tree through the root helper (a scratch container had left files behind)"
    else
      err "could not remove $WORK — it may hold a decrypted custody copy; remove it by hand"
    fi
  fi
  return "$rc"
}
trap cleanup EXIT

# wait_for <container> <seconds> <probe-command...> — bounded readiness (§9: no
# unbounded wait). Returns non-zero when the deadline passes.
wait_for() {
  local name="$1" limit="$2"; shift 2
  local i=0
  while [ "$i" -lt "$limit" ]; do
    if docker exec "$name" "$@" >/dev/null 2>&1; then return 0; fi
    i=$((i + 1)); sleep 1
  done
  return 1
}

# ---------------------------------------------------------------------------
# 0. Pick and open the bundle.
# ---------------------------------------------------------------------------
if [ -z "$BUNDLE" ]; then
  # Newest managed artifact in the default backup directory.
  BUNDLE="$(find "$ROOT/data/backups" -maxdepth 1 -type f -name 'correlix-*.tar.zst' -printf '%T@\t%p\n' 2>/dev/null \
            | sort -rn | head -1 | cut -f2-)"
fi
if [ -z "$BUNDLE" ] || [ ! -f "$BUNDLE" ]; then
  err "no bundle artifact to drill (looked for the newest data/backups/correlix-*.tar.zst; use --bundle <file>)"
  err "a drill with no artifact is not a failed drill, it is an ABSENT one — nothing is proven either way"
  exit 2
fi
BUNDLE_NAME="$(basename -- "$BUNDLE")"
log "drill $DRILL_ID against $BUNDLE_NAME"

# The artifact's own integrity comes FIRST. Drilling a tampered or truncated
# archive would produce a restore verdict about bytes nobody should trust.
VERIFY_DETAIL="signature/manifest verification not attempted"
if [ -x "$DIR/backup.sh" ]; then
  if "$DIR/backup.sh" --verify "$BUNDLE" >"$WORK/verify.out" 2>&1; then
    assert ok "bundle: integrity verified (scripts/backup.sh --verify)"
    VERIFY_DETAIL="integrity verified"
  else
    assert fail "bundle: integrity verification FAILED — $(tail -1 "$WORK/verify.out" 2>/dev/null)"
    VERIFY_DETAIL="integrity verification FAILED"
  fi
fi

mkdir -p "$EXTRACT"
# Extract ONLY what the legs need. A full extraction of a multi-gigabyte data/
# copy would double the disk the drill needs for no assertion it makes.
if zstd -dc -- "$BUNDLE" 2>"$WORK/extract.err" \
     | tar -x -C "$EXTRACT" \
           ./MANIFEST ./postgres.sql ./clickhouse-schema.sql ./clickhouse-data ./victoriametrics ./sealed \
           2>>"$WORK/extract.err"; then
  assert ok "bundle: members extracted"
else
  # tar exits non-zero when a NAMED member is absent, which is normal for a
  # bundle taken with a store down. The legs below each check their own inputs
  # and report an honest skip, so this is a note, not a failure.
  log "  (tar reported missing members — each leg reports its own input state: $(tail -1 "$WORK/extract.err" 2>/dev/null))"
fi

# ---------------------------------------------------------------------------
# 1. PostgreSQL leg — restore pg_dumpall into a scratch server, compare the
#    restored table set and row counts against the LIVE database.
# ---------------------------------------------------------------------------
# COMPOSE INVOCATION: `-f <file>`, never `--project-directory` alone.
# `docker compose --project-directory X` sets the path base for the compose
# file's own relative mounts; it does NOT change where the compose FILE is
# looked up, which stays the CWD. Run from anywhere but deployment/docker and
# every call dies with `stat ./docker-compose.yml: no such file or directory` —
# and because these calls are `2>/dev/null` reads, that surfaces as an EMPTY
# RESULT rather than an error. The first live drill run hit exactly that:
# "the LIVE cluster returned no databases". `-f` makes the file explicit and
# also sets the project directory to the file's own directory.

# live_pg <db> <sql> — read-only query against the LIVE cluster. Counts only.
live_pg() {
  docker compose -f "$COMPOSE_DIR/docker-compose.yml" exec -T \
    -e PGPASSWORD="$DB_PASS_V" postgres psql -U "$DB_USER_V" -d "$1" -tAc "$2" 2>/dev/null < /dev/null
}
drill_pg() {
  log "-- PostgreSQL leg --"
  local t0; t0=$(date +%s)
  local dump="$EXTRACT/postgres.sql"
  if [ ! -s "$dump" ]; then
    record_leg postgres skip "the bundle carries no postgres.sql (the dump was skipped or failed when it was taken)" 0
    return 0
  fi

  local scratch="$SCRATCH_PREFIX-pg"
  docker rm -f "$scratch" >/dev/null 2>&1
  if ! docker run -d --name "$scratch" \
        -e POSTGRES_USER="$DB_USER_V" -e POSTGRES_PASSWORD="$DB_PASS_V" -e POSTGRES_DB="$DB_NAME_V" \
        --tmpfs /var/lib/postgresql/data:rw \
        "$PG_IMAGE" >/dev/null 2>"$WORK/pg-run.err"; then
    assert fail "pg: scratch container start ($(tail -1 "$WORK/pg-run.err" 2>/dev/null))"
    record_leg postgres fail "the disposable Postgres could not be started, so the dump was never restored" 0
    return 1
  fi
  if ! wait_for "$scratch" 60 pg_isready -U "$DB_USER_V"; then
    assert fail "pg: scratch never became ready within 60s"
    record_leg postgres fail "the disposable Postgres never became ready" 0
    return 1
  fi

  # Restore. psql's exit code is NOT the verdict: a pg_dumpall replay legitimately
  # emits "role already exists" and "database already exists" notices. CONTENT is.
  docker exec -i -e PGPASSWORD="$DB_PASS_V" "$scratch" \
    psql -v ON_ERROR_STOP=0 -U "$DB_USER_V" -d "$DB_NAME_V" < "$dump" >"$WORK/pg-restore.log" 2>&1 \
    || log "  (psql returned non-zero on replay — evaluating by CONTENT, per policy)"
  local t1; t1=$(date +%s); local secs=$((t1 - t0))

  # WHAT IS COMPARED, and why it is the whole CLUSTER.
  #
  # pg_dumpall is a CLUSTER dump: it carries every database, and on this
  # platform the interesting one is not always the app database. The first
  # version of this leg asserted "the restored $DB_NAME has public tables" and
  # failed on a perfectly good backup, because the api's relational store is
  # build-tagged and OFF by default — netops legitimately has zero public
  # tables while keycloak has ~100. Asserting a shape the deployment does not
  # have is a false alarm, and a drill that cries wolf gets ignored exactly like
  # an always-firing alert.
  #
  # So the assertion is a COMPARISON against the live cluster: every live
  # database came back, every live public table in each of them came back, and
  # every restored table is countable. Row counts are compared and REPORTED but
  # not asserted equal — the bundle is a point-in-time older than now, so an
  # append-only table has legitimately grown since.
  local sq=(docker exec -e PGPASSWORD="$DB_PASS_V" "$scratch" psql -U "$DB_USER_V" -tAc)
  # `<table>|<exact row count>` for every ordinary table in the public schema,
  # in ONE statement. query_to_xml executes the generated count(*) per relation,
  # so these are real scans — pg_class.reltuples would be a planner ESTIMATE and
  # a drill that compares estimates has not compared anything.
  local PG_COUNT_SQL="SELECT c.relname || '|' || (xpath('/row/c/text()', query_to_xml(format('SELECT count(*) AS c FROM public.%I', c.relname), false, true, '')))[1]::text FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'public' AND c.relkind = 'r' ORDER BY c.relname"
  # sqd <db> <sql> — the same read against the SCRATCH cluster. Defined here
  # (not at file scope) because it closes over $scratch, which only exists once
  # the disposable container is up.
  sqd() { docker exec -e PGPASSWORD="$DB_PASS_V" "$scratch" psql -U "$DB_USER_V" -d "$1" -tAc "$2" 2>/dev/null < /dev/null; }

  local live_dbs restored_dbs
  live_dbs="$(live_pg postgres "SELECT datname FROM pg_database WHERE NOT datistemplate AND datallowconn ORDER BY datname" | tr -d '\r')"
  restored_dbs="$("${sq[@]}" "SELECT datname FROM pg_database WHERE NOT datistemplate AND datallowconn ORDER BY datname" 2>/dev/null | tr -d '\r')"
  if [ -z "$live_dbs" ]; then
    assert fail "pg: the LIVE cluster returned no databases — the comparison baseline is unreadable"
    record_leg postgres fail "the live cluster could not be read, so the restore had nothing to be compared against" "$secs"
    return 1
  fi

  local db missing_db=0 tables_total=0 tables_missing=0 unreadable=0 matched=0 compared=0
  local restored_rows=0 live_rows=0 dbs_ok=0
  while IFS= read -r db; do
    [ -z "$db" ] && continue
    if ! printf '%s\n' "$restored_dbs" | grep -qx -- "$db"; then
      missing_db=$((missing_db + 1))
      err "  database '$db' is in the live cluster and NOT in the restore"
      continue
    fi
    dbs_ok=$((dbs_ok + 1))
    # ONE round trip per database, not two per table. Keycloak alone has ~100
    # public tables; a per-table `docker exec psql` against both clusters is
    # ~200 process spawns per database and turned the leg into a multi-minute
    # crawl. query_to_xml runs the exact `count(*)` per relation INSIDE one
    # statement, so the counts are still real scans, not planner estimates.
    local counts_live counts_restored t rc lc
    counts_live="$(live_pg "$db" "$PG_COUNT_SQL" | tr -d '\r')"
    counts_restored="$(sqd "$db" "$PG_COUNT_SQL" | tr -d '\r')"
    while IFS='|' read -r t lc; do
      [ -z "$t" ] && continue
      tables_total=$((tables_total + 1))
      rc="$(printf '%s\n' "$counts_restored" | awk -F'|' -v t="$t" '$1==t {print $2; exit}')"
      if [ -z "$rc" ]; then
        tables_missing=$((tables_missing + 1))
        continue
      fi
      if ! [[ "$rc" =~ ^[0-9]+$ ]]; then
        # Present but uncountable — a different fault from missing: a lost
        # table is a lost backup, an unreadable one is a broken restore.
        unreadable=$((unreadable + 1))
        continue
      fi
      restored_rows=$((restored_rows + rc))
      if [[ "$lc" =~ ^[0-9]+$ ]]; then
        compared=$((compared + 1)); live_rows=$((live_rows + lc))
        [ "$rc" = "$lc" ] && matched=$((matched + 1))
      fi
    done <<< "$counts_live"
  done <<< "$live_dbs"

  local ok=1
  if [ "$missing_db" -gt 0 ]; then
    assert fail "pg: $missing_db live database(s) are absent from the restore"; ok=0
  else
    assert ok "pg: all $dbs_ok live databases came back"
  fi
  if [ "$tables_missing" -gt 0 ]; then
    assert fail "pg: $tables_missing of $tables_total live public tables are absent from the restore"; ok=0
  else
    assert ok "pg: all $tables_total live public tables came back"
  fi
  if [ "$unreadable" -gt 0 ]; then
    assert fail "pg: $unreadable restored table(s) exist but could not be counted"; ok=0
  else
    assert ok "pg: every restored table is readable"
  fi
  if [ "$restored_rows" -eq 0 ] && [ "$live_rows" -gt 0 ]; then
    assert fail "pg: the restore contains ZERO rows while the live cluster holds $live_rows — a schema-only restore is not a backup"; ok=0
  else
    assert ok "pg: restored row total is $restored_rows across $tables_total tables"
  fi

  local detail="restored $dbs_ok databases / $tables_total public tables / $restored_rows rows into a \
disposable Postgres; $matched of $compared tables matched the live count exactly (the rest differ because the \
bundle is a point-in-time older than now, which is expected); $tables_missing tables missing, $unreadable unreadable"
  if [ "$ok" = 1 ]; then record_leg postgres pass "$detail" "$secs"; else record_leg postgres fail "$detail" "$secs"; fi
  return 0
}

# ---------------------------------------------------------------------------
# 2. ClickHouse leg — replay the schema + FORMAT Native data into a scratch
#    server and compare row counts against the LIVE database.
# ---------------------------------------------------------------------------
live_ch() {
  docker compose -f "$COMPOSE_DIR/docker-compose.yml" exec -T clickhouse \
    clickhouse-client --user "$CH_USER_V" --password "$CH_PASS_V" --query "$1" 2>/dev/null < /dev/null
}
drill_ch() {
  log "-- ClickHouse leg --"
  local t0; t0=$(date +%s)
  local schema="$EXTRACT/clickhouse-schema.sql" data="$EXTRACT/clickhouse-data"
  if [ ! -s "$schema" ] || [ ! -d "$data" ]; then
    record_leg clickhouse skip "the bundle carries no ClickHouse schema/data export (it was skipped or failed when taken)" 0
    return 0
  fi

  local scratch="$SCRATCH_PREFIX-ch"
  docker rm -f "$scratch" >/dev/null 2>&1
  if ! docker run -d --name "$scratch" -e CLICKHOUSE_USER=drill -e CLICKHOUSE_PASSWORD=drillpw \
        --tmpfs /var/lib/clickhouse:rw "$CH_IMAGE" >/dev/null 2>"$WORK/ch-run.err"; then
    assert fail "ch: scratch container start ($(tail -1 "$WORK/ch-run.err" 2>/dev/null))"
    record_leg clickhouse fail "the disposable ClickHouse could not be started, so the export was never replayed" 0
    return 1
  fi
  if ! wait_for "$scratch" 90 clickhouse-client --user drill --password drillpw --query "SELECT 1"; then
    assert fail "ch: scratch never became ready within 90s"
    record_leg clickhouse fail "the disposable ClickHouse never became ready" 0
    return 1
  fi
  # TWO forms, and the split is load-bearing. `docker exec -i` attaches — and
  # therefore CONSUMES — stdin. Inside a `while read` loop that stdin is the
  # loop's own table list, so one `-i` call swallows every remaining name and
  # the loop ends after ONE iteration. That is the same defect this wave found
  # and fixed in scripts/backup.sh (1 of 26 tables ever dumped), and the first
  # green run of this drill reproduced it here: "1 of 1 tables matched" while
  # 25 existed. chq_in is for the ONE call that genuinely reads stdin (the
  # Native INSERT); chq is for everything else and attaches nothing.
  local chq_in=(docker exec -i "$scratch" clickhouse-client --user drill --password drillpw)
  local chq=(docker exec "$scratch" clickhouse-client --user drill --password drillpw)

  "${chq[@]}" --query "CREATE DATABASE IF NOT EXISTS netops" >/dev/null 2>&1 < /dev/null
  # The schema dump is one SHOW CREATE per table, ';'-terminated. Replay it as a
  # multi-statement script; a table that fails to create is counted, not fatal.
  if "${chq_in[@]}" --multiquery < "$schema" >"$WORK/ch-schema.log" 2>&1; then
    assert ok "ch: schema replayed into the disposable server"
  else
    log "  (schema replay returned non-zero — evaluating by CONTENT: $(tail -1 "$WORK/ch-schema.log" 2>/dev/null))"
  fi

  local created loaded=0 failed=0 restored_total=0 live_total=0 matched=0 compared=0
  created="$("${chq[@]}" --query "SELECT name FROM system.tables WHERE database='netops' ORDER BY name" 2>/dev/null | tr -d '\r')"
  if [ -z "$created" ]; then
    assert fail "ch: no tables exist after the schema replay — the export did not restore"
    local secs2=$(( $(date +%s) - t0 ))
    record_leg clickhouse fail "no tables exist after replaying the bundle's schema" "$secs2"
    return 1
  fi

  local f tbl rc lc empty=0
  for f in "$data"/*.native.gz; do
    [ -e "$f" ] || break
    tbl="$(basename -- "$f")"; tbl="${tbl%.native.gz}"
    # A table with no rows produces a ZERO-BYTE Native stream, and feeding that
    # to `INSERT … FORMAT Native` is an error ("unexpected end of stream"), not
    # a load failure. The first live drill counted 14 empty tables as 14 broken
    # dumps and failed a leg that had nothing wrong with it — a false alarm is
    # as corrosive to a drill as a false green. An empty dump is a faithful
    # backup of an empty table; the schema is what makes it restorable.
    if [ "$(gzip -dc -- "$f" 2>/dev/null | head -c 1 | wc -c)" -eq 0 ]; then
      empty=$((empty + 1)); loaded=$((loaded + 1))
      continue
    fi
    if gzip -dc -- "$f" 2>/dev/null | "${chq_in[@]}" --query "INSERT INTO netops.\"$tbl\" FORMAT Native" >/dev/null 2>>"$WORK/ch-load.err"; then
      loaded=$((loaded + 1))
    else
      failed=$((failed + 1))
      err "  $tbl failed to load: $(tail -1 "$WORK/ch-load.err" 2>/dev/null)"
    fi
  done
  local t1; t1=$(date +%s); local secs=$((t1 - t0))

  while IFS= read -r tbl; do
    [ -z "$tbl" ] && continue
    rc="$("${chq[@]}" --query "SELECT count() FROM netops.\"$tbl\"" 2>/dev/null | tr -d '[:space:]')"
    [[ "$rc" =~ ^[0-9]+$ ]] || continue
    restored_total=$((restored_total + rc))
    lc="$(live_ch "SELECT count() FROM netops.\"$tbl\" SETTINGS tenant_scope='__all__'" | tr -d '[:space:]')"
    if [[ "$lc" =~ ^[0-9]+$ ]]; then
      compared=$((compared + 1)); live_total=$((live_total + lc))
      [ "$rc" = "$lc" ] && matched=$((matched + 1))
    fi
  done <<< "$created"

  local ok=1
  # An UNREADABLE baseline is a failed comparison, not a passed one. Without
  # this, a leg that could reach neither side would satisfy "restored 0 while
  # live holds 0" and report success having compared nothing — the same
  # vacuous-green shape the whole surface exists to remove. (The PostgreSQL
  # leg above makes the identical check on its own baseline.)
  if [ "$compared" -eq 0 ]; then
    assert fail "ch: the LIVE database returned no comparable table counts — the restore had nothing to be compared against"
    ok=0
  fi
  if [ "$failed" -gt 0 ]; then
    assert fail "ch: $failed of $((loaded + failed)) table dumps failed to load"; ok=0
  else
    assert ok "ch: all $loaded table dumps loaded"
  fi
  if [ "$restored_total" -eq 0 ] && [ "$live_total" -gt 0 ]; then
    assert fail "ch: the restore contains ZERO rows while the live database holds $live_total"; ok=0
  else
    assert ok "ch: restored row total is $restored_total across $(printf '%s\n' "$created" | grep -c .) tables"
  fi

  local detail="replayed schema + $loaded Native dumps into a disposable ClickHouse ($empty of them empty, i.e. \
tables that legitimately hold no rows): $restored_total rows restored, $matched of $compared tables matched the \
live count exactly (differences are expected — the bundle predates now), $failed dumps failed to load"
  if [ "$ok" = 1 ]; then record_leg clickhouse pass "$detail" "$secs"; else record_leg clickhouse fail "$detail" "$secs"; fi
  return 0
}

# ---------------------------------------------------------------------------
# 3. VictoriaMetrics leg — start a THROWAWAY vmsingle directly on top of the
#    extracted snapshot and read a series back out.
#
# A VM snapshot directory IS a storageDataPath layout (data/ + indexdb/), so the
# import is a mount, not a conversion. The assertion is deliberately a QUERY,
# not "the container started": a vmsingle happily starts on an empty directory.
# ---------------------------------------------------------------------------
drill_vm() {
  log "-- VictoriaMetrics leg --"
  local t0; t0=$(date +%s)
  local snapdir
  snapdir="$(find "$EXTRACT/victoriametrics" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | head -1)"
  if [ -z "$snapdir" ]; then
    record_leg victoriametrics skip "the bundle carries no VictoriaMetrics snapshot (it was skipped or failed when taken)" 0
    return 0
  fi

  local scratch="$SCRATCH_PREFIX-vm"
  docker rm -f "$scratch" >/dev/null 2>&1
  # No published port: everything is asked from inside the container, so the
  # drill cannot collide with a host port or expose a scratch datastore.
  # --user: the vmsingle WRITES into the mounted snapshot (it opens the storage
  # for read-write and creates cache/, tmp/ and part metadata). As root that
  # leaves root-owned files inside our work tree, and the cleanup below then
  # cannot delete them — the first live drill left a 370 MB extraction tree
  # behind and said so. Running it as the invoking uid keeps every temporary
  # ours to remove.
  if ! docker run -d --name "$scratch" -v "$snapdir:/victoria" \
        --user "$(id -u):$(id -g)" \
        "$VM_IMAGE" --storageDataPath=/victoria --retentionPeriod=100y --search.maxUniqueTimeseries=1000000 \
        >/dev/null 2>"$WORK/vm-run.err"; then
    assert fail "vm: scratch container start ($(tail -1 "$WORK/vm-run.err" 2>/dev/null))"
    record_leg victoriametrics fail "the throwaway vmsingle could not be started on the snapshot" 0
    return 1
  fi
  if ! wait_for "$scratch" 60 wget -q -T 5 -O /dev/null "http://127.0.0.1:8428/health"; then
    assert fail "vm: scratch never became healthy within 60s"
    record_leg victoriametrics fail "the throwaway vmsingle never became healthy on the imported snapshot" 0
    return 1
  fi

  # 1) The metric NAMES must come back — an empty label set means the snapshot
  #    imported nothing, which is exactly what "the container started" hides.
  local names first_metric
  names="$(docker exec "$scratch" wget -q -T 15 -O - "http://127.0.0.1:8428/api/v1/label/__name__/values" 2>/dev/null)"
  first_metric="$(printf '%s' "$names" | sed -n 's/.*"data":\[\"\([^"]*\)\".*/\1/p')"
  local t1; t1=$(date +%s); local secs=$((t1 - t0))
  if [ -z "$first_metric" ]; then
    assert fail "vm: the imported snapshot exposes NO metric names — nothing was restored"
    record_leg victoriametrics fail "the imported snapshot exposes no metric names: nothing was restored" "$secs"
    return 1
  fi
  assert ok "vm: imported snapshot exposes metric names (first: $first_metric)"

  # 2) QUERY one series over the snapshot's own time range. `time()` now is far
  #    past the snapshot's last sample, so an instant query at now would
  #    legitimately return empty — the range query is the honest form.
  local now series_json points
  now="$(date +%s)"
  series_json="$(docker exec "$scratch" wget -q -T 30 -O - \
      "http://127.0.0.1:8428/api/v1/query_range?query=$first_metric&start=$((now - 90 * 86400))&end=$now&step=3600" 2>/dev/null)"
  points="$(printf '%s' "$series_json" | grep -o '\[[0-9]\{10\}' | wc -l)"
  secs=$(( $(date +%s) - t0 ))
  if [ "${points:-0}" -gt 0 ]; then
    assert ok "vm: queried series $first_metric back out of the imported snapshot ($points sample points)"
    record_leg victoriametrics pass "imported the snapshot into a throwaway vmsingle and queried $first_metric back out ($points sample points over 90d)" "$secs"
  else
    assert fail "vm: series $first_metric returned NO sample points from the imported snapshot"
    record_leg victoriametrics fail "the snapshot imported but $first_metric returned no sample points — the series data did not survive" "$secs"
    return 1
  fi
  return 0
}

# ---------------------------------------------------------------------------
# 4. Sealed custody leg — decrypt the envelope and verify it against the sha256
#    manifest that shipped beside it.
#
# This is the leg whose failure is unrecoverable in production: a bundle whose
# custody envelope will not decrypt restores every byte of data and unseals
# nothing. Proving the DECRYPTION and the CHECKSUMS is the only way to know the
# envelope is a key and not a paperweight.
# ---------------------------------------------------------------------------
drill_sealed() {
  log "-- sealed custody material leg --"
  local t0; t0=$(date +%s)
  local enc="$EXTRACT/sealed/sealed-material.tar.gz.enc"
  local man="$EXTRACT/sealed/sealed-material.manifest"
  if [ ! -s "$enc" ]; then
    record_leg sealed_material skip "the bundle carries no sealed custody envelope (BACKUP_SEALED_MATERIAL=0, or the component failed when it was taken)" 0
    return 0
  fi
  if [ -z "${BACKUP_SEALED_PASSPHRASE:-}" ]; then
    # A skip, not a fail: the ENVELOPE may be perfectly good; this host simply
    # has no passphrase to open it with. Saying "fail" here would blame the
    # backup for the operator's key custody.
    record_leg sealed_material skip "BACKUP_SEALED_PASSPHRASE is not available to this drill, so the envelope could not be opened (the envelope itself is untested, not proven bad)" 0
    return 0
  fi

  local out="$WORK/sealed-restore"
  mkdir -p "$out"
  # -pass env: keeps the passphrase out of argv (/proc is world-readable).
  if ! BACKUP_SEALED_PASSPHRASE="$BACKUP_SEALED_PASSPHRASE" \
       openssl enc -d -aes-256-cbc -pbkdf2 -iter 600000 -pass env:BACKUP_SEALED_PASSPHRASE \
         -in "$enc" 2>"$WORK/sealed.err" | tar -xzf - -C "$out" 2>>"$WORK/sealed.err"; then
    assert fail "sealed: the custody envelope did NOT decrypt/extract — $(tail -1 "$WORK/sealed.err" 2>/dev/null)"
    record_leg sealed_material fail "the custody envelope did not decrypt with the supplied passphrase, or the plaintext was not a readable tar" "$(( $(date +%s) - t0 ))"
    return 1
  fi
  assert ok "sealed: custody envelope decrypted and extracted"

  if [ ! -s "$man" ]; then
    assert fail "sealed: no sha256 manifest shipped beside the envelope — the decrypted tree cannot be verified"
    record_leg sealed_material fail "the envelope decrypted but shipped without its sha256 manifest, so its contents are unverifiable" "$(( $(date +%s) - t0 ))"
    return 1
  fi
  local secs=$(( $(date +%s) - t0 ))
  local files; files=$(grep -c . < "$man")
  if ( cd "$out" && sha256sum -c --quiet "$man" ) >"$WORK/sealed-verify.log" 2>&1; then
    assert ok "sealed: all $files files match the sha256 manifest"
  else
    assert fail "sealed: manifest verification FAILED — $(head -3 "$WORK/sealed-verify.log" 2>/dev/null | tr '\n' ' ')"
    record_leg sealed_material fail "the decrypted custody tree does not match its own sha256 manifest: $(head -1 "$WORK/sealed-verify.log" 2>/dev/null)" "$secs"
    return 1
  fi

  # The one member whose absence makes everything else pointless.
  if grep -q 'swtpm/' "$man"; then
    assert ok "sealed: the envelope carries data/swtpm (the KEK-bearing custody root)"
  else
    assert fail "sealed: the envelope does NOT carry data/swtpm — vault contents stay unrecoverable"
    record_leg sealed_material fail "the envelope verified but does not contain data/swtpm, so the KEK is still in no copy" "$secs"
    return 1
  fi

  record_leg sealed_material pass "decrypted the envelope and verified all $files files against its sha256 manifest, data/swtpm included" "$secs"
  # Shred the decrypted custody tree as soon as the leg is done, rather than
  # waiting for the EXIT trap: it is plaintext KEK material.
  rm -rf -- "$out"
  return 0
}

# ---------------------------------------------------------------------------
# Run the selected legs.
# ---------------------------------------------------------------------------
START_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
IFS=',' read -ra WANT <<< "$LEGS"
for leg in "${WANT[@]}"; do
  case "$leg" in
    pg)     drill_pg     || true ;;   # a failed leg is RECORDED, not fatal: the
    ch)     drill_ch     || true ;;   # remaining legs still have to run, and the
    vm)     drill_vm     || true ;;   # exit code below carries the verdict.
    sealed) drill_sealed || true ;;
    "")     ;;
    *) err "unknown leg '$leg' (want pg|ch|vm|sealed)"; ASSERT_FAIL=$((ASSERT_FAIL + 1)) ;;
  esac
done
END_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# ---------------------------------------------------------------------------
# Report. This file is the GUI's only proof-of-restore for the bundle, so a
# write that cannot land must be LOUD and must not be mistaken for success.
# ---------------------------------------------------------------------------
RESULT="pass"
[ "$ASSERT_FAIL" -eq 0 ] || RESULT="fail"
# A drill made entirely of skips proved nothing. Calling that "pass" is exactly
# the looks-backed-up-but-isn't state this whole area exists to remove.
PROVEN=0
for r in "${LEG_RESULTS[@]:-}"; do [ "$r" = "pass" ] && PROVEN=$((PROVEN + 1)); done
if [ "$PROVEN" -eq 0 ]; then RESULT="fail"; fi

legs_json() {
  local i out=""
  for i in "${!LEG_KEYS[@]}"; do
    [ -n "$out" ] && out+=","
    out+=$(printf '"%s":{"result":"%s","detail":"%s","duration_seconds":%s}' \
      "$(json_str "${LEG_KEYS[$i]}")" "$(json_str "${LEG_RESULTS[$i]}")" \
      "$(json_str "${LEG_DETAILS[$i]}")" "${LEG_SECONDS[$i]:-0}")
  done
  printf '{%s}' "$out"
}
write_report() {
  printf '{\n'
  printf '  "drill_id": "%s",\n'          "$(json_str "$DRILL_ID")"
  printf '  "bundle": "%s",\n'            "$(json_str "$BUNDLE_NAME")"
  printf '  "bundle_integrity": "%s",\n'  "$(json_str "$VERIFY_DETAIL")"
  printf '  "started": "%s",\n'           "$START_TS"
  printf '  "ended": "%s",\n'             "$END_TS"
  printf '  "assertions_passed": %d,\n'   "$ASSERT_PASS"
  printf '  "assertions_failed": %d,\n'   "$ASSERT_FAIL"
  printf '  "legs": %s,\n'                "$(legs_json)"
  printf '  "result": "%s"\n'             "$RESULT"
  printf '}\n'
}
REPORT_DIR="$(dirname -- "$REPORT")"
if [ -d "$REPORT_DIR" ] && write_report > "$REPORT.tmp" && mv -f -- "$REPORT.tmp" "$REPORT"; then
  chmod 0644 -- "$REPORT" 2>/dev/null || true   # optional: the api reads it as another uid; a chmod failure does not invalidate the drill
  log "report -> $REPORT"
else
  rm -f -- "$REPORT.tmp"
  err "could not write the drill report to $REPORT (missing $REPORT_DIR? permissions?) — the Data Protection page will keep showing the PREVIOUS drill as current"
  ASSERT_FAIL=$((ASSERT_FAIL + 1))
fi

echo
echo "--- backup drill $DRILL_ID ---"
for i in "${!LEG_KEYS[@]}"; do
  printf '  %-16s %-5s %s\n' "${LEG_KEYS[$i]}" "${LEG_RESULTS[$i]}" "${LEG_DETAILS[$i]}"
done
echo "  assertions: $ASSERT_PASS passed, $ASSERT_FAIL failed"
echo "  result: $RESULT"

[ "$RESULT" = "pass" ] || { err "backup drill FAILED"; exit 1; }
log "backup drill PASSED — a real bundle artifact was restored and its content verified"
exit 0
