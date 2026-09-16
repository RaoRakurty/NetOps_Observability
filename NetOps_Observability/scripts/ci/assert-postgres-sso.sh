#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix
#
# CI post-condition after an install (installer self-healing FMEA 2026-09-15
# §3.7 T1/T2): postgres is healthy, and — the `sso` profile being active —
# Keycloak's database exists and Keycloak is running, not crash-looping on a
# missing database.
#
#   --expect-crash-recovery EVIDENCE_JSON
#       The chaos leg: EVIDENCE_JSON is chaos_install.py's evidence file. The
#       kill must have landed, and the postgres container now serving must show
#       crash recovery in its log — proof the install healed an UNCLEAN stop
#       rather than a chaos kill that happened not to matter.
#
# Keycloak's stability over time (no RestartCount growth, no StartedAt inside a
# window) is proven by stack_stability.py in the step before this one; this
# script checks what a window cannot: the database, and the log line that was
# the .123 symptom (`database "keycloak" does not exist`).
#
# Run from the project directory (NetOps_Observability/). Needs docker access,
# and sudo for the root-owned 0600 .env and `docker compose exec`.
set -euo pipefail

PROJECT="netops"
ENV_FILE="deployment/docker/.env"
COMPOSE_DIR="deployment/docker"
EVIDENCE=""

die() { echo "::error::$*" >&2; exit 1; }

while [ "$#" -gt 0 ]; do
  case "$1" in
    --expect-crash-recovery)
      [ "$#" -ge 2 ] || die "--expect-crash-recovery needs the evidence file"
      EVIDENCE="$2"; shift 2 ;;
    *) die "unknown argument: $1" ;;
  esac
done

for tool in docker sudo python3 timeout; do
  command -v "$tool" >/dev/null || die "required tool not on PATH: $tool"
done
[ -d "$COMPOSE_DIR" ] || die "run from the project directory ($COMPOSE_DIR not found)"
sudo test -f "$ENV_FILE" || die "$ENV_FILE not found — the install did not write it"

# One key from .env, by name. Values read here are identifiers and a profile
# list, never secrets, and none is echoed except the profile list.
env_value() {
  local key="$1" line
  # grep exits 1 when the key is absent; that is a legitimate "unset", handled
  # by the caller's default — any other failure (2 = unreadable) is fatal.
  line=$(sudo grep -E "^${key}=" "$ENV_FILE" | tail -n 1) || {
    rc=$?
    [ "$rc" -eq 1 ] || die "could not read $ENV_FILE (grep exit $rc)"
    line=""
  }
  line="${line#*=}"
  line="${line%%#*}"
  line="${line//\"/}"
  printf '%s' "${line//[[:space:]]/}"
}

container_id() {
  local service="$1" ids
  ids=$(timeout 30 docker ps -q --no-trunc \
    --filter "label=com.docker.compose.project=${PROJECT}" \
    --filter "label=com.docker.compose.service=${service}")
  [ -n "$ids" ] || die "no ${service} container in project ${PROJECT}"
  [ "$(printf '%s\n' "$ids" | wc -l)" -eq 1 ] || die "more than one ${service} container"
  printf '%s' "$ids"
}

# ── postgres ────────────────────────────────────────────────────────────────
pg_id=$(container_id postgres)
pg_state=$(timeout 30 docker inspect --format \
  '{{.State.Status}} {{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}} {{.RestartCount}}' \
  "$pg_id")
echo "postgres ${pg_id:0:12}: status/health/restarts = ${pg_state}"
read -r pg_status pg_health _ <<<"$pg_state"
[ "$pg_status" = "running" ] || die "postgres is '$pg_status', expected running"
[ "$pg_health" = "healthy" ] || die "postgres health is '$pg_health', expected healthy"

if [ -n "$EVIDENCE" ]; then
  [ -f "$EVIDENCE" ] || die "chaos evidence file not found: $EVIDENCE"
  landed=$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print("yes" if d.get("landed") else "no")' "$EVIDENCE")
  killed_id=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("container_id",""))' "$EVIDENCE")
  [ "$landed" = "yes" ] || die "chaos evidence says the SIGKILL did not land — nothing was proven"
  echo "chaos: killed postgres container ${killed_id:0:12}; now serving ${pg_id:0:12}"
  # Crash recovery wording from PostgreSQL 16's own startup (xlogrecovery.c).
  # The TLS phase B recreates postgres, so these lines are in the NEW
  # container's log only if its data directory really was left unclean.
  pg_log=$(timeout 60 docker logs "$pg_id" 2>&1)
  if ! printf '%s\n' "$pg_log" | grep -E -q \
      'database system was interrupted|database system was not properly shut down|automatic recovery in progress'; then
    printf '%s\n' "$pg_log" | tail -n 40 >&2
    die "postgres log shows no crash recovery after the SIGKILL — the chaos did not reach the data directory"
  fi
  echo "postgres ran crash recovery and is healthy:"
  printf '%s\n' "$pg_log" | grep -E 'interrupted|not properly shut down|recovery|ready to accept' | tail -n 8
fi

# ── keycloak (profile sso) ──────────────────────────────────────────────────
profiles=$(env_value COMPOSE_PROFILES)
echo "COMPOSE_PROFILES=${profiles}"
case ",${profiles}," in
  *,sso,*) ;;
  *) die "the sso profile is not active, so the Keycloak half of this assertion cannot run — this leg exists to prove it (install.py DEFAULT_PROFILES includes sso; pass --profiles with sso if that changed)" ;;
esac

db_user=$(env_value DB_USER); db_user="${db_user:-netops}"
kc_db=$(env_value KEYCLOAK_DB_NAME); kc_db="${kc_db:-keycloak}"
# Same identifier rule install.py enforces before interpolating into SQL.
[[ "$db_user" =~ ^[A-Za-z0-9_]+$ ]] || die "DB_USER in .env is not a plain identifier"
[[ "$kc_db" =~ ^[A-Za-z0-9_]+$ ]] || die "KEYCLOAK_DB_NAME in .env is not a plain identifier"

exists=$(cd "$COMPOSE_DIR" && sudo timeout 60 docker compose exec -T postgres \
  psql -v ON_ERROR_STOP=1 -U "$db_user" -d postgres -tAc \
  "SELECT 1 FROM pg_database WHERE datname='${kc_db}'")
[ "$(printf '%s' "$exists" | tr -d '[:space:]')" = "1" ] \
  || die "Keycloak's database '${kc_db}' does not exist after the install"
echo "keycloak database '${kc_db}' exists"

kc_id=$(container_id keycloak)
kc_state=$(timeout 30 docker inspect --format '{{.State.Status}} {{.State.Restarting}} {{.RestartCount}}' "$kc_id")
echo "keycloak ${kc_id:0:12}: status/restarting/restarts = ${kc_state}"
read -r kc_status kc_restarting _ <<<"$kc_state"
[ "$kc_restarting" = "false" ] || die "keycloak is restarting (crash loop)"
[ "$kc_status" = "running" ] || die "keycloak is '$kc_status', expected running"

# The container's log spans every restart of that container. The database is
# created before Keycloak's first start (ffbb4055), so this line must never
# have been printed — not even once, early.
kc_log=$(timeout 60 docker logs "$kc_id" 2>&1)
if printf '%s\n' "$kc_log" | grep -F -q "database \"${kc_db}\" does not exist"; then
  printf '%s\n' "$kc_log" | grep -F "does not exist" | tail -n 5 >&2
  die "keycloak started before its database existed (the .123 crash-loop symptom)"
fi
echo "keycloak never saw a missing database"
