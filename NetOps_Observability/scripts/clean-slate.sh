#!/usr/bin/env bash
# clean-slate.sh — factory-reset the CORRELIX stack's application data.
#
# Scripts the clean-slate procedure the scale-test programme executed manually
# (docs/scale/CORRELIX_SCALE_TEST_REPORT.md §2): stop the compose project, wipe
# every app-state subdirectory under <repo>/data via a root helper container
# (service volumes are owned by service UIDs — postgres 70, correlation 10001,
# valkey 999 — so an unprivileged rm cannot), hand data/ back to the installing
# user, and optionally reinstall and verify emptiness.
#
# What is DESTROYED: everything under <repo>/data — device inventory, tenants,
# ClickHouse/OpenSearch/VictoriaMetrics/PostgreSQL data, Kafka log dirs,
# Grafana state, AND the TLS mesh custody (data/tls, data/swtpm,
# data/secrets-seal). A TLS-variant install therefore CANNOT start again until
# scripts/install.py re-mints custody — use --reinstall, or run install.py
# yourself afterwards.
#
# What is PRESERVED: deployment/docker/.env (all secrets/config) — by default.
# Pass --reset-env to have install.py rotate it (delegated, never done here).
#
# Usage:
#   clean-slate.sh [--yes] [--dry-run] [--reset-env] [--reinstall [--tls yes|no]]
#                  [--verify] [--data-dir PATH]
#
#   (no mode flags)   stop stack + wipe data/ + chown data/ (asks first)
#   --yes             skip the confirmation prompt (required when not a TTY)
#   --dry-run         print exactly what would be stopped/removed, change nothing
#   --reset-env       after the wipe, run install.py --reset-env (secret rotation)
#   --reinstall       after the wipe, run install.py (fresh install, .env kept
#                     unless --reset-env is also given)
#   --tls yes|no      forwarded to install.py --tls (only with --reinstall)
#   --verify          verify emptiness against the RUNNING stack (0 devices via
#                     API, ClickHouse key-table counts, OpenSearch indices,
#                     Kafka consumer-group offsets). With no other action flags,
#                     runs the checks alone and exits.
#   --data-dir PATH   override the data directory (testing; must resolve inside
#                     the repo — anything else is refused)
#
# Operator doc: docs/ops/OBSERVABILITY_AUDIT.md ("Clean-slate reset").
set -euo pipefail

# Cron/minimal-shell hardening (CLAUDE.md §16.2): explicit PATH, no reliance on
# an interactive profile. docker + python3 live in /usr/bin on supported hosts;
# /usr/local/bin covers manual docker installs.
PATH=/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
REPO_ROOT=$(cd -- "$SCRIPT_DIR/.." && pwd -P)
DOCKER_DIR="$REPO_ROOT/deployment/docker"
ENV_FILE="$DOCKER_DIR/.env"
# Root helper for the wipe/chown. Override only for offline hosts that mirror
# a different registry (e.g. CLEANSLATE_HELPER_IMAGE=registry.local/alpine:3.20).
HELPER_IMAGE="${CLEANSLATE_HELPER_IMAGE:-alpine:3.20}"

info() { printf 'clean-slate: %s\n' "$*"; }
warn() { printf 'clean-slate: WARNING: %s\n' "$*" >&2; }
die()  { printf 'clean-slate: ERROR: %s\n' "$*" >&2; exit 1; }

# Print the header comment block (everything up to the first non-comment line).
usage() { awk 'NR > 1 && !/^#/ { exit } NR > 1 { sub(/^# ?/, ""); print }' "${BASH_SOURCE[0]}"; }

# env_get KEY — first value of KEY= in .env. Missing file/key yields empty:
# both are expected states (fresh checkout, optional key), the CALLERS decide
# whether empty is fatal — hence the '|| true' on grep's no-match exit 1.
env_get() {
  [ -r "$ENV_FILE" ] || { echo ""; return 0; }
  grep -m1 "^${1}=" "$ENV_FILE" 2>/dev/null | cut -d= -f2- || true
}

ASSUME_YES=0 DRY_RUN=0 DO_RESET_ENV=0 DO_REINSTALL=0 DO_VERIFY=0
TLS_CHOICE="" DATA_DIR_OVERRIDE=""
while [ $# -gt 0 ]; do
  case "$1" in
    --yes|-y)     ASSUME_YES=1 ;;
    --dry-run)    DRY_RUN=1 ;;
    --reset-env)  DO_RESET_ENV=1 ;;
    --reinstall)  DO_REINSTALL=1 ;;
    --verify)     DO_VERIFY=1 ;;
    --tls)
      shift; [ $# -gt 0 ] || die "--tls needs a value: yes|no"
      case "$1" in yes|no) TLS_CHOICE="$1" ;; *) die "--tls must be yes|no (got '$1')" ;; esac ;;
    --data-dir)
      shift; [ $# -gt 0 ] || die "--data-dir needs a path"
      DATA_DIR_OVERRIDE="$1" ;;
    --help|-h)    usage; exit 0 ;;
    *)            usage >&2; die "unknown argument: $1" ;;
  esac
  shift
done
[ -n "$TLS_CHOICE" ] && [ "$DO_REINSTALL" -eq 0 ] && die "--tls only makes sense with --reinstall"

# ---------------------------------------------------------------------------
# Data-dir containment: the wipe must NEVER be able to point at an arbitrary
# host path. realpath -m resolves symlinks and '..' before the check.
# ---------------------------------------------------------------------------
DATA_DIR="${DATA_DIR_OVERRIDE:-$REPO_ROOT/data}"
command -v realpath >/dev/null 2>&1 || die "realpath not found (coreutils required)"
DATA_DIR=$(realpath -m -- "$DATA_DIR")
case "$DATA_DIR" in
  "$REPO_ROOT"/*) : ;;
  *) die "data dir '$DATA_DIR' resolves OUTSIDE the repo ($REPO_ROOT) — refusing. The wipe only ever targets a directory inside this checkout." ;;
esac
[ "$DATA_DIR" = "$REPO_ROOT" ] && die "data dir resolves to the repo root itself — refusing"

command -v docker >/dev/null 2>&1 || die "docker not found on PATH ($PATH)"
docker compose version >/dev/null 2>&1 || die "the Docker Compose v2 plugin is required ('docker compose', not legacy docker-compose)"

PROJECT=$(env_get COMPOSE_PROJECT_NAME); PROJECT="${PROJECT:-netops}"
COMPOSE_FILES=$(env_get COMPOSE_FILE)
IS_TLS=0
case "$COMPOSE_FILES" in *compose.tls.yml*) IS_TLS=1 ;; esac

# ---------------------------------------------------------------------------
# --verify (standalone or post-reinstall): emptiness against the LIVE stack.
# Bounds tolerate the platform's own self-telemetry, which starts writing the
# moment the stack boots (minutes-old install: hundreds of platform log docs,
# a handful of self corr_signals) but catch a non-wiped install, which carries
# thousands-to-millions. Every probe is bounded (curl -m / timeout).
# ---------------------------------------------------------------------------
FAILS=0
fail() { printf 'clean-slate: VERIFY FAIL: %s\n' "$*" >&2; FAILS=$((FAILS + 1)); }
pass() { printf 'clean-slate: verify ok: %s\n' "$*"; }

cid_of() {  # cid_of <service> — container id of a compose service, or empty
  docker ps -q \
    --filter "label=com.docker.compose.project=$PROJECT" \
    --filter "label=com.docker.compose.service=$1" 2>/dev/null | head -1 || true
}

verify_stack() {
  info "verify: project '$PROJECT' (TLS variant: $IS_TLS)"
  [ -r "$ENV_FILE" ] || die "verify needs $ENV_FILE (credentials); not readable"

  # --- API: 0 devices --------------------------------------------------------
  local base_port admin_user admin_pw login token devices
  base_port=$(env_get BASE_PORT); base_port="${base_port:-8000}"
  admin_user=$(env_get ADMIN_USERNAME)
  admin_pw=$(env_get ADMIN_INITIAL_PASSWORD)
  if [ -z "$admin_user" ] || [ -z "$admin_pw" ]; then
    fail "ADMIN_USERNAME/ADMIN_INITIAL_PASSWORD missing from .env — cannot check the device inventory"
  else
    # Credentials ride a curl config on stdin, never argv (visible in ps).
    login=$(printf 'url = "http://localhost:%s/api/auth/login"\nmax-time = 10\nsilent\nheader = "Content-Type: application/json"\ndata = "{\\"username\\":\\"%s\\",\\"password\\":\\"%s\\"}"\n' \
        "$base_port" "$admin_user" "$admin_pw" | curl --config - 2>&1) || {
      fail "API login on :$base_port failed — is the stack up? ($login)"; login=""; }
    token=$(printf '%s' "$login" | python3 -c 'import sys,json
try: print(json.load(sys.stdin).get("token",""))
except Exception: print("")')
    if [ -z "$token" ]; then
      [ -n "$login" ] && fail "API login returned no token (password changed since install? response: ${login:0:120})"
    else
      devices=$(printf 'url = "http://localhost:%s/api/devices"\nmax-time = 10\nsilent\nheader = "Authorization: Bearer %s"\n' \
          "$base_port" "$token" | curl --config - | python3 -c 'import sys,json
d=json.load(sys.stdin); print(len(d) if isinstance(d,list) else d.get("count","?"))') \
        || { fail "GET /api/devices failed"; devices="?"; }
      if [ "$devices" = "0" ]; then pass "API device inventory is empty (0 devices)"
      else fail "API reports $devices devices (expected 0)"; fi
    fi
  fi

  # --- ClickHouse: key tables ------------------------------------------------
  local ch_cid n
  ch_cid=$(cid_of clickhouse)
  if [ -z "$ch_cid" ]; then
    fail "no running clickhouse container in project '$PROJECT'"
  else
    # tenant_scope='__all__': the FORCE row policies on netops.* filter via
    # getSetting('tenant_scope'); without it the count query itself errors
    # (UNKNOWN_SETTING). Same trusted-internal-reader scope correlation uses.
    for t in netops.corr_signals netops.flows; do
      n=$(timeout 30 docker exec "$ch_cid" clickhouse-client \
            --query "SELECT count() FROM $t SETTINGS tenant_scope='__all__'" 2>&1) \
        || { fail "ClickHouse count on $t failed: $n"; continue; }
      if [ "$n" -le 1000 ] 2>/dev/null; then pass "ClickHouse $t: $n rows (<=1000, self-telemetry tolerance)"
      else fail "ClickHouse $t holds $n rows — not a clean slate"; fi
    done
  fi

  # --- OpenSearch: index inventory ------------------------------------------
  local os_cid os_out os_user os_pw
  os_cid=$(cid_of opensearch)
  if [ -z "$os_cid" ]; then
    fail "no running opensearch container in project '$PROJECT'"
  else
    if [ "$IS_TLS" -eq 1 ]; then
      # svc_bootstrap is the one service role with indices:monitor on netops-*
      # (svc_api 403s on _cat/indices — see docs/ops/OBSERVABILITY_AUDIT.md §4).
      os_user="svc_bootstrap"; os_pw=$(env_get OS_BOOTSTRAP_PASSWORD)
      if [ -z "$os_pw" ]; then
        fail "TLS install but OS_BOOTSTRAP_PASSWORD is missing from .env — cannot list indices"
        os_out=""
      else
        os_out=$(printf 'url = "https://opensearch:9200/_cat/indices/netops-*?h=index,docs.count"\nmax-time = 10\nsilent\ncacert = "/usr/share/opensearch/config/tls/ca.pem"\nuser = "%s:%s"\n' \
            "$os_user" "$os_pw" | timeout 30 docker exec -i "$os_cid" curl --config - 2>&1) \
          || { fail "OpenSearch _cat/indices probe failed: ${os_out:0:160}"; os_out=""; }
      fi
    else
      os_out=$(timeout 30 docker exec "$os_cid" \
          curl -s -m 10 "http://localhost:9200/_cat/indices/netops-*?h=index,docs.count" 2>&1) \
        || { fail "OpenSearch _cat/indices probe failed: ${os_out:0:160}"; os_out=""; }
    fi
    if [ -n "$os_out" ]; then
      # applogs/platformlogs are the STACK'S OWN logs (they refill from second
      # one of a fresh boot and the index is daily) — report them, but only
      # device/customer lanes (syslog, flows, snmptrap, cloudlogs, ...) can
      # prove a stale install.
      local bad=0
      while read -r idx cnt; do
        [ -n "$idx" ] || continue
        case "$idx" in netops-applogs-*|netops-platformlogs-*) continue ;; esac
        if [ "${cnt:-0}" -gt 5000 ] 2>/dev/null; then
          fail "OpenSearch index $idx holds $cnt docs — not a clean slate"; bad=1
        fi
      done <<< "$os_out"
      [ "$bad" -eq 0 ] && pass "OpenSearch device-lane indices within self-telemetry bounds:"$'\n'"$os_out"
    fi
  fi

  # --- Kafka: consumer-group offsets ----------------------------------------
  local k_cid k_out
  k_cid=$(cid_of kafka)
  if [ -z "$k_cid" ]; then
    warn "no running kafka container in project '$PROJECT' (external broker?) — skipping offset check"
  else
    if [ "$IS_TLS" -eq 1 ]; then
      # kafka/tls-entrypoint.sh stages an SSL client config for the broker's
      # own super-user SVID; the plaintext listener no longer exists (SEC-006.3).
      k_out=$(timeout 60 docker exec "$k_cid" /opt/kafka/bin/kafka-consumer-groups.sh \
          --bootstrap-server kafka:9094 --command-config /tmp/kafka-tls/admin.properties \
          --describe --all-groups 2>/dev/null | grep -v '^$' || true)
    else
      k_out=$(timeout 60 docker exec "$k_cid" /opt/kafka/bin/kafka-consumer-groups.sh \
          --bootstrap-server kafka:9092 --describe --all-groups 2>/dev/null | grep -v '^$' || true)
    fi
    if [ -z "$k_out" ]; then
      pass "Kafka: no consumer groups yet (offsets absent — expected right after a reset)"
    else
      # Column 4 = CURRENT-OFFSET. Self-telemetry lanes (applogs) begin moving
      # within minutes of boot; a carried-over install shows 1e5..1e6+.
      local max_off
      max_off=$(printf '%s\n' "$k_out" | awk 'NR>1 && $4 ~ /^[0-9]+$/ { if ($4 > m) m = $4 } END { print m + 0 }')
      if [ "$max_off" -le 100000 ]; then
        pass "Kafka consumer groups present, max current-offset $max_off (<=100000 self-telemetry bound)"
      else
        fail "Kafka consumer-group offsets reach $max_off — the bus data dir was not reset"
      fi
    fi
  fi

  if [ "$FAILS" -gt 0 ]; then
    die "verification FAILED with $FAILS problem(s) — see lines above"
  fi
  info "verification PASSED — the stack is running from a clean slate"
}

# verify-only invocation: no wipe, no reinstall.
if [ "$DO_VERIFY" -eq 1 ] && [ "$DO_REINSTALL" -eq 0 ] && [ "$DO_RESET_ENV" -eq 0 ] && [ "$DRY_RUN" -eq 0 ]; then
  verify_stack
  exit 0
fi

# ---------------------------------------------------------------------------
# The destructive path: stop → wipe → chown [→ reset-env] [→ reinstall] [→ verify]
# ---------------------------------------------------------------------------
[ -d "$DATA_DIR" ] || die "data dir '$DATA_DIR' does not exist — nothing to wipe (fresh checkout? run install.py instead)"

# What will be destroyed — shown BEFORE any action (§16.3: state what a
# destructive step will touch, and confirm the target is the intended one).
ENTRIES=$(ls -A -- "$DATA_DIR" 2>/dev/null || true)
info "compose project : $PROJECT  (TLS variant: $IS_TLS)"
info "data dir        : $DATA_DIR"
if [ -z "$ENTRIES" ]; then
  info "data dir is already empty"
else
  info "will PERMANENTLY DELETE these subdirectories:"
  printf '    %s\n' "$ENTRIES"
fi
info ".env preserved  : $ENV_FILE $( [ "$DO_RESET_ENV" -eq 1 ] && echo '(then ROTATED by install.py --reset-env)' || echo '(unchanged)')"
if [ "$IS_TLS" -eq 1 ] && [ "$DO_REINSTALL" -eq 0 ]; then
  warn "this is a TLS-variant install: wiping data/tls + data/swtpm destroys the mesh custody — the stack will NOT start again until 'python3 scripts/install.py' re-mints it (or rerun with --reinstall)"
fi

if [ "$DRY_RUN" -eq 1 ]; then
  info "--dry-run: stopping here; nothing was changed"
  exit 0
fi

if [ "$ASSUME_YES" -ne 1 ]; then
  [ -t 0 ] || die "stdin is not a TTY and --yes was not given — refusing to destroy data unattended"
  printf 'clean-slate: type "yes" to destroy the data listed above: '
  read -r reply
  [ "$reply" = "yes" ] || die "aborted (answer was '$reply', not 'yes')"
fi

# 1. Stop the stack. compose needs .env for interpolation; fall back to a
#    label-based stop so a missing/broken .env cannot leave writers running
#    against the volumes we are about to delete.
if out=$(cd "$DOCKER_DIR" && timeout 300 docker compose -p "$PROJECT" down --remove-orphans --timeout 60 2>&1); then
  info "compose project '$PROJECT' stopped"
else
  warn "docker compose down failed (${out##*$'\n'}) — falling back to label-based stop"
  RUNNING=$(docker ps -q --filter "label=com.docker.compose.project=$PROJECT")
  if [ -n "$RUNNING" ]; then
    # shellcheck disable=SC2086  # container ids are single tokens by construction
    timeout 300 docker stop $RUNNING >/dev/null
    # shellcheck disable=SC2086
    timeout 120 docker rm $RUNNING >/dev/null
  fi
fi
LEFT=$(docker ps -q --filter "label=com.docker.compose.project=$PROJECT")
[ -z "$LEFT" ] || die "containers of project '$PROJECT' are still running after stop — refusing to wipe live volumes: $LEFT"

# 2. Wipe via a root helper container: service-owned files (postgres uid 70,
#    correlation 10001, valkey 999, mode-0700 dirs) are not removable by the
#    installing user. Mount the data dir itself so nothing outside it is
#    reachable, then clear its contents (dot-glob patterns cover hidden files;
#    unmatched patterns pass through literally and rm -f ignores them).
info "wiping contents of $DATA_DIR (helper image $HELPER_IMAGE, as root) ..."
if ! out=$(timeout 600 docker run --rm -v "$DATA_DIR":/data "$HELPER_IMAGE" \
    sh -c 'rm -rf -- /data/* /data/.[!.]* /data/..?* && ls -A /data' 2>&1); then
  die "wipe FAILED: $out"
fi
[ -z "$out" ] || die "wipe left entries behind: $out"
info "data dir emptied"

# 3. Hand data/ back to the invoking user so install.py (unprivileged) can
#    recreate the subdirectory tree.
OWNER="$(id -u):$(id -g)"
if ! out=$(timeout 60 docker run --rm -v "$DATA_DIR":/data "$HELPER_IMAGE" chown "$OWNER" /data 2>&1); then
  die "chown of $DATA_DIR to $OWNER FAILED: $out"
fi
info "chowned $DATA_DIR to $OWNER"

# 4. Optional secret rotation / reinstall — both delegated to install.py, the
#    single owner of .env semantics.
INSTALL_ARGS=()
[ "$ASSUME_YES" -eq 1 ] && INSTALL_ARGS+=(--assume-yes)
if [ "$DO_REINSTALL" -eq 1 ]; then
  [ "$DO_RESET_ENV" -eq 1 ] && INSTALL_ARGS+=(--reset-env)
  [ -n "$TLS_CHOICE" ] && INSTALL_ARGS+=(--tls "$TLS_CHOICE")
  info "reinstalling: python3 $SCRIPT_DIR/install.py ${INSTALL_ARGS[*]}"
  command -v python3 >/dev/null 2>&1 || die "python3 not found on PATH"
  timeout 3600 python3 "$SCRIPT_DIR/install.py" "${INSTALL_ARGS[@]}" \
    || die "install.py failed (exit $?) — the stack is stopped and data/ is empty; fix the error above and rerun install.py"
elif [ "$DO_RESET_ENV" -eq 1 ]; then
  info "rotating secrets: python3 $SCRIPT_DIR/install.py --reset-env --no-start ${INSTALL_ARGS[*]}"
  command -v python3 >/dev/null 2>&1 || die "python3 not found on PATH"
  timeout 900 python3 "$SCRIPT_DIR/install.py" --reset-env --no-start "${INSTALL_ARGS[@]}" \
    || die "install.py --reset-env failed (exit $?)"
  info "secrets rotated; the stack is NOT started (run install.py or compose up when ready)"
else
  info "done. The stack is stopped and data/ is empty; run 'python3 scripts/install.py' to reinitialize"
fi

# 5. Optional post-reset verification (needs the stack up, i.e. --reinstall).
if [ "$DO_VERIFY" -eq 1 ]; then
  if [ "$DO_REINSTALL" -eq 1 ]; then
    verify_stack
  else
    warn "--verify after a wipe without --reinstall: the stack is down, nothing to verify against — run 'clean-slate.sh --verify' once the stack is up"
  fi
fi
