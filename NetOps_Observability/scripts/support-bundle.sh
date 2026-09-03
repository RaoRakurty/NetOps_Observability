#!/usr/bin/env bash
#
# support-bundle.sh — one redacted diagnostic bundle a pilot can send back.
#
# Collects the evidence a Correlix support engineer needs to diagnose a stuck
# or unhealthy install WITHOUT asking the customer for twenty commands, and
# without ever carrying a secret off their host:
#
#     ./scripts/support-bundle.sh [--out DIR] [--since 24h] [--no-logs]
#
# Output: <out>/correlix-support-<host>-<UTCstamp>.tar.zst
#
# WHAT IS INSIDE (docs/runbooks/support-bundle.md is the customer-facing list):
#   compose/     ps -a, the RESOLVED compose config with every secret redacted,
#                the .env KEY NAMES only (never a value)
#   docker/      docker stats --no-stream
#   host/        df -h, free -m, uname -a, nproc
#   api/         /admin/version, /api/health, /api/health/score through the
#                local nginx (same unauthenticated probe the watchdog uses;
#                SUPPORT_API_TOKEN adds a bearer for the authenticated views)
#   bus/         kafka-consumer-groups --describe for the correlation group
#                (READ-ONLY: describe never commits or resets an offset)
#   store/       ClickHouse system.parts size/row summary + correlation table
#                counts; OpenSearch _cluster/health + index sizes
#   alerts/      vmalert active alerts
#   watchdog/    last 200 lines of the stack watchdog log
#   logs/        per-container `docker logs --since <since> --tail 20000`
#   MANIFEST     sha256 of every file + the per-collector status (ok / skip /
#                FAILED with the reason). A partial bundle is NEVER silent.
#
# REDACTION (§8, §16.5). Two independent passes run over EVERY collected file
# before it is packed:
#   1. key-pattern — any `KEY=value` / `KEY: value` whose key contains
#      PASSWORD, PASSWD, SECRET, KEY, TOKEN or DSN loses its value, plus
#      URL userinfo (scheme://user:pw@host).
#   2. literal value — every secret-shaped value read from the stack's own
#      .env is replaced wherever it appears, in any file, even inside a log
#      line or a JSON body. This is the pass that makes the guarantee hold for
#      values whose key we would not have recognised.
# The bundle is written 0600. Read the MANIFEST before you send it.
#
# EXIT CODES
#   0  every collector produced output (or was legitimately skipped)
#   1  the bundle could not be produced at all (bad flags, no output dir,
#      missing tar/zstd/sha256sum, archive failed)
#   2  the bundle WAS written, but at least one collector failed — the
#      failures are named in MANIFEST (§16.1: a degraded run is loud)
#
# Collector functions are invoked INDIRECTLY, by name, through `collect`
# (which owns the per-collector status bookkeeping), so shellcheck cannot
# see their call sites.
# shellcheck disable=SC2329
set -euo pipefail
export PATH="/usr/local/bin:/usr/bin:/bin:${PATH:-}"

SCRIPT_DIR="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"

say()  { printf '%s\n' "$*"; }
warn() { printf 'support-bundle: %s\n' "$*" >&2; }
die()  { printf 'support-bundle: ERROR: %s\n' "$*" >&2; exit 1; }

usage() {
  sed -n '3,12p' "$0" | sed 's/^# \{0,1\}//'
  cat <<'EOF'

Flags:
  --out DIR     write the archive here (default: the current directory)
  --since SPEC  how far back to read container logs (default: 24h;
                a Docker duration like 30m/24h/7d, or an RFC3339 timestamp)
  --no-logs     skip container logs entirely (smallest, fastest bundle)
  -h, --help    this text

Environment (all optional):
  APP_URL             dashboard base URL           (default http://localhost:8000/)
  APP_CACERT          PEM to VERIFY a TLS ingress against (never -k)
  SUPPORT_API_TOKEN   bearer token for the authenticated /api/* views
  COMPOSE_PROJECT     compose project name         (default from .env, else netops)
  WATCHDOG_LOG_FILE   watchdog log                 (default /var/log/correlix-watchdog.log)
EOF
}

# ---------- flags ------------------------------------------------------------
OUT_DIR="$PWD"
SINCE="24h"
WANT_LOGS=1
while [ $# -gt 0 ]; do
  case "$1" in
    --out)     OUT_DIR="${2:?--out needs a directory}"; shift 2 ;;
    --since)   SINCE="${2:?--since needs a duration like 24h}"; shift 2 ;;
    --no-logs) WANT_LOGS=0; shift ;;
    -h|--help) usage; exit 0 ;;
    *) printf 'support-bundle: unknown option: %s\n' "$1" >&2; usage >&2; exit 1 ;;
  esac
done

# Validate --since at the boundary (§3): a bad value would otherwise surface as
# eighteen identical `docker logs` failures halfway through the run.
if ! printf '%s' "$SINCE" | grep -qE '^([0-9]+(ns|us|ms|s|m|h)|[0-9]+[dwy]|[0-9]{4}-[0-9]{2}-[0-9]{2}([T ][0-9:.+Z-]+)?)$'; then
  die "--since '$SINCE' is not a Docker duration (30m, 24h, 7d) or an RFC3339 timestamp"
fi

# ---------- required tooling -------------------------------------------------
# These three produce the artifact itself; without them there is no bundle, so
# they are a hard gate rather than eighteen confusing collector failures.
for t in tar zstd sha256sum; do
  command -v "$t" >/dev/null 2>&1 || die "'$t' is not on PATH — it is required to write the bundle (install it: apt-get install -y $t)"
done
if ! command -v docker >/dev/null 2>&1; then
  warn "'docker' is not on PATH — every container/stack collector will be recorded as FAILED"
fi
if ! command -v curl >/dev/null 2>&1; then
  warn "'curl' is not on PATH — the API probes will be recorded as FAILED"
fi

# §16.3: every external call is bounded. A wedged dockerd must not hang the
# bundle forever; a host without `timeout` degrades LOUDLY, once.
DOCKER_TIMEOUT="${SUPPORT_DOCKER_TIMEOUT:-60}"
if command -v timeout >/dev/null 2>&1; then
  dkr() { timeout "$DOCKER_TIMEOUT" docker "$@"; }
else
  warn "'timeout' is not on PATH — docker calls run unbounded in this run"
  dkr() { docker "$@"; }
fi

# ---------- locate the install ----------------------------------------------
if [ -f "$SCRIPT_DIR/../deployment/docker/docker-compose.yml" ]; then
  ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
elif [ -f "$SCRIPT_DIR/NetOps_Observability/deployment/docker/docker-compose.yml" ]; then
  ROOT="$SCRIPT_DIR/NetOps_Observability"
else
  die "cannot find a Correlix install next to this script (expected ../deployment/docker/docker-compose.yml)"
fi
COMPOSE_DIR="$ROOT/deployment/docker"
ENV_FILE="${SUPPORT_ENV_FILE:-$COMPOSE_DIR/.env}"

env_get() { sed -n "s/^$1=//p" "$ENV_FILE" 2>/dev/null | head -1; }

dcompose() { ( cd "$COMPOSE_DIR" && dkr compose "$@" ); }

PROJECT="${COMPOSE_PROJECT:-$(env_get COMPOSE_PROJECT_NAME)}"
PROJECT="${PROJECT:-netops}"
APP_URL="${APP_URL:-http://localhost:$(env_get BASE_PORT || true)}"
case "$APP_URL" in
  *:) APP_URL="http://localhost:8000" ;;   # BASE_PORT absent from .env
esac
APP_CACERT="${APP_CACERT:-}"
HTTP_TIMEOUT="${SUPPORT_HTTP_TIMEOUT:-15}"
KAFKA_GROUP="${SUPPORT_KAFKA_GROUP:-netops-correlation}"
WATCHDOG_LOG_FILE="${WATCHDOG_LOG_FILE:-/var/log/correlix-watchdog.log}"
LOG_TAIL="${SUPPORT_LOG_TAIL:-20000}"

TLS=0
if [ -r "$ENV_FILE" ] && grep -q '^COMPOSE_FILE=.*compose\.tls\.yml' "$ENV_FILE"; then
  TLS=1
fi

# ---------- staging ----------------------------------------------------------
mkdir -p "$OUT_DIR" || die "cannot create output directory: $OUT_DIR"
[ -w "$OUT_DIR" ] || die "output directory is not writable: $OUT_DIR"
OUT_DIR="$(cd "$OUT_DIR" && pwd)"

HOST="$(hostname 2>/dev/null || echo unknown)"
HOST="$(printf '%s' "$HOST" | tr -c 'A-Za-z0-9._-' '-' )"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
BUNDLE="correlix-support-${HOST}-${STAMP}"

STAGE="$(mktemp -d "${TMPDIR:-/tmp}/correlix-support.XXXXXX")" \
  || die "cannot create a staging directory"
chmod 700 "$STAGE"
WORK="$STAGE/$BUNDLE"
mkdir -p "$WORK"
ERRTMP="$STAGE/.collector.err"
SECRETS_FILE="$STAGE/.secret-values"
: > "$SECRETS_FILE"
chmod 600 "$SECRETS_FILE"

cleanup() { rm -rf "$STAGE"; }
trap cleanup EXIT

START_EPOCH=$(date -u +%s)

# ---------- collector bookkeeping -------------------------------------------
# One row per collector: "<status>\t<relative path>\t<note>". Nothing is
# allowed to fail quietly — every row lands in the MANIFEST (§16.1).
declare -a ROWS=()
FAILED=0
SKIPPED=0

record() { ROWS+=("$1"$'\t'"$2"$'\t'"${3:-}"); }

note_fail() {  # rel, reason
  FAILED=$((FAILED + 1))
  record "FAILED" "$1" "$2"
  warn "collector FAILED: $1 — $2"
}

note_skip() {  # rel, reason
  SKIPPED=$((SKIPPED + 1))
  record "skip" "$1" "$2"
}

# collect <rel> <cmd...> — run a collector, keep whatever it produced, and
# record its verdict. Never aborts the run: a bundle missing one collector is
# far more useful than no bundle, as long as the gap is NAMED.
collect() {
  local rel="$1"; shift
  local dest="$WORK/$rel" rc=0 detail
  mkdir -p "$(dirname "$dest")"
  : > "$dest"
  : > "$ERRTMP"
  "$@" >"$dest" 2>"$ERRTMP" || rc=$?
  detail="$(tr '\n' ' ' < "$ERRTMP" | cut -c1-300)"
  if [ "$rc" -ne 0 ]; then
    {
      printf '\n### COLLECTOR FAILED (exit %s)\n' "$rc"
      cat "$ERRTMP"
    } >> "$dest"
    note_fail "$rel" "exit $rc: ${detail:-no stderr}"
    return 0
  fi
  if [ ! -s "$dest" ]; then
    printf '### COLLECTOR PRODUCED NO OUTPUT\n' >> "$dest"
    note_fail "$rel" "exit 0 but empty output (probe answered nothing)"
    return 0
  fi
  record "ok" "$rel" "${detail:+stderr: $detail}"
  return 0
}

# ---------- container lookup -------------------------------------------------
cid_of() {  # compose service name -> container id (empty when not running)
  dkr ps -q --filter "label=com.docker.compose.project=$PROJECT" \
           --filter "label=com.docker.compose.service=$1" 2>/dev/null | head -1
}

# A container that is on the compose network AND has curl — the vantage the
# store probes speak from (same doctrine as stack-watchdog.sh: never publish a
# store port to the host just to observe it).
PROBE_CID=""
probe_cid() {
  local svc
  if [ -n "$PROBE_CID" ]; then printf '%s' "$PROBE_CID"; return 0; fi
  for svc in ${SUPPORT_PROBE_FROM:-vector-router opensearch nginx api}; do
    PROBE_CID="$(cid_of "$svc" || true)"
    if [ -n "$PROBE_CID" ]; then printf '%s' "$PROBE_CID"; return 0; fi
  done
  return 1
}

# ---------- 1. compose + docker ---------------------------------------------
c_compose_ps()    { dcompose ps -a; }
c_compose_config() { dcompose config; }
c_docker_stats()  { dkr stats --no-stream; }

c_env_keys() {
  # KEY NAMES ONLY. The value never leaves the host — not even redacted, so
  # there is no length or shape to infer from.
  [ -r "$ENV_FILE" ] || { printf 'cannot read %s\n' "$ENV_FILE" >&2; return 1; }
  printf '# %s — KEY NAMES ONLY, values are never collected\n' "$ENV_FILE"
  sed -n 's/^\([A-Za-z_][A-Za-z0-9_]*\)=.*/\1/p' "$ENV_FILE" | sort -u
}

collect compose/ps.txt              c_compose_ps
collect compose/config.redacted.yml c_compose_config
collect compose/env-keys.txt        c_env_keys
collect docker/stats.txt            c_docker_stats

# ---------- 2. host ----------------------------------------------------------
collect host/df.txt    df -h
collect host/free.txt  free -m
collect host/uname.txt uname -a
collect host/nproc.txt nproc

# ---------- 3. API through the local nginx -----------------------------------
# Same probe posture as the watchdog: plain curl through the ingress a user
# would use, CA-VERIFIED when APP_CACERT is set (never -k). /api/health and
# /api/health/score are authenticated routes — without SUPPORT_API_TOKEN they
# answer 401, which is a POSTURE fact worth capturing, not a collector failure.
# The token rides a curl config on STDIN so it appears in no argv.
api_fetch() {  # url path
  local cfg
  cfg=$(printf '%s\n' \
    "url = \"${APP_URL%/}$1\"" \
    "max-time = $HTTP_TIMEOUT" "silent" "show-error" \
    "write-out = \"\\nHTTP:%{http_code}\\n\"")
  if [ -n "$APP_CACERT" ]; then
    cfg="$cfg"$'\n'"cacert = \"$APP_CACERT\""
  fi
  if [ -n "${SUPPORT_API_TOKEN:-}" ]; then
    cfg="$cfg"$'\n'"header = \"Authorization: Bearer ${SUPPORT_API_TOKEN}\""
  fi
  printf '%s' "$cfg" | curl --config -
}

api_collect() {  # rel, path
  collect "$1" api_fetch "$2"
  local code
  code=$(sed -n 's/^HTTP:\([0-9]*\)$/\1/p' "$WORK/$1" 2>/dev/null | tail -1)
  case "${code:-}" in
    200|"") ;;
    401|403)
      record "note" "$1" "HTTP $code — authenticated route; set SUPPORT_API_TOKEN for the full view" ;;
    *)
      record "note" "$1" "HTTP $code — the endpoint answered, but not 200" ;;
  esac
}

api_collect api/admin-version.json /admin/version
api_collect api/health.json        /api/health
api_collect api/health-score.json  "/api/health/score?scope=global"

# ---------- 4. event bus (read-only) ----------------------------------------
c_kafka_lag() {
  local cid
  cid="$(cid_of kafka || true)"
  if [ -z "$cid" ]; then
    printf 'no running kafka container in project %s (external broker?)\n' "$PROJECT" >&2
    return 1
  fi
  # --describe is a READ. It reports lag; it never commits or resets an offset.
  if [ "$TLS" = 1 ]; then
    dkr exec "$cid" /opt/kafka/bin/kafka-consumer-groups.sh \
      --bootstrap-server kafka:9094 --command-config /tmp/kafka-tls/admin.properties \
      --describe --group "$KAFKA_GROUP"
  else
    dkr exec "$cid" /opt/kafka/bin/kafka-consumer-groups.sh \
      --bootstrap-server kafka:9092 --describe --group "$KAFKA_GROUP"
  fi
}
collect bus/kafka-consumer-lag.txt c_kafka_lag

# ---------- 5. ClickHouse (bounded, read-only) -------------------------------
CH_PROBE_CACERT="${CH_PROBE_CACERT:-/tls/ca.pem}"
if [ -n "${CH_PROBE_URL:-}" ]; then
  :
elif [ "$TLS" = 1 ]; then
  CH_PROBE_URL="https://clickhouse:8443"
else
  CH_PROBE_URL="http://clickhouse:8123"
fi

ch_query() {  # single-line SQL (no double quotes)
  local cid cfg user pw
  cid="$(probe_cid || true)"
  if [ -z "$cid" ]; then
    printf 'no running container to reach ClickHouse from (set SUPPORT_PROBE_FROM)\n' >&2
    return 1
  fi
  user="$(env_get CLICKHOUSE_USER || true)"
  pw="$(env_get CLICKHOUSE_PASSWORD || true)"
  if [ -z "$pw" ]; then
    printf 'CLICKHOUSE_PASSWORD is unreadable from %s — cannot query the store\n' "$ENV_FILE" >&2
    return 1
  fi
  # url/credentials/CA all arrive on STDIN: no credential in argv, on the host
  # or in the container (same doctrine as stack-watchdog.sh).
  cfg=$(printf '%s\n' \
    "url = \"$CH_PROBE_URL/\"" \
    "user = \"${user:-netops}:$pw\"" \
    "data = \"$1\"" \
    "max-time = 25" "silent" "show-error" "write-out = \"\\nHTTP:%{http_code}\\n\"")
  case "$CH_PROBE_URL" in
    https://*) cfg="$cfg"$'\n'"cacert = \"$CH_PROBE_CACERT\"" ;;
  esac
  printf '%s' "$cfg" | dkr exec -i "$cid" curl --config -
}

CH_PARTS_SQL="SELECT database, table, sum(rows) AS rows, formatReadableSize(sum(bytes_on_disk)) AS size, count() AS parts FROM system.parts WHERE active GROUP BY database, table ORDER BY sum(bytes_on_disk) DESC LIMIT 200 SETTINGS max_execution_time=20 FORMAT TSVWithNames"
# count() on a MergeTree is a metadata read, and the execution-time ceiling
# keeps a degraded store from turning the bundle into a long query.
CH_CORR_SQL="SELECT 'corr_signals' AS tbl, count() AS rows FROM netops.corr_signals UNION ALL SELECT 'corr_current', count() FROM netops.corr_current UNION ALL SELECT 'corr_objects', count() FROM netops.corr_objects UNION ALL SELECT 'corr_edges', count() FROM netops.corr_edges ORDER BY tbl SETTINGS max_execution_time=20, tenant_scope='__all__' FORMAT TSVWithNames"

collect store/clickhouse-parts.tsv      ch_query "$CH_PARTS_SQL"
collect store/clickhouse-corr-rows.tsv  ch_query "$CH_CORR_SQL"

# ---------- 6. OpenSearch ----------------------------------------------------
OS_PROBE_CACERT="${OS_PROBE_CACERT:-/usr/share/opensearch/config/tls/ca.pem}"
os_fetch() {  # path (+query)
  local cid cfg url pw
  cid="$(cid_of opensearch || true)"
  if [ -z "$cid" ]; then
    printf 'no running opensearch container in project %s\n' "$PROJECT" >&2
    return 1
  fi
  if [ "$TLS" = 1 ]; then
    url="https://localhost:9200"
    pw="$(env_get OS_API_PASSWORD || true)"
    if [ -z "$pw" ]; then
      printf 'TLS install but OS_API_PASSWORD is unreadable from %s\n' "$ENV_FILE" >&2
      return 1
    fi
  else
    url="http://localhost:9200"
  fi
  cfg=$(printf '%s\n' "url = \"$url$1\"" "max-time = 20" "silent" "show-error")
  if [ "$TLS" = 1 ]; then
    cfg="$cfg"$'\n'"cacert = \"$OS_PROBE_CACERT\""$'\n'"user = \"svc_api:$pw\""
  fi
  printf '%s' "$cfg" | dkr exec -i "$cid" curl --config -
}

collect store/opensearch-cluster-health.json os_fetch "/_cluster/health?pretty"
collect store/opensearch-indices.txt         os_fetch "/_cat/indices?v&bytes=b&s=store.size:desc"

# ---------- 7. vmalert -------------------------------------------------------
c_vmalert() {
  local cid out
  cid="$(probe_cid || true)"
  if [ -z "$cid" ]; then
    printf 'no running container to reach vmalert from (set SUPPORT_PROBE_FROM)\n' >&2
    return 1
  fi
  out="$(dkr exec "$cid" curl -sS -m 10 "http://vmalert:8880/api/v1/alerts" 2>&1)" || out=""
  if [ -n "$out" ] && printf '%s' "$out" | grep -q '"alerts"'; then
    printf '%s\n' "$out"
    return 0
  fi
  # vmalert unreachable (or answering something else): fall back to the firing
  # ALERTS series VictoriaMetrics itself holds — the same query the watchdog
  # pages from. Both being empty is reported as a failure, never as silence.
  printf '# vmalert /api/v1/alerts gave no alert list; falling back to the VictoriaMetrics ALERTS series\n'
  dkr exec "$cid" curl -sS -m 10 -G "http://victoria:8428/api/v1/query" \
    --data-urlencode 'query=ALERTS{alertstate="firing"}'
}
collect alerts/vmalert-alerts.json c_vmalert

# ---------- 8. watchdog log --------------------------------------------------
WD_LOG=""
# Order matters: first readable wins. $WATCHDOG_LOG_FILE is the packaged
# install's path; data/stack-watchdog.log is where the README's repo cron
# writes. `scripts/stack-watchdog.log` is a LEGACY path the README used to
# document — kept last so an old host still yields something, but it must
# never be preferred: on the dev host it survived as a 24 MB orphan, last
# written 2026-08-22, while the live log was elsewhere (2026-09-03 drill).
for cand in "$WATCHDOG_LOG_FILE" "$ROOT/data/stack-watchdog.log" \
            "$SCRIPT_DIR/stack-watchdog.log" "$ROOT/scripts/stack-watchdog.log"; do
  if [ -r "$cand" ]; then WD_LOG="$cand"; break; fi
done
if [ -n "$WD_LOG" ]; then
  collect watchdog/watchdog-log.txt tail -n 200 "$WD_LOG"
else
  mkdir -p "$WORK/watchdog"
  printf 'no readable watchdog log (looked at: %s)\n' "$WATCHDOG_LOG_FILE" \
    > "$WORK/watchdog/watchdog-log.txt"
  note_skip watchdog/watchdog-log.txt \
    "no readable watchdog log at $WATCHDOG_LOG_FILE (watchdog not installed on this host?)"
fi

# ---------- 9. container logs ------------------------------------------------
c_log_one() { dkr logs --since "$SINCE" --tail "$LOG_TAIL" "$1" 2>&1; }

if [ "$WANT_LOGS" = 1 ]; then
  containers="$(dkr ps -a --filter "label=com.docker.compose.project=$PROJECT" \
                  --format '{{.Names}}' 2>/dev/null || true)"
  if [ -z "$containers" ]; then
    mkdir -p "$WORK/logs"
    printf 'no containers found for compose project %s\n' "$PROJECT" > "$WORK/logs/README.txt"
    note_fail "logs/" "no containers found for compose project '$PROJECT' (set COMPOSE_PROJECT)"
  else
    while IFS= read -r name; do
      [ -n "$name" ] || continue
      safe="$(printf '%s' "$name" | tr -c 'A-Za-z0-9._-' '-')"
      collect "logs/$safe.log" c_log_one "$name"
    done <<< "$containers"
  fi
else
  mkdir -p "$WORK/logs"
  printf 'container logs were skipped (--no-logs)\n' > "$WORK/logs/README.txt"
  note_skip "logs/" "skipped by --no-logs"
fi

# ---------- redaction --------------------------------------------------------
# Pass 2's input: every secret-shaped VALUE this install actually holds. Read
# straight from .env, kept in a 0600 file under the staging dir, and destroyed
# with it on exit. Longest first so an embedded shorter value cannot leave a
# fragment of a longer one behind.
if [ -r "$ENV_FILE" ]; then
  sed -n 's/^[A-Za-z_][A-Za-z0-9_]*\(PASSWORD\|PASSWD\|SECRET\|KEY\|TOKEN\|DSN\)[A-Za-z0-9_]*=//p' "$ENV_FILE" \
    | sed 's/^["'"'"']//; s/["'"'"']$//' \
    | awk 'length($0) >= 6 { print length($0)"\t"$0 }' \
    | sort -rn | cut -f2- | sort -u -r \
    > "$SECRETS_FILE"
else
  warn "no readable $ENV_FILE — the literal-value redaction pass has nothing to match (key-pattern redaction still runs)"
fi
if [ -n "${SUPPORT_API_TOKEN:-}" ]; then
  printf '%s\n' "$SUPPORT_API_TOKEN" >> "$SECRETS_FILE"
fi

redact_stream() {
  # Pass 1: key-pattern + URL userinfo.
  LC_ALL=C sed -E \
    -e 's/^([[:space:]]*-?[[:space:]]*[A-Za-z0-9_]*(PASSWORD|PASSWD|SECRET|KEY|TOKEN|DSN)[A-Za-z0-9_]*)=.*/\1=***REDACTED***/' \
    -e 's/^([[:space:]]*"?[A-Za-z0-9_]*(PASSWORD|PASSWD|SECRET|KEY|TOKEN|DSN)[A-Za-z0-9_]*"?)[[:space:]]*:[[:space:]]*.*/\1: ***REDACTED***/' \
    -e 's#([a-zA-Z][a-zA-Z0-9+.-]*://[^:/@[:space:]]+):[^@[:space:]]+@#\1:***REDACTED***@#g' |
  # Pass 2: literal values from .env, replaced wherever they appear.
  LC_ALL=C awk -v secrets="$SECRETS_FILE" '
    BEGIN {
      n = 0
      while ((getline line < secrets) > 0) { if (length(line) >= 6) vals[++n] = line }
      close(secrets)
    }
    {
      for (i = 1; i <= n; i++) {
        v = vals[i]; out = ""; s = $0
        while ((p = index(s, v)) > 0) {
          out = out substr(s, 1, p - 1) "***REDACTED***"
          s = substr(s, p + length(v))
        }
        $0 = out s
      }
      print
    }'
}

redact_failed=0
while IFS= read -r f; do
  if redact_stream < "$f" > "$f.redacted"; then
    mv -f "$f.redacted" "$f"
  else
    rc=$?
    rm -f "$f.redacted"
    redact_failed=$((redact_failed + 1))
    warn "redaction pass failed for ${f#"$WORK"/} (exit $rc) — removing the file rather than shipping it unredacted"
    printf '### FILE REMOVED: the redaction pass failed, so this content was NOT shipped\n' > "$f"
    note_fail "${f#"$WORK"/}" "redaction failed (exit $rc); content withheld"
  fi
done < <(find "$WORK" -type f | sort)
if [ "$redact_failed" -gt 0 ]; then
  warn "$redact_failed file(s) could not be redacted and were withheld — see MANIFEST"
fi

# ---------- MANIFEST ---------------------------------------------------------
END_EPOCH=$(date -u +%s)
OK_COUNT=0
for row in ${ROWS+"${ROWS[@]}"}; do
  case "$row" in ok*) OK_COUNT=$((OK_COUNT + 1)) ;; esac
done

{
  printf 'Correlix support bundle\n'
  printf '=======================\n\n'
  printf 'bundle:        %s\n' "$BUNDLE"
  printf 'host:          %s\n' "$HOST"
  printf 'generated_utc: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf 'duration_s:    %s\n' "$((END_EPOCH - START_EPOCH))"
  printf 'install_root:  %s\n' "$ROOT"
  printf 'project:       %s\n' "$PROJECT"
  printf 'app_url:       %s\n' "$APP_URL"
  printf 'tls_variant:   %s\n' "$([ "$TLS" = 1 ] && echo yes || echo no)"
  printf 'log_window:    %s\n' "$([ "$WANT_LOGS" = 1 ] && echo "$SINCE (tail $LOG_TAIL)" || echo "skipped (--no-logs)")"
  printf 'script_sha256: %s\n' "$(sha256sum "${BASH_SOURCE[0]}" | cut -d' ' -f1)"
  printf 'collectors:    %s ok, %s skipped, %s FAILED\n' "$OK_COUNT" "$SKIPPED" "$FAILED"
  printf 'exit_code:     %s\n' "$([ "$FAILED" -gt 0 ] && echo 2 || echo 0)"
  printf '\nREDACTION\n'
  printf '  1. key-pattern: *PASSWORD*/*PASSWD*/*SECRET*/*KEY*/*TOKEN*/*DSN* values\n'
  printf '     in KEY=value and KEY: value form, plus URL userinfo credentials.\n'
  printf '  2. literal value: every secret-shaped value in the stack .env is\n'
  printf '     replaced wherever it appears in ANY file of this bundle.\n'
  printf '  .env is included as KEY NAMES ONLY — no value, redacted or otherwise.\n'
  printf '\nSTATUS (a FAILED collector means this bundle is PARTIAL — it is never silent)\n'
  for row in ${ROWS+"${ROWS[@]}"}; do
    printf '  %s\n' "$row"
  done
  printf '\nSHA256\n'
  ( cd "$WORK" && find . -type f ! -name MANIFEST | sort | sed 's|^\./||' | \
      while IFS= read -r rel; do sha256sum "$rel"; done )
} > "$WORK/MANIFEST"

# ---------- archive ----------------------------------------------------------
ARCHIVE="$OUT_DIR/$BUNDLE.tar.zst"
if ! ( cd "$STAGE" && tar -cf - "$BUNDLE" | zstd -q -T0 -o "$ARCHIVE" ); then
  die "could not write the archive $ARCHIVE (tar/zstd failed)"
fi
chmod 600 "$ARCHIVE"

SIZE="$(du -h "$ARCHIVE" | cut -f1)"
say ""
say "Support bundle: $ARCHIVE  ($SIZE)"
say "  collectors:   $OK_COUNT ok, $SKIPPED skipped, $FAILED failed"
say "  contents:     read MANIFEST inside the archive before sending it"
say "  redaction:    secrets removed by key pattern AND by literal .env value"
if [ "$FAILED" -gt 0 ]; then
  warn "$FAILED collector(s) FAILED — the bundle was still written and every failure is named in its MANIFEST"
  exit 2
fi
exit 0
