#!/usr/bin/env bash
#
# NetOps stack watchdog.
#
# Runs from cron once a minute. Verifies every compose service is running
# (and healthy, where a healthcheck exists) and that the dashboard answers
# on :8000. Then:
#
#   * Healthy   -> pings the healthchecks.io heartbeat URL. If this host or
#                  its network dies, the pings stop and healthchecks.io
#                  (off-host) alerts you — the dead-man's-switch.
#   * Down      -> hits the healthchecks.io /fail endpoint AND pushes an
#                  ntfy.sh notification to your phone naming the dead service.
#
# Alerts fire only on a state TRANSITION, tracked PER PROBLEM CLASS (H16,
# 2026-08-15): a sustained outage produces one push, not one per minute — and
# a STANDING advisory problem (config drift, a stale backup) can no longer
# swallow the push for a NEW critical one (a service dying), which is exactly
# what the old single up/down flag did.
#
# Config (NTFY_TOPIC, HC_PING_URL, WATCHDOG_EMAIL, ...) lives in
# stack-watchdog.env next to this script, or — for packaged installs, written
# by install-watchdog.sh — in /etc/correlix/stack-watchdog.env. The sibling
# file wins when both exist; WATCHDOG_ENV overrides both. See
# stack-watchdog.env.example for every knob. No secrets are baked in here.

set -uo pipefail
export PATH="/usr/local/bin:/usr/bin:/bin:${PATH:-}"

# ---------------------------------------------------------------------------
# §16.2 — TIMESTAMP EVERY LINE (2026-09-03).
#
# This script's diagnostics are appended by cron to a single ever-growing file
# (`data/stack-watchdog.log` for the repo cron; /var/log/correlix-watchdog.log
# for packaged installs). Until now not one line carried a time, so a 13 MB log
# could say WHAT happened and never WHEN: the 2026-09-03 drill had to
# reconstruct the outage timeline from container logs instead of from the
# watchdog's own record, which is the one artefact that is supposed to survive
# the stack dying.
#
# log()/logerr() are the ONLY way this script emits a diagnostic line. They
# stamp EVERY line of a multi-line message — the DOWN summary carries one line
# per problem, and an unstamped continuation is what made the old log
# ungreppable. Format is ISO-8601 local time WITH the UTC offset, so lines
# stay comparable across a DST change and against `docker logs -t`.
#
# Data-carrying `printf`s (function return values captured by `$( )`, state
# files) deliberately do NOT go through these — stamping those would corrupt
# the value.
# ---------------------------------------------------------------------------
_log_stamped() {
  local ts line
  ts="$(date +'%Y-%m-%dT%H:%M:%S%z')"
  printf '%s\n' "$*" | while IFS= read -r line; do
    printf '%s %s\n' "$ts" "$line"
  done
}
# Declared as full blocks (not one-liners) so the unit tests that extract a
# single function with `sed -n '/^name() {/,/^}/p'` can pull these in too —
# every extracted function calls them.
log() {
  _log_stamped "$*"
}
logerr() {
  _log_stamped "$*" >&2
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Config resolution: explicit WATCHDOG_ENV > sibling env file (the original
# layout — unchanged) > the packaged-install location install-watchdog.sh
# writes (root-owned 0600; the cron line it installs passes WATCHDOG_ENV
# explicitly, so this fallback only matters for by-hand runs).
SYSTEM_ENV_FILE="/etc/correlix/stack-watchdog.env"
if [ -n "${WATCHDOG_ENV:-}" ]; then
  ENV_FILE="$WATCHDOG_ENV"
elif [ -f "$SCRIPT_DIR/stack-watchdog.env" ]; then
  ENV_FILE="$SCRIPT_DIR/stack-watchdog.env"
else
  ENV_FILE="$SYSTEM_ENV_FILE"
fi

# shellcheck disable=SC1090
[ -f "$ENV_FILE" ] && { set -a; . "$ENV_FILE"; set +a; }

# Resolved AFTER the env file so WATCHDOG_STATE may be set there too (default:
# state lives next to the script; cron runs as root, which owns both).
STATE_FILE="${WATCHDOG_STATE:-$SCRIPT_DIR/.stack-watchdog.state}"

# ---------------------------------------------------------------------------
# M25 §16.3: EVERY docker call bounded. docker ps/inspect/logs/exec against a
# wedged dockerd block forever; from a one-minute cron that means runs pile up
# behind the hang (see the flock below) and the watchdog stops watching.
# dkr = the default 20s bound; dkr_slow = for calls that legitimately work
# (builder prune). §16.2: a host without `timeout` degrades LOUDLY, once.
# ---------------------------------------------------------------------------
if command -v timeout >/dev/null 2>&1; then
  dkr()      { timeout "${WATCHDOG_DOCKER_TIMEOUT:-20}" docker "$@"; }
  dkr_slow() { timeout "${WATCHDOG_DOCKER_SLOW_TIMEOUT:-120}" docker "$@"; }
else
  logerr "watchdog: 'timeout' not on PATH — docker calls run unbounded this run"
  dkr()      { docker "$@"; }
  dkr_slow() { docker "$@"; }
fi

PROJECT="${COMPOSE_PROJECT:-netops}"
APP_URL="${APP_URL:-http://localhost:8000/}"
# When APP_URL is https behind a self-signed/dev ingress cert, point APP_CACERT
# at the cert (PEM) so the probe VALIDATES it instead of riding -k. Empty =
# system trust store (real certs need nothing here).
APP_CACERT="${APP_CACERT:-}"
NTFY_SERVER="${NTFY_SERVER:-https://ntfy.sh}"

# NOTE: telegraf is intentionally absent — it was retired (legacy compose
# profile, not started by default; Go collector owns SNMP). Re-adding it here
# would false-alarm every minute. gnmic is the gNMI collector if profiled in.
# vmalert is in this list on purpose (F-16): it is the stack's ONLY standing
# metric-alerting engine, so if it dies every metric-based alert silently stops
# and nothing else would notice. cadvisor/node-exporter/grafana/kafka-exporter
# stay out — they belong to the optional self-monitoring profile.
# WATCHDOG_SERVICES (space-separated compose service names) overrides the
# default below. Packaged installs write the customer base set (no
# self-monitoring / osd add-ons); the default preserves the original layout.
EXPECTED_SERVICES="${WATCHDOG_SERVICES:-api clickhouse correlation frontend goflow2 grafana kafka \
nginx opensearch opensearch-dashboards postgres prober redis \
syslog-ng vector-aggregator vector-router victoria vmalert}"

push() {  # title, tags, priority, body
  if [ -z "${NTFY_TOPIC:-}" ]; then
    # ntfy can only publish TO A TOPIC; email fan-out rides the topic publish.
    # WATCHDOG_EMAIL alone is therefore a misconfiguration — name it (§16.1)
    # instead of silently delivering nothing.
    [ -n "${WATCHDOG_EMAIL:-}" ] &&
      logerr "watchdog: WATCHDOG_EMAIL is set but NTFY_TOPIC is empty — ntfy requires a topic, notification NOT sent"
    return 0
  fi
  local hdr=(-H "Title: $1" -H "Tags: $2" -H "Priority: $3")
  # Authenticated (self-hosted) ntfy: bearer token on every publish.
  [ -n "${NTFY_TOKEN:-}" ] && hdr+=(-H "Authorization: Bearer $NTFY_TOKEN")
  # Per-message email fan-out: the ntfy server also delivers this notification
  # to the address (needs a server with SMTP configured; ntfy.sh has it).
  [ -n "${WATCHDOG_EMAIL:-}" ] && hdr+=(-H "Email: $WATCHDOG_EMAIL")
  curl -fsS -m 10 "${hdr[@]}" \
    -d "$4" "$NTFY_SERVER/$NTFY_TOPIC" -o /dev/null \
    || logerr "watchdog: ntfy push failed"
}

json_str() {  # encode $1 as a JSON string literal (incl. surrounding quotes)
  local s
  # Drop control chars JSON forbids raw; \n, \r and \t survive and are escaped
  # below (detail text carries newline-joined problem lists and log excerpts).
  s=$(printf '%s' "$1" | tr -d '\000-\010\013\014\016-\037')
  s=${s//\\/\\\\}
  s=${s//\"/\\\"}
  s=${s//$'\n'/\\n}
  s=${s//$'\r'/\\r}
  s=${s//$'\t'/\\t}
  printf '"%s"' "$s"
}

# Generic enterprise channel: one JSON POST per up<->down transition to
# WATCHDOG_WEBHOOK_URL (Slack / Teams / Opsgenie incoming webhooks, or any
# relay). Optional WATCHDOG_WEBHOOK_TOKEN rides as a bearer header. Payload:
#   {"text":"...","host":"...","status":"down|up|test","detail":"...","ts":"..."}
# The "text" field is load-bearing: Slack and Teams incoming webhooks REJECT
# bodies without it (400), while relays that want structure read the typed
# fields — one payload serves both audiences (ultra-review find, 2026-08-14).
notify_webhook() {  # status, detail
  [ -n "${WATCHDOG_WEBHOOK_URL:-}" ] || return 0
  local hdr=(-H "Content-Type: application/json")
  [ -n "${WATCHDOG_WEBHOOK_TOKEN:-}" ] && hdr+=(-H "Authorization: Bearer $WATCHDOG_WEBHOOK_TOKEN")
  local payload
  payload=$(printf '{"text":%s,"host":%s,"status":%s,"detail":%s,"ts":%s}' \
    "$(json_str "Correlix watchdog: $(hostname) is $1 — $2")" \
    "$(json_str "$(hostname)")" "$(json_str "$1")" \
    "$(json_str "$2")" "$(json_str "$(date -Is)")")
  curl -fsS -m 10 "${hdr[@]}" -d "$payload" "$WATCHDOG_WEBHOOK_URL" -o /dev/null \
    || logerr "watchdog: webhook notify failed"
}

# -----------------------------------------------------------------------------
# API LIVENESS (tracker 194) — the probe that ":8000/" cannot be.
#
# The end-to-end probe further down hits APP_URL (:8000/), which nginx's
# `location /` proxies to the FRONTEND: the SPA answers 200 with the api dead,
# and default.conf declares no /healthz location, so that path falls through to
# the SPA too. The api container declares no healthcheck either, so the
# container loop reads "running" for a process that is not serving. Net effect
# (observed 2026-08-31 01:48-01:51): a two-minute api outage was invisible —
# no page, and the dead-man's switch kept reporting "healthy".
#
# /admin/version is the one route only the api BINARY can answer (nginx
# `location /admin/` proxies it to api:8080). A 200 with a non-empty body is
# proof the api is serving through the same ingress a user would use —
# transport, nginx and the process in one probe.
#
# COLD-BOOT GRACE. The api needs ~2.5 min to serve after a restart on this box
# (fault-in under redeploy IO pressure), so paging on the first failing minute
# would fire on every deploy. The grace is measured in WALL CLOCK, not in
# missed runs: the cron cadence is NOT a reliable clock — the flock above
# legitimately skips minutes when dockerd wedges, and a packaged install may
# schedule this at another interval, so a "3 consecutive misses" counter means
# a different amount of real time on every host (§16.2: assume nothing about
# the environment). The anchor is the LATER of
#   (a) the first failing probe, and
#   (b) the api container's .State.StartedAt,
# so a restart landing mid-outage restarts the boot budget exactly once, while
# a long-running api that starts failing still escalates after the same ~150 s.
# docker is best-effort here: an unreadable start time degrades to (a) alone,
# never to an unbounded grace. And the grace can never suppress forever —
# API_BOOT_GRACE_MAX_SEC is a hard ceiling, and once escalated the verdict is
# STICKY until a probe actually SUCCEEDS, so a crash-looping api cannot win a
# fresh grace every minute.
# -----------------------------------------------------------------------------
API_PROBE_URL="${API_PROBE_URL:-${APP_URL%/}/admin/version}"
API_SERVICE="${API_SERVICE:-api}"
API_STATE="${WATCHDOG_API_STATE:-$SCRIPT_DIR/.stack-watchdog.api}"
API_BOOT_GRACE_SEC="${API_BOOT_GRACE_SEC:-150}"
API_BOOT_GRACE_MAX_SEC="${API_BOOT_GRACE_MAX_SEC:-600}"
API_PROBE_TIMEOUT="${API_PROBE_TIMEOUT:-10}"

# Pure probe: no state, no problems[], no pushes — so --test and the cron flow
# exercise the SAME code. Prints "<curl-rc> <http-code> <detail>" and returns 0
# only for a 200 WITH a non-empty body (an empty 200 is not a serving api).
api_probe_once() {
  local out rc code body detail
  out=$(curl -sS -m "$API_PROBE_TIMEOUT" ${APP_CACERT:+--cacert "$APP_CACERT"} \
          -w '\nHTTP:%{http_code}' "$API_PROBE_URL" 2>&1)
  rc=$?
  code=$(printf '%s' "$out" | sed -n 's/.*HTTP:\([0-9]*\).*/\1/p' | tail -1)
  body=$(printf '%s' "$out" | sed 's/HTTP:[0-9]*//' | tr -d '[:space:]')
  detail=$(printf '%s' "$out" | tr '\n' ' ' | cut -c1-160)
  if [ "$rc" -eq 0 ] && [ "${code:-}" = "200" ] && [ -n "$body" ]; then
    printf '%s %s %s\n' "$rc" "$code" "ok"
    return 0
  fi
  # An empty body carries no curl error text to report — name that explicitly
  # rather than emitting a blank diagnostic (§16.1).
  [ -n "$body" ] || detail="${detail:-empty body}"
  printf '%s %s %s\n' "$rc" "${code:-none}" "${detail:-no output}"
  return 1
}

# --test exercises every configured channel so you can confirm delivery
# (phone subscribed, email arriving, webhook wired), then exits.
if [ "${1:-}" = "--test" ]; then
  push "NetOps watchdog test" "test_tube" "default" \
    "Test alert from $(hostname) at $(date -Is). If you see this, alerting works."
  log "Sent test push to topic '${NTFY_TOPIC:-<unset>}' on $NTFY_SERVER"
  if [ -n "${WATCHDOG_WEBHOOK_URL:-}" ]; then
    notify_webhook "test" "Test notification from $(hostname) at $(date -Is). If you see this, the webhook channel works."
    log "Sent test webhook POST to $WATCHDOG_WEBHOOK_URL"
  fi
  # Tracker 194: also exercise the api liveness probe. A --test that only
  # proves ntfy delivers cannot tell you the probe it arms is pointed at
  # anything real, and this probe is the one that pages for an api outage.
  if t_out=$(api_probe_once); then
    read -r t_rc t_code t_detail <<<"$t_out"
    log "api liveness probe OK: $API_PROBE_URL -> HTTP $t_code, non-empty body (curl rc=$t_rc, ${t_detail})"
    exit 0
  fi
  read -r t_rc t_code t_detail <<<"$t_out"
  logerr "api liveness probe FAILED: $API_PROBE_URL -> curl rc=$t_rc HTTP=$t_code: $t_detail"
  logerr "watchdog: sustained past the ${API_BOOT_GRACE_SEC}s cold-boot grace this is classified CRITICAL (urgent push, and the healthy heartbeat stops)"
  exit 1
fi

# M25: overlap guard. When dockerd wedges, a run outlives its minute; without
# a lock every later minute stacks another blocked watchdog behind it. flock
# -n: the newcomer yields (the RUNNING probe is the valid one) and says so —
# a skipped minute is visible in the log, and the healthchecks dead-man's
# switch still fires if the holder never finishes.
LOCK_FILE="${WATCHDOG_LOCK:-${STATE_FILE}.lock}"
if command -v flock >/dev/null 2>&1; then
  if exec 9>"$LOCK_FILE"; then
    if ! flock -n 9; then
      logerr "watchdog: previous run still holds $LOCK_FILE — skipping this minute (wedged docker?)"
      exit 0
    fi
  else
    logerr "watchdog: cannot open lock file $LOCK_FILE — running without overlap protection"
  fi
else
  logerr "watchdog: 'flock' not on PATH — running without overlap protection"
fi

problems=()

# -----------------------------------------------------------------------------
# PID/task cgroup capacity (2026-08-15 incident).
#
# A container that reaches pids.max cannot fork ANYTHING. Its healthcheck is an
# exec, so it fails, and the container reads as "unhealthy" with no clue why —
# while the service inside may be serving perfectly. ClickHouse sat at
# 19046/19046 for 12 hours against 739 REAL threads, answering every SQL query
# it was given, and the only symptom anyone could see was "health=unhealthy"
# plus a watchdog line blaming the database. This check names the actual fault.
#
# It reads HOST cgroup state and never uses `docker exec` — the whole point is
# to stay observant precisely when exec is what is broken.
#
# CONFIRMED in that incident: current==max, live tasks far below the charge, a
# restart cleared it. NOT confirmed: that failed execs CAUSED the accumulation
# (the arithmetic fits, but the first exec failure has no explanation under that
# theory). So the leak line below reports the OBSERVATION and explicitly does
# not name a culprit — no claiming a runc/kernel bug we have not proven.
#
# Best-effort by design: cgroup layout varies by driver/host, and a path we
# cannot read is not a stack fault. pids.max is the literal string "max" when
# uncapped, so every arithmetic path guards for non-numeric input.
# -----------------------------------------------------------------------------
check_pid_capacity() {  # service-name, container-id
  local svc="$1" cid="$2" t
  local cid_full cg pids_cur="" pids_max="" pids_evt="" util live=""

  cid_full=$(dkr inspect -f '{{.Id}}' "$cid" 2>/dev/null)
  [ -n "$cid_full" ] || return 0
  for cg in "${PID_CGROUP_ROOT:-/sys/fs/cgroup}/system.slice/docker-${cid_full}.scope" \
            "${PID_CGROUP_ROOT:-/sys/fs/cgroup}/docker/${cid_full}"; do
    if [ -r "$cg/pids.current" ] && [ -r "$cg/pids.max" ]; then
      pids_cur=$(cat "$cg/pids.current")
      pids_max=$(cat "$cg/pids.max")
      # pids.events "max N" = times a fork was REFUSED by this limit. Non-zero
      # is proof the ceiling was actually hit, not merely approached.
      [ -r "$cg/pids.events" ] && pids_evt=$(sed -n 's/^max[[:space:]]*//p' "$cg/pids.events")
      break
    fi
  done

  # A non-numeric pids.max means uncapped ("max") or unreadable — nothing to
  # compare against, and that is not itself a problem worth paging for.
  case "$pids_cur$pids_max" in ''|*[!0-9]*) return 0 ;; esac
  [ "$pids_max" -gt 0 ] || return 0
  util=$(( pids_cur * 100 / pids_max ))

  if [ "$pids_cur" -ge "$pids_max" ]; then
    problems+=("$svc: PID_LIMIT_REACHED ${pids_cur}/${pids_max} (100%) — the container CANNOT create new processes or threads. Healthchecks and docker exec will fail even while the service itself answers normally. Restarting the container recreates the cgroup and clears the charge.")
  elif [ "$util" -ge 95 ]; then
    problems+=("$svc: PID_CAPACITY_CRITICAL ${pids_cur}/${pids_max} (${util}%) — approaching the fork ceiling; exec/healthcheck failure is imminent")
  elif [ "$util" -ge 85 ]; then
    problems+=("$svc: PID_CAPACITY_HIGH ${pids_cur}/${pids_max} (${util}%)")
  elif [ "$util" -ge 70 ]; then
    problems+=("$svc: PID_CAPACITY_WARNING ${pids_cur}/${pids_max} (${util}%)")
  fi

  # Leak signal: charged tasks vastly exceeding the tasks we can actually see.
  # Counting real threads costs a directory listing per process and is only
  # worth doing once the charge is already elevated.
  if [ "$util" -ge 70 ] && [ -r "$cg/cgroup.procs" ]; then
    live=0
    while read -r p; do
      # Threads: from /proc/<pid>/status — one read per process, no listing.
      t=$(sed -n 's/^Threads:[[:space:]]*//p' "/proc/$p/status" 2>/dev/null)
      case "$t" in ''|*[!0-9]*) continue ;; esac  # process exited mid-scan
      live=$(( live + t ))
    done < "$cg/cgroup.procs"
    # 4x is deliberately conservative: normal churn does not quadruple the
    # charge. Report the numbers and let a human name the cause.
    if [ "$live" -gt 0 ] && [ "$pids_cur" -gt $(( live * 4 )) ]; then
      problems+=("$svc: PID_LEAK_SUSPECTED — cgroup task charge ${pids_cur} is far above the ${live} live threads actually observed (max=${pids_max}, ${util}%, pids.events:max=${pids_evt:-n/a}). Container-runtime/cgroup task leakage may be occurring; this is an observation, not a diagnosis.")
    fi
  fi
}

# -----------------------------------------------------------------------------
# ClickHouse health over the REAL data path (2026-08-15 incident).
#
# This probe used to be `docker exec clickhouse clickhouse-client`. That made
# the health of the DATABASE depend on the health of the CONTAINER RUNTIME, and
# when exec broke the watchdog spent 12 hours reporting "store unreachable or
# query rejected" about a ClickHouse that was answering every query put to it.
#
# Now we speak ClickHouse's own network interface — the same authenticated TLS
# endpoint the application uses — from a container that is ALREADY on the
# compose network and ALREADY trusts the internal CA. Two properties matter:
#
#   * it exercises the real data path, not a side channel;
#   * the vantage is a DIFFERENT cgroup from ClickHouse's, so ClickHouse's own
#     task-ceiling saturation cannot blind the probe that must observe it.
#
# The host cannot do this directly: ClickHouse deliberately publishes no ports
# (verified — `docker port` is empty), and publishing one to satisfy a monitor
# would reverse a posture the TLS programme set on purpose.
#
# TLS is VERIFIED against the internal CA — never -k/--insecure. The password is
# handed to curl through a config file on STDIN, so it appears in no argv on the
# host or in the container, and never in a log line.
# -----------------------------------------------------------------------------
CH_PROBE_FROM="${CH_PROBE_FROM:-vector-router}"
CH_PROBE_CACERT="${CH_PROBE_CACERT:-/tls/ca.pem}"
CH_ENV_FILE="${CH_ENV_FILE:-$SCRIPT_DIR/../deployment/docker/.env}"
# H16(c): the probe URL is DETECTED, not assumed. The old hard-coded
# https://clickhouse:8443 default made every plaintext install report a
# permanent CLICKHOUSE_TLS_FAILURE (8443 exists only on the TLS variant), and
# that standing false problem then masked real outages under the old single
# up/down state flag. Detection order: an explicit CH_PROBE_URL wins; else the
# stack's own .env says which variant runs (install.py appends compose.tls.yml
# to COMPOSE_FILE when TLS is enabled); else — .env unreadable — the probe
# container's CA bundle decides at probe time (check_clickhouse_health).
if [ -z "${CH_PROBE_URL:-}" ]; then
  if [ -r "$CH_ENV_FILE" ]; then
    if grep -q '^COMPOSE_FILE=.*compose\.tls\.yml' "$CH_ENV_FILE"; then
      CH_PROBE_URL="https://clickhouse:8443"
    else
      CH_PROBE_URL="http://clickhouse:8123"
    fi
  else
    CH_PROBE_URL=""
  fi
fi

check_clickhouse_health() {  # tel_stale_min
  local stale_min="$1" probe_cid out rc code age user pw cfg detail
  local -a tlsopt=()

  probe_cid=$(dkr ps -q --filter "label=com.docker.compose.project=$PROJECT" \
    --filter "label=com.docker.compose.service=$CH_PROBE_FROM" 2>/dev/null)
  if [ -z "$probe_cid" ]; then
    problems+=("clickhouse: CANNOT PROBE — no running '$CH_PROBE_FROM' container to reach ClickHouse from (set CH_PROBE_FROM). ClickHouse health is UNKNOWN, not healthy.")
    return 0
  fi

  # H16(c) fallback: no readable .env told us the variant, so let the probe
  # container itself — the internal CA bundle is mounted only on TLS installs.
  if [ -z "$CH_PROBE_URL" ]; then
    if dkr exec "$probe_cid" test -f "$CH_PROBE_CACERT" 2>/dev/null; then
      CH_PROBE_URL="https://clickhouse:8443"
    else
      CH_PROBE_URL="http://clickhouse:8123"
    fi
  fi
  case "$CH_PROBE_URL" in
    https://*) tlsopt=(--cacert "$CH_PROBE_CACERT") ;;
  esac

  # --- connectivity (+ TLS on the https variant), unauthenticated -------------
  out=$(dkr exec "$probe_cid" curl -sS --max-time 8 \
    ${tlsopt[@]+"${tlsopt[@]}"} "$CH_PROBE_URL/ping" 2>&1)
  rc=$?
  detail=$(printf '%s' "$out" | tr '\n' ' ' | cut -c1-160)
  if [ "$rc" -ne 0 ]; then
    if printf '%s' "$out" |
         grep -qiE 'OCI runtime|exec failed|procReady|unable to start container process'; then
      # The VANTAGE is broken, not ClickHouse. Never assert a database outage
      # from a transport failure — that conflation is the whole reason this
      # function exists.
      problems+=("CONTAINER_RUNTIME_EXEC_FAILURE: docker exec into '$CH_PROBE_FROM' failed, so ClickHouse could not be probed. This says NOTHING about the database. Check pid cgroup capacity on that container. Detail: ${detail:-no output}")
    elif printf '%s' "$out" | grep -qiE 'SSL|TLS|certificate|verify'; then
      problems+=("CLICKHOUSE_TLS_FAILURE: TLS handshake/verification to $CH_PROBE_URL failed: ${detail:-no output}")
    else
      problems+=("CLICKHOUSE_UNREACHABLE: $CH_PROBE_URL/ping failed from '$CH_PROBE_FROM' (curl rc=$rc): ${detail:-no output}")
    fi
    return 0
  fi

  # --- authenticated freshness query -----------------------------------------
  # Credentials come from the stack's own .env; absence is a real misconfig and
  # is named rather than silently downgrading to "no telemetry check".
  if [ ! -r "$CH_ENV_FILE" ]; then
    problems+=("clickhouse: reachable, but freshness UNCHECKED — cannot read $CH_ENV_FILE for credentials (set CH_ENV_FILE)")
    return 0
  fi
  user=$(sed -n 's/^CLICKHOUSE_USER=//p' "$CH_ENV_FILE" | head -1)
  pw=$(sed -n 's/^CLICKHOUSE_PASSWORD=//p' "$CH_ENV_FILE" | head -1)
  if [ -z "$pw" ]; then
    problems+=("clickhouse: reachable, but freshness UNCHECKED — CLICKHOUSE_PASSWORD is empty in $CH_ENV_FILE")
    return 0
  fi

  # curl config on stdin: url/credentials/CA all arrive off the command line.
  # write-out appends the HTTP status so auth/query faults are distinguishable
  # from transport faults. The cacert line rides only on the https variant.
  cfg=$(printf '%s\n' \
    "url = \"$CH_PROBE_URL/\"" \
    "user = \"${user:-netops}:$pw\"" \
    "data = \"SELECT toInt64(dateDiff('second', max(ts), now())) FROM netops.corr_signals WHERE ts > now() - INTERVAL 1 DAY SETTINGS tenant_scope='__all__'\"" \
    "max-time = 8" "silent" "show-error" "write-out = \"\\nHTTP:%{http_code}\"")
  case "$CH_PROBE_URL" in
    https://*) cfg="$cfg"$'\n'"cacert = \"$CH_PROBE_CACERT\"" ;;
  esac
  out=$(printf '%s' "$cfg" | dkr exec -i "$probe_cid" curl --config - 2>&1)
  rc=$?
  code=$(printf '%s' "$out" | sed -n 's/.*HTTP:\([0-9]*\).*/\1/p' | tail -1)
  detail=$(printf '%s' "$out" | sed 's/HTTP:[0-9]*//' | tr '\n' ' ' | cut -c1-160)

  case "$code" in
    401|403|516)
      problems+=("CLICKHOUSE_AUTH_FAILURE: ClickHouse rejected the watchdog's credentials (HTTP $code). The store is REACHABLE — this is a credential/permission fault, not an outage.")
      return 0 ;;
  esac
  # M25: judge the HTTP status BEFORE mining a number out of the body. An
  # error body (UNKNOWN_TABLE, READONLY, a memory-limit exception) is full of
  # digits — error codes, byte counts, server versions — and the old
  # tr -dc '0-9-' happily concatenated them into a plausible "age" that then
  # drove (or suppressed) the staleness compare on garbage.
  if [ "$rc" -ne 0 ] || [ "${code:-}" != "200" ]; then
    problems+=("CLICKHOUSE_QUERY_FAILURE: ClickHouse is reachable but the corr_signals freshness query FAILED (curl rc=$rc, HTTP ${code:-none}): ${detail:-no output}")
    return 0
  fi
  # A healthy reply is ONE integer (negative only under clock skew). Anything
  # else — even with HTTP 200 — is not an age; never arithmetic on it.
  age=$(printf '%s' "$out" | sed 's/HTTP:[0-9]*//' | tr -d '[:space:]')
  if ! printf '%s' "$age" | grep -qE '^-?[0-9]{1,12}$'; then
    problems+=("CLICKHOUSE_QUERY_FAILURE: corr_signals freshness query returned a non-numeric body (HTTP 200): ${detail:-no output}")
    return 0
  fi
  if [ "$age" -gt $(( stale_min * 60 )) ]; then
    problems+=("CLICKHOUSE_DATA_STALE: ClickHouse is HEALTHY and reachable, but the newest correlation signal is $(( age / 60 ))m old (limit ${stale_min}m) — the stack is up and nothing is being correlated")
  fi
}

for svc in $EXPECTED_SERVICES; do
  # A scaled service (docker compose --scale correlation=2) returns MULTIPLE
  # cids here. Passing them as one newline-joined string to `docker inspect`
  # fails ("no such container") and produced a permanent false "state=" DOWN
  # from the moment the second replica existed (found live 2026-08-23).
  # Probe EVERY replica: one sick replica of a scaled service is a problem
  # even while its sibling is healthy.
  cids=$(dkr ps -q \
    --filter "label=com.docker.compose.project=$PROJECT" \
    --filter "label=com.docker.compose.service=$svc" 2>/dev/null)
  if [ -z "$cids" ]; then
    problems+=("$svc: not running")
    continue
  fi
  for cid in $cids; do
    name=$(dkr inspect -f '{{.Name}}' "$cid" 2>/dev/null | tr -d /)
    label="${name:-$svc/${cid:0:12}}"
    state=$(dkr inspect -f '{{.State.Status}}' "$cid" 2>/dev/null)
    if [ "$state" != "running" ]; then
      problems+=("$label: state=${state:-unreadable}")
      continue
    fi
    health=$(dkr inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{end}}' "$cid" 2>/dev/null)
    if [ -n "$health" ] && [ "$health" != "healthy" ]; then
      problems+=("$label: health=$health")
    fi

    check_pid_capacity "$label" "$cid"
  done
done

# Container OOM / restart detection (#102 signoff): cadvisor's per-container
# metrics are dark under docker's containerd image store, so the in-platform
# ContainerOOMKilled alert cannot fire — THIS is the container-OOM sentinel.
# Any OOM-kill under restart:unless-stopped shows up as a RestartCount bump;
# OOMKilled=true is captured directly for containers sitting dead. One push
# per new event (count-delta keyed), distinct from the up/down state machine.
RESTART_STATE="${WATCHDOG_RESTARTS:-$SCRIPT_DIR/.stack-watchdog.restarts}"
touch "$RESTART_STATE" 2>/dev/null || true
oom_events=()
new_restart_state=""
for svc in $EXPECTED_SERVICES; do
  # Same scaled-service rule as the state loop above: `head -1` watched only
  # ONE replica of a scaled service, so an OOM-kill of the other was invisible.
  # Track restart counts per CONTAINER (keyed by name), not per service.
  for cid in $(dkr ps -aq \
    --filter "label=com.docker.compose.project=$PROJECT" \
    --filter "label=com.docker.compose.service=$svc" 2>/dev/null); do
  read -r rcount oomed exitcode <<<"$(dkr inspect -f '{{.RestartCount}} {{.State.OOMKilled}} {{.State.ExitCode}}' "$cid" 2>/dev/null)"
  [ -n "${rcount:-}" ] || continue
  cname=$(dkr inspect -f '{{.Name}}' "$cid" 2>/dev/null | tr -d /)
  cname="${cname:-$svc/${cid:0:12}}"
  prev=$(awk -v s="$cname" '$1==s{print $2}' "$RESTART_STATE" 2>/dev/null)
  new_restart_state+="$cname ${rcount}"$'\n'
  if [ -n "$prev" ] && [ "$rcount" -gt "$prev" ] 2>/dev/null; then
    if [ "$oomed" = "true" ] || [ "${exitcode:-0}" = "137" ]; then
      oom_events+=("$cname: OOM-KILLED by its cgroup limit (restarts $prev->$rcount) — compare its resource-plan limit vs usage, then --replan")
    else
      # Not an OOM (that's the branch above) — say what the container itself
      # said instead of speculating. The last log line is the diagnostic that
      # matters for a crash loop (2026-08-04: 109 api restarts pushed "check
      # for OOM" while the real cause, an unseal failure, sat in the log).
      # || true: the log fetch is diagnostic garnish; the restart event must
      # still be reported even if docker logs itself errors.
      lastlog=$(dkr logs --tail 1 "$cid" 2>&1 | tr -d '\r' | cut -c1-200 || true)
      oom_events+=("$cname: restarted (${prev}->${rcount}, exit ${exitcode:-?}) — last log: ${lastlog:-<no output>}")
    fi
  elif [ "$oomed" = "true" ] && [ -z "$prev" ]; then
    oom_events+=("$cname: sitting OOM-killed (exit ${exitcode:-?})")
  fi
  done
done
printf '%s' "$new_restart_state" > "$RESTART_STATE" 2>/dev/null || true
if [ "${#oom_events[@]}" -gt 0 ]; then
  # Title the alert for what ACTUALLY happened. The previous title said
  # "OOM/restart" for every restart-count bump, so an operator doing a routine
  # rebuild got a fire emoji and the word OOM — and a real OOM would have been
  # indistinguishable from it (2026-08-04: 18 nginx restarts from config
  # iteration were reported as OOM). Only claim OOM when we detected OOM.
  if printf '%s\n' "${oom_events[@]}" | grep -q "OOM-KILLED"; then
    push "🔥 NetOps container OOM-KILLED on $(hostname)" "fire" "high" \
      "$(printf '%s\n' "${oom_events[@]}")"
  else
    push "🔁 NetOps container restarted on $(hostname)" "arrows_counterclockwise" "default" \
      "$(printf '%s\n' "${oom_events[@]}")"
  fi
fi

# -----------------------------------------------------------------------------
# Kernel UDP-drop sentinel for the syslog lane. syslog-ng can only count what
# it READS; datagrams the KERNEL drops before syslog-ng dequeues them (socket
# receive-buffer overflow under burst) never appear in any syslog-ng counter,
# so the lane silently loses messages while every liveness check stays green.
# The truth lives in the syslog-ng container's network namespace: /proc/net/snmp
# `Udp:` RcvbufErrors (buffer overflow) and InErrors (its superset). Tracked as
# a run-over-run delta in its own state file (same mechanism as the restart /
# reject checks), with the same transition-only discipline as the up/down
# machine: one push when drops START, one when they STOP — never one per
# minute. A counter that moves BACKWARD (container/kernel restart reset) makes
# the delta unknowable: re-baseline silently, never alert a bogus huge delta.
# Degrades gracefully — no container, a failed exec or unparsable output is a
# named stderr "not measurable" note (§16.1), never a false alarm.
# -----------------------------------------------------------------------------
UDP_STATE="${WATCHDOG_UDPDROPS:-$SCRIPT_DIR/.stack-watchdog.udpdrops}"

check_syslog_udp_drops() {
  local cid snmp rcv_now inerr_now prev_rcv prev_inerr prev_state state d_rcv d_inerr
  # §16.3: every external call bounded — docker exec has no timeout of its own,
  # so without the wrapper a wedged daemon hangs the whole watchdog run. No
  # `timeout` on the host means we degrade to "not measurable", never to an
  # unbounded call.
  if ! command -v timeout >/dev/null 2>&1; then
    logerr "watchdog: syslog UDP-drop check not measurable: no 'timeout' on PATH (docker exec must stay bounded)"
    return 0
  fi
  cid=$(dkr ps -q --filter "label=com.docker.compose.project=$PROJECT" \
                  --filter "label=com.docker.compose.service=syslog-ng" 2>/dev/null | head -1)
  if [ -z "$cid" ]; then
    logerr "watchdog: syslog UDP-drop check not measurable: no running syslog-ng container in project $PROJECT"
    return 0
  fi
  if ! snmp=$(timeout 10 docker exec "$cid" cat /proc/net/snmp 2>&1); then
    logerr "watchdog: syslog UDP-drop check not measurable: docker exec failed: $(printf '%s' "$snmp" | head -1 | cut -c1-120)"
    return 0
  fi
  # /proc/net/snmp: the first `Udp:` line names the columns, the second carries
  # the values. Column POSITIONS differ across kernel versions, so resolve
  # RcvbufErrors / InErrors by NAME — a positional read silently tracks the
  # wrong counter forever.
  read -r rcv_now inerr_now <<<"$(printf '%s\n' "$snmp" | awk '
    $1=="Udp:" && !h { for (i=2; i<=NF; i++) { if ($i=="RcvbufErrors") r=i; if ($i=="InErrors") e=i }; h=1; next }
    $1=="Udp:" && h  { if (r && e) print $r, $e; exit }')"
  if [ -z "${rcv_now:-}" ] || [ -z "${inerr_now:-}" ]; then
    logerr "watchdog: syslog UDP-drop check not measurable: no parsable Udp: RcvbufErrors/InErrors in /proc/net/snmp"
    return 0
  fi
  prev_rcv=""; prev_inerr=""; prev_state=""
  # First run has no state file — that is the baseline case, not an error.
  if [ -f "$UDP_STATE" ]; then
    read -r prev_rcv prev_inerr prev_state < "$UDP_STATE" 2>/dev/null ||
      logerr "watchdog: UDP-drop state file $UDP_STATE unreadable — re-baselining"
  fi
  state="${prev_state:-clean}"
  # Delta is only meaningful when BOTH counters moved forward (or held); a
  # backward move is a reset and falls through to the silent re-baseline.
  if [ -n "$prev_rcv" ] && [ -n "$prev_inerr" ] &&
     [ "$rcv_now" -ge "$prev_rcv" ] 2>/dev/null && [ "$inerr_now" -ge "$prev_inerr" ] 2>/dev/null; then
    d_rcv=$(( rcv_now - prev_rcv ))
    d_inerr=$(( inerr_now - prev_inerr ))
    if [ $(( d_rcv + d_inerr )) -gt 0 ]; then
      if [ "$state" != "dropping" ]; then
        push "📉 Syslog UDP datagrams DROPPED by the kernel on $(hostname)" "chart_with_downwards_trend" "high" \
          "The kernel dropped syslog UDP datagrams inside the syslog-ng container's netns since the last check (RcvbufErrors +${d_rcv}, InErrors +${d_inerr}). These drops are INVISIBLE to syslog-ng's own counters — messages are lost before ingestion. Usual cause: socket receive-buffer overflow under burst; check so-rcvbuf() / net.core.rmem_max and the sender rate."
        notify_webhook "degraded" "syslog UDP drops started: kernel RcvbufErrors +${d_rcv}, InErrors +${d_inerr} since last check (invisible to syslog-ng's own stats)"
      fi
      state="dropping"
    else
      if [ "$state" = "dropping" ]; then
        push "✅ Syslog UDP kernel drops STOPPED on $(hostname)" "white_check_mark" "default" \
          "No new kernel-level UDP drops in the syslog-ng netns since the last check."
        notify_webhook "recovered" "syslog UDP kernel drops stopped: no new RcvbufErrors/InErrors since last check"
      fi
      state="clean"
    fi
  fi
  printf '%s %s %s\n' "$rcv_now" "$inerr_now" "$state" > "$UDP_STATE" 2>/dev/null ||
    logerr "watchdog: could not persist UDP-drop state to $UDP_STATE"
  return 0
}
check_syslog_udp_drops

# End-to-end probe: the dashboard must answer through nginx.
code=$(curl -s -o /dev/null -w '%{http_code}' -m 10 ${APP_CACERT:+--cacert "$APP_CACERT"} "$APP_URL" 2>/dev/null)
case "$code" in
  200|301|302|401) ;;                               # served (401 = auth on / is fine)
  *) problems+=("dashboard $APP_URL: HTTP ${code:-no-response}") ;;
esac

# API liveness verdict (tracker 194). The design note lives beside
# api_probe_once above; this half owns the STATE: the cold-boot grace, the
# sticky escalation, and the CRITICAL classification that drives the existing
# up<->down transition machine (problem_is_critical matches API_UNRESPONSIVE,
# so a new one pushes urgently exactly like a dead service).
api_probe_failing=0

api_started_epoch() {  # -> unix epoch of the api container's start, or nothing
  local cid started
  cid=$(dkr ps -q --filter "label=com.docker.compose.project=$PROJECT" \
                  --filter "label=com.docker.compose.service=$API_SERVICE" 2>/dev/null | head -1)
  [ -n "$cid" ] || return 0
  started=$(dkr inspect -f '{{.State.StartedAt}}' "$cid" 2>/dev/null) || return 0
  [ -n "$started" ] || return 0
  # RFC3339 with nanoseconds; GNU date parses it. A host whose `date` cannot
  # (busybox) yields no start time and the grace falls back to the
  # first-failure anchor — degraded, never unbounded (§16.2).
  started=$(date -d "$started" +%s 2>/dev/null) || return 0
  case "$started" in ''|*[!0-9]*) return 0 ;; esac
  printf '%s' "$started"
}

check_api_liveness() {
  local p_out p_rc p_code p_detail now first_fail escalated started anchor elapsed
  if p_out=$(api_probe_once); then
    if [ -f "$API_STATE" ]; then
      logerr "watchdog: api liveness RESTORED — $API_PROBE_URL answers 200 with a body again"
      rm -f "$API_STATE" 2>/dev/null ||
        logerr "watchdog: could not clear $API_STATE — a stale first-failure anchor will shorten the next cold-boot grace"
    fi
    return 0
  fi
  read -r p_rc p_code p_detail <<<"$p_out"
  api_probe_failing=1
  now=$(date +%s)

  first_fail=""; escalated=0
  if [ -f "$API_STATE" ]; then
    read -r first_fail escalated < "$API_STATE" 2>/dev/null || {
      logerr "watchdog: api liveness state $API_STATE unreadable — re-baselining the cold-boot grace"
      first_fail=""; escalated=0
    }
  fi
  case "${first_fail:-}" in ''|*[!0-9]*) first_fail="$now" ;; esac
  case "${escalated:-}" in 0|1) ;; *) escalated=0 ;; esac
  # A first-failure stamp in the FUTURE (clock stepped back) would grant an
  # unbounded grace — re-baseline instead of trusting it.
  [ "$first_fail" -gt "$now" ] && first_fail="$now"

  anchor="$first_fail"
  started=$(api_started_epoch)
  if [ -n "$started" ] && [ "$started" -gt "$anchor" ] && [ "$started" -le "$now" ]; then
    anchor="$started"
  fi
  elapsed=$(( now - first_fail ))

  if [ "$escalated" = "1" ] ||
     [ "$elapsed" -ge "$API_BOOT_GRACE_MAX_SEC" ] ||
     [ $(( now - anchor )) -ge "$API_BOOT_GRACE_SEC" ]; then
    escalated=1
    # Keep the first 160 characters — what problem_key hashes — FREE of
    # run-varying text: the transport detail goes to the log, not into the
    # key, or every minute would mint a "new" critical class and re-push.
    problems+=("API_UNRESPONSIVE: the api is not serving $API_PROBE_URL through nginx — the dashboard probe cannot see this, nginx answers / from the SPA whether or not the api is alive. Failing for ${elapsed}s (curl rc=${p_rc}, HTTP ${p_code}); transport detail is in the watchdog log.")
    logerr "watchdog: api liveness CRITICAL after ${elapsed}s: rc=${p_rc} HTTP=${p_code}: ${p_detail}"
  else
    logerr "watchdog: api liveness failing for ${elapsed}s (rc=${p_rc} HTTP=${p_code}: ${p_detail}) — inside the ${API_BOOT_GRACE_SEC}s cold-boot grace, NOT escalated yet; the healthy heartbeat is withheld this run"
  fi
  printf '%s %s\n' "$first_fail" "$escalated" > "$API_STATE" 2>/dev/null ||
    logerr "watchdog: could not persist api liveness state to $API_STATE — the cold-boot grace cannot accumulate, so an api outage may never escalate"
}
check_api_liveness

# Disk watermark — the cause of the silent log-ingest outage: OpenSearch sets
# EVERY index read-only at its 95% flood stage, and ingestion stops with no
# error. Warn well before that; auto-prune reclaimable Docker build cache (the
# usual filler on a dev/build host) when it crosses the higher mark.
disk_pct=$(df --output=pcent / 2>/dev/null | tail -1 | tr -dc '0-9')
if [ -n "$disk_pct" ] && [ "$disk_pct" -ge "${DISK_WARN_PCT:-85}" ]; then
  if [ "$disk_pct" -ge "${DISK_PRUNE_PCT:-90}" ]; then
    # §16.1: this is a DESTRUCTIVE remediation. It previously ended in
    # `>/dev/null 2>&1 || true`, so a prune that could not run (daemon busy,
    # permissions, no space to even prune) was indistinguishable from one that
    # reclaimed nothing — the watchdog would report the disk problem without
    # ever revealing that its own fix had failed. Report the failure; the disk
    # warning below still fires on the re-measured value either way.
    if ! prune_err=$(dkr_slow builder prune -f 2>&1 >/dev/null); then
      problems+=("disk auto-prune FAILED: ${prune_err:-unknown error} (disk still ${disk_pct}%)")
    fi
    disk_pct=$(df --output=pcent / 2>/dev/null | tail -1 | tr -dc '0-9')
  fi
  [ "$disk_pct" -ge "${DISK_WARN_PCT:-85}" ] &&
    problems+=("disk ${disk_pct}% (warn ${DISK_WARN_PCT:-85}%; OpenSearch flood-stage read-only at 95%)")
fi

# Docker-hygiene cron health (#100 contributing noise): the weekly prune cron
# silently failed for days (lost exec bit → 'Permission denied' in its log) and
# the resulting debris drove the disk warning DURING the incident, muddying
# diagnosis. Fail loudly instead: the hygiene log must exist, be fresher than
# ~8 days (weekly cron + slack), and its last run must not be an error.
hyg_log="$(dirname "${BASH_SOURCE[0]}")/docker-hygiene.log"
if [ -f "$hyg_log" ]; then
  hyg_age_days=$(( ($(date +%s) - $(stat -c %Y "$hyg_log" 2>/dev/null || echo 0)) / 86400 ))
  if [ "$hyg_age_days" -gt "${HYGIENE_MAX_AGE_DAYS:-8}" ]; then
    problems+=("docker-hygiene cron stale: log ${hyg_age_days}d old (weekly cron dead? check crontab + exec bit)")
  elif tail -3 "$hyg_log" 2>/dev/null | grep -qiE 'permission denied|not found|cannot'; then
    problems+=("docker-hygiene cron failing: $(tail -1 "$hyg_log" | cut -c1-80)")
  fi
fi

# host-hygiene (10-min threshold sweeper + OpenSearch block healer) must be
# alive for the same reason: a dead hygiene cron is invisible until the next
# disk-full outage. Quiet runs append nothing, so track a heartbeat marker the
# script's cron line touches — the log alone can legitimately stay silent.
hh_beat="$(dirname "${BASH_SOURCE[0]}")/.host-hygiene.heartbeat"
if [ -f "$hh_beat" ]; then
  hh_age_min=$(( ($(date +%s) - $(stat -c %Y "$hh_beat" 2>/dev/null || echo 0)) / 60 ))
  [ "$hh_age_min" -gt "${HOST_HYGIENE_MAX_AGE_MIN:-45}" ] &&
    problems+=("host-hygiene cron stale: heartbeat ${hh_age_min}m old (10-min cron dead? disk-full protection is OFF)")
fi

# TLS rotation sweep health (SEC-019.1 part 2): certificates age invisibly, so
# a dead or failing rotation cron is a FUTURE store outage (the 2026-08-05
# class: fresh disk mints, expired certs on the wire). Three signals, same
# transition-only problems machine as the hygiene checks above:
#   1. last run DEGRADED  — the sweep itself says the wire may be stale;
#   2. heartbeat age      — the daily --check cron stopped running at all;
#   3. act-heartbeat age  — the weekly FULL rotation stopped landing (a daily
#      check refreshing signal 2 must not mask this; soak-time deferrals
#      legitimately widen the gap, hence a floor above one deferred week).
# An absent heartbeat is quiet: pre-first-run, or a deployment without the
# TLS mesh — same convention as the hygiene blocks.
tls_beat="$(dirname "${BASH_SOURCE[0]}")/rotate-tls.heartbeat"
if [ -f "$tls_beat" ]; then
  if grep -q 'status=DEGRADED' "$tls_beat" 2>/dev/null; then
    problems+=("rotate-tls sweep DEGRADED: $(head -c 120 "$tls_beat") — wire may serve stale certs; see scripts/rotate-tls.log and re-run scripts/rotate-tls-services.sh")
  fi
  tls_age_h=$(( ($(date +%s) - $(stat -c %Y "$tls_beat" 2>/dev/null || echo 0)) / 3600 ))
  [ "$tls_age_h" -gt "${TLS_CHECK_MAX_AGE_H:-26}" ] &&
    problems+=("rotate-tls daily check stale: heartbeat ${tls_age_h}h old (cron dead? served-cert drift is unwatched)")
fi
tls_act_beat="$(dirname "${BASH_SOURCE[0]}")/rotate-tls.act.heartbeat"
if [ -f "$tls_act_beat" ]; then
  tls_act_days=$(( ($(date +%s) - $(stat -c %Y "$tls_act_beat" 2>/dev/null || echo 0)) / 86400 ))
  [ "$tls_act_days" -gt "${TLS_ACT_MAX_AGE_DAYS:-10}" ] &&
    problems+=("rotate-tls ACT sweep stale: last successful full rotation ${tls_act_days}d ago (weekly cron dead or perpetually deferred) — restart-class services drift toward the 2026-08-05 expiry outage")
fi

# -----------------------------------------------------------------------------
# #150 backup-intent applier — the host-side half of the Data Protection GUI.
#
# The API stores the operator's backup intent (remote, schedule, retention) to
# data/api/system_backup.json but runs in a container: it cannot write the host
# crontab or the host .env (system_backup.go ARCHITECTURE NOTE). Until this
# hook existed NOTHING invoked scripts/apply-backup-config.sh, so the GUI
# showed "enabled" while no cron was ever installed — F-59 reborn. This cron
# (root, every minute) is the natural host-side agent, so it closes the loop:
# whenever the intent file is NEWER than the last-applied stamp, run the
# applier once. Stamp discipline keeps it event-driven (§16.4): the stamp
# mtime is set to the intent's mtime on success, so a quiet steady state costs
# one -nt test per minute and applies exactly once per GUI change
# (transition-only logging — the apply is the event, not the poll). A FAILED
# apply keeps the stamp untouched (retried next minute, §16.3 idempotent) and
# is reported through the problems machine, which is itself transition-only.
#
# Packaged installs (watchdog copied to /etc/correlix) must point these at the
# bundle via stack-watchdog.env: BACKUP_INTENT_FILE, BACKUP_APPLY_SCRIPT,
# BACKUP_APPLY_STAMP. An absent intent file is a quiet no-op (GUI never used);
# intent WITH no applier is a loud problem — stored intent nobody enforces is
# the exact defect this hook removes.
# -----------------------------------------------------------------------------
BACKUP_INTENT="${BACKUP_INTENT_FILE:-$SCRIPT_DIR/../data/api/system_backup.json}"
BACKUP_APPLY="${BACKUP_APPLY_SCRIPT:-$SCRIPT_DIR/apply-backup-config.sh}"
BACKUP_STAMP="${BACKUP_APPLY_STAMP:-$SCRIPT_DIR/.backup-config.applied}"

apply_backup_intent() {
  local out detail
  [ -f "$BACKUP_INTENT" ] || return 0   # no stored intent — nothing to enforce
  if [ -f "$BACKUP_STAMP" ] && [ ! "$BACKUP_INTENT" -nt "$BACKUP_STAMP" ]; then
    return 0                            # intent unchanged since the last successful apply
  fi
  if [ ! -x "$BACKUP_APPLY" ]; then
    problems+=("backup intent stored at $BACKUP_INTENT but applier $BACKUP_APPLY is missing/not executable — GUI backup settings are NOT enforced on this host")
    return 0
  fi
  # §16.3: every external call bounded — the applier shells into python3 and
  # crontab; a wedged one must not hang the whole watchdog run. No `timeout`
  # on the host degrades to a named skip (§16.2), never to an unbounded call.
  if ! command -v timeout >/dev/null 2>&1; then
    logerr "watchdog: backup-intent apply skipped: no 'timeout' on PATH (the apply must stay bounded)"
    return 0
  fi
  if out=$(timeout 120 "$BACKUP_APPLY" 2>&1); then
    # Stamp carries the intent's OWN mtime, so -nt stays false until the API
    # writes a genuinely newer intent (its atomic rename bumps the mtime).
    if touch -r "$BACKUP_INTENT" "$BACKUP_STAMP" 2>/dev/null; then
      log "watchdog: backup intent applied ($BACKUP_INTENT -> $BACKUP_APPLY): $(printf '%s' "$out" | tail -1)"
    else
      problems+=("backup intent applied but stamp $BACKUP_STAMP is unwritable — the apply would repeat every minute")
    fi
  else
    # Prefer the applier's own ERROR line; a timeout kill or bare failure has
    # none, so fall back to its last output line (never an empty diagnostic).
    detail=$(printf '%s' "$out" | grep 'ERROR' | tail -1)
    [ -n "$detail" ] || detail=$(printf '%s' "$out" | tail -1)
    problems+=("backup-config apply FAILED (GUI intent NOT enforced): $(printf '%s' "${detail:-no output}" | cut -c1-200)")
  fi
}
apply_backup_intent

# Ingestion liveness — a pipeline that stops silently is invisible until someone
# looks at an empty dashboard. Container logs (applogs) flow continuously, so
# zero docs in the recent window means the log bus stalled (disk block, dead
# Vector/Kafka consumer). Counts via the opensearch container (not host-exposed).
#
# H17 (2026-08-15): on the TLS variant OpenSearch serves https WITH auth on
# 9200, so the old plain http://localhost:9200 probes got empty replies — and
# every consumer guarded its result with [ -n ], so ingest-stall, doc-reject,
# cluster-status and backup-freshness all became silent no-ops: the watchdog
# was BLIND on exactly the installs that carry customer data. Now the probe
# mirrors the ClickHouse pattern (variant detected from COMPOSE_FILE, CA
# verified, credentials from the stack's .env via a curl config on stdin —
# never argv), and "no parsable reply" is a NAMED problem, never silence.
os_cid=$(dkr ps -q --filter "label=com.docker.compose.project=$PROJECT" \
  --filter "label=com.docker.compose.service=opensearch" 2>/dev/null)
if [ -n "$os_cid" ]; then
  stale_min="${INGEST_STALE_MIN:-15}"

  OS_PROBE_URL="http://localhost:9200"
  OS_TLS=0
  # In-container path: compose.tls.yml mounts data/tls/services/opensearch at
  # /usr/share/opensearch/config/tls (ca.pem lives there).
  OS_PROBE_CACERT="${OS_PROBE_CACERT:-/usr/share/opensearch/config/tls/ca.pem}"
  OS_API_PW=""
  OS_MON_PW=""
  if [ -r "$CH_ENV_FILE" ] && grep -q '^COMPOSE_FILE=.*compose\.tls\.yml' "$CH_ENV_FILE"; then
    OS_TLS=1
    # Host MUST be a name the wire cert actually carries. The issued SAN set is
    # `DNS:opensearch` + the SPIFFE URI and nothing else, so https://localhost
    # fails hostname verification (curl exit 60, http 000) and blinded every
    # search-tier check on TLS installs. `opensearch` resolves in-container via
    # compose DNS and verifies against the same CA. The fix is the correct NAME,
    # never -k/--insecure: riding insecure here would turn a real MITM or a
    # misissued cert into a silent pass, which is the §16.1 defect class itself.
    OS_PROBE_URL="https://opensearch:9200"
    # svc_api: read netops-*, cluster health, snapshot get. svc_aggregator:
    # cluster:monitor/nodes/stats (the doc-reject counter). One user per
    # probe, matching the SEC-008 role model — no shared/admin credential.
    OS_API_PW=$(sed -n 's/^OS_API_PASSWORD=//p' "$CH_ENV_FILE" | head -1)
    OS_MON_PW=$(sed -n 's/^OS_AGGREGATOR_PASSWORD=//p' "$CH_ENV_FILE" | head -1)
  fi
  os_blind=""
  # Bare host of the probe URL — quoted back by the TLS self-test so the message
  # names the host that actually failed verification, not a hard-coded guess.
  os_probe_host=$(printf '%s' "$OS_PROBE_URL" | sed -e 's#^[a-z]*://##' -e 's#[:/].*##')

  # os_fetch <user> <password> <path+query> [json-body] — one bounded curl in
  # the opensearch container. TLS installs add CA verification + basic auth
  # through a config file on STDIN (credentials never in argv/ps). A transport
  # or auth fault yields empty output; the CALLER records that as blindness.
  os_fetch() {
    local cfg body
    cfg=$(printf '%s\n' \
      "url = \"$OS_PROBE_URL$3\"" \
      "max-time = 8" "silent")
    if [ "$OS_TLS" = 1 ]; then
      cfg="$cfg"$'\n'"cacert = \"$OS_PROBE_CACERT\""$'\n'"user = \"$1:$2\""
    fi
    if [ -n "${4:-}" ]; then
      body=${4//\"/\\\"}
      cfg="$cfg"$'\n'"header = \"Content-Type: application/json\""$'\n'"data = \"$body\""
    fi
    printf '%s' "$cfg" | dkr exec -i "$os_cid" curl --config - 2>/dev/null
  }

  # os_probe_diag — self-test for a BLIND run. os_fetch deliberately discards
  # transport detail (its callers only want a body), so "no parsable reply" was
  # reported with the guess "(TLS/auth mismatch? probe fault?)" — worthless at
  # 03:00, and in this lab actively wrong. This runs ONE extra bounded curl
  # against the cluster root with the SAME config the real probes use and
  # classifies the failure from EVIDENCE: curl's own exit code plus the HTTP
  # status. It NEVER guesses — an unrecognised pair is reported raw.
  #
  # Sets (not echoes, so the caller keeps them): os_diag_class os_diag_rc
  # os_diag_http os_diag_detail. Only the stable CLASS + the raw codes go into
  # the problem text; the run-varying curl message goes to the log, because
  # problem_key hashes the first 160 characters and run-varying text there
  # would mint a "new" problem class every minute and re-push (same discipline
  # as API_UNRESPONSIVE above).
  os_diag_class=""; os_diag_rc=""; os_diag_http=""; os_diag_detail=""
  os_probe_diag() {
    local cfg out pw
    cfg=$(printf '%s\n' \
      "url = \"$OS_PROBE_URL/\"" \
      "max-time = 8" "silent" "show-error" \
      "output = \"/dev/null\"" \
      "write-out = \"os_http=%{http_code}\"")
    if [ "$OS_TLS" = 1 ]; then
      cfg="$cfg"$'\n'"cacert = \"$OS_PROBE_CACERT\""$'\n'"user = \"svc_api:$OS_API_PW\""
    fi
    # stderr is KEPT on purpose (§16.1): curl's own message IS the evidence this
    # self-test exists to surface. Suppressing it is what made the run blind.
    out=$(printf '%s' "$cfg" | dkr exec -i "$os_cid" curl --config - 2>&1)
    os_diag_rc=$?   # OWN LINE. Inside `if ! out=$(...)` this would be the *if*'s
                    # status (always 0) — a trap that has already bitten this repo.
    # Read the status BEFORE truncating: --show-error puts curl's (possibly long)
    # stderr first and the write-out marker last, so a truncated buffer can lose
    # the very code we classify on.
    os_diag_http=$(printf '%s' "$out" | grep -oE 'os_http=[0-9]{3}' | tail -1 | cut -d= -f2)
    # §8: a credential must never reach a log line, a state file or a phone push.
    for pw in "$OS_API_PW" "$OS_MON_PW"; do
      [ -n "$pw" ] && out=${out//"$pw"/***}
    done
    out=$(printf '%s' "$out" | tr '\n' ' ' | cut -c1-240)
    if [ "$os_diag_rc" = 60 ]; then
      # curl(60) is CERTIFICATE VERIFICATION — never auth, never reachability:
      # the TCP connect succeeded and the peer answered with a cert we rejected.
      # curl distinguishes the two sub-causes in its own text; so do we, rather
      # than asserting a SAN mismatch when the CA is what is actually wrong.
      if printf '%s' "$out" | grep -qiE 'subject name|host ?name'; then
        os_diag_class="TLS_HOSTNAME"
        os_diag_detail="the certificate is trusted but its names do not cover the probe host '$os_probe_host'. This stack issues OpenSearch the SAN set 'DNS:opensearch' + a SPIFFE URI and NOTHING else — no localhost — so any other host name fails hostname verification. Point OS_PROBE_URL at 'opensearch' or add the name to the SAN. Do NOT add -k: that converts a real MITM or a misissued cert into a silent pass."
      else
        os_diag_class="TLS_CA"
        os_diag_detail="the certificate chain did not verify against the CA file in use ($OS_PROBE_CACERT). The names are not the problem; the trust anchor is — wrong/rotated CA, or the bundle is not the one that signed this leaf. Do NOT add -k."
      fi
      os_diag_detail="$os_diag_detail curl said: $out"
    elif [ "$os_diag_http" = 401 ] || [ "$os_diag_http" = 403 ]; then
      # An HTTP status came back at all, so the handshake COMPLETED: not TLS.
      os_diag_class="AUTH"
      os_diag_detail="the certificate verified and the node answered, so this is authentication/authorization, NOT TLS. Check OS_API_PASSWORD / OS_AGGREGATOR_PASSWORD in $CH_ENV_FILE and the svc_api / svc_aggregator roles."
    elif { [ "$os_diag_rc" = 7 ] || [ "$os_diag_http" = "000" ]; } &&
         ! printf '%s' "$out" | grep -qiE 'ssl|tls|certificate'; then
      os_diag_class="UNREACHABLE"
      os_diag_detail="nothing accepted a connection at $OS_PROBE_URL from inside the opensearch container, and curl reported no TLS error — the node is down, still starting, or bound elsewhere. Not TLS, not auth. curl said: $out"
    else
      # Anything else is reported RAW. A named guess we cannot evidence would be
      # worse than the numbers.
      os_diag_class="UNCLASSIFIED"
      os_diag_detail="no recognised failure signature (tls=$OS_TLS, cacert=$OS_PROBE_CACERT). Raw curl output: ${out:-<empty>}"
    fi
  }

  if [ "$OS_TLS" = 1 ] && [ -z "$OS_API_PW" ]; then
    # A TLS install without readable credentials cannot be probed at all —
    # name it once and skip the sub-checks rather than emitting four echoes.
    problems+=("OPENSEARCH_UNVERIFIABLE: TLS install but OS_API_PASSWORD is unreadable from $CH_ENV_FILE — ingest/reject/cluster/backup checks are BLIND (set CH_ENV_FILE)")
  else

  os_count() {  # $1 = gte, $2 = lt  -> doc count in that window
    os_fetch svc_api "$OS_API_PW" "/netops-applogs-*/_count" \
        "{\"query\":{\"range\":{\"timestamp\":{\"gte\":\"$1\",\"lt\":\"$2\"}}}}" |
      grep -oE '"count":[0-9]+' | grep -oE '[0-9]+'
  }

  cnt=$(os_count "now-${stale_min}m" "now")
  if [ -z "$cnt" ]; then
    os_blind="$os_blind ingest-stall"
  elif [ "$cnt" -eq 0 ]; then
    problems+=("log ingest stalled: 0 applogs in last ${stale_min}m (Vector/disk/consumer?)")
  fi

  # ---------------------------------------------------------------------------
  # F-19: PARTIAL loss. The check above is `== 0`, which only ever sees a TOTAL
  # stall. Through the entire measured 2026-07-21 incident the count was
  # ~14,000/h and this watchdog reported GREEN while ~4,390 documents/day were
  # being destroyed. A zero-test cannot tell "ingesting correctly" apart from
  # "ingesting with a 5% hole", and the hole is the failure mode that actually
  # happens.
  #
  # Compare the recent window against the 4 windows before it (its own trailing
  # baseline — no external state file, no cold-start problem). Only judge when
  # the baseline is meaningful: on a genuinely idle stack the ratio is noise,
  # and an alert nobody trusts is worse than no alert.
  # ---------------------------------------------------------------------------
  base_win=$(( stale_min * 4 ))
  base_cnt=$(os_count "now-$(( base_win + stale_min ))m" "now-${stale_min}m")
  [ -z "${base_cnt:-}" ] && os_blind="$os_blind ingest-baseline"
  if [ -n "${cnt:-}" ] && [ -n "${base_cnt:-}" ] && [ "$base_cnt" -gt 0 ]; then
    base_rate=$(( base_cnt / 4 ))                      # per stale_min window
    min_base="${INGEST_MIN_BASELINE:-200}"
    pct="${INGEST_DEGRADE_PCT:-50}"                    # fire under N% of baseline
    if [ "$base_rate" -ge "$min_base" ] && [ "$cnt" -lt $(( base_rate * pct / 100 )) ]; then
      problems+=("log ingest DEGRADED: ${cnt} applogs in ${stale_min}m vs baseline ${base_rate} (<${pct}%) — partial loss, not a stall")
    fi
  fi

  # ---------------------------------------------------------------------------
  # F-17: per-document rejection. OpenSearch's obvious counter LIES here —
  # `index_failed` read 0 while 1,127 documents were being discarded, because
  # bulk rejections are PER ITEM and index_failed only counts whole-request
  # failures. doc_status.4xx is the counter that moves. Tracked as a delta
  # against the previous run so a standing historical total does not alarm
  # forever; a reset (OpenSearch restart) yields a negative delta and is
  # ignored.
  # ---------------------------------------------------------------------------
  REJ_STATE="${WATCHDOG_REJECTS:-$SCRIPT_DIR/.stack-watchdog.rejects}"
  rej_now=$(os_fetch svc_aggregator "$OS_MON_PW" "/_nodes/stats/indices/indexing" |
    tr ',' '\n' | grep -oE '"4xx"[[:space:]]*:[[:space:]]*[0-9]+' | grep -oE '[0-9]+$' | head -1)
  if [ -n "${rej_now:-}" ]; then
    rej_prev=$(cat "$REJ_STATE" 2>/dev/null || echo "")
    if [ -n "$rej_prev" ] && [ "$rej_now" -gt "$rej_prev" ]; then
      problems+=("OpenSearch REJECTED $(( rej_now - rej_prev )) documents since last check — permanent loss (mapping/field-limit; index_failed will read ~0, ignore it)")
    fi
    echo "$rej_now" > "$REJ_STATE" 2>/dev/null || true
  else
    os_blind="$os_blind doc-rejects"
  fi

  # Cluster status. This only became a usable signal on 2026-07-21: previously
  # 35 shards were permanently unassignable (no index template on the snmptrap
  # lane + unmanaged ISM history indices, both defaulting to 1 replica on a
  # SINGLE-node cluster), so the cluster was always yellow and yellow meant
  # nothing. Replicas are pinned to 0 now, so a departure from green is real.
  os_status=$(os_fetch svc_api "$OS_API_PW" "/_cluster/health" |
    grep -oE '"status"[[:space:]]*:[[:space:]]*"[a-z]+"' | grep -oE '(green|yellow|red)' | head -1)
  case "${os_status:-}" in
    yellow|red) problems+=("OpenSearch cluster is ${os_status} (was pinned green on 2026-07-21 — check for a lane with no index template, i.e. replicas>0)") ;;
    green) : ;;
    *) os_blind="$os_blind cluster-status" ;;
  esac

  # ---------------------------------------------------------------------------
  # F-59: BACKUP FRESHNESS — checked here, out of band, on purpose.
  #
  # The 2026-07-21 audit found `GET _snapshot` = {}: no snapshot repository had
  # ever been registered, so nothing had ever backed up a search index. The
  # repository and the daily SM policy exist now (opensearch/apply-ism.sh), but
  # a policy that silently stops running returns the system to exactly the same
  # state — with the added problem that everyone now believes backups exist.
  #
  # This check deliberately does NOT live in rules.yaml. The metrics path runs
  # inside the stack; an alarm about the stack's last line of defence must not
  # share fate with it. Same reasoning that keeps this whole watchdog external.
  #
  # A PARTIAL snapshot is treated as a failure: it means shards were missed, so
  # a restore from it is incomplete — the most dangerous state of the three,
  # because it looks like success in `_cat/snapshots`.
  # ---------------------------------------------------------------------------
  snap_max_age_h="${SNAPSHOT_MAX_AGE_H:-36}"
  if [ "$snap_max_age_h" -gt 0 ]; then
    snap_json=$(os_fetch svc_api "$OS_API_PW" "/_cat/snapshots/netops-fs?h=id,status,end_epoch&format=json")
    case "${snap_json:-}" in
      *repository_missing*|*RepositoryMissingException*)
        problems+=("NO OPENSEARCH BACKUPS: snapshot repository 'netops-fs' is not registered — every search index is unrecoverable if data/ is lost (run docker compose up opensearch-init)") ;;
      "["*)
        # Newest end_epoch across all snapshots; empty list => no snapshot yet.
        snap_last=$(printf '%s' "$snap_json" |
          grep -oE '"end_epoch"[[:space:]]*:[[:space:]]*"?[0-9]+' |
          grep -oE '[0-9]+$' | sort -n | tail -1)
        if [ -z "${snap_last:-}" ]; then
          problems+=("NO OPENSEARCH BACKUPS: repository 'netops-fs' exists but contains ZERO snapshots — the daily policy has never completed")
        else
          snap_age_h=$(( ($(date +%s) - snap_last) / 3600 ))
          [ "$snap_age_h" -gt "$snap_max_age_h" ] &&
            problems+=("OpenSearch backup STALE: newest snapshot is ${snap_age_h}h old (>${snap_max_age_h}h) — the daily snapshot policy has stopped")
        fi
        if printf '%s' "$snap_json" | grep -q '"PARTIAL"'; then
          problems+=("OpenSearch snapshot is PARTIAL — some shards were NOT captured; a restore from it would be incomplete")
        fi
        ;;
      # No reply / unrecognized reply: the backup-freshness sentinel is blind,
      # which is NOT the same as backups being fresh.
      *) os_blind="$os_blind backup-freshness" ;;
    esac
  fi

  fi  # end of the OS_TLS credentialed-probe guard

  if [ -n "$os_blind" ]; then
    # Do not GUESS at the cause — measure it once, then name it (os_probe_diag).
    # The stable class + raw codes ride the problem text (and so the push); the
    # run-varying evidence goes to the log, out of problem_key's 160-char hash.
    os_probe_diag
    problems+=("OPENSEARCH_UNVERIFIABLE (self-test: ${os_diag_class}, curl exit ${os_diag_rc}, http ${os_diag_http:-none}): no parsable reply for:${os_blind} — these search-tier checks are BLIND this run, which is not the same as healthy; the self-test detail is in the watchdog log.")
    logerr "watchdog: OpenSearch probe self-test: ${os_diag_class} (curl exit ${os_diag_rc}, http ${os_diag_http:-none}) against $OS_PROBE_URL — ${os_diag_detail}"
  fi
fi

# -----------------------------------------------------------------------------
# TELEMETRY-FLOW probe (2026-07-27 audit): every container can be RUNNING and
# HEALTHY while zero telemetry lands. Container liveness is not data liveness,
# and the audit showed the platform could not detect its own blindness — a
# metric-store outage read as "no rules firing" and mass-RESOLVED live alerts.
# The applogs probe above covers the LOG lane; these cover the two lanes whose
# silence is most dangerous:
#
#   * correlation signals (ClickHouse netops.corr_signals) — the RCA substrate.
#     Empty means the bus/consumer stalled; the UI then shows an honestly empty
#     incident list that reads as "a quiet network".
#   * metrics (VictoriaMetrics) — the lane that drives every metric alert. Its
#     silence is the exact input that produced the mass-resolve.
#
# Both are DELTA-free absolute-freshness checks: we ask "what is the newest row
# / most recent scrape", not "how many". A stale-but-present store is the
# failure mode; a genuinely idle lab is handled by the opt-out below.
# Set TELEMETRY_STALE_MIN=0 to disable (e.g. a demo host with no live devices).
# -----------------------------------------------------------------------------
tel_stale_min="${TELEMETRY_STALE_MIN:-20}"
if [ "$tel_stale_min" -gt 0 ]; then
  check_clickhouse_health "$tel_stale_min"

  vm_cid=$(dkr ps -q --filter "label=com.docker.compose.project=$PROJECT" \
    --filter "label=com.docker.compose.service=victoria" 2>/dev/null)
  if [ -n "$vm_cid" ]; then
    # Age of the newest collector sample. NOTE the query shape: last_over_time
    # yields the VALUE, so freshness needs timestamp() around it — `time() -
    # max(last_over_time(...))` silently computes time()-1 and always looks
    # catastrophic. Verified against the live store when written.
    # 127.0.0.1, not localhost: the VM image is minimal and does not resolve it
    # (its own healthcheck uses 127.0.0.1 for the same reason).
    # The 6h lookback means a long blackout still yields a large AGE rather than
    # an empty result, so "stale" and "absent" stay distinguishable.
    vm_age=$(dkr exec "$vm_cid" wget -qO- --timeout=5 \
      'http://127.0.0.1:8428/api/v1/query?query=time()-max(timestamp(last_over_time(collector_up%5B6h%5D)))' 2>/dev/null |
      sed -n 's/.*"value":\[[^,]*,"\([0-9.]*\)".*/\1/p' | cut -d. -f1)
    if [ -z "$vm_age" ]; then
      problems+=("telemetry: no collector metric in VictoriaMetrics for at least 6h (store unreachable, or every collector has been silent that long)")
    elif [ "$vm_age" -gt $(( tel_stale_min * 60 )) ]; then
      problems+=("telemetry STALLED: newest collector metric is $(( vm_age / 60 ))m old (limit ${tel_stale_min}m) — metric alerting is blind, and a blind engine resolves alerts instead of firing them")
    fi
  fi
fi

# -----------------------------------------------------------------------------
# F-51: CONFIG-DRIFT probe.
#
# A single-file bind mount resolves to an INODE. Any editor that writes-then-
# renames (vim, VS Code, sed -i, python atomic writes) produces a NEW inode and
# the mount stays pinned to the OLD one forever — so `docker compose restart`
# re-runs the container against a stale file and the operator sees a fix that
# was never deployed. That is not hypothetical: on 2026-07-21 vector-router ran
# for hours on a config the repo had already replaced (host inode 268641 vs
# container 291584), and nothing anywhere reported it.
#
# The structural fix is directory mounts (done in docker-compose.yml), but the
# failure is invisible and WILL recur the next time someone adds a file mount.
# So verify the claim rather than trusting it: hash the repo file and the
# in-container file and compare. Config drift is the only thing this can report,
# and it reports it before the next incident instead of during it.
# -----------------------------------------------------------------------------
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
drift_check() {  # $1 = compose service, $2 = repo-relative path, $3 = in-container path
  local cid host_file host_sum cont_sum mnt_src
  cid=$(dkr ps -q --filter "label=com.docker.compose.project=$PROJECT" \
                  --filter "label=com.docker.compose.service=$1" 2>/dev/null | head -1)
  [ -n "$cid" ] || return 0
  # Compare against the file the container ACTUALLY bind-mounts at $3, not the
  # assumed repo path: a compose override may mount a deploy-time variant (the
  # mTLS deployment mounts nginx/default-mtls.conf as default.conf), and hashing
  # the base file against it reported CONFIG DRIFT for a correctly-configured
  # stack (2026-08-04). Stale-inode drift is still caught — the mount source
  # path yields the host's CURRENT content while the container serves the
  # pinned old inode. The passed repo path is only the no-mount fallback.
  mnt_src=$(dkr inspect -f "{{range .Mounts}}{{if eq .Destination \"$3\"}}{{.Source}}{{end}}{{end}}" "$cid" 2>/dev/null)
  host_file="$REPO_ROOT/$2"
  if [ -n "$mnt_src" ] && [ -f "$mnt_src" ]; then
    host_file="$mnt_src"
  fi
  [ -f "$host_file" ] || return 0
  host_sum=$(sha256sum "$host_file" 2>/dev/null | cut -d' ' -f1)
  # Hash on the HOST from a streamed `cat`, rather than running sha256sum
  # inside the container. Half these images have no sha256sum (vector, the
  # syslog-ng image), and a missing TOOL produced an empty result that the
  # first version of this check read as "fine" — a drift probe that silently
  # cannot detect drift is precisely the class of defect it exists to catch.
  cont_sum=$(dkr exec "$cid" cat "$3" 2>/dev/null | sha256sum 2>/dev/null | cut -d' ' -f1)
  # A MISSING file is not "unknown", it is a broken mount: the service is
  # running on the image's built-in default while the repo believes it is
  # configured. Report it.
  if ! dkr exec "$cid" test -f "$3" 2>/dev/null; then
    problems+=("CONFIG MISSING: $1 has no $3 in the container — the bind mount for $2 is not in effect. Fix: docker compose up -d --force-recreate $1")
    return 0
  fi
  # e3b0c442... is the sha256 of empty input, i.e. `cat` produced nothing.
  if [ -z "$cont_sum" ] || [ "$cont_sum" = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" ]; then
    problems+=("CONFIG UNVERIFIABLE: could not read $3 from $1 — the drift probe is blind for this service, fix the probe rather than ignoring it")
    return 0
  fi
  if [ "$host_sum" != "$cont_sum" ]; then
    problems+=("CONFIG DRIFT: $1 is running a different $2 than the repo — the container never picked up the edit (stale inode / not recreated). Fix: docker compose up -d --force-recreate $1")
  fi
}
drift_check vector-aggregator deployment/docker/vector/vector.yaml        /etc/vector/conf/vector.yaml
drift_check vector-router     deployment/docker/vector-router/vector.yaml /etc/vector/conf/vector.yaml
drift_check victoria          src/config/vmscrape.yml                     /etc/victoria/config/vmscrape.yml

# ---- BUILD drift: is the deployed BINARY the committed source? -------------
#
# drift_check above covers BIND-MOUNTED config, which updates the instant a
# container restarts. It cannot see the other half: code BAKED INTO AN IMAGE,
# which only changes on `docker compose build`.
#
# That asymmetry is what made F-08 invisible (2026-07-22). The feature's code and
# config were both correct and both committed, but the api image was never
# rebuilt, so it sat built-but-undeployed for weeks while looking complete.
# `docker compose up -d` recreates a container from whatever image already
# exists — it does not rebuild — so "restart the service" silently redeployed old
# code. prober was running a 38-hour-old binary and had been restarted repeatedly
# without ever gaining the fix it needed. Nothing objected, because nothing could
# answer "which commit is actually running?".
#
# Now the binary answers, at /admin/version, and this compares it to HEAD.
build_drift_check() { # $1 service, $2 url
  local running head_sha body
  head_sha=$(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null)
  [ -n "$head_sha" ] || return 0   # not a git checkout (e.g. an offline bundle)
  body=$(curl -fsS -m 10 ${APP_CACERT:+--cacert "$APP_CACERT"} "$2" 2>/dev/null) || {
    problems+=("BUILD UNVERIFIABLE: $1 did not answer $2 — the provenance probe is blind, fix the probe rather than ignoring it")
    return 0
  }
  running=$(printf '%s' "$body" | sed -n 's/.*"sha"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
  # An UNIDENTIFIED build is a failure, not a pass: a binary that cannot name its
  # revision is exactly the situation this check exists to end.
  if [ -z "$running" ] || [ "$running" = "unknown" ]; then
    problems+=("BUILD UNIDENTIFIED: $1 reports no git SHA — it was built without GIT_SHA. Rebuild with: GIT_SHA=\$(git rev-parse HEAD) docker compose build $1")
    return 0
  fi
  if [ "$running" != "$head_sha" ]; then
    problems+=("BUILD DRIFT: $1 is running ${running:0:8} but HEAD is ${head_sha:0:8} — the deployed image predates the source. Fix: GIT_SHA=\$(git rev-parse HEAD) BUILD_TIME=\$(date -u +%FT%TZ) docker compose build $1 && docker compose up -d $1")
  fi
}
build_drift_check api "${APP_URL%/}/admin/version"
drift_check vmalert           src/config/rules.yaml                       /etc/vmalert/config/rules.yaml
drift_check syslog-ng         deployment/docker/syslog-ng/syslog-ng.conf  /etc/syslog-ng/conf.d/syslog-ng.conf
drift_check nginx             deployment/docker/nginx/default.conf        /etc/nginx/conf.d/default.conf
drift_check nginx             deployment/docker/nginx/nginx.conf          /etc/nginx/nginx.conf

# -----------------------------------------------------------------------------
# ENGINE-CONSUMING probe (2026-09-02 incident).
#
# THE GAP THIS CLOSES. For three hours the correlation engine's Kafka consumer
# never started (a failed multi-topic subscribe abandoned all 14 lanes over one
# optional topic). The container healthcheck said "healthy" — it polls a
# sidecar thread that outlives the consumer BY DESIGN. This watchdog said
# green — it checked services running/healthy, :8000 and api liveness, none of
# which can tell "running" from "doing work". kafka-exporter had the proof in
# VictoriaMetrics the whole time and nothing read it.
#
# So this probe asks the ONE question the rest of the file cannot: is the
# engine actually consuming? It is deliberately kept HERE, in the external
# watchdog, rather than left to the new vmalert rules alone — the stack's own
# alerting cannot report its own death, which is the same reason the ntfy
# channel exists at all. The vmalert rules (CorrelationConsumerDead,
# RouterConsumerDead, ...) are the in-stack layer; this is the independent one.
#
# THREE checks, all read-only, all bounded:
#   1. correlation consumer group has members;
#   2. every netops-router-* lane has members;
#   3. the alert-delivery heartbeat is arriving (see below).
# Set ENGINE_CONSUMER_CHECK=0 to disable the lot.
#
# Queries are PRE-URL-ENCODED constants: the victoria image is minimal (wget,
# no curl, and it does not resolve "localhost" — 127.0.0.1 only), and encoding
# PromQL braces/quotes at runtime in bash is a bug farm. The readable form is
# in the comment above each one; keep the two in step.
# -----------------------------------------------------------------------------
if [ "${ENGINE_CONSUMER_CHECK:-1}" = "1" ]; then
  eng_cid=$(dkr ps -q --filter "label=com.docker.compose.project=$PROJECT" \
                      --filter "label=com.docker.compose.service=victoria" 2>/dev/null | head -1)
  if [ -z "$eng_cid" ]; then
    # Advisory, not critical: a missing victoria container is ALREADY reported
    # as a critical by the service loop above, and a second page for one fault
    # is noise. What must not happen is silence about the probe not running.
    problems+=("engine-consuming probe SKIPPED: no running victoria container in project '$PROJECT' — the consumer-group and alert-delivery checks did NOT run this minute")
  else
    eng_err=""

    # Query VictoriaMetrics for ONE scalar. Prints the value and returns 0; on
    # any failure prints nothing, returns non-zero, and leaves the diagnostic
    # in $eng_err for the caller to REPORT. A probe that cannot run must never
    # read as a pass (§16.1) — that swallow is what this whole section exists
    # to make impossible.
    eng_query() {  # $1 = url-encoded promql -> stdout: first sample value
      local out rc
      eng_err=""
      # rc is captured on its OWN line: inside `if ! cmd; then`, $? is the
      # status of the negated test (always 0), so reporting $? there would
      # print a confident, wrong "rc=0" for every real failure.
      out=$(dkr exec "$eng_cid" wget -qO- --timeout=5 \
              "http://127.0.0.1:8428/api/v1/query?query=$1" 2>&1)
      rc=$?
      if [ "$rc" -ne 0 ]; then
        eng_err="victoria query failed (rc=$rc): $(printf '%s' "$out" | tr '\n' ' ' | cut -c1-140)"
        return 1
      fi
      case "$out" in
        *'"status":"success"'*) : ;;
        *) eng_err="victoria returned a non-success body: $(printf '%s' "$out" | tr '\n' ' ' | cut -c1-140)"
           return 1 ;;
      esac
      printf '%s\n' "$out" | sed -n 's/.*"value":\[[^,]*,"\([-0-9.e+]*\)".*/\1/p' | head -1
      return 0
    }

    # -- 1/2. Consumer-group membership -------------------------------------
    # min(kafka_consumergroup_members{consumergroup="netops-correlation"})
    eng_corr=$(eng_query 'min%28kafka_consumergroup_members%7Bconsumergroup%3D%22netops-correlation%22%7D%29') || true
    if [ -n "$eng_err" ]; then
      problems+=("engine-consuming probe SKIPPED: $eng_err")
    elif [ -z "$eng_corr" ]; then
      # No series at all. kafka-exporter lives behind the optional
      # self-monitoring profile, so on a base install this is EXPECTED and must
      # be a named skip, not a fake pass and not a false page. Distinguish the
      # two by whether the exporter container is actually running.
      if [ -n "$(dkr ps -q --filter "label=com.docker.compose.project=$PROJECT" \
                           --filter "label=com.docker.compose.service=kafka-exporter" 2>/dev/null)" ]; then
        problems+=("engine-consuming probe: kafka-exporter is running but exports NO consumer-group series — every bus-lag and consumer-liveness check is blind (see KafkaLagMetricsMissing)")
      else
        logerr "watchdog: consumer-group checks skipped — kafka-exporter is not running (optional 'self-monitoring' profile); ENGINE_CONSUMER_CHECK=0 to silence this line"
      fi
    else
      # The value is a member COUNT, but VM may render it "0" or "0.0", so cut
      # the fraction off. Validate the SHAPE before comparing: `[ x -le 0 ]` on
      # a non-numeric value errors, and suppressing that error would report a
      # malformed reply as "members > 0" — i.e. as healthy. That is exactly the
      # swallow-and-look-fine defect this whole probe exists to undo (§16.1).
      eng_corr_i=${eng_corr%%.*}
      if ! printf '%s' "$eng_corr_i" | grep -qE '^-?[0-9]+$'; then
        problems+=("engine-consuming probe SKIPPED: correlation member count is not a number (got '${eng_corr}') — treating as UNKNOWN, not as healthy")
      elif [ "$eng_corr_i" -le 0 ]; then
        eng_lag=$(eng_query 'sum%28kafka_consumergroup_lag_sum%7Bconsumergroup%3D%22netops-correlation%22%7D%29') || true
        problems+=("ENGINE_NOT_CONSUMING: correlation consumer group has ZERO members (bus backlog ${eng_lag:-unknown}) — RCA has stopped; containers will still read healthy. Runbook: docs/runbooks/engine-not-consuming.md")
      fi

      # Router lanes. One query both DETECTS and NAMES the dead ones.
      # kafka_consumergroup_members{consumergroup=~"netops-router-.*"} == 0
      eng_dead_raw=$(dkr exec "$eng_cid" wget -qO- --timeout=5 \
        'http://127.0.0.1:8428/api/v1/query?query=kafka_consumergroup_members%7Bconsumergroup%3D~%22netops-router-.%2A%22%7D%20%3D%3D%200' 2>&1) || eng_dead_raw=""
      case "$eng_dead_raw" in
        *'"status":"success"'*)
          eng_dead=$(printf '%s' "$eng_dead_raw" | grep -oE '"consumergroup":"[^"]+"' | cut -d'"' -f4 | sort -u | tr '\n' ' ')
          [ -n "${eng_dead// /}" ] &&
            problems+=("ENGINE_NOT_CONSUMING: router lane(s) with ZERO consumers: ${eng_dead}— vector-router is not draining them; that data reaches no store and is lost once bus retention passes. Runbook: docs/runbooks/engine-not-consuming.md")
          ;;
        *)
          problems+=("engine-consuming probe SKIPPED: router consumer-group query returned no usable body: $(printf '%s' "$eng_dead_raw" | tr '\n' ' ' | cut -c1-140)")
          ;;
      esac
    fi

    # -- 3. Alert-delivery heartbeat ----------------------------------------
    # THE POINT: an alerting stack that cannot prove its own delivery path is
    # not an alerting stack. On 2026-09-02 thirteen alerts were firing, some
    # since 2026-08-27, and NOT ONE had ever been delivered — vmalert shipped
    # with -notifier.blackhole. The AlertingHeartbeat rule now fires always and
    # the api's webhook receiver stamps the arrival time into
    # netops_alert_webhook_heartbeat_timestamp_seconds. A fresh timestamp is
    # end-to-end proof of: vmalert evaluates -> notifier delivers -> api
    # receives. Checking it from HERE, over the watchdog's own independent
    # channel, is the only check that survives the delivery path being the
    # thing that is broken.
    # max(netops_alert_webhook_enabled)
    eng_hb_on=$(eng_query 'max%28netops_alert_webhook_enabled%29') || true
    if [ -n "$eng_err" ]; then
      problems+=("alert-delivery probe SKIPPED: $eng_err")
    elif [ -z "$eng_hb_on" ]; then
      # The api build predates the webhook receiver, or the api is not being
      # scraped. Either way the CHAIN IS UNPROVEN — say so once, quietly, and
      # never imply it is healthy.
      logerr "watchdog: alert-delivery heartbeat not checked — netops_alert_webhook_enabled is absent (api predates the vmalert webhook receiver, or is not scraped). Alert delivery is UNPROVEN on this deployment."
    elif [ "${eng_hb_on%%.*}" = "0" ]; then
      problems+=("alert delivery is DISABLED: VMALERT_WEBHOOK_TOKEN is unset, so vmalert's alerts are not delivered to the platform. Only this watchdog can page. Set it in deployment/docker/.env (see docs/runbooks/engine-not-consuming.md)")
    else
      # max(time() - netops_alert_webhook_heartbeat_timestamp_seconds)
      eng_hb_age=$(eng_query 'max%28time%28%29%20-%20netops_alert_webhook_heartbeat_timestamp_seconds%29') || true
      if [ -n "$eng_err" ]; then
        problems+=("alert-delivery probe SKIPPED: $eng_err")
      elif [ -z "$eng_hb_age" ]; then
        problems+=("ALERT_DELIVERY_BROKEN: the webhook receiver is enabled but exports no heartbeat timestamp — vmalert has never delivered an alert to it. Runbook: docs/runbooks/engine-not-consuming.md")
      else
        eng_hb_age_i=${eng_hb_age%%.*}
        eng_hb_max="${ALERT_HEARTBEAT_MAX_SEC:-900}"
        if ! printf '%s' "$eng_hb_age_i" | grep -qE '^-?[0-9]+$'; then
          problems+=("alert-delivery probe SKIPPED: heartbeat age is not a number (got '${eng_hb_age}') — treating as UNKNOWN, not as healthy")
        elif [ "$eng_hb_age_i" -gt "$eng_hb_max" ]; then
          problems+=("ALERT_DELIVERY_BROKEN: no alert has reached the platform for $(( eng_hb_age_i / 60 ))m (limit $(( eng_hb_max / 60 ))m) — vmalert is evaluating into a void and every 'quiet' alert is unproven. Runbook: docs/runbooks/engine-not-consuming.md")
        fi
      fi
    fi
  fi
fi

# -----------------------------------------------------------------------------
# F-16: surface what the alerting engine is actually firing.
#
# vmalert evaluates rules.yaml and writes the firing state back into
# VictoriaMetrics as ALERTS series, but nothing DELIVERS them — the stack ships
# no Alertmanager. This watchdog already owns an independent notification path
# (ntfy, deliberately not one of the stack's own notifiers, because a stack
# cannot report its own death), so it is the right place to turn a firing
# critical into a phone push.
#
# Only `critical` severity, and only alerts that have cleared their `for:`
# window, so this cannot become the noise that gets the watchdog muted.
# -----------------------------------------------------------------------------
if [ "${WATCHDOG_REPORT_ALERTS:-1}" = "1" ]; then
  vm_cid=$(dkr ps -q --filter "label=com.docker.compose.project=$PROJECT" \
                     --filter "label=com.docker.compose.service=opensearch" 2>/dev/null | head -1)
  if [ -n "$vm_cid" ]; then
    firing=$(dkr exec "$vm_cid" curl -s -m 5 -G "http://victoria:8428/api/v1/query" \
      --data-urlencode 'query=ALERTS{alertstate="firing",severity="critical"}' 2>/dev/null |
      grep -oE '"alertname":"[^"]+"' | cut -d'"' -f4 | sort -u | tr '\n' ' ')
    [ -n "${firing// /}" ] && problems+=("vmalert CRITICAL firing: ${firing}")
  fi
fi

# -----------------------------------------------------------------------------
# H16 (2026-08-15): per-problem-class transition machine.
#
# The old machine kept ONE up/down flag. Any standing problem — a config
# drift, a stale backup, one misdetected probe — parked the flag at "down",
# and every LATER problem (including a service actually dying) arrived into
# "already down": no transition, no push, ever. On shipped layouts with one
# permanently-red advisory check the watchdog could therefore never page for
# a real outage again.
#
# Now the state file holds the SET of active problem classes, one per line,
# "C <key>" (critical: service down/unhealthy, dashboard down, exec ceiling,
# store unreachable, ingest stalled) or "A <key>" (advisory: drift, stale
# backups, capacity warnings, ...). Each run:
#   * a NEW critical key        -> urgent push, regardless of what was already
#                                  standing (the fix);
#   * criticals all cleared but
#     advisories remain         -> default-priority all-clear-of-criticals;
#   * a NEW advisory key        -> one default-priority push (transition-only,
#                                  same as before);
#   * everything cleared        -> the RECOVERED push;
#   * unchanged set             -> silence (sustained problems never re-push).
# Keys are the problem text with digits stripped (ages/percentages/counts
# change run to run and must not mint a "new" problem), bounded, reduced to a
# safe charset. A legacy one-word up/down state file reads as an empty set, so
# the first post-upgrade run re-announces whatever is standing — once.
# -----------------------------------------------------------------------------
problem_key() {
  printf '%s' "$1" | cut -c1-160 | tr -d '0-9' | tr -c 'A-Za-z_:.-' '.' | tr -s '.'
}

problem_is_critical() {
  case "$1" in
    *": not running"*|*": state="*|*": health="*|"dashboard "*|\
    *PID_LIMIT_REACHED*|*CONTAINER_RUNTIME_EXEC_FAILURE*|\
    *CLICKHOUSE_UNREACHABLE*|*CLICKHOUSE_TLS_FAILURE*|*"CANNOT PROBE"*|\
    *API_UNRESPONSIVE*|\
    *ENGINE_NOT_CONSUMING*|*ALERT_DELIVERY_BROKEN*|\
    *"log ingest stalled"*)
      return 0 ;;
  esac
  return 1
}

nsvc=$(echo "$EXPECTED_SERVICES" | wc -w | tr -d ' ')

declare -A prev_set=()
prev_had_any=0
prev_had_crit=0
if [ -f "$STATE_FILE" ]; then
  while IFS= read -r line; do
    case "$line" in
      "C "*) prev_set["$line"]=1; prev_had_any=1; prev_had_crit=1 ;;
      "A "*) prev_set["$line"]=1; prev_had_any=1 ;;
      down)  prev_had_any=1 ;;   # legacy v1 state: something stood, class unknown
      *) : ;;
    esac
  done < "$STATE_FILE"
fi

declare -A cur_set=()
new_crit=()
new_adv=()
cur_has_crit=0
if [ ${#problems[@]} -gt 0 ]; then
  for prob in "${problems[@]}"; do
    pkey=$(problem_key "$prob")
    if problem_is_critical "$prob"; then
      psev="C"; cur_has_crit=1
    else
      psev="A"
    fi
    cur_set["$psev $pkey"]=1
    if [ -z "${prev_set["$psev $pkey"]:-}" ]; then
      if [ "$psev" = "C" ]; then new_crit+=("$prob"); else new_adv+=("$prob"); fi
    fi
  done
fi
cleared=0
for k in "${!prev_set[@]}"; do
  [ -z "${cur_set[$k]:-}" ] && cleared=$((cleared + 1))
done
[ "$cleared" -gt 0 ] &&
  logerr "watchdog: $cleared problem class(es) cleared since the last run"

write_state() {
  if [ ${#cur_set[@]} -gt 0 ]; then
    printf '%s\n' "${!cur_set[@]}" > "$STATE_FILE" 2>/dev/null ||
      logerr "watchdog: could not persist state to $STATE_FILE"
  else
    : > "$STATE_FILE" 2>/dev/null ||
      logerr "watchdog: could not persist state to $STATE_FILE"
  fi
}

if [ ${#problems[@]} -eq 0 ]; then
  if [ "$api_probe_failing" = 1 ]; then
    # Tracker 194: the api is not serving, but it is still inside its cold-boot
    # grace so nothing is CLASSIFIED as a problem yet. The dead-man's switch
    # must still not read "healthy" — withholding it is the entire point of a
    # dead-man's switch — and a RECOVERED all-clear here would be a lie. Stay
    # silent for this run and leave the previous problem set on disk untouched,
    # so a genuine recovery is still announced once the api answers again.
    logerr "watchdog: healthy heartbeat WITHHELD and the all-clear deferred — the api liveness probe is failing (inside its cold-boot grace)"
    exit 0
  fi
  [ -n "${HC_PING_URL:-}" ] && curl -fsS -m 10 "$HC_PING_URL" -o /dev/null
  if [ "$prev_had_any" = 1 ]; then
    push "✅ NetOps stack RECOVERED on $(hostname)" "white_check_mark" "default" \
      "All $nsvc services healthy again at $(date -Is)."
    notify_webhook "up" "All $nsvc services healthy again."
  fi
  write_state
  exit 0
fi

msg=$(printf '%s\n' "${problems[@]}")
[ -n "${HC_PING_URL:-}" ] && curl -fsS -m 10 --data-raw "$msg" "${HC_PING_URL%/}/fail" -o /dev/null

if [ ${#new_crit[@]} -gt 0 ]; then
  push "🚨 NetOps stack DOWN on $(hostname)" "rotating_light" "urgent" \
    "$(printf 'NEW: %s\n' "${new_crit[@]}"; printf 'ALL CURRENT PROBLEMS:\n'; printf '%s\n' "${problems[@]}")"
  notify_webhook "down" "$msg"
elif [ "$prev_had_crit" = 1 ] && [ "$cur_has_crit" = 0 ]; then
  push "✅ NetOps criticals CLEARED on $(hostname)" "white_check_mark" "default" \
    "$(printf 'Critical problems cleared; %s advisory issue(s) remain:\n' "${#problems[@]}"; printf '%s\n' "${problems[@]}")"
  notify_webhook "degraded" "criticals cleared; advisories remain: $msg"
elif [ ${#new_adv[@]} -gt 0 ]; then
  push "⚠️ NetOps advisory on $(hostname)" "warning" "default" \
    "$(printf '%s\n' "${new_adv[@]}")"
  notify_webhook "degraded" "$(printf '%s\n' "${new_adv[@]}")"
fi

write_state
logerr "watchdog: DOWN -> $msg"
exit 1
