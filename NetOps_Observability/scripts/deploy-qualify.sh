#!/usr/bin/env bash
#
# deploy-qualify.sh — the post-deploy gate that proves the platform is DOING
# WORK, not merely running.
#
# WHY THIS EXISTS
# ---------------
# `docker compose up` exiting 0 is not evidence. Neither is a clean
# `docker compose ps`, nor a green healthcheck, nor a green external watchdog.
# We have now paid for that lesson twice:
#
#   * 2026-09-02 — the correlation engine's Kafka consumer never started. Its
#     subscribe() raised TopicAuthorizationFailedError and then
#     UnknownTopicOrPartitionError on ONE optional topic (netops.security), and
#     kafka-python abandoned the WHOLE 14-topic subscription. The engine sat
#     there for three hours consuming nothing. Every container reported
#     "healthy", `docker compose ps` was clean, and the off-host watchdog was
#     green the entire time.
#
#   * 2026-08-16 — vector-router and correlation went auth-dead for ~80 minutes
#     after a `data/kafka` wipe emptied the KRaft ACL store (the store IS the
#     authorization state since SEC-007.2 flipped
#     allow.everyone.if.no.acl.found to false). Lag froze, nothing moved, and
#     again every healthcheck stayed green.
#
# Both failures share one shape: liveness was perfect and the pipeline was
# dead. A healthcheck answers "is the process up"; nothing in the stack asked
# "is the engine actually consuming and producing". This script is that missing
# question, asked as a gate.
#
# It does two things after a deploy:
#   PHASE 1  runs the bootstraps a fresh install needs (Kafka ACL matrix, topic
#            pre-creation, OpenSearch ISM/snapshot policy) — each documented
#            idempotent, each invoked so that re-running is a no-op, each with
#            its output CAPTURED and REPORTED on failure (§16.1: never
#            `>/dev/null 2>&1 || true` — that exact pattern is what let the
#            2026-08-16 incident run for 80 minutes).
#   PHASE 2  proves, inside a bounded wait, that the top-tier engines have
#            joined their consumer groups, that lag is draining rather than
#            piling up, that both Vector tiers are emitting, that neither
#            correlation nor vector-router logged a bootstrap-class Kafka
#            authorization/topic error, and that the API is serving.
#
# SAFETY: this script never restarts, recreates, scales or deletes any
# LONG-LIVED service, and never touches a data volume. Phase 1 recreates only
# the `restart: "no"` ONE-SHOT bootstrap containers (kafka-init,
# opensearch-init) — whose entire purpose is to run once and exit — and only
# when their work is actually outstanding. Everything else only READS.
#
# USAGE / EXIT CODES: see --help.
#
# Style contract: scripts/CLAUDE.md §16.1 (never swallow an error), §16.2
# (hostile minimal environment: explicit PATH, nothing sourced from a shell
# profile), §16.3 (set -euo pipefail, quoted expansions, bounded external
# calls, idempotent), §16.5 (no secrets, no lab fixtures — this file SHIPS in
# the customer bundle; it is not export-ignored and not in make-installer.sh's
# LAB_PATHS).

set -euo pipefail

# §16.2: cron/CI PATH is `/usr/bin:/bin` only. Name it explicitly rather than
# inheriting whatever the caller happened to have.
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:${PATH:-}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
COMPOSE_DIR="$REPO_ROOT/deployment/docker"
ACL_SCRIPT="$COMPOSE_DIR/kafka/apply-acls.sh"

# ---------------------------------------------------------------------------
# Presentation. A SKIP must never look like a PASS (a skipped required check is
# an un-answered question, not a good answer), so each verdict gets its own
# glyph AND its own colour, and colour is dropped entirely when stdout is not a
# terminal so a CI log stays readable.
# ---------------------------------------------------------------------------
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  C_OK=$'\033[32m'; C_BAD=$'\033[31m'; C_SKIP=$'\033[33m'
  C_ADV=$'\033[36m'; C_BOLD=$'\033[1m'; C_OFF=$'\033[0m'
else
  C_OK=''; C_BAD=''; C_SKIP=''; C_ADV=''; C_BOLD=''; C_OFF=''
fi

say()  { printf '%s\n' "$*"; }
warn() { printf '%s! %s%s\n' "$C_SKIP" "$*" "$C_OFF" >&2; }

# ---------------------------------------------------------------------------
# Result ledger. Every check lands here exactly once with a verdict; the final
# block prints all of them. PASS/FAIL/SKIP/ADVISORY are the only verdicts.
# ---------------------------------------------------------------------------
RESULTS=()          # "VERDICT<TAB>REQ|ADV<TAB>label<TAB>detail"
N_PASS=0; N_FAIL=0; N_SKIP_REQ=0; N_SKIP_ADV=0; N_ADV=0

record() {  # verdict, class(REQUIRED|ADVISORY), label, detail
  RESULTS+=("$1"$'\t'"$2"$'\t'"$3"$'\t'"$4")
  case "$1/$2" in
    PASS/*)         N_PASS=$((N_PASS + 1)) ;;
    FAIL/*)         N_FAIL=$((N_FAIL + 1)) ;;
    SKIP/REQUIRED)  N_SKIP_REQ=$((N_SKIP_REQ + 1)) ;;
    SKIP/ADVISORY)  N_SKIP_ADV=$((N_SKIP_ADV + 1)) ;;
    ADVISORY/*)     N_ADV=$((N_ADV + 1)) ;;
  esac
  case "$1" in
    PASS)     printf '  %s✓ PASS%s      %s — %s\n' "$C_OK"   "$C_OFF" "$3" "$4" ;;
    FAIL)     printf '  %s✗ FAIL%s      %s — %s\n' "$C_BAD"  "$C_OFF" "$3" "$4" >&2 ;;
    SKIP)     printf '  %s— SKIPPED%s   %s — %s\n' "$C_SKIP" "$C_OFF" "$3" "$4" ;;
    ADVISORY) printf '  %s· ADVISORY%s  %s — %s\n' "$C_ADV"  "$C_OFF" "$3" "$4" ;;
  esac
}

usage() {
  cat <<'EOF'
deploy-qualify.sh — prove a deployed Correlix stack is actually consuming and
producing, not merely "running". Run it after every deploy.

USAGE
  scripts/deploy-qualify.sh [--timeout SECONDS] [--project NAME]
                            [--no-bootstrap] [--help]

OPTIONS
  --timeout SECONDS  Qualification window for PHASE 2 (default 300). Every
                     assertion polls inside this ONE shared window, so the
                     whole phase is bounded by it. Once the window closes each
                     remaining assertion still gets one final evaluation, so it
                     reports a real verdict rather than vanishing.
  --project NAME     Compose project name. Default: discovered from the running
                     containers' com.docker.compose.project label, falling back
                     to COMPOSE_PROJECT_NAME / COMPOSE_PROJECT, then "netops".
  --no-bootstrap     Skip PHASE 1 entirely (qualification only).
  --help             This text. Exits 0 and contacts nothing.

WHAT IT DOES
  PHASE 1 (bootstraps — idempotent, skippable)
    B1  Kafka ACL matrix        deployment/docker/kafka/apply-acls.sh, piped
                                into the running kafka container. Applied ONLY
                                on a TLS/mTLS broker; skipped, loudly, on a
                                pre-TLS plaintext broker where minting a first
                                ACL would start denying everyone.
    B2  Kafka topic creation    one-shot kafka-init (create --if-not-exists,
                                partition increase-only).
    B3  OpenSearch ISM policy   one-shot opensearch-init (apply-ism.sh; PUTs
                                replace, so re-running converges).
    B2 is CHECK-FIRST: it reads the topic list and re-runs the one-shot only
    when a topic is actually missing (an unconditional re-run costs ~40 JVM
    starts to change nothing). Verdicts come from the topic list, never from
    the exit code alone. One-shots run detached + `docker wait` so the bound is
    enforceable and no orphan container survives a killed run. No long-lived
    container is restarted or removed; no data volume is touched.

  PHASE 2 (qualification)
    REQUIRED
      Q1  correlation consumer joined its group
      Q2  every netops-router-* consumer group has a live member
      Q3  correlation lag is draining, not strictly increasing
      Q4  vector-aggregator sinks are emitting events
      Q5  vector-router sinks are emitting events
      Q6  no bootstrap-class Kafka errors in correlation / vector-router logs
      Q7  the API answers 200 with a non-empty body
      Q9r OpenSearch cluster status is not RED
    ADVISORY (reported, never fatal)
      Q8  alert-delivery heartbeat is fresh
      Q9  OpenSearch cluster status is present and green/yellow

EXIT CODES
  0  every REQUIRED check PASSED.
  1  at least one REQUIRED check FAILED. The platform is not qualified.
  2  INCOMPLETE — no required check failed, but at least one could not be
     evaluated (e.g. kafka-exporter lives behind the optional "self-monitoring"
     compose profile, so the consumer-group metrics do not exist). "We could
     not check" is not "it passed"; the summary names each one and its remedy.
  3  Precondition failure — docker, the compose project or the repo layout is
     not usable. Nothing was qualified.

CONFIG (all optional; a bare checkout works with the defaults)
  The same env file scripts/stack-watchdog.sh reads is sourced when present:
    $WATCHDOG_ENV  >  scripts/stack-watchdog.env  >  /etc/correlix/stack-watchdog.env
  Recognised keys: COMPOSE_PROJECT_NAME / COMPOSE_PROJECT, APP_URL,
  API_PROBE_URL, APP_CACERT. Additional knobs read from the environment:
    DQ_POLL_INTERVAL       seconds between polls              (default 10)
    DQ_LAG_SAMPLES         correlation lag samples to take    (default 3)
    DQ_LAG_INTERVAL        seconds between lag samples        (default 20)
    DQ_LOG_WINDOW          log window for Q6, docker syntax   (default 20m)
    DQ_LOG_TAIL            max log lines pulled per service   (default 4000)
    DQ_BOOTSTRAP_TIMEOUT   per-bootstrap wall-clock bound     (default 600)
    DQ_DOCKER_TIMEOUT      bound on ordinary docker calls     (default 30)
    DQ_AGG_INSTANCE        Vector aggregator scrape instance  (vector-aggregator:9598)
    DQ_ROUTER_INSTANCE     Vector router scrape instance      (vector-router:9598)
    DQ_HEARTBEAT_MAX_AGE   Q8 freshness bound, seconds        (default 900)
EOF
}

# ---------------------------------------------------------------------------
# Arguments. Parsed BEFORE anything touches docker so --help is free.
# ---------------------------------------------------------------------------
TIMEOUT_SEC=300
PROJECT_OPT=''
RUN_BOOTSTRAP=1

while [ "$#" -gt 0 ]; do
  case "$1" in
    --timeout)
      [ "$#" -ge 2 ] || { warn "--timeout needs a value"; usage >&2; exit 3; }
      TIMEOUT_SEC="$2"; shift 2 ;;
    --timeout=*) TIMEOUT_SEC="${1#*=}"; shift ;;
    --project)
      [ "$#" -ge 2 ] || { warn "--project needs a value"; usage >&2; exit 3; }
      PROJECT_OPT="$2"; shift 2 ;;
    --project=*) PROJECT_OPT="${1#*=}"; shift ;;
    --no-bootstrap) RUN_BOOTSTRAP=0; shift ;;
    -h|--help) usage; exit 0 ;;
    *) warn "unknown argument: $1"; usage >&2; exit 3 ;;
  esac
done

case "$TIMEOUT_SEC" in
  ''|*[!0-9]*) warn "--timeout must be a whole number of seconds, got '$TIMEOUT_SEC'"; exit 3 ;;
esac
[ "$TIMEOUT_SEC" -ge 10 ] || { warn "--timeout must be at least 10s, got ${TIMEOUT_SEC}s"; exit 3; }

# ---------------------------------------------------------------------------
# Optional config file — shared with stack-watchdog.sh so an operator configures
# APP_URL / project name once. Its ABSENCE is normal, not an error (§16.2: the
# script must work on a bare checkout).
# ---------------------------------------------------------------------------
SYSTEM_ENV_FILE="/etc/correlix/stack-watchdog.env"
if [ -n "${WATCHDOG_ENV:-}" ]; then
  ENV_FILE="$WATCHDOG_ENV"
elif [ -f "$SCRIPT_DIR/stack-watchdog.env" ]; then
  ENV_FILE="$SCRIPT_DIR/stack-watchdog.env"
else
  ENV_FILE="$SYSTEM_ENV_FILE"
fi
ENV_FILE_USED=''
# -r, not -f: the packaged install writes /etc/correlix/stack-watchdog.env
# root-owned 0600, so a non-root run finds a file it cannot read. Under
# `set -e` a failed `.` would abort the whole gate with a bare "Permission
# denied"; name it instead and carry on with defaults (§16.1 — the degraded
# condition is reported, not swallowed).
if [ -f "$ENV_FILE" ] && [ ! -r "$ENV_FILE" ]; then
  warn "config file $ENV_FILE exists but is not readable by this user — continuing with built-in defaults."
fi
# shellcheck disable=SC1090  # operator-supplied config path; resolved at runtime, not statically
[ -r "$ENV_FILE" ] && { set -a; . "$ENV_FILE"; set +a; ENV_FILE_USED="$ENV_FILE"; }

POLL_INTERVAL="${DQ_POLL_INTERVAL:-10}"
LAG_SAMPLES="${DQ_LAG_SAMPLES:-3}"
LAG_INTERVAL="${DQ_LAG_INTERVAL:-20}"
LOG_WINDOW="${DQ_LOG_WINDOW:-20m}"
LOG_TAIL="${DQ_LOG_TAIL:-4000}"
# Per-bootstrap ceiling. Lowered 600 -> 240 on 2026-09-03: the old value was
# large enough that a slow-but-progressing bootstrap looked like a hang, and
# three of them in series could hold a deploy for 30 minutes. B2 no longer
# re-runs the expensive loop when the topics are already correct (see below),
# so 240s is generous for the case that genuinely has work to do.
BOOTSTRAP_TIMEOUT="${DQ_BOOTSTRAP_TIMEOUT:-240}"
# B1 only. apply-acls.sh issues 13 kafka-acls.sh --add calls plus two read-backs
# and each one is a JVM start against the mTLS listener (~5-6s measured), so it
# is structurally the slowest bootstrap. It is normally SKIPPED outright by the
# check-first read below; this bound applies only when the matrix really has to
# be (re)applied.
ACL_TIMEOUT="${DQ_ACL_TIMEOUT:-600}"
DOCKER_TIMEOUT="${DQ_DOCKER_TIMEOUT:-30}"
AGG_INSTANCE="${DQ_AGG_INSTANCE:-vector-aggregator:9598}"
ROUTER_INSTANCE="${DQ_ROUTER_INSTANCE:-vector-router:9598}"
HEARTBEAT_MAX_AGE="${DQ_HEARTBEAT_MAX_AGE:-900}"
APP_URL="${APP_URL:-http://localhost:8000/}"
API_PROBE_URL="${API_PROBE_URL:-${APP_URL%/}/admin/version}"
APP_CACERT="${APP_CACERT:-}"
API_PROBE_TIMEOUT="${API_PROBE_TIMEOUT:-10}"

# ---------------------------------------------------------------------------
# Bounded external calls (§16.3/§9). A wedged dockerd must never hang this gate
# — a hung qualifier is indistinguishable from a passing one, which is the
# whole defect class this script exists for.
# ---------------------------------------------------------------------------
if command -v timeout >/dev/null 2>&1; then
  HAVE_TIMEOUT=1
  # `-k`: plain `timeout N cmd` sends SIGTERM and then WAITS FOREVER if the
  # child ignores it. `docker compose` traps SIGTERM to run its own graceful
  # shutdown, so the bound was advisory, not binding — the 2026-09-03 B2 hang
  # ran ~15 minutes against a 600s "timeout". SIGKILL 10s later makes the bound
  # real. Every caller passes the duration as $1, so -k must precede "$@".
  bound() { timeout -k 10s "$@"; }
else
  HAVE_TIMEOUT=0
  warn "'timeout' is not on PATH — docker calls will run UNBOUNDED this run, and PHASE 1 will be skipped (apply-ism.sh waits for OpenSearch in an unbounded loop)."
  bound() { shift; "$@"; }
fi

dkr() { bound "$DOCKER_TIMEOUT" docker "$@"; }

# ---------------------------------------------------------------------------
# GLOBAL DEADLINE (§9/§16.1). A deploy gate that can hang IS the outage it is
# meant to catch: CI blocks, an operator kills it, and the deploy ships
# unqualified — which is worse than not running it, because someone believes it
# ran. Every bound below is additionally clamped to what is left of this budget,
# so the WHOLE script is bounded, not just each call inside it.
#
# Budget = the qualification window (--timeout) + the bootstrap allowance +
# slack for docker itself. DQ_GLOBAL_TIMEOUT overrides it outright.
# ---------------------------------------------------------------------------
GLOBAL_BUDGET="${DQ_GLOBAL_TIMEOUT:-$(( TIMEOUT_SEC + ACL_TIMEOUT + BOOTSTRAP_TIMEOUT * 2 + 120 ))}"
START_EPOCH="$(date +%s)"
GLOBAL_DEADLINE=$(( START_EPOCH + GLOBAL_BUDGET ))

remaining() {  # seconds left in the global budget; never negative
  local left=$(( GLOBAL_DEADLINE - $(date +%s) ))
  [ "$left" -lt 0 ] && left=0
  printf '%s' "$left"
}

# Clamp a requested bound to the global budget. A phase may be given less time
# than it asked for; it may never be given more.
clamp() {  # $1 = requested seconds -> the smaller of it and what remains
  local want="$1" left
  left="$(remaining)"
  if [ "$left" -lt "$want" ]; then printf '%s' "$left"; else printf '%s' "$want"; fi
}

# Returns 0 while there is usable time left. Callers that get non-zero must
# record SKIP REQUIRED — "we ran out of time" is NOT "it passed" (the summary
# turns any required SKIP into exit 2).
have_time() { [ "$(remaining)" -gt 5 ]; }

deadline_skip() {  # $1 = label
  record SKIP REQUIRED "$1" \
    "global ${GLOBAL_BUDGET}s deadline reached before this check could run — raise --timeout / DQ_GLOBAL_TIMEOUT, or fix what is slow. Not evaluated is not passed."
}

COMPOSE_ARGS=()
dc() {  # $1 = wall-clock bound (seconds); rest = docker compose arguments
  local t="$1"; shift
  ( cd "$COMPOSE_DIR" && bound "$t" docker compose ${COMPOSE_ARGS[@]+"${COMPOSE_ARGS[@]}"} "$@" )
}

# ---------------------------------------------------------------------------
# §8/§16.5: nothing this script prints may carry a credential. Log excerpts and
# bootstrap output are external text we did not write, so redact before echoing.
# A redaction FAILURE withholds the text and says so — it never falls through to
# printing the raw bytes.
# ---------------------------------------------------------------------------
redact() {  # reads stdin, writes redacted stdout
  local input out
  input="$(cat)"
  # Rule order matters. The Bearer/Basic rule runs FIRST: the key=value rule
  # below would otherwise consume "Authorization: Bearer" and leave the token
  # itself in the clear. `_` is a valid PRECEDING character so the common
  # CLICKHOUSE_PASSWORD= / INGEST_TOKEN= shapes are caught; a preceding LETTER
  # is not, so the key rule is anchored on a real word boundary
  # ((^|[^A-Za-z0-9])) so that "TopicAuthorizationFailedError: netops.security"
  # keeps its topic name — over-redaction destroys the diagnostic this check
  # exists to hand the operator, and the topic name is not a secret.
  if out="$(printf '%s\n' "$input" | sed -E \
        -e 's/(Bearer|Basic)[[:space:]]+[A-Za-z0-9._~+\/=-]{8,}/<redacted>/Ig' \
        -e 's/(^|[^A-Za-z0-9])(PASS|PASSWORD|PASSWD|SECRET|TOKEN|APIKEY|API_KEY|CREDENTIAL|AUTHORIZATION)([A-Za-z0-9_]*[[:space:]]*[=:][[:space:]]*)[^[:space:],;")]+/\1\2\3<redacted>/Ig' \
        -e 's#(://)[^/[:space:]@]+@#\1<redacted>@#g' 2>&1)"; then
    printf '%s\n' "$out"
  else
    printf '(output withheld: redaction failed — %s)\n' "$(printf '%s' "$out" | tr '\n' ' ' | cut -c1-120)"
  fi
}

# One-line, length-capped, redacted rendering for a detail field.
oneline() { printf '%s' "$1" | redact | tr '\n' ' ' | tr -s ' ' | cut -c1-"${2:-220}"; }

# ---------------------------------------------------------------------------
# Preconditions.
# ---------------------------------------------------------------------------
say ""
say "${C_BOLD}deploy-qualify — post-deploy qualification gate${C_OFF}"
say "  repo:            $REPO_ROOT"
say "  compose dir:     $COMPOSE_DIR"
[ -n "$ENV_FILE_USED" ] && say "  config:          $ENV_FILE_USED"
say "  window:          ${TIMEOUT_SEC}s (poll every ${POLL_INTERVAL}s)"
say ""

if ! command -v docker >/dev/null 2>&1; then
  warn "docker is not on PATH — nothing can be qualified."
  exit 3
fi
if [ ! -f "$COMPOSE_DIR/docker-compose.yml" ]; then
  warn "no docker-compose.yml under $COMPOSE_DIR — run this from a Correlix checkout."
  exit 3
fi
if ! dkr version >/dev/null 2>&1; then
  warn "the docker daemon did not answer within ${DOCKER_TIMEOUT}s — nothing can be qualified."
  exit 3
fi

# Project name. Prefer what the RUNNING containers say over anything we could
# guess: passing the wrong -p silently addresses an empty project, and every
# check would then report "not running" for a perfectly healthy stack.
PROJECT=''
if [ -n "$PROJECT_OPT" ]; then
  PROJECT="$PROJECT_OPT"
elif [ -n "${COMPOSE_PROJECT_NAME:-}" ]; then
  PROJECT="$COMPOSE_PROJECT_NAME"
elif [ -n "${COMPOSE_PROJECT:-}" ]; then
  PROJECT="$COMPOSE_PROJECT"
else
  # `|| DISCOVER_CID=''`: "no container matched" is a legitimate answer here
  # (nothing deployed yet), not an error to abort on — the empty case is
  # handled and named two lines below, never swallowed.
  DISCOVER_CID="$(dc "$DOCKER_TIMEOUT" ps --quiet 2>/dev/null | head -1)" || DISCOVER_CID=''
  if [ -n "$DISCOVER_CID" ]; then
    PROJECT="$(dkr inspect -f '{{index .Config.Labels "com.docker.compose.project"}}' "$DISCOVER_CID" 2>/dev/null)" || PROJECT=''
  fi
  if [ -z "$PROJECT" ]; then
    PROJECT="netops"
    warn "could not discover the compose project from any running container — assuming '$PROJECT'. Pass --project NAME if that is wrong."
  fi
fi
[ -n "$PROJECT_OPT" ] && COMPOSE_ARGS=(-p "$PROJECT_OPT")
say "  compose project: $PROJECT"
say ""

svc_cid() {  # compose service name -> container id (empty when not running)
  # A no-match `docker ps` is the ANSWER ("that service is not running"), which
  # every caller handles explicitly and reports; it is not a failure to abort
  # on. A genuinely broken daemon was already caught by the `docker version`
  # precondition above.
  dkr ps -q --filter "label=com.docker.compose.project=$PROJECT" \
           --filter "label=com.docker.compose.service=$1" 2>/dev/null | head -1 || true
}

KAFKA_CID="$(svc_cid kafka)"
OPENSEARCH_CID="$(svc_cid opensearch)"
VICTORIA_CID="$(svc_cid victoria)"
EXPORTER_CID="$(svc_cid kafka-exporter)"

# ===========================================================================
# PHASE 1 — BOOTSTRAPS
#
# Everything here is documented-idempotent and verified so from the source in
# this repo (not assumed):
#   * apply-acls.sh — its header: "kafka-acls --add of an existing ACL is a
#     no-op and --remove --force of an absent one is too, so re-running
#     converges"; it also reads the matrix BACK and fails loudly on a partial
#     apply. Piped in on stdin rather than exec'd by path, because the
#     /acls/apply-acls.sh mount exists only under compose.tls.yml.
#   * kafka-init — entrypoint uses `kafka-topics.sh --create --if-not-exists`
#     and only ALTERs partitions when the current count is BELOW the target
#     (Kafka cannot shrink), so a second run changes nothing. `restart: "no"`.
#   * opensearch-init — runs apply-ism.sh, whose header states "Idempotent (PUT
#     replaces; add is best-effort)"; the policy/template/snapshot writes are
#     all PUTs. `restart: "no"`.
#
# B1 is piped into the RUNNING broker (docker exec). B2/B3 recreate their own
# `restart: "no"` one-shot container detached (`up -d --no-deps
# --force-recreate`) and then `docker wait` on it under a bound. That is
# deliberately NOT `docker compose run --rm`: `run` creates a SECOND,
# differently-named container that KEEPS RUNNING when the CLI is killed, which
# is exactly the orphan found on the box after the 2026-09-03 hang. --no-deps
# keeps compose from starting anything else.
# ===========================================================================
# ---------------------------------------------------------------------------
# The canonical netops.* topic set. MUST match kafka-init's entrypoint list in
# deployment/docker/docker-compose.yml (and the compose.tls.yml override, which
# restates it). tests/test_deploy_qualify.py pins the two against each other so
# this copy cannot drift silently — a topic added there and missed here would
# make B2 report a green "all topics present" while a lane is unbootstrapped.
# ---------------------------------------------------------------------------
CANONICAL_TOPICS=(
  netops.applogs netops.syslog netops.syslog.control
  netops.flows netops.flows.raw
  netops.snmptrap
  netops.probes netops.metrics netops.cloud netops.app.identities.v1
  netops.controller_events netops.app.edge netops.verification
  netops.cloudlogs netops.cloudcosts netops.deadletter
  netops.wireless_sessions netops.wireless_events
  netops.security netops.bgp
)

# Names the topics that are absent, one line, space separated. Prints the
# broker error and returns 1 when the list cannot be read at all — "I could not
# look" must never be reported as "nothing is missing" (§16.1).
kafka_missing_topics() {
  local t out rc=0 missing='' topic
  local -a cfg=()
  t="$(clamp "$DOCKER_TIMEOUT")"
  [ "$t" -le 5 ] && { printf 'global deadline reached before the topic list could be read'; return 1; }
  # Same connection choice apply-acls.sh makes: the admin properties staged by
  # tls-entrypoint.sh mean the mTLS listener; without them this is a pre-TLS
  # plaintext lab broker.
  if dkr exec "$KAFKA_CID" test -f /tmp/kafka-tls/admin.properties >/dev/null 2>&1; then
    cfg=(--bootstrap-server kafka:9094 --command-config /tmp/kafka-tls/admin.properties)
  else
    cfg=(--bootstrap-server localhost:9092)
  fi
  out="$(bound "$t" docker exec "$KAFKA_CID" /opt/kafka/bin/kafka-topics.sh "${cfg[@]}" --list 2>&1)" || rc=$?
  if [ "$rc" -ne 0 ]; then
    printf '%s' "$(oneline "$out")"
    return 1
  fi
  for topic in "${CANONICAL_TOPICS[@]}"; do
    printf '%s\n' "$out" | grep -qx -- "$topic" || missing="$missing $topic"
  done
  printf '%s' "${missing# }"
  return 0
}

# Is the ACL matrix already applied? Mirrors apply-acls.sh's OWN definition of
# "verified" (it reads the store back and asserts the router grant plus a >=40
# entry floor), so this cannot drift into a weaker claim than the applier makes.
# Prints "<count>" on success; prints the broker error and returns 1 when the
# store cannot be read; returns 2 when it is readable but NOT yet applied.
KAFKA_ACL_FLOOR="${DQ_KAFKA_ACL_FLOOR:-40}"
kafka_acl_applied() {
  local t out rc=0 count
  local -a cfg=()
  t="$(clamp "$DOCKER_TIMEOUT")"
  [ "$t" -le 5 ] && { printf 'global deadline reached before the ACL store could be read'; return 1; }
  cfg=(--bootstrap-server kafka:9094 --command-config /tmp/kafka-tls/admin.properties)
  out="$(bound "$t" docker exec "$KAFKA_CID" /opt/kafka/bin/kafka-acls.sh "${cfg[@]}" --list 2>&1)" || rc=$?
  if [ "$rc" -ne 0 ]; then
    printf '%s' "$(oneline "$out")"
    return 1
  fi
  count="$(printf '%s\n' "$out" | grep -c 'principal=' || true)"
  printf '%s' "$count"
  # Both conditions, exactly as the applier asserts them: a count floor over the
  # whole store AND the load-bearing router grant actually present. A high count
  # with no router grant is a partial matrix, and a partial matrix is an
  # auth-dead bus (the 2026-08-16 incident).
  [ "$count" -ge "$KAFKA_ACL_FLOOR" ] || return 2
  printf '%s\n' "$out" | grep -q 'vector-router' || return 2
  return 0
}

# A killed `docker compose run` leaves its container RUNNING and orphaned
# (`<project>-<service>-run-<hash>`). One was found alive on the box after the
# 2026-09-03 incident. Sweep them, and SAY SO — a silent cleanup would hide the
# very evidence that a previous gate run was killed.
kafka_sweep_orphans() {  # $1 = id, for the log line
  local ids
  ids="$(dkr ps -aq --filter "label=com.docker.compose.project=$PROJECT" \
                    --filter "label=com.docker.compose.service=kafka-init" \
                    --filter "name=-run-" 2>/dev/null || true)"
  [ -z "$ids" ] && return 0
  warn "$1: found orphaned kafka-init 'compose run' container(s) from a previous killed run — removing: $(printf '%s' "$ids" | tr '\n' ' ')"
  printf '%s\n' "$ids" | while IFS= read -r oid; do
    [ -n "$oid" ] || continue
    dkr rm -f "$oid" >/dev/null 2>&1 ||
      warn "$1: could not remove orphan container $oid — remove it by hand before the next run"
  done
  return 0
}

# Run a `restart: "no"` one-shot service to completion, BOUNDED, with no
# orphan. Deliberately NOT `docker compose run --rm`: that creates a second,
# differently-named container which survives the CLI being killed. Starting the
# service container detached and then `docker wait`-ing on it means the bound is
# enforced on a container we can name, stop and report on.
run_oneshot() {  # $1 = id, $2 = label, $3 = compose service, $4.. = TOP-LEVEL compose flags
  local id="$1" label="$2" service="$3"; shift 3
  local t out rc=0 cid wait_rc
  t="$(clamp "$BOOTSTRAP_TIMEOUT")"
  if [ "$t" -le 5 ]; then
    record SKIP REQUIRED "$id $label" \
      "global ${GLOBAL_BUDGET}s deadline reached before the bootstrap could start — not evaluated is not passed"
    return 1
  fi
  # --force-recreate: the one-shot has usually already exited from install; a
  # plain `up -d` would consider it satisfied and do nothing.
  if ! out="$(dc "$t" "$@" up -d --no-deps --force-recreate "$service" 2>&1)"; then
    record FAIL REQUIRED "$id $label" "could not start the one-shot: $(oneline "$out")"
    return 1
  fi
  cid="$(dc "$(clamp "$DOCKER_TIMEOUT")" "$@" ps -aq "$service" 2>/dev/null | head -1)"
  if [ -z "$cid" ]; then
    record FAIL REQUIRED "$id $label" "started the one-shot but could not resolve its container id"
    return 1
  fi
  # `docker wait` prints the container's exit code on stdout and blocks until
  # it stops — the bound is what makes that safe.
  wait_rc="$(bound "$t" docker wait "$cid" 2>&1)" || rc=$?
  if [ "$rc" -ne 0 ]; then
    # Timed out (or wait failed). STOP the container: leaving it running is the
    # orphan bug in a different costume.
    dkr stop -t 5 "$cid" >/dev/null 2>&1 ||
      warn "$id: could not stop container $cid after the bound expired — check it by hand"
    record FAIL REQUIRED "$id $label" "TIMED OUT after ${t}s (container stopped)"
    say "    ---- $id output (redacted) ----"
    dkr logs --tail 40 "$cid" 2>&1 | redact | sed 's/^/    | /' || true
    say "    ---- end $id output ----"
    return 1
  fi
  case "$wait_rc" in
    0) return 0 ;;
    *)
      record FAIL REQUIRED "$id $label" "one-shot exited $wait_rc"
      say "    ---- $id output (redacted) ----"
      dkr logs --tail 40 "$cid" 2>&1 | redact | sed 's/^/    | /' || true
      say "    ---- end $id output ----"
      return 1 ;;
  esac
}

say "${C_BOLD}PHASE 1 — bootstraps${C_OFF}"
if [ "$RUN_BOOTSTRAP" -eq 0 ]; then
  record SKIP ADVISORY "B1 kafka ACL matrix"    "--no-bootstrap was passed"
  record SKIP ADVISORY "B2 kafka-init topics"   "--no-bootstrap was passed"
  record SKIP ADVISORY "B3 opensearch-init ISM" "--no-bootstrap was passed"
elif [ "$HAVE_TIMEOUT" -eq 0 ]; then
  # apply-ism.sh blocks in `until curl -sf .../_cluster/health; do sleep 5; done`
  # with no ceiling of its own. Without `timeout` there is nothing to bound it,
  # and a bootstrap that can hang forever is not a bootstrap this gate may run.
  record SKIP REQUIRED "B1 kafka ACL matrix"    "'timeout' not on PATH — refusing to run an unbounded bootstrap"
  record SKIP REQUIRED "B2 kafka-init topics"   "'timeout' not on PATH — refusing to run an unbounded bootstrap"
  record SKIP REQUIRED "B3 opensearch-init ISM" "'timeout' not on PATH — refusing to run an unbounded bootstrap"
else
  # ---- B1: the Kafka ACL matrix -------------------------------------------
  if ! have_time; then
    deadline_skip "B1 kafka ACL matrix"
  elif [ -z "$KAFKA_CID" ]; then
    record SKIP ADVISORY "B1 kafka ACL matrix" \
      "no running 'kafka' container in project '$PROJECT' — this stack uses an external broker (BROKER_URLS) or the embedded-bus profile is off; the ACL matrix belongs to that broker's operator"
  elif [ ! -r "$ACL_SCRIPT" ]; then
    record FAIL REQUIRED "B1 kafka ACL matrix" \
      "$ACL_SCRIPT is missing or unreadable — the ACL matrix cannot be applied"
  elif ! dkr exec "$KAFKA_CID" test -f /tmp/kafka-tls/admin.properties >/dev/null 2>&1; then
    # NOT applicable, and applying it anyway would be actively harmful: ACLs are
    # PER-RESOURCE, so minting the first ACL on a topic starts denying every
    # principal not named on it. On a plaintext lab broker every client is
    # ANONYMOUS, so that would auth-dead the whole bus (the 2026-08-05 lesson,
    # recorded in apply-acls.sh). ACLs land with TLS phase B, not here.
    record SKIP ADVISORY "B1 kafka ACL matrix" \
      "broker has no /tmp/kafka-tls/admin.properties — pre-TLS plaintext broker. Applying the matrix would create the FIRST ACL on those resources and immediately deny every ANONYMOUS client. Apply it with TLS enablement (install.py TLS phase B / docs/runbooks/tls-enforce-wave.md)."
  else
    # Piped on stdin: /acls/apply-acls.sh is mounted only by compose.tls.yml, so
    # exec'ing that path is a bet on the deployment variant. `sh -s` reads the
    # repo copy — one code path for every layout. Connection defaults are the
    # script's own (admin.properties present => mTLS listener kafka:9094).
    # CHECK FIRST, same lesson as B2 (2026-09-03): re-applying an idempotent
    # matrix costs 13 kafka-acls.sh JVM starts (~240s+ measured, which is what
    # timed this phase out) to change nothing. One read tells us whether there
    # is anything to do, and it uses the applier's own success criteria.
    b1_state=0
    b1_count="$(kafka_acl_applied)" || b1_state=$?
    if [ "$b1_state" -eq 0 ]; then
      record PASS REQUIRED "B1 kafka ACL matrix" \
        "already applied and verified — $b1_count ACL entries live (>= ${KAFKA_ACL_FLOOR} floor) including the load-bearing vector-router grant; the matrix was NOT re-applied (idempotent, and a re-apply costs 13 JVM starts to change nothing)"
    elif [ "$b1_state" -eq 1 ]; then
      record FAIL REQUIRED "B1 kafka ACL matrix" \
        "could not read the ACL store: $b1_count"
    else
    say "  ACL matrix not yet applied ($b1_count entries) — running B1 (piped into container $KAFKA_CID) ..."
    b1_rc=0
    b1_bound="$(clamp "$ACL_TIMEOUT")"
    b1_out="$(bound "$b1_bound" docker exec -i "$KAFKA_CID" sh -s < "$ACL_SCRIPT" 2>&1)" || b1_rc=$?
    if [ "$b1_rc" -eq 0 ]; then
      record PASS REQUIRED "B1 kafka ACL matrix" \
        "applied and verified: $(oneline "$(printf '%s\n' "$b1_out" | grep -i 'matrix applied' | tail -1)" 120)"
    elif [ "$b1_rc" -eq 124 ]; then
      record FAIL REQUIRED "B1 kafka ACL matrix" "TIMED OUT after ${b1_bound}s"
    else
      record FAIL REQUIRED "B1 kafka ACL matrix" "exit $b1_rc: $(oneline "$b1_out")"
    fi
    if [ "$b1_rc" -ne 0 ]; then
      say "    ---- B1 output (redacted) ----"
      printf '%s\n' "$b1_out" | tail -40 | redact | sed 's/^/    | /'
      say "    ---- end B1 output ----"
    fi
    fi
  fi

  # ---- B2: canonical topic pre-creation ------------------------------------
  #
  # 2026-09-03 BUG FIX. This used to be a bare
  #   docker compose run --rm --no-deps -T kafka-init
  # and it appeared to HANG a real deploy (killed at ~15 min). Diagnosis, from
  # measurement rather than inspection:
  #
  #   * kafka-init's entrypoint runs kafka-topics.sh TWICE per topic (--create
  #     then --describe) over 20 canonical topics = 40 JVM starts. On this stack
  #     one such call is ~5 s (JVM boot + mTLS handshake to kafka:9094), so an
  #     unconditional run costs 200 s MINIMUM and considerably more under load.
  #     It was never hung. It was doing 40 JVM starts to discover that all 20
  #     topics already existed.
  #   * `timeout` without `-k` sent SIGTERM, which the compose CLI traps, so the
  #     600 s bound never actually fired (fixed in bound(), above).
  #   * killing the compose CLI does NOT stop the container it started:
  #     `compose run` leaves a `<project>-kafka-init-run-<hash>` container
  #     RUNNING and then orphaned. One was found alive on the box afterwards.
  #
  # The fix is to stop treating "run the bootstrap" as the check. The CHECK is
  # the topic list; the run is only the remedy when the check fails. So:
  #   1. read the topic list (ONE kafka-topics.sh call, ~5 s);
  #   2. if every canonical topic is present -> PASS without re-running. The
  #      entrypoint is documented-idempotent, so re-running it is a guaranteed
  #      no-op that costs minutes;
  #   3. only if something is missing, run the one-shot BOUNDED, then re-read
  #      the list and judge on THAT. The exit code alone is never the verdict —
  #      it is exactly what "up succeeded but nothing works" hides behind.
  if [ -z "$KAFKA_CID" ]; then
    record SKIP ADVISORY "B2 kafka-init topics" \
      "no running 'kafka' container in project '$PROJECT' — topics live on the external broker"
  elif ! have_time; then
    deadline_skip "B2 kafka-init topics"
  else
    kafka_sweep_orphans "B2"
    b2_missing="$(kafka_missing_topics)"; b2_rc=$?
    if [ "$b2_rc" -ne 0 ]; then
      record FAIL REQUIRED "B2 kafka-init topics" \
        "could not read the topic list from the broker: $(oneline "$b2_missing")"
    elif [ -z "$b2_missing" ]; then
      record PASS REQUIRED "B2 kafka-init topics" \
        "all ${#CANONICAL_TOPICS[@]} canonical topics present on the broker — the one-shot is a documented no-op here and was NOT re-run (it costs ~40 JVM starts to change nothing)"
    else
      say "  missing topic(s): $b2_missing"
      say "  running B2 (kafka-init one-shot) ..."
      if run_oneshot "B2" "kafka-init topics" kafka-init --profile embedded-bus; then :; fi
      # Judge on the LIST, not on the exit code — always, including after a
      # "successful" run.
      b2_missing="$(kafka_missing_topics)"; b2_rc=$?
      if [ "$b2_rc" -ne 0 ]; then
        record FAIL REQUIRED "B2 kafka-init topics" \
          "topic list unreadable after the bootstrap ran: $(oneline "$b2_missing")"
      elif [ -n "$b2_missing" ]; then
        record FAIL REQUIRED "B2 kafka-init topics" \
          "still missing after the bootstrap ran: $b2_missing — producers to these topics fail LOUD (broker auto-create is OFF by design)"
      else
        record PASS REQUIRED "B2 kafka-init topics" \
          "bootstrap ran; all ${#CANONICAL_TOPICS[@]} canonical topics now present (verified by kafka-topics --list, not by exit code)"
      fi
    fi
  fi

  # ---- B3: OpenSearch ISM retention + snapshot policy ----------------------
  if [ -z "$OPENSEARCH_CID" ]; then
    record SKIP REQUIRED "B3 opensearch-init ISM" \
      "no running 'opensearch' container in project '$PROJECT' — apply-ism.sh would block waiting for a cluster that is not there"
  elif ! have_time; then
    deadline_skip "B3 opensearch-init ISM"
  else
    # Same one-shot machinery as B2: `compose run` would leak an orphaned
    # container if this gate is killed, and apply-ism.sh has no ceiling of its
    # own (it blocks in `until curl -sf .../_cluster/health`). Unlike B2 there is
    # no cheap "already applied?" read — the ISM/template/snapshot writes are
    # PUTs with no single queryable summary — so this one always runs, bounded.
    # `|| true`: the FAIL verdict is already recorded inside run_oneshot.
    run_oneshot "B3" "opensearch-init ISM" opensearch-init || true
  fi
fi
say ""

# ===========================================================================
# PHASE 2 — QUALIFICATION
# ===========================================================================
# Phase 2's own polling window, clamped to the GLOBAL budget. If Phase 1 ate
# most of the budget, Phase 2 gets what is left rather than extending past it —
# a gate that overruns its stated window is a gate someone will kill, and a
# killed gate is a deploy that ships unqualified.
DEADLINE=$(( $(date +%s) + TIMEOUT_SEC ))
[ "$DEADLINE" -gt "$GLOBAL_DEADLINE" ] && DEADLINE="$GLOBAL_DEADLINE"
PROBE_DETAIL=''

# ---- VictoriaMetrics query plumbing ---------------------------------------
# Established repo idiom (stack-watchdog.sh): docker exec into a container on
# the netops network and speak HTTP to the store. From INSIDE the victoria
# container the address must be 127.0.0.1 — the VM image is minimal and does not
# resolve "localhost" (its own healthcheck uses 127.0.0.1 for the same reason).
urlencode() {  # RFC3986-unreserved passthrough; everything else percent-encoded
  local s="$1" i c out=''
  for (( i = 0; i < ${#s}; i++ )); do
    c="${s:i:1}"
    case "$c" in
      [a-zA-Z0-9.~_-]) out="$out$c" ;;
      *) out="$out$(printf '%%%02X' "'$c")" ;;
    esac
  done
  printf '%s' "$out"
}

vm_body() {  # $1 = PromQL -> raw JSON on stdout
  dkr exec "$VICTORIA_CID" wget -qO- --timeout=8 \
    "http://127.0.0.1:8428/api/v1/query?query=$(urlencode "$1")" 2>&1
}

# On success: the first sample value on stdout, nothing on stderr.
# On failure: the REASON on stderr and a non-zero status. The reason travels on
# stderr rather than in a variable because every caller invokes this inside a
# command substitution — a subshell — where an assignment to a shared variable
# would be discarded and the caller would report a failure with no diagnostic.
# Callers therefore use:  if ! v="$(vm_scalar "$expr" 2>&1)"; then ... "$v" ...
vm_scalar() {  # $1 = PromQL
  local body value
  if ! body="$(vm_body "$1")"; then
    printf 'VictoriaMetrics query transport failed: %s\n' "$(oneline "$body" 140)" >&2
    return 1
  fi
  case "$body" in
    *'"status":"success"'*) : ;;
    *) printf 'VictoriaMetrics returned a non-success response: %s\n' "$(oneline "$body" 140)" >&2
       return 1 ;;
  esac
  value="$(printf '%s' "$body" | sed -n 's/.*"value":\[[^,]*,"\([^"]*\)".*/\1/p' | head -1)"
  if [ -z "$value" ]; then
    printf 'empty result set — the series does not exist (yet)\n' >&2
    return 1
  fi
  printf '%s' "$value"
}

# shellcheck disable=SC2329  # called from probe_q2, which shellcheck cannot see is invoked
vm_labels() {  # $1 = PromQL, $2 = label name -> one distinct label value per line
  local body
  body="$(vm_body "$1")" || return 1
  printf '%s' "$body" | tr ',' '\n' |
    sed -n "s/.*\"$2\":\"\([^\"]*\)\".*/\1/p" | sort -u
}

is_num() { printf '%s' "$1" | grep -qE '^[+-]?([0-9]+\.?[0-9]*|\.[0-9]+)([eE][+-]?[0-9]+)?$'; }
num_ge() { awk -v a="$1" -v b="$2" 'BEGIN { exit !(a + 0 >= b + 0) }'; }
# shellcheck disable=SC2329  # called from probe_vector, which shellcheck cannot see is invoked
num_gt() { awk -v a="$1" -v b="$2" 'BEGIN { exit !(a + 0 >  b + 0) }'; }

# ---- bounded polling -------------------------------------------------------
poll_until() {  # $1 = short label, rest = predicate command (sets PROBE_DETAIL)
  local label="$1"; shift
  local attempt=0 now left
  while :; do
    attempt=$((attempt + 1))
    if "$@"; then return 0; fi
    now="$(date +%s)"
    left=$(( DEADLINE - now ))
    if [ "$left" -le 0 ]; then return 1; fi
    printf '    %s… %s: not satisfied yet (attempt %d, %ds of the window left) — %s%s\n' \
      "$C_SKIP" "$label" "$attempt" "$left" "${PROBE_DETAIL:-no detail}" "$C_OFF"
    if [ "$left" -lt "$POLL_INTERVAL" ]; then sleep "$left"; else sleep "$POLL_INTERVAL"; fi
  done
}

say "${C_BOLD}PHASE 2 — qualification (is the platform doing work?)${C_OFF}"

# The consumer-group metrics (Q1/Q2/Q3) come from kafka-exporter, which lives
# behind the OPTIONAL "self-monitoring" compose profile. Its absence is not a
# pass and not a failure: it is an un-answered question, and it is named as one.
EXPORTER_SKIP_REASON="kafka-exporter is not running in project '$PROJECT'. It lives behind the optional 'self-monitoring' compose profile, so kafka_consumergroup_* does not exist and consumer-group liveness CANNOT be evaluated. Remedy: add self-monitoring to COMPOSE_PROFILES in deployment/docker/.env and redeploy, then re-run this gate."
VICTORIA_SKIP_REASON="no running 'victoria' container in project '$PROJECT' — VictoriaMetrics is the only query surface this gate has, so no metric assertion can be evaluated."

METRICS_OK=1
if [ -z "$VICTORIA_CID" ]; then
  METRICS_OK=0
fi

# --- Q1: correlation consumer joined its group ------------------------------
Q1_EXPR='max(kafka_consumergroup_members{consumergroup="netops-correlation"})'
# shellcheck disable=SC2329  # invoked indirectly by poll_until "$@"
probe_q1() {
  local v
  if ! v="$(vm_scalar "$Q1_EXPR" 2>&1)"; then
    PROBE_DETAIL="$v"
    return 1
  fi
  if ! is_num "$v"; then PROBE_DETAIL="non-numeric value '$v'"; return 1; fi
  if num_ge "$v" 1; then PROBE_DETAIL="$v member(s)"; return 0; fi
  PROBE_DETAIL="group exists but has $v members — the engine has not joined"
  return 1
}
if [ "$METRICS_OK" -eq 0 ]; then
  record SKIP REQUIRED "Q1 correlation consumer joined" "$VICTORIA_SKIP_REASON"
elif [ -z "$EXPORTER_CID" ]; then
  record SKIP REQUIRED "Q1 correlation consumer joined" "$EXPORTER_SKIP_REASON"
elif poll_until "Q1 correlation consumer" probe_q1; then
  record PASS REQUIRED "Q1 correlation consumer joined" \
    "kafka_consumergroup_members{consumergroup=\"netops-correlation\"} = $PROBE_DETAIL"
else
  record FAIL REQUIRED "Q1 correlation consumer joined" \
    "no live member of consumer group 'netops-correlation' within ${TIMEOUT_SEC}s ($PROBE_DETAIL). This is the exact 2026-09-02 shape: the container is 'healthy' and the engine is consuming NOTHING. Check its logs for TopicAuthorizationFailedError / UnknownTopicOrPartitionError — one bad topic abandons the whole subscription."
fi

# --- Q2: every netops-router-* group has a member ---------------------------
# The group list is DISCOVERED from the metric, never hardcoded: the router's
# lane set changes with the pipeline (9 today) and a hardcoded list would go
# stale silently. A count of ZERO discovered groups is itself a failure.
Q2_ALL='kafka_consumergroup_members{consumergroup=~"netops-router-.*"}'
Q2_JOINED='kafka_consumergroup_members{consumergroup=~"netops-router-.*"} >= 1'
Q2_FOUND=0
Q2_LIVE=0
Q2_MISSING=''
# shellcheck disable=SC2329  # invoked indirectly by poll_until "$@"
probe_q2() {
  local all joined
  if ! all="$(vm_labels "$Q2_ALL" consumergroup)"; then
    PROBE_DETAIL="VictoriaMetrics query failed for $Q2_ALL"
    return 1
  fi
  if [ -z "$all" ]; then
    Q2_FOUND=0; Q2_LIVE=0; Q2_MISSING=''
    PROBE_DETAIL="no netops-router-* consumer group exists at all"
    return 1
  fi
  joined="$(vm_labels "$Q2_JOINED" consumergroup)" || joined=''
  Q2_FOUND="$(printf '%s\n' "$all" | grep -c .)"
  if [ -n "$joined" ]; then Q2_LIVE="$(printf '%s\n' "$joined" | grep -c .)"; else Q2_LIVE=0; fi
  Q2_MISSING="$(comm -23 <(printf '%s\n' "$all") <(printf '%s\n' "$joined") | tr '\n' ' ')"
  if [ "$Q2_LIVE" -gt 0 ] && [ "$Q2_LIVE" -eq "$Q2_FOUND" ]; then
    PROBE_DETAIL="$Q2_LIVE/$Q2_FOUND groups have a live member"
    return 0
  fi
  PROBE_DETAIL="$Q2_LIVE/$Q2_FOUND groups joined; still memberless: ${Q2_MISSING:-<none>}"
  return 1
}
if [ "$METRICS_OK" -eq 0 ]; then
  record SKIP REQUIRED "Q2 router consumers joined" "$VICTORIA_SKIP_REASON"
elif [ -z "$EXPORTER_CID" ]; then
  record SKIP REQUIRED "Q2 router consumers joined" "$EXPORTER_SKIP_REASON"
elif poll_until "Q2 router consumers" probe_q2; then
  record PASS REQUIRED "Q2 router consumers joined" \
    "discovered $Q2_FOUND netops-router-* group(s), all $Q2_LIVE with a live member"
elif [ "$Q2_FOUND" -eq 0 ]; then
  record FAIL REQUIRED "Q2 router consumers joined" \
    "ZERO netops-router-* consumer groups exist. The router has never joined the bus — see the 2026-08-16 incident (empty KRaft ACL store after a data/kafka wipe left vector-router auth-dead for 80 minutes with every healthcheck green)."
else
  record FAIL REQUIRED "Q2 router consumers joined" \
    "only $Q2_LIVE of $Q2_FOUND discovered netops-router-* groups have a live member after ${TIMEOUT_SEC}s. Memberless: ${Q2_MISSING:-<none>}"
fi

# --- Q3: correlation lag is DRAINING, not merely present --------------------
# "Lag exists" proves nothing; a frozen or climbing lag is the signature of a
# consumer that joined and then stopped making progress. Sample repeatedly and
# fail only on a STRICTLY increasing series (a flat or falling series is fine,
# and so is a legitimately idle 0).
Q3_EXPR='sum(kafka_consumergroup_lag_sum{consumergroup="netops-correlation"})'
if [ "$METRICS_OK" -eq 0 ]; then
  record SKIP REQUIRED "Q3 correlation lag draining" "$VICTORIA_SKIP_REASON"
elif [ -z "$EXPORTER_CID" ]; then
  record SKIP REQUIRED "Q3 correlation lag draining" "$EXPORTER_SKIP_REASON"
else
  lag_samples=''
  lag_err=''
  taken=0
  while [ "$taken" -lt "$LAG_SAMPLES" ]; do
    if s="$(vm_scalar "$Q3_EXPR" 2>&1)" && is_num "$s"; then
      lag_samples="${lag_samples:+$lag_samples }$s"
      taken=$((taken + 1))
      say "    · Q3 lag sample $taken/$LAG_SAMPLES: $s"
    else
      lag_err="${s:-no diagnostic emitted}"
      break
    fi
    [ "$taken" -lt "$LAG_SAMPLES" ] || break
    remaining=$(( DEADLINE - $(date +%s) ))
    if [ "$remaining" -le 0 ]; then
      # A TREND needs two points. If an earlier assertion spent the whole
      # window, stopping here would report "could not evaluate" for a check
      # that is one sample away from an answer. Allow exactly one extra
      # interval so a second sample is always taken — the overrun is bounded
      # by DQ_LAG_INTERVAL and by nothing else.
      if [ "$taken" -ge 2 ]; then break; fi
      say "    · Q3: window closed after $taken sample(s); taking one more ${LAG_INTERVAL}s apart so a trend can be judged"
      sleep "$LAG_INTERVAL"
    elif [ "$remaining" -lt "$LAG_INTERVAL" ]; then
      sleep "$remaining"
    else
      sleep "$LAG_INTERVAL"
    fi
  done

  if [ "$taken" -eq 0 ]; then
    record SKIP REQUIRED "Q3 correlation lag draining" \
      "no lag sample could be read: ${lag_err:-unknown}"
  elif [ "$taken" -lt 2 ]; then
    record SKIP REQUIRED "Q3 correlation lag draining" \
      "only $taken lag sample was taken (the window closed first) — a trend needs at least two. Raise --timeout or lower DQ_LAG_INTERVAL."
  else
    lag_first="${lag_samples%% *}"
    lag_last="${lag_samples##* }"
    if awk -v s="$lag_samples" 'BEGIN {
          n = split(s, a, " ");
          if (n < 2) exit 1;
          for (i = 2; i <= n; i++) if (!(a[i] + 0 > a[i-1] + 0)) exit 1;
          exit 0 }'; then
      record FAIL REQUIRED "Q3 correlation lag draining" \
        "lag is STRICTLY INCREASING across $taken samples: [$lag_samples] (first=$lag_first last=$lag_last). The engine is falling behind, not draining."
    else
      record PASS REQUIRED "Q3 correlation lag draining" \
        "$taken samples, first=$lag_first last=$lag_last (not strictly increasing): [$lag_samples]"
    fi
  fi
fi

# --- Q4 / Q5: the Vector tiers are actually EMITTING ------------------------
# component_kind="sink" is the output side: a tier that receives but emits
# nothing is exactly the silent stall this gate exists to catch. The instance
# label is the scrape target from src/config/vmscrape.yml's 'vector' job.
vector_emit_check() {  # $1 = check id, $2 = human label, $3 = instance label
  local id="$1" label="$2" inst="$3" expr
  expr="sum(increase(vector_component_sent_events_total{component_kind=\"sink\",instance=\"$inst\"}[5m]))"
  # shellcheck disable=SC2329  # invoked indirectly by poll_until "$@"
  probe_vector() {
    local v
    if ! v="$(vm_scalar "$expr" 2>&1)"; then PROBE_DETAIL="$v"; return 1; fi
    if ! is_num "$v"; then PROBE_DETAIL="non-numeric value '$v'"; return 1; fi
    if num_gt "$v" 0; then PROBE_DETAIL="$v events in the last 5m"; return 0; fi
    PROBE_DETAIL="0 events sent by any sink in the last 5m"
    return 1
  }
  if [ "$METRICS_OK" -eq 0 ]; then
    record SKIP REQUIRED "$id $label" "$VICTORIA_SKIP_REASON"
  elif poll_until "$id $label" probe_vector; then
    record PASS REQUIRED "$id $label" "instance=$inst — $PROBE_DETAIL"
  else
    record FAIL REQUIRED "$id $label" \
      "instance=$inst emitted NOTHING from any sink within ${TIMEOUT_SEC}s ($PROBE_DETAIL). A running-but-silent Vector tier is a dead pipeline with a green healthcheck."
  fi
}
vector_emit_check "Q4" "vector-aggregator emitting" "$AGG_INSTANCE"
vector_emit_check "Q5" "vector-router emitting"     "$ROUTER_INSTANCE"

# --- Q6: no bootstrap-class Kafka errors in the logs ------------------------
# THE direct regression guard for both incidents. Evaluated once, at the end of
# the window, so it covers everything that happened during qualification. It is
# deliberately NOT a poll: these errors do not "clear" — a subscription
# abandoned at bootstrap stays abandoned until the process restarts.
Q6_PATTERN='TopicAuthorizationFailedError|UnknownTopicOrPartitionError|TOPIC_AUTHORIZATION_FAILED|UNKNOWN_TOPIC_OR_PARTITION|GroupAuthorizationFailed'
q6_rc=0
q6_logs="$(dc "$DOCKER_TIMEOUT" logs --no-color --since "$LOG_WINDOW" --tail "$LOG_TAIL" \
             correlation vector-router 2>&1)" || q6_rc=$?
if [ "$q6_rc" -ne 0 ]; then
  record SKIP REQUIRED "Q6 no bootstrap-class Kafka errors" \
    "could not read logs for correlation/vector-router (exit $q6_rc): $(oneline "$q6_logs" 180)"
else
  # `|| true` neutralizes grep's documented exit-1-on-no-match ONLY; the
  # no-match case is the PASS branch immediately below, not a swallowed error.
  q6_hits="$(printf '%s\n' "$q6_logs" | grep -E "$Q6_PATTERN" || true)"
  if [ -z "$q6_hits" ]; then
    record PASS REQUIRED "Q6 no bootstrap-class Kafka errors" \
      "none of TopicAuthorizationFailedError / UnknownTopicOrPartitionError / TOPIC_AUTHORIZATION_FAILED / UNKNOWN_TOPIC_OR_PARTITION / GroupAuthorizationFailed in the last $LOG_WINDOW"
  else
    q6_count="$(printf '%s\n' "$q6_hits" | grep -c .)"
    record FAIL REQUIRED "Q6 no bootstrap-class Kafka errors" \
      "$q6_count matching line(s) in the last $LOG_WINDOW — a Kafka authorization/topic fault at subscribe() abandons the ENTIRE subscription, not just the offending lane (2026-09-02, 2026-08-16)."
    say "    ---- first 5 matching log lines (redacted, truncated) ----"
    printf '%s\n' "$q6_hits" | head -5 | redact | cut -c1-240 | sed 's/^/    | /'
    say "    ---- end matching log lines ----"
  fi
fi

# --- Q7: the API is SERVING ------------------------------------------------
# Same convention as stack-watchdog.sh: a 200 with a NON-EMPTY body. An empty
# 200 is not a serving api, and /admin/version is the one route only the api
# binary can answer (nginx `location /` falls through to the SPA).
# shellcheck disable=SC2329  # invoked indirectly by poll_until "$@"
probe_q7() {
  local out rc=0 code body
  if ! command -v curl >/dev/null 2>&1; then
    PROBE_DETAIL="curl is not on PATH"
    return 1
  fi
  out="$(curl -sS -m "$API_PROBE_TIMEOUT" ${APP_CACERT:+--cacert "$APP_CACERT"} \
          -w '\nHTTP:%{http_code}' "$API_PROBE_URL" 2>&1)" || rc=$?
  code="$(printf '%s' "$out" | sed -n 's/.*HTTP:\([0-9]*\).*/\1/p' | tail -1)"
  body="$(printf '%s' "$out" | sed 's/HTTP:[0-9]*//' | tr -d '[:space:]')"
  if [ "$rc" -eq 0 ] && [ "${code:-}" = "200" ] && [ -n "$body" ]; then
    PROBE_DETAIL="HTTP 200 with a non-empty body"
    return 0
  fi
  if [ -z "$body" ] && [ "${code:-}" = "200" ]; then
    PROBE_DETAIL="HTTP 200 but an EMPTY body — not a serving api"
  else
    PROBE_DETAIL="curl rc=$rc HTTP=${code:-none}: $(oneline "$out" 140)"
  fi
  return 1
}
if poll_until "Q7 api serving" probe_q7; then
  record PASS REQUIRED "Q7 api serving" "$API_PROBE_URL — $PROBE_DETAIL"
else
  record FAIL REQUIRED "Q7 api serving" "$API_PROBE_URL — $PROBE_DETAIL"
fi

# --- Q8 (ADVISORY): the alert DELIVERY chain is alive -----------------------
# netops_alert_webhook_heartbeat_timestamp_seconds is exposed by the api and
# scraped as job 'netops-api'. A fresh value proves vmalert evaluated a rule AND
# delivered it to the api webhook — the whole chain, not just the evaluator.
# The endpoint is landing concurrently, so ABSENT is reported as absent and
# never fails the run.
# The gauge is 0 when no heartbeat has EVER been received (alertwebhook/
# metrics.go: "0 = never"), so the raw value is read first — `time() - 0` would
# otherwise be rendered as a 56-year-old delivery, which is noise, not a fact.
Q8_TS_EXPR='max(netops_alert_webhook_heartbeat_timestamp_seconds)'
Q8_AGE_EXPR='time() - max(netops_alert_webhook_heartbeat_timestamp_seconds)'
if [ "$METRICS_OK" -eq 0 ]; then
  record SKIP ADVISORY "Q8 alert delivery heartbeat" "$VICTORIA_SKIP_REASON"
elif ! q8_ts="$(vm_scalar "$Q8_TS_EXPR" 2>&1)" || ! is_num "$q8_ts"; then
  record ADVISORY ADVISORY "Q8 alert delivery heartbeat" \
    "metric netops_alert_webhook_heartbeat_timestamp_seconds is ABSENT (${q8_ts:-no series}). The api endpoint that exposes it is being landed concurrently; on a build that predates it this is expected and is NOT a failure."
elif ! num_gt "$q8_ts" 0; then
  record ADVISORY ADVISORY "Q8 alert delivery heartbeat" \
    "the metric exists but reads 0 — NO heartbeat has ever reached the api webhook. vmalert may be evaluating rules that are never delivered. Advisory only."
elif ! q8_age="$(vm_scalar "$Q8_AGE_EXPR" 2>&1)" || ! is_num "$q8_age"; then
  record ADVISORY ADVISORY "Q8 alert delivery heartbeat" \
    "heartbeat timestamp is present but its age could not be computed (${q8_age:-no diagnostic}). Advisory only."
else
  q8_int="${q8_age%%.*}"
  case "$q8_int" in ''|*[!0-9-]*) q8_int=0 ;; esac
  if num_ge "$HEARTBEAT_MAX_AGE" "$q8_age"; then
    record ADVISORY ADVISORY "Q8 alert delivery heartbeat" \
      "fresh — last webhook delivery ${q8_int}s ago (bound ${HEARTBEAT_MAX_AGE}s): vmalert evaluated a rule and the api received it"
  else
    record ADVISORY ADVISORY "Q8 alert delivery heartbeat" \
      "STALE — last webhook delivery ${q8_int}s ago, older than the ${HEARTBEAT_MAX_AGE}s bound. Alert DELIVERY (not just evaluation) may be broken. Advisory only."
  fi
fi

# --- Q9 (ADVISORY unless RED): OpenSearch cluster status --------------------
# Published by the vector-aggregator's cluster-health scrape. 0 green, 1 yellow,
# 2 red. Red is a real failure; absent is advisory.
if [ "$METRICS_OK" -eq 0 ]; then
  record SKIP ADVISORY "Q9 opensearch cluster status" "$VICTORIA_SKIP_REASON"
elif q9="$(vm_scalar 'max(opensearch_cluster_status)' 2>&1)" && is_num "$q9"; then
  if num_ge "$q9" 2; then
    record FAIL REQUIRED "Q9 opensearch cluster status" \
      "opensearch_cluster_status = $q9 (RED) — unassigned primaries; the search tier is losing or refusing writes."
  elif num_ge "$q9" 1; then
    record ADVISORY ADVISORY "Q9 opensearch cluster status" \
      "opensearch_cluster_status = $q9 (YELLOW) — replicas unassigned. Expected on a single-node appliance with OPENSEARCH_REPLICAS>0; investigate otherwise."
  else
    record ADVISORY ADVISORY "Q9 opensearch cluster status" "opensearch_cluster_status = $q9 (GREEN)"
  fi
else
  record ADVISORY ADVISORY "Q9 opensearch cluster status" \
    "metric opensearch_cluster_status is ABSENT (${q9:-no series}) — cluster health is UNKNOWN, not green. Advisory only."
fi

# ===========================================================================
# FINAL BLOCK — every check, with its verdict. A degraded run must be at least
# as visible as the condition it checks for (§16.1).
# ===========================================================================
say ""
say "${C_BOLD}================ deploy-qualify SUMMARY ================${C_OFF}"
say "  project '$PROJECT' · window ${TIMEOUT_SEC}s · $(date -Is)"
say ""
for row in ${RESULTS[@]+"${RESULTS[@]}"}; do
  verdict="${row%%$'\t'*}"; rest="${row#*$'\t'}"
  class="${rest%%$'\t'*}";  rest="${rest#*$'\t'}"
  label="${rest%%$'\t'*}";  detail="${rest#*$'\t'}"
  case "$verdict" in
    PASS)     printf '  %s✓ PASS%s      [%s] %s\n' "$C_OK"   "$C_OFF" "$class" "$label" ;;
    FAIL)     printf '  %s✗ FAIL%s      [%s] %s\n' "$C_BAD"  "$C_OFF" "$class" "$label" ;;
    SKIP)     printf '  %s— SKIPPED%s   [%s] %s\n' "$C_SKIP" "$C_OFF" "$class" "$label" ;;
    ADVISORY) printf '  %s· ADVISORY%s  [%s] %s\n' "$C_ADV"  "$C_OFF" "$class" "$label" ;;
  esac
  printf '                  %s\n' "$(printf '%s' "$detail" | cut -c1-300)"
done
say ""
say "  passed: $N_PASS · failed: $N_FAIL · skipped(required): $N_SKIP_REQ · skipped(advisory): $N_SKIP_ADV · advisory: $N_ADV"
say ""

if [ "$N_FAIL" -gt 0 ]; then
  printf '%s  RESULT: NOT QUALIFIED — %d required check(s) FAILED.%s\n' "$C_BAD" "$N_FAIL" "$C_OFF" >&2
  printf '%s  The stack may report every container healthy and still be doing no work.%s\n' "$C_BAD" "$C_OFF" >&2
  printf '%s  Do not treat this deploy as complete.%s\n' "$C_BAD" "$C_OFF" >&2
  exit 1
fi
if [ "$N_SKIP_REQ" -gt 0 ]; then
  printf '%s  RESULT: INCOMPLETE — %d required check(s) could not be evaluated.%s\n' "$C_SKIP" "$N_SKIP_REQ" "$C_OFF" >&2
  printf '%s  Nothing failed, but "we could not check" is not "it passed" — that%s\n' "$C_SKIP" "$C_OFF" >&2
  printf '%s  conflation is precisely what made both incidents invisible. See each%s\n' "$C_SKIP" "$C_OFF" >&2
  printf '%s  SKIPPED line above for the reason and its remedy.%s\n' "$C_SKIP" "$C_OFF" >&2
  exit 2
fi
printf '%s  RESULT: QUALIFIED — every required check passed. The engines are%s\n' "$C_OK" "$C_OFF"
printf '%s  consuming and producing, not merely running.%s\n' "$C_OK" "$C_OFF"
exit 0
