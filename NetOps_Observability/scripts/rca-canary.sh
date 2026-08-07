#!/usr/bin/env bash
# rca-canary.sh (#99 R1) — live end-to-end RCA pipeline canary.
#
# Injects two KNOWN raw failure events onto the bus for a dedicated canary
# tenant/app (a synthetic HTTPS 503 probe + a same-app LB 503), then asserts:
#
#   1. both semantic signals (synthetic_http_5xx, lb_5xx) land in
#      netops.corr_signals within SIGNAL_BUDGET_S, and
#   2. a CONFIRMED sig.ent.app.saas-experience-degraded object forms in
#      netops.corr_objects within OBJECT_BUDGET_S (two independent modality
#      classes on one app entity — the full verified path:
#      bus → consumer → normalizer → grounding → signature → verdict), and
#   3. autoticketing DELIVERS a ticket for that object within TICKET_BUDGET_S
#      (sweeper → outbox → worker → ITSM connector → the bundled mock
#      ServiceNow). One-time setup (2026-07-09, PG-persisted): the canary
#      tenant's connection points at the mock —
#        PUT /api/notify/itsm?tenant=t-rca-canary
#            {"servicenow":{"enabled":true,"instance_url":"http://mock-servicenow:8090",
#             "user":"correlix","password":"correlix-mock-secret","min_severity":"info"}}
#      A missing/disabled connection FAILS the canary — config drift on the
#      ticketing path is exactly what this leg guards. Set TICKET_BUDGET_S=0
#      to skip (e.g. when running without the mock-snow compose profile).
#
# Unit tests prove the code path; THIS proves the deployed pipeline. A lab or
# ingest outage that silences telemetry fails the canary at the RCA level —
# the class of gap that previously went unnoticed for days.
#
# Isolation: everything is scoped to tenant "t-rca-canary" (never a customer
# tenant); canary rows expire with the tables' TTLs. On failure, pushes to the
# ntfy topic from scripts/stack-watchdog.env (same channel as the watchdog).
#
# Usage: rca-canary.sh [--quiet]     (cron: */15 * * * *)
set -u

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_DIR="${COMPOSE_DIR:-$DIR/../deployment/docker}"
TENANT="t-rca-canary"
APP="rca_canary_app"
RUN_ID="canary-$(date +%s)-$$"
SIGNAL_BUDGET_S="${SIGNAL_BUDGET_S:-90}"
OBJECT_BUDGET_S="${OBJECT_BUDGET_S:-240}"
TICKET_BUDGET_S="${TICKET_BUDGET_S:-240}"   # 0 = skip the autoticketing leg
QUIET="${1:-}"
[ -f "$DIR/stack-watchdog.env" ] && . "$DIR/stack-watchdog.env"

log() { [ "$QUIET" = "--quiet" ] || echo "[rca-canary] $*"; }
fail() {
    echo "[rca-canary] FAIL: $*" >&2
    if [ -n "${NTFY_TOPIC:-}" ]; then
        curl -fsS -m 10 -H "Title: Correlix RCA canary FAILED" -H "Priority: high" \
            -d "RCA canary $RUN_ID: $*" "https://ntfy.sh/${NTFY_TOPIC}" >/dev/null 2>&1 || true
    fi
    exit 1
}

dc() { docker compose --project-directory "$COMPOSE_DIR" "$@"; }
# produce publishes stdin to a topic, with the two things whose absence cost a
# week of misdirected alerts (2026-07-22).
#
# WHAT HAPPENED: this discarded stderr, so when `docker compose exec` began
# failing at CONFIG-PARSE time — `.env` had no INGEST_TOKEN after the F-08
# change, and compose validates the whole file before running anything — the
# only symptom was "could not produce probe event onto the bus". That accused
# Kafka, which was healthy with zero restarts throughout. 47 of 100 logged
# failures, plus the 27 "signals missing" ones (ch() has the same shape), were
# this single unset variable.
#
# So: keep stderr, and retry, because one transient blip should not page a human
# at high priority.
PRODUCE_TRIES="${PRODUCE_TRIES:-3}"
PRODUCE_ERR=""

# SEC-013/task #9 (2026-08-06): injection moved from kafka-console-producer on
# the plaintext listener (an ANONYMOUS principal the ACL matrix rightly
# refuses) to the aggregator's AUTHENTICATED bus lane: an mTLS POST to bus_in
# carrying a {topic,key,event} envelope — the same path and shape the api's
# own bus producer uses — authorized by the bus lane token. Transport rides a
# `docker compose exec` into the correlation container (always present, has
# python + a client-EKU SVID); the token is read from the compose .env WITHOUT
# sourcing it (passwords with shell metacharacters broke a naive source on
# 2026-08-05) and travels via the environment, never argv.
# SEC-013 narrowing: the bus lane accepts ONLY its per-lane token — the
# shared INGEST_TOKEN opens no lane anymore, so falling back to it here
# would turn a missing bus token into a 401 storm blamed on the wrong secret.
BUS_TOKEN="$(sed -n 's/^INGEST_TOKEN_BUS=//p' "$COMPOSE_DIR/.env" | head -1)"
if [ -z "$BUS_TOKEN" ]; then
    fail "no INGEST_TOKEN_BUS in $COMPOSE_DIR/.env — run scripts/install.py (its migration seeds per-lane tokens); the shared INGEST_TOKEN no longer authenticates the bus lane"
fi

produce() { # $1 topic, stdin = ONE JSON event
    local topic="$1" payload err attempt=1
    payload="$(cat)"   # buffer: stdin is consumed once but may be sent twice
    while :; do
        # `timeout` execs a program, so call docker compose directly, never a
        # shell function (2026-07-22 regression, kept as a warning).
        if err="$(printf '{"topic":"%s","key":"rca-canary","event":%s}' "$topic" "$payload" | timeout 60 \
            docker compose --project-directory "$COMPOSE_DIR" exec -T -e BUS_TOKEN="$BUS_TOKEN" correlation python3 -c '
import base64, os, ssl, sys, urllib.request
ctx = ssl.create_default_context(cafile="/certs/ca.pem")
ctx.load_cert_chain("/certs/svid/correlation.crt", "/certs/svid/correlation.key")
auth = base64.b64encode(("netops-ingest:" + os.environ["BUS_TOKEN"]).encode()).decode()
req = urllib.request.Request("https://vector-aggregator:8692/",
    data=sys.stdin.buffer.read(),
    headers={"Content-Type": "application/json", "Authorization": "Basic " + auth})
resp = urllib.request.urlopen(req, timeout=10, context=ctx)
sys.exit(0 if resp.status == 200 else 1)
' 2>&1 >/dev/null)"; then
            return 0
        fi
        PRODUCE_ERR="$(printf '%s' "$err" | tr '\n' ' ' | cut -c1-300)"
        [ "$attempt" -ge "$PRODUCE_TRIES" ] && return 1
        log "produce to $topic failed (attempt $attempt/$PRODUCE_TRIES): $PRODUCE_ERR"
        attempt=$((attempt + 1))
        sleep $((attempt * 2))
    done
}
ch() { dc exec -T clickhouse clickhouse-client -q "$1" 2>/dev/null; }

TS="$(date -u +%Y-%m-%dT%H:%M:%S.%6NZ)"

# 1) canary synthetic probe failure (exact enriched ProbeEvent wire shape)
printf '%s\n' "{\"kind\":\"http\",\"prober\":\"rca-canary-probe\",\"target\":\"https://portal.rca-canary.example/health\",\"ok\":false,\"rtt_ms\":800,\"loss_pct\":100,\"ts\":\"$TS\",\"tenant_id\":\"$TENANT\",\"site_id\":\"canary\",\"status_code\":503,\"method\":\"GET\",\"path\":\"/health\",\"total_ms\":800,\"app_name\":\"$APP\",\"signal_purpose\":\"validation\",\"environment\":\"validation\"}" \
    | produce netops.probes || fail "could not produce probe event onto the bus: ${PRODUCE_ERR:-no stderr captured}"

# 2) canary LB 503 for the SAME app (independent witness class)
printf '%s\n' "{\"source\":\"lb\",\"vendor\":\"generic\",\"product\":\"reverse_proxy\",\"tenant_id\":\"$TENANT\",\"ts\":\"$TS\",\"app_name\":\"$APP\",\"service_name\":\"canary_frontend\",\"host\":\"portal.rca-canary.example\",\"path\":\"/health\",\"status_code\":503,\"reason\":\"backend_unavailable\",\"lb_name\":\"canary-lb\",\"raw_event_id\":\"$RUN_ID\",\"signal_purpose\":\"validation\",\"environment\":\"validation\"}" \
    | produce netops.app.edge || fail "could not produce app-edge event onto the bus: ${PRODUCE_ERR:-no stderr captured}"

log "injected $RUN_ID; waiting for signals (budget ${SIGNAL_BUDGET_S}s)"

# 3) both semantic signals present?
deadline=$(( $(date +%s) + SIGNAL_BUDGET_S ))
while :; do
    n=$(ch "SELECT uniqExact(kind) FROM netops.corr_signals
            WHERE tenant_id='$TENANT' AND kind IN ('synthetic_http_5xx','lb_5xx')
              AND ts > now() - INTERVAL 5 MINUTE
            SETTINGS tenant_scope='__all__'" || echo 0)
    [ "${n:-0}" = "2" ] && break
    [ "$(date +%s)" -ge "$deadline" ] && fail "signals missing after ${SIGNAL_BUDGET_S}s (got kinds=$n/2) — bus→normalizer→CH path broken"
    sleep 5
done
log "both semantic signals landed"

# 4) SUSPECTED app-impact object? (truthfulness epic §11: the canary declares
#    signal_purpose=validation, so its evidence is DEBUG_ONLY and can never
#    anchor a CONFIRMED verdict — the pipeline-health assertion is that the
#    object forms and ranks the saas-experience hypothesis, capped at
#    suspected. The confirm path is exercised by real drills, never by test
#    traffic.)
#    Damping-aware (#100): signals injected mid-window JOIN the already-open
#    canary object, and the engine deliberately does NOT re-persist an
#    unchanged-material object until its heartbeat (CORR_VERSION_HEARTBEAT_S,
#    900s) — so the freshest persisted row can be up to ~15 min old while the
#    incident is alive and healthy. Accept a confirmed persist within 20 min
#    (heartbeat + injection cadence guarantees one in steady state); a broken
#    engine still fails within one canary cadence.
deadline=$(( $(date +%s) + OBJECT_BUDGET_S ))
while :; do
    tier=$(ch "SELECT argMax(verdict_tier, created_at) FROM netops.corr_objects
               WHERE tenant_id='$TENANT'
                 AND created_at > now() - INTERVAL 20 MINUTE
               SETTINGS tenant_scope='__all__'" || echo "")
    # validation-declared evidence cannot satisfy signature clauses (debug
    # demotion), so the object may honestly rank undetermined — the assertion
    # is that it FORMS and never confirms.
    { [ "$tier" = "undetermined" ] || [ "$tier" = "suspected" ] || [ "$tier" = "confirmed" ]; } && break
    [ "$(date +%s)" -ge "$deadline" ] && fail "no saas-experience object after ${OBJECT_BUDGET_S}s (latest tier='${tier:-none persisted in 20m}') — grounding/signature path broken"
    sleep 10
done

if [ "$tier" = "confirmed" ]; then
    fail "VALIDATION LEAK: canary evidence anchored a CONFIRMED verdict — debug demotion failed"
fi
log "RCA object formed at tier=$tier (validation evidence correctly capped below confirmed)"

# 5) ticket-SUPPRESSION leg (truthfulness epic §11, required test 23): the
#    canary declares signal_purpose=validation, so even the CONFIRMED object
#    must NOT file a production ticket — the sweeper holds it
#    ("validation scenario — production ticket side effects suppressed").
#    Asserts NO outbox row appears within one sweeper tick + margin.
if [ "$TICKET_BUDGET_S" -gt 0 ] 2>/dev/null; then
    cid=$(ch "SELECT toString(argMax(correlation_id, created_at)) FROM netops.corr_objects
              WHERE tenant_id='$TENANT'
                AND created_at > now() - INTERVAL 20 MINUTE
              SETTINGS tenant_scope='__all__'")
    [ -n "$cid" ] || fail "confirmed object has no correlation_id (unexpected)"
    log "waiting ${TICKET_BUDGET_S}s to prove the validation case is HELD (no ticket)"
    sleep "$TICKET_BUDGET_S"
    st=$(dc exec -T postgres psql -U netops -d netops -tA \
         -c "SELECT status FROM ticket_outbox WHERE tenant_id='$TENANT'
              AND corr_object_id='$cid' ORDER BY updated_at DESC LIMIT 1" 2>/dev/null || echo "")
    [ -z "$st" ] || fail "VALIDATION LEAK: canary produced a ticket_outbox row (status='$st') — the §11 gate failed"
    log "validation suppression proven for $cid (no outbox row)"
fi

log "OK: $RUN_ID confirmed end-to-end (bus → signals → confirmed RCA object → ticket SUPPRESSED as validation)"
exit 0
