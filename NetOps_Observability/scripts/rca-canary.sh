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
produce() { # $1 topic, stdin = one JSON event per line
    dc exec -T kafka /opt/kafka/bin/kafka-console-producer.sh \
        --bootstrap-server kafka:9092 --topic "$1" >/dev/null 2>&1
}
ch() { dc exec -T clickhouse clickhouse-client -q "$1" 2>/dev/null; }

TS="$(date -u +%Y-%m-%dT%H:%M:%S.%6NZ)"

# 1) canary synthetic probe failure (exact enriched ProbeEvent wire shape)
printf '%s\n' "{\"kind\":\"http\",\"prober\":\"rca-canary-probe\",\"target\":\"https://portal.rca-canary.example/health\",\"ok\":false,\"rtt_ms\":800,\"loss_pct\":100,\"ts\":\"$TS\",\"tenant_id\":\"$TENANT\",\"site_id\":\"canary\",\"status_code\":503,\"method\":\"GET\",\"path\":\"/health\",\"total_ms\":800,\"app_name\":\"$APP\",\"signal_purpose\":\"validation\",\"environment\":\"validation\"}" \
    | produce netops.probes || fail "could not produce probe event onto the bus"

# 2) canary LB 503 for the SAME app (independent witness class)
printf '%s\n' "{\"source\":\"lb\",\"vendor\":\"generic\",\"product\":\"reverse_proxy\",\"tenant_id\":\"$TENANT\",\"ts\":\"$TS\",\"app_name\":\"$APP\",\"service_name\":\"canary_frontend\",\"host\":\"portal.rca-canary.example\",\"path\":\"/health\",\"status_code\":503,\"reason\":\"backend_unavailable\",\"lb_name\":\"canary-lb\",\"raw_event_id\":\"$RUN_ID\",\"signal_purpose\":\"validation\",\"environment\":\"validation\"}" \
    | produce netops.app.edge || fail "could not produce app-edge event onto the bus"

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

# 4) confirmed app-impact object?
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
                 AND top_hypothesis='sig.ent.app.saas-experience-degraded'
                 AND created_at > now() - INTERVAL 20 MINUTE
               SETTINGS tenant_scope='__all__'" || echo "")
    [ "$tier" = "confirmed" ] && break
    [ "$(date +%s)" -ge "$deadline" ] && fail "no CONFIRMED saas-experience object after ${OBJECT_BUDGET_S}s (latest tier='${tier:-none persisted in 20m}') — grounding/signature/verdict path broken"
    sleep 10
done

log "confirmed RCA object formed"

# 5) autoticketing leg (#78 loop): the confirmed object must produce a DELIVERED
#    ticket — sweeper (60s tick) → ticket_outbox → worker → ITSM connector → mock.
#    Asserts the outbox row reaches status='sent' (the worker got an HTTP 2xx
#    from the ITSM endpoint), not merely that a create was enqueued.
if [ "$TICKET_BUDGET_S" -gt 0 ] 2>/dev/null; then
    cid=$(ch "SELECT toString(argMax(correlation_id, created_at)) FROM netops.corr_objects
              WHERE tenant_id='$TENANT'
                AND top_hypothesis='sig.ent.app.saas-experience-degraded'
                AND created_at > now() - INTERVAL 20 MINUTE
              SETTINGS tenant_scope='__all__'")
    [ -n "$cid" ] || fail "confirmed object has no correlation_id (unexpected)"
    deadline=$(( $(date +%s) + TICKET_BUDGET_S ))
    while :; do
        st=$(dc exec -T postgres psql -U netops -d netops -tA \
             -c "SELECT status FROM ticket_outbox WHERE tenant_id='$TENANT'
                  AND corr_object_id='$cid' ORDER BY updated_at DESC LIMIT 1" 2>/dev/null || echo "")
        [ "$st" = "sent" ] && break
        [ "$(date +%s)" -ge "$deadline" ] && fail "ticket not delivered after ${TICKET_BUDGET_S}s (outbox status='${st:-none}') — sweeper/outbox/worker/ITSM-connection path broken"
        sleep 10
    done
    log "ticket delivered for $cid (autoticketing loop closed)"
fi

log "OK: $RUN_ID confirmed end-to-end (bus → signals → confirmed RCA object → ticket)"
exit 0
