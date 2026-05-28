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
# Alerts fire only on a state TRANSITION (up->down, down->up), so a sustained
# outage produces one push, not one per minute.
#
# Config (NTFY_TOPIC, HC_PING_URL, ...) lives in stack-watchdog.env next to
# this script — see stack-watchdog.env.example. No secrets are baked in here.

set -uo pipefail
export PATH="/usr/local/bin:/usr/bin:/bin:${PATH:-}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${WATCHDOG_ENV:-$SCRIPT_DIR/stack-watchdog.env}"
STATE_FILE="${WATCHDOG_STATE:-$SCRIPT_DIR/.stack-watchdog.state}"

# shellcheck disable=SC1090
[ -f "$ENV_FILE" ] && { set -a; . "$ENV_FILE"; set +a; }

PROJECT="${COMPOSE_PROJECT:-netops}"
APP_URL="${APP_URL:-http://localhost:8000/}"
NTFY_SERVER="${NTFY_SERVER:-https://ntfy.sh}"

EXPECTED_SERVICES="api clickhouse correlation frontend goflow2 grafana nginx \
opensearch opensearch-dashboards postgres prometheus redis redpanda syslog-ng \
telegraf vector-aggregator vector-router victoria"

push() {  # title, tags, priority, body
  [ -n "${NTFY_TOPIC:-}" ] || return 0
  curl -fsS -m 10 \
    -H "Title: $1" -H "Tags: $2" -H "Priority: $3" \
    -d "$4" "$NTFY_SERVER/$NTFY_TOPIC" -o /dev/null \
    || echo "watchdog: ntfy push failed" >&2
}

# --test sends one push so you can confirm your phone is subscribed, then exits.
if [ "${1:-}" = "--test" ]; then
  push "NetOps watchdog test" "test_tube" "default" \
    "Test alert from $(hostname) at $(date -Is). If you see this, alerting works."
  echo "Sent test push to topic '${NTFY_TOPIC:-<unset>}' on $NTFY_SERVER"
  exit 0
fi

problems=()

for svc in $EXPECTED_SERVICES; do
  cid=$(docker ps -q \
    --filter "label=com.docker.compose.project=$PROJECT" \
    --filter "label=com.docker.compose.service=$svc" 2>/dev/null)
  if [ -z "$cid" ]; then
    problems+=("$svc: not running")
    continue
  fi
  state=$(docker inspect -f '{{.State.Status}}' "$cid" 2>/dev/null)
  if [ "$state" != "running" ]; then
    problems+=("$svc: state=$state")
    continue
  fi
  health=$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{end}}' "$cid" 2>/dev/null)
  if [ -n "$health" ] && [ "$health" != "healthy" ]; then
    problems+=("$svc: health=$health")
  fi
done

# End-to-end probe: the dashboard must answer through nginx.
code=$(curl -s -o /dev/null -w '%{http_code}' -m 10 "$APP_URL" 2>/dev/null)
case "$code" in
  200|301|302|401) ;;                               # served (401 = auth on / is fine)
  *) problems+=("dashboard $APP_URL: HTTP ${code:-no-response}") ;;
esac

prev=$(cat "$STATE_FILE" 2>/dev/null || echo up)
nsvc=$(echo "$EXPECTED_SERVICES" | wc -w | tr -d ' ')

if [ ${#problems[@]} -eq 0 ]; then
  [ -n "${HC_PING_URL:-}" ] && curl -fsS -m 10 "$HC_PING_URL" -o /dev/null
  if [ "$prev" = "down" ]; then
    push "✅ NetOps stack RECOVERED on $(hostname)" "white_check_mark" "default" \
      "All $nsvc services healthy again at $(date -Is)."
  fi
  echo up > "$STATE_FILE"
  exit 0
fi

msg=$(printf '%s\n' "${problems[@]}")
[ -n "${HC_PING_URL:-}" ] && curl -fsS -m 10 --data-raw "$msg" "${HC_PING_URL%/}/fail" -o /dev/null
if [ "$prev" = "up" ]; then
  push "🚨 NetOps stack DOWN on $(hostname)" "rotating_light" "urgent" "$msg"
fi
echo down > "$STATE_FILE"
echo "watchdog: DOWN -> $msg" >&2
exit 1
