#!/usr/bin/env bash
# validate-nms-e2e.sh — exercise the NMS vendor-controller integration cycle
# (#95) end-to-end against the running stack and the bundled mock controller.
#
# It proves the WHOLE path on real data (not a unit): create a vManage
# integration pointed at mock-nms → live auth test → poll → transformer →
# 3-class routing → VictoriaMetrics (controller_metric_*), Redpanda
# netops.controller_events → correlation → ClickHouse corr_signals, and the
# controller_state_current table via the /states API.
#
# Prereqs:
#   deployment/docker/.env: FEATURE_NMS_INTEGRATIONS=true, COMPOSE_PROFILES
#   includes mock-nms (or: docker compose --profile mock-nms up -d mock-nms)
#   docker compose up -d api
#
# Usage:
#   scripts/validate-nms-e2e.sh              # create + validate (idempotent-ish;
#                                            # re-running adds a new integration)
#   scripts/validate-nms-e2e.sh --teardown   # delete integrations it created
#
# Env overrides:
#   BASE_URL (http://localhost:8000)  ADMIN_USER (admin)  ADMIN_PASS (netops-admin-2026)
#   NMS_URL_INTERNAL (http://mock-nms:8091 — as the api sees it)
#   MOCK_USER (correlix)  MOCK_PASS (correlix-mock-secret)  TENANT (first non-global)
set -euo pipefail

BASE_URL="${BASE_URL:-http://localhost:8000}"
ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PASS="${ADMIN_PASS:-netops-admin-2026}"
NMS_URL_INTERNAL="${NMS_URL_INTERNAL:-http://mock-nms:8091}"
MOCK_USER="${MOCK_USER:-correlix}"
MOCK_PASS="${MOCK_PASS:-correlix-mock-secret}"
E2E_NAME="e2e-validation-vmanage"

say()  { printf '\033[1;36m▸ %s\033[0m\n' "$*"; }
ok()   { printf '\033[1;32m✓ %s\033[0m\n' "$*"; }
die()  { printf '\033[1;31m✗ %s\033[0m\n' "$*" >&2; exit 1; }
jget() { python3 -c 'import sys,json;d=json.load(sys.stdin);print(eval("d"+sys.argv[1]))' "$1"; }

command -v curl >/dev/null || die "curl is required"
command -v python3 >/dev/null || die "python3 is required"

say "Logging in to $BASE_URL as $ADMIN_USER"
TOKEN="$(curl -fsS -m 10 -X POST "$BASE_URL/api/auth/login" \
  -H 'Content-Type: application/json' \
  -d "{\"username\":\"$ADMIN_USER\",\"password\":\"$ADMIN_PASS\"}" | jget "['token']")"
[ -n "$TOKEN" ] || die "login failed"
AUTH=(-H "Authorization: Bearer $TOKEN")
ok "authenticated"

if [ -z "${TENANT:-}" ]; then
  TENANT="$(curl -fsS -m 10 "$BASE_URL/api/tenants" "${AUTH[@]}" | python3 -c '
import sys, json
d = json.load(sys.stdin)
ts = d if isinstance(d, list) else d.get("tenants", [])
for t in ts:
    if t.get("id") != "global":
        print(t["id"]); break
')"
fi
[ -n "$TENANT" ] || die "no non-global tenant found (create one first)"
ACT=(-H "X-Acting-Tenant: $TENANT")
say "Acting tenant: $TENANT"

# ── teardown mode ─────────────────────────────────────────────────────────────
if [ "${1:-}" = "--teardown" ]; then
  say "Deleting e2e integrations named $E2E_NAME"
  curl -fsS "$BASE_URL/api/nms/integrations" "${AUTH[@]}" "${ACT[@]}" | python3 -c '
import sys, json
for i in json.load(sys.stdin)["integrations"]:
    if i["displayName"] == "'"$E2E_NAME"'":
        print(i["id"])
' | while read -r id; do
    curl -fsS -X DELETE "$BASE_URL/api/nms/integrations/$id" "${AUTH[@]}" "${ACT[@]}" >/dev/null
    ok "deleted $id"
  done
  exit 0
fi

say "1/7 Connector catalog lists all 8 vendors"
NVEND="$(curl -fsS "$BASE_URL/api/nms/connectors" "${AUTH[@]}" | jget "['connectors']" | python3 -c 'import sys,ast;print(len(ast.literal_eval(sys.stdin.read())))')"
[ "$NVEND" -ge 8 ] || die "expected >=8 connectors, got $NVEND"
ok "$NVEND connectors registered"

say "2/7 Creating vManage integration → $NMS_URL_INTERNAL"
CREATED="$(curl -fsS -X POST "$BASE_URL/api/nms/integrations" "${AUTH[@]}" "${ACT[@]}" \
  -H 'Content-Type: application/json' -d "{
  \"vendor\": \"vmanage\",
  \"displayName\": \"$E2E_NAME\",
  \"baseUrl\": \"$NMS_URL_INTERNAL\",
  \"enabled\": true,
  \"pollIntervalS\": 60,
  \"streams\": [\"alarms\", \"statistics\"],
  \"credentials\": {\"username\": \"$MOCK_USER\", \"password\": \"$MOCK_PASS\"}
}")"
IID="$(printf '%s' "$CREATED" | jget "['id']")"
[ -n "$IID" ] || die "create failed: $CREATED"
printf '%s' "$CREATED" | grep -q "$MOCK_PASS" && die "SECRET LEAKED in create response"
ok "created $IID (no secret in response)"

say "3/7 Live auth test against the controller"
TRES="$(curl -fsS -X POST "$BASE_URL/api/nms/integrations/$IID/test" "${AUTH[@]}" "${ACT[@]}")"
[ "$(printf '%s' "$TRES" | jget "['ok']")" = "True" ] || die "auth test failed: $TRES"
ok "authentication verified (JWT login round-trip)"

say "4/7 Poll now → events produced"
PRES="$(curl -fsS -X POST "$BASE_URL/api/nms/integrations/$IID/poll" "${AUTH[@]}" "${ACT[@]}")"
PSTATUS="$(printf '%s' "$PRES" | jget "['status']")"
PEVENTS="$(printf '%s' "$PRES" | jget "['events']")"
[ "$PSTATUS" = "ok" ] || die "poll failed: $PRES"
[ "$PEVENTS" -ge 1 ] || die "poll produced no events: $PRES"
ok "poll ok — $PEVENTS controller events"

say "5/7 Controller state tracked (BFD entity)"
STATES="$(curl -fsS "$BASE_URL/api/nms/integrations/$IID/states" "${AUTH[@]}" "${ACT[@]}")"
printf '%s' "$STATES" | grep -q '"stateKind": *"bfd"' || printf '%s' "$STATES" | grep -q '"stateKind":"bfd"' || die "no bfd state row: $STATES"
ok "controller_state_current has the BFD session"

say "6/7 Metric lane → VictoriaMetrics controller_metric_tunnel_latency_ms"
# VictoriaMetrics hides the newest ~30s from instant queries by default
# (-search.latencyOffset), so a fixed sleep races the import — poll with a
# deadline like stage 7 does.
VM_DEADLINE=$(( $(date +%s) + 60 ))
VMQ=""
while [ "$(date +%s)" -lt "$VM_DEADLINE" ]; do
  VMQ="$(docker exec netops-victoria-1 wget -qO- 'http://127.0.0.1:8428/api/v1/query?query=controller_metric_tunnel_latency_ms')"
  printf '%s' "$VMQ" | grep -q '"__name__":"controller_metric_tunnel_latency_ms"' && break
  sleep 5
done
printf '%s' "$VMQ" | grep -q '"__name__":"controller_metric_tunnel_latency_ms"' || die "metric not in VictoriaMetrics after 60s: $VMQ"
ok "controller metrics landed in VictoriaMetrics"

say "7/7 Event lane → correlation → ClickHouse corr_signals (source=controller)"
DEADLINE=$(( $(date +%s) + 90 ))
while :; do
  N="$(docker exec netops-clickhouse-1 clickhouse-client -q \
    "SELECT count() FROM netops.corr_signals WHERE source='controller' AND ts > now() - INTERVAL 10 MINUTE SETTINGS tenant_scope='__all__'" 2>/dev/null || echo 0)"
  [ "${N:-0}" -ge 1 ] && break
  [ "$(date +%s)" -ge "$DEADLINE" ] && die "no controller corr_signal in ClickHouse after 90s (check correlation logs)"
  sleep 5
done
ok "$N controller signal(s) in corr_signals — RCA evidence lane live"

printf '\n\033[1;32m━━ NMS INTEGRATION CYCLE VALIDATED END-TO-END ━━\033[0m\n'
echo   "   auth → poll → transform → route → VM + bus + state table → corr_signals"
echo   "   Integration: $IID (tenant $TENANT). UI: Infrastructure → NMS Integrations."
echo   "   Teardown: scripts/validate-nms-e2e.sh --teardown"
