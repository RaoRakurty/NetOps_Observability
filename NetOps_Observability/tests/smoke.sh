#!/usr/bin/env bash
# High-level feature smoke test — logs in once, then exercises every major API
# surface and asserts each responds successfully. Confirms "are all the features
# working" end-to-end against a running stack. NOT a deep correctness test (see
# the Go/pytest unit suites for that) — it's the broad reachability sweep.
#
# Usage:
#   tests/smoke.sh                          # uses admin creds from env
#   NETOPS_BASE=http://host:8000 tests/smoke.sh
#   NETOPS_TOKEN=<jwt> tests/smoke.sh       # skip login, use a token directly
#
# Env: NETOPS_BASE (default http://localhost:8000), NETOPS_USER (admin),
#      NETOPS_PASS, or NETOPS_TOKEN.
set -u

BASE="${NETOPS_BASE:-http://localhost:8000}"
USER="${NETOPS_USER:-admin}"
PASS="${NETOPS_PASS:-}"
TOKEN="${NETOPS_TOKEN:-}"
PASS_N=0; FAIL_N=0

jq_get() { python3 -c "import sys,json;d=json.load(sys.stdin);print(d$1)" 2>/dev/null; }

login() {
  [ -n "$TOKEN" ] && { echo "• using NETOPS_TOKEN"; return; }
  [ -z "$PASS" ] && { echo "✗ no NETOPS_TOKEN and no NETOPS_PASS — set one"; exit 2; }
  local r; r=$(curl -s -m10 -X POST "$BASE/api/auth/login" \
    -H 'Content-Type: application/json' -d "{\"username\":\"$USER\",\"password\":\"$PASS\"}")
  TOKEN=$(printf '%s' "$r" | jq_get "['token']")
  [ -z "$TOKEN" ] && { echo "✗ login failed: $r"; exit 2; }
  echo "• logged in as $USER (role $(printf '%s' "$r" | jq_get "['user']['role']"))"
}

# check NAME METHOD PATH [EXPECTED] [BODY]
check() {
  local name="$1" method="$2" path="$3" expect="${4:-200}" body="${5:-}"
  local args=(-s -m15 -o /dev/null -w '%{http_code}' -X "$method"
              -H "Authorization: Bearer $TOKEN")
  [ -n "$body" ] && args+=(-H 'Content-Type: application/json' -d "$body")
  local code; code=$(curl "${args[@]}" "$BASE$path")
  if printf '%s' "$expect" | grep -qw "$code"; then
    printf "  \033[32m✓\033[0m %-26s %s %s\n" "$name" "$method" "$code"; PASS_N=$((PASS_N+1))
  else
    printf "  \033[31m✗\033[0m %-26s %s got %s want %s\n" "$name" "$method" "$code" "$expect"; FAIL_N=$((FAIL_N+1))
  fi
}

echo "== NetOps smoke test ($BASE) =="
login
echo "-- platform --"
check health      GET  /admin/health
check version     GET  /admin/version
check me          GET  /api/auth/me
check permissions GET  /api/auth/permissions
echo "-- inventory & collection --"
check devices     GET  /api/devices
check collectors  GET  /api/collectors
echo "-- alerts --"
check alerts      GET  /api/alerts
check rules       GET  /api/rules
check findings    GET  /api/findings
echo "-- explore: logs / metrics / flows --"
check logs_indices GET /api/logs/indices
check logs_search  POST /api/logs/search 200 '{"query":"*","size":5}'
check metric_tiles GET  /api/metrics
check metric_names GET  /api/metrics/names
check metric_query GET  "/api/metrics/query?query=up"
check flows_top    GET  "/api/flows/top?since=1h"
check flows_proto  GET  "/api/flows/by-proto?since=1h"
check flows_ts     GET  "/api/flows/timeseries?since=1h"
check tunnels      GET  /api/tunnels
echo "-- saved / reports / search --"
check saved        GET  /api/saved
check reports_runs GET  /api/reports/runs
check global_srch  GET  "/api/search/global?q=core"
echo "-- API & ITSM --"
check graphql      POST /api/graphql 200 '{"query":"{ devices { id } health }"}'
check openapi      GET  /api/openapi.json
check itsm_snow    GET  /api/itsm/servicenow
check itsm_jira    GET  /api/itsm/jira

echo
echo "== $PASS_N passed, $FAIL_N failed =="
[ "$FAIL_N" -eq 0 ]
