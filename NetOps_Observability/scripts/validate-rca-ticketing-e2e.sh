#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

# validate-rca-ticketing-e2e.sh — exercise the RCA auto-ticketing CREATE leg (#78)
# AND the INBOUND state-sync leg (#84) end-to-end against the running stack and
# the bundled mock ServiceNow.
#
# It proves the WHOLE path on real data (not a unit): a live correlation object →
# the policy sweeper → the outbox → the worker → a REAL HTTP create → the mock's
# incident table → the ticket link → /api/tickets + ticket_status. It configures
# the global tenant's ServiceNow connection to point at the mock, installs a
# permissive policy so a real suspected/confirmed object tickets deterministically,
# waits for the sweeper+worker, then asserts an INC landed with the right
# correlation_id + u_correlix_* fields.
#
# It then closes the loop the other way: it PATCHes the mock incident as a
# "human" would in ServiceNow (In Progress → Resolved) and asserts the inbound
# state syncer (RCA_TICKETING_INBOUND_INTERVAL, 45s default) appends the
# acknowledged/resolve phases to the ticket audit and advances the link status.
#
# Prereqs (see deployment/docker/mock-servicenow/README.md):
#   docker compose --profile mock-snow up -d --build mock-servicenow
#   .env: FEATURE_RCA_TICKETING=true  +  SSRF_ALLOWED_HOSTS=mock-servicenow
#   docker compose up -d api
#
# Usage:
#   scripts/validate-rca-ticketing-e2e.sh            # configure + validate
#   scripts/validate-rca-ticketing-e2e.sh --teardown # disable connection + remove policy
#
# Env overrides:
#   BASE_URL (http://localhost:8000)  ADMIN_USER (admin)  ADMIN_PASS (netops-admin-2026)
#   SNOW_URL_INTERNAL (http://mock-servicenow:8090 — as the api sees it)
#   MOCK_INSPECT_URL  (http://localhost:8099 — as this host sees it)
#   MOCK_USER (correlix)  MOCK_PASS (correlix-mock-secret)  TIMEOUT (180 seconds)
set -euo pipefail

BASE_URL="${BASE_URL:-http://localhost:8000}"
ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PASS="${ADMIN_PASS:-netops-admin-2026}"
SNOW_URL_INTERNAL="${SNOW_URL_INTERNAL:-http://mock-servicenow:8090}"
MOCK_INSPECT_URL="${MOCK_INSPECT_URL:-http://localhost:8099}"
MOCK_USER="${MOCK_USER:-correlix}"
MOCK_PASS="${MOCK_PASS:-correlix-mock-secret}"
TIMEOUT="${TIMEOUT:-180}"
POLICY_ID="e2e-validation-permissive"

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
[ -n "$TOKEN" ] || die "login failed (no token)"
AUTH=(-H "Authorization: Bearer $TOKEN")
ok "authenticated"

# ── teardown mode ─────────────────────────────────────────────────────────────
if [ "${1:-}" = "--teardown" ]; then
  say "Disabling the global ServiceNow connection"
  curl -fsS -m 10 -X PUT "$BASE_URL/api/notify/itsm" "${AUTH[@]}" \
    -H 'Content-Type: application/json' \
    -d '{"servicenow":{"enabled":false,"instance_url":"","user":""}}' >/dev/null
  say "Removing the permissive validation policy ($POLICY_ID)"
  curl -fsS -m 10 -X DELETE "$BASE_URL/api/incident-policies/$POLICY_ID" "${AUTH[@]}" >/dev/null 2>&1 || true
  ok "teardown complete"
  exit 0
fi

# ── 1. point the global tenant's ServiceNow connection at the mock ────────────
say "Configuring global ServiceNow connection → $SNOW_URL_INTERNAL"
RESP="$(curl -fsS -m 10 -X PUT "$BASE_URL/api/notify/itsm" "${AUTH[@]}" \
  -H 'Content-Type: application/json' \
  -d "{\"servicenow\":{\"enabled\":true,\"instance_url\":\"$SNOW_URL_INTERNAL\",\"user\":\"$MOCK_USER\",\"password\":\"$MOCK_PASS\",\"min_severity\":\"info\"}}")"
CONFIGURED="$(printf '%s' "$RESP" | jget "['servicenow']['configured']")"
[ "$CONFIGURED" = "True" ] || die "connection not live after save (configured=$CONFIGURED). Did the api start with SSRF_ALLOWED_HOSTS=mock-servicenow? Response: $RESP"
ok "ServiceNow connection live (configured=true)"

# ── 2. install a permissive policy so a real object tickets deterministically ──
# Relaxes the default gates (probe-only allowed, suspected need not be critical,
# internal allowed, no customer-facing requirement) but keeps min_verdict=suspected
# so undetermined objects are still (correctly) held.
say "Installing permissive validation policy ($POLICY_ID)"
# Only one policy may be enabled per (tenant, system): the API 409s if another
# enabled policy exists. Surface that message instead of a bare curl failure —
# the operator must disable the conflicting policy deliberately, not have a
# validation script shadow it.
POLICY_RESP="$(curl -sS -m 10 -w '\n%{http_code}' -X POST "$BASE_URL/api/incident-policies" "${AUTH[@]}" \
  -H 'Content-Type: application/json' \
  -d "{\"id\":\"$POLICY_ID\",\"name\":\"E2E validation (permissive)\",\"external_system\":\"servicenow\",\"enabled\":true,\"min_verdict\":\"suspected\",\"require_customer_facing\":false,\"allow_probe_only\":true,\"allow_internal_monitoring\":true,\"suspected_requires_critical\":false,\"default_impact\":2,\"default_urgency\":2}")"
POLICY_STATUS="${POLICY_RESP##*$'\n'}"
[ "$POLICY_STATUS" = "200" ] || die "policy install failed (HTTP $POLICY_STATUS): ${POLICY_RESP%$'\n'*}"
ok "policy installed"

# ── 3. wait for the sweeper (≤60s) + worker (≤15s) to file an incident ─────────
say "Waiting up to ${TIMEOUT}s for the sweeper+worker to file an incident in the mock…"
deadline=$(( $(date +%s) + TIMEOUT ))
COUNT=0
while [ "$(date +%s)" -lt "$deadline" ]; do
  SNAP="$(curl -fsS -m 10 -u "$MOCK_USER:$MOCK_PASS" "$MOCK_INSPECT_URL/inspect" 2>/dev/null || echo '{}')"
  COUNT="$(printf '%s' "$SNAP" | jget "['count']" 2>/dev/null || echo 0)"
  if [ "${COUNT:-0}" -gt 0 ] 2>/dev/null; then break; fi
  printf '  … %ds elapsed, incidents=%s\n' "$(( $(date +%s) - (deadline - TIMEOUT) ))" "$COUNT"
  sleep 8
done
[ "${COUNT:-0}" -gt 0 ] 2>/dev/null || die "no incident created within ${TIMEOUT}s — check: docker compose logs api | grep ticketing"

# ── 4. assert the created incident carries the RCA correlation_id + fields ─────
say "Verifying the filed incident"
SNAP="$(curl -fsS -m 10 -u "$MOCK_USER:$MOCK_PASS" "$MOCK_INSPECT_URL/inspect")"
python3 - "$SNAP" <<'PY' || die "incident verification failed"
import sys, json
snap = json.loads(sys.argv[1])
incs = snap.get("incidents", [])
assert incs, "no incidents"
inc = incs[0]
need = ["number", "sys_id", "correlation_id", "u_correlix_verdict", "u_correlix_object_id", "short_description"]
missing = [k for k in need if not inc.get(k)]
assert not missing, f"incident missing fields: {missing}\n{json.dumps(inc, indent=2)}"
assert inc["correlation_id"] == inc["u_correlix_object_id"], "correlation_id != u_correlix_object_id"
print(f"  INC {inc['number']} sys_id={inc['sys_id']}")
print(f"  correlation_id   = {inc['correlation_id']}")
print(f"  verdict          = {inc['u_correlix_verdict']}  confidence={inc.get('u_correlix_confidence','?')}")
print(f"  short_description= {inc['short_description']}")
print(f"  signature        = {inc.get('u_correlix_signature','')}")
PY
ok "incident verified — RCA correlation_id + u_correlix_* fields present"

# ── 5. confirm Correlix's own ticket link/status reflects the create ──────────
CORR="$(printf '%s' "$SNAP" | python3 -c 'import sys,json;print(json.load(sys.stdin)["incidents"][0]["correlation_id"])')"
say "Confirming ticket_status on correlation $CORR"
STATUS="$(curl -fsS -m 10 "${AUTH[@]}" "$BASE_URL/api/correlations/$CORR/tickets")"
STATE="$(printf '%s' "$STATUS" | jget "['status']['state']" 2>/dev/null || echo unknown)"
NUM="$(printf '%s' "$STATUS" | jget "['status'].get('ticket_number','')" 2>/dev/null || echo '')"
[ "$STATE" = "open" ] || [ "$STATE" = "updated" ] || die "ticket link state=$STATE (expected open/updated). $STATUS"
ok "ticket link state=$STATE number=$NUM — the create leg is closed end-to-end"

# ── 6. inbound leg: a "human" moves the ticket to In Progress in ServiceNow ────
SYS_ID="$(printf '%s' "$SNAP" | jget "['incidents'][0]['sys_id']")"
[ -n "$SYS_ID" ] || die "no sys_id in mock snapshot"

# audit_has <action> — succeeds when the correlation's ticket audit holds an ok
# row for <action> (the inbound syncer appends them with actor servicenow:sync).
audit_has() {
  curl -fsS -m 10 "${AUTH[@]}" "$BASE_URL/api/correlations/$CORR/tickets" 2>/dev/null \
    | python3 -c 'import sys,json;d=json.load(sys.stdin);sys.exit(0 if any(e.get("action")==sys.argv[1] and e.get("result")=="ok" for e in d.get("audit") or []) else 1)' "$1" 2>/dev/null
}

say "Inbound leg: PATCHing mock incident $SYS_ID → In Progress (state=2 + work_start)"
curl -fsS -m 10 -u "$MOCK_USER:$MOCK_PASS" -X PATCH \
  "$MOCK_INSPECT_URL/api/now/table/incident/$SYS_ID" \
  -H 'Content-Type: application/json' \
  -d "{\"state\":\"2\",\"work_start\":\"$(date -u '+%Y-%m-%d %H:%M:%S')\"}" >/dev/null

say "Waiting up to ${TIMEOUT}s for the inbound sync (RCA_TICKETING_INBOUND_INTERVAL, 45s default) to observe acknowledged…"
deadline=$(( $(date +%s) + TIMEOUT ))
until audit_has acknowledged; do
  [ "$(date +%s)" -lt "$deadline" ] || die "acknowledged phase not observed within ${TIMEOUT}s — check: docker compose logs api | grep 'inbound'"
  printf '  … %ds elapsed, waiting for acknowledged\n' "$(( $(date +%s) - (deadline - TIMEOUT) ))"
  sleep 8
done
ok "acknowledged phase appended by the inbound sync"

# ── 7. inbound leg: resolve in ServiceNow → resolve phase + link advances ──────
say "PATCHing mock incident $SYS_ID → Resolved (state=6 + resolved_at)"
curl -fsS -m 10 -u "$MOCK_USER:$MOCK_PASS" -X PATCH \
  "$MOCK_INSPECT_URL/api/now/table/incident/$SYS_ID" \
  -H 'Content-Type: application/json' \
  -d "{\"state\":\"6\",\"resolved_at\":\"$(date -u '+%Y-%m-%d %H:%M:%S')\"}" >/dev/null

say "Waiting up to ${TIMEOUT}s for the resolve phase + link advance…"
deadline=$(( $(date +%s) + TIMEOUT ))
until audit_has resolve; do
  [ "$(date +%s)" -lt "$deadline" ] || die "resolve phase not observed within ${TIMEOUT}s — check: docker compose logs api | grep 'inbound'"
  printf '  … %ds elapsed, waiting for resolve\n' "$(( $(date +%s) - (deadline - TIMEOUT) ))"
  sleep 8
done
# The link advance lands in the same sync pass as the resolve row; poll briefly
# in case we read between the audit append and the link write.
deadline=$(( $(date +%s) + 30 ))
STATE=unknown
while [ "$(date +%s)" -lt "$deadline" ]; do
  STATUS="$(curl -fsS -m 10 "${AUTH[@]}" "$BASE_URL/api/correlations/$CORR/tickets" 2>/dev/null || echo '{}')"
  STATE="$(printf '%s' "$STATUS" | jget "['status']['state']" 2>/dev/null || echo unknown)"
  [ "$STATE" = "resolved" ] && break
  sleep 3
done
[ "$STATE" = "resolved" ] || die "ticket link state=$STATE (expected resolved after inbound sync)"
ok "resolve phase appended and link status advanced to resolved"

echo
ok "PASS — RCA → ServiceNow create AND inbound state-sync legs validated live against the mock."
echo "  Re-run with --teardown to disable the connection + remove the policy."
