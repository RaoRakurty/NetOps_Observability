#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

# verify-critical-alert-channel.sh (#101) — the first-customer alert-delivery
# gate. FAILS (exit 1) unless critical alerts demonstrably LEAVE the app.
#
# In-app alert visibility is NOT sufficient for customer operations: a
# corr_current projection failure at 02:00 must reach a phone/pager. This gate
# verifies, against the RUNNING stack:
#
#   G1  at least one external notification channel is enabled AND fully
#       configured (ntfy topic / Slack webhook / PagerDuty key / SMTP host /
#       Twilio SID)
#   G2  that channel's min_severity admits critical alerts (any valid value
#       does — critical is the highest severity — but the value must be valid)
#   G3  watchdog independence: the ntfy topic is NOT the external stack
#       watchdog's topic (checked against scripts/stack-watchdog.env when
#       present; the API additionally refuses it server-side when
#       WATCHDOG_NTFY_TOPIC is exported)
#   G4  the critical contract alerts are present in the shipped rules file
#       (parse-depth is guarded by TestShippedRulesFileParses in CI):
#       CHMemoryLimitExceeded, CHFailedQueriesRising, CorrVersionChurnUndamped,
#       CorrCurrentProjectionFailing, CorrTenantWriteAmpOverBudget
#   G5  delivery: with --send, POSTs the enabled channel's /test endpoint and
#       requires success (a REAL push lands). Without --send it is a dry-run:
#       configuration is validated end-to-end but nothing is delivered —
#       go-live acceptance REQUIRES a --send run (checklist §4).
#
# Auth: CORRELIX_API_TOKEN, or CORRELIX_ADMIN_USER/CORRELIX_ADMIN_PASSWORD
# (defaults: admin / ADMIN_INITIAL_PASSWORD from deployment/docker/.env — the
# fallback only works until the admin password is rotated).
#
# Usage: verify-critical-alert-channel.sh [--send] [--quiet]
# Env:   API_URL=http://localhost:8000 COMPOSE_DIR=... WATCHDOG_ENV=...
set -u

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
API_URL="${API_URL:-http://localhost:8000}"
WATCHDOG_ENV="${WATCHDOG_ENV:-$DIR/stack-watchdog.env}"
ENV_FILE="${ENV_FILE:-$DIR/../deployment/docker/.env}"
RULES_FILE="${RULES_FILE:-$DIR/../src/config/rules.yaml}"
SEND=0; QUIET=0
for a in "$@"; do
    case "$a" in
        --send) SEND=1 ;;
        --quiet) QUIET=1 ;;
        *) echo "usage: $0 [--send] [--quiet]" >&2; exit 2 ;;
    esac
done
log()  { [ "$QUIET" = 1 ] || echo "[alert-gate] $*"; }
fail() { echo "[alert-gate] FAIL: $*" >&2; FAILED=1; }
FAILED=0

# ---- auth -------------------------------------------------------------------
TOKEN="${CORRELIX_API_TOKEN:-}"
if [ -z "$TOKEN" ]; then
    USER="${CORRELIX_ADMIN_USER:-admin}"
    PASS="${CORRELIX_ADMIN_PASSWORD:-}"
    if [ -z "$PASS" ] && [ -r "$ENV_FILE" ]; then
        PASS=$(grep -E '^ADMIN_INITIAL_PASSWORD=' "$ENV_FILE" | head -1 | cut -d= -f2-)
    fi
    TOKEN=$(curl -s -X POST "$API_URL/api/auth/login" -H 'Content-Type: application/json' \
        -d "{\"username\":\"$USER\",\"password\":\"$PASS\"}" \
        | python3 -c 'import json,sys;print(json.load(sys.stdin).get("token",""))' 2>/dev/null)
fi
if [ -z "$TOKEN" ]; then
    echo "[alert-gate] FAIL: cannot authenticate to $API_URL (set CORRELIX_API_TOKEN or CORRELIX_ADMIN_USER/PASSWORD)" >&2
    exit 1
fi
api() { curl -s "$API_URL$1" -H "Authorization: Bearer $TOKEN"; }

# ---- G1+G2: an enabled, fully-configured external channel --------------------
ENABLED_CHANNELS=()
NTFY_TOPIC=""
check_channel() { # name endpoint ready_expr
    local name="$1" ep="$2" expr="$3" json
    json=$(api "/api/notify/$ep")
    python3 - "$name" "$expr" <<PYEOF && ENABLED_CHANNELS+=("$name")
import json, sys
j = json.loads('''$json''')
name, expr = sys.argv[1], sys.argv[2]
if not j.get("enabled"):
    sys.exit(1)
if not eval(expr, {}, {"j": j}):
    print(f"[alert-gate] WARN: {name} is enabled but incompletely configured: {j}", file=sys.stderr)
    sys.exit(1)
sev = (j.get("min_severity") or "").lower()
if sev not in ("", "info", "notice", "warning", "error", "critical"):
    print(f"[alert-gate] WARN: {name} has invalid min_severity {sev!r}", file=sys.stderr)
    sys.exit(1)
sys.exit(0)
PYEOF
    if [ "$name" = "ntfy" ]; then
        NTFY_TOPIC=$(python3 -c "import json;print(json.loads('''$json''').get('topic',''))" 2>/dev/null)
    fi
}
check_channel ntfy      ntfy      'bool(j.get("topic"))'
check_channel slack     slack     'bool(j.get("webhook_set"))'
check_channel pagerduty pagerduty 'bool(j.get("routing_set"))'
check_channel smtp      smtp      'bool(j.get("host"))' 2>/dev/null || true
check_channel twilio    twilio    'bool(j.get("sid_set") or j.get("account_set"))' 2>/dev/null || true

if [ "${#ENABLED_CHANNELS[@]}" -eq 0 ]; then
    fail "NO external notification channel is enabled — critical alerts exist only in-app. Configure Admin → Notifications (recommended: ntfy, dedicated topic, min severity critical) or seed via FEATURE_NTFY_NOTIFICATIONS/NTFY_ALERT_TOPIC in .env."
else
    log "external channel(s) enabled: ${ENABLED_CHANNELS[*]} (critical alerts leave the app)"
fi

# ---- G3: watchdog independence -----------------------------------------------
if [ -n "$NTFY_TOPIC" ] && [ -r "$WATCHDOG_ENV" ]; then
    WD_TOPIC=$(grep -E '^NTFY_TOPIC=' "$WATCHDOG_ENV" | head -1 | cut -d= -f2-)
    if [ -n "$WD_TOPIC" ] && [ "$NTFY_TOPIC" = "$WD_TOPIC" ]; then
        fail "product ntfy topic equals the stack-watchdog topic — watchdog independence is mandatory (it must be able to report the stack's own death). Use a dedicated topic."
    else
        log "watchdog independence OK (product topic differs from watchdog topic)"
    fi
fi

# ---- G4: critical contract alerts shipped -------------------------------------
if [ -r "$RULES_FILE" ]; then
    for rule in CHMemoryLimitExceeded CHFailedQueriesRising CorrVersionChurnUndamped \
                CorrCurrentProjectionFailing CorrTenantWriteAmpOverBudget; do
        grep -q "alert: $rule" "$RULES_FILE" || fail "contract alert $rule missing from $RULES_FILE"
    done
    log "contract alerts present in rules file (parse depth: TestShippedRulesFileParses)"
else
    log "rules file not found at $RULES_FILE — skipping G4 (bundle layout?)"
fi

# ---- G5: delivery ---------------------------------------------------------------
if [ "$SEND" = 1 ] && [ "${#ENABLED_CHANNELS[@]}" -gt 0 ]; then
    ch="${ENABLED_CHANNELS[0]}"
    resp=$(curl -s -w '\n%{http_code}' -X POST "$API_URL/api/notify/$ch/test" -H "Authorization: Bearer $TOKEN")
    code=$(echo "$resp" | tail -1)
    if [ "$code" = "200" ]; then
        log "TEST ALERT DELIVERED via $ch (verify it arrived on the subscribed device)"
    else
        fail "test delivery via $ch failed (HTTP $code): $(echo "$resp" | head -1)"
    fi
elif [ "${#ENABLED_CHANNELS[@]}" -gt 0 ]; then
    log "dry-run only — run with --send before go-live (checklist §4 requires a delivered test alert)"
fi

if [ "$FAILED" = 0 ]; then
    log "PASS — external critical alert delivery gate satisfied"
    exit 0
fi
exit 1
