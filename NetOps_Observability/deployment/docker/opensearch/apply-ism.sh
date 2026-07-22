#!/bin/sh
# apply-ism.sh — install an OpenSearch ISM (Index State Management) retention
# policy that deletes the netops time-series indices once they age past the
# retention window. Without this, daily log/flow indices grow until they fill
# the disk and trip OpenSearch's flood watermark (read-only) — the #1 thing that
# ends a multi-day run. Run once by the opensearch-init container after the
# cluster is healthy. Idempotent (PUT replaces; add is best-effort).
set -eu

OS="${OPENSEARCH_URL:-http://opensearch:9200}"
DAYS="${OPENSEARCH_LOG_RETENTION_DAYS:-14}"
# F-53 (2026-07-21): this list covered 3 of the 6 log lanes. netops-snmptrap-*
# and netops-cloudlogs-* matched NO ism_template, so `_ism/explain` reported
# policy None and those indices were NEVER DELETED — unbounded growth on the
# lane with the widest, most vendor-controlled schema, on a filesystem that has
# already hit NOT_ENOUGH_SPACE once (F-55). Dead-letter is included too: it is
# tiny by construction but "tiny by construction" is exactly the assumption that
# stops being true during the incident you wrote it for.
PATTERNS='["netops-applogs-*","netops-syslog-*","netops-flows-*","netops-snmptrap-*","netops-cloudlogs-*","netops-deadletter-*"]'
ADD_PATTERNS='netops-applogs-*,netops-syslog-*,netops-flows-*,netops-snmptrap-*,netops-cloudlogs-*,netops-deadletter-*'

echo "ism: waiting for OpenSearch at $OS ..."
until curl -sf "$OS/_cluster/health" >/dev/null 2>&1; do sleep 5; done

# ---------------------------------------------------------------------------
# F-54: single-node shard hygiene, applied BEFORE the retention policy so the
# history indices this very plugin creates are born with 0 replicas.
#
# The cluster ran permanently YELLOW with 35 UNASSIGNED shards — 33 of them the
# ISM plugin's OWN audit-history indices (.opendistro-ism-managed-index-history-*),
# which roll daily, default to 1 replica, and are managed by no policy. On a
# single-node cluster a replica can never be assigned, so every one of those
# indices is born yellow. Yellow then stops meaning anything, and the real
# yellow (F-53's snmptrap) hid inside the noise for weeks.
#
# These are DYNAMIC cluster settings — no restart, no data movement. Note the
# setting is rollover_RETENTION_period (default 30d, which is why 33 daily
# history indices had accumulated); `retention_period` is not a real setting and
# a typo here 400s the WHOLE request, so keep this list verified against
# GET _cluster/settings?include_defaults=true.
echo "ism: pinning single-node shard settings (history replicas 0, 7d retention) ..."
curl -s -X PUT "$OS/_cluster/settings" -H 'Content-Type: application/json' -d '{
  "persistent": {
    "plugins.index_state_management.history.number_of_replicas": "0",
    "plugins.index_state_management.history.number_of_shards": "1",
    "plugins.index_state_management.history.rollover_check_period": "12h",
    "plugins.index_state_management.history.rollover_retention_period": "7d"
  }
}' | grep -q '"acknowledged":true' || echo "ism: WARNING cluster-settings PUT was rejected"

# Drop the unassignable replicas on everything that already exists. Idempotent;
# a no-match is fine on a fresh stack. This is what actually turns the cluster
# green, so that "yellow" becomes an alarm signal again.
# Covers the plugin-owned system indices too (alerting-alert-history,
# alerting-alerts, ism-config, job-scheduler-lock): they all default to 1
# replica and are all permanently yellow here for the same reason.
for pat in '.opendistro-*' '.opensearch-*' 'netops-*'; do
  curl -sf -X PUT "$OS/$pat/_settings?expand_wildcards=all" \
    -H 'Content-Type: application/json' \
    -d '{"index":{"number_of_replicas":0}}' >/dev/null 2>&1 || true
done

echo "ism: installing retention policy (delete after ${DAYS}d) ..."

# The header comment used to claim "Idempotent (PUT replaces)". It is not:
# once the policy exists, a bare PUT returns 409 version_conflict and the
# policy is left at its OLD definition. That is how the ism_template patterns
# could stay stuck at 3 lanes while this file said 6 — the classic "the fix is
# in the repo but not in the system" shape (cf. F-51). An UPDATE requires the
# current seq_no/primary_term, so read them first and pass them through.
SEQ=$(curl -s "$OS/_plugins/_ism/policies/netops-retention" 2>/dev/null |
      sed -n 's/.*"_seq_no"[[:space:]]*:[[:space:]]*\([0-9]*\).*/\1/p' | head -1)
PTERM=$(curl -s "$OS/_plugins/_ism/policies/netops-retention" 2>/dev/null |
      sed -n 's/.*"_primary_term"[[:space:]]*:[[:space:]]*\([0-9]*\).*/\1/p' | head -1)
if [ -n "${SEQ:-}" ] && [ -n "${PTERM:-}" ]; then
  PUT_URL="$OS/_plugins/_ism/policies/netops-retention?if_seq_no=${SEQ}&if_primary_term=${PTERM}"
  echo "ism: policy exists (seq_no=$SEQ) — updating in place"
else
  PUT_URL="$OS/_plugins/_ism/policies/netops-retention"
fi

POLICY_RESP=$(curl -s -X PUT "$PUT_URL" \
  -H 'Content-Type: application/json' -d @- <<JSON
{
  "policy": {
    "description": "Delete netops time-series indices after ${DAYS} days.",
    "default_state": "hot",
    "states": [
      { "name": "hot", "actions": [],
        "transitions": [ { "state_name": "delete", "conditions": { "min_index_age": "${DAYS}d" } } ] },
      { "name": "delete", "actions": [ { "delete": {} } ], "transitions": [] }
    ],
    "ism_template": [ { "index_patterns": ${PATTERNS}, "priority": 1 } ]
  }
}
JSON
)
case "$POLICY_RESP" in
  *'"_id":"netops-retention"'*) echo "ism: policy written." ;;
  *) echo "ism: WARNING policy PUT did not take: $POLICY_RESP" >&2 ;;
esac

# Attach to any already-existing matching indices (new ones auto-adopt via the
# ism_template above). Best-effort — a no-match is fine on a fresh stack.
curl -s -X POST "$OS/_plugins/_ism/add/$ADD_PATTERNS" \
  -H 'Content-Type: application/json' -d '{"policy_id":"netops-retention"}' >/dev/null 2>&1 || true

echo "ism: retention policy applied — netops-* indices delete after ${DAYS}d."

# Report coverage instead of asserting it. A lane with policy "null" here is a
# lane that will grow forever; print it so the boot log carries the evidence.
echo "ism: coverage check —"
curl -s "$OS/_plugins/_ism/explain/netops-*" 2>/dev/null | python3 -c '
import json,sys
try: d=json.load(sys.stdin)
except Exception: sys.exit(0)
missing=[k for k,v in d.items() if isinstance(v,dict) and not v.get("index.plugins.index_state_management.policy_id")]
for k in sorted(missing): print("  ism: NO POLICY ->",k)
print("  ism: %d/%d netops indices managed" % (len([k for k,v in d.items() if isinstance(v,dict)])-len(missing),
                                               len([k for k,v in d.items() if isinstance(v,dict)])))
' 2>/dev/null || true
