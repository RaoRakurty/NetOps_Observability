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
PATTERNS='["netops-applogs-*","netops-syslog-*","netops-flows-*"]'

echo "ism: waiting for OpenSearch at $OS ..."
until curl -sf "$OS/_cluster/health" >/dev/null 2>&1; do sleep 5; done

echo "ism: installing retention policy (delete after ${DAYS}d) ..."
curl -sf -X PUT "$OS/_plugins/_ism/policies/netops-retention" \
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
echo ""

# Attach to any already-existing matching indices (new ones auto-adopt via the
# ism_template above). Best-effort — a no-match is fine on a fresh stack.
curl -s -X POST "$OS/_plugins/_ism/add/netops-applogs-*,netops-syslog-*,netops-flows-*" \
  -H 'Content-Type: application/json' -d '{"policy_id":"netops-retention"}' >/dev/null 2>&1 || true

echo "ism: retention policy applied — netops-* indices delete after ${DAYS}d."
