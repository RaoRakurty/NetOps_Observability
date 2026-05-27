#!/usr/bin/env bash
#
# Applies index templates to a running OpenSearch cluster. Safe to run
# multiple times — template puts are idempotent.

set -euo pipefail

OS_URL="${OPENSEARCH_URL:-http://localhost:9200}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TEMPLATES="${ROOT}/deployment/docker/opensearch/index-templates.json"

if [[ ! -f "$TEMPLATES" ]]; then
  echo "missing $TEMPLATES" >&2
  exit 1
fi

echo "Waiting for ${OS_URL}..."
for _ in $(seq 1 30); do
  if curl -sf "${OS_URL}/_cluster/health" >/dev/null; then break; fi
  sleep 2
done

for name in netops-applogs netops-syslog netops-flows; do
  body=$(python3 -c "import json,sys; d=json.load(open('$TEMPLATES')); print(json.dumps(d['templates']['$name']))")
  echo "→ Applying template: $name"
  curl -sf -X PUT "${OS_URL}/_index_template/${name}" \
       -H 'Content-Type: application/json' \
       -d "$body" \
       | python3 -c "import json,sys; print(json.dumps(json.load(sys.stdin), indent=2))"
done

echo "Done."
