#!/usr/bin/env bash
#
# Applies index templates to a running OpenSearch cluster.
#
# OpenSearch in the default docker-compose isn't port-mapped to the
# host, so we run curl from INSIDE the opensearch container (via
# docker compose exec) where `localhost:9200` is reachable.
#
# Override by setting OPENSEARCH_URL to a host-reachable endpoint and
# we'll use that instead — useful if you've exposed 9200 or run
# OpenSearch outside compose.
#
# Idempotent: re-running is safe (PUT _index_template just overwrites).

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
COMPOSE_DIR="$ROOT/deployment/docker"
TEMPLATES="$COMPOSE_DIR/opensearch/index-templates.json"

if [[ ! -f "$TEMPLATES" ]]; then
  echo "missing $TEMPLATES" >&2
  exit 1
fi

# Decide whether to run curl on the host (if OPENSEARCH_URL is set and
# the cluster is reachable) or via `docker compose exec` inside the
# opensearch container.
USE_HOST=0
if [[ -n "${OPENSEARCH_URL:-}" ]]; then
    if curl -sf --max-time 3 "${OPENSEARCH_URL}/_cluster/health" >/dev/null 2>&1; then
        USE_HOST=1
        echo "Using OPENSEARCH_URL=$OPENSEARCH_URL"
    else
        echo "OPENSEARCH_URL set but unreachable from host — falling back to docker exec"
    fi
fi

# Helper that wraps either: curl from the host, OR curl-via-docker-exec.
os_curl() {
    if [[ $USE_HOST -eq 1 ]]; then
        curl "$@"
    else
        # shift the user-supplied args after we set the URL ourselves
        docker compose -f "$COMPOSE_DIR/docker-compose.yml" exec -T opensearch \
            curl "$@"
    fi
}

# Wait for the cluster to be reachable.
echo "Waiting for OpenSearch to respond..."
for _ in $(seq 1 30); do
    if [[ $USE_HOST -eq 1 ]]; then
        if curl -sf --max-time 3 "${OPENSEARCH_URL}/_cluster/health" >/dev/null 2>&1; then break; fi
    else
        if docker compose -f "$COMPOSE_DIR/docker-compose.yml" exec -T opensearch \
            curl -sf --max-time 3 http://localhost:9200/_cluster/health >/dev/null 2>&1; then break; fi
    fi
    sleep 2
done

# Apply each template.
for name in netops-applogs netops-syslog netops-flows; do
    body=$(python3 -c "
import json
d = json.load(open('$TEMPLATES'))
print(json.dumps(d['templates']['$name']))
")
    url="${OPENSEARCH_URL:-http://localhost:9200}/_index_template/$name"
    echo "→ Applying template: $name"

    if [[ $USE_HOST -eq 1 ]]; then
        resp=$(curl -sf -X PUT "$url" \
            -H 'Content-Type: application/json' \
            -d "$body" 2>&1) || resp="$(echo "$resp"; echo "(curl exit=$?)")"
    else
        resp=$(docker compose -f "$COMPOSE_DIR/docker-compose.yml" exec -T opensearch \
            curl -sf -X PUT "http://localhost:9200/_index_template/$name" \
            -H 'Content-Type: application/json' \
            -d "$body" 2>&1) || resp="$(echo "$resp"; echo "(curl exit=$?)")"
    fi

    # Try to pretty-print as JSON; fall back to raw on parse error.
    echo "$resp" | python3 -m json.tool 2>/dev/null || echo "$resp"
    echo
done

echo "Done."
