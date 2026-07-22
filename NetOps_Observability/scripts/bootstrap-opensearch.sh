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
#
# F-06/F-15/F-53 (2026-07-21): this list used to be HARD-CODED to the three
# original lanes, so adding a template to index-templates.json silently did
# nothing — which is how snmptrap and cloudlogs ended up 100% dynamically
# mapped (and snmptrap permanently yellow) while a template file sat in the
# repo looking authoritative. Enumerate the file instead: the JSON is the
# single source of truth for which lanes have a declared schema.
TEMPLATE_NAMES=$(python3 -c "
import json
print(' '.join(k for k in json.load(open('$TEMPLATES'))['templates']))
")
echo "Templates declared in index-templates.json: $TEMPLATE_NAMES"

for name in $TEMPLATE_NAMES; do
    # Strip _-prefixed documentation keys: OpenSearch's _index_template parser
    # rejects unknown fields outright (400 x_content_parse_exception), and the
    # old `curl -sf` swallowed that into an empty response — a template could
    # fail to apply while the script printed nothing and exited 0.
    body=$(python3 -c "
import json
d = json.load(open('$TEMPLATES'))
t = {k: v for k, v in d['templates']['$name'].items() if not k.startswith('_')}
print(json.dumps(t))
")
    url="${OPENSEARCH_URL:-http://localhost:9200}/_index_template/$name"
    echo "→ Applying template: $name"

    if [[ $USE_HOST -eq 1 ]]; then
        resp=$(curl -s -X PUT "$url" \
            -H 'Content-Type: application/json' \
            -d "$body" 2>&1) || resp="$(echo "$resp"; echo "(curl exit=$?)")"
    else
        resp=$(docker compose -f "$COMPOSE_DIR/docker-compose.yml" exec -T opensearch \
            curl -s -X PUT "http://localhost:9200/_index_template/$name" \
            -H 'Content-Type: application/json' \
            -d "$body" 2>&1) || resp="$(echo "$resp"; echo "(curl exit=$?)")"
    fi

    # Try to pretty-print as JSON; fall back to raw on parse error.
    echo "$resp" | python3 -m json.tool 2>/dev/null || echo "$resp"
    case "$resp" in *'"acknowledged":true'*|*'"acknowledged": true'*) ;;
      *) echo "!! template $name was NOT applied — see the response above" >&2; FAILED=1 ;;
    esac
    echo
done

if [[ "${FAILED:-0}" -ne 0 ]]; then
  echo "One or more templates FAILED to apply." >&2
  exit 1
fi
echo "Done."
