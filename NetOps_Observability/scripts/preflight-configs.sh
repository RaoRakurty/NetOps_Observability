#!/usr/bin/env bash
#
# preflight-configs.sh — FRESH-LOAD validation for every config-driven service.
#
# Catches the "landmine" class of bug: a committed config that the *running* service
# tolerates in memory but that FAILS a fresh load — so a restart or a clean
# `install.py` on a new server silently brings up a broken pipeline. The canonical
# example was a Vector VRL `error[E651]` that `vector validate` PASSED but the real
# topology builder REJECTED; the aggregator had been up 11 days on an old in-memory
# config, so nothing noticed until a restart dropped the whole syslog pipeline.
#
# Each check loads the COMMITTED config with the service's ACTUAL runtime binary in
# a throwaway container (the stack does NOT need to be running). Exit non-zero if any
# config won't boot.
#
#   scripts/preflight-configs.sh            # validate all
#
# Used by: .github/workflows/config-preflight.yml (CI gate), the optional pre-push
# hook (githooks/pre-push), and install.py (preflight before `docker compose up`).
#
# Image pins below MUST stay in sync with deployment/docker/docker-compose.yml.

set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
D="$ROOT/deployment/docker"
FAIL=0

green(){ printf '  \033[32m✓\033[0m %s\n' "$1"; }
red(){   printf '  \033[31m✗ %s\033[0m\n' "$1" >&2; FAIL=1; }
skip(){  printf '  \033[33m— %s (skipped)\033[0m\n' "$1"; }

if ! command -v docker >/dev/null 2>&1; then
  echo "preflight-configs: docker not available — cannot run the real-runtime checks" >&2
  exit 2
fi

# --- image pins (keep in sync with docker-compose.yml) -----------------------
VECTOR_IMG="timberio/vector:0.40.0-alpine"
NGINX_IMG="nginx:1.27-alpine"
PROM_IMG="prom/prometheus:v2.54.1"   # promtool only (rules.yaml validation); not shipped
VM_IMG="victoriametrics/victoria-metrics:v1.101.0"
SYSLOGNG_IMG="balabit/syslog-ng:4.7.1"

# --- vector: BOOT the config (topology build catches the E651 class) ----------
# `vector validate` is too lenient (it passed the E651). Booting compiles the
# topology: a VRL/topology error prints `error[E…]` and exits BEFORE sinks connect;
# a clean config proceeds to start (we time it out). Stub env + enrichment dir so
# config LOAD reaches the VRL compile.
# INGEST_TOKEN is stubbed like the other secrets below: the ingest sources use
# `${INGEST_TOKEN:?}` so Vector REFUSES TO START without it (F-08 fail-closed
# auth on the previously unauthenticated ingest ports). That is correct at
# runtime, but this check validates that the committed topology COMPILES, not
# that a secret has been provisioned — without the stub every future run fails
# for a reason that has nothing to do with the config being broken.
check_vector(){
  local rel="$1" label="$2"
  [ -f "$ROOT/$rel" ] || { skip "$label (no $rel)"; return; }
  local stub; stub="$(mktemp -d)"
  printf 'identity,tenant_id\n' > "$stub/device_tenant.csv"
  local out
  out="$(timeout 30 docker run --rm --entrypoint vector \
      -e CLICKHOUSE_USER=x -e CLICKHOUSE_PASSWORD=x -e OPENSEARCH_URL=http://x:9200 \
      -e DB_HOST=x -e DB_USER=x -e DB_PASSWORD=x -e REDIS_HOST=x \
      -e INGEST_TOKEN=preflight-stub \
      -v "$ROOT/$rel:/etc/vector/vector.yaml:ro" \
      -v "$stub:/etc/vector/enrichment:ro" \
      "$VECTOR_IMG" --config /etc/vector/vector.yaml 2>&1)"
  rm -rf "$stub"
  if grep -qE 'error\[E[0-9]+\]' <<<"$out"; then
    red "$label — VRL/topology compile error: $(grep -oE 'error\[E[0-9]+\][^
]*' <<<"$out" | head -1)"
  elif grep -qiE 'configuration error|failed to (load|parse|build)' <<<"$out"; then
    # Report a REASON, always. The env-variable filter exists to avoid
    # classifying a benign unset-var notice as a config break, but applying it
    # to the DETAIL once produced "✗ vector-aggregator — " with nothing after
    # the dash: the check correctly failed and told the operator nothing, which
    # is the same silent-failure shape this repo keeps fixing elsewhere. Fall
    # back to the first error-ish line when the filter empties the detail.
    detail="$(grep -iE 'configuration error|failed to' <<<"$out" | grep -viE 'environment variable' | head -1)"
    [ -n "$detail" ] || detail="$(grep -iE 'error|missing|required' <<<"$out" | head -1)"
    [ -n "$detail" ] || detail="(no diagnostic emitted; re-run the docker command in check_vector by hand)"
    red "$label — $detail"
  else
    green "$label (vector topology compiles on a fresh load)"
  fi
}

# --- nginx: `nginx -t` is exactly the runtime reload check (exit code is truth) -
check_nginx(){
  [ -f "$D/nginx/nginx.conf" ] || { skip "nginx (no nginx.conf)"; return; }
  local out rc
  out="$(docker run --rm \
      -v "$D/nginx/nginx.conf:/etc/nginx/nginx.conf:ro" \
      -v "$D/nginx/default.conf:/etc/nginx/conf.d/default.conf:ro" \
      "$NGINX_IMG" nginx -t 2>&1)"; rc=$?
  if [ "$rc" -eq 0 ]; then
    green "nginx (nginx -t)"   # a [warn] (e.g. duplicate MIME) keeps rc=0 — not a landmine
  else
    red "nginx — $(grep -iE 'emerg|\[error\]' <<<"$out" | head -1)"
  fi
}

# --- metrics: VM validates its scrape config; promtool validates rules.yaml ---
# (Prometheus the SERVICE is gone — #97 footprint pass — but promtool remains
# the best build-time validator for the Prometheus-rules-format file the Go
# alert engine consumes. Dev/CI-only pull; the image ships in no bundle.)
check_metrics_configs(){
  [ -f "$ROOT/src/config/vmscrape.yml" ] || { skip "victoria (no vmscrape.yml)"; return; }
  local out rc
  out="$(docker run --rm \
      -v "$ROOT/src/config/vmscrape.yml:/etc/victoria/vmscrape.yml:ro" \
      "$VM_IMG" -promscrape.config=/etc/victoria/vmscrape.yml -dryRun 2>&1)"; rc=$?
  if [ "$rc" -eq 0 ]; then
    green "victoria (-promscrape.config -dryRun)"
  else
    red "victoria scrape config — $(grep -iE 'cannot|error|invalid' <<<"$out" | head -1)"
  fi
  out="$(docker run --rm --entrypoint promtool \
      -v "$ROOT/src/config/rules.yaml:/etc/prometheus/rules.yaml:ro" \
      "$PROM_IMG" check rules /etc/prometheus/rules.yaml 2>&1)"; rc=$?
  if [ "$rc" -eq 0 ]; then
    green "rules.yaml (promtool check rules)"
  else
    red "rules.yaml — $(grep -iE 'FAILED|error' <<<"$out" | head -1)"
  fi
}

# --- syslog-ng: -s is the syntax-only config check (exit code is truth) -------
check_syslogng(){
  [ -f "$D/syslog-ng/syslog-ng.conf" ] || { skip "syslog-ng (no config)"; return; }
  local out rc
  # --entrypoint: the balabit image's entrypoint IS syslog-ng, so we pass only args.
  out="$(docker run --rm --entrypoint syslog-ng \
      -v "$D/syslog-ng/syslog-ng.conf:/etc/syslog-ng/syslog-ng.conf:ro" \
      "$SYSLOGNG_IMG" -s -f /etc/syslog-ng/syslog-ng.conf 2>&1)"; rc=$?
  # rc=0 on valid syntax; the "capability management disabled" line is a sandbox
  # warning (rc stays 0), not a config error.
  if [ "$rc" -eq 0 ]; then
    green "syslog-ng (syntax check)"
  else
    red "syslog-ng — $(grep -iE 'error|parse' <<<"$out" | grep -viE 'capabilit' | head -1)"
  fi
}

echo "=== config preflight: fresh-load every committed service config ==="
check_vector "deployment/docker/vector/vector.yaml"        "vector-aggregator"
check_vector "deployment/docker/vector-router/vector.yaml" "vector-router"
check_nginx
check_metrics_configs
check_syslogng

echo ""
if [ "$FAIL" -ne 0 ]; then
  echo "preflight-configs: FAILED — a committed config will not survive a fresh load (see ✗ above)." >&2
  echo "Fix it before shipping: a restart or a clean install would break that service." >&2
  exit 1
fi
echo "preflight-configs: all configs boot clean on a fresh load."
