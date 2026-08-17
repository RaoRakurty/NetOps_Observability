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
# Used by: .github/workflows/fresh-install-integrity.yml (via scripts/preflight.sh)
# — there is no config-preflight.yml workflow — and the optional pre-push
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
  # $3 (optional): a SECOND config file the tier loads at runtime — the router's
  # generated processor hooks (item 121). The base config's sinks reference
  # transforms defined there, so validating the base alone would always fail.
  local rel="$1" label="$2" extra="${3:-}"
  [ -f "$ROOT/$rel" ] || { skip "$label (no $rel)"; return; }
  local stub; stub="$(mktemp -d)"
  printf 'identity,tenant_id\n' > "$stub/device_tenant.csv"
  local -a extra_mounts=() extra_flags=()
  if [ -n "$extra" ]; then
    if [ ! -f "$ROOT/$extra" ]; then
      red "$label — companion config $extra is missing (the router cannot boot without it)"
      rm -rf "$stub"
      return
    fi
    extra_mounts=(-v "$ROOT/$extra:/etc/vector/processors/processors.yaml:ro")
    extra_flags=(--config /etc/vector/processors/processors.yaml)
  fi
  local out
  out="$(timeout 30 docker run --rm --entrypoint vector \
      -e CLICKHOUSE_USER=x -e CLICKHOUSE_PASSWORD=x -e OPENSEARCH_URL=http://x:9200 \
      -e DB_HOST=x -e DB_USER=x -e DB_PASSWORD=x -e REDIS_HOST=x \
      -e INGEST_TOKEN=preflight-stub \
      -e INGEST_TOKEN_TRAPS=preflight-stub \
      -e INGEST_TOKEN_PROBES=preflight-stub \
      -e INGEST_TOKEN_METRICS=preflight-stub \
      -e INGEST_TOKEN_BUS=preflight-stub \
      -v "$ROOT/$rel:/etc/vector/vector.yaml:ro" \
      -v "$stub:/etc/vector/enrichment:ro" \
      "${extra_mounts[@]}" \
      "$VECTOR_IMG" --config /etc/vector/vector.yaml "${extra_flags[@]}" 2>&1)"
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

# --- nginx mTLS variant: same check, deploy-time file set (Security v1, #18) --
# An mTLS deployment mounts default-mtls.conf as default.conf plus the
# api-mtls.conf include and the CA-minted certs. The include's proxy_ssl_*
# files are loaded at CONFIG PARSE, so `nginx -t` needs cert material to exist;
# a throwaway self-signed pair stands in for the runtime SVIDs — this validates
# that the committed TOPOLOGY fresh-loads, not that a CA has been provisioned
# (same reasoning as the stubbed Vector secrets above). Guards the exact
# landmine shipped 2026-08-04: default.conf hard-included a file only a
# gitignored override provided, so a clean install could not boot nginx.
check_nginx_mtls(){
  [ -f "$D/nginx/default-mtls.conf" ] || { skip "nginx-mtls (no default-mtls.conf)"; return; }
  if ! command -v openssl >/dev/null 2>&1; then
    # Visible, not fatal: only this one check needs openssl; CI has it.
    skip "nginx-mtls (openssl not on PATH — cannot mint stub certs)"; return
  fi
  local tls out rc
  tls="$(mktemp -d)" || { red "nginx-mtls — mktemp failed"; return; }
  mkdir -p "$tls/nginx"
  # Stub SVID + trust bundle (contents irrelevant; parse-time existence + parseability).
  out="$(openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=preflight-stub" \
      -keyout "$tls/nginx/nginx.key" -out "$tls/nginx/nginx.crt" 2>&1)" || {
    red "nginx-mtls — stub cert mint failed: $(head -1 <<<"$out")"; rm -rf "$tls"; return; }
  cp "$tls/nginx/nginx.crt" "$tls/ca.pem"
  chmod -R a+rX "$tls"   # image may run nginx -t as non-root
  out="$(docker run --rm \
      -v "$D/nginx/nginx.conf:/etc/nginx/nginx.conf:ro" \
      -v "$D/nginx/default-mtls.conf:/etc/nginx/conf.d/default.conf:ro" \
      -v "$D/nginx/api-mtls.conf.example:/etc/nginx/conf.d/api-mtls.conf:ro" \
      -v "$tls:/etc/nginx/tls:ro" \
      "$NGINX_IMG" nginx -t 2>&1)"; rc=$?
  rm -rf "$tls"
  if [ "$rc" -eq 0 ]; then
    green "nginx-mtls (default-mtls.conf + api-mtls include, nginx -t)"
  else
    red "nginx-mtls — $(grep -iE 'emerg|\[error\]' <<<"$out" | head -1)"
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
  # The mTLS variant is what a TLS-enabled deployment ACTUALLY runs — leaving
  # it unvalidated meant the live lab's scrape config had no gate at all
  # (found 2026-08-05 while converting the correlation job). tls_config paths
  # resolve under /etc/victoria/tls at runtime; -dryRun does not stat them.
  if [ -f "$ROOT/src/config/vmscrape-mtls.yml" ]; then
    out="$(docker run --rm \
        -v "$ROOT/src/config/vmscrape-mtls.yml:/etc/victoria/vmscrape.yml:ro" \
        "$VM_IMG" -promscrape.config=/etc/victoria/vmscrape.yml -dryRun 2>&1)"; rc=$?
    if [ "$rc" -eq 0 ]; then
      green "victoria mTLS variant (vmscrape-mtls.yml -dryRun)"
    else
      red "victoria mTLS scrape config — $(grep -iE 'cannot|error|invalid' <<<"$out" | head -1)"
    fi
  fi
  out="$(docker run --rm --entrypoint promtool \
      -v "$ROOT/src/config/rules.yaml:/etc/prometheus/rules.yaml:ro" \
      "$PROM_IMG" check rules /etc/prometheus/rules.yaml 2>&1)"; rc=$?
  if [ "$rc" -eq 0 ]; then
    green "rules.yaml (promtool check rules)"
  else
    red "rules.yaml — $(grep -iE 'FAILED|error' <<<"$out" | head -1)"
  fi
  # rules-scale-slo.yaml is loaded by vmalert via a SECOND -rule= flag and was
  # never validated here — it could ship malformed or with an expression that
  # can never fire, and nothing would say so. Same bar as rules.yaml.
  out="$(docker run --rm --entrypoint promtool \
      -v "$ROOT/src/config/rules-scale-slo.yaml:/etc/prometheus/rules-scale-slo.yaml:ro" \
      "$PROM_IMG" check rules /etc/prometheus/rules-scale-slo.yaml 2>&1)"; rc=$?
  if [ "$rc" -eq 0 ]; then
    green "rules-scale-slo.yaml (promtool check rules)"
  else
    red "rules-scale-slo.yaml — $(grep -iE 'FAILED|error' <<<"$out" | head -1)"
  fi
  # Alert-rule UNIT tests (SEC-020.2): synthetic series must make each
  # security rule fire (and the all-clear must not). `check rules` only
  # proves the file parses — an expression that drifted off the emitted
  # vocabulary still "checks" while it can never fire.
  local tf
  for tf in "$ROOT"/src/config/rules-tests/*.test.yaml; do
    [ -f "$tf" ] || { skip "rule unit tests (no rules-tests/*.test.yaml)"; break; }
    # BOTH rule files are mounted for every test file, so a *.test.yaml may
    # target either via its own `rule_files:` list. Mounting only rules.yaml
    # silently made scale-slo rules untestable: promtool resolves no rules for
    # the alertname and reports "no alerts found" as a PASS.
    out="$(docker run --rm --entrypoint promtool \
        -v "$ROOT/src/config/rules.yaml:/etc/prometheus/rules.yaml:ro" \
        -v "$ROOT/src/config/rules-scale-slo.yaml:/etc/prometheus/rules-scale-slo.yaml:ro" \
        -v "$tf:/etc/prometheus/tests.yaml:ro" \
        "$PROM_IMG" test rules /etc/prometheus/tests.yaml 2>&1)"; rc=$?
    if [ "$rc" -eq 0 ]; then
      green "rule unit tests ($(basename "$tf"))"
    else
      red "rule unit tests $(basename "$tf") — $(grep -iE 'FAILED|error' <<<"$out" | head -3 | tr '\n' ' ')"
    fi
  done
}

# --- syslog-ng: -s is the syntax-only config check (exit code is truth) -------
# BOTH top-level variants are validated (F-1 added syslog-ng-tls.conf), each
# with the SAME directory mount the compose service uses (F-51), so the shared
# core.conf @include resolves exactly as it does at runtime. A variant that is
# valid alone but missing from the dir would ship a container that cannot boot.
check_syslogng(){
  [ -d "$D/syslog-ng" ] || { skip "syslog-ng (no config dir)"; return; }
  local conf out rc stub
  # The tls() block's file arguments are EXISTENCE-checked at parse time
  # (verified: "File /tls/ca.pem not found" is a parse error; empty files
  # pass). Same stub idiom as check_vector: this validates that the committed
  # config PARSES, not that certs are provisioned.
  stub="$(mktemp -d)"
  : > "$stub/ca.pem"; : > "$stub/syslog-ng.crt"; : > "$stub/syslog-ng.key"
  for conf in syslog-ng.conf syslog-ng-tls.conf; do
    if [ ! -f "$D/syslog-ng/$conf" ]; then
      red "syslog-ng — $conf missing (both variants are tracked; compose.tls.yml boots the tls one)"
      continue
    fi
    # --entrypoint: the balabit image's entrypoint IS syslog-ng, so we pass only args.
    out="$(docker run --rm --entrypoint syslog-ng \
        -v "$D/syslog-ng:/etc/syslog-ng/conf.d:ro" \
        -v "$stub/ca.pem:/tls/ca.pem:ro" \
        -v "$stub:/tls/svid:ro" \
        "$SYSLOGNG_IMG" -s -f "/etc/syslog-ng/conf.d/$conf" 2>&1)"; rc=$?
    # rc=0 on valid syntax; the "capability management disabled" line is a sandbox
    # warning (rc stays 0), not a config error.
    if [ "$rc" -eq 0 ]; then
      green "syslog-ng ($conf syntax check)"
    else
      red "syslog-ng $conf — $(grep -iE 'error|parse' <<<"$out" | grep -viE 'capabilit' | head -1)"
    fi
  done
  rm -rf "$stub"
}

echo "=== config preflight: fresh-load every committed service config ==="
check_vector "deployment/docker/vector/vector.yaml"        "vector-aggregator"
# The router loads TWO configs at runtime: base + the generated processor hooks
# (item 121). Validate with the checked-in no-op default standing in for the
# generated file — exactly what install.py seeds on a cold start.
check_vector "deployment/docker/vector-router/vector.yaml" "vector-router" \
             "deployment/docker/vector-router/processors-default.yaml"
check_nginx
check_nginx_mtls
check_metrics_configs
check_syslogng

echo ""
if [ "$FAIL" -ne 0 ]; then
  echo "preflight-configs: FAILED — a committed config will not survive a fresh load (see ✗ above)." >&2
  echo "Fix it before shipping: a restart or a clean install would break that service." >&2
  exit 1
fi
echo "preflight-configs: all configs boot clean on a fresh load."
