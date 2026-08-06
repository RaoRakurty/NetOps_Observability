#!/bin/sh
# cx-secret-backend.sh — Vector `exec` secret backend for Sealed Fields.
#
# Vector runs this at CONFIG LOAD, writes a JSON request on stdin, and expects a
# JSON reply on stdout. The keys it asks for never touch disk: Vector holds them
# in memory for the life of the process, which is the whole reason sealing can
# put key material at the edge at all.
#
#   stdin :  {"version":"1.0","secrets":["cxseal.<tenant>","cxmac.<tenant>", ...]}
#   stdout:  {"cxseal.<tenant>":{"value":"<base64>","error":null}, ...}
#
# A secret that cannot be resolved is returned with a non-null "error", which
# makes Vector refuse to load the config. That is deliberate and it is the
# safest failure available: a router that loaded WITHOUT a tenant's seal key
# would run the pipeline with sealing silently absent, writing the very values
# the operator believes are protected straight into storage. Failing to start is
# loud, recoverable, and cannot leak.
#
# §16 applies to this file: it is unattended production software on the path
# customer data flows through.

set -eu

API="${SEALING_API_URL:-http://api:8080}"
INGEST_USER="${INGEST_USER:-netops-ingest}"
INGEST_TOKEN="${INGEST_TOKEN:-}"
# SEC-018.1: on a TLS deployment the fetch authenticates with the router's
# OWN workload certificate — the api's edge-key endpoint accepts only that
# identity, so a stolen shared token can no longer fetch any tenant's keys.
SEALING_TLS_CA="${SEALING_TLS_CA:-}"
SEALING_TLS_CRT="${SEALING_TLS_CRT:-}"
SEALING_TLS_KEY="${SEALING_TLS_KEY:-}"

# Authentication mode follows the API scheme, fail-closed in both:
#   https:// → mutual TLS, all three cert paths REQUIRED (never -k, never a
#              downgrade to token-over-tls: key material rides workload
#              identity or it does not ride);
#   http://  → the stack-internal token, exactly the documented plaintext
#              baseline this script always had.
case "$API" in
  https://*)
    if [ -z "$SEALING_TLS_CA" ] || [ -z "$SEALING_TLS_CRT" ] || [ -z "$SEALING_TLS_KEY" ]; then
      echo '{"error":"SEALING_API_URL is https but SEALING_TLS_CA/CRT/KEY are not all set; refusing to fetch key material without mutual TLS"}' >&2
      # Well-formed reply → Vector reports a clean secret error, not a parse
      # failure (far harder to diagnose in a container log).
      echo '{}'
      exit 1
    fi
    for f in "$SEALING_TLS_CA" "$SEALING_TLS_CRT" "$SEALING_TLS_KEY"; do
      if [ ! -r "$f" ]; then
        echo "{\"error\":\"sealing TLS material not readable: $f\"}" >&2
        echo '{}'
        exit 1
      fi
    done
    ;;
  *)
    # Refuse to run unauthenticated rather than fetching key material over an
    # anonymous request. Mirrors the fail-closed posture of the endpoint.
    if [ -z "$INGEST_TOKEN" ]; then
      echo '{"error":"INGEST_TOKEN is not set; refusing to fetch sealing keys unauthenticated"}' >&2
      echo '{}'
      exit 1
    fi
    ;;
esac

# fetch <tenant>: one key-fetch against the API with the mode's credential.
# Non-2xx/transport failure yields an empty body, which the caller turns into
# a per-secret non-null error — Vector then refuses the config (see header).
fetch() {
  case "$API" in
    https://*)
      curl -fsS --max-time 10 \
        --cacert "$SEALING_TLS_CA" --cert "$SEALING_TLS_CRT" --key "$SEALING_TLS_KEY" \
        "${API}/internal/sealing/edge-keys?tenant=$1" 2>/dev/null || true
      ;;
    *)
      curl -fsS --max-time 10 \
        -u "${INGEST_USER}:${INGEST_TOKEN}" \
        "${API}/internal/sealing/edge-keys?tenant=$1" 2>/dev/null || true
      ;;
  esac
}

request="$(cat)"

# Extract the requested secret names. There is no jq in the vector image, so
# this is a deliberate minimal parse of the DOCUMENTED request shape rather than
# a general JSON reader. Names are matched against a strict character class, so
# nothing from the request can escape into the shell below.
names="$(printf '%s' "$request" \
  | tr ',' '\n' \
  | sed -n 's/.*"\(cxseal\.[A-Za-z0-9_-]\{1,128\}\)".*/\1/p; s/.*"\(cxmac\.[A-Za-z0-9_-]\{1,128\}\)".*/\1/p' \
  | sort -u)"

printf '{'
first=1
for name in $names; do
  backend="${name%%.*}"   # cxseal | cxmac
  tenant="${name#*.}"

  body="$(fetch "$tenant")"

  case "$backend" in
    cxseal) field='seal_key' ;;
    cxmac)  field='mac_key'  ;;
    *)      field=''         ;;
  esac

  value=''
  if [ -n "$body" ] && [ -n "$field" ]; then
    # Whitespace-tolerant: Go's encoder emits no space after the colon, but a
    # key-delivery path must not break if that ever changes or a proxy reformats.
    value="$(printf '%s' "$body" \
      | sed -n 's/.*"'"$field"'"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')"
  fi

  [ "$first" -eq 1 ] || printf ','
  first=0
  if [ -n "$value" ]; then
    printf '"%s":{"value":"%s","error":null}' "$name" "$value"
  else
    # Vector treats this as fatal and refuses the config — see the header.
    printf '"%s":{"value":null,"error":"could not resolve sealing key for %s"}' "$name" "$tenant"
  fi
done
printf '}\n'
