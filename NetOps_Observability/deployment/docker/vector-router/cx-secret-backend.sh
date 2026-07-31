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

# Refuse to run unauthenticated rather than fetching key material over an
# anonymous request. Mirrors the fail-closed posture of the endpoint itself.
if [ -z "$INGEST_TOKEN" ]; then
  echo '{"error":"INGEST_TOKEN is not set; refusing to fetch sealing keys unauthenticated"}' >&2
  # Emit a well-formed reply so Vector reports a clean secret error rather than
  # a parse failure, which is far harder to diagnose in a container log.
  echo '{}'
  exit 1
fi

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

  body="$(curl -fsS --max-time 10 \
      -u "${INGEST_USER}:${INGEST_TOKEN}" \
      "${API}/internal/sealing/edge-keys?tenant=${tenant}" 2>/dev/null || true)"

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
