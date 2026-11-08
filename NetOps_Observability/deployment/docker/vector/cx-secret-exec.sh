#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

# cx-secret-exec.sh — Vector `exec` secret backend for FILE-MOUNTED service
# credentials (tracker 367 layer 1: no secrets in URLs or container env).
#
# Vector 0.40 has exactly one pluggable secret backend, `exec`: at every config
# (re)load it runs this script, writes a JSON request on stdin and reads a JSON
# reply on stdout. The credential therefore lives in a read-only bind-mounted
# file rendered by scripts/install.py from .env — never in `docker inspect`,
# never in vector.yaml, never in an argv. A rotated file is picked up at the
# next config reload (the cx-enrichment-reload.sh wrapper SIGHUPs vector), with
# no container recreate.
#
# THE WIRE CONTRACT (the one cx-secret-backend.sh verified against 0.40.0):
# Vector STRIPS the backend name, so `SECRET[vmauth.vector]` arrives as the
# bare key "vector":
#
#   stdin :  {"version":"1.0","secrets":["vector", ...]}
#   stdout:  {"vector":{"value":"<secret>","error":null}, ...}
#
# Key -> file: "$1/<key>/password", where $1 is the secret ROOT set per backend
# in vector.yaml's `secret:` block (e.g. /run/secrets/vmauth). Keys are matched
# against a strict character class, so nothing from the request can name a
# path outside that root.
#
# Failure is FAIL-CLOSED by design: an unresolvable key is answered with a
# non-null "error", which makes Vector refuse the config (or, on a reload, keep
# the previous topology). A sink silently sending no credential — or a stale
# placeholder — is the defect this replaces, not a fallback.
#
# The value is validated exactly like the Go reader (internal/credfile): one
# trailing newline trimmed; empty, > 1 KiB or non-printable-ASCII refused.
# Secret values are NEVER written to stderr; diagnostics name the key only.
#
# §16 applies (scripts/CLAUDE.md): unattended production software on the path
# customer data flows through. Runs under busybox ash in timberio/vector:alpine.

set -eu
export LC_ALL=C

MAX_BYTES=1024
ROOT="${1:-}"

reply_error() {  # $1 = message for stderr; the reply stays well-formed JSON
    printf 'cx-secret-exec: %s\n' "$1" >&2
    printf '{}\n'
    exit 1
}

case "$ROOT" in
    /*) ;;
    *)  # $1 below is literal prose in the message, not an expansion.
        # shellcheck disable=SC2016
        reply_error 'secret root argument missing or relative: expected an absolute directory as $1 (set in vector.yaml secret.<backend>.command)' ;;
esac
[ -d "$ROOT" ] || reply_error "secret root ${ROOT} is not a directory (is the data/secrets bind mount missing?)"

NL='
'

# read_secret <file>: on success sets VALUE; on refusal sets REASON (key-free,
# value-free text). Called WITHOUT a command substitution so both survive.
REASON=''
VALUE=''
read_secret() {
    f="$1"
    VALUE=''
    if [ ! -f "$f" ] || [ ! -r "$f" ]; then
        REASON='credential file missing or unreadable'
        return 1
    fi
    size="$(wc -c < "$f" | tr -d ' ')"
    case "$size" in
        ''|*[!0-9]*) REASON='credential file size unreadable'; return 1 ;;
    esac
    # +1: the one trailing newline the format allows does not count.
    if [ "$size" -gt $((MAX_BYTES + 1)) ]; then
        REASON="credential file larger than ${MAX_BYTES} bytes"
        return 1
    fi
    # Command substitution strips EVERY trailing newline; the sentinel keeps
    # them so exactly one can be trimmed (matches internal/credfile).
    v="$(cat "$f"; printf x)"
    v="${v%x}"
    v="${v%"$NL"}"
    if [ -z "$v" ]; then
        REASON='credential file is empty'
        return 1
    fi
    if [ "${#v}" -gt "$MAX_BYTES" ]; then
        REASON="credential longer than ${MAX_BYTES} bytes"
        return 1
    fi
    case "$v" in
        *[!\ -~]*) REASON='credential contains non-printable characters'; return 1 ;;
    esac
    VALUE="$v"
}

# Bounded read: the documented request is a few dozen bytes.
request="$(head -c 65536)"

# Minimal parse of the DOCUMENTED request shape (no jq in the image). A legacy
# fully-qualified "vmauth." prefix is tolerated and stripped.
names="$(printf '%s' "$request" \
    | sed -n 's/.*"secrets"[[:space:]]*:[[:space:]]*\[\(.*\)\].*/\1/p' \
    | tr ',' '\n' \
    | sed -n 's/^[[:space:]]*"\(vmauth\.\)\{0,1\}\([A-Za-z0-9_-]\{1,64\}\)"[[:space:]]*$/\2/p' \
    | sort -u)"

[ -n "$names" ] || reply_error 'request named no valid secret keys'

printf '{'
first=1
failed=0
for key in $names; do
    [ "$first" -eq 1 ] || printf ','
    first=0
    if read_secret "$ROOT/$key/password"; then
        # Printable ASCII only past read_secret, so escaping \ and " is a
        # complete JSON string encoding.
        esc="$(printf '%s' "$VALUE" | sed 's/\\/\\\\/g; s/"/\\"/g')"
        printf '"%s":{"value":"%s","error":null}' "$key" "$esc"
    else
        failed=$((failed + 1))
        printf 'cx-secret-exec: key %s refused: %s\n' "$key" "$REASON" >&2
        printf '"%s":{"value":null,"error":"%s"}' "$key" "$REASON"
    fi
done
printf '}\n'
# Non-zero exit as well as the per-key error: a degraded run is loud (§16.1).
[ "$failed" -eq 0 ] || exit 1
