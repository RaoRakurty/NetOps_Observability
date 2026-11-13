#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

# cx-credfp-set.sh — Vector `exec` secret backend that serves the api's
# published SNMP-community fingerprint set to the aggregator (tracker 387 (a),
# owner decision D1: a community is never stored).
#
# The api writes one "scope/fingerprint" line per community it holds
# (internal/credfp; scope is a tenant id or "*", the fingerprint 43 URL-safe
# base64 characters) to the shared enrichment directory. The aggregator's
# syslog lane matches the user slot of ConfD's session lines against it. This
# is delivered as a "secret" only because Vector 0.40's `exec` backend is the
# one mechanism that injects a value into the config at load AND is re-run on
# every reload (the cx-enrichment-reload.sh wrapper SIGHUPs vector when the
# file changes). A fingerprint is not secret: without the key (served by
# cx-secret-exec.sh from its own 0400 file) it is an opaque 256-bit string.
#
# THE WIRE CONTRACT (as cx-secret-exec.sh, verified against 0.40.0):
#
#   stdin :  {"version":"1.0","secrets":["current"]}
#   stdout:  {"current":{"value":",<scope>/<fp>,<scope>/<fp>,","error":null}}
#
# The value is comma-framed on both ends so the VRL can test membership with
# one literal substring search: contains(set, "," + scope + "/" + fp + ",").
#
# FAILURE IS DELIBERATELY NOT FAIL-CLOSED HERE, unlike the key backend:
#   * a MISSING file (a fresh install before the api's first publish, or an
#     api without the key) is an EMPTY set: the lines whose shape alone proves
#     a community are still scrubbed, and refusing the config would stop ALL
#     syslog ingest to protect the remainder;
#   * a malformed line (only a corrupted or tampered file has one) is skipped
#     and counted on stderr, never served: it could not match anything anyway.
# Both are said on stderr, which is vector's log (§16.1: never silent).
#
# §16 applies (scripts/CLAUDE.md). Runs under busybox ash in timberio/vector:alpine.

set -eu
export LC_ALL=C

# The bound internal/credfp.MaxLines publishes at most.
MAX_LINES=16384
FILE="${1:-}"

reply_error() {  # $1 = message for stderr; the reply stays well-formed JSON
    printf 'cx-credfp-set: %s\n' "$1" >&2
    printf '{}\n'
    exit 1
}

case "$FILE" in
    /*) ;;
    *)  # $1 below is literal prose in the message, not an expansion.
        # shellcheck disable=SC2016
        reply_error 'set file argument missing or relative: expected an absolute path as $1 (set in vector.yaml secret.credfpset.command)' ;;
esac

# Bounded read: the documented request is a few dozen bytes.
request="$(head -c 65536)"

names="$(printf '%s' "$request" \
    | sed -n 's/.*"secrets"[[:space:]]*:[[:space:]]*\[\(.*\)\].*/\1/p' \
    | tr ',' '\n' \
    | sed -n 's/^[[:space:]]*"\(credfpset\.\)\{0,1\}\([A-Za-z0-9_-]\{1,64\}\)"[[:space:]]*$/\2/p' \
    | sort -u)"

[ -n "$names" ] || reply_error 'request named no valid secret keys'

value=','
if [ ! -e "$FILE" ]; then
    printf 'cx-credfp-set: %s not published yet: serving an EMPTY community set (only the certain-by-shape lines are scrubbed until the api publishes)\n' "$FILE" >&2
elif [ ! -r "$FILE" ]; then
    reply_error "${FILE} exists but is unreadable (check its mode: the api writes it 0644)"
else
    total="$(wc -l < "$FILE" | tr -d ' ')"
    # grep exits 1 when nothing matches, which is an empty set, not a failure;
    # any other status is a real read error and is reported.
    set +e
    good="$(grep -E '^(\*|[a-z0-9_-]{1,128})/[A-Za-z0-9_-]{43}$' "$FILE")"
    rc=$?
    set -e
    if [ "$rc" -gt 1 ]; then
        reply_error "reading ${FILE} failed (grep status ${rc})"
    fi
    count=0
    if [ -n "$good" ]; then
        count="$(printf '%s\n' "$good" | wc -l | tr -d ' ')"
    fi
    if [ "$count" -gt "$MAX_LINES" ]; then
        printf 'cx-credfp-set: %s holds %s fingerprints, over the %s bound: serving the first %s\n' "$FILE" "$count" "$MAX_LINES" "$MAX_LINES" >&2
        good="$(printf '%s\n' "$good" | head -n "$MAX_LINES")"
        count="$MAX_LINES"
    fi
    case "$total" in
        ''|*[!0-9]*) total=0 ;;
    esac
    if [ "$total" -gt "$count" ]; then
        printf 'cx-credfp-set: skipped %s malformed line(s) in %s (a corrupted or tampered file; they cannot match a fingerprint)\n' "$((total - count))" "$FILE" >&2
    fi
    if [ -n "$good" ]; then
        value=",$(printf '%s\n' "$good" | tr '\n' ',')"
    fi
    printf 'cx-credfp-set: serving %s community fingerprint(s)\n' "$count" >&2
fi

printf '{'
first=1
for key in $names; do
    [ "$first" -eq 1 ] || printf ','
    first=0
    # The value holds only [A-Za-z0-9_*/,-]: no JSON escaping is needed.
    printf '"%s":{"value":"%s","error":null}' "$key" "$value"
done
printf '}\n'
