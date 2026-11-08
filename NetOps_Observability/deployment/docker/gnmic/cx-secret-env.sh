#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

# cx-secret-env.sh — load file-mounted credentials into the PROCESS environment,
# then exec the real program (tracker 367 layer 1: no secrets in URLs or in the
# container's declared env).
#
# Usage:  cx-secret-env.sh VAR=/path/to/file [VAR=/path ...] -- program [args...]
#
# gnmic 0.46 can authenticate its prometheus_write output natively
# (`authentication: {username, password}`, and it prints that password as
# "***" in its parsed-config echo — verified against 0.46.0, 2026-11-07), and
# it expands ${VAR} in output config. What it cannot do is read a file. This
# wrapper bridges exactly that gap: the value goes from a read-only bind mount
# into the exec'd process's environment — which `docker inspect` does NOT show
# (only the container's declared env is there) — and never into an argv, a
# URL or a log line.
#
# The value is validated like the Go reader (internal/credfile): one trailing
# newline trimmed; empty, > 1 KiB or non-printable-ASCII refused. Any refusal
# is FATAL (exit 78, EX_CONFIG) and names the variable only — a collector that
# started without its credential would write nothing and look healthy, which is
# the silent-lane failure this repo keeps paying for.
#
# Rotation: the value is read once at start (the program holds it in memory);
# a rotated file takes effect at the next container restart.
#
# §16 applies (scripts/CLAUDE.md). Runs under busybox ash (gnmic's alpine
# image) and any POSIX sh.

set -eu
export LC_ALL=C

MAX_BYTES=1024
NL='
'

die() {
    printf 'cx-secret-env: FATAL: %s\n' "$1" >&2
    exit 78
}

loaded=0
while [ "$#" -gt 0 ]; do
    case "$1" in
        --) shift; break ;;
        *=*) ;;
        *) die "expected VAR=/path/to/file or --, got an argument without '=' (argument $((loaded + 1)))" ;;
    esac
    var="${1%%=*}"
    file="${1#*=}"
    shift
    case "$var" in
        ''|[0-9]*|*[!A-Za-z0-9_]*) die "invalid environment variable name in a VAR=file pair" ;;
    esac
    case "$file" in
        /*) ;;
        *) die "${var}: credential path must be absolute" ;;
    esac
    if [ ! -f "$file" ] || [ ! -r "$file" ]; then
        die "${var}: credential file ${file} is missing or unreadable (is the data/secrets bind mount present? scripts/install.py renders it)"
    fi
    size="$(wc -c < "$file" | tr -d ' ')"
    case "$size" in
        ''|*[!0-9]*) die "${var}: cannot read the size of ${file}" ;;
    esac
    # +1: the one trailing newline the format allows does not count.
    [ "$size" -le $((MAX_BYTES + 1)) ] || die "${var}: credential file ${file} is larger than ${MAX_BYTES} bytes"
    # The sentinel keeps trailing newlines so exactly one can be trimmed.
    v="$(cat "$file"; printf x)"
    v="${v%x}"
    v="${v%"$NL"}"
    [ -n "$v" ] || die "${var}: credential file ${file} is empty"
    [ "${#v}" -le "$MAX_BYTES" ] || die "${var}: credential is longer than ${MAX_BYTES} bytes"
    case "$v" in
        *[!\ -~]*) die "${var}: credential file ${file} contains non-printable characters" ;;
    esac
    export "${var}=${v}"
    loaded=$((loaded + 1))
done

[ "$#" -gt 0 ] || die "no program to exec after '--'"
[ "$loaded" -gt 0 ] || die "no VAR=file pairs given — refusing to start the program without its credential"
printf 'cx-secret-env: loaded %d credential(s) from file; exec %s\n' "$loaded" "$1" >&2
exec "$@"
