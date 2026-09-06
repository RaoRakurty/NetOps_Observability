#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

# check-device-ssh.sh (tracker 247) — is the platform's read-only device SSH
# identity CONFIGURED, and does it still AUTHENTICATE?
#
# Why this exists. Config capture and the protocol-diagnostics / TAC collectors
# authenticate to devices with one least-privilege read-only account supplied by
# the operator in `deployment/docker/.env`. When that account's password is
# rotated on the devices and not in `.env`, every capture fails INSIDE a detached
# worker: `POST /api/devices/{id}/config/backup` still answers 202, the UI shows
# nothing new, and the only evidence is a log line. That is exactly how the
# 2026-09-05 TAC lab proof found a dead credential on the cEOS leaves.
#
# What it does, in order:
#   1. resolves the identity the SERVER would resolve (the same precedence as
#      protocolDiagCredential() in src/backend/protocol_diag_gateway.go);
#   2. prints `configured: yes|no` and the SHAPE of what is set — never a value;
#   3. runs ONE read-only `show version` against ONE named device, bounded by a
#      hard timeout, and prints success or the error CLASS.
#
# What it never does: print, log or echo the credential; print the device's
# pre-auth banner or command output (byte counts only); write to the platform's
# own pinned host-key store; touch a device's configuration.
#
# It does NOT need the stack to be up — it reads `.env` and dials the device
# directly. Use it before and after rotating the value. The in-product
# confirmation is `POST /api/devices/{id}/config/backup` followed by
# `GET /api/devices/{id}/config/status` (`last_error`, `last_capture_at`); see
# docs/runbooks/device-ssh-credentials.md.
#
# Usage:
#   scripts/check-device-ssh.sh --device core-sw1 [--address 192.0.2.10]
#   scripts/check-device-ssh.sh --address 192.0.2.11 --identity config-backup
#
# Options:
#   --device NAME        device id, for reporting and inventory lookup
#   --address ADDR       device address; skips the inventory lookup
#   --port N             SSH port (default: the identity's *_SSH_PORT, else 22)
#   --identity WHICH     auto (default) | protocol-diag | config-backup
#   --env-file FILE      default deployment/docker/.env
#   --inventory FILE     default src/config/devices.yaml
#   --timeout SECONDS    whole-session bound, default 25
#   --connect-timeout N  TCP connect bound, default 8
#   --known-hosts FILE   default $HOME/.correlix/device-ssh-known-hosts
#   --show-user          also print the account name (off by default)
#   --show-error         also print the matched stderr line (off by default)
#   --quiet              suppress the informational lines; the verdict still prints
#   -h | --help
#
# Exit codes:
#   0  configured and the account authenticated
#   1  configured but the test failed — the class is on the verdict line
#   2  usage error, or a required tool is missing
#   3  not configured (no user, or no password and no key)
#   4  configured but the secret is SEALED (`v1:`) — only the api can open it
set -Eeuo pipefail

# §16.2 — cron's PATH is not a login shell's. Set it explicitly.
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$DIR/.." && pwd)"

DEVICE=""
ADDRESS=""
PORT=""
IDENTITY="auto"
ENV_FILE="${ENV_FILE:-$ROOT/deployment/docker/.env}"
INVENTORY="${INVENTORY:-$ROOT/src/config/devices.yaml}"
TIMEOUT=25
CONNECT_TIMEOUT=8
KNOWN_HOSTS=""
SHOW_USER=0
SHOW_ERROR=0
QUIET=0

# The one command this tool ever runs. It is a read-only, vendor-common status
# command on every dialect Correlix collects from. It is a constant on purpose:
# a caller-supplied command would make this a remote-execution tool (§3, §8).
readonly PROBE_COMMAND='show version'

usage() {
    cat <<'USAGE'
check-device-ssh.sh — report whether the platform's read-only device SSH
identity is configured, and prove it still authenticates against one device.
The credential is never printed, logged or echoed.

Usage:
  scripts/check-device-ssh.sh --device core-sw1 [--address 192.0.2.10]
  scripts/check-device-ssh.sh --address 192.0.2.11 --identity config-backup

Options:
  --device NAME        device id, for reporting and inventory lookup
  --address ADDR       device address; skips the inventory lookup
  --port N             SSH port (default: the identity's *_SSH_PORT, else 22)
  --identity WHICH     auto (default) | protocol-diag | config-backup
  --env-file FILE      default deployment/docker/.env
  --inventory FILE     default src/config/devices.yaml
  --timeout SECONDS    whole-session bound, default 25
  --connect-timeout N  TCP connect bound, default 8
  --known-hosts FILE   default $HOME/.correlix/device-ssh-known-hosts
  --show-user          also print the account name (off by default)
  --show-error         also print the matched ssh stderr line (off by default)
  --quiet              suppress the informational lines; the verdict still prints
  -h, --help           this text

Exit codes:
  0  configured and the account authenticated
  1  configured but the test failed - the class is on the verdict line
  2  usage error, or a required tool is missing
  3  not configured (no user, or no password and no key)
  4  configured but the secret is sealed (v1:) - only the api can open it

Runbook: docs/runbooks/device-ssh-credentials.md
USAGE
}

log()  { [ "$QUIET" = 1 ] || printf '[device-ssh] %s\n' "$*"; }
say()  { printf '[device-ssh] %s\n' "$*"; }
fail() { printf '[device-ssh] FAIL: %s\n' "$*" >&2; }

# §16.1 — an unexpected failure is loud and names where it happened, never a
# silent partial run that a caller could read as "the credential is fine".
trap 'rc=$?; fail "aborted at line $LINENO (exit $rc)"; exit "$rc"' ERR

while [ $# -gt 0 ]; do
    case "$1" in
        --device)          DEVICE="${2:-}"; shift 2 ;;
        --address)         ADDRESS="${2:-}"; shift 2 ;;
        --port)            PORT="${2:-}"; shift 2 ;;
        --identity)        IDENTITY="${2:-}"; shift 2 ;;
        --env-file)        ENV_FILE="${2:-}"; shift 2 ;;
        --inventory)       INVENTORY="${2:-}"; shift 2 ;;
        --timeout)         TIMEOUT="${2:-}"; shift 2 ;;
        --connect-timeout) CONNECT_TIMEOUT="${2:-}"; shift 2 ;;
        --known-hosts)     KNOWN_HOSTS="${2:-}"; shift 2 ;;
        --show-user)       SHOW_USER=1; shift ;;
        --show-error)      SHOW_ERROR=1; shift ;;
        --quiet)           QUIET=1; shift ;;
        -h|--help)         usage; exit 0 ;;
        *) fail "unknown argument: $1"; usage >&2; exit 2 ;;
    esac
done

case "$IDENTITY" in
    auto|protocol-diag|config-backup) ;;
    *) fail "--identity must be auto, protocol-diag or config-backup"; exit 2 ;;
esac
for n in "$TIMEOUT:--timeout" "$CONNECT_TIMEOUT:--connect-timeout"; do
    v="${n%%:*}"; flag="${n##*:}"
    case "$v" in
        ''|*[!0-9]*) fail "$flag must be a whole number of seconds"; exit 2 ;;
    esac
    [ "$v" -ge 1 ] || { fail "$flag must be at least 1"; exit 2; }
done
if [ -n "$PORT" ]; then
    case "$PORT" in
        ''|*[!0-9]*) fail "--port must be a whole number"; exit 2 ;;
    esac
fi
if [ -z "$DEVICE" ] && [ -z "$ADDRESS" ]; then
    fail "name the device: --device NAME (and/or --address ADDR)"
    usage >&2
    exit 2
fi

# §16.2 — every external tool is checked BY NAME before it is needed, so a
# missing one is a named error rather than a confusing failure mid-probe.
for tool in ssh timeout python3; do
    command -v "$tool" >/dev/null 2>&1 || { fail "required tool not found on PATH: $tool"; exit 2; }
done

# ---- resolve the identity ---------------------------------------------------
# Values come from ENV_FILE, which is the file compose feeds the api. A variable
# ABSENT from that file falls back to this process's environment, so the tool
# also works on a host where the operator exports them (and in CI, where no .env
# exists). The file is PARSED, never sourced: sourcing it would execute it.
declare -A CFG=()
read_env() {
    local out
    out="$(python3 - "$ENV_FILE" <<'PY'
import base64, os, sys

WANTED = (
    "CONFIG_BACKUP_SSH_USER", "CONFIG_BACKUP_SSH_PASSWORD",
    "CONFIG_BACKUP_SSH_KEY", "CONFIG_BACKUP_SSH_PORT",
    "PROTOCOL_DIAG_SSH_USER", "PROTOCOL_DIAG_SSH_PASSWORD",
    "PROTOCOL_DIAG_SSH_KEY", "PROTOCOL_DIAG_SSH_PORT",
)

path = sys.argv[1]
found = {}
if os.path.exists(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, value = line.partition("=")
                key = key.strip()
                if key.startswith("export "):
                    key = key[len("export "):].strip()
                if key not in WANTED:
                    continue
                value = value.strip()
                if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
                    value = value[1:-1]
                found[key] = value
    except OSError as exc:
        # §16.1: an unreadable .env is a hard error. Reporting "not configured"
        # here would be a lie the operator would act on.
        print("ERROR\t%s" % exc, file=sys.stderr)
        sys.exit(1)

for key in WANTED:
    value = found.get(key, os.environ.get(key, ""))
    print("%s\t%s" % (key, base64.b64encode(value.encode()).decode()))
PY
)" || return 1
    local key b64
    while IFS=$'\t' read -r key b64; do
        [ -n "$key" ] || continue
        CFG["$key"]="$(printf '%s' "$b64" | base64 -d)"
    done <<<"$out"
}
read_env || { fail "could not read $ENV_FILE"; exit 2; }

# Precedence, mirroring protocolDiagCredential(): the DEDICATED protocol-diag
# identity wins; only when NONE of its three variables is set does the
# config-backup capture account apply. A PARTIALLY set dedicated identity is a
# hard error in the server too — never a silent fallback to a different account.
PREFIX=""
case "$IDENTITY" in
    config-backup) PREFIX="CONFIG_BACKUP_SSH" ;;
    protocol-diag) PREFIX="PROTOCOL_DIAG_SSH" ;;
    auto)
        if [ -n "${CFG[PROTOCOL_DIAG_SSH_USER]}${CFG[PROTOCOL_DIAG_SSH_PASSWORD]}${CFG[PROTOCOL_DIAG_SSH_KEY]}" ]; then
            PREFIX="PROTOCOL_DIAG_SSH"
        else
            PREFIX="CONFIG_BACKUP_SSH"
        fi
        ;;
esac

SSH_USER="${CFG[${PREFIX}_USER]}"
SSH_PASSWORD="${CFG[${PREFIX}_PASSWORD]}"
SSH_KEY="${CFG[${PREFIX}_KEY]}"
SSH_PORT="${CFG[${PREFIX}_PORT]}"

shape() { [ -n "$1" ] && printf 'set' || printf 'unset'; }

log "env file:  $ENV_FILE"
FALLBACK_NOTE=""
if [ "$IDENTITY" = auto ] && [ "$PREFIX" = CONFIG_BACKUP_SSH ]; then
    FALLBACK_NOTE=" (dedicated identity unset — the documented fallback)"
fi
log "identity:  $IDENTITY -> ${PREFIX}_*${FALLBACK_NOTE}"
log "variables: ${PREFIX}_USER=$(shape "$SSH_USER") ${PREFIX}_PASSWORD=$(shape "$SSH_PASSWORD") ${PREFIX}_KEY=$(shape "$SSH_KEY")"
if [ "$SHOW_USER" = 1 ]; then log "account:   ${SSH_USER:-<unset>}"; fi

if [ "$PREFIX" = "PROTOCOL_DIAG_SSH" ] && [ -n "$SSH_USER" ] && [ -z "$SSH_PASSWORD" ] && [ -z "$SSH_KEY" ]; then
    say "configured: no"
    fail "PROTOCOL_DIAG_SSH_USER is set with neither a password nor a key — the api refuses this rather than falling back to the config-backup account"
    exit 3
fi
if [ -z "$SSH_USER" ] || { [ -z "$SSH_PASSWORD" ] && [ -z "$SSH_KEY" ]; }; then
    say "configured: no"
    fail "set ${PREFIX}_USER and one of ${PREFIX}_PASSWORD or ${PREFIX}_KEY in $ENV_FILE (see docs/runbooks/device-ssh-credentials.md)"
    exit 3
fi
say "configured: yes"

# A `v1:` value is vault ciphertext sealed under the platform DEK. The host has
# no way to open it and MUST NOT try — say so instead of reporting a false
# auth failure.
if [ "${SSH_PASSWORD:0:3}" = "v1:" ] || [ "${SSH_KEY:0:3}" = "v1:" ]; then
    say "verdict: NOT TESTED (class: sealed-secret)"
    say "the secret is sealed under the platform vault; only the api can open it — validate through POST /api/devices/{id}/config/backup then GET /api/devices/{id}/config/status"
    exit 4
fi

# ---- resolve the target -----------------------------------------------------
if [ -z "$ADDRESS" ]; then
    ADDRESS="$(python3 - "$INVENTORY" "$DEVICE" <<'PY'
import sys

path, want = sys.argv[1], sys.argv[2]
try:
    import yaml
except ImportError:
    print("", end="")
    sys.exit(0)
try:
    with open(path, encoding="utf-8") as fh:
        doc = yaml.safe_load(fh) or {}
except (OSError, yaml.YAMLError) as exc:
    # §16.1: a broken inventory is reported, never read as "no such device".
    print("ERROR\t%s" % exc, file=sys.stderr)
    sys.exit(1)
devices = doc.get("devices") or {}
row = devices.get(want) if isinstance(devices, dict) else None
print((row or {}).get("address", "") if isinstance(row, dict) else "", end="")
PY
)" || { fail "could not read the inventory $INVENTORY"; exit 2; }
fi
if [ -z "$ADDRESS" ]; then
    fail "no address for '${DEVICE}' in $INVENTORY — pass --address ADDR (the inventory may live in the api's device store rather than a file)"
    exit 2
fi
[ -n "$PORT" ] || PORT="${SSH_PORT:-22}"
[ -n "$PORT" ] || PORT=22
log "target:    ${DEVICE:-$ADDRESS} ${ADDRESS}:${PORT}"

# ---- host-key custody -------------------------------------------------------
# This tool keeps its OWN trust-on-first-use file. It never reads or writes the
# platform's pinned fingerprint store: a probe must not be able to pin a key the
# api will later trust, and a probe must not be refused because a fingerprint it
# has never seen is absent from its own file.
if [ -z "$KNOWN_HOSTS" ]; then
    HOME_DIR="${HOME:-}"
    if [ -z "$HOME_DIR" ]; then   # §16.2: HOME may be unset under cron
        HOME_DIR="$(getent passwd "$(id -u)" | cut -d: -f6)"
    fi
    [ -n "$HOME_DIR" ] || { fail "HOME is unset and could not be resolved — pass --known-hosts FILE"; exit 2; }
    KNOWN_HOSTS="$HOME_DIR/.correlix/device-ssh-known-hosts"
fi
KH_DIR="$(dirname "$KNOWN_HOSTS")"
if [ ! -d "$KH_DIR" ]; then
    mkdir -p "$KH_DIR"
    chmod 700 "$KH_DIR"   # only ever on a directory this tool created
fi
[ -e "$KNOWN_HOSTS" ] || : >"$KNOWN_HOSTS"
chmod 600 "$KNOWN_HOSTS"

# ---- the probe --------------------------------------------------------------
WORK="$(mktemp -d)"
chmod 700 "$WORK"
trap 'rm -rf "$WORK"' EXIT

ERR_FILE="$WORK/stderr"
OUT_FILE="$WORK/stdout"

SSH_OPTS=(
    -p "$PORT"
    -o "ConnectTimeout=$CONNECT_TIMEOUT"
    -o StrictHostKeyChecking=accept-new
    -o "UserKnownHostsFile=$KNOWN_HOSTS"
    -o LogLevel=ERROR
    -o NumberOfPasswordPrompts=1
)

rc=0
if [ -n "$SSH_KEY" ]; then
    KEY_FILE="$WORK/key"
    (umask 077; printf '%s\n' "$SSH_KEY" >"$KEY_FILE")
    timeout -k 5 "$TIMEOUT" ssh "${SSH_OPTS[@]}" \
        -o BatchMode=yes -o IdentitiesOnly=yes -o PasswordAuthentication=no \
        -i "$KEY_FILE" "$SSH_USER@$ADDRESS" "$PROBE_COMMAND" \
        >"$OUT_FILE" 2>"$ERR_FILE" || rc=$?
else
    command -v sshpass >/dev/null 2>&1 || {
        fail "the identity uses a PASSWORD and sshpass is not installed — install sshpass, or configure ${PREFIX}_KEY, or validate through the api (docs/runbooks/device-ssh-credentials.md)"
        exit 2
    }
    # sshpass -d reads the secret from a file descriptor: it never reaches argv
    # (visible in ps) and never reaches the environment. `printf` is a bash
    # builtin, so the value is not an argument of any separate process either.
    timeout -k 5 "$TIMEOUT" sshpass -d 3 ssh "${SSH_OPTS[@]}" \
        -o PubkeyAuthentication=no \
        -o PreferredAuthentications=keyboard-interactive,password \
        "$SSH_USER@$ADDRESS" "$PROBE_COMMAND" \
        >"$OUT_FILE" 2>"$ERR_FILE" 3< <(printf '%s\n' "$SSH_PASSWORD") || rc=$?
fi

# ---- classify ---------------------------------------------------------------
# Only the CLASS is reported. The device's stderr can carry a pre-auth banner
# and its stdout carries configuration-adjacent facts; neither is printed.
ERR_TEXT="$(tr '\r' '\n' <"$ERR_FILE" | tr '[:upper:]' '[:lower:]')"
MATCHED_LINE="$(grep -m1 -iE 'denied|authentic|host key|identification has changed|timed out|refused|unreachable|no route|resolve|no matching' "$ERR_FILE" 2>/dev/null || true)"
OUT_BYTES="$(wc -c <"$OUT_FILE" | tr -d ' ')"

# Ordering matters and is deliberate:
#   1. success, then the timeout wrapper's own codes;
#   2. what ssh SAID — the transport-level failures all announce themselves,
#      and this is the only evidence that distinguishes them reliably;
#   3. sshpass's own codes, checked AFTER the stderr patterns because they
#      overlap the numeric range a remote command can exit with;
#   4. 255 is ssh's "I failed" code with nothing recognisable in it;
#   5. anything else means the SESSION SUCCEEDED and the remote command exited
#      non-zero — on Arista EOS that is what a below-privilege-15 account looks
#      like on `show running-config`.
classify() {
    case "$rc" in
        0)       printf 'ok'; return ;;
        124|137) printf 'timeout'; return ;;
    esac
    case "$ERR_TEXT" in
        *"identification has changed"*|*"host key verification failed"*) printf 'host-key'; return ;;
        *"no matching host key"*|*"no matching key exchange"*|*"no matching cipher"*) printf 'crypto-mismatch'; return ;;
        *"permission denied"*|*"authentication failed"*|*"too many authentication failures"*) printf 'auth-failed'; return ;;
        *"connection timed out"*|*"operation timed out"*) printf 'timeout'; return ;;
        *"connection refused"*|*"no route to host"*|*"network is unreachable"*) printf 'unreachable'; return ;;
        *"could not resolve"*|*"name or service not known"*|*"nodename nor servname"*) printf 'dns'; return ;;
    esac
    case "$rc" in
        5) printf 'auth-failed'; return ;;   # sshpass: incorrect password
        6) printf 'host-key'; return ;;      # sshpass: host key unknown/changed
        255) printf 'unknown'; return ;;     # ssh's own failure, unrecognised
    esac
    printf 'command-refused'
}
CLASS="$(classify)"

if [ "$SHOW_ERROR" = 1 ] && [ -n "$MATCHED_LINE" ]; then
    say "ssh said:  ${MATCHED_LINE:0:160}"
fi

case "$CLASS" in
    ok)
        say "verdict: AUTH OK — '$PROBE_COMMAND' returned ${OUT_BYTES} bytes (content not shown)"
        exit 0
        ;;
    command-refused)
        say "verdict: AUTH OK, COMMAND REFUSED (class: command-refused, remote exit $rc)"
        say "the account authenticated and the session opened, but the device exited non-zero on '$PROBE_COMMAND' — check the account's privilege level"
        exit 1
        ;;
    *)
        say "verdict: FAILED (class: $CLASS, ssh exit $rc)"
        case "$CLASS" in
            auth-failed) say "the account did not authenticate — rotate ${PREFIX}_PASSWORD/${PREFIX}_KEY in $ENV_FILE to the device's current read-only account, then recreate the api container" ;;
            host-key)    say "the device's host key differs from the one recorded in $KNOWN_HOSTS — treat as a possible MITM until the device is confirmed rebuilt" ;;
            unreachable|timeout|dns) say "the device did not answer on ${ADDRESS}:${PORT} — this is reachability, not the credential" ;;
            crypto-mismatch) say "no common host-key/kex/cipher with this device — an ssh client policy issue, not the credential" ;;
            *)           say "unclassified failure — re-run with --show-error to see the ssh line" ;;
        esac
        exit 1
        ;;
esac
