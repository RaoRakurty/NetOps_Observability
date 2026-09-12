#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

# Per-connection handler for the sealing sidecar (#17). socat pipes one client
# connection to stdin/stdout; we read ONE request line and emit ONE response:
#
#   UNSEAL              -> OK <base64-kek>   | ERR no-kek | ERR <reason>
#   SEAL <base64-kek>   -> OK                | ERR exists | ERR <reason>
#   RESEAL <base64-kek> -> OK                | ERR <reason>
#
# Only the 32-byte root KEK ever crosses this socket — never a tenant secret.
# tpm2-tools calls are serialized with flock (a single swtpm isn't concurrent).
#
# SEAL vs RESEAL (2026-08-14 hardening, after the 2026-08-04 custody incident
# proved the client-side ErrNoKEK guard alone can wrongly reach Seal):
#   * SEAL is FIRST-RUN ONLY. If a sealed KEK already exists (seal.priv
#     present) it replies "ERR exists" and touches nothing — a stray or rogue
#     SEAL on this 0666 socket must never be able to overwrite the blobs that
#     every sealed secret (CA key, tenant DEKs, sealed fields) depends on.
#   * RESEAL deliberately overwrites an existing sealed KEK. It is an
#     OPERATOR-ONLY verb for a deliberate, runbook-driven key ceremony
#     (docs/design/secret-custody.md); the Go vault client
#     (src/backend/internal/vault/secrets_swtpm.go) NEVER sends it, and no
#     automatic code path may. Anyone invoking RESEAL owns re-encrypting or
#     accepting the loss of everything sealed under the previous KEK.
#
# The KEK is piped base64→tpm2_create via stdin (-i-, verified against the
# pinned image, tpm2-tools 5.4): the plaintext KEK NEVER touches a file. The
# previous implementation staged it in $TPMDIR/kek.bin (a persistent host bind
# mount) and shred-ed it afterwards — a crash in that window left the root KEK
# in cleartext on host disk forever, and shred is ineffective on CoW/journaled
# filesystems anyway. entrypoint.sh purges (and loudly reports) any stray
# kek.bin left behind by a pre-fix crash.
set -u

TPMDIR="${TPMDIR:-/tpmstate}"
export TPM2TOOLS_TCTI="swtpm:host=127.0.0.1,port=2321"
LOCK="$TPMDIR/.lock"

# do_seal <base64-kek> — seal via stdin; the KEK never becomes a file. New blobs
# are created under temp names and renamed in only as a pair, so an interrupted
# (RE)SEAL can never leave a mismatched seal.pub/seal.priv on disk.
do_seal() {
    # Validate the base64 FIRST (decode to /dev/null): tpm2_create must never
    # see — let alone seal — a partial decode of malformed input.
    if ! printf '%s' "$1" | base64 -d >/dev/null 2>&1; then
        echo "ERR b64"
        return 0
    fi
    if printf '%s' "$1" | base64 -d | tpm2_create -C "$TPMDIR/primary.ctx" \
            -g sha256 -i- -u "$TPMDIR/seal.pub.new" -r "$TPMDIR/seal.priv.new" \
            >/dev/null 2>&1; then
        if mv "$TPMDIR/seal.pub.new" "$TPMDIR/seal.pub" &&
           mv "$TPMDIR/seal.priv.new" "$TPMDIR/seal.priv"; then
            echo "OK"
        else
            echo "ERR install"
        fi
    else
        rm -f "$TPMDIR/seal.pub.new" "$TPMDIR/seal.priv.new"
        echo "ERR create"
    fi
}

IFS= read -r line || exit 0
cmd="${line%% *}"
arg="${line#* }"

case "$cmd" in
UNSEAL)
    (
        flock 9
        # swtpm has only 3 transient object slots; tpm2-tools leaves the primary
        # loaded after each invocation, so without this they exhaust and every op
        # fails with "out of memory for object contexts". Flush before loading.
        tpm2_flushcontext -t >/dev/null 2>&1 || true
        if [ ! -f "$TPMDIR/seal.priv" ]; then
            echo "ERR no-kek"   # first run — no KEK sealed yet; the Vault generates one
            exit 0
        fi
        if ! tpm2_load -C "$TPMDIR/primary.ctx" -u "$TPMDIR/seal.pub" \
                -r "$TPMDIR/seal.priv" -c "$TPMDIR/seal.ctx" >/dev/null 2>&1; then
            echo "ERR load"
            exit 0
        fi
        if kek="$(tpm2_unseal -c "$TPMDIR/seal.ctx" 2>/dev/null | base64 -w0)"; then
            echo "OK $kek"
        else
            echo "ERR unseal"
        fi
    ) 9>"$LOCK"
    ;;
SEAL)
    (
        flock 9
        tpm2_flushcontext -t >/dev/null 2>&1 || true
        # Server-side first-run guard (see header): an existing sealed KEK is
        # NEVER overwritten by SEAL. The 2026-08-04 incident proved the client
        # discipline (only Seal after ErrNoKEK) is not a sufficient guard on its
        # own — one stray SEAL would irreversibly orphan every sealed secret.
        if [ -f "$TPMDIR/seal.priv" ]; then
            echo "ERR exists"
            exit 0
        fi
        do_seal "$arg"
    ) 9>"$LOCK"
    ;;
RESEAL)
    (
        flock 9
        tpm2_flushcontext -t >/dev/null 2>&1 || true
        # Deliberate overwrite — operator-only key ceremony, see header. Loud in
        # the sidecar log: a RESEAL is always a notable custody event.
        echo "secrets-seal: RESEAL requested — overwriting the sealed KEK (operator ceremony; every secret sealed under the previous KEK must be re-encrypted or is lost)" >&2
        do_seal "$arg"
    ) 9>"$LOCK"
    ;;
*)
    echo "ERR unknown"
    ;;
esac
