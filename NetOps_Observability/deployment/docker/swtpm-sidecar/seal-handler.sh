#!/bin/sh
# Per-connection handler for the sealing sidecar (#17). socat pipes one client
# connection to stdin/stdout; we read ONE request line and emit ONE response:
#
#   UNSEAL              -> OK <base64-kek>   | ERR no-kek | ERR <reason>
#   SEAL <base64-kek>   -> OK                | ERR <reason>
#
# Only the 32-byte root KEK ever crosses this socket — never a tenant secret.
# tpm2-tools calls are serialized with flock (a single swtpm isn't concurrent).
set -u

TPMDIR="${TPMDIR:-/tpmstate}"
export TPM2TOOLS_TCTI="swtpm:host=127.0.0.1,port=2321"
LOCK="$TPMDIR/.lock"

IFS= read -r line || exit 0
cmd="${line%% *}"
arg="${line#* }"

case "$cmd" in
UNSEAL)
    (
        flock 9
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
        if ! printf '%s' "$arg" | base64 -d > "$TPMDIR/kek.bin" 2>/dev/null; then
            echo "ERR b64"
            exit 0
        fi
        if tpm2_create -C "$TPMDIR/primary.ctx" -g sha256 -i "$TPMDIR/kek.bin" \
                -u "$TPMDIR/seal.pub" -r "$TPMDIR/seal.priv" >/dev/null 2>&1; then
            rc=0
        else
            rc=1
        fi
        shred -u "$TPMDIR/kek.bin" 2>/dev/null || rm -f "$TPMDIR/kek.bin"
        [ "$rc" -eq 0 ] && echo "OK" || echo "ERR create"
    ) 9>"$LOCK"
    ;;
*)
    echo "ERR unknown"
    ;;
esac
