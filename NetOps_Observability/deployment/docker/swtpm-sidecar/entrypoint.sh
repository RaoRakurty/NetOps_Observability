#!/bin/sh
# Secret-custody sealing sidecar entrypoint (#17).
#
# Boots a software TPM (swtpm, TCP TCTI on localhost, state persisted under
# $TPMDIR), creates the primary key the sealed objects live under (once), then
# serves the SEAL/UNSEAL line protocol on a Unix socket via socat. Each
# connection forks seal-handler.sh. See docs/design/secret-custody.md §4.2.
set -eu

TPMDIR="${TPMDIR:-/tpmstate}"
SEAL_SOCKET="${SEAL_SOCKET:-/run/secrets-seal/seal.sock}"
mkdir -p "$TPMDIR" "$(dirname "$SEAL_SOCKET")"

# Software TPM: server (commands) + ctrl on localhost TCP; tpm2-tools reach it via
# the swtpm TCTI. State (incl. the sealed KEK objects) lives in $TPMDIR.
swtpm socket --tpm2 --tpmstate dir="$TPMDIR" \
    --server type=tcp,port=2321,bindaddr=127.0.0.1 \
    --ctrl type=tcp,port=2322,bindaddr=127.0.0.1 \
    --flags not-need-init,startup-clear &
SWTPM_PID=$!
trap 'kill "$SWTPM_PID" 2>/dev/null || true' INT TERM EXIT

export TPM2TOOLS_TCTI="swtpm:host=127.0.0.1,port=2321"

# Wait for the TPM to accept commands (bounded).
i=0
until tpm2_startup -c >/dev/null 2>&1; do
    i=$((i + 1))
    [ "$i" -ge 60 ] && { echo "swtpm did not become ready" >&2; exit 1; }
    sleep 0.5
done

# Primary key under the owner hierarchy — the parent of every sealed object.
# Created once; persisted as a context file so restarts reuse it.
if [ ! -f "$TPMDIR/primary.ctx" ]; then
    tpm2_createprimary -C o -g sha256 -G rsa -c "$TPMDIR/primary.ctx" >/dev/null
fi

rm -f "$SEAL_SOCKET"
echo "secrets-seal: ready, serving $SEAL_SOCKET" >&2
exec socat "UNIX-LISTEN:${SEAL_SOCKET},fork,mode=0660" EXEC:/usr/local/bin/seal-handler.sh
