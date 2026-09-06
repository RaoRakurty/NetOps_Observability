#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

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

# Stray-plaintext purge (2026-08-14). Before the stdin-pipe fix, SEAL staged the
# decoded root KEK at $TPMDIR/kek.bin (a PERSISTENT host bind mount) and relied
# on a post-hoc shred — a crash/OOM-kill in that window left the KEK in
# cleartext on host disk indefinitely. Nothing writes kek.bin anymore, so its
# presence at boot is INCIDENT EVIDENCE (a pre-fix crash, or something else
# placed a file there): log it LOUDLY before removal — per the 2026-08-04
# custody-incident discipline, evidence is named before it is destroyed — then
# purge it. shred is best-effort (ineffective on CoW/journaled filesystems);
# rm is the part that must succeed, and a failed purge aborts boot (set -e):
# a custodian that cannot remove plaintext key material must not serve.
if [ -e "$TPMDIR/kek.bin" ]; then
    echo "secrets-seal: SECURITY WARNING: stray plaintext KEK file found at $TPMDIR/kek.bin (size $(wc -c < "$TPMDIR/kek.bin" 2>/dev/null || echo '?') bytes) — this is evidence of a pre-fix SEAL crash: the root KEK may have been exposed on the host disk backing this bind mount. Purging it now. Consider an operator-driven RESEAL/key rotation per docs/design/secret-custody.md." >&2
    shred -u "$TPMDIR/kek.bin" 2>/dev/null || rm -f "$TPMDIR/kek.bin"
    [ ! -e "$TPMDIR/kek.bin" ] || { echo "secrets-seal: FATAL: could not purge $TPMDIR/kek.bin — refusing to serve with plaintext key material on disk" >&2; exit 1; }
fi
# Interrupted (RE)SEAL leftovers: harmless (sealed ciphertext, temp names) but
# stale — a completed rename pair is the only valid blob state. Quiet cleanup.
rm -f "$TPMDIR/seal.pub.new" "$TPMDIR/seal.priv.new"

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
# Recreated on EVERY boot: a saved context blob is bound to the TPM reset cycle,
# so a swtpm restart invalidates the previous primary.ctx (Esys_ContextLoad
# 0x1DF "integrity check failed" — this took the API down in a restart loop on
# 2026-08-04). The primary is derived deterministically from the owner-hierarchy
# seed persisted in $TPMDIR, so recreating yields the SAME key and the existing
# seal.pub/seal.priv blobs keep loading under it. Failure aborts boot (set -e) —
# a sidecar that can't reach its primary must be loud, not "ready".
tpm2_createprimary -C o -g sha256 -G rsa -c "$TPMDIR/primary.ctx.new" >/dev/null
mv "$TPMDIR/primary.ctx.new" "$TPMDIR/primary.ctx"
# swtpm exposes only 3 transient object slots; flush any left loaded by the
# warm-up so the first SEAL/UNSEAL starts from a clean slate (the per-op handler
# also flushes — see seal-handler.sh). Without this, slots leak and ops fail with
# "out of memory for object contexts". Validated live against swtpm 0.7.1.
tpm2_flushcontext -t >/dev/null 2>&1 || true

rm -f "$SEAL_SOCKET"
echo "secrets-seal: ready, serving $SEAL_SOCKET" >&2
# mode=0666: the api connects as a different (non-root) uid. The socket only ever
# carries the root KEK (never tenant secrets) and lives on a host-private bind
# mount; this is lab-grade. A real TPM/HSM deployment would gate by uid/group.
exec socat "UNIX-LISTEN:${SEAL_SOCKET},fork,mode=0666" EXEC:/usr/local/bin/seal-handler.sh
