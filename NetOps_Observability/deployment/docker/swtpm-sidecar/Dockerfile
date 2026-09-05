# Secret-custody sealing sidecar (#17, docs/design/secret-custody.md).
#
# A software TPM (swtpm) + tpm2-tools that seal/unseal ONLY the 32-byte root KEK
# over a local Unix socket. Tenant secrets never cross this boundary — the Go
# backend's Vault does the AES-256-GCM of secrets in-process; this container is
# just the key custodian. Keeping the TPM interaction here (shelling out to
# tpm2-tools) is why the Go go.mod stays dependency-free (no CLAUDE.md §6 amend).
#
# swtpm is a SOFTWARE emulator: correct for lab/dev and for building the
# integration, NOT a hardware root of trust. Production assurance needs a real
# TPM 2.0 / HSM / cloud KMS behind the same SealingProvider interface.
FROM debian:bookworm-slim@sha256:0104b334637a5f19aa9c983a91b54c89887c0984081f2068983107a6f6c21eeb

# The image's licence, in OCI metadata, so `docker image inspect` answers it
# without unpacking the image. Correlix core is Apache-2.0; see LICENSING.md for
# which parts of the tree are commercial add-ons instead. Enforced by
# scripts/licensing-gate.py check D and tests/test_licensing_consistency.py.
LABEL org.opencontainers.image.licenses="Apache-2.0"

RUN apt-get update && apt-get install -y --no-install-recommends \
        swtpm swtpm-tools tpm2-tools socat coreutils ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY deployment/docker/swtpm-sidecar/entrypoint.sh /usr/local/bin/entrypoint.sh
COPY deployment/docker/swtpm-sidecar/seal-handler.sh /usr/local/bin/seal-handler.sh
RUN chmod +x /usr/local/bin/entrypoint.sh /usr/local/bin/seal-handler.sh

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
