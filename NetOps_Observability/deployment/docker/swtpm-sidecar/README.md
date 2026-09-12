# Secret-custody sealing sidecar (swtpm) — #17

This sidecar is the **key custodian** for the backend's secret-custody Vault
(`src/backend/secrets.go`, design `docs/design/secret-custody.md`). It seals and
unseals **only the 32-byte root KEK** over a local Unix socket; the actual
AES-256-GCM of tenant secrets happens in the Go process. Keeping the TPM
interaction here (shelling out to `tpm2-tools`) is why the Go `go.mod` stays
dependency-free — no CLAUDE.md §6 allowlist amendment.

## Protocol (line-based, over the Unix socket)

```
UNSEAL              -> OK <base64-kek>   | ERR no-kek | ERR <reason>
SEAL <base64-kek>   -> OK                | ERR <reason>
```

`ERR no-kek` on first run tells the Vault to generate a fresh KEK and `SEAL` it.

## Bring-up

```bash
# 1. start the sidecar (creates the swtpm + serves the socket)
docker compose --profile seal up -d secrets-seal

# 2. activate custody on the api
SEAL_PROVIDER=swtpm docker compose up -d api

# 3. (optional, one-time) encrypt any secrets still stored in plaintext
SEAL_PROVIDER=swtpm SECRETS_RESEAL=true docker compose up -d api
```

Without `SEAL_PROVIDER`, the Vault is **dormant** (plaintext passthrough) and this
sidecar need not run — behavior is unchanged.

## Security note (read before production)

`swtpm` is a **software TPM emulator** — its state is a file under
`data/swtpm/`. It is correct for lab/dev and for *building* the integration, but
it is **not a hardware root of trust** and its attestation is meaningless against
a compromised host. Production assurance needs a real **TPM 2.0** (PCR-sealed), an
**HSM**, or a **cloud KMS** — each drops in behind the same `SealingProvider`
interface with no backend code change.

What this buys today: a stolen disk / DB dump / backup leak yields **ciphertext,
not secrets**. The KEK is sealed; tenant DEKs are wrapped under it; secrets are
GCM-bound to `tenant|field`. That is the crypto complement to RLS.
