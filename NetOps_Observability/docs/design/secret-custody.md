# Secret Custody — TPM-rooted envelope encryption (task #17)

> Status: **phase 1 building** (updated 2026-06-04). Phase **1a (swtpm sidecar +
> SealingProvider)** and **1b (Vault envelope)** are DONE; **1c (wire stores)** is
> partial — SNMP creds + integration webhook_secret encrypted, remaining config
> stores pending. Decisions locked: abstracted sealing provider, tpm2-tools
> **sidecar** (no Go TPM dependency → governance-clean).
> Pairs with: `postgres-rls.md` (#15/#19/#33), TLS (#18), cert auto-rotation (#30).

---

## 1. Problem & goal

Today the platform stores reversible secrets **as cleartext at rest**:

| Secret | Where | File |
|--------|-------|------|
| OIDC `client_secret` | kv config store (write-only API, plaintext at rest) | `oidc_config.go` |
| LDAP `bind_password` | kv config store | `auth_config.go` |
| TACACS shared `secret` | kv config store | `auth_config.go` |
| SMTP password, Twilio `auth_token`, ntfy `token` | kv config store | `notify_config.go` |
| Copilot API key | kv config store | `copilot_config.go` |
| SNMP v2c `community`, v3 `auth_key`/`priv_key` | kv `snmp_credentials` (tenant-scoped) | `snmp_creds.go` |
| `JWT_SECRET`, DB password, AWS creds | env / `.env` | compose |

The write-only API pattern (`redact-on-GET`, `*_set` booleans) stops secrets
leaving over HTTP, but **anyone with the file or a DB dump reads them in the
clear**. One-way values (user password hashes, API-key secret hashes) are NOT in
scope — they are already irreversible and stay as-is.

**Goal.** Make every *reversible* secret **useless without this host's TPM**, and
**isolated per tenant**. Note the reframing this forces:

> A TPM (and swtpm) is a **key custodian with a few KB of NVRAM — not a secret
> store.** You cannot put certs and customer credentials *inside* it. The
> achievable, stronger goal is **envelope encryption**: the TPM seals a root key;
> secrets are AES-256-GCM encrypted under per-tenant keys; the **ciphertext lives
> in the existing store**, and only the TPM can unwrap the key chain. "Stored in
> the TPM" → **"unrecoverable without the TPM."**

This is the **crypto complement to RLS** (#33): RLS controls *row visibility*;
envelope encryption controls *plaintext recoverability*. A query/RLS bug then
leaks ciphertext, not secrets. Defense in depth.

---

## 2. Threat model — what swtpm does and does NOT buy

- **Protects against:** a stolen file/disk/DB dump, a backup leak, a read-only
  data-exfil bug, a curious operator with DB access. Ciphertext is inert without
  the TPM-sealed KEK.
- **Does NOT protect against (swtpm specifically):** a root-level compromise of
  the *running host*. **swtpm is a software emulator — its state is a file**, so
  it is **not a hardware root of trust** and its attestation is meaningless
  against a compromised host. It is correct for dev/lab and for *building the
  integration*; production assurance needs a real **TPM 2.0** (PCR-sealed),
  **HSM**, or **cloud KMS**.
- **Therefore:** the sealing layer sits behind a `SealingProvider` interface
  (§4.1). swtpm is impl #1; TPM2/KMS/HSM drop in with **no caller change**. This
  is the "don't bake in a substrate capability you don't have yet" discipline —
  and the *same root-of-trust substrate* a future supply-chain signing pipeline
  (SBOM/SLSA/cosign) will need, so the abstraction is reused, not throwaway.

---

## 3. Key hierarchy

```
            ┌────────────────────────────┐
  TPM seal  │  Root KEK  (32B, AES-256)   │   never leaves unwrapped except in
  /unseal   └────────────┬───────────────┘   the sidecar's memory
                         │ wraps (AES-256-GCM)
        ┌────────────────┼─────────────────────┐
        ▼                ▼                       ▼
  ┌───────────┐   ┌───────────┐           ┌───────────┐
  │ platform  │   │ tenant A  │   …       │ tenant B  │   DEKs (32B each),
  │   DEK     │   │   DEK     │           │   DEK     │   stored WRAPPED
  └─────┬─────┘   └─────┬─────┘           └─────┬─────┘
        │ AES-256-GCM   │                       │
        ▼               ▼                       ▼
  JWT_SECRET,    tenant-A SNMP creds,     tenant-B secrets …
  platform OIDC  tenant-A SMTP/LDAP …
```

- **Root KEK** — 32 random bytes, **sealed by the TPM** (sidecar holds it
  unwrapped in memory only). The single thing whose secrecy roots everything.
- **Per-tenant DEK** — one AES-256 key per tenant, plus a **platform DEK** for
  global secrets (JWT, platform OIDC). Stored **wrapped by the KEK** in a new
  `wrapped_keys` table (or `app_kv`). Unwrapped DEKs are cached **in memory
  only**, never written.
- **Per-tenant isolation:** tenant A's secrets are encrypted under tenant A's
  DEK. Even with full DB read access, tenant B's secrets are unrecoverable. The
  **GCM AAD binds each ciphertext to `tenant_id || field-id`**, so a row copied
  into another tenant's record fails to decrypt (no copy-paste / confused-deputy).

All crypto is **stdlib** (`crypto/aes`, `crypto/cipher`, `crypto/rand`) — no new
Go dependency.

---

## 4. Architecture

### 4.1 `SealingProvider` (Go interface, in-process)

```go
// Seals/unseals the 32-byte root KEK. The ONLY thing that talks to the TPM.
type SealingProvider interface {
    // Unseal returns the root KEK, or fails closed if the TPM is unavailable.
    Unseal(ctx context.Context) ([]byte, error)
    // Seal persists a (re)generated root KEK under the TPM. First-run only.
    Seal(ctx context.Context, kek []byte) error
}
```

Impls: `swtpmSidecarProvider` (phase 1), `tpm2Provider`, `kmsProvider`,
`hsmProvider` (later). Selected by `SEAL_PROVIDER` env, fail-closed default.

### 4.2 swtpm sidecar (governance-clean: no Go TPM dep)

A tiny service (its own container) that shells out to **`tpm2-tools`** against the
host swtpm and exposes **Seal/Unseal of the KEK over a local Unix socket** (root
KEK only — never the secrets). The Go backend's `swtpmSidecarProvider` is a thin
socket client. Because the TPM interaction lives in the sidecar, **`go.mod` stays
dependency-free — no CLAUDE.md §6 allowlist amendment needed.**

- Socket file perms + a per-boot shared token gate the sidecar; it is **not**
  exposed on any network port.
- Sidecar uses `tpm2_createprimary`/`tpm2_create`/`tpm2_load`/`tpm2_unseal`
  (later: PCR policy for measured boot on real hardware).

### 4.3 Envelope layer (`secrets.go`, new)

```go
type Vault interface {
    Encrypt(tenant, fieldID, plaintext string) (string, error) // → "v1:<b64 nonce|ct>"
    Decrypt(tenant, fieldID, ciphertext string) (string, error)
}
```

- `Encrypt` loads (or lazily creates + wraps) the tenant DEK, AES-256-GCM with a
  fresh random nonce, AAD = `tenant|fieldID`, returns a versioned, self-describing
  string.
- Ciphertext is stored **in the same field** the plaintext used to occupy — no
  schema churn for the config stores (they already round-trip a JSON blob). The
  `*_set` redaction booleans and write-only API are unchanged.
- Decrypt is on the hot path only when a secret is actually *used* (e.g. the
  collector reads an SNMP priv key, the dispatcher reads the SMTP password).

### 4.4 Wiring into existing stores

- **Config stores** (`auth_config.go`, `oidc_config.go`, `notify_config.go`,
  `copilot_config.go`): on Save, `Vault.Encrypt` the secret field before it hits
  the kv blob; on use, `Vault.Decrypt`. These are **global** → platform DEK.
- **SNMP creds** (`snmp_creds.go`): tenant-scoped → **tenant DEK**. Encrypt
  `community`/`auth_key`/`priv_key`; decrypt where the collector consumes them.
- Storage backend untouched: the encrypted blob rides the existing `kvBackend` /
  `pgStore` path (`kvstore.go`, `pgstore.go`). Wrapped DEKs live in a small
  `wrapped_keys` table added by a new migration (`0002_secret_custody.sql`) or in
  `app_kv` for the file backend.

---

## 5. Failure modes (fail closed, observable)

- **TPM/sidecar unavailable at boot:** the KEK can't be unsealed → the Vault
  refuses to start → **the API fails to start** (loud, not silent). Matches the
  `assertRLSCapable` fail-closed precedent in `db.go`.
- **Sidecar dies at runtime:** unwrapped DEKs are cached in memory, so in-flight
  decrypts continue; *new* tenant DEK creation blocks until it recovers
  (bounded + logged — no silent fallback to plaintext, ever).
- **Decrypt failure (wrong tenant / tampered ciphertext):** GCM auth fails → error
  surfaced, secret treated as unavailable. No partial/plaintext fallback.

---

## 6. Migration of existing plaintext secrets

1. Ship the Vault dormant (reads pass through plaintext if not `v1:`-prefixed).
2. **Encrypt-on-next-write:** any Save re-persists the field encrypted.
3. **One-time re-seal pass** at boot (opt-in `SECRETS_RESEAL=true`): walk the
   config + SNMP stores, encrypt any still-plaintext secret, rewrite. Idempotent
   (skips `v1:`-prefixed). Logged.
4. Once confirmed, plaintext reads are removed (a stray plaintext secret then
   becomes a loud error, not a silent accept).

---

## 7. Phased build plan

| Phase | Deliverable | Notes |
|------|-------------|-------|
| **1a** | ✅ **DONE** swtpm sidecar (tpm2-tools) + `SealingProvider` + Unix-socket client | `deployment/docker/swtpm-sidecar/` + compose `secrets-seal` (profile `seal`); `secrets_swtpm.go` client. No Go dep. Profile-gated; not live-verified in this env (no TPM) — gated test `SEAL_SWTPM_TEST`. |
| **1b** | ✅ **DONE** `Vault` envelope layer (`secrets.go`) + `wrapped_keys` storage | stdlib AES-256-GCM; per-tenant + platform DEK; AAD = tenant\|fieldID. Wrapped DEKs ride the kv backend (no migration needed). Dormant default. Unit-tested. |
| **1c** | 🟡 **PARTIAL** Wire stores through the Vault | ✅ SNMP creds (tenant DEK) + integration `webhook_secret` (tenant DEK). ⏳ remaining config stores: `notify_config.go` (SMTP/Twilio/ntfy/Slack-webhook), `oidc_config.go`, `auth_config.go` (LDAP/TACACS), `copilot_config.go` — platform DEK, same pattern. Re-seal pass (`SECRETS_RESEAL`) env reserved; encrypt-on-next-write is the active path. |
| **2** | TLS private keys through the same Vault | lands with #18; seam already exists |
| **3** | `JWT_SECRET` + bootstrap secrets off `.env` into the sealed store | changes bootstrap; do last. (Note: compose's `ENCRYPTION_KEY` is currently an unused placeholder — a candidate env-KEK seam.) |
| **later** | `tpm2Provider` (real HW, PCR seal + attest), `kmsProvider`, `hsmProvider` | drop-in; no caller change |

## 8. Test plan

- **Unit (no TPM):** Vault round-trips; AAD mismatch (wrong tenant/field) fails to
  decrypt; versioned-prefix handling; plaintext-passthrough during migration.
- **Gated live (swtpm present):** like `DATABASE_URL_TEST` — `SEAL_SWTPM_TEST=1`
  exercises real seal/unseal through the sidecar; cross-tenant decrypt is proven
  impossible; KEK rotation re-wraps all DEKs.
- **Fail-closed:** sidecar down → boot aborts with an observable error.

## 9. Open decisions

- KEK/DEK **rotation** cadence + re-wrap procedure (design now, automate later;
  ties to #30 cert rotation).
- On **real TPM**, which **PCRs** to seal against (measured-boot policy) — defer
  to the `tpm2Provider` phase.
- Whether `wrapped_keys` is its own RLS table or `app_kv` (lean: own table,
  platform-scope — DEKs are platform-custody even when they protect tenant data).
