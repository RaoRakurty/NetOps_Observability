# ADR-SEC-007 — Secret sealing: keep `internal/vault` + swtpm, require sealing in production, refuse to boot an unsealed CA

- **Status:** **Accepted (owner, 2026-08-04)** — **partially implemented,
  formalizing.** Decision: **keep the existing `internal/vault` envelope layer
  and the swtpm sealing sidecar.** Add two enforcement rules that do not exist
  today: **`REQUIRE_SEAL` in production**, and a **boot refusal when
  `TLS_INTERNAL_CA=true` is set without a seal provider** — the verified defect
  in which the internal CA's private key is written in plaintext.
  HashiCorp Vault, cloud KMS, Kubernetes Secrets + encryption-at-rest, and the
  External Secrets Operator are **documented future options, not v1**; their
  analysis is retained below so a later revisit starts from it.
- **Implementation state:** the custody layer is **built and tested**
  (`docs/design/secret-custody.md` §7: phase 1a swtpm sidecar + `SealingProvider`
  ✅, 1b `Vault` envelope ✅, 1c store wiring ✅). It is **dormant by default** —
  `SEAL_PROVIDER` is empty unless set (`deployment/docker/docker-compose.yml:1448`)
  and the live `.env` sets no `SEAL_*` variable at all (HLD §1.1). The two
  enforcement rules are **not implemented**.
- **Owner rationale:** zero new components. The sealing sidecar already exists
  (`deployment/docker/swtpm-sidecar/`, compose service `secrets-seal`, profile
  `seal`, `docker-compose.yml:1683-1693`); the envelope layer is stdlib
  AES-256-GCM with no new dependency. The gap is **enforcement**, not capability
  — and enforcement is a boot check, not a subsystem.
- **Relates to:** `docs/design/secret-custody.md`; HLD §6.1 (domain 4), §6.5,
  §11.2; ADR-SEC-002 (the in-process root is only tolerable *because* of this
  ADR); ADR-SEC-008 (this is one of the fail-closed rules);
  `docs/runbooks/security/secret-unseal-failure.md`,
  `docs/runbooks/security/ca-compromise-response.md`.

---

## Context

### What already exists

Correlix has a complete, stdlib envelope-encryption layer with a pluggable
custodian:

| Piece | Where | State |
|---|---|---|
| `SealingProvider` interface (`Seal`/`Unseal` of a 32-byte root KEK) | `docs/design/secret-custody.md` §4.1; `src/backend/internal/vault/secrets_swtpm.go` | ✅ built |
| swtpm sidecar shelling to `tpm2-tools` over a Unix socket (**no Go TPM dependency** — keeps `go.mod` clean under root `CLAUDE.md` §6) | `deployment/docker/swtpm-sidecar/`, compose `secrets-seal` (profile `seal`), `docker-compose.yml:1683-1693` | ✅ built, live-validated (`docs/runbooks/tls-mtls.md` "Validation status") |
| Envelope layer: root KEK → platform DEK + per-tenant DEKs → AES-256-GCM ciphertext, **AAD = `tenant\|fieldID`** | `src/backend/internal/vault/secrets.go`, `tenantkeys.go` | ✅ built, unit-tested |
| Dormant passthrough when no provider is configured | `src/backend/internal/vault/dormant.go` | ✅ built |
| Stores wired through it | SNMP credentials + integration `webhook_secret` (tenant DEK); notify/OIDC/LDAP/TACACS secrets (platform DEK) — `secret-custody.md` §7 phase 1c | ✅ built |
| Selection knob | `SEAL_PROVIDER` / `SEAL_SOCKET` (`docker-compose.yml:1448-1449`) | ✅ built, **empty by default** |

The AAD binding is the part worth naming explicitly: a ciphertext copied from
one tenant's row into another's fails to decrypt, so a query or RLS bug leaks
ciphertext rather than secrets (`secret-custody.md` §3). That is real
defence-in-depth, already shipped.

### The two gaps

**Gap 1 — sealing is optional everywhere, including production.** `SEAL_PROVIDER`
defaults to empty; the Vault runs in passthrough and every "sealed" secret is
stored in the clear. Nothing warns, nothing refuses. A production deployment can
therefore look fully configured while the custody feature is off.

**Gap 2 — the verified defect: an unsealed internal CA writes its private key in
plaintext.** `src/backend/tls_ca.go` says so in its own header:

> ```
> 22 //
> 23 // Dormant unless TLS_INTERNAL_CA=true. When the Vault is also dormant the CA key
> 24 // is stored plaintext (passthrough) — turning on SEAL_PROVIDER=swtpm seals it.
> ```

The CA key is stored as a Vault field (`tls_ca.go:31` — `caKeyField =
"tls.ca.key"`, platform DEK), so when the Vault is dormant that field is written
unencrypted. The result is a **10-year root** (`tls_ca.go:33`, `caValidity`) that
signs **every internal service identity**, sitting readable on disk and in every
backup. An operator following `docs/runbooks/tls-mtls.md` who sets
`TLS_INTERNAL_CA=true` but skips `SEAL_PROVIDER=swtpm` gets a working mesh and a
plaintext root, with no signal that anything is wrong.

This is the single most consequential foot-gun found in the inventory. HLD §1.1
and §5 (threat T11, "CA compromise", scored **MED-HIGH**) both call it out, and
ADR-SEC-002's decision to keep an in-process root in v1 is *only* defensible if
this gap is closed.

### The honest limit of swtpm

swtpm is a **software emulator — its state is a file** (`secret-custody.md` §2).
It protects against a stolen disk, a DB dump, a backup leak and a read-only
exfiltration bug. It does **not** protect against root compromise of the running
host, and its attestation is meaningless there. It is correct for dev, lab, and
for *building the integration*; production assurance on real hardware needs a
TPM 2.0 with PCR sealing, an HSM, or a cloud KMS — all of which drop in behind
the same `SealingProvider` interface with no caller change.

## Decision

**1. Keep `internal/vault` + the swtpm sidecar as the v1 sealing provider.**
No new secret-management component ships in v1.

**2. `REQUIRE_SEAL=true` is mandatory in the production deployment profile.**
When set, the API refuses to start unless a sealing provider is configured *and*
unseals successfully. This is a profile-level rule (HLD §6.5: production ⇒
"`REQUIRE_SEAL=true` — boot fails unsealed"), enforced by the production
validator (ADR-SEC-008), not left to the operator's memory.

**3. `TLS_INTERNAL_CA=true` without a working seal provider is a BOOT REFUSAL, in
every profile except `lab`.** This closes Gap 2. The refusal must fire *before*
the CA is generated or loaded — a plaintext key that is written and then
complained about has already leaked.

The error message must be actionable and must name both the cause and the fix,
e.g.:

```
FATAL: TLS_INTERNAL_CA=true requires a sealing provider — refusing to start.
  The internal CA's private key signs every service identity in this deployment
  and would be written to disk in PLAINTEXT (see docs/adr/ADR-SEC-007).
  Fix:  docker compose --profile seal up -d secrets-seal
        SEAL_PROVIDER=swtpm  (on the api service)
  Lab only: DEPLOYMENT_PROFILE=lab to accept an unsealed CA key.
```

**4. Lab is the only escape hatch, and it is explicit.** A lab profile may run
unsealed; it must say so loudly at boot and the posture must be visible, never
inferred. (ADR-SEC-008 owns the profile mechanics.)

**5. Fail closed, never degrade.** If the sidecar is unavailable at boot, the KEK
cannot be unsealed and the API does not start (`secret-custody.md` §5 — matching
the existing `assertRLSCapable` precedent in `db.go`). If the sidecar dies at
runtime, cached DEKs keep in-flight decrypts working and *new* DEK creation
blocks, bounded and logged. **There is no plaintext fallback at any point.**

**6. The `SealingProvider` seam is the upgrade path.** `tpm2Provider`
(real hardware, PCR-sealed), `kmsProvider` and `hsmProvider` drop in with no
caller change (`secret-custody.md` §4.1, §7). Choosing swtpm for v1 does not
commit the product to it.

**7. The sealing root is trust domain 4 and stays separate** from every transport
CA (ADR-SEC-002). Direction of dependency is one-way and must stay that way: the
transport CA key is *protected by* the sealing root; the sealing root is never
protected by, derived from, or recoverable through the transport PKI.

## Alternatives considered

| Alternative | Assessment |
|---|---|
| **Keep `internal/vault` + swtpm (CHOSEN for v1)** | **Pro:** already built, tested and live-validated; no new service, no new Go dependency (the TPM interaction lives in a sidecar shelling to `tpm2-tools`, deliberately, `secret-custody.md` §4.2); works offline and in an air-gapped appliance; `SealingProvider` keeps every stronger custodian a drop-in. **Con:** swtpm is not a hardware root of trust; a root-compromised host defeats it; PCR/measured-boot policy is not yet used even where real TPM hardware exists. |
| **HashiCorp Vault (Transit / KV)** | **Pro:** the industry default; real key management, rotation, leasing, audit; many enterprise customers already run it, and where they do it is the *right* answer. **Con for v1:** a substantial new service to deploy, unseal, back up, upgrade and secure — and a hard runtime dependency at boot for a product that ships single-node and air-gapped installs. Rejected for v1 on overhead; retained as the first-choice option for Vault-native customers and as the natural `kmsProvider`-shaped integration. |
| **Cloud KMS (AWS KMS / GCP KMS / Azure Key Vault)** | **Pro:** no infrastructure to run; hardware-backed key custody; per-call audit; the strongest option for a SaaS deployment. **Con:** requires network egress to the provider on every unseal, ties the deployment to a cloud account, and is unavailable to appliance/air-gapped installs — which are a first-class deployment shape here. Rejected for v1 as the *default*; ideal as `kmsProvider` for the hosted offering. |
| **Kubernetes Secrets + encryption-at-rest (KMS provider on etcd)** | **Pro:** zero application code; native to a k8s deployment. **Con:** there is no Kubernetes substrate — no manifests, Helm charts or kustomize overlays exist anywhere in the repo, and #114 is unstarted (HLD §1.3). It also protects secrets only *at rest in etcd*: any pod with the Secret mounted sees plaintext, and it provides **no per-tenant key separation**, which is the property `internal/vault`'s per-tenant DEK + AAD binding exists to deliver. Not a substitute even under k8s. |
| **External Secrets Operator (ESO)** | **Pro:** a clean way to sync secrets from Vault/KMS into a cluster; good operational ergonomics once k8s exists. **Con:** it is a *distribution* mechanism, not a custody mechanism — it still needs a real backing store (Vault/KMS), and it needs Kubernetes. It solves a problem Correlix does not yet have, on a substrate it does not yet run. Revisit at Phase 7 (HLD §9). |
| **Environment variables / `.env` only (status quo default)** | **Rejected.** This is the current effective behaviour when `SEAL_PROVIDER` is unset, and it is exactly what `secret-custody.md` §1 was written to eliminate: anyone with the file or a DB dump reads every reversible secret in the clear. |
| **Application-level encryption with a static key in config** | Rejected: moves the problem to "where does the key live", with no custodian and no rotation story. It is envelope encryption without the envelope. |
| **Age/SOPS-style file encryption of the compose `.env`** | Rejected as insufficient: protects the file at rest but requires the decryption key at boot with no custodian, and gives no per-tenant separation and no runtime protection for secrets already loaded into stores. |
| **Do nothing about Gap 2** (document the foot-gun, do not enforce it) | **Rejected.** A documented foot-gun in a security control is a foot-gun. The header comment at `tls_ca.go:22-24` has been accurate and present the whole time and did not prevent the exposure — enforcement is the only thing that will. |

## Consequences

**Positive**
- **Makes the "everything over TLS" claim safe to make.** A demonstrable mesh
  whose CA key sits in plaintext on disk would be worse than no claim at all: it
  would be a control that fails silently and completely if the host is imaged,
  backed up, or copied. The boot refusal is what makes the v1 in-process root
  (ADR-SEC-002) an acceptable design rather than a latent incident.
- No new components; the entire decision is enforcement on top of shipped code.
- Per-tenant DEKs plus AAD binding mean an RLS or query bug leaks ciphertext,
  not credentials — a property most competing designs do not have.
- The `SealingProvider` seam means "we use swtpm today" never becomes "we are
  stuck with swtpm".

**Negative**
- **A misconfigured upgrade now fails to start rather than starting insecurely.**
  That is the intent (ADR-SEC-008 states the availability tradeoff in full), but
  it is a real operational change: an operator who removes the `seal` profile
  takes the API down.
- **swtpm is a software emulator.** v1's production assurance is therefore
  weaker than the design's endpoint. This must be stated honestly to customers —
  "sealed to this host" is true; "hardware root of trust" is not, unless a real
  TPM/HSM/KMS provider is configured.
- **The sidecar becomes a boot-critical dependency.** `secrets-seal` down at
  start ⇒ no API. Its own health, restart policy and startup ordering matter more
  than they did when the feature was dormant.
- **KEK/DEK rotation is designed but not automated** (`secret-custody.md` §9,
  first open decision). Requiring sealing in production makes rotation an
  operational need, not a future nicety.

## Security implications

- **Closes the plaintext-CA-key defect (HLD T11).** After this, there is no
  supported configuration in which the internal CA's private key exists
  unencrypted outside a lab profile.
- **Mitigates T13 (plaintext credential exposure) at rest** for every secret
  already wired through the Vault: SNMP credentials, webhook secrets, SMTP/
  Twilio/ntfy/Slack/PagerDuty tokens, the OIDC client secret, the LDAP bind
  password, the TACACS+ shared secret (`secret-custody.md` §7 phase 1c).
- **Does not fix secrets in transit.** The per-tenant sealing keys are still
  fetched over plaintext HTTP by the Vector router
  (`deployment/docker/vector-router/cx-secret-backend.sh:24` — `API=
  "${SEALING_API_URL:-http://api:8080}"`, fetch at `:55`), authenticated by the
  shared ingest credential. **Sealing at rest and shipping the key in the clear
  is self-defeating**; that hop is a P0 in HLD §7 and belongs to the transport
  work, not to this ADR. Both must land, and if only one can, the transport hop
  is the more urgent.
- **Does not fix the `.env` bootstrap secrets.** `JWT_SECRET` and the database
  password still live in `deployment/docker/.env` (`secret-custody.md` §7 phase 3
  — deliberately last, because it changes bootstrap). `REQUIRE_SEAL` does not
  cover them, and claiming otherwise would be false.
- **Backups inherit the custody model, and that cuts both ways.** Ciphertext in a
  backup is inert without the host's sealed KEK — excellent for confidentiality,
  and a restore hazard: a backup restored onto a *different* host cannot be
  decrypted. That is the whole reason the backup encryption authority is a
  separate trust domain (ADR-SEC-002 domain 5) and why
  `docs/runbooks/security/restore-encrypted-backup.md` exists.
- **swtpm's state is a file.** Whoever can read the sidecar's state directory can
  recover the KEK. Its volume permissions are part of the control surface, not
  an implementation detail.

## Operational implications

- **Enabling sealing is one compose command** — `docker compose --profile seal
  up -d secrets-seal` plus `SEAL_PROVIDER=swtpm` on the api
  (`docs/runbooks/tls-mtls.md` step 1–2). The runbook already exists; what
  changes is that production stops treating it as optional.
- **Startup ordering matters.** The sidecar must be healthy before the API's
  first unseal attempt; a race looks identical to a real custody failure.
- **New boot-failure class for operators to recognize.** The error text in
  decision 3 is not cosmetic: an unhelpful fatal here will be misdiagnosed as a
  TLS problem. `docs/runbooks/security/secret-unseal-failure.md` is the triage
  path.
- **Rotation runbooks become necessary:** KEK rotation re-wraps every DEK; the CA
  key is "just another sealed secret" (`docs/runbooks/tls-mtls.md`, Rotation).
  Cadence is undecided (U3).
- **Monitoring:** unseal success/failure, sidecar availability, and — once
  rotation exists — key age. A silent custody failure is not acceptable under
  root `CLAUDE.md` §10.

## Migration implications

1. **No data migration is required.** The Vault already supports plaintext
   passthrough for values without the `v1:` prefix and encrypts on next write
   (`secret-custody.md` §6). Turning sealing on does not invalidate anything
   already stored.
2. **Order matters: enable sealing *before* enabling the internal CA.** If
   `TLS_INTERNAL_CA=true` is switched on first, the CA key is written in
   plaintext and later sealing does not retroactively protect the copy already
   on disk (and in any backup taken since). The bootstrap runbook
   (`docs/runbooks/security/bootstrap-pki.md`) sequences this deliberately.
3. **Deployments that already enabled the CA unsealed must treat the key as
   exposed** — seal, then **rotate the CA** (`rotate-workload-ca.md`), not merely
   seal in place. Sealing a leaked key protects nothing.
4. **A one-time re-seal pass exists but is not the active path**
   (`SECRETS_RESEAL` env, reserved; encrypt-on-next-write is what runs today —
   `secret-custody.md` §7 phase 1c). If a deployment needs every stored secret
   encrypted immediately rather than on next write, that pass must be finished
   and exercised first.
5. **Restore compatibility is a migration concern.** A backup taken before
   sealing restores fine; a backup taken after sealing requires the same KEK.
   The DR procedure must be validated before production sealing is mandatory —
   otherwise the control creates an unrecoverable-backup incident.

## Unresolved questions

- **RESOLVED (owner, 2026-08-04):** keep `internal/vault` + swtpm; `REQUIRE_SEAL`
  in production; boot refusal for `TLS_INTERNAL_CA` without a seal provider.
  Vault / cloud KMS / k8s Secrets / ESO are future options, not v1.
- **U1 — Is `REQUIRE_SEAL` a new env var or a derived property of
  `DEPLOYMENT_PROFILE=production`?** HLD §6.5 implies the latter; a standalone
  var is easier to test but adds a second way to be wrong. ADR-SEC-008 should
  own this.
- **U2 — Does the boot refusal apply to `staging` as well as `production`?**
  HLD §6.5 says staging prohibits plaintext "except declared exceptions"; whether
  an unsealed CA can *ever* be a declared exception outside lab is unstated. The
  recommendation is no.
- **U3 — KEK/DEK rotation cadence and procedure.** Designed, not automated
  (`secret-custody.md` §9). Becomes load-bearing the moment sealing is mandatory.
- **U4 — Which PCRs to seal against on real TPM hardware** (measured-boot
  policy)? Deferred to the `tpm2Provider` phase (`secret-custody.md` §9).
- **U5 — Multi-host / HA custody.** The KEK is sealed to *one* host's TPM. A
  second API instance cannot unseal it. Any HA story needs a shared custodian
  (KMS/HSM) or a documented per-host KEK with re-wrapped DEKs — unaddressed.
- **U6 — What happens to the sealing-key distribution hop?**
  `cx-secret-backend.sh` fetching per-tenant keys over plaintext HTTP is tracked
  as a transport P0, but the *design* question — should edge sealing keys be
  distributed at all, or should sealing happen server-side? — has never been
  asked.
- **U7 — `.env` bootstrap secrets** (`JWT_SECRET`, DB password, and the unused
  `ENCRYPTION_KEY` placeholder noted in `secret-custody.md` §7) remain outside
  the sealed store. Phase 3 of secret-custody; no date.
