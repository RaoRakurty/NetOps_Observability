# Security runbooks — index

Operator procedures for Correlix's transport-security, PKI, secret-custody and
incident-response work.

**Every document in this directory is an OUTLINE.** They are complete in
structure — purpose, prerequisites, safety warnings, pre-validation, numbered
procedure, rollback, audit evidence, post-checks — but several describe features
that are **not yet built**, and those steps are marked `[PENDING SEC-0XX]`
inline. Nothing here is an authorization to change a live system: the
implementation boundary in
[`docs/security/CORRELIX_CLOUD_NATIVE_SECURITY_HLD.md`](../../security/CORRELIX_CLOUD_NATIVE_SECURITY_HLD.md)
§12 still applies.

---

## Relationship to `docs/runbooks/tls-mtls.md`

**[`../tls-mtls.md`](../tls-mtls.md) is not superseded and must not be
duplicated.** It is the existing, validated enable-sequence for the internal
mesh — the internal CA bootstrap, the nginx↔API mTLS configuration (including
the exact `proxy_ssl_*` block), the outbound backend-TLS variables, the Postgres
DSN form, and the known failure modes. Parts of it are **live-validated** (swtpm
seal/unseal round-trip) rather than merely designed.

These runbooks **wrap** it:

| `tls-mtls.md` gives you | These runbooks add |
|---|---|
| How to turn the mesh on | The trust-domain model, the sealing-before-CA ordering rule, and the evidence to capture (`bootstrap-pki.md`) |
| Three lines on rotation | Full dual-root ceremony with overlap arithmetic and rollback (`rotate-workload-ca.md`, `rotate-service-certificate.md`) |
| Client-side backend TLS variables | The **server**-side migration each datastore needs before those variables mean anything (`opensearch-*`, `clickhouse-*`, `postgres-*`, `valkey-*`) |
| Failure modes, briefly | Triage and recovery paths (`secret-unseal-failure.md`, `ca-compromise-response.md`) |
| — | Device-lane onboarding, Phase 2 (`syslog-*`, `gnmi-*`, `rotate-device-ca.md`) |

When a step exists in both, **`tls-mtls.md` is authoritative for the commands**
and these runbooks are authoritative for the sequencing, safety and evidence.

Other existing runbooks these depend on:
[`../backup-restore.md`](../backup-restore.md) (operational authority for
backups), [`../secret-rotation.md`](../secret-rotation.md) (`.env` credentials),
[`../okta-sso-setup.md`](../okta-sso-setup.md).

---

## Readiness at a glance

| Runbook | What it is for | Executable today? |
|---|---|---|
| [`bootstrap-pki.md`](bootstrap-pki.md) | Stand up the v1 PKI: sealing custody → workload CA → nginx mTLS → public ingress | 🟡 **Partial** — CA bootstrap works; validator gate and offline root pending |
| [`rotate-workload-ca.md`](rotate-workload-ca.md) | Dual-root rotation of the internal CA with zero dropped connections | 🟡 **Partial** — `TrustBundle` supports multi-root; the staged second-root tooling does not exist |
| [`rotate-service-certificate.md`](rotate-service-certificate.md) | Replace one service's leaf SVID | 🟢 **Yes for `api`/`nginx`** (automatic at TTL/2); 🔴 pending for all other services |
| [`revoke-compromised-identity.md`](revoke-compromised-identity.md) | Contain a stolen key, token or certificate | 🟡 **Partial** — allowlist removal and rotation work; **there is no CRL/OCSP**, so revocation is eventual |
| [`secret-unseal-failure.md`](secret-unseal-failure.md) | The API refuses to start because it cannot unseal | 🟢 **Yes** — sidecar and fail-closed boot both exist |
| [`ca-compromise-response.md`](ca-compromise-response.md) | CA private key exposed or suspected exposed | 🟡 **Partial** — recovery mechanism exists; ceremony tooling does not |
| [`restore-encrypted-backup.md`](restore-encrypted-backup.md) | Restore with key custody and post-restore security reconciliation | 🟡 **Partial** — restore tooling exists; **backup encryption domain does not** (HLD T20) |
| [`postgres-tls-migration.md`](postgres-tls-migration.md) | Move app-state DB to `sslmode=verify-full` | 🟡 **Partial** — client side works today; server-side TLS is unbuilt deployment config |
| [`gnmi-certificate-onboarding.md`](gnmi-certificate-onboarding.md) | Verified TLS to gNMI targets | 🟡 **Partial** — per-target `tls-ca` is doable now; Correlix-issued client certs are **Phase 2** |
| [`kafka-tls-migration.md`](kafka-tls-migration.md) | Bus → mTLS + topic/group ACLs | 🔴 **No** — Kafka is `PLAINTEXT`, no auth, no ACLs |
| [`opensearch-security-bootstrap.md`](opensearch-security-bootstrap.md) | Enable the security plugin, TLS and roles | 🔴 **No** — `DISABLE_SECURITY_PLUGIN: "true"` |
| [`clickhouse-tls-migration.md`](clickhouse-tls-migration.md) | TLS + per-client users, preserving row policies | 🔴 **No** — plaintext + Basic today |
| [`valkey-acl-migration.md`](valkey-acl-migration.md) | ACL users + TLS | 🔴 **No** — no password, no TLS |
| [`syslog-tls-onboarding.md`](syslog-tls-onboarding.md) | Device onto the RFC 5425 secure syslog lane | 🔴 **No — PHASE 2**, lane does not exist |
| [`rotate-device-ca.md`](rotate-device-ca.md) | Rotate the device trust anchor | 🔴 **No — PHASE 2**, device CA does not exist |

🟢 executable · 🟡 partially executable, read the status banner · 🔴 outline only

---

## What each runbook is for

**PKI lifecycle**
- **`bootstrap-pki.md`** — first-time setup. Its most important content is an
  *ordering rule*: sealing custody must be working **before** the internal CA is
  enabled, because `TLS_INTERNAL_CA=true` without a seal provider writes the CA
  private key in plaintext (`src/backend/tls_ca.go:22-24`), and sealing
  afterwards does not protect the copy already on disk.
- **`rotate-workload-ca.md`** — planned rotation of the internal trust anchor via
  a dual-root window. The emergency variant is `ca-compromise-response.md`.
- **`rotate-device-ca.md`** — the same mechanics for the device domain, on a
  timescale of weeks, against equipment Correlix does not control. **Phase 2.**
- **`rotate-service-certificate.md`** — leaf-level rotation. Routine rotation is
  already automatic for `api` and `nginx`; the recurring manual step is
  **reloading nginx**, which does not hot-swap its client SVID.

**Incident response**
- **`revoke-compromised-identity.md`** — start here for a leaf/token compromise.
  Be honest about the limitation it documents: with no CRL/OCSP, "revoked" means
  "no longer re-issued and removed from allowlists", not "cryptographically
  invalid".
- **`ca-compromise-response.md`** — start here if the *CA* is suspect. Note its
  observation that the most likely real cause is an unsealed CA key, not an
  attacker.
- **`secret-unseal-failure.md`** — the API will not start. Its single most
  important warning: **do not "fix" it by unsetting `SEAL_PROVIDER`** — that
  turns an availability incident into a confidentiality and data-loss one.
- **`restore-encrypted-backup.md`** — the security half of a restore: key
  custody, the cross-host sealed-secret hazard, and the post-restore checks that
  re-prove tenant isolation before traffic is allowed back.

**Component migrations** (each moves one hop from plaintext to authenticated TLS)
- **`kafka-tls-migration.md`** — the highest-risk procedure in the programme;
  the bus is the spine and retention is the deadline for any stalled consumer.
- **`opensearch-security-bootstrap.md`** — the most invasive datastore change;
  currently there is **no authentication at all** in front of every tenant's logs.
- **`clickhouse-tls-migration.md`** — must preserve the row policies that are the
  strongest tenant control in the platform.
- **`postgres-tls-migration.md`** — climbs the `sslmode` ladder to `verify-full`
  while keeping FORCE-RLS intact.
- **`valkey-acl-migration.md`** — ACL users + TLS; note the compose healthcheck
  must change in the same commit or the stack marks itself unhealthy.

**Device lanes (Phase 2)**
- **`syslog-tls-onboarding.md`** — binds tenancy to a certificate instead of a
  spoofable hostname. Its "what v1 does instead" section is the part that applies
  today.
- **`gnmi-certificate-onboarding.md`** — has a rung ladder; rung 2 (verified TLS
  per target) is actionable now, rung 3 (mutual TLS) is Phase 2.

---

## Decision records

These runbooks execute the decisions in [`../../adr/`](../../adr/):

| ADR | Decision | Status |
|---|---|---|
| `ADR-SEC-001` | Per-peer transport policy: outbound mode + inbound accept-set; plaintext requires an owned, expiring exception | Accepted (owner) — v1 scope: intra-stack + ingress |
| `ADR-SEC-002` | Trust domains — v1 = public ingress + one workload domain | Accepted (owner) |
| `ADR-SEC-003` | Workload identity = the existing in-process internal CA, SPIFFE-compatible | Accepted (owner) |
| `ADR-SEC-004` | Native TLS + native authz per component; no service mesh | Accepted (owner) |
| `ADR-SEC-005` | Kafka authn = mTLS with the same internal CA | Accepted (owner) |
| `ADR-SEC-006` | Device identity: certs + per-device PSK, tenant in the identity, never auto-create | Proposed — **Phase 2**; v1 = protocol-native + honest labeling + segmentation |
| `ADR-SEC-007` | Keep `internal/vault` + swtpm; `REQUIRE_SEAL` in production; boot refusal on an unsealed CA | Accepted (owner) |
| `ADR-SEC-008` | Production fails closed at boot; lab is the escape hatch | Accepted (owner) |

---

## Conventions used in these documents

- **`[PENDING SEC-0XX]`** — the step requires a feature that is not built. It is
  written so it is ready when the backlog item ships.
- **Safety icons** — 🔴 can cause an outage, data loss, or lock operators out ·
  🟠 significant but bounded · ⚪ reversible / informational.
- **"Point of no return"** marks the specific step after which rollback is no
  longer available.
- Every runbook names, explicitly, **which steps can drop telemetry** — because
  in an observability platform, losing data while securing it is the failure mode
  that matters most.
- Any shell snippet added later must satisfy [`scripts/CLAUDE.md`](../../../scripts/CLAUDE.md)
  §16 (`set -euo pipefail`, explicit PATH, quoted expansions, bounded external
  calls, and **never** `|| true` around a security check).
