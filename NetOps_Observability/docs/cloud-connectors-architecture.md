# Cloud Connectors — Architecture

How a Correlix tenant connects an AWS / Azure / GCP account for read-only
observability, **secure-by-default and federated-first**. Provider-neutral at the
API and UI; provider-specific only in the adapters.

## 0. The two identity planes are completely separate (non-negotiable)

Correlix has two identity planes that share **no** credentials, sessions or config
objects:

| Plane | Direction | What | Where it lives |
|-------|-----------|------|----------------|
| **Human auth** | user → Correlix | SSO/OIDC/SAML/local login of a person into the product | existing `auth_config.go`, `oidc_config.go`, session/JWT layer — **untouched by this work** |
| **Machine auth** | Correlix → cloud | a workload identity Correlix uses to read a customer's cloud | `cloudconn/` + the Identity Broker — **this work** |

The machine plane's "OAuth/OIDC secure way" is **OIDC-based Workload Identity
Federation** (Azure Entra WIF, GCP WIF, AWS OIDC→role), plus **admin-consent
OAuth** as an Azure *setup* step. That is NOT the human login OIDC. A cloud admin
username/password is never a connector credential (`AuthMethodProhibited`).

## 1. A CloudConnection is five separate concerns

Modeled in `cloudconn` (not one opaque "credentials" blob):

1. **Identity** (`IdentityConfig`) — who Correlix authenticates AS. Trust metadata
   ONLY (role ARN, client/tenant id, workload provider, audience, issuer,
   ExternalId, cert thumbprint, SA email, a `csr_` secret handle). Never a secret.
2. **Authorization** (`CapabilityPack` FullID) — what it may do. Versioned,
   immutable, least-privilege, read-only.
3. **Collection scope** (`[]Scope`) — where to collect (org/account/subscription/
   project/region/...). Distinct from the *permission* scope; a mismatch is a
   warning, never a silent widening.
4. **Data sources** — the telemetry lanes, declared by the pack's capabilities.
5. **Health + audit** — **identity health** (can we authenticate?) is tracked
   SEPARATELY from **telemetry health** (is data flowing?). A successful auth never
   implies data is flowing or permissions are complete.

The identity key is the opaque `ccn_<random>` id — never a display name, account,
subscription, project name or client id.

## 2. Connector identity preference order

`cloudconn/provider.go` ranks methods (lower = preferred), federated-first:

1. `workload_identity_federation` — secretless OIDC federation **(recommended, visually dominant)**
2. `cloud_role` — cross-account role / managed identity (AWS AssumeRole + ExternalId)
3. `certificate` — customer cert (Azure)
4. `client_secret` — rotatable client secret (Azure) — **legacy, de-emphasized**
5. `static_key` — static access key / SA key — **legacy, de-emphasized**
6. `admin_password` — **PROHIBITED** (rejected by validation)

`ProviderMethods(p)` returns each provider's methods federated-first; the wizard
renders index 0 as "Recommended" and marks `IsLegacy()` methods "legacy — not
recommended".

## 3. The three federated connection methods (the core deliverable)

### AWS — cross-account IAM role via STS AssumeRole
- Trust: a role in the **customer** account trusts the **Correlix** principal,
  gated by a **per-tenant+connector, cryptographically-random ExternalId**
  (`cloudconn.NewExternalID`, 160-bit, `correlix-` prefixed) — confused-deputy
  protection. Never derived from tenant/account/email/name. No wildcard principal,
  no root (`awsAdapter.ValidateConfiguration`).
- Setup: `SetupInstructions` renders CloudFormation, Terraform and manual-IAM
  templates wiring the exact ExternalId + the pack's least-privilege permissions,
  `MaxSessionDuration: 3600`.
- Runtime (deferred): `sts:AssumeRole(RoleArn, ExternalId, DurationSeconds ≤ cap)`.

### Azure — Entra Workload Identity Federation (+ admin-consent OAuth setup)
- Preferred: a **federated credential** on the Correlix app registration trusts
  the Correlix workload OIDC issuer/subject; runtime presents that assertion for a
  short-lived Azure token. No stored secret.
- Setup: `SetupInstructions` renders the federated-credential JSON, an `az` CLI
  script granting **Reader + Monitoring Reader** at subscription scope, and the
  **admin-consent OAuth** ("Connect with Microsoft") flow. Admin-consent grants
  APP roles; runtime uses the app/workload identity, **never** a delegated user
  token, and stores no user session.
- Fallbacks: `certificate` (non-federated), `client_secret` (legacy).

### GCP — Workload Identity Federation (+ optional SA impersonation)
- Preferred: a **workload identity pool + OIDC provider** federated to the
  Correlix issuer; runtime exchanges the assertion for a short-lived federated
  token (optionally impersonating a least-privilege observer SA). No stored key.
- Setup: `SetupInstructions` renders gcloud/Cloud-Shell + Terraform creating the
  pool/provider + observer SA with viewer roles + the `workloadIdentityUser`
  binding.
- Fallback: `static_key` (SA JSON key, legacy; owner/editor/default-compute SA
  rejected).

Legacy secrets across all three: labeled "legacy — not recommended", root/admin
rejected, **encrypted immediately via the existing Vault**, never re-displayed,
rotatable, and tenant-policy-disableable (policy hook is a follow-up).

## 4. The Cloud Identity Broker

`cloud_connectors_broker.go`. Collectors do NOT store or refresh credentials; they
ask the broker for a **scoped token**: one tenant, one connector, one provider
account, one identity, one bounded capability set, one bounded lifetime.

- **Cache key** binds tenant + connector + provider + provider-account + identity
  ref + capability-set hash + audience + region. Two tenants with identical role
  ARNs / client ids / account ids therefore never share a cache entry (proved by
  `TestBrokerTokenCacheTenantConnectorIsolation`).
- **Max lifetime** capped at 1h; a provider token exceeding the cap is rejected;
  tokens are never persisted and never logged.
- **Fail-closed**: disabled/revoked/draft/deleted connectors cannot mint a token
  (`LifecycleState.CanExchangeToken`).
- **Secret custody**: only the broker decrypts, via the existing envelope Vault
  (per-tenant DEK; field-id bound to `connector+kind`). `StoreSecret`/`RotateSecret`
  (version bump + rotation overlap); every secret create/access/rotate audited.

## 5. Lifecycle state machine

`DRAFT → DEPLOYING → VALIDATING → ACTIVE → DEGRADED → ROTATION_REQUIRED →
REAUTHORIZATION_REQUIRED → DISABLED → REVOKED → DELETING → DELETED`
(`cloudconn/connection.go`, `CanTransition`). A connector **cannot reach ACTIVE
without a successful configuration validation** (`activate` returns 409 until
`last_validation.OK`). Only ACTIVE/DEGRADED collect.

## 6. Onboarding wizard shape (UI is a follow-up)

Provider → Scope → **Auth method (federated methods dominant, legacy
de-emphasized)** → Deploy trust (render CloudFormation/Terraform/CLI/manual) →
Capabilities → Validate (exact remediation from `ValidationResult.Findings`) →
Review/Activate. Backed by:

| Step | API |
|------|-----|
| catalog | `GET /api/cloud/providers` |
| create draft | `POST /api/cloud/connectors` |
| select auth | `POST /api/cloud/connectors/{id}/auth` |
| deploy templates | `POST /api/cloud/connectors/{id}/setup` |
| select scopes | `POST /api/cloud/connectors/{id}/scopes` |
| discover scopes | `POST /api/cloud/connectors/{id}/discover-scopes` (deferred live) |
| select capabilities | `POST /api/cloud/connectors/{id}/capabilities` |
| validate trust | `POST /api/cloud/connectors/{id}/validate` (config validation, real) |
| validate permissions | `POST /api/cloud/connectors/{id}/permissions` (deferred live) |
| activate / disable / revoke | `POST /api/cloud/connectors/{id}/{activate\|disable\|revoke}` |
| store / rotate secret | `POST /api/cloud/connectors/{id}/{secret\|rotate}` |
| health | `GET /api/cloud/connectors/{id}/health` |
| delete | `DELETE /api/cloud/connectors/{id}` |

All tenant-scoped, RBAC-gated (`infrastructure` read/write), opaque ids,
optimistic version, **no secrets in any response**, stable error codes.

## 7. Coordination seam with the Azure/topology agents

The canonical capability contract lives in **`src/backend/cloudconn/`** (importable
package `netops/backend/cloudconn`). The Azure inventory/metadata agent and the
topology agent should import `cloudconn.CapabilityPack` / `Pack(fullID)` /
`PacksForProvider(p)` rather than redefining packs. If their capability model needs
fields this contract lacks, extend `cloudconn.Capability` (additively) — do not
fork. This package intentionally has no dependency on package main, the DB, or the
Vault, so it is safe to import from any layer.

## 8. Phased roadmap (deferred)

- **P5** AWS STS AssumeRole runtime + live permission/scope validation.
- **P6** Azure Entra WIF token runtime + admin-consent OAuth runtime.
- **P7** GCP WIF token-exchange runtime (+ SA impersonation).
- **P8** Onboarding wizard UI (reuse admin/integration primitives).
- **P9** Migrate the `deployment/docker/cloud-ingest/` Python sidecar to request
  broker tokens; retire env-var/mounted-file creds.
- **P10** Tenant-policy disable-legacy toggle; legacy→federated migration flow.
- **P11** Service View / topology consumption of connector-sourced inventory.
