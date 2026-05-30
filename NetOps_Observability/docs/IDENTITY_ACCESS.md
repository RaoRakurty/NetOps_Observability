# Identity & Access

> **Status: implemented.** Local accounts, granular RBAC, multi-tenancy, rotating
> refresh tokens and SSO (OIDC/SAML/LDAP via Keycloak) are live in the Go API and
> under **Administration** (`src/frontend/src/tabs/admin.tsx`). This document is
> both the design rationale and the as-built reference. The identity/saved stores
> persist through a single pluggable backend (`kvstore.go`): file-backed by
> default, **Postgres** with `STORE_BACKEND=postgres` — same methods, same API
> (see *Storage backend* below).
>
> **As-built quick map**
> - Local auth + RBAC: `auth.go`, `rbac.go`, `identity_handlers.go`, `users.go`
> - Rotating refresh tokens: `refresh.go` (single-use, 7d, replay → revoke lineage)
> - SSO broker flow: `oidc.go`; RS256/JWKS verify: `jwks.go`
> - Multi-tenancy isolation: `tenancy.go` (+ `tenancy_test.go`)
> - Endpoints: `POST /api/auth/login` · `POST /api/auth/refresh` ·
>   `GET /api/auth/sso/{config,login,callback}` · `GET /api/auth/permissions`

The goal: turn the current single-admin login into a real, enterprise-ready
identity layer — **multi-tenant**, with **granular RBAC**, **built-in and custom
roles**, and **SSO/SAML/LDAP** — while keeping the Go backend dependency-free
(stdlib-only) by pushing federation out to **Keycloak**.

---

## The two planes

We deliberately split identity into two cooperating planes so the backend stays
lean and the enterprise features are pluggable:

```
                         ┌────────────────────────────┐
   Browser / API client  │  React SPA  ·  API clients  │
                         └───────────────┬────────────┘
                                         │ Bearer <JWT>
                         ┌───────────────▼────────────┐
   AUTHORIZATION plane   │   Go API (stdlib only)      │
   (who can do what)     │  · validates JWT (RS256)    │
                         │  · loads tenant + role grant│
                         │  · enforces RBAC per request│
                         │  · local accounts fallback  │
                         └───────────────┬────────────┘
                                         │ OIDC / token introspection
                         ┌───────────────▼────────────┐
   AUTHENTICATION plane  │   Keycloak (compose svc)    │
   (who you are)         │  · OAuth2/OIDC · SAML2      │
                         │  · LDAP/AD federation       │
                         │  · MFA, brute-force, JIT    │
                         └────────────────────────────┘
```

- **Authentication** (proving identity) → **Keycloak**. It already speaks OIDC,
  SAML 2.0 and LDAP/AD, does MFA and brute-force protection, and brokers
  external IdPs (Okta, Azure AD, Google). We do **not** reimplement SAML/LDAP in
  Go — that is the whole reason to add Keycloak.
- **Authorization** (deciding what you may do) → **our Go API**. RBAC and tenant
  scoping are product logic and stay in-house, enforced on every request.

**Local accounts** remain a first-class, always-available fallback (the existing
PBKDF2 + JWT path), so the stack still works with zero external IdP — Keycloak is
opt-in per deployment.

---

## Data model (PostgreSQL)

The user store moves from `users.json` to PostgreSQL (already in the stack for
app state). Proposed tables:

```
tenants(id, name, slug, settings_jsonb, created_at)

users(id, tenant_id?, email, display_name,
      auth_source ENUM(local|oidc|saml|ldap),
      pw_hash?,            -- only for auth_source=local
      external_subject?,   -- IdP 'sub' for federated users
      status ENUM(active|invited|disabled),
      created_at, last_seen_at)

roles(id, tenant_id?, name, builtin BOOL, description)
      -- tenant_id NULL = global/built-in role

permissions(role_id, module TEXT, level ENUM(none|read|write|admin))
      -- one row per (role, module); module ∈ product sections

memberships(user_id, tenant_id, role_id)
      -- a user can hold different roles in different tenants

api_keys(id, tenant_id, label, hash, scopes TEXT[], created_by,
         created_at, last_used_at, revoked_at?)   -- see API_ACCESS.md
```

A user with `tenant_id NULL` and a `Super Admin` membership is a cross-tenant
operator; everyone else is scoped through `memberships`.

---

## RBAC model

**Modules** map 1:1 to the product's nav sections, so permissions are intuitive:

`Overview · Explore · Alerts · Infrastructure · Topology · Reports · Administration`

**Levels** are a 4-step ladder, monotonic (each implies the one below):

| Level   | Means |
|---------|-------|
| `none`  | section hidden |
| `read`  | view dashboards, alerts, devices |
| `write` | acknowledge/silence alerts, run discovery, edit dashboards |
| `admin` | manage the module's config; on `Administration` = manage identity |

**Built-in roles** (global, non-deletable presets):

| Role        | Shape |
|-------------|-------|
| Super Admin | `admin` on every module, across all tenants |
| Operator    | `write` on Alerts/Infrastructure, `read` elsewhere, no Admin |
| Read-only   | `read` everywhere except Administration |

**Custom roles** are just rows: an admin composes any `(module → level)` grid in
the UI (the matrix on **Administration → Roles**) and scopes it to a tenant.
There is no special-casing — built-in roles are seeded rows with `builtin=true`.

### Enforcement

A single middleware resolves `(user, tenant)` from the JWT, loads the effective
permission grid, and gates each handler with a required `(module, level)`:

```go
mux.Handle("POST /api/alerts/{id}/ack",
    rbac.Require("Alerts", rbac.Write)(ackHandler))
```

Tenant scoping is enforced at the query layer (every tenant-owned table carries
`tenant_id`; the request's tenant is bound into each query). Defense-in-depth:
the UI also hides sections the user can't `read`, but the API is the source of
truth.

---

## Tokens (JWT)

- **Algorithm:** migrate local signing from HS256 → **RS256** so Keycloak and the
  Go API share one verification path (JWKS). Local accounts get tokens signed by
  the API's own RSA key; federated tokens are verified against Keycloak's JWKS.
- **Access token TTL:** short (default **15 min**), configurable.
- **Refresh tokens:** rotating, longer TTL (default **7 days**); refresh endpoint
  issues a new access token and rotates the refresh token (reuse detection).
- **Claims:** `sub`, `tenant`, `roles`, `email`, standard `exp/iat/iss/aud`.
- **Logout / revocation:** refresh-token revocation list in Postgres/Redis.

These knobs surface read-only on **Administration → Authentication → Token
policy** and are set via env / tenant settings.

---

## Keycloak integration

- Add Keycloak as a compose service (its own Postgres schema or DB).
- One **realm** per deployment; **tenants → Keycloak groups** (or realm roles)
  mapped onto NetOps `memberships` via a group/attribute mapper.
- **OIDC:** Authorization Code + PKCE from the SPA; the API validates the
  resulting JWT against Keycloak's JWKS.
- **SAML 2.0:** configured per-tenant in Keycloak (IdP metadata + attribute
  mapping); NetOps never parses SAML itself.
- **LDAP/AD:** Keycloak's LDAP federation provider binds to AD and syncs
  users/groups; group→role mapping flows through the same membership table.
- **JIT provisioning / SCIM:** first federated login upserts a `users` row
  (`auth_source` set, `pw_hash` null); optional SCIM endpoint for push-sync.

The Go backend gains **zero** third-party modules for this — it only learns to
verify RS256 against a JWKS URL (stdlib `crypto/rsa` + `encoding/json`, see
`jwks.go`).

### As-built: bringing SSO up

Keycloak ships as an **opt-in** compose service (it isn't in the default stack):

```bash
# 1. Create Keycloak's database in the bundled Postgres (one-time):
docker compose exec postgres createdb -U "$DB_USER" keycloak

# 2. Start the broker:
docker compose --profile sso up -d keycloak     # serves under /auth

# 3. In Keycloak: create a realm (e.g. `netops`), an OIDC *confidential* client
#    with redirect URI http://<host>:8000/api/auth/sso/callback, and (optionally)
#    add SAML/LDAP identity providers + a role/group mapper.

# 4. Point the API at it via .env, then `docker compose up -d api`:
OIDC_ENABLED=true
OIDC_ISSUER=http://<host>:8000/auth/realms/netops
OIDC_CLIENT_ID=netops
OIDC_CLIENT_SECRET=<from Keycloak>
OIDC_REDIRECT_URL=http://<host>:8000/api/auth/sso/callback
# Optional extra IdP buttons (id:Label:kind), e.g. a SAML and an LDAP provider:
OIDC_PROVIDERS=corp-saml:Corp SSO:saml,corp-ad:Active Directory:ldap
```

The login page and **Administration → Authentication** then render the live
providers; a Keycloak realm role in `OIDC_ADMIN_ROLES`/`OIDC_OPERATOR_ROLES`
maps a federated user onto a NetOps built-in role at first login.

---

## Multi-tenancy (as-built)

Tenant isolation is enforced at the API boundary, not just hidden in the UI:

- Every device carries a `tenant_id` (`models.Device`); empty = global/shared.
- Access tokens carry the principal's `tenant` claim (set at login / refresh /
  SSO callback from the user's tenant).
- A principal is **cross-tenant** (sees everything) when it is a super-admin or
  is unbound / bound to the `global` tenant — that covers the seeded admin and
  platform operators. Everyone else is **strictly scoped**: `GET /api/devices`
  returns only their tenant's (and shared/global) devices, `GET /api/alerts` is
  filtered to alerts on devices they can see, fetching another tenant's device by
  id returns **404** (never confirm it exists), and a scoped principal can only
  create devices inside its own tenant and delete only its own (not shared ones).
- Scoping extends past devices/alerts to the rest of the device-keyed surface:
  - **Flows** (`/api/flows/*`) are restricted to rows whose `src_addr`/`dst_addr`
    is one of the principal's device addresses; **tunnels** (`/api/tunnels`) to
    those terminating on a visible device.
  - **Findings** (`/api/findings`) are restricted to those whose `device` column
    matches a visible device id/name.
  - **Saved objects** (`/api/saved`) carry a `tenant_id`: a scoped principal sees
    only its own (and shared/global) objects, may mutate/delete only its own, and
    new objects are stamped with the creator's tenant. **Global search**
    (`/api/search/global`) applies the same device/alert/saved scoping.
  A scoped principal with no visible devices gets an empty (not errored) result.
- API keys are tenant-bound, so a machine client is scoped the same way.

See `tenancy.go`; the cross-tenant leak cases are pinned by `tenancy_test.go`,
`tenancy_saved_test.go` and `tenancy_flows_test.go`.

---

## Storage backend (file ↔ Postgres)

All the JSON-blob stores (users, roles, tenants, API keys, refresh tokens, SNMP
credentials, saved objects) persist through one seam — `kvBackend` in
`kvstore.go` — so moving them off local files is a backend swap with **no change
to any store's logic and no change to the HTTP API**:

- **`file`** (default) — atomic JSON files on the data volume (the original
  behavior, now centralized so every store shares one durable-write contract).
- **`postgres`** (`STORE_BACKEND=postgres` + `DATABASE_URL`) — each store's blob
  is one row in a `netops_kv(key, data, updated_at)` table (`pgkv.go`).

`pgkv.go` uses **only `database/sql` from the standard library**, so the default
build stays dependency-free per the stdlib-only invariant. A Postgres *driver*
(`lib/pq`, `pgx`, …) is third-party and is **not** imported; to run the Postgres
backend an operator compiles a driver in — a one-line, build-tagged blank import
registered under `DATABASE_DRIVER` (default `postgres`):

```go
//go:build pg
package main
import _ "github.com/lib/pq"
```

`go get github.com/lib/pq && go build -tags pg`. That single opt-in dependency is
the only place the dependency-free rule is relaxed, and only when Postgres is
chosen. Without a registered driver, startup fails fast (never a silent fallback
to files). The pluggability is pinned by `kvstore_test.go` (an in-memory backend
round-trips the saved + user stores with zero file I/O).

## Build order

1. **Postgres user store + local accounts CRUD** — replace `users.json`; keep
   PBKDF2; add `/api/users` (Super Admin only). *(Foundation.)*
2. **Tenants + memberships + RBAC middleware** — modules/levels, built-in roles
   seeded, enforcement on every handler. Wire **Users/Roles/Tenants** UI.
3. **RS256 + refresh tokens** — token policy, rotation, revocation.
4. **Keycloak** — compose service, OIDC first, then SAML, then LDAP/AD. Wire
   **Authentication** UI.
5. **API keys** — see [`API_ACCESS.md`](API_ACCESS.md).

Each step is independently shippable and leaves the existing login working.

---

## Related

- [`AUTH.md`](AUTH.md) — the current, live auth (single admin, JWT HS256).
- [`API_ACCESS.md`](API_ACCESS.md) — programmatic API & API keys.
- [`ITSM_INTEGRATION.md`](ITSM_INTEGRATION.md) — ServiceNow/Jira ticketing.
- UI: `src/frontend/src/tabs/admin.tsx`.
