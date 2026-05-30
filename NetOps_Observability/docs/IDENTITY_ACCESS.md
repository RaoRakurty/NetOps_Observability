# Identity & Access (design)

> **Status: design / scaffolding.** The UI for this lives under
> **Administration** (`src/frontend/src/tabs/admin.tsx`) as *planned previews*.
> This document is the build plan. Today's working auth is the single-admin JWT
> flow in [`AUTH.md`](AUTH.md); everything here extends it without throwing it
> away.

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
verify RS256 against a JWKS URL (stdlib `crypto/rsa` + `encoding/json`).

---

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
