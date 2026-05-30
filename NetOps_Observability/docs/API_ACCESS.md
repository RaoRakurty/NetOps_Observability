# API Access

> **Status: implemented.** Scoped, tenant-bound API keys, token auth with
> rotating refresh, and a live **OpenAPI 3** document (`GET /api/openapi.json`,
> rendered in **Administration → API Access**) are all live. A GraphiQL explorer
> and per-key rate limits remain follow-ups. Backend: `apikeys.go`, `openapi.go`,
> `auth.go`, `refresh.go`.

NetOps is **API-first**: every action in the dashboard is already a documented
HTTP call against the Go API. This document makes that programmatic surface a
first-class, self-service product feature — **scoped API keys**, **token auth
with refresh**, a **live OpenAPI reference**, and a **GraphQL explorer**.

---

## What exists today

- REST + JSON endpoints under `/api/` (devices, logs, flows, alerts, findings,
  tunnels, …), all behind `Authorization: Bearer <JWT>`.
- A **GraphQL stub** at `/api/graphql` in the Go backend.
- A WebSocket event hub for live updates.

What's missing is *self-service*: non-interactive clients (CI, Grafana
datasource, sync jobs) shouldn't use a human's JWT. That's what API keys add.

---

## API keys

- **Creation:** Administration → API Access → *Generate key*. Shown **once**;
  only a hash is stored (`api_keys.hash`).
- **Scoping:** each key carries a scope list (e.g. `read:metrics`,
  `read:alerts`, `write:incidents`) and is **tenant-bound** and **RBAC-bound** —
  a key can never exceed the permissions of the role it's minted under.
- **Auth:** `Authorization: Bearer <api_key>` (or `X-API-Key`). The middleware
  resolves a key the same way it resolves a JWT — into a `(tenant, permissions)`
  context — so downstream RBAC enforcement is identical.
- **Lifecycle:** `created_at` / `last_used_at` tracked; revoke is immediate
  (`revoked_at` set, key rejected). Optional expiry per key.

Table shape is in [`IDENTITY_ACCESS.md`](IDENTITY_ACCESS.md#data-model-postgresql).

---

## Token auth (interactive clients)

Same JWT mechanics as the UI (see `IDENTITY_ACCESS.md` → Tokens):

- short-lived **access token** (default 15 min),
- rotating **refresh token** (default 7 days) via `POST /api/auth/refresh`,
- RS256 so the verification path is shared with Keycloak.

A client either uses a long-lived **API key** (machine) or the
**access+refresh** pair (interactive). Both land in the same RBAC context.

---

## Self-describing API

- **OpenAPI 3:** serve a generated spec at `/api/openapi.json` and embed a
  reference ("try it" console) in the API Access page. Generated from the Go
  handlers (annotations or a small registry) so it can't drift.
- **GraphQL:** promote the existing stub to a real schema and ship an in-app
  explorer (GraphiQL-style) at `/api/graphql`. One endpoint, typed, introspectable.
- **Rate limits & quotas:** per-key rate limiting (nginx `limit_req` keyed on the
  key id, and/or app-level token bucket); surfaced in the UI per key.

---

## Build order

1. `api_keys` table + key middleware (resolve key → RBAC context).
2. API Access UI wired to key CRUD (generate / list / revoke).
3. OpenAPI generation + embedded reference.
4. GraphQL schema + explorer.
5. Per-key rate limiting + usage stats.

Depends on the RBAC context from steps 1–2 of `IDENTITY_ACCESS.md`.

---

## Related

- [`IDENTITY_ACCESS.md`](IDENTITY_ACCESS.md) — auth, RBAC, tenancy, tokens.
- [`AUTH.md`](AUTH.md) — current live auth.
- UI: `src/frontend/src/tabs/admin.tsx` (`ApiAccessAdmin`).
