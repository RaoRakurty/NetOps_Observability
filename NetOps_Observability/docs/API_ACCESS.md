# API Access

> **Status: implemented.** Scoped, tenant-bound API keys, token auth with
> rotating refresh, a live **OpenAPI 3** document (`GET /api/openapi.json`), an
> in-app **GraphQL explorer**, and **per-key rate limits + usage stats** are all
> live and rendered under **Administration → API Access**. Backend: `apikeys.go`,
> `openapi.go`, `graphql.go`, `auth.go`, `refresh.go`.

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
  handlers (annotations or a small registry) so it can't drift. **Done.**
- **GraphQL:** typed endpoint at `/api/graphql` (devices/alerts/rules/health +
  `__schema`), tenant-scoped, with an in-app **GraphiQL-style explorer** in the
  API Access page (query editor, example queries, JSON result pane — no external
  CDN bundle). **Done.** Promoting the naïve dispatch to a full schema/resolver
  is the remaining follow-up.
- **Rate limits & quotas:** app-level **per-key rate limiting** (fixed window /
  minute) enforced in the auth middleware — over-cap calls get `429` +
  `Retry-After`. Each key has its own cap (or inherits `APIKEY_RATE_LIMIT_PER_MIN`,
  default 600; 0 = unlimited). Live current-minute usage and lifetime call counts
  are surfaced per key in the UI. **Done.**

---

## Pagination & totals contract (stable)

Every bounded list/search endpoint stamps the same response headers; the body
alone is NOT the whole answer. This shape is pinned by a build-time test
(`internal/httppage/contract_test.go`) — renaming a header or envelope key is
a breaking API change and fails the build.

| Header | Meaning |
|---|---|
| `X-Total-Count` | TRUE number of rows matching the caller's filter |
| `X-Page-Limit` | limit actually applied (after server clamping) |
| `X-Page-Offset` | offset actually applied |
| `X-Page-Complete` | `true` iff this response IS the whole matching set |
| `X-Page-Max-Limit` | server-side ceiling, so a client can size its walk |

Header-blind clients (or proxies that strip headers) opt into the **envelope**
with `?envelope=1`: the rows arrive under the endpoint's collection key plus
the same numbers in the body — keys `total`, `returned`, `limit`, `offset`,
`complete`. A client that reads neither the headers nor the envelope and
treats the bare array as complete is silently wrong on any result set larger
than one page — integrate against one of the two.

---

## Build order

1. ~~`api_keys` table + key middleware (resolve key → RBAC context).~~ **Done.**
2. ~~API Access UI wired to key CRUD (generate / list / revoke).~~ **Done.**
3. ~~OpenAPI generation + embedded reference.~~ **Done.**
4. ~~GraphQL endpoint + in-app explorer.~~ **Done** (real schema/resolver is the
   remaining polish).
5. ~~Per-key rate limiting + usage stats.~~ **Done.**

Depends on the RBAC context from steps 1–2 of `IDENTITY_ACCESS.md`.

---

## Related

- [`IDENTITY_ACCESS.md`](IDENTITY_ACCESS.md) — auth, RBAC, tenancy, tokens.
- [`AUTH.md`](AUTH.md) — current live auth.
- UI: `src/frontend/src/tabs/admin.tsx` (`ApiAccessAdmin`).
