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
- **Scoping:** each key carries a scope list (see the table below) and is
  **tenant-bound** and **RBAC-bound** — a key can never exceed the permissions of
  the role it's minted under, and the mint call refuses (403) a scope set that
  would out-rank the caller.
- **Auth:** `Authorization: Bearer <api_key>` (or `X-API-Key`). The middleware
  resolves a key the same way it resolves a JWT — into a `(tenant, permissions)`
  context — so downstream RBAC enforcement is identical.
- **Lifecycle:** `created_at` / `last_used_at` tracked; revoke is immediate
  (`revoked_at` set, key rejected). Optional expiry per key.

Table shape is in [`IDENTITY_ACCESS.md`](IDENTITY_ACCESS.md#data-model-postgresql).

### Scopes the backend honours

The vocabulary is **closed** — `internal/apikey.KnownScopes()` is the single
list, validated on every mint (an unknown scope is a `400`, not a stored typo)
and rendered by the wizard in **Administration → API Access → Generate key**.

What the middleware actually acts on is the **verb** half: `roleFromScopes`
(auth.go) derives the RBAC role the key runs as. The **resource** half records
operator intent and shows up in the key row and the audit trail; it does not
narrow the derived role further today.

| Scope | Derived role | The key may |
|---|---|---|
| `read:metrics` | read-only | read metrics, health and topology state |
| `read:alerts` | read-only | read alerts, incidents and their history |
| `read:devices` | read-only | read the device inventory |
| `read:flows` | read-only | read flows, logs and traces |
| `read:*` | read-only | read everything its tenant can see |
| `write:incidents` | operator | acknowledge, silence and annotate incidents |
| `write:alerts` | operator | create, edit and toggle alert rules |
| `write:devices` | operator | add, edit, monitor and scan devices |
| `write:*` | operator | every write above |
| `ingest:cloud` | read-only + service | the cloud-ingest poller surface — honoured ONLY for a key in the platform realm (`cloud_ingest_service.go`); see [`deployment/docker/cloud-ingest/CREDENTIALS.md`](../deployment/docker/cloud-ingest/CREDENTIALS.md) |
| `ingest:experience` | ingest (reads nothing) | POST the DEM experience lane (`/api/dem/events`, `/api/dem/business-events`) and nothing else — honoured ONLY for a key bound to a CONCRETE tenant, since the events are stamped with it; write-only on purpose, because the RUM snippet's key is served inside a public page (see [`docs/design/dem-rum-snippet.md`](design/dem-rum-snippet.md)) |
| `admin:*` | administrator | administer the key's tenant: tenants, users, devices, rules, scans |

`read:*` satisfies any `read:<x>`, `write:*` any `write:<x>`, and `admin:*`
satisfies every scope check (`token.Claims.HasScope`).

### Who may mint what

Minting is `administration:admin`-gated, and then bounded twice more:

1. **Tenant** — the key is stamped with the *caller's* tenant, never the tenant
   in the request body. A tenant admin's key can only ever act inside its own
   tenant; cross-tenant list/revoke returns `404`.
2. **Authority** — the role the key will act under may not out-rank the caller
   on any module (`authorizeKeyScopes`). An `admin:*` key **in the platform
   realm** is a cross-tenant super-admin credential and is mintable **only by a
   platform administrator**; the same scope minted by a tenant admin produces a
   tenant-administrator key. Every mint is recorded as `API_KEY_CREATED` in the
   identity audit trail with its scopes and derived role (never the secret).

The wizard offers a caller only the scopes it may actually mint, and an
administrative key needs an explicit confirmation before it can be generated.

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
