# NetOps Observability — Test Suites

Runnable tests across three layers, plus the research-backed answers to the
auth/identity design questions.

## What's here

| File | Layer | Run |
|---|---|---|
| `smoke.sh` | High-level feature reachability (every API surface) | `NETOPS_PASS=… tests/smoke.sh` |
| `auth.sh` | Authentication & identity end-to-end (curl) | `NETOPS_PASS=… tests/auth.sh` |
| `netops.postman_collection.json` | Same surface, interactive | Import into Postman; set `password`; run **Auth › Login** first |
| `../src/backend/*_test.go` | Go unit/HTTP tests | `cd src/backend && go test ./...` |
| `../src/correlation/test_anomaly.py` | Causality/anomaly engine | `cd src/correlation && python -m pytest` |

`smoke.sh` and `auth.sh` take `NETOPS_BASE` (default `http://localhost:8000`),
`NETOPS_USER` (default `admin`), `NETOPS_PASS`, or a pre-minted `NETOPS_TOKEN`.

**Latest run:** `smoke.sh` 25/25 ✓ · `auth.sh` 22/22 ✓ · `go test ./...` green.

> **Admin locked out?** Set `ADMIN_RESET_PASSWORD=<new>` on the `api` service and
> restart — it force-resets the bootstrap admin on boot (then unset it). This is
> how the suites obtain a known login.

### Go unit/HTTP tests (security-critical helpers + new coverage)

```
src/backend/
├── password_test.go       — PBKDF2 hash/verify, malformed-encoding rejection
├── jwt_test.go            — HS256 roundtrip, tampering, expiry, alg=none attack
├── jwks_test.go           — RS256 / JWKS verification (Keycloak path), offline
├── users_test.go          — user store CRUD, case-insensitivity, persistence
├── user_limit_test.go     — MAX_USERS cap on both create paths (+ SSO exempt)
├── token_policy_test.go   — access/refresh TTL clamping to standards bounds
├── refresh_test.go        — refresh rotation + reuse-detection + lineage revoke
├── auth_flow_test.go      — HTTP login/me/refresh/logout/RBAC/API-key
├── identity_test.go       — roles/tenants/api-keys + per-key rate limit
├── tenancy_test.go        — pure tenant-visibility matrix (devices)
├── tenancy_http_test.go   — HTTP-boundary cross-tenant leak prevention
├── tenancy_saved_test.go  — saved-object tenant scoping
├── tenancy_flows_test.go  — flow/finding device-scope helpers
├── kvstore_test.go        — pluggable store backend (file ↔ Postgres)
├── tacacs_test.go         — TACACS+ primitives (pass) + handshake spec (skip)
└── alerts/parse_test.go   — rules-file YAML parser
src/correlation/
└── test_anomaly.py        — z-score anomaly / causality scorer
```

---

## 1. High-level feature test (item 1)

`smoke.sh` logs in once and asserts a 2xx from every major surface: health,
auth/me/permissions, devices, collectors, alerts, rules, findings, logs
(indices + search), metrics (tiles/names/query), flows (top/by-proto/timeseries),
tunnels, saved, reports, global search, GraphQL, OpenAPI, and both ITSM
connectors. It's a breadth sweep — depth lives in the Go/pytest suites.

## 2. Authentication test matrix (item 2)

`auth.sh` automates everything that doesn't need an external IdP:

| # | Area | Coverage | Status |
|---|---|---|---|
| 2.1 | **User auth** | login good/bad, bearer enforcement, junk-token reject | ✅ automated |
| 2.1 | **User limit** | `MAX_USERS` cap enforced on both create paths | ✅ `user_limit_test.go` |
| 2.4 | **API via curl/Postman** | Bearer + `X-API-Key`, mint/use/revoke | ✅ automated + Postman |
| 2.5 | **Token generation/use** | login → access+refresh, use, rotate | ✅ automated |
| 2.5 | **Rotation + reuse detection** | old refresh → 401, lineage revoked | ✅ automated + `refresh_test.go` |
| 2.6 | **Token configurable limits** | TTL bounds clamped/validated | ✅ `token_policy_test.go` |
| 2.7 | **Multitenancy** | cross-tenant leak prevention | ✅ `tenancy_http_test.go` + unit |
| — | **RBAC** | read-only denied admin/key-mint (403) | ✅ automated |
| 2.2 | **LDAP / AD** | via Keycloak federation | ⚙️ manual (needs IdP) — below |
| 2.3 | **SSO / SAML + AD** | via Keycloak | ⚙️ manual (needs IdP) — below |
| 2.8 | **TACACS+** | new module | 🚧 scaffold + skipped acceptance tests |

### 2.2/2.3 — LDAP/AD + SAML/SSO (manual, needs Keycloak)

Federation is brokered by Keycloak (the Go API only verifies tokens, staying
stdlib-only), so these need the optional Keycloak service and an IdP:

```bash
cd deployment/docker && docker compose --profile sso up -d keycloak
# In Keycloak: add an LDAP/AD user-federation provider AND/OR a SAML 2.0 IdP.
```

Then:
1. `GET /api/auth/sso/config` lists the live providers (automatable — included in
   the Postman collection / can be added to smoke).
2. Browser flow: `GET /api/auth/sso/login?provider=<id>` → Keycloak login (LDAP
   creds, or SAML IdP redirect via `kc_idp_hint`) → callback issues a native
   session. Assert `GET /api/auth/me` returns the JIT-provisioned user with the
   Keycloak-mapped role.
3. Service-account path: present a Keycloak RS256 bearer to any `/api/*` route —
   `jwks_test.go` already unit-tests the RS256/JWKS verification offline.

### 2.8 — TACACS+ (build-next)

`tacacs.go` ships the config + tested wire primitives (MD5 obfuscation pad,
header, PAP START); the PAP handshake is the next build step. `tacacs_test.go`
holds the full acceptance spec against a **mock TACACS+ server** — 7 primitive
tests pass now; 2 handshake tests are `t.Skip`-ped until `Authenticate` lands.
Config: `TACACS_ENABLED`, `TACACS_HOST`, `TACACS_PORT`(49), `TACACS_SECRET`,
`TACACS_DEFAULT_ROLE`.

---

## Design answers (researched)

### How many users? Should we set a limit? (item 2.1)

There's no protocol limit — the file/Postgres store scales to thousands. But a
**configurable cap is best practice** for abuse/DoS control, predictable
licensing, and blast-radius limits (Versa, for instance, caps a single VOS at
**256 tenants** [4]). Implemented as `MAX_USERS` (env): **default `0` = unlimited**
(no behavior change), enforced on both create paths; federated SSO provisioning
is exempt so a cap never locks out IdP logins. **Recommendation:** set it per
deployment tier (e.g. 50–500 for a single org; raise for MSP/multi-tenant).

### Token configurable options + industry limits (item 2.6)

Per **RFC 9700** (OAuth 2.0 Security BCP, Jan 2025) [1] and **NIST SP 800-63B**
session guidance [2]:

| Knob | Our default | Bounds enforced | Standard says |
|---|---|---|---|
| `ACCESS_TOKEN_TTL` | 1h | clamp **[1m, 24h]**, warn > 1h | 5–15m sensitive / 30–60m general [1] |
| `REFRESH_TOKEN_TTL` | 7d | clamp **[5m, 90d]**, warn > 30d | 7–30d, rotate single-use [1] |
| Rotation | on | single-use refresh | required [1][3] |
| Reuse detection | on | revokes lineage | required (rotation without it ≈ no gain) [1] |
| Algorithm | HS256 (local) / RS256 (Keycloak) | alg/iss/aud/exp validated | RFC 8725 JWT BCP [3] |

NIST AAL2 wants reauth ≤ **12h** absolute and after **30m** inactivity [2] — so
for AAL2 compliance set `ACCESS_TOKEN_TTL=15m` and keep refresh ≤ 30d. The new
`token_policy.go` clamps out-of-range values and logs a warning above the
recommended ceiling. (`token_policy_test.go` pins the bounds.)

### True multitenancy — how it's built, vs Versa (item 2.7)

Industry isolation models are **silo** (DB-per-tenant), **pool** (shared, row-
scoped by `tenant_id`), and **bridge** (shared DB, separate schemas) [5][6]. We
implement the **pool model enforced at the API boundary** (`tenancy.go`): every
tenant-owned resource carries `tenant_id`; the principal's tenant comes from the
token claim; reads are filtered and cross-tenant fetch-by-id returns **404, not
403** (never confirm another tenant's id exists). Scoping now spans devices,
alerts, flows, findings, tunnels, saved objects, GraphQL, and global search —
pinned by `tenancy_test.go`, `tenancy_http_test.go`, `tenancy_saved_test.go`,
`tenancy_flows_test.go`.

**Versa** [4] does "genuine multi-tenancy" across management/control/data/
analytics planes, with **independent RBAC per tenant**, users seeing only their
tenant's devices, routing-table (VRF) separation, and **nested MSP→subtenant**
hierarchy. The control/data-plane separation is N/A for an observability app, but
two Versa traits are worth adopting next:
- **Per-tenant RBAC** — today roles are global; scope role grants per tenant.
- **Nested tenants (MSP → subtenant)** — a tenant tree so an MSP sees its
  subtenants but not siblings.

These are tracked as Phase-8 follow-ups.

---

## Sources

1. [RFC 9700 — OAuth 2.0 Security Best Current Practice (2025)](https://www.rfc-editor.org/rfc/rfc9700.html) · summary via [APIsec](https://www.apisec.ai/blog/jwt-security-vulnerabilities-prevention)
2. [NIST SP 800-63B — Session management (AAL1/2/3 reauth)](https://pages.nist.gov/800-63-3/sp800-63b.html)
3. [OWASP JWT / Session Management Cheat Sheets](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html) · [Auth0: refresh-token rotation](https://auth0.com/blog/refresh-tokens-what-are-they-and-when-to-use-them/)
4. [Versa Networks — Genuine Multi-Tenancy](https://versa-networks.com/products/multi-tenancy/) · [blog](https://versa-networks.com/blog/secure-sd-wan-architecture-genuine-multi-tenancy/)
5. [AWS SaaS Tenant Isolation Strategies (silo/pool/bridge)](https://docs.aws.amazon.com/whitepapers/latest/saas-tenant-isolation-strategies/)
6. [Tenant isolation: pool, silo and bridge models](https://www.justaftermidnight247.com/insights/tenant-isolation-in-saas-pool-silo-and-bridge-models-explained/)
