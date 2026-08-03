# SSO design — SAML 2.0 and OIDC (finalized v3, 2026-08-03)

> **This dated file is the ONLY authoritative version.** It supersedes and
> consolidates every earlier SSO design input — the pre-v2 draft at this
> file's old undated path (git history), the owner review documents
> `/var/tmp/SAML-OIDC.md` and `/var/tmp/SAML-Enhancements.pdf`, and the
> resume prompt `/var/tmp/correlix-sso-resume-prompt.md`. Disregard all of
> those; anything from them that survived review is folded in here (§15
> records what was adopted, overridden, or deferred, and why).

**Status: APPROVED — IMPLEMENTATION DEFERRED UNTIL SaaS (owner, 2026-08-03).**
Owner decision, same day as approval: the native SAML SP is not needed while
the product is self-hosted — **Keycloak brokering is the supported SSO path**
(with the Okta Bookmark tile as the supported IdP-initiated experience), and
this design is kept ready-to-implement for the SaaS transition, when its
locator/custom-domain model becomes fully applicable. A precondition-0.1/0.2
implementation (PG GuardRole fix + parity contract) was built, reviewed, and
then reverted with the rest of the SAML code at owner request; tracker **#136**
keeps that security gap visible because it affects the CURRENT Keycloak path
on Postgres deployments, independent of this design.

When implementation resumes, the gate below stands unchanged.
No SAML *feature* implementation (endpoints, config surface, UI) until the
Phase 0 preconditions below are complete, in this order:

> 0.1 PG GuardRole repair → 0.2 persistence authorization parity contract
> tests → 0.3 canonical identity migration → 0.4 PKCE S256 → 0.5 nonce
> validation → 0.6 atomic auth transactions → 0.7 SAML library pinned +
> wrapper verification → 0.8 SAML request-size/XML resource limits →
> **then** SAML implementation → administrative UI.

v3 (same day) folds in the owner's second architecture document
(`/var/tmp/SAML-Enhancements.pdf`): the **login locator / login policy /
federation connection** product model, stable connection-scoped federation
endpoints, the six-way tenant binding invariant, and the configuration
lifecycle. §15 records exactly what was adopted, what was right-sized for a
self-hosted single-port deployment, and the two places that document conflicts
with repository reality (no Redis — removed permanently per tracker #97; no
Correlix-operated SaaS DNS).

Inputs reconciled across v2+v3: the original draft; the Okta runbook
(`docs/runbooks/okta-sso-setup.md`); tracker #135; the owner's first review
(`/var/tmp/SAML-OIDC.md`); the owner's implementation spec
(`/var/tmp/SAML-Enhancements.pdf`); independent code verification and the
Aug-2026 SAML library research.

---

## 1. Decision summary

| Decision | Position | Why |
|---|---|---|
| Root cause of IdP-initiated SAML failure | Confirmed: absence of a SAML SP in Correlix. Keycloak 25.0's IdP-initiated machinery resolves SAML clients only; the broker terminates SAML and starts an OIDC flow an unsolicited assertion cannot anchor to | Verified in code + live evidence (runbook); three independent confirmations |
| Target architecture | **Hybrid**: keep Keycloak as broker; add native, tenant-aware SAML SP. Both direct and Keycloak-brokered integrations are modeled as tenant-owned **federation connections** | Direct + IdP-initiated + egress-free SAML for enterprise customers; broker keeps multi-IdP/LDAP/MFA orchestration; one product model over both |
| Product model | Tenant → **login locator** → **login policy** → **federation connection** (each tenant-owned; explicit association table policy↔connections) | One tenant ≠ one URL ≠ one IdP. Multiple locators, policies and connections per tenant, without forking the session model |
| Federation endpoints | **Stable, connection-scoped, Correlix-owned**: `/api/auth/federation/{connection_public_id}/saml/{acs,metadata,login}` (OIDC variants when per-tenant OIDC lands). Public ID: opaque, immutable, non-sequential, globally unique, unrelated to the DB key | Tenant-facing URLs select login context only; the stable endpoint processes IdP responses. Supersedes v2's tenant-slug ACS paths — slugs are mutable and enumerable, connection IDs are neither |
| Tenant binding invariant | Six-way equality, fail-closed (§6.3): locator tenant == policy tenant == connection tenant == validated-issuer tenant == transaction tenant == session tenant | The browser must not be able to move tenants via slugs, RelayState, state, headers, claims, or another tenant's connection ID |
| Convergence rule | Every auth path terminates in ONE normalized identity → ONE completion pipeline → ONE session mint; adapters structurally unable to mint sessions | Prevents policy drift between doors |
| Identity keying (federated, tenant-scoped IdPs) | `(tenant_id, issuer, subject)`; email is an attribute, never an identity key; no email-based linking | Cross-tenant collision is the leak; OIDC `sub` / SAML persistent NameID are the stable keys |
| Tenant resolution | Locator resolves a **candidate** tenant only; acceptance requires the full §6.3 invariant | Route ≠ proof |
| Per-tenant vs global | Per-tenant schema from day one; `""` = platform-global registration; UI last | No global→per-tenant migration on a security surface |
| Library | `github.com/russellhaering/gosaml2 v0.11.0` + `github.com/russellhaering/goxmldsig v1.6.0` behind a Correlix-owned hard-fail wrapper (§11 carries the full module identity: path, version, checksum, license, maintenance, CVEs, compensations) | Only actively-maintained candidate, patched as shipped; smallest pure-Go surface. crewjam/saml dormant 15 months with a vulnerable pinned dependency |
| Validity windows | §7.1 exact formulas: skew 120 s asymmetric; SubjectConfirmation clamped to 5 min from IssueInstant; Conditions clamped to 10 min; clamping never extends an earlier IdP expiry | Blanket reject at `Conditions` breaks Entra; clamp gives the same security outcome |
| IdP-initiated framing | Per-connection **opt-in**, disabled by default, not marketed as higher assurance | No request correlation; NIST FAL2 requires RP-initiated |
| Sessions | Keep existing model (HS256 access carrying `sid` + server-side revocable session record), enriched with `external_identity_id`, `federation_connection_id`, auth method/strength/time | Already server-side + revocable; single verifier service. Session content per the owner's spec |
| Transient state | PG-backed (or bounded in-memory for the file backend) atomic stores. **No Redis** — removed from the stack permanently (licensing, #97); the owner's second document assumed it and is overridden on this point | Repository constraint |
| Deployment shape | Single-port self-hosted stack: locator types `shared_path` (`/t/{slug}`) and `immutable_org_url` (`/org/{org_public_id}`) now; `managed_subdomain` and `custom_domain` are schema-reserved but deferred (§15) | No Correlix-operated DNS/TLS plane exists in a compose product |
| Pre-work (Phase 0) | Fix PG `GuardRole`; parity contract tests; canonical identity migration; PKCE S256 + nonce; atomic transactions; pin+wrap library; ACS limits | Owner-mandated gate, in order |

---

## 2. What exists today (verified against code, 2026-08-03)

### 2.1 Architecture

Correlix speaks **OIDC** to Keycloak, which brokers external SAML/OIDC IdPs:

```
Okta ──SAML 2.0──▶ Keycloak ──OIDC──▶ Correlix ──▶ HS256 access (sid) + server session
       (terminates here)     (starts here)
```

Correction to the draft and `IDENTITY_ACCESS.md`: Keycloak is **not** the only
federation plane. Correlix ships native **LDAP** (`internal/ldap`) and
**TACACS+** (`internal/tacacs`), both converging on `users.UpsertFederated` +
`mintSession`. The native SAML SP is the third such front door. What remains
non-negotiable is *not hand-rolling XML-DSig* (§11).

### 2.2 Component inventory

| Component | Where | State |
|-----------|-------|-------|
| OIDC client (authorization-code, confidential) | `src/backend/oidc.go` | ✅ working — **no nonce, no PKCE** (§2.5) |
| ID-token verification, RS256 hard-pinned | `internal/jwks/jwks.go:268` | ✅ working |
| CSRF state cookie on SSO round trip | `oidc.go:98` | ✅ working |
| JIT provisioning | `users.UpsertFederated` (file + PG stores) | ✅ working — §2.5 caveats |
| Role mapping from ID-token claims | `internal/oidc.RoleFor()` | ✅ working |
| MFA assertion check (`amr`/`acr`) | `oidc.go:134` | ✅ working |
| Server-side sessions: idle/absolute TTL, revocation, concurrency cap, events | `auth.go` mintSession / sessions store | ✅ working |
| Rotating refresh tokens bound to `sid` | `refresh.go` | ✅ working |
| Runtime config store + platform-admin API | `oidc_config.go`, `PUT /api/auth/oidc/config` | ✅ working |
| Native LDAP / TACACS+ | `internal/ldap`, `internal/tacacs` | ✅ working |
| Keycloak (opt-in, compose profile `sso`, pinned 25.0) | `docker-compose.yml:138` | ✅ working |
| Per-tenant runtime config precedent | `itsm_config.go` (tenant-keyed kv, `""` = global) | ✅ working — the storage template |
| SAML Service Provider (ACS, metadata, AuthnRequest) | — | ❌ **does not exist** |
| Login locators / policies / connections model | — | ❌ does not exist (this design adds it) |

### 2.3 Proven flows (real Okta org, Homedepot tenant, 2026-08-03)

| Flow | Result |
|------|--------|
| SAML SP-initiated (brokered) | ✅ |
| OIDC SP-initiated (brokered) | ✅ |
| OIDC IdP-initiated (`initiate_login_uri`) | ✅ |
| SAML IdP-initiated | ❌ — the gap this design closes (✅ UX-equivalent via Okta Bookmark tile) |
| Role mapping → super-admin in the right tenant | ✅ |
| Federated user lands in exactly one tenant | ✅ |

### 2.4 Constraints already paid for (do not rediscover)

1. `OIDC_*` env vars are a **fallback**, not an override — a saved kv config wins.
2. OIDC brokering needs Keycloak→IdP **egress**; SAML brokering is
   front-channel and does not. A live argument for the direct SAML door.
3. Keycloak realm-role mappers need `id.token.claim=true` or `RoleFor()`
   never sees the role.
4. One tenant per OIDC provider today (`OIDC_DEFAULT_TENANT`).

### 2.5 Code-verified gaps this design must not build on top of

1. **`PGStore.UpsertFederated` never applies the SR-025 role guard.** File
   store guards merge+create (`internal/users/store.go:306,317`); PG store
   (`internal/users/pg.go:361`) passes the raw role through. On Postgres a
   mis-mapped IdP group can seize `global` + `super-admin`. **Precondition 0.1.**
2. **`UpsertFederated` binds by globally-unique username, tenant-blind.**
   §4 replaces this binding for tenant-scoped IdPs. **Precondition 0.3.**
3. **No `nonce`, no PKCE** in the OIDC code flow. **Preconditions 0.4/0.5.**
4. **`CallbackURL()` derives from request `Host`/`X-Forwarded-*`**
   (`internal/oidc/oidc.go:223`). The owner's spec is adopted: federation
   URLs (SP metadata, ACS, redirect URIs) must be generated from **persisted
   canonical public-URL configuration**, never the raw incoming Host header
   (§6.4). The existing OIDC path keeps its behavior until migrated onto the
   same canonical-URL config.
5. Runbook drift: the break-glass warning about local-account conversion is
   stale — current code never converts local accounts.

---

## 3. Root cause — why IdP-initiated SAML cannot work today (confirmed)

**a)** Keycloak's IdP-initiated machinery (`saml_idp_initiated_sso_url_name`,
`/broker/{alias}/endpoint/clients/{name}`) resolves **SAML clients only**.
Correlix is `protocol=openid-connect`. Observed: `clientId="null"` then
`invalid_redirect_uri` — the client is never resolved.

**b)** The broker terminates SAML and must then *start* an OIDC flow toward
Correlix; an unsolicited assertion has no OIDC authorization request to
anchor to.

**c)** The SP owns the ACS and defines RelayState. Correlix has neither.

The untested alternative (a *SAML client* in Keycloak chained onward) is
subsumed: once Correlix has a native ACS, Keycloak becomes just another
registrable IdP — brokered LDAP/multi-IdP setups get IdP-initiated SAML
through the broker with zero extra engineering, modeled as one more
federation connection (`provider_type: keycloak`).

---

## 4. Identity model and binding rules (the §3a core)

### 4.1 Canonical external identity

```
external_identities
  tenant_id      the tenant owning the federation connection ("" = platform-global)
  protocol       saml | oidc
  issuer         exact IdP entityID / OIDC iss (normalized)
  subject        SAML persistent NameID (or configured immutable attribute) / OIDC sub
  user_id        internal user record (preserved across migration)
  first_seen_at, last_login_at
  UNIQUE (tenant_id, issuer, subject)      ← the identity authority
```

Email, display name, preferred_username are **profile attributes, not
identity keys**, refreshed from the IdP without changing identity ownership.
PG: `tenant_iso` FORCE-RLS + `withTenant`. File backend: tenant-keyed in the
store.

### 4.2 Binding rules (all hard, all tested)

1. A tenant-scoped connection mints sessions **only in its own tenant**.
2. A tenant-scoped connection **never binds to a local account**
   (`auth_source=local`) — local accounts (break-glass included) are
   invisible to tenant federation.
3. No email-based auto-linking across issuers, ever. Existing-user linking
   only through an explicit controlled workflow (deferred, §15 — until then:
   no linking).
4. Usernames for tenant-federated users are **opaque, generated, non-login
   identifiers** (owner decision; NIST FAL2 forbids plaintext PII in
   federated identifiers):

   ```
   fed_<tenant-fragment>_<identity-hash>      e.g. fed_t7h2k9m_4qv8n2psj1x6d3wk

   identity-hash = SHA-256( version_byte || tenant_id || 0x00 ||
                            normalized_issuer || 0x00 || subject )
                   truncated to ≥100 bits, base32/base64url unpadded,
                   lowercase ASCII + digits
   ```

   Immutable; login with it prohibited; display of it prohibited; exists only
   to satisfy the users table's global-uniqueness requirement.
5. JIT never resurrects a disabled user; JIT policy (enabled, default role)
   is per **login policy** (§6.2).
6. The platform-global OIDC provider keeps its current binding semantics,
   with 0.1's GuardRole fix on the PG path.

### 4.3 Collision handling and migration (owner-approved)

On a generated-username collision: re-read by the authoritative tuple; tuple
match → return the existing identity; otherwise generate a longer hash. Never
resolve by email or display username.

Migration (precondition 0.3): create the canonical external-identity row
first, preserving `user_id`; generate the namespaced username only where
required; never create a second user because the username format changed;
flag ambiguous email-based links for manual review; backfill
platform-global-provider rows lazily at next login where offline derivation
is impossible.

### 4.4 Convergence pipeline

```go
type FederatedIdentity struct {
    TenantID     string   // "" = platform-global provider
    ConnectionID string   // federation connection public id ("" = legacy global OIDC)
    Protocol     string   // saml | oidc | ldap | tacacs
    Issuer       string
    Subject      string
    Email        string
    Name         string
    Groups       []string
    AuthnCtx     string   // SAML AuthnContextClassRef / OIDC acr
    MFA          bool
    SessionRef   string   // SAML SessionIndex / OIDC sid — stored for future targeted revocation
}

completeFederatedLogin(w, r, id FederatedIdentity)
// binding (§4.1-4.3) → role mapping → JIT per policy → guardrails →
// mintSession → audit. The ONLY path to a session for any adapter.
```

Extracted from today's `handleSSOCallback` tail; the OIDC path is refactored
onto it with zero behavior change (proven by existing tests).

---

## 5. Target architecture

```
                 ┌── SAML 2.0 direct ── /api/auth/federation/{conn}/saml/acs ──┐
Okta/Entra/ADFS ─┤                                                             ├─▶ FederatedIdentity
                 └── SAML/OIDC/LDAP ─▶ Keycloak ──OIDC── /api/auth/sso/* ──────┘        │
LDAP (native) ─────────────────────────────────────────────────────────────────▶ completeFederatedLogin
TACACS+ ───────────────────────────────────────────────────────────────────────▶        │
                                                                                        ▼
                                                                              HS256 access (sid) + server session
```

Keycloak stays for multi-IdP brokering, MFA orchestration, and existing
deployments — modeled as a federation connection (`provider_type: keycloak`)
when the connection model lands, so both integration styles share the
lifecycle, audit, and test machinery.

---

## 6. Product model: locators, policies, connections (v3)

Adopted from the owner's spec, right-sized to a single-port self-hosted
stack. One tenant = one or more locators, one or more policies, one or more
connections. Storage: PG tables with `tenant_iso` FORCE-RLS (file-backend:
tenant-keyed kv), opaque non-sequential `public_id` on every row, versioned
config, audited changes. DB-level guarantees where the backend supports them:
unique public IDs, tenant-consistent FKs, one default connection per policy,
no cross-tenant policy↔connection or locator↔policy association, valid state
transitions, optimistic concurrency on admin updates.

### 6.1 Login locators

Resolve a **candidate** tenant from the entry URL. Types now:

```
shared_path        /t/{tenant-slug}          slug is a display alias; the row
                                             carries the immutable tenant_id
immutable_org_url  /org/{org_public_id}      opaque, immutable, safe to share
```

`managed_subdomain` and `custom_domain` are reserved enum values, **deferred**
(§15): they require a Correlix-operated DNS/TLS plane that a compose product
does not have. The resolution and invariant logic is written against the
locator abstraction so adding them later is additive.

Rules: normalized lowercase matching; unknown or disabled locator **fails
closed** (no fallback to another tenant or the platform default); a mutable
slug change never changes tenant ownership (the locator row pins
`tenant_id`); every tenant always retains at least one active Correlix-owned
recovery locator (the immutable org URL, created automatically).

### 6.2 Login policies

Per-tenant, versioned. Fields (right-sized from the spec): name, status,
allowed connections (explicit association table with `tenant_id` denormalized
for DB-level consistency), default connection, `auto_redirect_to_default`,
`allow_provider_selection`, `allow_local_login`, `allow_break_glass_login`,
`jit_enabled`, `required_auth_strength` (maps to the existing RequireMFA
machinery), `default_landing_path` (relative, validated). A locator binds to
exactly one policy.

Login flow at a locator: resolve locator → tenant → policy → allowed
connections; exactly one connection + auto-redirect → create transaction and
redirect; otherwise tenant-scoped provider-selection page. Never expose
another tenant's providers; never accept a client-supplied tenant override.
Deleting/disabling is blocked when it would remove the tenant's last login
method or the last tenant-admin access path (§6.5).

### 6.3 Federation connections and the six-way invariant

Connection row: `public_id` (opaque, immutable, non-sequential, globally
unique, unrelated to the DB PK), tenant_id, protocol (saml|oidc),
provider_type (okta|entra_id|keycloak|adfs|google|generic_*), status,
labels/icon, `configuration` (versioned), `secret_reference` (write-only via
the existing secret handling — never in read APIs, logs, audit payloads, or
the browser), cert/metadata versions, test/validation timestamps.

Stable Correlix-owned endpoints, generated from canonical config (§6.4):

```
POST /api/auth/federation/{connection_public_id}/saml/acs
GET  /api/auth/federation/{connection_public_id}/saml/metadata
GET  /api/auth/federation/{connection_public_id}/saml/login      (SP-initiated)
```

(OIDC per-tenant variants use the same shape when per-tenant OIDC lands;
SLO paths are reserved, not implemented — §15.)

**The invariant (fail-closed, before any session is created):**

```
tenant(locator) == tenant(policy) == tenant(connection)
              == tenant(validated issuer) == tenant(transaction)
              == tenant(session-to-be)
```

The browser cannot change the tenant via query params, slugs, email domains,
RelayState, OIDC state, forwarded/Host headers, SAML attributes, unvalidated
claims, return URLs, or another tenant's connection ID. The connection
resolved from the callback URL must match the connection bound in the
consumed transaction (IdP-initiated: must match the connection's own tenant
and its opt-in flag).

### 6.4 Canonical public URLs

Federation documents and URLs (SP metadata, ACS/redirect URIs, entity IDs)
are generated from **persisted canonical public-URL configuration**, never
from the incoming `Host`/`X-Forwarded-*` headers. Correlix sits behind its
own nginx on one port; the canonical base URL is operator-set (install-time
default, platform-admin editable). Unknown hosts never influence generated
URLs. (The existing OIDC `CallbackURL(r)` Host-derivation is migrated onto
this config with the connection model — §2.5.4.)

### 6.5 Configuration lifecycle and break-glass

Lifecycle per connection (and policy): `draft → validate → test → activate →
monitor → rollback`. Editing an active connection creates a new version;
activation is atomic; the previous version is retained for one-click
rollback; metadata re-import produces a **pending** trust change requiring
admin confirmation (never silent). Test mode never creates an unrestricted
production session.

Deletion of a connection is blocked while it is: the only active login
method, the default of an active policy, the last tenant-admin access path,
needed for active rollback, or referenced by live transactions.

Break-glass: local platform/tenant recovery accounts, separate from SSO,
restricted + rate-limited + alerted + audited, never discoverable on tenant
login pages, never a silent fallback after SSO failure. A policy change that
would leave a tenant with no working login path is refused with an explicit
warning flow.

---

## 7. Assertion validation — the hard-fail wrapper specification

gosaml2's defaults are insufficient alone (audience/time violations surface
as *warnings*; `Destination` checked only if present; no skew tolerance; no
InResponseTo validation). The wrapper below IS the security boundary — built
and tested as a unit (precondition 0.7), never improvised:

| Check | Rule (all failures hard-reject; all rejects audited with a failure category §13.4) |
|---|---|
| Signature | Required on the Response or on **every** consumed Assertion per the connection's signing requirements; verified only against the connection's registered cert set (`active`+`next`); in-document `KeyInfo` ignored as trust input; `SkipSignatureValidation` pinned false; RSA-SHA256 minimum, SHA-1 rejected |
| XML hygiene | §7.2 limits enforced first; DTD/external entities rejected; duplicate IDs rejected; >1 Assertion rejected (CVE-2022-41912 class); signed-node == consumed-node (goxmldsig ≥ v1.6.0 — CVE-2026-33487) |
| Issuer | Exact match to the connection's registered IdP entityID; no wildcards |
| Audience | Exact match to the connection's SP entityID; `NotInAudience` warning → hard fail |
| Destination / Recipient | **Required present** and exact-match the connection's canonical ACS URL (§6.4) |
| Time | §7.1 formulas; `InvalidTime` warning → hard fail |
| Correlation (SP-initiated) | `InResponseTo` REQUIRED, must match the pending transaction's AuthnRequest ID — one-time, TTL-bounded, atomically consumed |
| Correlation (IdP-initiated) | Only when the connection's flag is on; `InResponseTo` MUST be absent (present ⇒ replay indicator ⇒ reject) |
| Replay | Response ID **and** every Assertion ID inserted into the replay store with TTL ≥ accepted window; atomic set-if-absent; duplicate ⇒ reject. SessionIndex is NEVER the replay key |
| Tenant | The six-way invariant (§6.3) |
| Subject | NameID format per connection config (persistent default); transient rejected unless an immutable attribute is configured as subject |
| RelayState | Relative path only (`/`-prefixed, no `//`, no `\`, no scheme), optional per-connection allowlist; violations → policy's default landing path, not an error page. RelayState never selects a tenant |
| MFA | When required: `AuthnContextClassRef` must match the accepted-classes list — parity with the OIDC door's `amr`/`acr` check |
| Rate limiting | Per-source and per-connection limits on the unauthenticated ACS |

EncryptedAssertion: supported (gosaml2 native, GCM in v0.11.0), per-connection
opt-in; never a substitute for any check above.

### 7.1 Time semantics — exact (owner-approved)

Clock skew = 120 s; platform-controlled, not tenant-editable initially; hard
maximum 300 s. Asymmetric application:

```
NotBefore:      accept when  now + skew >= NotBefore
NotOnOrAfter:   accept when  now - skew <  NotOnOrAfter
```

Skew never expands Correlix's own transaction TTLs — those are exact.

Clamp semantics (a 60-min declared window is not rejected for declaring
60 min; Correlix refuses to honor more than the cap — but an assertion
already expired by the IdP's own declared time always fails; clamping never
extends an earlier IdP expiry):

```
effective_subject_expiry    = min( SubjectConfirmationData.NotOnOrAfter,
                                   Assertion.IssueInstant + 5 min,
                                   authentication_transaction.expires_at )

effective_conditions_expiry = min( Conditions.NotOnOrAfter,
                                   Assertion.IssueInstant + 10 min )

effective_login_expiry      = min( effective_subject_expiry,
                                   effective_conditions_expiry,
                                   transaction.expires_at )
```

Bearer SubjectConfirmation must present: `Recipient` (exact ACS),
`NotOnOrAfter`, `InResponseTo` for SP-initiated (absent for unsolicited),
`Method=bearer`, and must match the ACS and the live transaction. (Entra
declares Conditions windows far longer than SubjectConfirmation validity;
accepted, clamped.)

### 7.2 ACS transport and structural limits (owner-approved)

`const maxACSRequestBytes = 256 << 10` — raw HTTP body limit enforced
**before** reading the full body, form parsing, base64 decoding, XML parsing,
or signature work. Not tenant-configurable. Transport violation → HTTP 413;
browser gets the generic login-failure page; sanitized admin diagnostic +
metric recorded.

Independent structural limits, each enforced regardless of the transport cap:
maximum decoded XML size, nesting depth, element count, attribute count,
certificate count, assertion count (=1), SubjectConfirmation count,
compressed-input expansion bound if compression is ever accepted.
(Precondition 0.8.)

---

## 8. Authentication transactions (precondition 0.6)

One transaction model for both protocols, per the owner's spec. Binds:
tenant, locator, policy, connection, configuration version, protocol, return
destination. Fields (right-sized): `transaction_id`, the five binding IDs +
config version, `state_hash`, `nonce_hash`, `pkce_verifier` (server-side
only — never cookies, URLs, or logs), `relay/return path` (validated
relative), `created_at`, `expires_at` (exact, 10 min, no skew grace),
`consumed_at`.

Properties: short-lived, single-use, tamper-resistant (server-side record;
the browser holds only the opaque state), **atomically consumed**
(set-if-absent / delete-on-consume; concurrent double-consumption yields
exactly one winner), replay-protected. Full security context never rides in
RelayState or query parameters.

Backends: PG `INSERT … ON CONFLICT DO NOTHING` + consume-delete when
`STORE_BACKEND=postgres`; bounded in-memory map with TTL sweep for the file
backend (single-process by definition). **No Redis** (#97). Same store
semantics serve the SAML pending-request store and replay cache (§7).

The OIDC flow migrates onto this store in preconditions 0.4-0.6 (state cookie
retained as browser binding, defense in depth).

---

## 9. IdP-initiated SSO — scope and honest framing

Per-connection opt-in flag, **disabled by default**. Supported because
enterprise portals require it — not because it is more secure; unsolicited
responses have no request correlation, and NIST FAL2 requires RP-initiated.
Controls: the §7 unsolicited rows + the six-way invariant (the callback
connection ID pins the expected tenant and IdP; the user lands only in the
connection-owning tenant; RelayState can never select a tenant; return
destinations allow-listed). Enabling the flag is a step-up-worthy admin
action (§13.5).

The Okta **Bookmark tile** remains the documented pattern for connections
that leave the flag off. OIDC IdP-initiated stays as is
(`initiate_login_uri`, passed live testing).

---

## 10. SP key management and certificate rotation

- **SP keypair**: RSA-2048+ generated server-side per connection at first
  SAML configuration. Private key stored write-only behind the store
  interface (no KMS in a compose stack; the interface leaves room for one);
  cert published via the metadata endpoint.
- **IdP certs**: a set with `active`/`next`/`retired` states; verification
  accepts `active`+`next` (overlap rotation, no outage); old cert fails after
  rollover completion. Metadata re-import → **pending** trust change
  requiring admin confirmation.
- **Secrets**: never returned by read APIs, never logged, never in audit
  payloads, never re-shown to the browser; replaceable without exposing the
  current value; independent rotation. UI shows status only
  (configured / not configured / rotation recommended / expired).
- Alerts: cert expiry thresholds, secret rotation age, signature-failure
  spikes, unknown-cert rejections — via existing notification channels.

---

## 11. Library selection and CLAUDE.md §6 amendment (precondition 0.7)

**Selected:** the design refers to these ONLY by exact module identity —
never by nickname:

| | Module 1 | Module 2 |
|---|---|---|
| Path | `github.com/russellhaering/gosaml2` | `github.com/russellhaering/goxmldsig` |
| Version | `v0.11.0` (pinned) | `v1.6.0` (pinned, direct — never lower: v1.6.0 fixes CVE-2026-33487) |
| go.sum checksum | recorded in `go.sum` at pin time (0.7 acceptance evidence) | recorded in `go.sum` at pin time |
| License | Apache-2.0 | Apache-2.0 |
| Maintainer status | Active (same-day coordinated fixes for all three Mar 2026 advisories; OSS-Fuzz integrated) | Active (same) |
| Known security issues | CVE-2020-15216, CVE-2020-29509, CVE-2020-7731, CVE-2023-26483, GHSA-pcgw-qcv5-h8ch, GHSA-hwqm-qvj9-4jr2 — **all fixed ≤ v0.11.0** | CVE-2020-7711, GHSA-q547-gmf8-8jr7, CVE-2026-33487 — **all fixed ≤ v1.6.0** |
| Required wrapper compensations | Every `WarningInfo` field (InvalidTime, NotInAudience, OneTimeUse, ProxyRestriction) → hard error; Destination required-present + exact; InResponseTo correlation owned by us; replay cache owned by us; explicit skew (§7.1); algorithm floor (reject SHA-1); assertion count = 1; §7.2 resource limits; `SkipSignatureValidation` pinned false | (via gosaml2) |

Assessment basis (full research on file, Aug 2026): actively maintained and
patched as shipped vs crewjam/saml dormant ~15 months, unreacted to the
goxmldsig CVE, still pinning vulnerable v1.4.0, with its highest-scrutiny
user (Grafana) forked away. Smallest pure-Go surface: 4 net-new runtime
modules (`beevik/etree`, `jonboulle/clockwork`,
`mattermost/xml-roundtrip-validator`, `russellhaering/goxmldsig`), all
vendorable; Go ≥ 1.25.0 = our `go.mod`. Production scrutiny: Teleport,
Mattermost, Sourcegraph, HashiCorp Vault SAML (pins these exact versions).
Rejected: `hashicorp/cap/saml` (cgo xmlsec in graph, no documented
IdP-initiated support), `grafana/saml` (maintained for Grafana only).
govulncheck is already a blocking CI gate; track the Mattermost fork for
hardening patches worth mirroring.

CLAUDE.md §6 allowlist rows (applied in the same change that adds the
dependency): as in the table above, with the wrapper-only usage rule stated.

---

## 12. Sessions, logout, and what deliberately does not change

- **Session model kept**: `completeFederatedLogin` → `mintSession` → HS256
  access carrying `sid` + server-side revocable record (idle/absolute
  timeouts, concurrency policy, events, rotating refresh). Enriched per the
  owner's spec: sessions record/resolve `external_identity_id`,
  `federation_connection_id`, authentication method, time, strength, and
  session version. Compatible with connection disablement (revoke sessions of
  a disabled connection), user disablement, and role changes.
- **Cookies**: host-only (single-host product); no domain-wide cookies.
- **Logout**: local logout authoritative, always succeeds. Upstream logout
  (SAML SLO, OIDC RP-initiated/back-channel) out of scope; `SessionRef`
  stored from day one so targeted revocation and future SLO need no
  migration. UI says "signed out of Correlix", never "everywhere".
- **No silent local fallback** after SSO failure; local login visibility is
  policy-controlled (§6.2), break-glass separate (§6.5).

---

## 13. Phasing, permissions, observability

### Phase 0 — mandatory preconditions (owner-ordered, separate tracker rows)

| # | Row | Acceptance evidence |
|---|---|---|
| 0.1 | Fix PostgreSQL GuardRole platform-owner enforcement (`internal/users/pg.go:361`) | PG denies every operation the file store denies; positive + negative tests; raw escalated role never persisted; authorization-denied audit event without sensitive data |
| 0.2 | Persistence authorization parity contract tests | ONE shared behavioral contract (`RunUserStoreAuthorizationContract(t, newStore)`) executed against file AND PG stores |
| 0.3 | Replace email-based federated identity binding | Canonical `UNIQUE(tenant_id, issuer_normalized, subject)`; §4.3 migration; cross-issuer and cross-tenant negative tests |
| 0.4 | OIDC PKCE S256 | Verifier generated, stored safely (server-side txn only), validated, single-use; plain method structurally impossible |
| 0.5 | OIDC nonce validation | Nonce bound to transaction and ID token; missing, incorrect, replayed → rejected |
| 0.6 | Atomic authentication transaction store | Create, expire, consume; concurrent double-consumption test proves exactly one winner |
| 0.7 | Pin and wrap the SAML library | Exact module/version/checksum in §11 + go.sum; wrapper contract as executable tests for every §7 hard-fail row |
| 0.8 | SAML request-size and XML resource limits | Oversized/structurally abusive inputs rejected before expensive validation |

Plus operational fixes (non-gating): `install.py` creates the `keycloak` DB
when profile `sso` is selected; compose comment corrected to "seed only".

### Phase 1 — backend foundation + SAML core (security-complete, SP-initiated)
Locator/policy/connection schema + tenant-safe repositories + migrations
(§6, §15-migration) · stable federation endpoints (§6.3) · canonical
public-URL config (§6.4) · SP keypair + metadata (§10) · signed AuthnRequest
+ transaction binding (§8) · the **entire §7 wrapper** in force (unsolicited
rejected outright) · external identities + binding (§4) ·
`completeFederatedLogin` extraction (OIDC refactored on, zero behavior
change) · permissions (§13.5) · audit events + failure categories (§13.4) ·
full §14 test matrix rows for everything above.

### Phase 2 — IdP-initiated flag
Per-connection `allow_idp_initiated` + unsolicited-specific §7 rows + default
landing page + §14 IdP-initiated rows. Small by construction.

### Phase 3 — configuration lifecycle + migration
Draft/validate/test/activate/rollback with versioning (§6.5) · migration of
existing tenants: default policy per tenant, existing OIDC/Keycloak config
converted to a federation connection, immutable org locator created per
tenant, existing login behavior preserved, existing callback URLs unchanged
(compatibility redirects where safe), config versions recorded, rollback
procedure documented.

### Phase 4 — administrative UI
Administration → Identity and Access → Login URLs · Login Policies · SSO
Connections · Role Mappings · Authentication Logs. Existing Correlix UI
patterns (ServiceNow-connector precedent): wizards (SAML: template/metadata
import/manual, SP entity + ACS display, mappings, cert lifecycle, test,
activate; OIDC equivalent), secret fields status-only, stable-endpoint
explanation, version history + rollback, guided flows for §6.5 deletion
blocks. Generic user-facing errors with reference codes; admin diagnostics
carry the failure category, never raw assertions/tokens. Frontend suite runs.

Each phase ends with the full gate: `go vet`, `go test -race`, staticcheck,
gosec, govulncheck (+ frontend suite where touched).

### 13.4 Audit failure categories and metrics

Failure categories (audit + admin diagnostics + metric dimension):
`unknown_locator · disabled_locator · tenant_mismatch · connection_mismatch ·
invalid_state · invalid_nonce · invalid_signature · invalid_issuer ·
invalid_audience · expired_assertion · replayed_response · replayed_assertion
· user_disabled · mapping_failed · jit_denied · configuration_inactive`.

Metrics (bounded cardinality — no emails, hostnames, tokens, state/nonce,
assertion IDs, or tenant names in labels; tenant IDs only where observability
policy permits): `authentication_attempts_total`, `…_successes_total`,
`…_failures_total`, `…_failure_by_category_total`,
`authentication_latency_seconds`, `saml_validation_failures_total`,
`oidc_validation_failures_total`, `authentication_replay_rejections_total`,
`login_locator_resolution_failures_total`,
`federation_connection_test_failures_total`, `certificate_expiry_days`,
`secret_rotation_age_days`. Structured logs with request IDs and sanitized
identifiers; never log assertions, tokens, codes, secrets, full RelayState,
or full state/nonce values.

### 13.5 Permissions

Introduce (or map onto existing PBAC vocabulary): `identity.login_urls.
{read,manage}`, `identity.login_policies.{read,manage}`,
`identity.connections.{read,manage,test,activate}`, `identity.secrets.rotate`,
`identity.role_mappings.manage`, `identity.auth_logs.read`,
`identity.break_glass.manage`. Tenant admins manage only their tenant;
platform admins cross tenants only via explicit privileged workflows
(`requirePlatformAdmin` / `?tenant=`). Step-up (or explicit confirmation
where step-up is unavailable) for: activating an IdP, disabling the last
connection, changing signing requirements, rotating secrets, enabling local
login / break-glass / IdP-initiated, changing role mappings.

---

## 14. Test matrix (ships with the feature — §3a/§11, no exceptions)

**Unit — wrapper (§7), one test per row minimum:** bad/absent signature ·
signature on wrong node · >1 assertion · duplicate IDs · DTD/XXE ·
oversized/deflate-bomb/structural limits (§7.2) · wrong issuer / audience /
destination / recipient · absent destination · expired / not-yet-valid /
skew-boundary (both §7.1 formulas) · Conditions over cap (clamped, not
rejected) · SubjectConfirmation over 5 min (clamped) · IdP-expired despite
clamp → rejected · replayed Response ID · replayed Assertion ID · unknown /
reused / expired InResponseTo · unsolicited with InResponseTo · transient
NameID rejected · RelayState: absolute, protocol-relative, backslash,
traversal, allowlist hit/miss, cannot select tenant · AuthnContext below
required class · SHA-1 rejected · wrong certificate · old cert valid during
rollover, invalid after completion.

**Binding (§4):** tenant-A connection asserting an existing tenant-B
identity → no session · local-admin username → no bind · same email two
issuers → distinct identities · matching emails never cross-tenant link ·
disabled user rejected · JIT policy honored · GuardRole enforced on both
stores (the 0.2 contract) · username-collision handling (§4.3).

**Six-way invariant / cross-tenant (org_isolation_test.go template,
REQUIRED):** tenant-A locator cannot invoke tenant-B connection · tenant-A
policy cannot bind tenant-B connection · tenant-A callback cannot consume
tenant-B transaction · modified connection public ID fails safely · modified
RelayState/state cannot select another tenant · a user authenticated by
tenant A's issuer is never placed in tenant B · tenant admin sees only own
config; cross-tenant get/put/delete → 404; no existence leaks (hostname/
connection/user) · `as_tenant` into another org ignored · platform owner
reaches tenant config only via `requirePlatformAdmin`.

**Transactions (§8):** single-use · exact expiry (no skew grace) · concurrent
consumption → exactly one winner · state/nonce/PKCE bound and validated ·
code replay fails · missing/incorrect/replayed nonce fails · plain PKCE
method structurally impossible.

**Routing (§6.1):** shared path resolves correct tenant · immutable org URL
resolves correct tenant · unknown locator fails closed · disabled locator
fails closed · slug rename does not change ownership · generated URLs immune
to Host-header values (§6.4).

**Lifecycle (§6.5):** draft does not affect active login · activation atomic
· failed activation preserves previous version · rollback restores previous
working version · disabling the only login method blocked · deleting a
referenced connection blocked · concurrent edits do not silently overwrite ·
secrets never in API reads or audit records.

**Integration:** SP-initiated round trip against a fixture IdP ·
IdP-initiated round trip (flag on) · flag off ⇒ unsolicited rejected · cert
rollover mid-traffic · metadata validates against the OASIS schema.

**Regression:** all four runbook cells stay green · existing OIDC tests pass
unchanged after the `completeFederatedLogin` extraction · LDAP/TACACS logins
unchanged · migrated tenants keep working logins.

**Fixtures:** captured-and-sanitized Okta + Keycloak responses now;
Entra/ADFS golden fixtures as customers appear.

Verification claims discipline (owner rule): source-scan coverage is not
end-to-end verification; tenant isolation is claimed only after cross-tenant
negative tests execute; "federation works" is claimed only after a real flow
through the running application.

---

## 15. Adopted vs right-sized vs deferred (nothing silently dropped)

**Adopted from the owner's first review (`SAML-OIDC.md`):** canonical
`(tenant, issuer, subject)` identity + no-email-linking (§4) · convergence
pipeline (§4.4) · PKCE+nonce (0.4/0.5) · IdP-initiated assurance framing
(§9) · clamp-not-reject validity (§7.1) · cert state machine + pending
metadata trust (§10) · atomic replay semantics (§7/§8) · negative-matrix
shape (§14) · generic errors + admin diagnostics · minimum security-complete
first release.

**Adopted from the owner's second document (`SAML-Enhancements.pdf`):**
locator/policy/connection product model with explicit association table and
DB-level tenant-consistency guarantees (§6) · stable opaque connection-scoped
federation endpoints — supersedes v2's tenant-slug ACS (§6.3) · six-way
binding invariant (§6.3) · canonical public URLs, never Host-derived (§6.4)
· transaction binding fields incl. config version (§8) · configuration
lifecycle draft→…→rollback with versioned activation (§6.5) · safe-deletion
+ last-login-path + recovery-locator invariants (§6.1/§6.5) · break-glass
requirements (§6.5) · failure categories, metrics, log-redaction rules
(§13.4) · `identity.*` permission vocabulary + step-up list (§13.5) ·
migration plan shape (§13 Phase 3) · SessionIndex-never-replay-key ·
session content/compatibility fields (§12) · verification-claims discipline
(§14).

**Overridden — conflicts with repository reality:**

| Item | Why |
|---|---|
| Redis for transient state | Redis is fully removed from this stack (licensing, tracker #97) and must never be reintroduced. PG / bounded in-memory stores per §8 |
| `auth.correlix.com` / hosted-domain model | No Correlix-operated SaaS edge exists; stable endpoints live under the deployment's canonical base URL (§6.4) with the same path shape |

**Deferred — with reasons, candidates for tracker rows:**

| Item | Why deferred |
|---|---|
| `managed_subdomain` and `custom_domain` locators (DNS verification, TLS wizards) | Require a Correlix-operated DNS/TLS plane; enum reserved, logic additive later |
| SCIM lifecycle | Separate feature; seams left (membership status, JIT-never-resurrects, "SCIM compatibility" in binding rules) |
| SAML SLO / OIDC RP-initiated + back-channel logout | Provider-dependent; local logout authoritative; `SessionRef` + reserved SLO paths keep it additive |
| Per-tenant direct **OIDC** connections | Symmetric follow-up once the connection model exists; modeled in the same tables from day one, implementation after SAML |
| Existing-user linking ceremony | §4.2.3 forbids auto-linking; explicit workflow later |
| KMS/HSM custody, multi-region consistency, opaque/asymmetric session migration, `private_key_jwt`/mTLS | As in v2 — deployment shapes/infrastructure this product does not have; seams noted |
| UserInfo-dependent claims, provider template gallery beyond okta/entra/keycloak/generic | Nice-to-have after core lands |

---

## 16a. Capability classification (2026-08-03, post-deferral Keycloak session)

The owner's follow-up directive made the working Keycloak-brokered flow a
first-class capability. Canonical terminology — say **"Okta dashboard
launch"** / **"Okta Bookmark-based SSO launch"** / **"Correlix-initiated SSO
through Keycloak"**; never "native IdP-initiated SAML" or "unsolicited SAML
into Correlix" for this flow (the technical flow is properly SP-initiated:
Bookmark → Correlix → Keycloak OIDC → Okta SAML → Keycloak → Correlix
session; Okta reuses the live session so the click lands signed-in).

**Required now — IMPLEMENTED (2026-08-03):**
- PG GuardRole authorization parity + shared file/PG contract test (#136)
- OIDC PKCE S256 (constant method; verifier server-side only)
- OIDC nonce (issued per login, validated against the ID token)
- Atomic single-use login transactions (`internal/oidc.TxnStore`: exact
  10-min TTL, bounded 4096, delete-on-read consume, one winner under
  concurrent callbacks)
- Server-owned IdP alias selection (`Provider.ValidIDP`: kc_idp_hint must be
  an operator-configured alias; browser-invented aliases → 404)
- Correlix-owned sessions (pre-existing) · Keycloak-brokered Okta dashboard
  launch (pre-existing, now documented as supported)

**Required for SaaS (deferred with the native-SAML build, §15):** login
locators/policies, multiple per-tenant federation connections, opaque
connection-scoped endpoints, config lifecycle, tenant admin UI, custom URLs.

**Deferred optional:** native SAML SP (ACS/metadata/unsolicited), SCIM, SLO —
unchanged from §15. This design is NOT deleted; it is the ready plan for when
SaaS or contract requires it.

## 16. Approval record (2026-08-03)

1. Design v2 **approved with eight mandatory preconditions** (header). v3
   integrates the owner's second document per §15; the preconditions are
   unchanged and remain the gate.
2. Username scheme: owner-specified opaque `fed_` form (§4.2.4); readable
   schemes rejected (PII, mutability, collision).
3. Security defaults approved with exact semantics — §7.1, §7.2.
4. Phase 0 filed as eight separate tracker rows with acceptance evidence.
5. CLAUDE.md §6 amendment applied with the dependency pin (0.7); the design
   refers to the library only by exact module identity (§11).
