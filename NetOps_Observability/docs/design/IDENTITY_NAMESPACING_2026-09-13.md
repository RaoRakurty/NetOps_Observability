# Identity namespacing — tracker 300 (owner decision 2026-09-13)

**Status: DESIGN OF RECORD, Phase 1 inspection complete, Phases 2–6 in execution.**
Supersedes nothing: it implements `docs/design/sso-saml-oidc-design-2026-08-03.md`
§4.1–4.3 under the owner's 2026-09-13 tightening (`docs/TRACKER.md` row 300,
`docs/release/RC1_GOVERNANCE_DIRECTIVE_2026-09-13.md`). Where the two disagree,
the 2026-09-13 decision wins and the disagreement is called out.

## 0. The owner's rules (binding)

1. Canonical identity = **tenant_id + issuer + subject**. Never username, never email.
2. `UNIQUE (tenant_id, issuer, subject)`, **enforced at the DB**, not only in code.
3. Local auth is **its own issuer namespace**.
4. **No email- or username-based auto-linking across issuers, ever.**
5. Bearer-JIT and LDAP scoped the same way.
6. Migration = expand → backfill → switch → enforce → contract; **idempotent**;
   **never merges on email or username**; ambiguous legacy provenance is
   **flagged for manual remediation, never guessed**.
7. Window is now: user ids are about to be referenced by findings, audit,
   ownership, PBAC/RLS and API tokens.

## 1. Phase 1 — what the code does today (inspected 2026-09-13, HEAD b350b062)

### 1.1 The key
`User.Username` is the **sole, global, case-insensitive identity key** on both
backends. PG: `users.id TEXT PRIMARY KEY` = `lower(username)` (`pg.go:89 userID`),
`tenant_id` column, FORCE-RLS `tenant_iso` — but `Get`/`UpsertFederated*` run at
platform scope (`WithTenant(ctx, "", true)`) because login must find the tenant
from the row. File: `map[lower(username)]User` flushed to `/data/users.json`.

### 1.2 Every door writes into that key
| Door | Username used as key | Issuer / subject stored? |
|---|---|---|
| Local create (`identity_handlers.go:144 CreateFull`, `SeedAdmin`) | typed name | n/a — `auth_source=local` |
| OIDC callback (`oidc.go:252`) | `firstNonEmpty(preferred_username, email, sub)` | **iss verified by JWKS, then discarded; `sub` discarded when a username/email exists** |
| Bearer JIT (`auth.go:1163 bearerPrincipal`) | same derivation | same |
| LDAP (`ldap_wiring.go:106`) | typed login name | DN is fetched (`ldap.Identity.DN`) and discarded |
| TACACS+ (`tacacs_wiring.go:58`) | typed login name | nothing else exists |
| Elevation (`oidc.go:357`) | same derivation → `users.Get` | read-only door, binds on username |

So identity today **is** username/email-keyed linking across whatever asserts
it. The C3 realm fix (`users.Realm`, `UpsertFederatedInRealm`) bounds which
tenants an EXISTING account can be signed into by a bound connection; the H1
fix refuses federated merges into local accounts. Neither namespaces. The
premise is pinned, deliberately, by `TestBearerUsernameIsOneGlobalNamespace`
(tracker 279d), which must be **retired** by this work, not worked around.

### 1.3 Where the username fans out as a foreign key (must follow the new user id)
- session JWT `token.Claims.Sub` (`auth.go:385`), `session.Session.UserID`,
  `RefreshStore.IssueForSession(username, …)`;
- `rbac.RoleBinding.PrincipalID` (mirror binding id derived from it,
  `binding_sync.go`), elevation grants (principal = username);
- `audit.Event.Actor`; `apikey.Key.CreatedBy`; ownership strings
  (`created_by`, `owner`) in PG tables are free text, not FKs;
- HTTP: `/api/users/{id}` handle, `publicUser.Username`; frontend
  `admin.tsx` keys rows and every mutation on `u.username`; `TopBar.tsx:273`,
  `IconRail.tsx:366` **display `user.username`** (the design forbids displaying
  a generated federated username).
- 28 non-test Go files reference `.Username`; 36 reference `claims.Subject`/`.Sub`.

### 1.4 Federation topology (what "issuer" means here)
Every IdP is **brokered through one platform Keycloak**: `oidc.Provider.issuer`
is the only `iss` this code ever verifies (`internal/oidc/oidc.go:247`); the
upstream IdP is the connection **alias** (`kc_idp_hint`, `txn.IdP`), stored as
`ssoidp.Config{Alias, Protocol, Kind, TenantID, …}`. Keycloak's `sub` is the
stable per-realm user id. Consequence: for OIDC the tuple is
`(tenant, iss = Keycloak realm issuer, sub = Keycloak sub)`; the alias is
recorded as `connection_id` beside it (design §4.4), **not** in the key.
Keycloak's own first-broker-login flow can link two upstream identities into
one Keycloak user by email *inside Keycloak*; that is outside this schema and
is recorded as residual risk with the recommended Keycloak setting (§8).

LDAP: one platform-global config (`LDAP_*` env); `ldap.Identity{Username, DN,
Email, DisplayName, Groups}`. TACACS+: one platform-global config; the login
name is the only subject that exists.

### 1.5 Migration machinery
PG: `internal/platformdb/migrations/NNNN_*.sql`, lexical, one tx each,
advisory-locked, forward-only with `rollback/NNNN_*.down.sql`; next number
**0049**. File backend: in-code normalisation at load (`store.go load()` — the
H1 `AuthSource` backfill is the template; `kv_legacy_migrate.go` is the
copy-never-move template).

## 2. Target model

### 2.1 Two concepts that are one string today
- **`User.ID`** — the immutable internal principal id. This is what sessions,
  JWT `sub`, bindings, audit actor, API handles and every future FK reference.
  Legacy rows: `ID == lower(username)` (preserved — nothing that references a
  user today changes value). New local accounts: `u_<32 hex>` minted by
  `mintUserID()` next to `mintTenantID()` in `identity_ids.go`. New federated
  accounts: deterministic `fed_<tenant-fragment>_<hash>` (§2.4), so a JIT
  race and a re-run migration converge on the same id.
- **`User.Username`** — the login/display handle. For local accounts it is the
  typed name, unique **per tenant** (rule 3). For federated accounts it equals
  the opaque id and is **never displayed and never accepted at a login form**.

### 2.2 The identity table (PG, authority; file store mirrors it)
```sql
-- 0049_user_identities.sql  (EXPAND — additive, idempotent)
CREATE TABLE IF NOT EXISTS user_identities (
    tenant_id     TEXT NOT NULL,
    issuer        TEXT NOT NULL,                 -- normalized (§2.3)
    subject       TEXT NOT NULL,
    user_id       TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    protocol      TEXT NOT NULL,                 -- local | oidc | saml | ldap | tacacs
    connection_id TEXT NOT NULL DEFAULT '',      -- ssoidp alias ("" = platform/legacy global)
    provenance    TEXT NOT NULL,                 -- asserted | backfilled-local | legacy-lazy-bound
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_login_at TIMESTAMPTZ,
    PRIMARY KEY (tenant_id, issuer, subject),    -- rule 2, at the DB
    UNIQUE (user_id)                             -- rule 4: exactly ONE identity per user; no linking
);
CREATE INDEX IF NOT EXISTS user_identities_user_idx ON user_identities (user_id);
ALTER TABLE user_identities ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_identities FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_iso ON user_identities;
CREATE POLICY tenant_iso ON user_identities USING (...) WITH CHECK (...);  -- same text as users
```
`UNIQUE (user_id)` is the DB-level form of "no auto-linking": a second identity
cannot be attached to an account by any code path. A future explicit linking
ceremony (design §15, deferred) would relax it deliberately.

Local-username uniqueness per tenant (rule 3) is the same table: local rows are
`(tenant, 'local', lower(username))`. The legacy global PK on `users.id` still
prevents two *legacy* rows colliding; new local rows have opaque ids, so two
tenants may both create `admin`.

`users.data` JSONB gains nothing authoritative; `User` in Go gains
`ID` and a read-only `Identity` view loaded by join. On the **file backend** the
identity is a field of `User` (`Identity{Issuer, Subject, Protocol,
ConnectionID, Provenance, …}`), and `FileStore` keeps two indexes built at load
and enforced at every write: `byID` and `byTuple[(tenant, issuer, subject)]`,
plus `byLocalLogin[(tenant, username)]`. Uniqueness is enforced inside the
store lock, identically to the PG PK; a contract test (federated_contract_test
pattern) runs the same cases against both backends.

### 2.3 Issuer namespaces (normalised strings, never displayed)
| Door | issuer | subject | connection_id |
|---|---|---|---|
| local | `local` | `lower(trim(username))` | `` |
| OIDC callback / bearer | the verified `iss`, trailing `/` trimmed, lowercased host | `claims.Sub` **only** | alias (`txn.IdP`), or `` for the platform default |
| LDAP | `ldap:` + normalised `LDAP_URL` host:port (no scheme case, no path) | `lower(DN)` when the directory returned one, else `lower(login name)`; which one was used is recorded in `subject_kind` (`dn` \| `login`) | `` |
| TACACS+ | `tacacs:` + normalised server host:port | `lower(login name)` | `` |
`subject_kind TEXT NOT NULL DEFAULT ''` is added for LDAP so a later DN-vs-login
policy change is visible, not silent. A DN move (OU change) therefore yields a
NEW account — by design; the old one is listed as identity-orphaned for the
admin (§2.7). preferred_username and email are **profile attributes**
refreshed on login (`MergeFederated`), never keys.

### 2.4 Federated id/username derivation (design §4.2.4, unchanged)
```
fed_<tenant-fragment>_<hash>
hash = base32-lower-unpadded( SHA-256( 0x01 || tenant_id || 0x00 || issuer || 0x00 || subject ) )[:26]  (130 bits)
tenant-fragment = first 7 chars of tenant_id after the "t_" prefix ("global" for the global tenant)
```
Collision (§4.3): re-read by tuple; tuple match → that account; otherwise
extend the hash to 52 chars. Never resolve by email or username.

### 2.5 Resolution — the ONLY way a federated assertion becomes an account
```go
// internal/users
type Identity struct {
    TenantID, Issuer, Subject, Protocol, ConnectionID, SubjectKind, Provenance string
    FirstSeenAt time.Time; LastLoginAt time.Time
}
type Assertion struct {           // what the door verified
    Identity                      // TenantID = provisioning tenant for a NEW account
    Email, DisplayName, Role string
    LegacyUsername string         // the pre-migration derivation, for §2.6 ONLY
}
type Repo interface {
    Get(id string) (User, bool)                                 // by User.ID
    LookupLocal(tenant, username string) (User, bool)           // exact tenant
    LookupLocalAny(username string) ([]User, bool)              // unbound login form: 0, 1 or many
    ResolveFederated(a Assertion, realm Realm) (User, error)    // find-or-provision by tuple
    ResolveFederatedUnbound(a Assertion) (User, error)          // platform-default connection: (issuer, subject) across tenants; >1 → ErrAmbiguousIdentity
    ...existing mutators keyed by id...
}
```
`ResolveFederated` inside one lock/transaction: tuple hit → `realm.Permits`
→ `MergeFederated` profile → touch → return. Tuple miss → §2.6 legacy check →
else provision: id = §2.4, `Username = id`, `AuthSource = protocol`, identity
row inserted in the same transaction (PK/UNIQUE violations map to
`ErrIdentityConflict`, retried once by re-reading the tuple). JIT never
resurrects `status=disabled` (design §4.2.5): a disabled account is returned
as-is and the caller refuses, exactly as today.

The three doors call it with what they actually verified:
- OIDC callback: `{Tenant: ssoProvisionTenant, Issuer: p.Issuer(), Subject: claims.Sub, Protocol: "oidc", ConnectionID: txn.IdP}` + realm from `ssoSignInRealm`.
- Bearer: `{Tenant: op.DefaultTenant(), Issuer: op.Issuer(), Subject: oc.Sub, Protocol: "oidc"}` via `ResolveFederatedUnbound`.
- LDAP/TACACS: §2.3 tuples via `ResolveFederatedUnbound` (one platform config each today; when per-tenant directories arrive they use the bound form — the seam already exists).
- Elevation door: `ResolveFederated` in read-only mode (`provision=false`): tuple miss → refuse. It never binds by username again.

Local login (`handleLogin`): locator/realm tenant present → `LookupLocal(tenant,
name)`; absent → `LookupLocalAny(name)`: exactly one → proceed; none → 401
generic; **more than one → 401 generic + audit `login.ambiguous_local_identity`
+ log naming the count, never the tenants**. The per-tenant sign-in URL is the
disambiguator, and the generic message tells the user to use their
organisation's sign-in page.

### 2.6 Legacy accounts — the one bounded exception, written down
Pre-migration federated rows (`auth_source ∈ {oidc, ldap, tacacs}`) carry no
issuer/subject; **it cannot be derived offline**, and design §4.3 (owner-
approved 2026-08-03) says such rows are bound "lazily at next login". Rule 6
says never merge on username. Both are honoured as follows — this is the
single place username equality is ever consulted, and it is time- and
provenance-bounded:

A tuple miss may adopt an existing account ONLY IF **all** hold, inside the
same transaction, row locked `FOR UPDATE`:
1. the account has **no identity row** (`UNIQUE(user_id)` would refuse anyway);
2. the account's `auth_source` equals the assertion's protocol (an OIDC
   assertion can never adopt an LDAP account, and never a local one — H1);
3. the account was created **before** the migration marker
   (`users_identity_migration_started_at`, written once by the backfill);
4. `lower(a.LegacyUsername) == users.id` where `LegacyUsername` is computed by
   the **exact** legacy derivation of that door (`firstNonEmpty(preferred_username,
   email, sub)` for OIDC; the login name for LDAP/TACACS);
5. the realm permits the account's tenant;
6. the account is not `disabled`.
Then the identity row is inserted with `provenance = 'legacy-lazy-bound'`,
an audit event `identity.legacy_bound` (actor = the account, detail = issuer,
protocol, connection) is recorded, and a counter is incremented. A **second,
different** subject presenting the same legacy username later finds
`UNIQUE(user_id)` already satisfied → it gets a fresh `fed_…` account. Nothing
is ever guessed offline; nothing is ever merged after the first bind.

**Why this is not "merging on username":** it is a one-shot claim of an account
that the legacy code itself created from that very string, by the same door,
before any tuple existed, and it is refused for anything already bound. The
alternative — every existing SSO user re-provisioned with a fresh account and
an operator re-assigning roles by hand — is the manual remediation the owner
reserved for **ambiguous** provenance; an identity-less legacy row matched by
its own creating door is not ambiguous. **Flagged for the owner's veto in the
run report; if vetoed, the lazy bind is switched off by deleting one branch and
the accounts surface as `identity_status: pending` (§2.7) for manual binding.**

What IS ambiguous, and is only flagged: a legacy federated row whose username
matches the legacy derivation of an assertion from a **different** issuer class
or door than its `auth_source` (condition 2 fails) — it stays unbound, the
assertion provisions a fresh account, and the legacy row is listed as pending.

### 2.7 Admin visibility (minimal, no new pages)
`publicUser` gains `id` and `identity_status: bound | pending` (pending = no
identity row). `GET /api/users?identity=pending` filters. The users table shows
a small "identity pending" badge; no other UI change. The admin can disable a
pending account (existing control) if they do not want it lazily bound.

## 3. Migration — expand / backfill / switch / enforce / contract

| Step | PG | File | Idempotent because |
|---|---|---|---|
| **Expand** (0049) | create `user_identities` + RLS; `users` gets nothing | `User.Identity` field, nil = pending | `IF NOT EXISTS`; nil field |
| **Backfill** (0050 + Go at boot) | insert `(tenant, 'local', id, id, 'local', '', 'backfilled-local')` for every `auth_source ∈ {'', local}` row `ON CONFLICT DO NOTHING`; federated rows: **nothing** (§2.6); write the migration marker once | same in `load()`; the marker in the KV | `ON CONFLICT DO NOTHING`; marker written only if absent |
| **Switch** | code resolves through §2.5 for every door; legacy tests updated; `TestBearerUsernameIsOneGlobalNamespace` replaced by `TestBearerIdentityIsTenantIssuerSubject` | same code path | n/a |
| **Enforce** | already enforced by the PK from step 1; add `CHECK (issuer <> '' AND subject <> '' )`; boot refuses to start if any `local` user lacks an identity row after backfill (a converge step must not destroy the estate, so it refuses, it does not delete) | store refuses a write that would create a second identity for a user | pure constraints |
| **Contract** | **NOT in this release.** `users.id` stays the principal id and legacy rows keep `id == username`. Nothing is dropped. Recorded as a follow-up tracker row: retire the username-as-id shape once no pending legacy federated row remains on any deployment | | |

Re-running any step is a no-op: PK/UNIQUE conflicts are `DO NOTHING`, the
marker is write-once, boot-time backfill on the file store is
compare-then-write. `rollback/0049_*.down.sql` drops the table; `0050` down
deletes only `provenance='backfilled-local'` rows.

## 4. Fan-out changes (Phase 4 checklist — every line is a test target)
1. `token.Claims.Sub` ← `User.ID` (legacy value unchanged).
2. `session.Store.Create(user.ID, …)`, `RefreshStore.IssueForSession(user.ID, …)`, `RevokeAllForUser(id)`, `ListForUser(id)`.
3. `binding_sync.go` principal id ← `User.ID`; `removeUserBindings(id)`; elevation principal ← id.
4. `audit.Event.Actor` ← id (already `claims.Sub`); apikey `CreatedBy` ← id.
5. `identity_handlers.go`: `/api/users/{id}` resolves by **id**; `Update/Delete/ResetPassword/SetMFA/TouchLogin` keyed by id; create: `LookupLocal(tenant, name)` collision → 409 (was global).
6. `mfa.go`, `session_handlers.go`, `bindings_api.go`: `users.Get(claims.Sub)` unchanged in shape — `Sub` is now the id.
7. `publicUser{ID, Username, IdentityStatus, …}`; frontend `admin.tsx` keys and mutations on `u.id`; `TopBar`/`IconRail`/`App.tsx` display `display_name || (auth_source==="local" ? username : email || "Signed in")` — never a `fed_` string. The frontend `User` type gains `id`.
8. `handleLogin` local resolution per §2.5.
9. Every `logInfo/logWarn` that prints `"user": username` prints the id (opaque for federated — no PII in logs, which is an improvement).

## 5. Tests (Phase 6 — ship with the feature, red-before on the current code)
**Fixture rule:** every new-style fixture user has `ID != Username`, so any path
still keying on the username fails loudly.

The nine required security tests (each on both backends where the store is
involved, via the contract-test seam):
1. **DB uniqueness** — inserting a second identity with the same
   `(tenant, issuer, subject)` is refused by the PK (PG) / store (file).
2. **One identity per user** — attaching a second tuple to an existing user is
   refused (`UNIQUE(user_id)`), through every public store method.
3. **Same subject, two issuers → two accounts** — never linked.
4. **Same email across issuers → two accounts** — never linked; email refreshed
   as profile only.
5. **Same preferred_username / login name across issuers → two accounts**
   (OIDC vs LDAP vs TACACS pairwise) — never linked.
6. **Local is its own namespace** — `admin` in tenant A and `admin` in tenant B
   are two accounts; a federated assertion whose subject equals a local
   username never touches the local account (H1 preserved); an unbound login
   form with an ambiguous local name is refused generically and audited; the
   per-tenant sign-in URL resolves it.
7. **Bearer-JIT is keyed by (tenant, iss, sub)** — same preferred_username,
   different sub → different account; same sub, different iss → different
   account; the stored account's tenant/role/status remain authoritative (H2).
8. **Tenant-A connection asserting a tenant-B identity → no session and no
   write** (C3 regression, re-asserted through the tuple path, including the
   suspended-tenant realm-source case the 2026-09-12 review found).
9. **Legacy lazy bind is bounded** — binds exactly once for a pre-marker,
   identity-less, same-auth-source account; a second different subject with
   the same legacy username gets a fresh account; a post-marker account is
   never adopted; a different auth_source never adopts; a disabled account is
   never adopted; the audit event and counter are emitted.

Plus: **migration idempotency** (apply 0049/0050 twice; run the file-store
load twice; boot backfill twice → identical state, zero duplicate rows) ·
**JIT never resurrects a disabled user** · **fan-out**: session revoke by id,
binding mirror by id, audit actor = id, API handle by id, and a frontend unit
test that no `fed_` username is ever rendered.

## 6. Execution plan and ownership
| Phase | Scope | Owner |
|---|---|---|
| 2+3 | `internal/users` (store.go, pg.go, new identity.go), `identity_ids.go mintUserID`, migrations 0049/0050 (+down), file-store load backfill, marker; store-level + contract tests incl. security tests 1–5 and idempotency | Opus agent "300-store" |
| 4 | doors (`auth.go`, `oidc.go`, `ldap_wiring.go`, `tacacs_wiring.go`, elevation), fan-out list §4, frontend; security tests 6–9, C3 regression, fan-out tests | Opus agent "300-doors" (starts when 300-store lands, builds on its branch) |
| 5 | enforce-at-boot check + `identity_status` surface | inside 300-doors |
| review | architect review of both diffs against §0 rules before merge | Fable |

## 7. What this deliberately does not do
- No SAML adapter, no SCIM, no explicit linking ceremony (design §15).
- No change to Keycloak; no per-tenant LDAP/TACACS (the seam is there).
- No contract step: `users.id` is not renamed and no legacy value changes.
- No claim-to-tenant mapping (tracker 275) — but 275 will place NEW accounts
  through `Assertion.TenantID`, so it slots in without touching the key.

## 8. Residual risk (to the run report)
- Keycloak first-broker-login may link upstream identities by email *inside
  Keycloak* before we ever see a `sub`. Recommended: set the realm's
  first-broker-login flow to create-new-user-only (no "link existing account
  by email") — an operator setting, documented in the SSO runbook.
- LDAP DN as subject: an OU move creates a new account (§2.3). Stated, listed
  as pending on the old row.
- The lazy bind (§2.6) is the one place username equality is consulted;
  flagged for the owner's veto.
