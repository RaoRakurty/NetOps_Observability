# Okta SSO — setup + test log

**Status: IN PROGRESS** (started 2026-08-02). This is a live working document —
every step is recorded as it is executed, including what failed and why, so the
next person can reproduce it without rediscovering the dead ends.

Target: federate Okta into Correlix for the **Homedepot Retail** tenant.

---

## 0. Architecture — read this first

Correlix **does not speak SAML, and never will**. That is a deliberate decision
recorded in `src/backend/oidc.go` and `docs/IDENTITY_ACCESS.md`:

```
Okta  ──SAML 2.0──▶  Keycloak  ──OIDC──▶  Correlix
                     (SAML SP)            (OIDC client only)
```

- **Keycloak** is the authentication plane. It speaks OIDC, SAML 2.0 and LDAP/AD
  and brokers external IdPs. All SAML parsing happens here.
- **Correlix** is the authorization plane. It is an OIDC client of Keycloak,
  verifies the ID token against Keycloak's JWKS, JIT-provisions a local user
  record, and mints its own HS256 session.

So "configure SAML" means two separate configurations:
1. **Okta ↔ Keycloak** in SAML 2.0
2. **Keycloak ↔ Correlix** in OIDC

There is no ACS endpoint on Correlix. Do not look for one.

### Testing SAML *and* OIDC — both are real protocol tests

"Correlix speaks OIDC" does not mean SAML goes untested. The SAML leg is
Okta→Keycloak, and it is a genuine SAML 2.0 exchange: Okta issues and signs a
real assertion, Keycloak validates the signature and consumes the attributes.
Only the *second* hop (Keycloak→Correlix) is OIDC, always.

To cover both federation protocols we stand up **two Okta apps**, each with its
own Keycloak IdP alias, running side by side:

| Okta app | Keycloak IdP alias | Correlix entry point | What it proves |
|----------|--------------------|----------------------|----------------|
| SAML 2.0 app | `okta-saml` | `/api/auth/sso/login?idp=okta-saml` | Okta-signed SAML assertion → Keycloak SP |
| OIDC app | `okta-oidc` | `/api/auth/sso/login?idp=okta-oidc` | Okta OIDC authorization code → Keycloak |

Keycloak supports both IdP types in one realm simultaneously, and
`kc_idp_hint=<alias>` selects which one a given login uses. Both land in
Correlix over the same OIDC callback, so the Correlix-side behaviour
(JIT provisioning, role mapping, tenant assignment) is identical and gets
exercised twice.

### Which SSO flows are supported

| Flow | Supported | Why |
|------|-----------|-----|
| **SP-initiated** (start at Correlix → Okta → back) | ✅ Yes | The designed path: `/api/auth/sso/login?idp=okta` |
| **IdP-initiated** (click tile in Okta → land in Correlix) | ❌ Not end-to-end | See below |

IdP-initiated is blocked by design at `src/backend/oidc.go:98`:

```go
state := r.URL.Query().Get("state")
ck, err := r.Cookie(ssoStateCookie)
if err != nil || ck.Value == "" || ck.Value != state {
    s.ssoFail(w, r, "invalid SSO state")
```

The callback requires a CSRF state cookie that Correlix set when Correlix started
the flow. An unsolicited assertion has no such cookie and is rejected. This is
correct CSRF protection — IdP-initiated SAML is a known weak spot precisely
because it has no such binding.

**Recommended: get the IdP-initiated *experience* without weakening anything.**
Configure the Okta tile as a **Bookmark app** pointing at:

```
http://10.70.245.122:8000/api/auth/sso/login?idp=okta
```

The user clicks the tile in Okta, lands on Correlix, which starts a normal
SP-initiated flow. Because the Okta session already exists, it completes with no
further prompts. Same UX, full CSRF protection retained.

Protocol-level IdP-initiated would require a deliberate code change (safe
handling of unsolicited assertions, a replay cache, RelayState validation). Not
in scope here; scope it separately if genuinely required.

---

## 1. Environment facts (verified 2026-08-02)

| Item | Value |
|------|-------|
| Correlix base URL | `http://10.70.245.122:8000` |
| Target tenant | `t_062d774a46c631273e4b9e9496df67e9` (Homedepot Retail, slug `homedepot`) |
| Keycloak | compose service `keycloak`, profile `sso`, relative path `/auth` |
| Keycloak admin user | `KEYCLOAK_ADMIN` in `deployment/docker/.env` (password already generated) |

Keycloak is **opt-in** and was not running before this exercise:

```bash
cd deployment/docker && docker compose --profile sso up -d keycloak
```

"Opt-in" is literal, and means three concrete things:

1. `docker-compose.yml` gives the `keycloak` service `profiles: ["sso"]`, so a
   plain `docker compose up` never starts it.
2. `OIDC_ENABLED` defaults to `false`, so the API serves no SSO endpoints.
3. **`install.py` never creates the `keycloak` Postgres database.**

### ⚠ Gap found 2026-08-02 — the opt-in path is broken out of the box

Enabling the profile is not sufficient. Keycloak crashes on first boot:

```
ERROR: Failed to obtain JDBC connection
ERROR: FATAL: database "keycloak" does not exist
```

`KC_DB_URL` points at `jdbc:postgresql://postgres:5432/keycloak`, but nothing in
the install path ever creates that database. Every operator who enables SSO will
hit this. Worked around here with:

```bash
docker exec netops-postgres-1 psql -U netops -d postgres \
  -c 'CREATE DATABASE keycloak OWNER "netops";'
```

Then Keycloak boots and `http://10.70.245.122:8000/auth/` returns 200.

**This should be fixed properly** — either `install.py` creates the DB when the
`sso` profile is selected, or the compose service gets an init step. Filed as a
tracker item.

### JIT provisioning behaviour — important

`oidc.go:146` provisions the federated user like this:

```go
user, err := s.users.UpsertFederated(username, claims.Email,
    firstNonEmpty(claims.Name, username), role, "oidc", p.DefaultTenant())
```

Two consequences worth understanding before testing:

1. **Every Okta user lands in ONE tenant** — `p.DefaultTenant()`, set by
   `OIDC_DEFAULT_TENANT` (default `global`). It is per-provider, not per-user.
   For this exercise it must be `t_062d774a46c631273e4b9e9496df67e9`.
2. **`UpsertFederated` sets `auth_source = "oidc"`.** Pointing SSO at an existing
   **local** account converts it to federated, and local accounts are the only
   ones with a password Correlix owns (`auth.go:705`). See the break-glass
   warning below.

### ⚠ Break-glass warning

`hd-admin` already exists as a **local** `super-admin` in the Homedepot tenant.
If SSO is pointed at that same identity it becomes federated, and if SSO then
breaks there is no local admin left for that tenant. Keep at least one local
admin account that SSO never touches.

---

## 2. Configuration values

Fill these in as they are created.

| Setting | Where | Value |
|---------|-------|-------|
| Okta org URL | Okta | _pending_ |
| Okta API token (SSWS) | Okta → Security → API → Tokens | _pending, not recorded here_ |
| Keycloak realm | Keycloak | _pending_ |
| Keycloak OIDC client id | Keycloak | `netops` (default) |
| Keycloak IdP alias | Keycloak | `okta` |
| SAML ACS URL | Okta app config | `http://10.70.245.122:8000/auth/realms/<realm>/broker/okta/endpoint` |
| SAML Audience / Entity ID | Okta app config | same as ACS URL |
| `OIDC_ENABLED` | Correlix `.env` | `true` |
| `OIDC_ISSUER` | Correlix `.env` | `http://10.70.245.122:8000/auth/realms/<realm>` |
| `OIDC_CLIENT_ID` | Correlix `.env` | `netops` |
| `OIDC_CLIENT_SECRET` | Correlix `.env` | from Keycloak client credentials |
| `OIDC_REDIRECT_URL` | Correlix `.env` | `http://10.70.245.122:8000/api/auth/sso/callback` |
| `OIDC_DEFAULT_TENANT` | Correlix `.env` | `t_062d774a46c631273e4b9e9496df67e9` |
| `OIDC_ADMIN_ROLES` | Correlix `.env` | `super-admin,admin,netops-admin` (default) |

**Secrets are never written into this file.** They live in
`deployment/docker/.env`, which is gitignored.

---

## 2b. ⚠ The `OIDC_*` env vars DO NOT enable SSO on their own

This is the most important finding of the exercise, and it contradicts the
setup instructions in `docker-compose.yml` ("set `OIDC_ENABLED=true` and the
`OIDC_*` vars in .env — the api service reads them").

The live provider is built from a **stored** config, not from the environment:

```go
s.srv.oidc.Store(oidc.NewProviderFromConfig(stored, jwksTTL()))   // oidc_config.go:177
```

`load()` falls back to env **only when the stored key is absent or empty**:

```go
b, err := platformdb.Load(s.path)
if errors.Is(err, os.ErrNotExist) { return nil }  // absent = env defaults apply
if len(b) == 0 { return nil }                     // empty  = env defaults apply
```

But the key already exists, holding a disabled config:

```
app_kv['/data/oidc_config.json'] =
  { "enabled": false, "issuer": "", "client_id": "", ... }
```

So a fully correct `.env` produces `{"enabled": false, "providers": []}` from
`/api/auth/sso/config`, and `/api/auth/sso/login` returns **404**. Verified live
2026-08-03 with every `OIDC_*` var confirmed present in the api container.

**Correct path:** configure SSO through **Administration → Authentication**
(`PUT /api/auth/oidc/config`), which is platform-admin gated — auth providers are
platform-GLOBAL plumbing, so a tenant admin (even a tenant `super-admin` like
`hd-admin`) cannot set them (CLAUDE.md §3a).

**Either the env path should work as documented, or the compose comment and
docs should say "seed only — configure in the UI".** Filed as a tracker item.

---

## 3. Step log

| # | Step | Result |
|---|------|--------|
| 1 | Confirmed Correlix has no SAML implementation; Keycloak is the SAML plane | ✅ verified in code |
| 2 | Confirmed SP-initiated supported, IdP-initiated rejected by state check | ✅ verified at `oidc.go:98` |
| 3 | Located target tenant `t_062d774a46c631273e4b9e9496df67e9` | ✅ |
| 4 | Confirmed `hd-admin` exists, local super-admin, Homedepot tenant | ✅ |
| 5 | Brought up Keycloak (`--profile sso`) | ⏳ booting |
| 6 | Create Keycloak realm + OIDC client | ⏳ |
| 7 | Create Okta SAML app | ⏳ blocked on Okta API token |
| 8 | Add Okta as SAML IdP in Keycloak | ⏳ |
| 9 | Wire `OIDC_*` into `.env`, restart api | ⏳ |
| 10 | Test SP-initiated login end-to-end | ⏳ |
| 11 | Add Okta bookmark tile, test IdP-initiated UX | ⏳ |
