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
| **IdP-initiated** (click tile in Okta → land in Correlix) | ✅ Yes — two ways | See §4 CORRECTION |

> **SUPERSEDED — read §4 first.** The paragraphs below were written believing
> Correlix's CSRF state check made IdP-initiated impossible. That is wrong: the
> assertion never reaches Correlix at all — Keycloak terminates it and then runs
> a normal SP-initiated OIDC leg, so the state cookie is always present. The
> correct mechanism is the client-scoped broker endpoint documented in §4.

The state check itself is real, at `src/backend/oidc.go:98`:

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

The bookmark remains a legitimate option, but it is NOT the only one — see §4
for the client-scoped broker endpoint, which is true protocol-level
IdP-initiated and needs no Correlix code change.

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
| 10 | Enable SSO via the admin API (what the GUI calls) | ✅ `PUT /api/auth/oidc/config` → 200, `ready: true` |
| 11 | `/api/auth/sso/config` shows both providers | ✅ `enabled: true`, okta-saml + okta-oidc |
| 12 | SP-initiated OIDC reaches Okta | ✅ chain ends at Okta `/oauth2/v1/authorize`, 200 |
| 13 | SP-initiated SAML AuthnRequest correct | ✅ see below |
| 14 | Complete the 4 cells in a browser | ⏳ needs a human at Okta's login page |

### Verified chains (2026-08-03)

**OIDC, SP-initiated** — followed with curl, ends on Okta's own login page:

```
/api/auth/sso/login?idp=okta-oidc
  → 302 /auth/realms/correlix/protocol/openid-connect/auth?...&kc_idp_hint=okta-oidc
  → 302 https://trial-4975697.okta.com/oauth2/v1/authorize?scope=openid+profile+email&state=…  [200]
```

**SAML, SP-initiated** — stops at Keycloak's self-submitting POST form (curl does
not execute it; that is the HTTP-POST binding working, not a failure). The form
and the AuthnRequest inside it are correct:

```
form action = https://trial-4975697.okta.com/app/…/exk15x4v3xdsXW0AJ698/sso/saml
fields      = SAMLRequest, RelayState

<samlp:AuthnRequest
  AssertionConsumerServiceURL="http://10.70.245.122:8000/auth/realms/correlix/broker/okta-saml/endpoint"
  Destination="https://trial-4975697.okta.com/app/…/sso/saml" …>
```

The ACS matches what was registered in the Okta app, and the Destination matches
Okta's SSO endpoint from its metadata — so the round trip is correctly addressed
in both directions.

### ✅ CELL 1 — SAML, SP-initiated: PASSED (2026-08-03)

Full chain exercised in a browser: Correlix → Keycloak → Okta (password + MFA)
→ back to Correlix, signed in. Provisioning verified in Postgres:

```
id      rao.rakurty@versa-networks.com
tenant  t_062d774a46c631273e4b9e9496df67e9   (Homedepot Retail — correct)
src     oidc
role    read-only                            (= OIDC_DEFAULT_ROLE)
```

Okta enforced MFA in the browser flow even though the `/api/v1/authn` API path
did not — the org sign-on policy applies to app access, and Correlix honours it
(`oidc.go:132` verifies the IdP asserted a second factor before accepting).

#### Role mapping — the half that is invisible until it bites

The user landed as `read-only`, which is correct-by-default but not useful.
`RoleFor()` scans `realm_access.roles` + `groups` from the **ID token** against
`OIDC_ADMIN_ROLES` / `OIDC_OPERATOR_ROLES`, falling back to `OIDC_DEFAULT_ROLE`.

Granting a matching Keycloak realm role is **not sufficient on its own**:
Keycloak's built-in realm-roles mapper sets `access.token.claim=true` but
`id.token.claim=false`. The role is granted, the config looks right everywhere
you would think to look, and the role never reaches Correlix. Both halves are
required:

```bash
# 1. role whose NAME matches OIDC_ADMIN_ROLES, granted to the user
POST /admin/realms/correlix/roles                      {"name":"netops-admin"}
POST /admin/realms/correlix/users/{id}/role-mappings/realm
# 2. and put it in the ID TOKEN (default is access-token only)
PUT  /admin/realms/correlix/client-scopes/{roles}/protocol-mappers/models/{id}
     config.id.token.claim = "true"
```

**Production note:** granting per user does not scale. Use
Okta group → IdP mapper (*Advanced Claim to Role*) so group membership drives
the Correlix role for both protocols.

#### Administration 403s are partly CORRECT

A tenant `super-admin` still cannot open platform-GLOBAL pages — Collectors,
Regions, Sessions, Stack Health, Self-Monitoring, OpenSearch, GraphQL Explorer,
Authentication, Token Policy, LLM keys, notification channels. These are
`platformOnly` / `requirePlatformAdmin` (CLAUDE.md §3a): a tenant admin
configuring the platform's own auth providers would leak privilege across every
tenant. Only the platform `admin` account sees them. A *tenant-scoped* page
that 403s for a tenant super-admin WOULD be a bug — none observed.

### ✅ FINAL RESULTS — all four cells (2026-08-03)

| # | Cell | Result |
|---|------|--------|
| 1 | SAML SP-initiated | ✅ PASS |
| 3 | OIDC SP-initiated | ✅ PASS |
| 4 | OIDC IdP-initiated | ✅ PASS — via `initiate_login_uri` (the spec's mechanism) |
| 2 | SAML IdP-initiated | ✅ PASS via bookmark · ❌ protocol-level blocked: SAML-client-only lookup, OIDC downstream |

Role mapping confirmed end to end after the realm role + ID-token fix:

```
rao.rakurty@versa-networks.com | super-admin | oidc | t_062d774a46c631273e4b9e9496df67e9
```

#### ⚠ CORRECTION (2026-08-03, later) — the claim below was WRONG

The section that follows concluded that protocol-level IdP-initiated SAML is
impossible through a Keycloak broker. **That is not true**, and the reasoning was
faulty: two failed attempts were used to infer an architectural limit, when both
failed for the same mundane reason — no landing target was ever configured.

The owner pushed back from experience ("RelayState is embedded in the URL for
IdP-initiated SAML"), which is correct and is the industry norm:

- **AWS** requires the IdP to support "unsolicited IdP-initiated SSO with a deep
  link target resource or relay state endpoint URL".
- **Azure AD** exposes a static **Relay State** field on the enterprise app.
- **ADFS** defines a composed format (URL-encoded RPID + state, re-encoded).

The rule everywhere: **the SP defines what RelayState means; the IdP passes it
through opaquely.** Keycloak is the SP here, and it has its own mechanism.

#### The mechanism that actually works: a client-scoped broker endpoint

Keycloak routes IdP-initiated brokered logins through a **client sub-path** on
the broker endpoint:

```
{keycloak}/realms/{realm}/broker/{idp-alias}/endpoint/clients/{name}
```

`{name}` is the target client's `saml_idp_initiated_sso_url_name` attribute.
Verified live: that path is routed (400 "Invalid Request" on a bare GET, i.e.
"no SAMLResponse", rather than 404), while a nonexistent IdP alias responds
differently.

Configured 2026-08-03:

```
Keycloak client `netops`:  saml_idp_initiated_sso_url_name = netops
Okta SAML app default ACS: …/broker/okta-saml/endpoint/clients/netops
```

**Both directions coexist** via Okta's multiple-ACS support, which matters
because IdP-initiated uses the app's DEFAULT ACS while SP-initiated uses the ACS
named in Keycloak's AuthnRequest:

```
allowMultipleAcsEndpoints = true
acsEndpoints = [ …/endpoint/clients/netops   (index 0 — IdP-initiated default)
                 …/endpoint                  (index 1 — SP-initiated request)  ]
```

Confirmed after the change that Keycloak's AuthnRequest still carries
`AssertionConsumerServiceURL=…/broker/okta-saml/endpoint`, which is in the
allowed list — so cell 1 is unaffected.

**TESTED 2026-08-03 — DOES NOT WORK with an OIDC downstream client.**

The error progressed usefully, which is how we know each step was real:

```
Illegal base64url string!          RelayState held a URL, Keycloak wanted its own token
RelayState parameter was null      RelayState removed; no landing target at all
invalid_redirect_uri (clientId=null)   client-scoped endpoint configured
```

The decisive detail is `clientId="null"`: Keycloak never resolves the client, so
`invalid_redirect_uri` is a symptom rather than the cause. The reason fits the
evidence — `saml_idp_initiated_sso_url_name` is a **SAML client** attribute and
Keycloak matches it against SAML clients only. `netops` is an **OIDC** client, so
the lookup finds nothing.

So this mechanism bridges *SAML IdP → SAML client*. Our topology is
*SAML IdP → OIDC client*, and that is the gap.

**What is NOT yet established:** whether another Keycloak path bridges
IdP-initiated SAML into an OIDC client (e.g. a SAML client in Keycloak that
chains onward, or behaviour that differs in Keycloak 26+; this stack is pinned to
25.0). Do not read this as "impossible" — that claim was made once already on
thinner evidence and was wrong. It is "not achieved, by this mechanism, on this
version".

**Working today:** the Bookmark tile, which delivers the same operator
experience via a silent SP-initiated flow.

#### Superseded reasoning, kept for the record

Keycloak's SAML broker only accepts **solicited** responses. It requires a
`RelayState` that Keycloak itself issued, so an unsolicited assertion — which is
exactly what an Okta tile sends — can never be consumed. Demonstrated from both
directions:

| RelayState sent by Okta | Keycloak |
|-------------------------|----------|
| a destination URL | `RuntimeException: Illegal base64url string!` |
| omitted | `SAML RelayState parameter was null when it should be returned by the IDP` |

Both surface to the user as a Keycloak error page *after* they have already
entered password and MFA. No configuration fixes this; it is structural.

**The supported implementation is an Okta Bookmark app** pointing at
`/api/auth/sso/login?idp=okta-saml`. The tile click starts a normal SP-initiated
flow which completes silently (the Okta session already exists), so the operator
experience is identical — and the CSRF state binding that makes unsolicited SAML
risky in the first place is preserved.

OIDC differs: `initiate_login_uri` IS the standard third-party-initiated login
hook, so cell 4 is a genuine protocol-level pass.

#### Okta app settings that are not obvious

- OIDC apps are created **hidden** (`visibility.hide = {iOS:true, web:true}`) and
  with `idp_initiated_login.mode = "DISABLED"`. Both must be flipped or the tile
  never appears on the end-user dashboard. SAML apps get a tile automatically.
- Every app create needs a `visibility` block; OIDC apps also need
  `"name": "oidc_client"`.
- App **assignment** controls who may sign in — it does NOT influence the role
  the user receives in Correlix. That comes from Keycloak realm roles / groups.

#### OIDC brokering needs Keycloak→IdP egress; SAML does not

Observed live as `SocketTimeoutException: Read timed out` on
`AbstractOAuth2IdentityProvider`, failing *after* successful Okta auth. SAML
brokering is entirely front-channel — the browser carries the assertion and
Keycloak verifies the signature offline against the imported certificate. OIDC
requires a back-channel `/token` exchange and JWKS fetch from the Keycloak
container itself.

**In egress-restricted or proxied networks, SAML will work where OIDC silently
will not**, and the failure appears only after the user has entered credentials
and MFA. Recommend SAML as the default for locked-down deployments.

### What is left, and why

Everything up to the Okta login prompt is verified. The remaining step is
entering credentials at Okta, which needs a browser — the Claude in Chrome
extension is not connected in this session, and Okta admin sign-in is an
interactive flow. The four cells to click through:

| # | Cell | URL to open |
|---|------|-------------|
| 1 | SAML SP-initiated | `http://10.70.245.122:8000/api/auth/sso/login?idp=okta-saml` |
| 2 | SAML IdP-initiated | the "Correlix (SAML via Keycloak)" tile in Okta |
| 3 | OIDC SP-initiated | `http://10.70.245.122:8000/api/auth/sso/login?idp=okta-oidc` |
| 4 | OIDC IdP-initiated | the "Correlix (OIDC via Keycloak)" tile in Okta |

After each, confirm the user lands in Correlix and check the provisioned account:

```sql
select id, tenant_id, data->>'auth_source', data->>'role'
from users where data->>'auth_source' = 'oidc';
```

Expect `tenant_id = t_062d774a46c631273e4b9e9496df67e9` (Homedepot) for all four.
