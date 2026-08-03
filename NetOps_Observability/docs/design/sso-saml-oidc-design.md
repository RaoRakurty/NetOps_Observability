# SSO design — SAML 2.0 and OIDC

**Status: DESIGN, awaiting owner review.** Nothing here is built beyond what
§2 marks as existing. Written 2026-08-03 immediately after the first real
end-to-end Okta bring-up, so every "today" claim below is observed, not assumed.

Evidence for all of it: `docs/runbooks/okta-sso-setup.md` (live test log).
Decision item: tracker **#135**.

---

## 1. Why this document exists

Correlix federates today, and federation works — but only in three of the four
shapes customers ask for. The missing one, **IdP-initiated SAML**, is not a
configuration gap. It falls out of an architectural choice, so closing it is a
design decision rather than a bug fix.

Two things make it worth doing rather than deferring:

- **SAML is the majority protocol** in the enterprise segment we sell to.
- **High-security customers prefer IdP-initiated**, because users start at the
  trusted portal and never type credentials at a URL the application controls.

Industry guidance agrees products should support both: SP-initiated is the SaaS
norm, IdP-initiated is what enterprise portals and internal tools use.

---

## 2. What exists today (verified 2026-08-02/03)

### 2.1 Architecture

Correlix speaks **OIDC only**. All SAML/LDAP is delegated to Keycloak, which
acts as an identity **broker** — it terminates the external protocol and starts
a fresh OIDC conversation with Correlix.

```
Okta ──SAML 2.0──▶ Keycloak ──OIDC──▶ Correlix ──▶ own HS256 session
       (terminates here)     (starts here)
```

This is deliberate and documented (`src/backend/oidc.go`,
`docs/IDENTITY_ACCESS.md`):

> Keycloak is the AUTHENTICATION plane... The Go API is the AUTHORIZATION plane
> and never parses SAML/LDAP itself.

The rationale is sound and still holds: no XML-DSig in Go, one token
verification path on the hot request path, LDAP/AD federation for free.

### 2.2 Components that exist

| Component | Where | State |
|-----------|-------|-------|
| OIDC client (authorization-code + PKCE-less confidential) | `src/backend/oidc.go` | ✅ working |
| ID-token verification against JWKS | `internal/jwks`, `internal/oidc` | ✅ working |
| CSRF state cookie on the SSO round trip | `oidc.go:98` | ✅ working |
| JIT user provisioning | `oidc.go:146` `UpsertFederated` | ✅ working |
| Role mapping from IdP claims | `internal/oidc/oidc.go` `RoleFor()` | ✅ working |
| MFA assertion check (`amr`/`acr`) | `oidc.go:132` | ✅ working |
| Runtime config store + admin API | `oidc_config.go`, `PUT /api/auth/oidc/config` | ✅ working |
| Keycloak service (opt-in) | `docker-compose.yml` profile `sso` | ✅ working |
| SAML Service Provider (ACS) | — | ❌ **does not exist** |

### 2.3 What was proven to work

Validated against a real Okta trial org, Homedepot tenant:

| Flow | Result |
|------|--------|
| SAML SP-initiated | ✅ pass |
| OIDC SP-initiated | ✅ pass |
| OIDC IdP-initiated (`initiate_login_uri`) | ✅ pass |
| SAML IdP-initiated | ❌ **fails** |
| Role mapping → `super-admin` in the right tenant | ✅ pass |
| Tenant isolation (federated user lands in one tenant) | ✅ pass |

### 2.4 Known constraints discovered

1. **`OIDC_*` env vars are a fallback, not an override.** A saved config in the
   kv store wins. (Fixed so a *blank* stored record falls through — commit
   `1a575530`.)
2. **OIDC brokering requires Keycloak→IdP egress**; SAML brokering does not.
   Observed as `SocketTimeoutException` on the back-channel token exchange,
   failing only *after* the user authenticated. In egress-restricted networks
   SAML works where OIDC silently does not.
3. **Role grants need `id.token.claim=true`.** Keycloak's realm-role mapper
   defaults to access-token only; `RoleFor()` reads the ID token.
4. **One tenant per OIDC provider.** `OIDC_DEFAULT_TENANT` is a single value;
   per-user tenant mapping from claims is not implemented.

---

## 3. Why IdP-initiated SAML cannot work today

Not a missed setting. Three independent confirmations:

**a) Keycloak's IdP-initiated machinery resolves SAML clients only.**
`saml_idp_initiated_sso_url_name`, `/broker/{alias}/endpoint/clients/{name}` and
the "IDP Initiated SSO URL Name" field all target a SAML client. Correlix is
registered `protocol=openid-connect`. Observed: `clientId="null"` followed by
`invalid_redirect_uri` — the client is never resolved, so the redirect error is
a symptom rather than the cause.

**b) The translation has nothing to anchor to.** An unsolicited assertion
arrives with no prior request. Keycloak can consume it, but must then *start* an
OIDC flow toward Correlix — and OIDC has no notion of a login nobody asked for.
SP-initiated survives translation because the chain is already in flight.

**c) The SP owns the ACS.** Okta's and scalekit's documentation both state the
IdP posts directly to the Service Provider's ACS endpoint, and that the SP
defines what RelayState means. Correlix has neither.

**Conclusion:** the gap is the absence of a SAML SP, and every route to closing
it — native ACS, or a Keycloak SAML client chained onward — is the same
engineering work.

---

## 4. Target architecture

Keep the broker. **Add** a native SAML SP. Two front doors, one session model.

```
                    ┌── SAML 2.0 (direct) ─────────────┐
Okta / ADFS / Azure ┤                                  ├─▶ Correlix ─▶ HS256 session
                    └── SAML/OIDC/LDAP ─▶ Keycloak ─OIDC┘
```

Why keep Keycloak: LDAP/AD federation, multi-IdP brokering, MFA orchestration.
Native SAML is an **additional** path for customers who want a direct,
egress-free, IdP-initiated-capable integration — not a replacement.

Both paths converge on the same downstream behaviour, which must not fork:
JIT provisioning, role mapping, tenant scoping, session minting, audit.

---

## 5. What must be implemented

### Phase 1 — SAML SP core (SP-initiated)

| Item | Detail |
|------|--------|
| ACS endpoint | `POST /api/auth/saml/acs` — consumes `SAMLResponse` |
| Metadata endpoint | `GET /api/auth/saml/metadata` — SP entity descriptor for the IdP |
| AuthnRequest | `GET /api/auth/saml/login` — SP-initiated, signed, with `RelayState` |
| Signature validation | XML-DSig against the IdP's registered cert |
| Assertion validation | issuer, audience, recipient, destination, `NotBefore`/`NotOnOrAfter` |
| Attribute mapping | email / firstName / lastName / groups → the same shape `RoleFor()` consumes |
| Session minting | reuse the existing path — do NOT fork |

### Phase 2 — IdP-initiated + hardening (the point of the exercise)

An unsolicited assertion has **no `InResponseTo`**, so there is no request
correlation. These are mandatory, not best-effort:

| Control | Rule |
|---------|------|
| Replay cache | Cache `AssertionID` (and `SessionIndex`); reject duplicates within the validity window |
| Short validity | Enforce 2–5 min `NotBefore`/`NotOnOrAfter`; reject wider windows |
| Reject suspicious | An **unsolicited** response that DOES carry `InResponseTo` is a replay indicator → reject |
| Issuer/audience | Strict match against the tenant's registered IdP; no wildcards |
| RelayState | **Allowlist or relative-path only.** Redirecting to an arbitrary RelayState is an open redirect in the login flow |
| Clock skew | Bounded, explicit (±2 min), not unlimited |

### Phase 3 — Per-tenant configuration + isolation (CLAUDE.md §3a)

The isolation requirement is the piece most likely to be got subtly wrong.

| Item | Detail |
|------|--------|
| Per-tenant IdP registration | entity id, SSO URL, signing cert, attribute map |
| Tenant resolution | ACS path or assertion issuer → tenant. **Never** from user-supplied body |
| Cross-tenant refusal | Homedepot's IdP must not be able to assert a user into another tenant |
| Storage | Per-tenant rows, FORCE-RLS, `withTenant` — same as every other tenant table |
| Isolation test | `org_isolation_test.go` template; **required** with the feature |

### Phase 4 — Operator UI

Follow the ServiceNow connector pattern (`docs/integrations/servicenow.md`):
tenant admin pastes IdP metadata (or URL), downloads SP metadata, presses
**Test connection**, sees a clear pass/fail. No hand-editing Keycloak.

---

## 6. Dependencies — requires a CLAUDE.md §6 amendment

Hand-rolling XML-DSig and canonicalisation is exactly the wire-format code the
stdlib-only rule exists to keep out; Okta's own documentation says to use a
toolkit. Proposed allowlist addition:

| Module | Purpose | Gates |
|--------|---------|-------|
| `github.com/crewjam/saml` **or** `github.com/russellhaering/gosaml2` | SAML SP: XML-DSig verification, c14n, assertion parsing | need ✅ (stdlib genuinely cannot) · offline ✅ (vendorable) · pinned ✅ · minimal — **to be assessed**: transitive tree must be reviewed before selection |

Selection criteria, in order: audit history and CVE record; transitive
dependency count; whether IdP-initiated (unsolicited) responses are supported
first-class; maintenance activity.

---

## 7. Testing requirements

No feature is complete without these (§11 + §3a):

- Unit: assertion validation — expired, wrong audience, wrong issuer, bad
  signature, replayed ID, unsolicited-with-`InResponseTo`, skewed clock
- Unit: RelayState — absolute URL rejected, relative accepted, allowlist honoured
- Integration: SP-initiated round trip against a fixture IdP
- Integration: **IdP-initiated** round trip (unsolicited POST to ACS)
- **Isolation: cross-tenant assertion refused** — tenant A's IdP cannot mint a
  session in tenant B
- Regression: OIDC paths unchanged (all four cells in the runbook stay green)

---

## 8. Open decisions for owner review

1. **Build native SAML SP, or ship the bookmark workaround?** The bookmark works
   today and gives the same one-click experience via a silent SP-initiated flow.
   Native SP is the real fix and a multi-week effort.
2. **Which library?** Needs the §6 assessment above before committing.
3. **Does Keycloak stay?** Recommendation: yes, for LDAP/AD and multi-IdP.
4. **Per-tenant or platform-global SAML?** Recommendation: per-tenant, matching
   the ServiceNow connector model — but that is the expensive choice.
5. **Do we keep OIDC brokering via Keycloak** for customers who want OIDC, given
   it needs egress that SAML does not?

---

## 9. Recommendation

Build it, in the phase order above, **per-tenant**, keeping Keycloak.

The reasoning is not the one failing test — it is that the failure exposed a
structural gap against the segment we sell to, and that gap will recur with
every enterprise SAML customer. Phase 1+2 alone (platform-global, single IdP)
would close the functional gap quickly if a faster path is wanted, with Phase 3
following before the first multi-tenant customer.

The one thing not to do is hand-roll the crypto.
