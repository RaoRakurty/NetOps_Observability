# Elevation identity providers — a second IdP for just-in-time access

**Status: shipped 2026-09-07.** Companion to `docs/runbooks/okta-sso-setup.md`
(which covers the standing connection) and to the addendum in
`docs/design/sso-saml-oidc-design-2026-08-03.md`.

---

## 0. What this is, and what it is not

Some customers run two identity providers on purpose:

> "In extreme secure environments they maintain different IdPs, one for regular
> auth and another one to maintain the JIT access." — owner, 2026-09-07

Correlix supports that as a first-class **access model** on each connection:

| Kind | What a sign-in through it does |
|------|--------------------------------|
| `standing` (default) | The everyday front door. Provisions the account on first login, sets its tenant, carries its everyday role. Unchanged from every release before this one. |
| `elevation` | Grants access to an account that **already exists**. Produces one time-bound role binding and nothing else. |

An elevation connection **cannot**:

1. **create an account** — an unknown subject is refused with
   *"sign in through your standing provider first"* on an unbound door. On a
   TENANT-BOUND door (`/t/{slug}/…`, `/org/{id}/…`) the refusal is instead the
   generic *"… is not an identity provider for …"* wording, byte-identical to
   the one a mis-registered provider gets, so the pair cannot be used as a
   cross-tenant username-existence oracle. The real reason is in the audit
   trail;
2. **move a tenant** — the grant is stamped with the account's own tenant; a
   claim naming a tenant is not consulted and cannot be;
3. **change a standing role** — `UpsertFederated`/`MergeFederated` are not on
   this path at all, so the stored account is read, never written;
4. **reach outside the realm in the URL** — an elevation door opened at a
   tenant URL grants nothing to an account in another tenant, in the `global`
   tenant, or in no tenant. Platform staff elevate through an unbound door at
   the installation's own address, never through a customer's tenant link.

Those four refusals are the point: the blast radius of the elevation IdP is one
expiring grant, not an identity. `FEDERATION_ALLOW_PLATFORM_OWNER` (SR-025)
still applies to the elevated role, so an elevation IdP is not a back door to
platform ownership either.

**What it does not do (yet):** an elevation binding does not widen the general
permission decider. It is the credential a **step-up gate** demands, and it is
stamped on every audit row written while it is held. Making the elevated *role*
authoritative everywhere is the PBAC Phase-B union decider — a change to the
whole authorization path, not something to do one gate at a time.

---

## 1. Configure the connection (Correlix)

Administration → Authentication → Single Sign-On → **Identity providers** →
*+ Add OIDC provider* (or SAML).

| Field | Value |
|-------|-------|
| Alias | e.g. `okta-jit` (URL-safe, immutable) |
| Display name | e.g. `Break-glass IdP` — this is what the sign-in page and every step-up refusal shows |
| Access model | **Elevation — grants time-bound access** |
| Maximum duration | minutes, 1–480. The provider ceiling. |
| Duration claim | optional; the claim carrying the requested lifetime |
| Reason claim | optional; the change/ticket id recorded on the grant |
| Resource claim | optional; confines the grant to one device |

Group → role mappings work exactly as on a standing connection: the mapped role
becomes the **elevated** role recorded on the grant.

**A claim can only ever make a grant shorter or narrower.** The duration claim
is read in three shapes, told apart by magnitude:

| Shape | Example claim value | Read as |
|-------|--------------------|---------|
| UNIX seconds (≥ 1 000 000 000) | `1789000000` | an absolute instant |
| RFC3339 | `2026-09-07T18:00:00Z` | an absolute instant |
| anything smaller | `30` | a count of **minutes** |

The grant lasts `min(claim, maximum)`. A missing, blank, zero, negative or
unparseable claim falls back to the maximum — a typo in an IdP mapping must not
look like an outage. A claim that is **already in the past** refuses the sign-in
rather than minting a grant that is dead on arrival.

The **resource claim** must name a device the account can already reach. One
naming another tenant's device is refused outright (§3a) — never widened to the
tenant scope.

### Env-only deployments

A connection can also be marked elevation in `OIDC_PROVIDERS`, whose entry
format gained a fourth segment:

```
OIDC_PROVIDERS=corp:Corp SSO:oidc,okta-jit:Break-glass IdP:oidc:elevation
```

Three-segment entries (every entry written before this release) stay standing,
and only the exact word `elevation` marks a door — a typo leaves it standing,
which merely provisions as before. An env-only elevation door runs on the
package defaults (60-minute ceiling, no claims); the stored record is what
carries claim names and a custom ceiling.

---

## 2. Configure the app at the IdP

### Okta (OIDC app, brokered through Keycloak)

1. Create a **second** OIDC app — do not reuse the standing one. Assign only the
   people allowed to elevate, and put it behind your strictest sign-on policy
   (hardware factor, short session, device trust).
2. Add the claims Correlix will read (Security → API → Authorization Servers →
   your server → **Claims**, include in **ID token / always**):

   | Claim name | Value | Purpose |
   |------------|-------|---------|
   | `access_expires_at` | e.g. `(now() + 900)` from an expression, or a user/group attribute | how long the grant lasts |
   | `change_ticket` | `user.changeTicket` (a profile attribute your access-request tool writes) | the reason recorded on the grant |
   | `target_device` | `user.targetDevice` | confine the grant to one device |
   | `sid` | Okta emits it on the ID token | correlates the grant with the IdP session |

3. Group → role mapping is configured on the Correlix side, as for any
   connection.

### Entra ID (Azure AD)

1. Register a **second** application; scope it with a Conditional Access policy
   of its own (privileged access, sign-in frequency, PIM-eligible group).
2. Add optional claims to the **ID token** (Token configuration → *Add optional
   claim*), and directory extensions / claims-mapping-policy claims for the
   ticket and device values:

   | Claim name | Source |
   |------------|--------|
   | `access_expires_at` | claims-mapping policy over a directory extension |
   | `change_ticket` | directory extension written by your access-request flow |
   | `target_device` | directory extension |
   | `sid` | optional claim `sid` |

3. Entra's `groups` claim drives the group → role mapping as usual.

> **Do not point the elevation connection at the same app as the standing one.**
> The whole control is that the two doors are governed separately.

---

## 3. What a sign-in produces

The sign-in page shows elevation doors in their own group, **Elevated access**,
separate from the ordinary sign-in buttons — an operator who picks one because
it looked like the front door otherwise learns the difference from an error.

A successful elevation login creates one binding:

```json
{
  "principal_id": "jdoe",
  "role_id":      "operator",              // the elevation connection's mapping
  "scope_id":     "tenant:t_ab…",          // or resource:device:<id>
  "effect":       "allow",
  "not_before":   "2026-09-07T12:00:00Z",  // now
  "expires_at":   "2026-09-07T12:15:00Z",  // min(claim, maximum)
  "granted_by":   "okta-jit",              // the provider alias
  "reason":       "CHG-4471",              // the reason claim, else "elevation login"
  "condition": {
    "elevation": true,
    "elevation_provider": "okta-jit",
    "elevation_sid": "…",                  // the IdP session id, when present
    "elevation_tenant": "t_ab…",           // from the ACCOUNT, never a claim
    "elevation_expiry_source": "claim"     // or "provider_max"
  }
}
```

**Re-login refreshes, never stacks.** Every prior elevation for the principal is
dropped before the new one is written — including one that mapped to a different
role or a different device, which a same-id overwrite would have left standing.

---

## 4. Expiry, revoke, and step-down

- **Expiry** needs nothing. The grant stops being honoured on the first request
  after `expires_at`; the session carries on with standing rights. The request
  that notices also reaps the binding and writes `ELEVATION_EXPIRED`.
- **Step down**: `DELETE /api/auth/elevation` (the *End* button in the account
  menu). Idempotent.
- **Admin revoke**: `DELETE /api/bindings/{id}`. Immediate — every gate re-reads
  the store per request — and audited as `ELEVATION_REVOKED` with the binding id.

**Revocation is never step-up gated.** A safety control you cannot exercise
without first passing the control is not a safety control: if the elevation IdP
is down, an admin must still be able to take access away.

### Known gap — upstream logout

Ending a Correlix grant does **not** end the IdP session. The SSO design
(`docs/design/sso-saml-oidc-design-2026-08-03.md` §12) puts SAML SLO and OIDC
RP-initiated / back-channel logout out of scope and makes local logout
authoritative. The IdP session id **is** captured on the binding
(`elevation_sid`) so targeted upstream revocation needs no migration when that
is built. Until then: revoking in Correlix removes the access; the operator's
IdP session is the IdP's to end.

---

## 5. Step-up: which actions require elevation

When at least one **enabled** elevation connection exists, these refuse a
standing session:

| Route | Why |
|-------|-----|
| `POST /api/bindings` | granting standing access to anyone |
| `POST /api/incidents/{id}/tac/case` | ships a redacted diagnostic bundle to a vendor |
| `POST /api/devices/{id}/ssh-ticket` and the `/ssh` socket | an interactive shell on a customer device |

Reads and `DELETE /api/bindings/{id}` are never gated.

The refusal is **403 with a named body**, not a generic denial:

```json
{
  "error": "elevated access is required — sign in through Break-glass IdP",
  "code": "ELEVATION_REQUIRED",
  "elevation_providers": [{ "id": "okta-jit", "name": "Break-glass IdP" }]
}
```

The SPA turns that into a dialog with the sign-in button, from any screen.

**With no elevation connection configured, every one of these routes behaves
exactly as it did before.** The gate is additive by construction — otherwise
this release would have locked operators out of routes they administer today on
the strength of a feature they never configured.

---

## 6. Auditing a grant

Every audit row carries `binding_id` (the elevated grant in force when the
action ran, blank otherwise) and `session_id`. So "what did that grant actually
do" is one query:

```
GET /api/audit?binding_id=<id>
```

Tenant scoping is unchanged: the filter narrows, it never widens. A tenant admin
filtering by a binding id from another realm gets nothing.

The lifecycle events themselves are on the same trail, under
`/elevation/ELEVATION_GRANTED`, `/elevation/ELEVATION_EXPIRED` and
`/elevation/ELEVATION_REVOKED`.

---

## 7. Verifying it end to end

1. Sign in through the **standing** provider once, so the account exists.
2. Sign out. Sign in through the elevation door with an account the standing
   provider has never seen → on an unbound door expect the refusal naming the
   standing provider; on a tenant-bound door expect the generic realm refusal
   instead. Either way, **no** new account in the user store.
3. Sign in through the elevation door as the account from step 1 → the account
   menu shows *Elevated · &lt;role&gt; · N m left*.
4. Confirm the account's tenant and standing role are unchanged:

   ```sql
   select tenant_id, data->>'role', data->>'auth_source'
   from users where id = '<username>';
   ```

5. Open the elevated-only action. It should now succeed.
6. Wait for the expiry (or *End* in the account menu) and retry → the named 403
   is back, with no logout in between.
7. `GET /api/audit?binding_id=<id>` shows the grant and everything done under it.
