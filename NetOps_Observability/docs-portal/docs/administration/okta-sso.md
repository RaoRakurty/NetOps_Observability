---
title: "Okta SSO — step by step"
sidebar_label: "Okta SSO (guide)"
sidebar_position: 3.5
description: Self-guided Okta integration — SAML or OIDC through the bundled Keycloak broker, role mapping, dashboard launch tiles, and a test checklist.
---

# Okta SSO — step by step

This guide takes you from nothing to **"click Correlix in Okta, land signed-in"** using the bundled Keycloak broker. Every step lists its **mandatory fields**, ends with a **verify** check so you always know where you are, and the [troubleshooting table](#troubleshooting) maps every error we have seen in real bring-ups to its fix. Okta is the worked example; any SAML/OIDC identity provider follows the same shape.

What you get when you finish:

| Capability | How it works |
| --- | --- |
| **Sign in with Okta** from the Correlix login page | SP-initiated: Correlix → Keycloak → Okta → back, signed in |
| **Okta dashboard launch** — the Correlix tile in Okta | An Okta Bookmark app opens Correlix's SSO launch URL; because your Okta session already exists, it completes with no prompts |
| Automatic account creation with the **right role and tenant** | Okta groups map to Correlix roles; users are created on first sign-in |

:::note Terminology
The tile experience is **"Okta dashboard launch"** (a Bookmark-based, Correlix-initiated flow) — not native unsolicited IdP-initiated SAML, which Correlix deliberately does not accept. Same one-click experience for the user, with full CSRF/replay protection retained.
:::

The architecture, in one line — Okta speaks SAML (or OIDC) to Keycloak; Correlix only ever speaks OIDC to Keycloak:

```text
Okta ──SAML or OIDC──▶ Keycloak (broker) ──OIDC──▶ Correlix ──▶ its own session
```

---

## Before you begin

Work through this checklist first — each item prevents a dead end later.

| # | Prerequisite | Why |
| --- | --- | --- |
| 1 | **Correlix reachable over HTTPS** | Browsers reject Keycloak's cross-site SSO cookies over plain HTTP. HTTP labs work only in a normal browser window; **incognito/strict browsers hard-require HTTPS**. Production must be HTTPS. |
| 2 | **Okta admin access** to your org (e.g. `yourorg-admin.okta.com`) | You will create two or three app integrations |
| 3 | **Correlix platform-admin sign-in** | Only the platform admin can configure authentication — a tenant admin cannot (by design) |
| 4 | **A local admin account you will never federate** | Break-glass: if SSO breaks, this is how you get back in. Never point SSO at your last local admin |
| 5 | Decide the **target tenant** for Okta users | All users of one provider config land in one tenant (its ID, e.g. `t_0…`, from <kbd>Administration → Tenants</kbd>) |

Throughout this guide, replace `correlix.example.com` with your host. Collect these as you go:

| Value | You get it from | Example |
| --- | --- | --- |
| Correlix base URL | your deployment | `https://correlix.example.com` |
| Keycloak realm | you create it (Phase 1) | `correlix` |
| Keycloak client ID / secret | you create it (Phase 1) | `netops` / *(secret)* |
| Okta metadata URL | Okta app (Phase 2) | *(per app)* |

---

## Phase 1 — Bring up Keycloak

Keycloak ships with Correlix but is **opt-in**.

1. In `deployment/docker/.env`, add `sso` to `COMPOSE_PROFILES` (comma-separated).
2. Re-run the installer — it creates Keycloak's database and starts the service:

   ```bash
   python3 scripts/install.py
   ```

3. Open the Keycloak admin console at `https://correlix.example.com/auth/` and sign in with `KEYCLOAK_ADMIN` / `KEYCLOAK_ADMIN_PASSWORD` from `.env`.
4. Create a **realm** (example: `correlix`).
5. In that realm, create an **OpenID Connect client** for Correlix:

   | Field | Required | Value |
   | --- | --- | --- |
   | **Client ID** | Yes | `netops` |
   | **Client authentication** | Yes | On (confidential) |
   | **Valid redirect URIs** | Yes | `https://correlix.example.com/api/auth/sso/callback` |
   | **Web origins** | Recommended | `https://correlix.example.com` |

6. Copy the **client secret** from the client's *Credentials* tab.

**Verify:** `https://correlix.example.com/auth/realms/correlix/.well-known/openid-configuration` returns JSON whose `issuer` is exactly `https://correlix.example.com/auth/realms/correlix`. That issuer string is used twice later — scheme and host must match character-for-character.

---

## Phase 2 — Create the Okta SAML app

In the Okta admin console: <kbd>Applications → Applications → Create App Integration → SAML 2.0</kbd>. Name it something operators will recognize as plumbing, e.g. *Correlix (SAML via Keycloak)*.

**Mandatory SAML settings:**

| Okta field | Value |
| --- | --- |
| **Single sign-on URL (ACS)** | `https://correlix.example.com/auth/realms/correlix/broker/okta-saml/endpoint` |
| **Audience URI (SP Entity ID)** | `https://correlix.example.com/auth/realms/correlix` — the **realm** URL, *not* the broker endpoint |
| **Name ID format** | EmailAddress (or Persistent) |
| **Application username** | Email |

**Attribute statements** (names matter — Keycloak maps them in Phase 3):

| Name | Value |
| --- | --- |
| `email` | `user.email` |
| `firstName` | `user.firstName` |
| `lastName` | `user.lastName` |

**Group attribute statement** (needed for role mapping in Phase 5): name `groups`, filter matching the groups you'll map (e.g. *Starts with* `correlix-`).

Then: **Assignments** → assign the users/groups who may sign in, and on the app's *Sign On* tab copy the **SAML metadata URL**.

:::tip Hide this tile
This app is Okta↔Keycloak plumbing — its dashboard tile performs unsolicited IdP-initiated SAML, which Correlix does not accept, so clicking it can only produce an error. On the app's *General* tab check **"Do not display application icon to users"**. The user-facing tile is the Bookmark app in Phase 7.
:::

**Verify:** the metadata URL downloads XML in a browser.

---

## Phase 3 — Register Okta as an identity provider in Keycloak

In the Keycloak admin console, realm `correlix`:

1. <kbd>Identity Providers → Add provider → SAML v2.0</kbd>. Set **Alias** to `okta-saml` — the alias is part of the ACS URL you registered in Phase 2, so it must match exactly.
2. In **Service provider entity ID**, keep/confirm `https://correlix.example.com/auth/realms/correlix` — it must equal the **Audience URI** you set in Okta. *(This value is pinned here; it does not follow your URL automatically. If you ever change host or scheme, update both sides — a mismatch shows as Okta's "Bad SAML request".)*
3. Import the Okta app's **metadata URL** from Phase 2 (fills the SSO URL and signing certificate).
4. Add three **mappers** (type *Attribute Importer*): `email` → `email`, `firstName` → `firstName`, `lastName` → `lastName`.

**Verify:** from an incognito window, `https://correlix.example.com/auth/realms/correlix/protocol/openid-connect/auth?client_id=netops&response_type=code&scope=openid&kc_idp_hint=okta-saml&state=test&redirect_uri=https%3A%2F%2Fcorrelix.example.com%2Fapi%2Fauth%2Fsso%2Fcallback` should land on the **Okta sign-in page** (don't sign in yet).

---

## Phase 4 — Optional: the OIDC variant

If you prefer OIDC end-to-end (or want both, side by side):

1. Okta: <kbd>Create App Integration → OIDC → Web Application</kbd>. Mandatory: **Sign-in redirect URI** = `https://correlix.example.com/auth/realms/correlix/broker/okta-oidc/endpoint`. Copy client ID + secret.
2. Keycloak: <kbd>Identity Providers → Add provider → OpenID Connect v1.0</kbd>, alias `okta-oidc`, discovery URL `https://yourorg.okta.com/.well-known/openid-configuration`, paste client ID + secret. Add the same three mappers.

:::caution OIDC needs outbound network access
SAML brokering is entirely front-channel (browser-carried). The OIDC broker flow requires **Keycloak → Okta back-channel access** (token exchange). In egress-restricted networks SAML works where OIDC fails — and the OIDC failure appears only *after* the user has entered credentials and MFA (`SocketTimeoutException` in Keycloak's log). Prefer SAML for locked-down deployments.
:::

---

## Phase 5 — Role mapping (the step everyone gets wrong)

Correlix reads roles from the **ID token**'s `realm_access.roles` and `groups` claims and matches them against its configured role lists. Two ways to feed it:

**Recommended — Okta group → Keycloak role (scales):** create Okta groups (e.g. `correlix-admins`, `correlix-operators`), include them in the Phase-2 group attribute, and in the Keycloak IdP add an *Advanced Attribute to Role* mapper per group: attribute `groups` = `correlix-admins` → realm role `netops-admin` (create the realm roles first).

**Quick lab variant:** grant a realm role (e.g. `netops-admin`) directly to the Keycloak user after their first login.

:::caution The invisible-role trap
Keycloak's built-in realm-roles mapper puts roles in the **access token only** by default — Correlix reads the **ID token**, so the role never arrives and every user lands as read-only *while every screen you check looks correctly configured*. Fix once per realm: <kbd>Client scopes → roles → Mappers → realm roles</kbd> → turn **"Add to ID token"** ON.
:::

The role names must appear in Correlix's **Admin roles** / **Operator roles** lists (Phase 6) — defaults include `netops-admin` and `netops-operator`.

---

## Phase 6 — Configure Correlix

Sign in to Correlix as the **platform admin** → <kbd>Administration → Authentication</kbd> → **Single Sign-On** tile → **Enabled**.

| Field | Required | Value |
| --- | --- | --- |
| **Issuer** | Yes | `https://correlix.example.com/auth/realms/correlix` — exactly the Phase-1 issuer |
| **Client ID** | Yes | `netops` |
| **Client secret** | Yes (confidential client) | from Phase 1 — write-only after saving |
| **Providers** | Recommended | `okta-saml:Okta:saml` (add `,okta-oidc:Okta OIDC:oidc` if you did Phase 4) — one login-page button per entry, and **only aliases listed here are accepted** on the launch URL |
| **Default tenant** | Yes | the tenant ID from *Before you begin* |
| **Default role** | Yes | role for users matching no mapping (default `read-only`) |
| **Admin / Operator roles** | Yes | must contain the role names from Phase 5 |

Click **Save** — the tile shows **Enabled · Ready**.

:::note The `OIDC_*` variables in `.env` are a first-boot seed only
Once a configuration has been saved from this page, the saved config **wins over the environment**. Editing `.env` afterward does nothing — change it here.
:::

**Verify:** log out. The login page shows the **Okta** button; clicking it lands on Okta's sign-in page; signing in returns you to Correlix. Check the new account under <kbd>Administration → Identity & Access → Users</kbd>: correct email, **correct tenant**, **correct role**.

---

## Phase 7 — The Correlix tile in Okta (dashboard launch)

1. Okta admin: <kbd>Applications → Create App Integration → Bookmark App</kbd> (search "Bookmark" in the catalog).
2. **URL**: `https://correlix.example.com/api/auth/sso/login?idp=okta-saml` *(use `?idp=okta-oidc` for the OIDC variant)*.
3. Name it **Correlix**, upload the Correlix logo, and assign the **same users/groups** as the Phase-2 app.

**Verify:** on the Okta **end-user** dashboard, the Correlix tile appears; clicking it lands you in Correlix with no prompts (your Okta session already exists).

---

## Test checklist

Run all of these before calling it done — each proves a different link:

| # | Test | Proves |
| --- | --- | --- |
| 1 | Login page → **Okta** button → sign in | SP-initiated end to end |
| 2 | Okta dashboard → **Correlix** tile | Dashboard launch |
| 3 | User with an admin-mapped group lands as **Super Admin**; user without lands as the default role | Role mapping, both directions |
| 4 | New user's **tenant** is the intended one | Tenant assignment |
| 5 | An Okta user **not assigned** to the app is refused by Okta | Assignment gating |
| 6 | Repeat 1–2 in an **incognito window** (HTTPS deployments) | Customer-shaped browsers work |
| 7 | Your **local admin** still signs in with a password | Break-glass intact |

---

## Troubleshooting

Every entry below comes from a real bring-up.

| Symptom | Cause | Fix |
| --- | --- | --- |
| Keycloak container restarts forever; log says `FATAL: database "keycloak" does not exist` | The `sso` profile was enabled by hand without creating the DB | Re-run `python3 scripts/install.py` (it creates the DB), or `docker compose exec postgres createdb -U $DB_USER keycloak` |
| Okta: **"Bad SAML request"** | Audience URI ≠ Keycloak's SP entity ID (often after a host/scheme change — the entity ID is pinned in the Keycloak IdP config) | Make Okta's **Audience URI** and Keycloak's **Service provider entity ID** identical: `https://<host>/auth/realms/<realm>` |
| Okta: `The 'redirect_uri' parameter must be a Login redirect URI…` | OIDC variant: broker redirect URI not registered in the Okta app | Add `https://<host>/auth/realms/<realm>/broker/okta-oidc/endpoint` to the app's Sign-in redirect URIs |
| Keycloak error page **after** Okta sign-in; Keycloak log: `cookie_not_found` | Plain-HTTP deployment + a browser blocking third-party cookies (incognito default) — Keycloak's `Secure` cookies can't exist over HTTP | Serve Correlix over **HTTPS**. On HTTP labs, test in a normal window only |
| **502 Bad Gateway** on the Keycloak page, only for fresh/incognito visitors; nginx log: `upstream sent too big header` | Keycloak's cookie-less first response overflows small proxy buffers | Shipped Correlix nginx config ≥ 2026-08 has 16k buffers on `/auth/`; if you customized nginx, add `proxy_buffer_size 16k; proxy_buffers 8 16k;` |
| User signs in but has the wrong (read-only) role; all config *looks* right | Realm roles go to the access token only; Correlix reads the **ID token** | Phase 5's fix: realm-roles mapper → **"Add to ID token" ON** — then check the role name is listed in Correlix's Admin/Operator roles |
| Keycloak page: **"User already exists"** mid-login | Same email arriving from a second IdP (e.g. you set up both SAML and OIDC) — Keycloak wants explicit account linking | Complete the link once per user, or enable an auto-link first-login flow for trusted IdPs, or use one IdP per user population |
| Okta sign-in works, then Keycloak times out (OIDC variant); Keycloak log: `SocketTimeoutException` | No Keycloak→Okta back-channel egress | Allow outbound 443 to your Okta org from the Keycloak container, or use the SAML variant |
| Clicking the **SAML app's own tile** (not the Bookmark) errors with `invalid_redirect_uri` | That is unsolicited IdP-initiated SAML, which Correlix does not accept by design | Use the Bookmark tile (Phase 7); hide the SAML app's tile (Phase 2 tip) |
| Edited `OIDC_*` in `.env` but nothing changed | A saved UI configuration overrides the environment | Change it at <kbd>Administration → Authentication</kbd> |

Related: [Authentication & SSO](/administration/authentication) for the form reference, LDAP/TACACS+, MFA, and session policy.
