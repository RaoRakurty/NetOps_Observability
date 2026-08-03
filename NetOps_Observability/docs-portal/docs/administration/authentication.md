---
title: Authentication & SSO
sidebar_label: Authentication & SSO
sidebar_position: 3
description: Local accounts, SSO via OIDC, LDAP/Active Directory, TACACS+, MFA, and session behavior.
---

# Authentication & SSO

Correlix supports local accounts and your existing identity infrastructure, side by side. Configure it at <kbd>Administration → Authentication</kbd> — a tile per method, each opening a short guided form. Local accounts are always on, so an SSO outage can never lock you out.

| Tile | Use it for |
| --- | --- |
| **Local accounts** | Username + password held by Correlix — small teams and break‑glass. Always on. |
| **Single Sign-On** | Federate sign‑in to your **OIDC** identity provider (Okta, Azure AD, Google, …). |
| **LDAP / Active Directory** | Bind directly against your directory; groups map onto roles. |
| **TACACS+** | Authenticate operators against your existing AAA server. |

:::note SAML
There is no native SAML form. If your identity provider is SAML‑only, front it with an OIDC‑capable broker and connect Correlix to the broker via the Single Sign‑On tile. The bundled Keycloak service does exactly this — the **[Okta SSO step‑by‑step guide](/administration/okta-sso)** walks through the whole setup, including the Okta dashboard tile.
:::

Required fields are marked with a red asterisk, and every stored secret is **write‑only** — after saving it shows as `••••••`; leaving it blank on a later edit keeps the existing value.

## Local accounts & password policy

Accounts are managed under [Identity & Access → Users](/administration/identity-access#add-a-user). Policy knobs live in the per‑scope **Security Settings** tab (Provider, organization, or tenant). Defaults:

| Policy | Default |
| --- | --- |
| Minimum password length | 8 (also the hard floor — a scope can raise it, never lower it) |
| Character classes | lowercase, uppercase, digit and symbol all required |
| Password expiry | enabled, 90 days |
| Reuse | the new password must differ from the current one |
| Lockout | 3 failed attempts; auto‑unlocks after 15 minutes |

Users change their own password from the account menu → **Change password** (**Current password**, **New password**, **Confirm new password**, with a live strength meter and policy checklist). Changing a password **revokes all of that user's sessions**. Federated (SSO/LDAP) accounts change their password at the identity provider, not here.

## Multi‑factor authentication (MFA)

Local accounts can add a one‑time code from an authenticator app:

1. Open the account menu → **Two-factor authentication** and click **Enable two-factor**.
2. **Scan the QR code** with your authenticator app (a *Can't scan?* link reveals the manual entry key).
3. **Enter the 6‑digit code** it shows and click **Confirm & turn on**.

From then on, sign‑in asks for the password and then a code (the challenge is valid for 5 minutes). To turn it off, enter a current code and click **Turn off two-factor**. An admin can **reset two‑factor** for selected users from the Users page; federated accounts enroll MFA at their identity provider — for OIDC you can *require* it (below).

## Set up Single Sign‑On (OIDC)

1. In your identity provider, create an **OIDC web application** (Authorization Code flow) and register the redirect URI Correlix shows on the form: `https://<your-host>/api/auth/sso/callback`. Note the issuer URL, client ID and client secret.
2. In Correlix, open <kbd>Administration → Authentication</kbd> → **Single Sign-On**, tick **Enabled**, and complete the three steps:

**Step 1 — Connection**

| Field | Required | Notes |
| --- | --- | --- |
| **Issuer / Discovery URL** | Yes | Base issuer URL; `/.well-known/openid-configuration` is appended |
| **Client ID** | Yes | |
| **Client secret** | No | Write‑only; blank for a public client |
| **Scopes** | No | Defaults like `openid email profile` |

**Step 2 — Role mapping**

| Field | Notes |
| --- | --- |
| **Default role** | Role for signed‑in users with no mapped group |
| **Default tenant** | Tenant new federated users land in |
| **Admin roles** | Comma‑separated IdP roles/groups mapped to Super Admin |
| **Operator roles** | Comma‑separated IdP roles/groups mapped to Operator |
| **Require multi-factor authentication** | Reject sign‑ins your IdP didn't verify with a second factor |
| **MFA assurance values** | Optional — the assurance (`acr`/`amr`) values you accept as "MFA done" |

**Step 3 — Sign‑in & redirect** — the sign‑in **Providers** buttons shown on the login page, the **Post-login URL**, and an optional **Redirect URL override**.

3. Click **Save**, then test with a real IdP account. The tile's badge flips to **Enabled · Ready**.

## Set up LDAP / Active Directory

Open the **LDAP / Active Directory** tile, tick **Enabled**, and complete the three steps:

**Step 1 — Connection**

| Field | Required | Notes |
| --- | --- | --- |
| **Host** | Yes | e.g. `ldap.example.com` |
| **Port (0 = auto)** | No | Auto‑picks by encryption |
| **Encryption** | No | *None (389)* / *StartTLS* / *LDAPS (636)* — use StartTLS or LDAPS in production |
| **Bind DN (service acct)** | No | e.g. `cn=svc,dc=example,dc=com`; blank = anonymous bind |
| **Bind password** | No | Write‑only |
| **Base DN** | Yes | e.g. `dc=example,dc=com` |
| **Skip TLS verify (lab only)** | No | Never in production |

**Step 2 — Users & groups** — **User filter** *(required — `%s` is the username, e.g. `(uid=%s)` or `(sAMAccountName=%s)`)*, **Group base DN** (defaults to Base DN), **Group filter** (`%s` is the user DN, e.g. `(member=%s)`), **Default role**, **Default tenant**.

**Step 3 — Roles & test** — add **group DN → role** mapping rows with **+ Add mapping** (highest‑privilege match wins). Then enter a test username/password and click **Test connection** — the result shows each stage, the resolved DN, the user's groups, and the role that *would* be assigned. Click **Save**.

## Set up TACACS+

Open the **TACACS+** tile, tick **Enabled**:

**Step 1 — Connection** — **Host** *(required)*, **Port** (default 49), **Shared secret** (write‑only), **Timeout (s)** (default 5).

**Step 2 — Defaults & test** — **Default role**, **Default tenant**, then a test username/password and **Test connection**. Click **Save**.

## Sessions

Sign‑in issues a short‑lived access token (15 minutes by default) plus a rotating, single‑use refresh token — replaying an old refresh token revokes the whole session lineage. On top of that, server‑side limits apply:

| Limit | Default |
| --- | --- |
| Idle timeout | 30 minutes — set per scope in **Security Settings → "Sign out after inactivity (min)"** (minimum 5) |
| Maximum session lifetime | 12 hours — a fixed platform standard, deliberately not a UI knob |
| Concurrent sessions per user | 5 — the oldest is evicted past that |

Per‑role policy can *shorten* these windows, never lengthen them. Changing a password revokes all of the user's sessions.

**Live session control:** <kbd>Administration → Sessions</kbd> (visible to platform operators only) lists live sign‑ins — **Person · Tenant · IP · Status · Started · Last activity · Idle** — with a per‑row **Revoke** that signs that person out immediately.

:::note Break-glass
Platform operators have a separate, fully audited emergency‑access mechanism: a time‑boxed grant (60 minutes by default, 8 hours max) that requires a written reason and self‑expires. It's for incident response into restricted tenants — not a hidden password.
:::

## Verify

- The provider tile shows **Enabled** (and, for SSO, **Ready**); the **Active** count on the stat strip increments.
- For LDAP/TACACS+, **Test connection** returns OK with the expected role before you rely on it.
- A real test login appears in the **Audit Log** and lands with the mapped role and tenant.

## Troubleshooting

- **SSO sign‑in loops or errors** — the redirect URI at the IdP must match `…/api/auth/sso/callback` exactly, and the issuer must be the *base* URL (Correlix appends the discovery path).
- **Directory user gets the wrong role** — mappings are highest‑privilege‑wins; check the test result's group list against your mapping rows.
- **Locked out after failed attempts** — wait for the auto‑unlock (15 minutes by default) or have an admin intervene; local admin sign‑in keeps working even if a provider is down.
- **"password is managed by your identity provider"** — the account is federated; change it at the IdP.
