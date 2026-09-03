---
title: Configure authentication
sidebar_label: Authentication
description: Set the password, lockout and session policy for a scope, and connect OIDC, LDAP or TACACS+ alongside local accounts.
page_type: task
sidebar_position: 4
---

# Configure authentication

Correlix authenticates locally and against your existing identity infrastructure at the same time. Local accounts are always available, so an outage at an identity provider cannot lock every administrator out. This page sets the policy that governs local accounts, then connects an external provider.

## Before you begin

- **Permission, provider configuration:** platform administrator. Authentication providers are platform-global plumbing. `GET` and `PUT` on `/api/auth/oidc/config`, `/api/auth/ldap/config`, `/api/auth/tacacs/config` and `/api/auth/token-policy` all call `requirePlatformAdmin`, and the console hides **Administration → Platform Security → Authentication** from a tenant administrator for the same reason.
- **Permission, security policy:** `administration:admin` plus reach over the scope you are editing. `/api/security-settings?scope=<tenant>` accepts the platform administrator or an administrator who reaches that tenant. The `provider` scope is platform administrator only.
- Keep one local administrator account that is never federated. It is the way back in when single sign-on breaks.
- For OIDC, have the issuer URL, client id and client secret ready. Correlix appends `/.well-known/openid-configuration` to the issuer, so register the base URL.

## Steps

### Set the password, lockout and session policy

Policy is per scope: the Provider realm, an organization, or one tenant. Open **Administration → Identity & Access → (scope) → Security Settings**.

The shipped defaults:

| Setting | Field | Default |
| --- | --- | --- |
| Minimum password length | `min_password_length` | 8 |
| Character classes | `require_uppercase`, `require_lowercase`, `require_number`, `require_special` | All four required |
| Password expiry | `password_expire_enabled`, `password_expire_days` | Enabled, 90 days |
| Password history | `password_history` | Off. When enabled, the last 5 hashes are checked. |
| Failed sign-ins before lockout | `login_attempts_allowed` | 3 |
| Lockout duration | `unlock_time_seconds` | 900 seconds, which is 15 minutes |
| Account validity | `account_validity_days` | 180 days |
| Inactivity cutoff | `account_inactivity_days` | 90 days |
| Concurrent sign-in | `concurrent_login` | `allow` |
| Idle timeout | `idle_timeout_minutes` | 30 minutes, floor 5 |
| Absolute session lifetime | `absolute_timeout_minutes` | 720 minutes, which is 12 hours |

Two facts the form does not state. On save, `min_password_length` is clamped to a floor of **4**, not 8, so a scope can be set below the shipped default. `login_attempts_allowed` is clamped to a floor of 1, and a value of 0 or less disables lockout entirely.

A new password must always differ from the current one, whether or not history is enabled. Changing a password revokes every session that user holds, and the response says whether the revocation persisted:

```json
{"status":"ok","sessions_revoked":true}
```

A `sessions_revoked` of `false` means the password did change and the revocation was not written durably, so old sessions may survive a restart. It is reported rather than hidden behind a `500` that would wrongly say the password change failed.

### Understand the lockout

Lockout counts consecutive failed sign-ins per account and is enforced before the password is checked, so a locked account cannot be guessed at. A locked sign-in answers `429` with a `Retry-After` header and the message `account temporarily locked due to failed sign-ins; try again later`. A successful sign-in clears the counter.

The counter is in memory and process-local. It resets when the API restarts, and it is not shared between API replicas. Under a username-spraying attack that fills the tracker with live locks, new sign-ins are refused with `429` and the message `sign-in temporarily unavailable due to failed-login pressure` rather than being silently untracked. Refusing loudly is deliberate: an uncounted failure is an unlimited guess.

### Enrol multi-factor authentication

A local account adds a time-based one-time code from an authenticator application.

1. Open the account menu, then **Two-factor authentication**.
2. Select **Enable two-factor**.
3. Scan the QR code. A **Can't scan?** link reveals the manual entry key.
4. Enter the 6-digit code and select **Confirm & turn on**.

From then on, sign-in returns `{"mfa_required": true, "mfa_token": "…"}` instead of a session, and the code is completed at `POST /api/auth/mfa/login`. The challenge is valid for 5 minutes. An administrator can reset two-factor for a user from the Users page. A federated account enrols at its identity provider instead.

### Connect an OIDC identity provider

1. At the identity provider, create an OIDC web application using the authorization-code flow, and register the redirect URI `https://<your-host>/api/auth/sso/callback`.
2. In Correlix, open **Administration → Platform Security → Authentication**, open the **Single Sign-On** tile and tick **Enabled**.
3. Complete the connection fields:

   | Field | Required | Notes |
   | --- | --- | --- |
   | **Issuer / Discovery URL** | Yes | The base issuer URL. The discovery path is appended. |
   | **Client ID** | Yes | |
   | **Client secret** | No | Write-only. Leave blank for a public client. |
   | **Scopes** | No | Defaults to `openid email profile`. |

4. Complete the role mapping: **Default role**, **Default tenant**, **Admin roles** and **Operator roles**. Correlix reads roles from the ID token's `realm_access.roles` and `groups` claims and matches them against these lists.
5. Optionally require multi-factor authentication and name the assurance values you accept.
6. Set the sign-in **Providers** buttons, the **Post-login URL** and any redirect override.
7. Select **Save**, then sign in with a real account from the provider.

There is no native SAML form. Correlix speaks OIDC to a broker, and the broker speaks SAML to the provider. The bundled Keycloak service is that broker. [Connect Okta as an identity provider](/administration/okta-sso) is the worked bring-up.

Environment variables prefixed `OIDC_` are a first-boot seed only. Once a configuration has been saved from this page, the saved configuration wins and editing the environment changes nothing.

### Connect LDAP or Active Directory

1. Open the **LDAP / Active Directory** tile and tick **Enabled**.
2. Enter **Host**, and set **Encryption** to StartTLS or LDAPS in production. Leave **Port** at 0 to pick the port from the encryption choice.
3. Enter the **Bind DN** and **Bind password** for the service account, or leave both blank for an anonymous bind. The password is write-only.
4. Enter the **Base DN**.
5. Enter the **User filter**, where `%s` is the username, for example `(uid=%s)` or `(sAMAccountName=%s)`. Add the **Group base DN** and **Group filter** if groups drive roles.
6. Add group-DN to role mapping rows. The highest-privilege match wins.
7. Enter a test username and password and select **Test connection**. The result names each stage, the resolved DN, the user's groups, and the role that would be assigned.
8. Select **Save**.

### Connect TACACS+

1. Open the **TACACS+** tile and tick **Enabled**.
2. Enter **Host**, **Port** (49 by default), the write-only **Shared secret**, and **Timeout** in seconds (5 by default).
3. Set **Default role** and **Default tenant**.
4. Run **Test connection**, then select **Save**.

A disabled provider answers its test with the stage `config` and the message `TACACS+ is not enabled`, rather than a connection error.

### Set the token policy

**Administration → API Access → Token Policy** governs interactive session tokens platform-wide. It is platform administrator only.

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/api/auth/token-policy
```

```json
{
  "access_ttl_seconds": 3600,
  "refresh_ttl_seconds": 604800,
  "bounds": {
    "access_min_seconds": 60,
    "access_max_seconds": 86400,
    "access_recommended_seconds": 3600,
    "refresh_min_seconds": 300,
    "refresh_max_seconds": 7776000,
    "refresh_recommended_seconds": 2592000
  }
}
```

The shipped defaults are 15 minutes for the access token and 7 days for the refresh token. The capture above is from a deployment that raised the access token to one hour. A value outside `bounds` is clamped on save rather than rejected. Refresh tokens are single-use and rotating: replaying an old refresh token revokes the whole session lineage.

Session limits sit on top of the token lifetimes. A user holds at most 5 concurrent sessions, and the oldest is evicted past that. Setting `concurrent_login` to `deny` on the scope revokes a user's prior sessions when they sign in, so the newest sign-in wins rather than the new one being refused.

## Result

The tile shows **Enabled**, and for single sign-on also **Ready**. `GET /api/auth/methods` reports which sign-in options the login page renders, and a real test sign-in lands with the mapped role and the mapped tenant. The sign-in appears in the [audit log](/administration/audit-log).

## Related

- [Connect Okta as an identity provider](/administration/okta-sso) for the end-to-end broker setup.
- [Add users and grant access](/administration/identity-access) for accounts and roles.
- [Mint an API key](/administration/api-access) for unattended clients, which skip passwords and MFA entirely.
- [Troubleshooting](/reference/troubleshooting#sign-in-problems) for sign-in symptoms.
