---
title: Mint an API key
sidebar_label: API access
description: Generate a scoped, tenant-bound credential for a script or pipeline, and call the REST API with it.
page_type: task
sidebar_position: 6
---

# Mint an API key

Everything the console does goes through the REST API, so anything you can select, you can script. An API key is a long-lived, tenant-bound credential for machine clients such as CI pipelines, exporters and integrations. It carries no password and no MFA prompt.

## Before you begin

- **Permission:** `administration:admin`. API keys are per-tenant data. A tenant administrator sees and mints only their own tenant's keys, and a key created by a non-cross-tenant caller is stamped with that caller's tenant regardless of what the request body says.
- **Token policy is different.** **Administration → API Access → Token Policy** governs interactive session tokens platform-wide and calls `requirePlatformAdmin`. See [Configure authentication](/administration/authentication).
- Decide the scopes the client needs. A key can never exceed them.
- Have a secret manager ready. The secret is displayed once and is never retrievable afterwards.

## Steps

### Generate an API key {#generate-an-api-key}

1. Open **Administration → API Access** and select **Generate API key**.
2. Enter a **Label**. It is required, and it is how you will recognise the key later, for example `ci-pipeline`.
3. Optionally set **Rate limit / min**. Blank inherits the server default of 600 requests per minute, and `0` means unlimited.
4. Select the scopes:

   | Scope | Allows |
   | --- | --- |
   | `read:metrics` | Read metric data. The default selection. |
   | `read:alerts` | Read alerts. |
   | `read:devices` | Read the device inventory. |
   | `read:flows` | Read flow data. |
   | `read:*` | Read everything the tenant can see. |
   | `write:incidents` | Write incident operations. |

5. Select the grant types. `client_credentials` is the default and is the key authenticating as itself. `authorization_code` and `refresh_token` are also accepted. The `password` grant is refused, because RFC 9700 deprecates it.
6. Optionally set **Client URL**, **Logo URL** and **Allowed source IP / CIDR**. The source list is a comma-separated set of CIDRs, and a request from anywhere else is refused with `403` before the key is authenticated at all. Blank means any source.
7. Optionally set **Client expires on** and **Secret expires on**, and the contact email and phone that record ownership. Blank means no expiry.
8. Select **Generate key**.

The response returns the record and the plaintext secret exactly once:

```json
{
  "key": { "id": "34ba05aac2ab", "label": "ci-pipeline", "prefix": "ntk_34ba05…", "…": "…" },
  "secret": "ntk_<shown once, copy it now>"
}
```

Correlix stores only a SHA-256 hash of the secret. There is no way to display it again, and no support path that can recover it. If it is lost, revoke the key and mint another.

### Use the key

Both header forms are accepted and are equivalent.

```bash
curl -s -H "Authorization: Bearer ntk_YOUR_KEY" https://<your-host>/api/devices
curl -s -H "X-API-Key: ntk_YOUR_KEY"            https://<your-host>/api/devices
```

### Read the key inventory

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/api/apikeys
```

```json
[
  {
    "id": "34ba05aac2ab",
    "tenant_id": "global",
    "label": "ADMIN-API-KEY",
    "prefix": "ntk_34ba05…",
    "scopes": [
      "read:metrics",
      "read:alerts",
      "read:devices",
      "read:flows",
      "read:*",
      "write:incidents"
    ],
    "rate_limit_per_min": 600,
    "use_count": 0,
    "window_used": 0,
    "created_by": "admin",
    "created_at": "2026-09-03T02:54:29.818430265Z",
    "grant_types": [
      "client_credentials",
      "authorization_code"
    ]
  }
]
```

The list never carries the hash and never carries the secret. `prefix` is the masked display form, which is `ntk_` plus the first six characters. `use_count` is the lifetime count of authenticated calls, and `window_used` is how many calls the key has made in the current minute, so the console can show how close it is to its cap. A key that has been used also carries `last_used_at`, and a revoked key carries `revoked_at`.

## How a key behaves

- **Scope-bound.** The key's effective role is derived from its scopes. It is read-only unless it holds a `write:` scope, which grants operator-level write; `admin:*` grants super-admin. A key can never exceed what its scopes describe.
- **Tenant-bound.** The key acts inside its own tenant. A `200 OK` with an empty result means the key's tenant owns nothing matching, not that the query was wrong.
- **Rate-limited.** The cap is a fixed window per minute. Over the cap the API answers `429` with a `Retry-After` header and the message `API key rate limit exceeded`.
- **Source-restricted.** With `source_cidrs` set, a call from another address is refused with `403` before authentication.
- **Expiring and revocable.** Past either expiry the key is refused. **Revoke** disables it immediately and keeps the record for audit.
- **Suspension-aware.** If the owning tenant is [suspended](/administration/tenants-orgs#suspend-a-tenant), its keys are refused on every request with `403 tenant suspended`.
- **Deleting a key you cannot see returns `404`.** Cross-tenant key ids are never confirmed.

## Sign in as a person instead

A script can also sign in the way an operator does and use the returned bearer token. The capture below is real, from the lab stack, with both token values replaced by placeholders.

```bash
curl -s -X POST http://localhost:8000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "…"}'
```

```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.<redacted>",
  "refresh_token": "<redacted>",
  "expires_in": 3600,
  "user": {
    "username": "admin",
    "role": "admin",
    "auth_source": "local",
    "mfa_enabled": false,
    "created_at": "2026-08-16T17:16:58.129878023Z",
    "last_login_at": "2026-09-03T04:38:56.933945193Z"
  }
}
```

The access token is the `token` field. There is no `access_token` field. `expires_in` is the access token's lifetime in seconds, and it reads `3600` above because that deployment raised the token policy from the shipped default of 900.

Rotate it before it expires:

```bash
curl -s -X POST http://localhost:8000/api/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{"refresh_token": "<the refresh token from the login>"}'
```

The response is a fresh token pair. Refresh tokens are single-use, so the old one is dead the moment the new pair is issued, and replaying it revokes the whole session lineage.

If the account has MFA enrolled, the login returns `{"mfa_required": true, "mfa_token": "…"}` instead of a session, and the code is completed at `POST /api/auth/mfa/login` within 5 minutes. For unattended automation, use an API key rather than this flow.

## The generated REST reference

**Administration → API Access → REST API Reference** renders the specification produced by the running API, so it always matches the deployment you are looking at. The raw document imports into Postman or any OpenAPI client:

```bash
curl -s http://localhost:8000/api/openapi.json
```

The same route set is published as [API reference](/reference/api).

## Result

The new key appears in the keys table as active. A test call returns your tenant's data and the key's **Last used** column updates. After **Revoke**, the same call returns `401 invalid or revoked API key` and the row reads revoked. Every call the key makes is authorized and audited exactly like a console action, under the actor `apikey:<id>`.

## Related

- [Add users and grant access](/administration/identity-access) for the `api-client` role and the permission grid.
- [Create tenants and organizations](/administration/tenants-orgs) for how suspension disables a tenant's keys.
- [Read the audit log](/administration/audit-log) to see what a key did.
- [API reference](/reference/api) for the route set.
