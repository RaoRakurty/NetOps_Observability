---
title: API access
sidebar_label: API access
sidebar_position: 6
description: Generate API keys, set token policy, and use the REST API.
---

# API access

Everything the console does goes through the REST API, so anything you can click, you can script. <kbd>Administration → API Access</kbd> is where you mint machine credentials, tune token lifetimes, and browse the live API reference. The page shows a stat strip (**Keys · Active · Revoked · Rate-limited**) and three tiles: **Generate API key**, **Token Policy**, and **REST API Reference**.

## Generate an API key {#generate-an-api-key}

An API key is a long‑lived, scoped credential for machine clients (CI pipelines, exporters, integrations). Keys are tenant‑scoped and can never exceed the scopes you give them.

1. Go to <kbd>Administration → API Access</kbd> → **Generate API key** (or click **+ Generate key** above the keys table).
2. **Step 1 — Identity**: enter a **Label** *(required, e.g. `ci-pipeline`)* and optionally a **Rate limit / min** (blank inherits the default of 600 requests/minute; `0` means unlimited).
3. **Step 2 — Scopes & grant**: pick the scopes the key may use, and the grant types:

   | Scope | Allows |
   | --- | --- |
   | `read:metrics` | Read metric data (the default) |
   | `read:alerts` | Read alerts |
   | `read:devices` | Read the device inventory |
   | `read:flows` | Read flow data |
   | `read:*` | Read everything the tenant can see |
   | `write:incidents` | Write incident operations |

   Grant types: `client_credentials` (default — the key itself authenticates), `authorization_code`, `refresh_token`.
4. **Step 3 — Client & network**: optional **Client URL**, **Logo URL**, and **Allowed source IP / CIDR** — a comma‑separated allowlist; requests from anywhere else are refused. Blank = any source.
5. **Step 4 — Expiry & contacts**: optional **Client expires on** and **Secret expires on** dates (blank = never), plus **Contact email** / **Contact phone** for ownership.
6. Click **Generate key**. The secret (an `ntk_…` value) is displayed **once**, in a green banner: *"Copy it now — it won't be shown again."* Store it in your secret manager; Correlix keeps only a hash.

Use the key on requests as either header:

```bash
curl -H "Authorization: Bearer ntk_YOUR_KEY" https://<your-host>/api/devices
# or equivalently
curl -H "X-API-Key: ntk_YOUR_KEY" https://<your-host>/api/devices
```

### How keys behave

- **Scope‑bound**: a key's effective role is derived from its scopes — read‑only unless it holds a `write:*` scope. It acts within its own tenant only.
- **Rate‑limited**: per‑key requests/minute; over the cap the API returns `429` with a `Retry-After` header. The keys table shows live usage and turns amber at 80% of the cap.
- **Expiring & revocable**: past either expiry date the key is refused; **Revoke** (per row in the keys table) disables it immediately while keeping the record for audit.
- **Suspension‑aware**: if the owning tenant is [suspended](/administration/tenants-orgs#suspend-a-tenant), its keys stop working instantly.

The **API keys** table lists every key: **Label · Client ID · Scopes · Grant types · Source CIDRs · Rate/min · Usage · Created · Expires · Last used · Status**, plus the **Revoke** action.

## Token Policy

**Token Policy** governs *interactive* session tokens platform‑wide:

| Knob | Default | Bounds |
| --- | --- | --- |
| **Access token TTL (minutes)** | 15 | 1 minute – 24 hours (≤ 60 min recommended) |
| **Refresh token TTL (days)** | 7 | 5 minutes – 90 days (≤ 30 days recommended) |

Out‑of‑range values are clamped to the safe bounds on save (**Save policy**). The read‑only rows remind you of the fixed behavior: refresh tokens are single‑use with reuse detection — replaying an old refresh token revokes the whole session lineage.

## REST API Reference

**REST API Reference** renders the live, generated API specification — every endpoint, grouped by area, with its method and path. It is generated from the running API, so it is always current. The `openapi.json` link opens the raw spec, which you can import straight into Postman or any OpenAPI‑aware client:

```
GET https://<your-host>/api/openapi.json
```

## Programmatic access without an API key

Scripts can also sign in exactly like a person and use the returned bearer token. Worked example:

```bash
# 1. Sign in — returns a short-lived access token + a rotating refresh token
curl -s -X POST https://<your-host>/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "YOUR_USER", "password": "YOUR_PASSWORD"}'
# → {"token":"…","refresh_token":"…","expires_in":900,"user":{…}}

# 2. Call the API with the access token
curl -s https://<your-host>/api/devices \
  -H "Authorization: Bearer ACCESS_TOKEN_FROM_STEP_1"

# 3. When the access token expires (default 15 min), rotate the refresh token
curl -s -X POST https://<your-host>/api/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{"refresh_token": "REFRESH_TOKEN_FROM_STEP_1"}'
# → a fresh {"token":…, "refresh_token":…} pair; the old refresh token is now dead
```

Notes:

- The access token is the `token` field; pass it as `Authorization: Bearer …`.
- If the account has MFA enrolled, login instead returns `{"mfa_required": true, "mfa_token": "…"}` — complete it at `POST /api/auth/mfa/login` with the 6‑digit code. For unattended automation, prefer an API key: no password, no MFA prompt, no refresh dance.
- Every API call is authorized and audited exactly like the UI — same roles, same tenant isolation, same [Audit Log](/administration/overview#the-audit-log).

## Verify

- After generating a key, it appears in the table as **active**; a test `curl` against `/api/devices` returns your tenant's devices and the key's **Last used** timestamp updates.
- After revoking, the same call returns `401` and the row shows **revoked**.
- API activity shows in the Audit Log with the key as the actor.

## Troubleshooting

| Symptom | Likely cause |
| --- | --- |
| `401 Unauthorized` | Wrong/expired/revoked key or token; check the key's **Status** and **Expires** columns |
| `403 Forbidden` | The key lacks the needed scope (e.g. writing with a read‑only key), the request came from outside the **Allowed source IP / CIDR** list, or the owning tenant is suspended |
| `429 Too Many Requests` | Per‑key rate limit hit — honor the `Retry-After` header, or raise the key's **Rate limit / min** |
| Empty results but `200 OK` | Keys are tenant‑scoped — the key sees only its own tenant's data, by design |

## Related

- **[Identity & Access](/administration/identity-access)** — the `api-client` role for least‑privilege machine identities.
- **[Tenants & Organizations](/administration/tenants-orgs)** — suspension disables a tenant's keys.
