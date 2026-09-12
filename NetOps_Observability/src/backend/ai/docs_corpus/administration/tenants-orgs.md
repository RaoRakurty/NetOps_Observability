---
title: Create tenants and organizations
sidebar_label: Tenants & organizations
description: Create the isolation unit that holds devices and data, group tenants under an organization, and suspend or delete one safely.
page_type: task
sidebar_position: 3
---

# Create tenants and organizations

A tenant is the isolation boundary. Every device, log line, incident, saved object and API key belongs to exactly one tenant. An organization is an optional account layer above tenants, for an operator who runs many customers or business units. This page creates both, and covers the two irreversible actions.

## Before you begin

- **Permission:** platform administrator. The tenant and organization registry is platform-global configuration. `POST /api/tenants`, `PATCH /api/tenants/{id}`, `DELETE /api/tenants/{id}` and every `/api/orgs` route call `requirePlatformAdmin`, so a tenant or organization administrator holding `administration:admin` is refused with `403`.
- Decide the display name. The slug is derived from it unless you supply one, and the slug is fixed for the life of the object.
- Decide the data-residency region for the organization. Its tenants inherit it. See [Set a data-residency region](/administration/regions).

## The hierarchy

The account tree is a strict single-parent tree, and containment is the only thing authorization traverses.

```text
platform            the operator's own realm, the root
  organization      one customer account, optional
    tenant          the isolation boundary, required
```

- A **tenant** carries a region, an isolation mode, and an operator-restricted flag. It belongs to exactly one organization.
- An **organization** carries a home region and an optional single sign-on connection, both inherited by its tenants.
- The **Provider** realm is the platform owner's own space. The `global` tenant holds platform-owned and untagged records. It is visible only to the platform owner, never to a scoped tenant, and it can be neither suspended nor deleted.

A tenant marked **operator restricted** hides its telemetry from the platform owner: logs, syslog, flows and traps are excluded from the Global view and refused if the operator scopes into that tenant. The tenant's own users are unaffected.

## Names, slugs and ids

Every organization and tenant carries three identifiers. Know which is which before you create one.

| Identifier | Example | Properties |
| --- | --- | --- |
| Id | `t_d3d501aa08e2395893b378a453b8af67` | `t_` or `org_` plus 32 hex characters of cryptographic randomness. Opaque, immutable, never derived from the name. Use it in automation. |
| Slug | `acme-prod` | The human handle. Globally unique across the platform, fixed at creation. |
| Display name | `Acme Corp Production` | The label the console shows. |

Slug rules, applied to a supplied slug and to one derived from the name alike:

- 2 to 40 characters.
- Lowercase letters, digits and hyphens only. No underscores, no spaces, no uppercase.
- No leading or trailing hyphen, and no two hyphens in a row.
- Not a reserved word. The reserved set is `admin`, `api`, `login`, `logout`, `signup`, `support`, `root`, `system`, `internal`, `auth`, `sso`, `billing`, `metrics`, `health`, `status`, `static`, `assets`, `global`, `platform`, `provider`.

## Steps

To create an organization and its first tenant in one pass:

1. Open **Administration → Identity & Access**.
2. Select **＋ Add**, then the **Customer organization** card.
3. Enter the **Organization name**, pick a **Home region**, and leave **SSO connection** blank if you will bind it later.
4. On the next step, tick **Create a first tenant now** and enter the **Tenant name**. Leave **Region** on the inherited option unless this tenant genuinely differs from its organization.
5. Optionally tick **Create a first user** and fill in the account.
6. Read **Review & create**, then select **Create**.

To add a tenant to an existing organization:

1. Open **Administration → Identity & Access → Organizations**.
2. Select the organization, then its **Tenants** tab.
3. Add the tenant there. It is pre-bound to that organization.

To read the registry from the API:

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/api/tenants
```

```json
[
  {
    "id": "global",
    "name": "Provider",
    "slug": "global",
    "note": "The provider (platform-owner) realm.",
    "org_id": "global",
    "isolation_mode": "shared",
    "created_at": "2026-08-16T17:16:58.130501624Z"
  },
  {
    "id": "t_d3d501aa08e2395893b378a453b8af67",
    "name": "lab",
    "slug": "lab",
    "note": "Lab fabric — SR Linux spines + EOS leaves (created 2026-09-03 via API)",
    "org_id": "global",
    "isolation_mode": "shared",
    "status": "active",
    "created_at": "2026-09-03T02:58:15.708334429Z"
  }
]
```

A tenant created before the lifecycle field existed carries no `status`. A blank status is read as `active`.

## Suspend a tenant {#suspend-a-tenant}

Suspension is the reversible "pause this customer" switch. It takes effect on the next request, not at the next sign-in.

1. Open the tenant's row under **Administration → Identity & Access → Organizations → (org) → Tenants**.
2. Select **Suspend**.
3. Confirm the prompt.

What suspension enforces, deny-by-default:

- Sign-in is refused with `403 tenant suspended`.
- The tenant's API keys are refused on every request with the same status.
- A session that is already open loses access on its next request.
- The tenant switcher is closed too. An organization administrator who could reach the tenant through a binding is refused on the effective tenant, not only on the tenant named in their token.

The platform owner is exempt by design, because it has to reach a suspended tenant in order to reactivate it. The `global` tenant can never be suspended.

To reactivate, select **Reactivate** on the same row. The status badge returns to **Active** and users sign in again immediately.

## Delete, and its guardrails

Deletion is permanent, and the server enforces the safeguards rather than the console.

- **Type-to-confirm.** The exact tenant name must be echoed back. Anything else is refused with `400 deletion not confirmed`.
- **A populated tenant needs force.** If the tenant still owns users, the delete is refused with `409 tenant still has N user(s)` unless the force option is set.
- **An organization that still owns tenants cannot be deleted.** The refusal is `409 organization still owns N tenant(s)`. Reassign or remove the tenants first.
- The `global` tenant and the Provider organization are permanent.

## Result

The new organization and tenant appear in the Organizations tree with the expected region, and `GET /api/tenants` returns the tenant with an opaque `t_` id and `status: active`. After a suspension, the tenant's row shows **Suspended**, a sign-in by one of its users is refused, and the refusal appears in the [audit log](/administration/audit-log) with decision `deny`.

## Related

- [Add users and grant access](/administration/identity-access) to populate the new tenant.
- [Set a data-residency region](/administration/regions) for what a region does and does not do.
- [Configure authentication](/administration/authentication) to bind the customer's identity provider.
- [Onboard devices](/onboard-devices/overview) to bring the tenant's network in.
