---
title: Tenants & Organizations
sidebar_label: Tenants & Organizations
sidebar_position: 5
description: Create isolated tenants and the organization layer above them.
---

# Tenants & Organizations

Correlix is multi‑tenant. A **tenant** is a fully isolated workspace — its own devices, telemetry, incidents, users and roles. An **organization** is an optional account layer *above* tenants, for operators who manage many customers or business units.

## The model

The account hierarchy is a strict tree:

```
Provider (platform)  →  Organization (optional)  →  Tenant (required)  →  Users & data
```

- **Tenant** — the isolation boundary and the *required* unit. Devices, telemetry and incidents always belong to exactly one tenant. A tenant never sees another tenant's data, on any surface — search, dashboards, exports, the AI, or the API.
- **Organization** — groups tenants under one account. Each organization has a home data **region** and an optional sign‑in connection, both inherited by its tenants. If you don't create one, tenants live directly under the Provider realm.
- **Provider** — the platform operator's own realm; the root organization (shown with a *Parent Organization* badge) and the seed tenant cannot be deleted or suspended.

A tenant admin holds full administrative rights *inside* their tenant but has no visibility into the platform or other tenants. Isolation is enforced in the backend at every layer, not just hidden in the UI.

## Names, slugs and IDs

Every organization and tenant has three identifiers — know which is which before you create one:

| Identifier | Example | Properties |
| --- | --- | --- |
| **ID** | `org_…` / `t_…` + 32 hex characters | Opaque, minted by the platform, **immutable**. Never derived from the name. Use it in automation. |
| **Slug** | `acme-prod` | Human‑friendly handle, **globally unique**, fixed at creation. |
| **Display name** | `Acme Corp — Production` | The label shown in the UI. |

Slug rules (a slug is derived from the name if you don't supply one): 2–40 characters, lowercase letters, digits and hyphens only; no leading/trailing or consecutive hyphens; no underscores or spaces; and reserved words (`admin`, `api`, `global`, `platform`, `provider`, `system`, and similar) are refused.

:::tip Choose names carefully
The ID and slug are permanent. For organizations, the name is also fixed after creation — only the note, home region and sign‑in connection can be edited later.
:::

## Create an organization and tenant

Creating organizations and tenants is **platform‑operator‑only**.

**Recommended — the guided wizard:** <kbd>Administration → Identity & Access</kbd> → **＋ Add** walks you through organization (optional) → tenant → first user in one pass. See [the guided ＋ Add wizard](/administration/identity-access#guided-add-wizard).

**Onboard a customer in one step:** <kbd>Identity & Access → Organizations</kbd> → **＋ Onboard customer** creates the organization *and* its first tenant together in a single audited action, so a customer is never left as an empty org.

**Individually:**

1. <kbd>Identity & Access → Organizations</kbd> → **＋ Create organization**. Fill in **Name** *(required)*, **Region** *(required — the data‑residency region its tenants inherit)*, optional **Sign‑in connection** and **Note**, then click **Create organization**.
2. Drill into the organization (click its name or **Manage**) and open its **Tenants** tab to add tenants inside it.

The Organizations list shows each org's **Data region**, **Users** (accounts owned by the org), **Tenants** count, **Sign‑in** (its SSO connection or *Platform default*) and note, with **Manage / Edit / Delete** actions per row.

## Suspend a tenant {#suspend-a-tenant}

Suspension is the "pause this customer" switch — reversible, immediate, and platform‑operator‑only.

1. Open the tenant list (its organization's **Tenants** tab under <kbd>Identity & Access → Organizations → *(org)*</kbd>).
2. Click **Suspend** on the tenant's row.
3. Confirm the prompt: *"Suspend "\{name\}"? Its users (and API keys) will be unable to sign in or make requests until you reactivate it. The platform operator is unaffected."*

What suspension enforces, instantly and deny‑by‑default:

- **Sign‑in is blocked** — the tenant's users are refused at login.
- **API keys stop working** — the tenant's machine credentials are rejected on every request.
- **Live sessions are cut** — anyone already signed in loses access on their next request, not at their next login.

The platform operator is never affected (the Provider realm cannot be suspended), so you can always get back in to reactivate.

### Reactivate

Same place: the row's button now reads **Reactivate** — click it and the tenant's **Status** badge flips from **Suspended** back to **Active**. Users can sign in again immediately.

## Delete — and its guardrails

Deletion is permanent, so it is deliberately hard to do by accident:

- **A tenant with users requires force.** Deleting a tenant asks you to **type its exact name to confirm**; if it still has users, you must additionally confirm force‑deletion.
- **An organization that still owns tenants can't be deleted.** Reassign or remove its tenants first — the confirm dialog says so explicitly.
- The Provider (root) organization and the seed tenant are permanent.

## Regions and inheritance

Each organization has a home data region; a tenant inherits it unless you override the region at tenant creation. Regions are data‑residency metadata managed by the platform operator — see [Regions](/administration/regions) for what they do today.

## Verify

- After creating: <kbd>Identity & Access</kbd> — the hierarchy map ("How your account is organized") shows the new org → tenant branch with its region.
- After suspending: the tenant's row shows a red **Suspended** badge; a sign‑in attempt by one of its users is refused, and the attempt appears in the **Audit Log** as a deny.
- After reactivating: badge back to **Active**; users sign in normally.

## Troubleshooting

- **"organization still owns N tenant(s)"** on delete — move or delete the org's tenants first.
- **Slug rejected** — check the rules above (lowercase, 2–40 chars, hyphens only, not a reserved word, not already taken). Slugs are unique across the whole platform.
- **A suspended tenant's user says they're locked out** — that's the feature. Reactivate the tenant, or if only one person should be blocked, keep the tenant active and disable that user instead.
- **Can't create a tenant** — tenant and organization creation requires the platform operator; a tenant admin manages *inside* a tenant, never the registry itself.

## Next

- **[Identity & Access](/administration/identity-access)** — add users and grant roles in the new tenant.
- **[Authentication](/administration/authentication)** — bind the customer's SSO.
- **[Onboard devices](/onboard-devices/overview)** — bring their network in.
