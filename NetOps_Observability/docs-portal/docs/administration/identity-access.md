---
title: Identity & Access
sidebar_label: Identity & Access
sidebar_position: 2
description: Organizations, tenants, users and roles — the hierarchy map, the guided ＋ Add wizard, and access grants.
---

# Identity & Access

Identity & Access is the one place where people, roles and security settings are managed. Open it at <kbd>Administration → Identity & Access</kbd>.

What you see depends on who you are: a **tenant admin** gets a focused view — *"Users, roles and security settings for your tenant"* — with their own tenant's tabs (Users, User Roles, Custom User Roles, External SSO Roles, Security Settings); the **platform operator** gets the full page — the hierarchy map, a **Provider / Organizations** scope switch, per‑organization drill‑in, and the guided **＋ Add** wizard.

The model in one sentence: access is a **binding** — *a person* is given *a role* at *a scope* (the platform, an organization, or a tenant). Users are accounts; roles define what they can do; bindings define where.

## The hierarchy map

At the top of the page, **"How your account is organized"** shows the live account tree:

```
Provider (you) → Organization (Optional) → Tenant (Required) → User → Assign access
```

**Provider** is the platform‑owner realm; an **Organization** is an *optional* grouping (a customer, a BU — skip it and things live directly under the Provider); a **Tenant** is the *required* unit that holds devices and data, and the isolation boundary. The chips used throughout mean: **Required** (the tenant), **Optional** (the org — defaults to Provider), **Inherited** (a tenant inherits its org's region). The tree shows each organization, its tenants, regions, user counts, and any `suspended` markers.

## The guided ＋ Add wizard {#guided-add-wizard}

The fastest way to set up a complete workspace — organization (optional), tenant, and a first user — is the wizard. Nothing is created until you click **Create** on the final step, and the objects are then created in order.

1. Go to <kbd>Administration → Identity & Access</kbd> and click **＋ Add** (top right; platform operator only).
2. **Step 1 — Organization** *(optional)*. Tick **Create a new organization** to group tenants under a customer or BU, or leave it unticked to use the default Provider realm. If ticked, fill in:

   | Field | Required | Notes |
   | --- | --- | --- |
   | **Organization name** | Yes | e.g. `Acme Corp` |
   | **Home region** | — | The data‑residency region its tenants inherit — see [Regions](/administration/regions) |
   | **SSO connection** | No | Bind later in [Authentication](/administration/authentication) |

3. **Step 2 — Tenant** *(required)*. The workspace that holds devices and data:

   | Field | Required | Notes |
   | --- | --- | --- |
   | **Tenant name** | Yes | e.g. `acme-prod` |
   | **Organization** | — | Fixed: the org from step 1, or *Provider (default)* |
   | **Region** | — | Defaults to *inherited* from the org/Provider; pick a region to override |

4. **Step 3 — First user** *(recommended)*. Leave **Create a user for this tenant** ticked and fill in **Username** (required), **Email**, **Password** (leave blank to set later or sign in via SSO), and **Role** (defaults to `operator`).
5. **Step 4 — Review & create**. A numbered summary shows exactly what will be created, in order: ① Organization (or *Provider (default) — skipped*), ② Tenant (name · region), ③ User (name · role, or *skipped*). Click **Create**.

You can also create objects individually: **Organizations tab → ＋ Create organization** (Name and Region required), or **＋ Onboard customer** — a one‑step flow that creates an organization *and* its first tenant together.

## Add a user {#add-a-user}

Users can be owned at three levels — create them where they belong:

| The user is… | Create them under |
| --- | --- |
| A platform operator's colleague (no org/tenant) | <kbd>Identity & Access → Provider → Users</kbd> |
| A customer‑org person (not tied to one tenant) | <kbd>Identity & Access → Organizations → *(org)* → Users</kbd> |
| A tenant's own operator/admin | The tenant's **Users** tab (via the org's **Tenants** tab → **Manage**), or the tenant admin's own Identity & Access |

Open the **Users** tab at the right scope and add the user: **username** (required), optional **email**, **display name** and initial **password** (blank if they'll sign in through SSO/LDAP), and a **role** — defaults to `read-only` if unset. The account is usable within its scope immediately; broader reach comes from access grants (below). A tenant admin can only create users in their own tenant.

## Grant access (bindings) {#grant-access-bindings}

Two equivalent surfaces write the same grants:

**From Assign access** — <kbd>Administration → Assign access</kbd>:

1. Click **＋ Assign access**. The *Grant access* dialog opens.
2. **Person** *(required)* — pick an existing user.
3. **Organization** *(required)* — the scope of the grant (scope options here are organizations).
4. **Role** — defaults to `operator`; pick from the table below.
5. **Effect** — **Allow** or **Deny**. Deny wins over allow, so a targeted Deny carves an exception out of a broader grant.
6. Click **Grant access**.

**From an organization's Access tab** — <kbd>Identity & Access → Organizations → *(org)* → Access</kbd>: same flow with the scope fixed to that org — pick **User** and **Role**, click **＋ Assign access**.

The grants list shows **Person · Role · Scope · Effect · Granted by**, with a per‑row **Revoke**. An org admin can grant and revoke only within their own organization and never `super-admin`; platform‑scope grants require the platform operator.

## Roles

A role is a grid of permission levels — **none / read / write / admin** — over seven product areas: *overview, explore, alerts, infrastructure, topology, reports, administration*.

| Role | What it can do |
| --- | --- |
| **Super Admin** (`super-admin`) | Full control across all tenants, including identity. Reserved for the platform operator. |
| **Org Admin** (`org-admin`) | Full admin rights, bounded to one organization's tenants and people. |
| **Operator** (`operator`) | Read everything, plus write on alerts (acknowledge/silence) and infrastructure (discovery, devices). No administration. |
| **Read-only** (`read-only`) | View everything, change nothing. The default for new users. |
| **Auditor** (`auditor`) | Read‑only everywhere **including administration and the audit trail**. |
| **API Client** (`api-client`) | Least‑privilege machine identity; narrow further with [API‑token scopes](/administration/api-access). |

An **org‑scoped** grant of Super Admin or Org Admin reaches every tenant inside that org; other roles bound at org scope do not fan out — grant them where they should apply.

### Custom roles

1. Open <kbd>Identity & Access → *(scope)* → Custom User Roles</kbd> and click **＋ New custom role** (e.g. *NOC Engineer*).
2. In the permission grid, click a cell to cycle its level `none → read → write → admin`; changes persist immediately. Built‑in roles are read‑only, and a custom role can never grant *administration* at **admin** level — that is reserved for the built‑in administrators.

The **External SSO Roles** tab shows how roles arriving from your identity provider map in — configure that mapping in [Authentication](/administration/authentication) (the provider's *Role mapping* step).

## Verify

- New user: have them sign in — they land scoped to their tenant, with menus matching their role.
- New grant: <kbd>Administration → Assign access</kbd> lists it with the right **Role · Scope · Effect**, and the **Audit Log** records it with you as **Actor**.
- Wizard run: the hierarchy map shows the new org/tenant with a user count of 1.

## Troubleshooting

- **The Person dropdown is empty.** Grants attach to existing users — create the account first under the right Users tab.
- **"cannot grant super-admin".** Only the platform operator can hand out Super Admin; org admins grant non‑escalating roles inside their org.
- **A user sees less than their role suggests.** Check for a **Deny** binding (deny always wins), and confirm the grant's scope — an `operator` bound at org scope does not fan out to the org's tenants.
- **Can't delete a role.** Built‑in roles are fixed; only custom roles can be deleted.
