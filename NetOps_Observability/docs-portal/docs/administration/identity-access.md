---
title: Users & roles (Global vs Tenant)
sidebar_label: Users & roles
sidebar_position: 2
description: Create users at the global (platform) or tenant level, assign roles, and grant scoped access.
---

# Users & roles (Global vs Tenant)

Identity & Access is where you manage **who** can sign in and **what** they can do. Open it at <kbd>Administration → Identity & Access</kbd>. It's split into two tabs:

- **Global** — platform‑wide identities and settings (managed by the platform owner).
- **Tenants** — each tenant is configured independently; drill into a tenant to manage its own users and roles.

## Global vs Tenant users — which do I create?

| You want to… | Create the user in… |
| --- | --- |
| Give a **platform operator** cross‑tenant/administrative access | **Global** |
| Give someone access to **one tenant/organization** only | That **Tenant** (drill in) |
| Model a customer's own admins/operators | Inside **their tenant** |

A **tenant user** can only ever see and act within that tenant. A **global** (platform) identity is the only cross‑tenant scope, and is reserved for platform operations.

## Create a user

1. Go to <kbd>Administration → Identity & Access</kbd>.
2. Pick the scope:
   - **Global** tab for a platform user, **or**
   - **Tenants** tab → open the target tenant for a tenant user.
3. Add the user — username/email and initial credentials (or leave to SSO, below).
4. Assign one or more **roles** (see below).
5. Save. If MFA is required (see [Authentication](/administration/authentication)), the user enrolls at first sign‑in.

:::tip Organizations
If you use the **Organization** layer above tenants, users can be created at the organization level and become members of its tenants. Org membership can auto‑grant roles across the org's tenants.
:::

## Roles

Access is **role‑based**. A role is a set of permissions (read/write per module). Assign roles when you create a user, or manage them separately.

- Built‑in roles cover common personas (operator, admin, read‑only).
- Create custom roles to match your org's separation of duties.
- Roles are scoped — a role granted in one tenant doesn't leak to another.

## Access Grants

For fine‑grained control, <kbd>Administration → Access Grants</kbd> binds a **principal → role → scope** (e.g. "user X has the Operator role in tenant Y"). Use it to grant temporary or cross‑scope access without changing a user's home tenant.

## Next

- **[Authentication & SSO](/administration/authentication)** — connect an IdP so users sign in with your identity provider.
- **[Tenants & Organizations](/administration/tenants-orgs)** — create the tenants users belong to.
