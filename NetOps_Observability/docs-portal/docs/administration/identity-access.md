---
title: Add users and grant access
sidebar_label: Identity & Access
description: Create an account at the right scope, give it a role, and read the permission grid the role compiles to.
page_type: task
sidebar_position: 2
---

# Add users and grant access

Access in Correlix is a binding: a person is given a role at a scope. Users are accounts, roles are permission grids, and bindings decide where a role applies. This page creates the account, hands it a role, and shows you how to read the grid it resolves to.

## Before you begin

- **Permission:** `administration:admin`. Creating a user inside your own tenant is per-tenant data. Changing a role definition, and any grant at platform scope, is platform-global and needs the platform administrator.
- Know the scope the person belongs to: the Provider realm, an organization, or one tenant. See [Create tenants and organizations](/administration/tenants-orgs).
- Decide whether the account signs in locally or through an identity provider. A federated account is created on first sign-in instead. See [Configure authentication](/administration/authentication).
- Open **Administration → Identity & Access**. A tenant administrator sees one scope. A platform administrator sees the Organizations tree with the Provider realm as its root row.

## Steps

### Add a user {#add-a-user}

Create the account where it belongs. The owning scope decides what the person can ever see, and it is stamped from the scope you create them in, never from a field they can edit.

| The person is | Create them under |
| --- | --- |
| A platform administrator's colleague, tied to no customer | **Identity & Access → Provider → Users** |
| An organization's person, not tied to one tenant | **Identity & Access → Organizations → (org) → Users** |
| A tenant's own operator or administrator | The tenant's **Users** tab, reached from the organization's **Tenants** tab |

To add a user:

1. Open the **Users** tab at the right scope.
2. Enter the **Username**. It is required.
3. Enter **Email**, **Display name** and an initial **Password** if the account signs in locally. Leave the password blank for an account that will sign in through single sign-on, LDAP or TACACS+.
4. Pick a **Role**. It defaults to `read-only` when unset.
5. Save. The account works inside its own scope immediately.

A tenant administrator can only create users in their own tenant.

### Grant a role at an organization scope {#grant-access-bindings}

A grant reaches wider than the scope the account lives in. Grants are written from an organization's **Access** tab, or from the guided wizard's **Access grant** path.

To grant access from an organization:

1. Open **Administration → Identity & Access → Organizations → (org) → Access**.
2. Select the **Person**. Grants attach to accounts that already exist.
3. Select the **Role**.
4. Select the **Effect**, either **Allow** or **Deny**. Deny wins over allow, so a targeted deny carves an exception out of a wider grant.
5. Select **＋ Assign access**.

The grants list shows Person, Role, Scope, Effect and Granted by, with a per-row **Revoke**.

Reach follows containment. A binding grants reach when its scope is the target tenant or an ancestor of it. An organization-scope binding confers reach across that organization's tenants only for an organization-manager role, which means `org-admin` and `super-admin`. Other roles bound at an organization scope do not fan out to its tenants, so grant those where they should apply. An organization administrator can never grant `super-admin`.

### Create a whole workspace with the guided wizard {#guided-add-wizard}

The **＋ Add** button at the top right of Identity & Access is one guided path for four objects. It is available to the platform administrator.

1. Select **＋ Add**.
2. On **What to add**, pick one of four cards:

   | Card | What it creates |
   | --- | --- |
   | **Customer organization** | An organization, optionally with its first tenant and first user. |
   | **Tenant** | A workspace under the Provider or under an organization, optionally with its first user. |
   | **User** | A person under the Provider, an organization or a tenant, with a role. |
   | **Access grant** | A role for an existing person on an organization. |

3. Complete the steps the card asks for. **Organization name**, **Tenant name**, **Username**, and for a grant both **Person** and **Organization**, are the required fields.
4. Read **Review & create**. It lists what will be created, numbered, in the order it will be created.
5. Select **Create**. Nothing exists until this step.

## The permission grid

A role is a grid of one level per module. `GET /api/auth/permissions` returns the caller's own effective grid, which is what the console uses to decide which sections to render.

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/api/auth/permissions
```

```json
{
  "permissions": {
    "administration": 3,
    "alerts": 3,
    "explore": 3,
    "infrastructure": 3,
    "overview": 3,
    "reports": 3,
    "sensitive_data": 3,
    "topology": 3
  },
  "role": "admin"
}
```

The levels are a four-step ladder, and each level implies the ones below it.

| Value | Level | Means |
| --- | --- | --- |
| `0` | none | The section is hidden. |
| `1` | read | View the module's data. |
| `2` | write | Act on it: acknowledge or silence an alert, run discovery, edit a dashboard. |
| `3` | admin | Manage the module's configuration. On `administration`, manage identity. |

The eight modules and what each one gates:

| Module | Gates |
| --- | --- |
| `overview` | The Command Center and the home dashboards. |
| `explore` | Metrics, logs, flows and events. |
| `alerts` | Alerts, monitors and incident actions. |
| `infrastructure` | Devices, discovery, interfaces and the parser's unrecognized-shapes view. |
| `topology` | The topology canvas and the geomap. |
| `reports` | Report definitions and executions. |
| `administration` | Everything under Administration: users, roles, tenants, API keys, processors, the audit trail. |
| `sensitive_data` | Sealed fields. `read` sees that a field is sealed and its masked form, `write` creates and edits `seal` processors, `admin` reveals plaintext through the audited unseal route. |

`sensitive_data` is deliberately its own module rather than a level of `administration`. Revealing a card number is a different capability from configuring the platform, and an infrastructure or alerting administrator must not acquire it by being an administrator of something else.

## Roles

Six built-in roles ship as seeded, non-deletable rows.

| Role | Grid |
| --- | --- |
| **Super Admin** (`super-admin`) | `admin` on every module. Bound at platform scope it is the platform owner. |
| **Org Admin** (`org-admin`) | The same grid as Super Admin. The scope is the limiter: bound at an organization, it reaches that organization's tenants and never platform plumbing. |
| **Operator** (`operator`) | `write` on `alerts` and `infrastructure`, `read` elsewhere, `none` on `administration`. |
| **Read-only** (`read-only`) | `read` everywhere except `administration`, which is `none`. The default for a new user. |
| **Auditor** (`auditor`) | `read` on every module including `administration`, so the audit trail is readable. No write anywhere. |
| **API Client** (`api-client`) | `read` on operational modules. `none` on `reports` and `administration`. Narrow it further with [API key scopes](/administration/api-access). |

To build a custom role:

1. Open **Identity & Access → (scope) → Custom User Roles**.
2. Select **＋ New custom role** and name it.
3. Select a cell in the grid to cycle its level through none, read, write and admin. Changes persist as you make them.

Built-in roles are read-only. Role definitions are platform-wide: a tenant administrator can read them in order to assign them, and only the platform administrator can change them.

The **External SSO Roles** tab shows how roles arriving from an identity provider map onto these. Configure that mapping on the provider itself, in [Configure authentication](/administration/authentication).

## Result

The new account signs in and lands scoped to its own tenant, with the sections its role allows and nothing else. `GET /api/auth/permissions` returns the grid you expect for that person. The grant appears in the organization's **Access** list with the right Role, Scope and Effect, and the creation appears in the [audit log](/administration/audit-log) with you as the actor.

## Related

- [Create tenants and organizations](/administration/tenants-orgs) for the scopes a user can belong to.
- [Configure authentication](/administration/authentication) for federated accounts, password policy and lockout.
- [Read the audit log](/administration/audit-log) to prove a permission change took effect.
- [Mint an API key](/administration/api-access) for a machine identity instead of a person.
