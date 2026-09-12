---
title: Security and identity FAQ
sidebar_label: Security and identity FAQ
description: Short answers to the identity, access, claim-handling, token-lifetime and audit questions a security review asks, with every planned item marked.
page_type: reference
sidebar_position: 5.2
---

# Security and identity FAQ

The questions below come up in security questionnaires and vendor reviews. Each answer describes what the shipped code does. Anything not built yet is marked **Planned** with its tracker row, and is never described as available.

## Can one tenant use more than one identity provider?

Yes. Three registrations exist side by side: one OIDC single sign-on, one LDAP or Active Directory, and one TACACS+. Local accounts remain available underneath all three, which is what keeps a provider outage from locking every administrator out.

One OIDC registration can front several upstream identity providers through the bundled Keycloak broker. The **Providers** list renders one button per broker alias, and the alias selects the upstream provider for that sign-in.

Each registration pins exactly one tenant, through its **Default tenant** field, and every account provisioned through it lands there. Two limits apply today:

| Limit | Status |
| --- | --- |
| The main sign-in page lists every enabled provider to every visitor | Shipped behaviour. The page is answered before sign-in, so it cannot know the visitor's tenant. |
| Only the platform administrator may register a provider | Shipped behaviour. Provider configuration is platform-global plumbing. |
| A tenant sign-in URL lists only that tenant's providers, and signs in only that tenant's accounts | Shipped behaviour. `/t/{slug}` and `/org/{id}` name the tenant. An account in another tenant, in the `global` tenant, or in no tenant is refused there, so platform staff sign in at the main address instead. See [Set up a per-tenant sign-in URL](/administration/tenant-sign-in). |
| Home-realm discovery from a typed identifier | Not built. Correlix does not route a visitor to a provider by their email domain. |
| Mapping a claim value to a tenant, so one provider serves many tenants | **Planned**, tracker 275. |

## How fine-grained is the access model?

Access is a binding: a principal holds a role at a scope. Each binding carries an effect, an optional condition map, optional time bounds, the account that granted it, and a reason.

| Dimension | Values |
| --- | --- |
| Principal | User, service account, agent or device. |
| Role | A grid of one level per module, across eight modules, at four levels: none, read, write, admin. |
| Scope | `platform`, `org:<id>`, `tenant:<id>`, `resource:<kind>:<id>`. |
| Effect | `allow` or `deny`. A deny at any covering scope wins over every allow. |
| Condition | A map on the binding. `break_glass` marks an emergency grant. |
| Time bounds | `not_before` and `expires_at`. Neither set means permanent. |
| Provenance | `granted_by` and `reason`, stored on the binding. |

Two honest caveats. Reach is decided at platform, org and tenant scope: the resource form is in the scope vocabulary and is carried on the record, and per-resource decisions are not made from it yet. Deny is evaluated across every covering scope, so a targeted deny carves an exception out of a wider grant.

Underneath the binding, tenant isolation is not a permission at all. It is enforced in the storage layer on every data-returning surface, and a cross-tenant read by id returns `404` rather than revealing that the id exists.

## How real-time is the platform?

The console is a polling surface. Dashboards, device lists and the Command Center reload on a 30-second interval, and that is the cadence to plan around. Ingestion itself is continuous, so data is already stored before a panel next asks for it.

Nothing in the product is sub-second, and no page claims to be. A question that needs an answer inside a second, such as inline traffic enforcement, is outside what this platform does.

## Are dynamically injected claims accepted?

Only from a verified ID token, and only under the claim names the code reads.

An ID token is accepted after its signature verifies against the provider's published JWKS, its issuer and audience match the registration, its expiry is in the future, and the `nonce` echoes the value the server minted for that one login transaction. A token that fails any of those is refused, and the login transaction is consumed once so a replay cannot reuse it.

| Claim | Used for |
| --- | --- |
| `preferred_username`, `email`, `sub` | The username, in that order of preference |
| `email`, `name` | The stored email and display name |
| `realm_access.roles`, `groups` | Role mapping |
| `amr`, `acr` | Proof the provider performed a second factor |
| `nonce` | Binding the token to this login transaction |

The claim **names** are fixed in the code. What an administrator configures is the **values** that map onto a role: the **Admin roles** and **Operator roles** lists, and the accepted assurance values. A claim arriving anywhere other than the verified ID token, such as a request body, a header or a query parameter, is never read as identity.

Three guards sit behind the mapping. A claim cannot move an existing account into another tenant, because the stored tenant is used on every refresh. A claim cannot silently grant platform ownership, because the mapped role passes through a guard before it is written. A sign-in that starts at a tenant URL cannot reach an account outside that tenant at all: the store refuses it before the refresh is written, so the account keeps its role and its authentication source.

## What time-to-live applies to a token, and to elevated access?

| Item | Default | Bounds or ceiling |
| --- | --- | --- |
| Access token | 15 minutes | 60 seconds to 24 hours |
| Refresh token | 7 days, single-use and rotating | 5 minutes to 90 days |
| Idle timeout | 30 minutes | Floor of 5 minutes |
| Absolute session lifetime | 12 hours | Per scope |
| Concurrent sessions per user | 5, oldest evicted | Fixed |
| Break-glass session | 60 minutes | 8 hours |
| Any binding | Permanent unless bounded | `not_before` and `expires_at` |

A value set outside the token-policy bounds is clamped on save rather than rejected. Replaying a spent refresh token revokes the whole session lineage.

A break-glass session requires a reason, expires on its own, and can be ended early with `DELETE /api/breakglass/{id}`. It grants reach into one named tenant, never all of them.

## What is the password of last resort, and can a vault rotate it?

Keep at least one local administrator account that no identity provider ever federates. It is the way back in when single sign-on breaks, and pointing a provider at that same username is refused precisely so the account cannot be converted out from under you.

It is rotatable two ways today:

| Method | What it does |
| --- | --- |
| `PATCH /api/users/{username}` with a new password | Rotates the credential in place, and revokes every session that account holds. Local accounts only: the route refuses a password on a federated account. |
| `scripts/reset-admin.sh` | Removes the local user store and lets the API re-seed the admin from `ADMIN_INITIAL_PASSWORD`. A recovery tool, not a routine credential swap: it discards local accounts. |

An external vault can drive the first of those from its own scheduled job, because it is an ordinary authenticated API call. There is no native HashiCorp Vault or CyberArk connector, no dedicated credential for that one call, and no rule that refuses a break-glass sign-in when the secret is stale. All of that is **Planned**, tracker 274.

## Are elevated sessions audited?

Every API call is audited, and the record carries these fields:

| Field | Content |
| --- | --- |
| `id`, `time` | Event identity and timestamp |
| `actor` | Username or subject. Empty means unauthenticated |
| `tenant` | The actor's tenant |
| `cross` | True when the actor was acting as the platform owner |
| `method`, `path`, `status` | The request and its outcome |
| `decision` | `allow`, `deny` or `error`, derived from the status |
| `remote` | Client address |
| `detail` | Per-route detail map |

Opening and ending a break-glass session are audited as calls like any other, and they also emit a warning-level event carrying the operator, the target tenant, the reason and the expiry time.

One gap, stated rather than glossed over: the binding id is not a field on audit events today, so joining an audited call to the exact grant that permitted it is done through the actor, the tenant and the timestamp. Carrying the binding id on the event is part of the elevation work, which is in progress.

## Is SCIM supported?

No. **Planned**, tracker 273.

The `scim` entitlement exists in the licence vocabulary at the Enterprise tier, and it gates nothing today because no route sits behind it. Nothing is served at `/scim/v2/Users` or `/scim/v2/Groups`. Provisioning today is just-in-time, and deprovisioning is the manual sequence in [Identity provisioning](/administration/identity-provisioning).

## Is SAML supported?

Yes, through the bundled Keycloak broker. Okta or another provider issues a signed SAML assertion to Keycloak, and Keycloak speaks OIDC onwards to Correlix, so the SAML leg is a real SAML 2.0 exchange.

Correlix serves no assertion consumer service of its own. Unsolicited provider-initiated SAML therefore cannot reach it, and the supported one-click experience is a bookmark tile that starts the flow at Correlix. A native SAML service provider is deferred.

## Related

- [Identity provisioning](/administration/identity-provisioning) for what just-in-time provisioning writes, and how to deprovision.
- [Configure authentication](/administration/authentication) for provider registration, password policy and the token policy.
- [Add users and grant access](/administration/identity-access) for roles and the permission grid.
- [Read the audit log](/administration/audit-log) for filtering and retention of the events above.
- [Licensing](/reference/licensing) for which entitlements are commercial and which are planned.
