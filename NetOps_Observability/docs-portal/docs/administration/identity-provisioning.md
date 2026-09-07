---
title: Identity provisioning
sidebar_label: Identity provisioning
description: How just-in-time provisioning creates and refreshes federated accounts, what a binding grants and for how long, and where SCIM stands.
page_type: concept
sidebar_position: 5.1
---

# Identity provisioning

Correlix provisions federated accounts just in time. There is no account to create in advance and no directory to import: the first successful sign-in through a configured provider creates the account, and every sign-in after that refreshes it from the provider. SCIM provisioning is planned and is not in this release, so the deprovisioning steps on this page are the ones that apply today.

## What just-in-time provisioning does

One code path handles all three provider types, so OIDC, LDAP and TACACS+ behave identically once the external system has said yes.

| Event | Behaviour |
| --- | --- |
| First sign-in | The account is created in the provider's tenant with the mapped role, no password, and status `active`. |
| Later sign-ins | Name, email and role are refreshed from the provider. A non-empty incoming value overwrites the stored one. |
| Tenant | Set once, at creation, from the provider registration. A later claim never moves the account to another tenant. |
| Deactivated account | Never resurrected. Provisioning does not touch status, and the sign-in is refused with `401 account disabled`. |
| Name collision with a local account | Refused. The provider's verdict is not accepted against an account Correlix holds a password for. |
| Role | Mapped from the provider, then guarded, so a claim cannot silently make its holder the platform owner. |
| User limit | Not applied. Federated provisioning is exempt from `MAX_USERS`, so single sign-on cannot lock out at the cap. |

Two of those rules carry more weight than the rest.

**A claim never moves a tenant.** The tenant a person lands in is decided by the provider registration they signed in through, and it is written once. On every later sign-in the stored tenant is used, so a changed group, a changed directory or a re-registered provider cannot migrate an existing account, or its data, into a different tenant.

**A deactivated account is never resurrected.** Setting an account to `disabled` is the deprovisioning action, and a later sign-in through the provider does not undo it. The refresh leaves status alone and the sign-in path refuses the account, so the disable holds until an administrator lifts it.

Multi-factor authentication is carried, not re-run. Correlix does not enrol a second factor for a federated account, because the provider owns that credential. When the single sign-on registration has **Require MFA** set, the ID token must assert a second factor in `amr`, or an `acr` value listed as an accepted assurance value. A token without one is refused, with the message that the identity provider did not confirm a second factor.

## By provider type

| | OIDC single sign-on | LDAP or Active Directory | TACACS+ |
| --- | --- | --- | --- |
| Provisioned at | The single sign-on callback, after the ID token verifies | The sign-in request, after the directory bind succeeds | The sign-in request, after the server authenticates |
| Username from | `preferred_username`, else `email`, else `sub` | The username typed at sign-in | The username typed at sign-in |
| Email and name from | The `email` and `name` claims | The directory entry | Not supplied. The username becomes the display name |
| Role from | `realm_access.roles` and `groups`, matched against the **Admin roles** and **Operator roles** lists, else the **Default role** | The group-DN to role map, highest privilege wins | The registration's **Default role**. TACACS+ carries no group mapping |
| Tenant | The registration's **Default tenant** | `LDAP_DEFAULT_TENANT` | The registration's **Default tenant** |
| `auth_source` stamped | `oidc` | `ldap` | `tacacs` |

Configure all three in [Configure authentication](/administration/authentication). SAML reaches Correlix through the bundled Keycloak broker, which terminates SAML and speaks OIDC onwards, so a SAML user is provisioned by the OIDC row above. [Connect Okta as an identity provider](/administration/okta-sso) is the worked example.

## More than one provider

A tenant can be served by several registrations at once. Local accounts always stay available underneath them.

| Fact | Today |
| --- | --- |
| Registrations | Three: one OIDC, one LDAP, one TACACS+. All are platform-global. |
| Tenant per registration | Each registration pins exactly one tenant, through its **Default tenant** field. |
| Upstream providers behind OIDC | Several. The **Providers** list renders one button per broker alias, and the alias selects the upstream identity provider. |
| Tenant for those aliases | All of them land in the OIDC registration's single default tenant. |
| Who may register one | The platform administrator only. |
| What the sign-in page shows | Every enabled provider, to every visitor. |

The last row is worth stating plainly. `GET /api/auth/methods` answers before anyone has signed in, so it cannot know which tenant the visitor belongs to, and the sign-in page therefore lists all enabled providers to everyone. Per-tenant sign-in URLs and home-realm discovery, so a tenant sees only its own providers, are planned (tracker 276). Mapping a group or claim value to a tenant, so one corporate provider can serve many tenants, is planned (tracker 275).

A separate provider registration for time-bound higher access, alongside the standing one a person signs in with daily, is in progress and is not in this release.

## What a binding grants, and for how long

The role a person carries out of provisioning is one half of access. The other half is the binding: the record of who holds which role, where, granted by whom, and until when.

| Field | Meaning |
| --- | --- |
| Principal | The account the grant attaches to. A user, a service account, an agent or a device. |
| Role | The permission grid that applies. See [Add users and grant access](/administration/identity-access). |
| Scope | Where it applies: `platform`, `org:<id>`, `tenant:<id>` or `resource:<kind>:<id>`. |
| Effect | `allow` or `deny`. A deny at any covering scope wins over every allow. |
| Not before | Optional. The binding is inert until this time. |
| Expires at | Optional. The binding stops applying at this time. Absent means permanent. |
| Granted by | The account that created the grant. |
| Reason | Free text recorded with the grant. Mandatory for break-glass. |
| Condition | Optional map. `break_glass` marks an emergency grant. |

Reach is decided at platform, org and tenant scope. The resource form is in the scope vocabulary and is carried on the record, and per-resource decisions are not made from it yet.

**Break-glass** is the platform operator's audited route into a tenant whose data is marked operator-restricted. `POST /api/breakglass` opens one: a reason is required, the default window is 60 minutes, and 8 hours is the ceiling. The session un-hides that one tenant for its window and expires on its own, and `DELETE /api/breakglass/{id}` ends it early. A tenant's own administrators never need it, because they already reach their own data.

## Token lifetimes and revocation timing

| Setting | Shipped default | Where |
| --- | --- | --- |
| Access token | 15 minutes | `ACCESS_TOKEN_TTL`, or the token policy |
| Refresh token | 7 days, single-use and rotating | `REFRESH_TOKEN_TTL`, or the token policy |
| Idle timeout | 30 minutes | Security settings, per scope |
| Absolute session lifetime | 12 hours | Security settings, per scope |
| Concurrent sessions per user | 5, oldest evicted | Fixed |
| Break-glass session | 60 minutes, ceiling 8 hours | Per request |

Revocation splits into two halves, and the difference matters when someone leaves.

**Correlix-side revocation is immediate.** Disabling an account, deleting it, suspending its tenant or killing a session is re-checked on every single request, not at token expiry. The next call the holder makes fails with `401`, whatever their access token still says.

**Provider-side removal is not.** Correlix is not told when someone is removed at the identity provider. That removal stops the next sign-in, and it does not end a session that is already open. To cut an open session off at the moment of the leaver event, disable the account or revoke the session in Correlix as well.

## Deprovisioning today

Until SCIM ships, deprovisioning is these four actions, and the first one is the one that matters.

1. Set the account's **Status** to `disabled` in **Administration → Identity & Access**, or with `PATCH /api/users/{username}`. Every sign-in path refuses a disabled account, and every in-flight session fails on its next request.
2. Revoke live sessions in **Administration → Access & Audit → Sessions**, or with `DELETE /api/sessions/{id}`.
3. Delete the account when the record is no longer needed. Its bindings are removed with it.
4. Remove the person at the identity provider. On its own this stops the next sign-in and nothing else, which is why step 1 comes first.

Each of those appears in the [audit log](/administration/audit-log) with the actor, the path and the decision.

## SCIM: planned, not shipped

SCIM 2.0 user and group provisioning is on the roadmap and is not in this release. Stating that precisely:

| Question | Answer |
| --- | --- |
| Is there a SCIM endpoint? | No. Nothing is served at `/scim/v2/Users` or `/scim/v2/Groups`. |
| Does the entitlement exist? | Yes. `scim` is in the licence vocabulary at the Enterprise tier, and it gates nothing today because there is no route behind it. |
| Was the design done? | Yes. The 2026-08-03 single sign-on design left the seams: membership status, the never-resurrect rule, and SCIM compatibility in the binding rules. |
| What is tracked? | Tracker row 273: per-tenant `/scim/v2/Users` and `/Groups` behind a per-tenant bearer token, with deprovisioning that revokes sessions and bindings at once. |
| What do I use instead? | Just-in-time provisioning for joiners and movers, and the four deprovisioning actions above for leavers. |

An entitlement in the licence file is a commercial vocabulary entry, not a promise that a route exists. [Licensing](/reference/licensing) lists which entitlements are planned.

## Related

- [Configure authentication](/administration/authentication) to register OIDC, LDAP or TACACS+ and set the token policy.
- [Connect Okta as an identity provider](/administration/okta-sso) for the worked broker setup.
- [Add users and grant access](/administration/identity-access) for roles, the permission grid and grants.
- [Security and identity FAQ](/administration/identity-faq) for the questions a security review asks.
- [Read the audit log](/administration/audit-log) to prove a provisioning or revocation change took effect.
