---
title: Administration
sidebar_label: Overview
description: Users, roles, tenants, authentication, API access, audit and data-collection administration, for whoever runs the deployment.
page_type: index
sidebar_position: 1
---

# Administration

Administration holds the configuration that decides who signs in, what each person may reach, and how telemetry is shaped before it is stored. The section is written for two readers: the platform administrator who owns the whole deployment, and the tenant or organization administrator who owns one workspace inside it.

## The two planes

Every Administration surface sits on one of two planes, and the plane decides which check opens it.

**Per-tenant data** is gated by a per-tenant permission check plus a tenant filter. The permission is a module and a level, such as `administration:admin` or `infrastructure:read`. The filter restricts the answer to the caller's own tenant. Devices, processors, API keys, security settings and the audit trail are per-tenant.

**Platform-global plumbing** is gated by a platform-admin or cross-tenant check. Authentication providers, LLM provider keys, token policy, notification channels and stack configuration are platform-global. A tenant or organization administrator holds full `administration:admin` inside their own tenant, so a scope-blind admin check on platform-global configuration would be a privilege leak. Those routes call `requirePlatformAdmin` or `requireCrossTenant` instead, which ask an identity question: is the caller the platform owner?

Every Administration task page names its permission and its plane in the first bullet of `## Before you begin`. A reader should never discover a `403` by trying.

## Tenant isolation

A tenant is the isolation boundary. Every piece of customer data carries exactly one tenant id, and the rules below hold on every data-returning surface.

| Rule | Behaviour |
| --- | --- |
| Scoped by the principal | Every list, get, search, aggregate and export is filtered to the caller's tenant, default-closed. |
| Cross-tenant get by id | Returns `404`, identical to an id that does not exist, so another tenant's ids are never revealed. |
| Cross-tenant write or delete | Refused. |
| Owner on create and update | Stamped from the authenticated principal. A tenant in the request body is ignored. |
| One tenant at a time | A cross-tenant principal opens a single tenant through the organization and tenant picker. The choice rides on the `X-Acting-Tenant` header (or the `as_tenant` query parameter) and follows every page, query and export. |
| Single-tenant principals | Never gated by the picker, and never able to widen their reach with it. |
| No "all tenants" telemetry view | Deliberate. The platform owner's Global view is the only cross-tenant read, and it is the platform owner's alone. |

Organization isolation is derived from tenant isolation: an organization is its tenants. There is no separate cross-organization grant.

## The Administration pages

| Page | What you do there |
| --- | --- |
| [Add users and grant access](/administration/identity-access) | Create people, pick their role, and grant a role at an organization scope. |
| [Create tenants and organizations](/administration/tenants-orgs) | Create the isolation units and the account layer above them, suspend and delete. |
| [Configure authentication](/administration/authentication) | Local accounts, password and lockout policy, MFA, OIDC single sign-on, LDAP and TACACS+. |
| [Connect Okta as an identity provider](/administration/okta-sso) | The worked Okta bring-up through the bundled Keycloak broker. |
| [Mint an API key](/administration/api-access) | Machine credentials, token policy and the generated REST reference. |
| [Read the audit log](/administration/audit-log) | Who changed what, who was refused, and how to filter it. |
| [Set a data-residency region](/administration/regions) | Record where a tenant's data is meant to live. |
| [Configure system settings](/administration/system-settings) | Landing page, time display, DNS, NTP and log-export limits. |
| [Shape data with a pipeline processor](/administration/processors) | Mask, drop, hash and tag fields before storage, with a dry-run preview. |
| [Review sensitive-data access](/administration/sensitive-data-access) | The compliance read-back of every attempt to reveal a sealed value. |
| [Check telemetry parser coverage](/administration/telemetry-coverage) | What the parser recognises, and what your network says that it does not. |

## The console map

The labels below are the ones the console shows. A leaf marked platform-only is hidden from a tenant administrator, and the backend refuses it independently, so calling the route directly still returns `403`.

| Console path | Plane | Who sees it |
| --- | --- | --- |
| **Administration → Incident Response → Integrations** | Per-tenant | All administrators |
| **Administration → Incident Response → Notifications** | Platform-global | Platform administrator only |
| **Administration → Incident Response → Ticketing & Automation** | Per-tenant | All administrators |
| **Administration → Data Collection → Data Sources** | Per-tenant | All administrators |
| **Administration → Data Collection → SNMP Profiles** | Per-tenant | All administrators |
| **Administration → Data Collection → Sensors** | Platform-global | Platform administrator only |
| **Administration → Data Collection → Processors** | Per-tenant | All administrators |
| **Administration → Data Collection → Sensitive Data Access** | Per-tenant | Holders of `sensitive_data:admin` |
| **Administration → Data Collection → Telemetry Coverage** | Both halves on one page | All administrators, parser statistics are platform-only |
| **Administration → Identity & Access** | Per-tenant | All administrators, scoped to what they own |
| **Administration → Platform Security → Authentication** | Platform-global | Platform administrator only |
| **Administration → Platform Security → Access Explorer** | Per-tenant | All administrators |
| **Administration → Platform Security → Sessions** | Platform-global | Platform administrator only |
| **Administration → Platform Security → Audit Log** | Per-tenant | All administrators |
| **Administration → Platform Security → Transport Security** | Per-tenant | All administrators |
| **Administration → Platform → Regions · Stack Health · Self-Monitoring · Search Dashboards · GraphQL Explorer** | Platform-global | Platform administrator only |
| **Administration → API Access** | Mixed | All administrators, token policy is platform-only |
| **Administration → Settings** | Mixed | All administrators, DNS and NTP are platform-only |

## Which administrator am I?

Open **Administration → Identity & Access**. A platform administrator sees the Organizations tree with the Provider realm as a clickable root row. A tenant administrator sees one page headed "Users, roles and security settings for your tenant", with no tree and no picker. The second check is the icon rail: the **Platform** group under Administration appears only for the platform administrator.

## Related

- [Permissions and honest states](/reference/honest-states) for what an empty answer means on each surface.
- [Feature flags](/reference/feature-flags) for every `FEATURE_` and `ENABLE_` switch and its shipped default.
- [Troubleshooting](/reference/troubleshooting) for the symptom index.
