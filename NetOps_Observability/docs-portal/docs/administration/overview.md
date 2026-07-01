---
title: Administration overview
sidebar_label: Overview
sidebar_position: 1
description: Configure users, access, authentication, API access, tenants, regions, and audit.
---

# Administration

Administration is where you configure *who* can use Correlix and *how*, plus platform‑level settings. It lives in the **Administration** section pinned near the bottom of the icon rail.

## Two kinds of administrator

Correlix distinguishes two administrative audiences, and the console adapts to which one you are:

- **Platform operator** — the cross‑tenant owner of the deployment. Sees the full Administration tree, creates organizations and tenants, and manages platform plumbing (regions, collectors, system network settings).
- **Tenant / organization admin** — administers *their own* scope. Holds full administrative rights inside their tenant or organization, but never sees another tenant, the platform configuration, or the platform‑operator menu items.

Menu items reserved for the platform operator are simply hidden from tenant admins. This is a courtesy, not the security boundary — the backend enforces the same rule independently, so a hidden endpoint called directly still returns **403**.

## The Administration menu, mapped

| Area | Console path | What it's for | Who sees it |
| --- | --- | --- | --- |
| **[Settings](/administration/system-settings)** | <kbd>Administration → Settings</kbd> | Default landing page, **DNS** and **NTP** (platform operators only), log export limits | All admins (some cards platform‑only) |
| **Data Sources** | <kbd>Administration → Data Collection → Data Sources</kbd> | Per‑device telemetry status — see [Data sources](/onboard-devices/data-sources) | All admins |
| **Collectors** | <kbd>Administration → Data Collection → Collectors</kbd> | The ingestion/poller plumbing itself | **Platform operators only** |
| **SNMP Profile Manager** | <kbd>Administration → Data Collection → SNMP Profile Manager</kbd> | [SNMP credentials and vendor profiles](/onboard-devices/snmp-profiles) | All admins |
| **[Regions](/administration/regions)** | <kbd>Administration → Regions</kbd> | Data‑residency regions and which tenants live where | **Platform operators only** |
| **[Identity & Access](/administration/identity-access)** | <kbd>Administration → Identity & Access</kbd> | Organizations, tenants, users, roles, security settings — plus the guided **＋ Add** setup wizard | All admins (scoped to what they own) |
| **[Assign access](/administration/identity-access#grant-access-bindings)** | <kbd>Administration → Assign access</kbd> | Grant a person a role on an organization; review and revoke grants | All admins (scoped) |
| **Sessions** | <kbd>Administration → Sessions</kbd> | Live sign‑in sessions with per‑session revoke | **Platform operators only** |
| **[Authentication](/administration/authentication)** | <kbd>Administration → Authentication</kbd> | Local accounts, SSO (OIDC), LDAP/AD, TACACS+, MFA | All admins |
| **[API Access](/administration/api-access)** | <kbd>Administration → API Access</kbd> | API keys, token policy, live REST API reference | All admins (scoped) |
| **Audit Log** | <kbd>Administration → Audit Log</kbd> | Every security‑relevant action, allow and deny | All admins (scoped) |

The **Stack** section (the platform's self‑observability and raw backend tools) is a separate icon‑rail entry and is also platform‑operator‑only.

## The Audit Log

<kbd>Administration → Audit Log</kbd> is the scoped trail of every mutation and every denied request. The platform operator sees all events; a tenant admin sees only their own tenant's.

Each row shows: **Time** · **Actor** · **Tenant** (`platform` for cross‑tenant events) · **Action** (method + API path, e.g. `POST /api/devices`) · **Status** (HTTP code) · **Decision** (**allow** / **deny** pill) · **From** (source IP). Denied requests are highlighted in red. The view shows the most recent 300 events and refreshes automatically every 20 seconds; click a column header to sort.

Use it to answer "who changed this?", "who tried and was refused?", and to verify that a permission change actually took effect.

## Common tasks

| I want to… | Go to |
| --- | --- |
| Onboard a new customer (org + tenant + first user) | [Identity & Access — the guided ＋ Add wizard](/administration/identity-access#guided-add-wizard) |
| Add a user | [Identity & Access → Users](/administration/identity-access#add-a-user) |
| Give someone a role in an organization | [Assign access](/administration/identity-access#grant-access-bindings) |
| Connect our identity provider (SSO / LDAP / TACACS+) | [Authentication](/administration/authentication) |
| Suspend or reactivate a tenant | [Tenants & Organizations](/administration/tenants-orgs#suspend-a-tenant) |
| Mint a credential for a script or CI pipeline | [API access](/administration/api-access#generate-an-api-key) |
| Point the platform at our DNS/NTP servers | [System settings](/administration/system-settings) |
| Check the platform's clock offset | [System settings → NTP](/administration/system-settings#ntp-time-sources) |

## Verify your own scope

Not sure which administrator you are? Two quick checks:

1. Look at the icon rail. If you can see **Stack**, and **Regions** / **Sessions** / **Collectors** under Administration, you are the platform operator.
2. Open <kbd>Administration → Identity & Access</kbd>. The platform operator sees the **Provider / Organizations** tabs and the hierarchy map; a tenant admin sees only *"Users, roles and security settings for your tenant."*

## Troubleshooting

- **A menu item described in these docs isn't in my console.** You're signed in as a tenant or org admin and the item is platform‑operator‑only (Regions, Collectors, Sessions, the Stack section, the DNS/NTP cards in Settings). Ask your platform operator.
- **I can open a page but saving returns "forbidden".** The backend enforces scope independently of the menu. Some pages render for any admin but only accept changes from the platform operator (for example, log export limits). The denied call appears in the Audit Log with decision **deny**.
- **I made a change and want to prove it happened.** Every administrative mutation is audited. Open <kbd>Administration → Audit Log</kbd> and look for your username in **Actor** with the matching **Action**.
