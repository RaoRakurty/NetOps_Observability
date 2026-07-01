---
title: Administration overview
sidebar_label: Overview
sidebar_position: 1
description: Configure users, access, authentication, API access, tenants, regions, and audit.
---

# Administration

Administration is where you configure *who* can use Correlix and *how*, plus platform‑level settings. Most items live under the **Administration** section pinned near the bottom of the icon rail.

| Area | Console path | What it's for |
| --- | --- | --- |
| **Settings** | <kbd>Administration → Settings</kbd> | General instance settings |
| **Data Collection** | <kbd>Administration → Data Collection</kbd> | [Data Sources](/onboard-devices/data-sources), Collectors, [SNMP Profile Manager](/onboard-devices/snmp-profiles) |
| **[Identity & Access](/administration/identity-access)** | <kbd>Administration → Identity & Access</kbd> | Users, roles, security settings (Global + per‑Tenant) |
| **Access Grants** | <kbd>Administration → Access Grants</kbd> | Grant a principal a role in a scope |
| **[Authentication](/administration/authentication)** | <kbd>Administration → Authentication</kbd> | SSO (OIDC/SAML), LDAP, TACACS+, MFA |
| **[API Access](/administration/api-access)** | <kbd>Administration → API Access</kbd> | API keys, token policy, REST reference |
| **[Regions](/administration/regions)** | <kbd>Administration → Regions</kbd> | Region routing (platform owner) |
| **Audit Log** | <kbd>Administration → Audit Log</kbd> | Every security‑relevant action |

:::info Scope matters
Some items are **platform‑owner only** (Regions, Collectors, Sessions, Stack) — a tenant admin manages their own tenant, never the platform. The backend enforces this independently of the UI.
:::
