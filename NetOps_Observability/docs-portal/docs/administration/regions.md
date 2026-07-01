---
title: Regions
sidebar_label: Regions
sidebar_position: 4
description: Region configuration for multi-region deployments (platform owner).
---

# Regions

Regions let a multi‑region deployment route tenants and their data to the right location. This is a **platform‑owner** capability — configure it at <kbd>Administration → Regions</kbd>.

:::info When you need this
Most single‑region deployments don't need to configure regions at all. Use Regions when you operate Correlix across **multiple geographic locations** and need tenants pinned to a specific region for data residency or latency.
:::

## What a region defines

- A **location/label** for a deployment footprint.
- Which **tenants/organizations** are homed there.
- The routing so a tenant's traffic and data stay in its region.

## Configure a region

1. Go to <kbd>Administration → Regions</kbd> (visible to the platform owner only).
2. Add a region with its label/identifier.
3. Home the appropriate **tenants/organizations** to it.

Region homing composes with tenant isolation — a tenant remains fully isolated *and* pinned to its region.

## Related

- **[Tenants & Organizations](/administration/tenants-orgs)**
- **[Users & roles](/administration/identity-access)**
