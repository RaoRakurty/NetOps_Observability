---
title: Set a data-residency region
sidebar_label: Regions
description: Set where an organization's and a tenant's data is meant to live, and read what a region does in this build.
page_type: task
sidebar_position: 8
---

# Set a data-residency region

A region records where a tenant's telemetry is meant to live. One global control plane holds organizations, identity, access and the tenant registry, and routes each tenant to the data plane its region names. Assign regions from the day you create an account, so the residency intent is on record before there is anything to move.

## Before you begin

- **Permission:** `administration:admin` to read the region catalog at `GET /api/regions`. The catalog is a fixed list and carries no tenant data.
- **Permission:** platform administrator for everything else. `GET /api/regions/topology` calls `requireCrossTenant`, and assigning a region means creating or patching an organization or tenant, which is platform-global. The console hides the whole Platform section, **Platform → Tools → Regions** with it, from a tenant administrator.
- Know which organization the tenant belongs to. A tenant inherits its organization's home region unless you override it.

## What a region does in this build

Be precise about this before you use it as a compliance control.

**A region does** record residency intent on an organization and on each tenant, drive the routing model that resolves a tenant to a data plane, and show which tenants and organizations sit in which region.

**A region does not** move data on its own, and it does not enforce residency by itself. Every region resolves to the local in-cluster stack until a regional data plane is configured for it. Lighting up a real region is deployment configuration, one environment variable per region named `REGION_DATAPLANE_<REGION>`, and it changes nothing about organizations, tenants, users or access. That is the point of recording regions early.

The catalog is fixed and curated. There is deliberately no way to create a region from the console, so a typo can never become a residency destination. Adding one is a platform change, because it asserts that a data plane exists or will exist there.

## Steps

### Read the catalog

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/api/regions
```

```json
[
  { "id": "ap-southeast", "label": "Asia Pacific (Southeast)" },
  { "id": "eu-central",   "label": "EU Central" },
  { "id": "eu-west",      "label": "EU West" },
  { "id": "us-east",      "label": "US East" },
  { "id": "us-west",      "label": "US West" }
]
```

Five regions ship, sorted by id. `us-east` is the default assigned when no region is given. A region outside this set is refused on save, never accepted and quietly normalised.

### Set an organization's home region

1. Open **Administration → Identity & Access → Organizations**.
2. Create the organization with **＋ Create organization**, or open an existing one and select **Edit**.
3. Pick the **Region**. It is required on creation. The guided **＋ Add** wizard asks the same question as **Home region**.
4. Save.

Every tenant in that organization inherits this region unless it carries its own.

### Set or inherit a tenant's region

1. In the wizard's **Tenant** step, the **Region** field defaults to the inherited option, which names the organization and its region.
2. Leave it inherited unless this one tenant genuinely differs, for example a customer's EU subsidiary under an organization homed in the United States.
3. To change it later, patch the tenant's region from **Identity & Access → Organizations → (org) → Tenants**.

Region assignment composes with tenant isolation. A tenant stays fully isolated and additionally carries its residency record.

### Read the region topology

**Platform → Tools → Regions** is an inventory of the deployment's region topology, not a control panel.

- The stat strip shows the control plane, the regions in use, and the tenant and organization counts.
- The diagram shows the global control plane routing to a card per region, each with a **Local** or **Dedicated** data-plane badge and its tenant and organization counts.
- The table lists one row per region with its data plane, tenant count, organization count and endpoint.

`GET /api/regions/topology` returns the same numbers, with a `control_plane` object holding `orgs`, `tenants` and `users`, and a `regions` array. Each region entry carries `id`, `label`, `tenants`, `orgs` and a `data_plane` object. In a single-region deployment every `data_plane` reads `"local": true` and names the in-cluster backends. That response includes internal service endpoints, so treat it as operator-only output.

## Result

The organization appears under its region in the topology diagram immediately after creation, and **Regions in use** counts every region you have assigned. In a single-region deployment every row's data plane reads Local, which is correct and expected. `GET /api/tenants` shows the tenant with the region it inherited or the one you set.

## Related

- [Create tenants and organizations](/administration/tenants-orgs) for the objects a region attaches to.
- [Add users and grant access](/administration/identity-access) for the tree that shows each tenant's effective region.
- [Deployment overview](/deploy/overview) for what standing up a second data plane involves.
