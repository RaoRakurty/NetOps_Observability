---
title: Regions
sidebar_label: Regions
sidebar_position: 4
description: Region configuration for multi-region deployments (platform owner).
---

# Regions

Regions record **where each tenant's data is meant to live**. One global control plane (organizations, identity, access, tenant registry) routes tenants to a regional data plane by their assigned region. This entire area is **visible to platform operators only** — open it at <kbd>Administration → Regions</kbd>.

:::info Honest scope — what regions do today
Today, regions are a **governance and data‑residency attribute** on organizations and tenants, plus the routing model that will act on it. In a single‑region deployment every region routes to the local stack — the Regions page itself says so: *"Single‑region today: every region routes to the local stack. To stand up a real region, point its data plane at a regional deployment — no code change."* Assign regions from day one so residency intent is recorded; lighting up a real second region later is a deployment‑configuration step, not a migration of your account model.
:::

## The region catalog

Regions are a fixed, curated catalog — you assign them, you don't invent them:

| Region ID | Label |
| --- | --- |
| `us-east` | US East *(the default)* |
| `us-west` | US West |
| `eu-central` | EU Central |
| `eu-west` | EU West |
| `ap-southeast` | Asia Pacific (Southeast) |

Extending the catalog is a platform change, not a console action — there is deliberately no "create region" button, so a typo can never become a residency destination.

## Reading the Regions page

The page is an inventory of your deployment's region topology:

- **Stat strip** — **Control plane** (*Global*), **Regions in use**, **Tenants**, **Organizations**.
- **Topology diagram** — the global control plane box (*Orgs · Identity · RBAC · Tenants · Billing*) routing down to a card per region in use, each showing its label, a **Local** or **Dedicated** data‑plane badge, and its tenant/org counts.
- **Region table** — one row per region: **Region · Data plane · Tenants · Orgs · Endpoint** (*in‑cluster* for the local stack, or the configured regional endpoint for a dedicated one).

## Assign a region

Regions attach at two levels, with inheritance:

- An **organization** has a home region — **every tenant inherits it** unless overridden.
- A **tenant** may override with its own region at creation.

### Set an organization's region

1. When creating the org — <kbd>Administration → Identity & Access → Organizations</kbd> → **＋ Create organization** — the **Region** field is *required*: pick from the catalog. (The guided **＋ Add** wizard and **＋ Onboard customer** ask the same question as **Home region**.)
2. To change it later, click **Edit** on the organization's row and pick a new region. The Organizations list shows each org's current **Data region** badge.

### Set (or inherit) a tenant's region

1. In the guided wizard's **Tenant** step, the **Region** dropdown defaults to *"From \{org\} (\{region\})"* — inherited. Leave it to inherit.
2. Pick an explicit region only when one tenant genuinely needs to differ from its organization (for example, a customer's EU subsidiary under a US‑homed org).

Region assignment composes with tenant isolation — a tenant stays fully isolated *and* carries its residency intent.

## Standing up a real second region

When you deploy a regional data plane, the platform operator points a region at it through deployment configuration (per‑region data‑plane endpoints); the console then shows that region's data plane as **Dedicated** with its endpoint, and tenants homed there route to it. No changes to organizations, tenants, users, or access are needed — that is the point of recording regions early. Coordinate this step with whoever operates your deployment; it is not a console workflow.

## Verify

- <kbd>Administration → Regions</kbd> — **Regions in use** counts every region you've assigned, and each region card shows the expected tenant/org counts.
- A new organization appears under its region in the topology diagram immediately after creation.
- In a single‑region deployment, every row's **Data plane** reads *Local* and **Endpoint** reads *in‑cluster* — that is correct and expected.

## Troubleshooting

- **I don't see Regions in my menu.** It's platform‑operator‑only. Tenant and org admins never manage residency.
- **I need a region that isn't listed.** The catalog is fixed by the platform; raise it with your platform team rather than picking a "nearest" wrong region — the assignment is your residency record.
- **A tenant shows the "wrong" region.** Check whether it inherited its org's home region or was overridden at creation; the hierarchy map on [Identity & Access](/administration/identity-access) shows each tenant's effective region.
- **Two regions, one data plane?** Expected until a dedicated regional data plane is configured — regions record intent first, routing follows deployment.

## Related

- **[Tenants & Organizations](/administration/tenants-orgs)** — where regions are inherited from.
- **[Identity & Access](/administration/identity-access)** — the hierarchy map shows regions per org and tenant.
