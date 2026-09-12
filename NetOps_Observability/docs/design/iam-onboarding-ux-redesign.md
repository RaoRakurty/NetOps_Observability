# IAM Onboarding UX Redesign — Provider · Regions · Orgs · Tenants · Users · Grants

Status: PROPOSAL (2026-07-01) — for owner review before build.

The account/identity model is powerful but the console doesn't make the **order**
or the **dependencies** explicit, so "how do I create X and assign a user" is not
intuitive. This doc grounds the redesign in the real code model, then proposes a
guided, create-then-assign flow with an explicit hierarchy.

## 1. The real model (grounded in code)

```
Provider (platform-owner realm — the root; = the default "Global" org)
│
├── Region                 predefined placement set: us-east(default), us-west,
│                          eu-central, eu-west, ap-southeast  (data residency)
│
├── Organization (Org)     a customer / business unit.
│     • home_region  → picks ONE region (tenants inherit it)
│     • sso_connection (optional) → one IdP for all its tenants
│
│     └── Tenant           the ISOLATION UNIT — holds devices, telemetry, incidents.
│           • org_id       belongs to exactly ONE org (blank ⇒ the Provider/Global org)
│           • region       blank ⇒ inherit the org's home_region
│           • isolation_mode, operator_restricted, status
│
└── Users + Roles + Access Grants
      • User    an identity (local or from an IdP)
      • Role    a permission bundle (scoped)
      • Grant   binds  principal → role → scope(org|tenant)   ← the "assign" step
```

### Mandatory vs optional — the answer to "which is optional?"

| Entity | Required? | Default if you skip it | Create it when… |
| --- | --- | --- | --- |
| **Provider** | Always exists (the root — it's *you*) | — | never — it's the platform owner |
| **Region** | Optional to think about | `us-east` | you need data residency / multi-region |
| **Organization** | **Optional** | the built‑in **Provider/Global** org | you have a separate customer/BU that needs its own region or SSO |
| **Tenant** | **Required** (the unit that holds data) | — | always — this is the workspace you onboard devices into |
| **User** | Required to log anyone in | — | to give a person access |
| **Access Grant** | Required to make a user useful | — | to give a user a role in an org/tenant |

**Key clarifications the UI must state out loud:**
- A **Tenant does NOT require you to create an Org first** — leave the org blank and it lands in the default **Provider** org. Orgs are an *optional grouping* layer for multi‑customer / multi‑BU setups.
- **Region** is a *placement*, not a container — you don't "put users in a region." Orgs pick a home region; tenants inherit it.
- **Provider** isn't something you create — it's the root (the operator).

## 2. What's wrong today

- The admin nav scatters the pieces across separate leaves (**Regions**, **Identity & Access**, **Access Grants**, and tenant/org drill-ins) with **no implied order** and **no visible dependency**.
- Nothing tells you Org is optional or that Tenant is the real unit — so people hunt for "where do I start."
- "Create" and "assign" are entangled — you can land on a form that needs a parent that doesn't exist yet.

## 3. Design principles (from market patterns)

- **Decouple dependency setup from onboarding** — pre-wire defaults (a Provider org, a default region) so creating a tenant is config-only, not a prerequisite chase. *(AWS/Azure 2026 guidance.)*
- **Smart defaults over forced choices** — auto-fill org=Provider, region=inherited; let the user override, don't make them pick. *(AWS auto-populates role names; Auth0 uses management APIs over manual entry.)*
- **Create first, assign later** — creating an entity and granting access are two explicit, separate steps.
- **Role templates, clone-to-customize** — prevent role sprawl. *(WorkOS/LoginRadius.)*
- **IdP-group → role mapping** is the enterprise reality — surface it in the Org's SSO step. *(Okta/Entra.)*

## 4. Proposed redesign

### 4a. One "Identity & Access" home with a live hierarchy

Replace the scattered leaves with a single **Identity & Access** home whose top is a
**hierarchy map** (the diagram in §1, rendered live from real data) + a legend that
marks **Required** vs **Optional** and shows counts:

```
 Provider (you)                                        [Regions ▸ 5]
   └ Organizations  (optional grouping)                        + New org
       ├ Provider / Global · us-east ·  3 tenants · 12 users
       └ Acme Corp        · eu-west  ·  2 tenants ·  8 users · SSO: Okta
           └ Tenants  (required — holds data)                  + New tenant
               ├ acme-prod   · eu-west · dedicated · 6 users
               └ acme-lab    · eu-west · shared    · 2 users
```

Clicking a node drills in (org detail / tenant detail); the map always shows where
you are and what's required next.

### 4b. A guided "Set up access" wizard (the ordered flow)

A single **+ Add** entry opens a wizard that enforces the create-then-assign order,
with smart defaults so simple cases are 2 clicks:

```
Step 1  What do you want to create?
        ( ) A tenant (a workspace to monitor a network)     ← most common
        ( ) An organization (group several tenants/customers)
        ( ) A user
        ( ) A grant (give a user access)

Step 2  (Tenant) Name  ▸  Org [ Provider ▾ (default) ]  ▸  Region [ inherit ▾ ]
        ▸ Isolation [ shared ▾ ]        [ Advanced ⌄ ]
        "This tenant will hold devices, telemetry and incidents. Org is optional —
         leave it as Provider unless you're grouping customers."

Step 3  (optional) Add users now?  →  invite by email / create local  →  assign role + scope
        else "Skip — you can add users any time under Users."
```

- The wizard **only asks for a parent that exists** (org list is pre-populated incl. the default).
- Each optional field shows an explicit **"(optional — default: X)"** hint.
- At the end: a **summary card** "Acme-prod tenant created in Provider org, us-east, shared. 0 users — add some?" with a one-click "Add users."

### 4c. Create-then-assign, everywhere

- **Users** page: create/invite a user (no role needed) → they exist with no access.
- **Access Grants** becomes **"Assign access"**: pick an existing **user** → **role** →
  **scope** (org or tenant, from a tree picker). This is the *only* place assignment
  happens, and it always references things that already exist.
- Every entity detail page has an **"Access" tab** showing who's granted here + an
  **Assign** button (so you can assign from context, not just the global page).

### 4d. Make optionality explicit in the UI

- Section headers carry a chip: **Required** / **Optional** / **Inherited**.
- The Tenant form's Org field: label "Organization *(optional)*" with helper
  "Leave as **Provider** if you're not grouping customers."
- Region field: "Region *(inherited from org: eu-west)*" — pre-filled, overridable.

## 5. How it all ties together (the flow)

```
        ┌─────────────────────────────────────────────────────────────┐
        │ 1. (rare) Define REGIONS         platform · data residency   │
        └───────────────┬─────────────────────────────────────────────┘
                        │ (default us-east already exists)
        ┌───────────────▼─────────────────────────────────────────────┐
        │ 2. (optional) Create ORG         picks home region + SSO     │
        │    skip → default "Provider" org                             │
        └───────────────┬─────────────────────────────────────────────┘
                        │
        ┌───────────────▼─────────────────────────────────────────────┐
        │ 3. Create TENANT   (REQUIRED)    org (or default) + region   │
        │    → the workspace you onboard DEVICES into                  │
        └───────────────┬─────────────────────────────────────────────┘
                        │
        ┌───────────────▼──────────────┐   ┌──────────────────────────┐
        │ 4. Create/invite USER        │   │  Roles (templates)       │
        └───────────────┬──────────────┘   └───────────┬──────────────┘
                        │                               │
        ┌───────────────▼───────────────────────────────▼─────────────┐
        │ 5. ASSIGN ACCESS (grant)   user → role → scope(org|tenant)   │
        └──────────────────────────────────────────────────────────────┘
```

Create flows **down**; access is **granted** at the end and can target any scope.

## 6. Build plan (phased, if approved)

1. **Hierarchy map + legend** on the Identity & Access home (read-only first — high
   clarity, low risk).
2. **Explicit optionality** on the existing Tenant/Org forms (labels, defaults,
   inherited hints) + "create tenant without org → Provider" made obvious.
3. **Guided "+ Add" wizard** (tenant / org / user / grant) with smart defaults.
4. **"Assign access"** rename + tree-scope picker + per-entity Access tab.
5. Role **templates / clone-to-customize**; Org **SSO group→role** mapping surfaced.

Phases 1–2 are the quickest wins and directly answer "which is optional / where do I
start." 3–5 make the whole thing feel guided.

## Sources (market patterns)
- WorkOS — multi-tenant RBAC design (role templates, clone-to-customize).
- LoginRadius — access control for B2B/multi-tenant (per-org role differences).
- Microsoft Entra — multitenant organizations (IdP group→role mapping).
- AWS/Azure 2026 onboarding guidance — decouple dependency setup; smart defaults.
