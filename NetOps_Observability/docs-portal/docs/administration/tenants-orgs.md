---
title: Tenants & Organizations
sidebar_label: Tenants & Organizations
sidebar_position: 5
description: Create isolated tenants and the organization layer above them.
---

# Tenants & Organizations

Correlix is multi‑tenant. A **tenant** is a fully isolated view — its own devices, telemetry, incidents, users, and roles. An **organization** is an optional account layer *above* tenants, for operators who manage many customers.

## The model

- **Tenant** — the isolation boundary. A tenant never sees another tenant's data, on any surface.
- **Organization** — groups tenants under one account; org admins can be granted access across the org's tenants.
- **Platform owner** — the cross‑tenant super‑admin who creates tenants/orgs and manages the platform.

## Create a tenant

1. Go to <kbd>Administration → Identity & Access</kbd> → **Tenants**.
2. Create a tenant (name + handle). Correlix mints an **opaque, immutable id** (like the major clouds) and a human‑friendly **slug**.
3. Drill into the tenant to add its **[users and roles](/administration/identity-access)** and configure tenant‑scoped settings.

## Onboarding a new customer

A typical new‑customer flow:

1. Create the **tenant** (or organization + tenant).
2. Create tenant **admin users**, or connect **[SSO](/administration/authentication)** and map their IdP group to a tenant admin role.
3. Onboard the customer's **[devices](/onboard-devices/overview)** into that tenant.

Everything the customer sees — dashboards, incidents, AI answers — is automatically scoped to their tenant.

## Isolation guarantees

Isolation is enforced at every layer (queries, storage, search, and the AI), not just the UI. A tenant admin holds full administrative rights **within their tenant** but has no visibility into the platform or other tenants.
