# Provider → Organization → Tenant — Identity IA

**Status:** Agreed model (renames + UI restructure on the existing backend).
**Supersedes the confusing flat `Global | Organizations | Tenants` layout.**
**Related:** `saas-identity-pbac.md`, `saas-orgs-regions-compliance.md`.

---

## 1. The model

```
PROVIDER  ── the platform-owner's console (Provider Admin only)
│            • sees ALL organizations + everything beneath (standing, management plane)
│            • TOP-LEFT org switcher (elegant dropdown): "All orgs" or jump into one
│            • manages Provider users + Roles (provider · customer · SSO mappings)
│
└─ ORGANIZATION ── the account — IS a tenant by default
│                  • Org Admin sees only this org
│                  • its own Users + Roles
│
   └─ TENANT ── OPTIONAL — never required. Only when an org splits into
                several isolation units (prod / dev / region).
```

## 2. Naming (UI rename; backend ids unchanged)

| Today (UI) | Becomes | Backend id (UNCHANGED) |
|------------|---------|------------------------|
| "Global" (platform realm) | **Provider** | tenant/org id stays `global` |
| Platform Owner / super-admin@global | **Provider Admin** (sees all) | `isPlatformOwner` |
| Organization | **Organization** (Parent/Child naming optional) | `org` |
| Tenant super-admin | **Org Admin** (own org only) | org-scoped admin binding |
| Tenant | **Tenant** | `tenant` |

> The backend id `global` is load-bearing (RLS, index routing, scope ids). It is
> NOT renamed — only its **display label** becomes "Provider".

## 3. Roles ≠ visibility

The only real difference between admins is **how much they see** — already enforced:
- **Provider Admin** → cross-everything (management plane).
- **Org Admin** → its org (+ the org's tenants).
- **Tenant user** → one tenant.

## 4. Provider vs break-glass (two planes)

- **Provider** = standing **management** visibility (orgs, tenants, users, config, billing).
- **Break-glass** = time-boxed, audited access to a **restricted tenant's actual
  telemetry** (`OperatorRestricted`). Even the Provider must break-glass for a
  compliance-walled tenant's *data*. (§7.1 posture: standing mgmt, zero-standing
  restricted-data, break-glass bridge.)

## 5. Org = tenant (Path A — the SAFE build)

Every org **auto-provisions one default tenant** (= the org). The tenant-keyed
isolation (RLS / OpenSearch / ClickHouse / VictoriaMetrics), verified end-to-end,
is **untouched**. "Tenants optional" is a UI truth; underneath, an org always has
its one default tenant. Extra tenants are created only when an org needs them.
**Rejected:** Path B (make `org_id` the isolation key) — a full rewrite of proven
isolation. Not done.

## 6. Security (no standalone Security Policy section)

Delete the abstract Security Policy editor. Distribute its parameters:
- **Per-user** (require MFA, temp password→must-change, expiry, status, role) →
  the **Create User** form. Shown every time.
- **Scope-wide** (password length/complexity/history, lockout, session/idle) →
  the **Org (and Tenant) setup**, set once, inherited.
- The Create User form shows the **effective** scope-wide policy read-only for
  context (no re-typing). [option (a)]

## 7. Access (cross-cutting — not under "Provider/Global")

- **Access** (grant/revoke bindings: principal → role → scope) = its own area.
- **Access Explorer** ("why does X have access?") stays under **Explain (L3)**.

## 8. Administration layout (target)

```
Administration
├─ Provider             → provider users · roles (provider/customer/SSO) · platform settings
├─ Organizations        → list orgs → drill into one → its users + optional Tenants → tenant users
├─ Access               → grant/revoke (cross-cutting)
├─ Regions
├─ Authentication …
Top-left org switcher    → Provider/Org admins switch org context (elegant dropdown)
Explain (L3)
└─ Access Explorer       → why access? (read-only)
```

## 9. Build order (safe → structural)

1. **Renames** — Global → Provider (display only), badges, labels. Zero risk.
2. **Provider console** — its Users + Roles (provider/customer/SSO) + top-left org switcher.
3. **Org = default tenant** (Path A) + Tenants optional in the UI.
4. **Security fold-in** — remove the section; distribute params (option a).
5. **Access** stays its own area; Access Explorer under Explain.
