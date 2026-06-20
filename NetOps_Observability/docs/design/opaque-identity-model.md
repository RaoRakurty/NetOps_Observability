# Opaque Identity Model — org/tenant ids matched to AWS/Azure/GCP

**Status:** proposed (phased) · **Created:** 2026-06-20 · Owner-directed ("full
opaque-ID refactor") · Builds on [org-tenant-model.md](org-tenant-model.md).

## 1. Why

Today Correlix mints `ID = Slug = slugify(name)` for both orgs (`orgs.go:129`)
and tenants (`tenants.go:188`), and every piece of customer data is tagged with
that name-derived string (`Device.TenantID = "acme"`, PG `tenant_id`, OpenSearch
per-tenant index, VictoriaMetrics label, ClickHouse scope, file/kv key).

AWS, Azure and GCP **all** deliberately avoid keying data off a human/name-derived
string. The validated, unanimous pattern (see research below) is a **two-part
identity**:

| Cloud | Opaque internal key (immutable, system-minted) | Human handle(s) |
|---|---|---|
| AWS | 12-digit Account ID | account name (mutable) + unique alias |
| Azure | Tenant **GUID** (Directory ID) | display name + immutable `*.onmicrosoft.com` + verified domains |
| GCP | Org **number** / Project **number** | display name + globally-unique **immutable** project ID (slug) |

Plus three load-bearing rules they share: (a) opaque immutable key separate from
the display name; (b) policy inheritance from a single root, default-closed
(Correlix already has this — `principalTenant` + FORCE-RLS); (c) provisioning is
a privileged, **audited** control-plane action by an authorized principal, never
implicit/agentic (Correlix already gates with `requirePlatformAdmin`).

**Only (a) is missing.** This doc makes the internal key opaque and immutable and
separates it from a mutable display name + an immutable, globally-unique slug.

## 2. Target model

```
Org    { ID: "o_<24hex>"  (opaque, immutable, system-minted)
         Slug: "acme"     (human, globally-unique, validated, immutable-once-set)
         Name: "Acme Inc" (display, mutable) }
Tenant { ID: "t_<24hex>"  (opaque, immutable, system-minted)
         Slug: "acme-prod"
         Name: "Acme Production"
         OrgID: "o_<24hex>" }
```

- **Canonical data key everywhere = the opaque `ID`.** Claims carry it,
  `principalTenant` returns it, every store/data-plane tags + filters on it.
- **Slug** is the human/URL handle. Resolved to the opaque `ID` once, at the API
  boundary (path params, `?as_tenant=`, import payloads accept slug **or** id).
- **Name** is display only — never a key, freely renamable (matches all 3 clouds).
- **`global` / `OrgGlobal` keep their well-known sentinel ids** (platform-owned /
  untagged). Opaque ids are for real customers only.

## 3. The zero-data-risk principle (the crux)

A live multi-tenant system already has data tagged with the *current* slug-ids
across five data planes. Rewriting all of it is the dangerous part. We avoid it:

> **Existing orgs/tenants keep `ID == their current slug`. Only NEW customers get
> opaque ids.**

An already-readable legacy id still satisfies the external contract — it is
*stable and immutable*; "opaque" is a property of *new* mints. AWS/GCP carry
legacy accounts the same way. This means **no device re-tag, no PG/CH row rewrite,
no OpenSearch reindex, no VM relabel** — existing tenants' data keeps resolving
because their id is unchanged. Going forward every new customer is fully opaque,
name-decoupled, slug/display-separated.

Slug uniqueness is enforced across BOTH legacy (id==slug) and new tenants, so a
new tenant whose `slugify(name)` collides with a legacy id is rejected — no
ambiguity. (An optional, separately-approved Phase 5 can backfill-rename legacy
data to fully-opaque ids; not required for the contract and not in this plan.)

## 4. Blast radius (110 Go files touch tenant identity)

| Layer | Change |
|---|---|
| **Identity model** (`orgs.go`, `tenants.go`) | add opaque `ID` mint; `Slug` = validated, unique, immutable; `Name` mutable. Existing → `ID=Slug`. |
| **Resolution boundary** (`tenancy.go`, `identity_handlers.go`, `org_handlers.go`) | accept slug **or** id on every ingress; resolve to opaque id; claims & `principalTenant` return the id. `as_tenant` resolves slug→id. |
| **Scopes/bindings** (`scopes.go`, `access.go`, `bindings.go`) | `tenant:<id>` / `org:<id>` use the opaque id; `scopeParent` lookups unchanged (Get by id). |
| **Stores** (PG `withTenant` GUC + `tenant_id` cols; `tenantKV`; in-memory) | no schema change — the value carried just becomes opaque for new rows. |
| **Data planes** (`clickhouse*`, `logs.go`/OpenSearch index naming, `metrics*`/VM labels, `telemetry_enrichment.go`) | key off opaque id; new per-tenant OS indices / VM labels are id-named from creation. |
| **Frontend** | display `Name`; use `Slug` in URLs; never show the opaque id except in an "advanced/details" affordance (like a cloud console shows the account/tenant id). |
| **Tests** | isolation tests assert id↔slug separation, rename-doesn't-move-data, slug-uniqueness, cross-tenant-by-id→404. |

## 5. Onboarding (operator-driven, audited — matches the clouds)

Provisioning stays a **platform-owner** action (`requirePlatformAdmin`); the AI
agent never onboards customers. Add an operator **"Onboard customer"** flow that,
in one audited step, creates: the **org** (mint `o_…`, slug, name, home region) →
its **first tenant** (mint `t_…`, slug, name) → optional **SSO connection** at the
org (inherited by tenants). Emits an `ONBOARD_*` / `ORG_CREATED` / `TENANT_CREATED`
audit event with the acting principal — the CloudTrail/Entra-audit analog. This
also fixes the earlier question: an org is never left tenant-less — onboarding
always creates the first tenant (the data boundary).

## 6. Phased plan (safety-gated; build+test green between phases)

- **Phase 1 — additive identity (no behavior change).** Add opaque `ID` mint +
  slug validation/uniqueness/immutability to `orgs.go`/`tenants.go`; existing →
  `ID=Slug`; `global`/`OrgGlobal` unchanged. New helper `resolveTenantRef(s)` and
  `resolveOrgRef` (slug-or-id → opaque id). Unit tests. **Risk: none** (new mints
  only; nothing reads the new ids yet).
- **Phase 2 — boundary resolution.** Route handlers + `as_tenant` + import resolve
  slug-or-id via the new helpers; claims carry the opaque id; `principalTenant`
  returns it. Cross-org isolation tests still green. **Risk: low** (resolution is
  identity for legacy id==slug).
- **Phase 3 — data planes.** Confirm OS index / VM label / CH scope / enrichment
  CSV all derive from the opaque id; add a new-tenant smoke test (id-named index/
  label). **Risk: low** (legacy unchanged; only new tenants differ).
- **Phase 4 — onboarding UX + audit.** Operator wizard (org+tenant+SSO), audit
  events, slug uniqueness UI. Frontend uses slug in URLs, name for display.
- **Phase 5 (optional, separately approved) — legacy backfill.** Rewrite legacy
  data to fully-opaque ids (device re-tag + PG/CH/OS/VM migration). **Risk: high
  — not in this plan.**

## 7. Non-goals

No change to the isolation *enforcement* (RLS/chScope/osFilter/VM-label stay —
they just carry an opaque value). No multi-region data-plane routing (separate
roadmap). No self-service customer signup (operator-led only, for now). No legacy
data rewrite unless Phase 5 is separately approved.
