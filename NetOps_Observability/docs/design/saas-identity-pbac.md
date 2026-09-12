# SaaS Identity & Access — Principal-Based Access Control (PBAC)

**Status:** IMPLEMENTED — Phases A–E shipped (commits `5c63832` → `40ee846`),
behaviour-preserving, CI-gated. Remaining depth flagged inline in §6.
**Author:** Platform / NetOps_Observability
**Supersedes (evolves):** the single-`role`+single-`tenant_id` model in `rbac.go` /
`tenancy.go` / `authz.go`; builds on the Org layer (`orgs.go`, commit `119dcd0`).
**Related:** `docs/design/postgres-rls.md`, `docs/design/multitenant-telemetry-isolation.md`,
`docs/design/tls-architecture.md`, `docs/TRACKER.md` (Tenancy & isolation).

---

## 0. Why this doc exists

The current identity model is **scaffold-grade**: correct for single-tenant /
small multi-tenant, wrong for commercial SaaS. A structured review surfaced a
set of P0/P1/P2 findings; this doc records the agreed target model, the
evaluation semantics, the performance architecture, and a **non-breaking**
migration. It is the propose-half of the team's propose → review → build rule.

### What's wrong with today's model

| # | Finding | Severity |
|---|---------|----------|
| 1 | A user is pinned to **one tenant + one role**. Breaks MSP / consultant / SRE / cross-org auditor. | **P0** |
| 2 | Scope is **implicit** (inferred from `user.tenant_id`), not an explicit, auditable declaration. | **P0** |
| 3 | No explicit **`(principal, role, scope)` binding** record — RBAC can't be audited (SOC2/ISO). | **P0** |
| 4 | The **Global tenant** doubles as control plane + data plane + super-admin bypass. | **P0** |
| 5 | Identity is modelled as a strict **tree**; SaaS needs a graph (shared services, cross-org, break-glass). | P1 |
| 6 | Roles are **coarse** (module→level); no resource/feature/data-level permissions. | P1 |
| 7 | No explicit **resource-authorization** model (device/dashboard/alert ACLs implied, not declared). | P1 |
| 8 | **Identity / authorization / policy-evaluation** are merged into RBAC roles. | P1 |
| 9 | "Org owns ≥1 tenant" is rigid; need system / sandbox / shared tenants. | P2 |
| 10 | No **service / agent / device** identity (only `user` + `api-client`). | P2 |
| 11 | No **scoped audit** (org-level vs tenant-level audit visibility). | P2 |

> **On finding #2 (the framing):** a role's permission grid is — and must remain —
> **fixed and invariant**. What varies is the *data a binding points at*. The
> defect is not mutable roles; it is that scope is implicit. Making scope an
> explicit binding (finding #3) is the fix, and #2 folds into it.

### Root cause

Three independent axes are partially entangled:

1. **Identity** — *who/what* you are (user / service / agent / device).
2. **Authorization** — *what* you may do (role = permission grid/rules).
3. **Scope** — *where* you may do it (platform / org / tenant / resource).

The target model separates them explicitly. Every P0 collapses once they're
separated.

---

## 1. Target model — three explicit axes

```
①  IDENTITY (Principal)              ②  BINDING (the join — the auditable record)   ③  SCOPE (resource tree)
   principal_id                          principal_id  ─┐                              platform
   type: user|service|agent|device       role_id        │  a principal has             └─ org
   display, status                       scope_type      │  MANY bindings →                └─ tenant
   ── auth is SEPARATE ──                scope_id         │  multi-org / multi-tenant          └─ resource
   credentials: password|oidc|           effect: allow|deny                                    (device/dashboard/
   saml|ldap|tacacs|mtls-svid|token      condition (tags/time/break-glass)                      alert/…)
                                         not_before, expires_at
   AUTHENTICATION (prove who)            granted_by, granted_at, reason
                                         ── this row is the SOC2/ISO artifact ──
```

- **Multi-everything is free.** An SRE = one principal with 20 tenant-scoped
  bindings. A consultant = bindings across 5 orgs. An auditor = `auditor`
  bindings at several org scopes. No schema gymnastics — just more rows.
- **The binding table is the compliance artifact**: "who can do what, where,
  granted by whom, expiring when" in one queryable place.
- **Roles stay fixed**; scope is what changes — exactly the SaaS expectation.

### 1.1 Principal (identity)

```
principal(
  id            text primary key,         -- stable, opaque
  type          text not null,            -- user | service_account | agent | device
  display_name  text,
  status        text not null default 'active',  -- active | disabled
  home_org      text references org(id),  -- the principal's "owning" org (nullable for platform principals)
  bindings_version bigint not null default 1,    -- bumped on any binding change (cache key)
  created_at    timestamptz not null default now()
)
```

Authentication methods (password, OIDC/SAML/LDAP/TACACS, mTLS SVID, API token)
attach to a principal but are **not** authority — they only prove identity.
`home_org` is organisational ("which account is this person/thing billed under")
and is independent of where they have access.

### 1.2 Scope (resource hierarchy)

A **strict single-parent tree** with a fixed type lattice:

```
platform  >  org  >  tenant  >  resource
```

```
scope(
  id          text primary key,    -- e.g. "platform", "org:acme", "tenant:acme-prod", "device:r1"
  type        text not null,       -- platform | org | tenant | resource
  parent_id   text references scope(id),
  -- invariants (enforced at write time):
  --   * exactly one parent (root 'platform' has none)
  --   * parent.type must be strictly higher in the lattice (no cycles, no type inversion)
  --   * a resource scope can never become an ancestor of an org/tenant
  constraint no_cycle ...,
  constraint lattice_order ...
)
```

- **Ids are `type:slug`** (`org:acme`, `tenant:acme-prod`, `resource:device-123`)
  and creation is **hybrid**: org/tenant **eager**, resource **lazy** (first ACL /
  observation). **Invariant: a scope id, once minted, is STABLE — never re-mapped.**
  (§7.4)
- **Ancestor check = walk `parent_id`** (depth ≤ 4) — the *only* traversal
  authorization performs.
- **Cross-cutting access (MSP / shared / break-glass) is NOT re-parenting.** It is
  a **binding whose `scope_id` points across the tree** (a consultant homed in
  org-A holding a binding at org-B's scope). The resource hierarchy stays a clean
  tree; the *graph* lives entirely in the binding table. → "tree for resources,
  graph for access," made an invariant.

### 1.3 Binding (authorization join)

```
role_binding(
  id          bigserial primary key,
  principal_id text not null references principal(id),
  role_id     text not null references role(id),
  scope_type  text not null,       -- platform | org | tenant | resource
  scope_id    text not null references scope(id),
  effect      text not null default 'allow',  -- allow | deny  (deny overrides)
  condition   jsonb,               -- optional: {device_tag:[...]}, time windows, break_glass:true
  not_before  timestamptz,
  expires_at  timestamptz,         -- null = permanent
  granted_by  text not null references principal(id),
  reason      text,
  granted_at  timestamptz not null default now()
)
-- indexes:
--   (principal_id, scope_type, scope_id)   -- evaluation path
--   (scope_id, principal_id)               -- reverse "who can access X" (admin UI only)
```

### 1.4 Role (the "what" — a fixed bundle, evolving into a template)

Today: `Role{ Permissions: map[module]level }` (`rbac.go`). Target: a role is a
**named bundle of rules**, not a frozen matrix —

```
rule = { effect, resource_type, actions[], condition? }
role = { id, name, builtin, rules[] }
```

- The five built-ins (`super-admin`, `operator`, `read-only`, `auditor`,
  `api-client`) become pre-authored bundles; today's grids compile into rule form
  with no behaviour change.
- **The decider's interface takes *rules*, not module→level**, and **the token
  never carries a role name as authority** — it carries the compiled permission
  set. So roles can evolve into policy templates (custom / tenant-defined,
  validated against the rule schema via the existing `policy/` gate) **without a
  breaking interface change.** Don't over-freeze roles; don't bake `module→level`
  into the token or decider.
- **Custom roles are sandboxed** (§7.2): schema-validated bundles only — no
  free-form graphs, no override of platform invariants (e.g. `infra_stack`), no
  custom `deny`-bypass, no cross-scope escalation. Rejected at the `policy/` gate.

---

## 2. Evaluation algebra (formal, pure, order-independent)

`decide(principal, action, resource, now) → { allow, reason, matched_binding }`

1. **Default-deny (closed).** No matching binding ⇒ deny.
2. Gather bindings for `principal` whose `scope_id` is **ancestor-or-self** of the
   resource's scope, and whose `[not_before, expires_at]` contains `now`.
3. For each, the role's rules that match `(resource_type, action)` and whose
   `condition` holds (tags/time) contribute their `effect`.
4. **Resolution:**
   - **explicit `deny` overrides any `allow`** (AWS model: `Deny > Allow >
     implicit deny`). Required for "operator sees all tenants **except**
     OperatorRestricted" and break-glass exclusions.
   - allows are **additive** (union; per action take the max level).
   - **no most-specific-wins** — the only override is deny. ⇒ evaluation is
     **order-independent**, hence deterministic, hence the *same answer in every
     service* (the audit-consistency requirement).
5. **The decider is a pure function** of `(active bindings, role rules, request,
   clock)` — no IO — shipped as **one Go library** used by HTTP handlers, the WS
   hub, background jobs, and (replicated) the data plane. Never reimplemented.

This is the direct evolution of today's pure `Authorize(Principal, Action,
Resource) Decision` in `authz.go` — same shape, richer inputs.

---

## 3. Performance architecture (the SaaS hot path)

The binding table is the **source of truth** (normalized, audited, rarely
written). It is **not** what the request path reads.

### 3.1 Write model vs read model

Derive a **compiled effective-access map** per principal:
`principal_id → { scope_id → permission_bitset }`, already collapsed over the
scope chain. That compiled map *is* the "effective access snapshot."

- **Invalidation by version, not purge:** each principal has `bindings_version`;
  there's a global `role_epoch`. Cache keys embed both. A binding/role change
  bumps the version → a stale read is impossible (version mismatch forces
  recompute), and there's no purge bookkeeping.

### 3.2 Four-tier resolution (cheapest path = highest QPS)

| Tier | Source | Cost | Covers |
|------|--------|------|--------|
| **L0** | **token / mTLS-SVID claim** carries `principal_id`, `bindings_version`, compiled scope set | pure verify, **0 DB** | ~all UI, most ingest, single-binding service/agent/device |
| **L1** | in-process LRU of compiled maps | sub-µs | large principals (many bindings) |
| **L2** | Redis (per region), version-keyed | ~ms | shared across API replicas, survives restart |
| **L3** | recompute from replicated binding store (the multi-join) | rare | cold miss / version bump |

- **Ingestion (millions/sec)** is service/agent/device principals with a single
  narrow binding → resolves at **L0 from the SVID/token**, never reaches L3. By
  design the highest-volume path is the cheapest.
- The **reverse "who-can-see-X" index** is an async-maintained projection used
  only by sharing/admin UIs — **never on the request hot path.**
- Revocation latency is bounded by token TTL; a version bump invalidates L1/L2
  immediately, and short access-token TTL (already configured) bounds L0.

---

## 4. Control plane vs data plane (identity edition)

| Owns | Control plane (global, single source of truth) | Data plane (per region) |
|------|---------------------------------|--------------------------|
| Identity graph (principals) | ✅ | replica (read-only) |
| Role definitions / bindings / policy | ✅ | replica (read-only) |
| Scope-tree topology | ✅ | replica (read-only) |
| Audit ledger | ✅ | ships events up |
| **Runtime evaluation** | ❌ | ✅ (the pure decider runs here) |
| **Result cache (bitsets, versioned)** | ❌ | ✅ (Redis, per region) |
| Telemetry / customer data | ❌ | ✅ |

- Control plane **defines** policy; data plane **evaluates** it locally against a
  replicated, read-only copy. **No cross-region call on the hot path.**
- The result cache holds **permission bitsets keyed by version, never customer
  data** — so the control-plane purity isn't reintroduced as a coupling.
- **Kill the "Global tenant = super-admin bypass" conflation:** platform
  operators get bindings at the **`platform` scope** (no customer data); infra-
  stack telemetry moves to a dedicated **system scope**, not a customer tenant.
  This is the riskiest change (the global-tenant assumption is woven through RLS,
  OpenSearch index routing, and VM scoping) and is sequenced last among the
  structural phases.

---

## 5. Identity types beyond users

| Type | Auth | Typical binding | Substrate we already have |
|------|------|-----------------|---------------------------|
| `user` | password / OIDC / SAML / LDAP / TACACS | role @ tenant/org/platform | `auth.go`, `oidc.go`, `ldap.go`, `tacacs.go` |
| `service_account` | API token (RFC 7591) | least-privilege @ narrow scope | `apikeys.go` (#23) |
| `agent` (collector) | **mTLS SVID** | telemetry-write @ tenant/region | `tlsconfig/`, `federation.go` (SPIFFE) |
| `device` | device-bound cred / SVID | self-report @ its own resource scope | SNMP creds, ZTP (future) |

Service/agent/device identities are **first-class principals** with their own
bindings — not a magic `api-client` role. The SPIFFE/mTLS seam already in the
codebase carries scope in the SVID, which is exactly the L0 fast path for ingest.

---

## 6. Migration — non-breaking, phased

The current `user.role` + `user.tenant_id` and the Global tenant are load-bearing
across auth, RLS, ClickHouse row policies, OpenSearch index routing, and the SPA.
The sequence preserves behaviour at every step.

> **Implementation status (all shipped, behaviour-preserving):**
> A ✅ `5c63832` · B ✅ `0f82b06` · C ✅ `fda2191` · D ✅ `4e4d1a9` · E ✅ `40ee846`.
> **Remaining depth (explicitly deferred, not silently dropped):** live re-pointing
> of RLS / OpenSearch index routing / VM scoping off the global tenant onto a
> dedicated system scope (needs the regional data plane + staged rollout, Phase C);
> tag/data-condition ENFORCEMENT across telemetry read paths and agent/device
> authentication via SPIFFE SVID → principal (Phase D); the event-driven
> control→data-plane binding replication + per-region L2 cache (needs regional data
> planes to exist). The MODEL for all of these is in place; the integrations are
> the deferred work.

### Phase A — binding table, behaviour-preserving  *(keystone, ships first)*
- Add `principal`, `scope`, `role_binding` (PG migration; file-kv fallback as
  elsewhere). Backfill **every user as one principal + one binding**
  `(user, role, scope=tenant:<tenant_id>)`; platform owner → `(…, scope=platform)`.
- `principalFrom`/`principalTenant`/`can`/`Authorize` (`authz.go`, `tenancy.go`)
  read from bindings; **single-binding fast path returns identical output to
  today.** Compile roles' `map[module]level` into rule form transparently.
- **Net behaviour change: none.** The audit artifact (binding table) lands;
  findings #1, #2, #3 become structurally fixed and #4 becomes *expressible*.
- Files: new `principals.go` / `bindings.go` / `scopes.go`; evolve `authz.go`,
  `tenancy.go`, `rbac.go`; PG migration; tests.

### Phase B — multi-binding (unlocks MSP / consultant / SRE + Org-Admin)
- Allow N bindings/principal; `decide` = union over bindings (§2).
- UI to grant/revoke bindings (Identity & Access → a Principal's access list).
- Delivers the **Org-Admin rung** for free: an `org`-scoped admin binding.
- Add the compiled-map cache + `bindings_version` (§3).

### Phase C — split the control plane
- Introduce the `platform` system realm + a system telemetry scope; migrate the
  platform owner off "global tenant." Re-point RLS / OS index routing / VM
  scoping at the system scope. **Gated, isolation regression tests mandatory.**

### Phase D — fine-grained roles + the standalone decider
- Roles become rule bundles; add resource-type/action rules + tag/data
  conditions ("logs not metrics", "ack alerts not modify devices", "devices
  tagged X"). Promote service/agent/device to first-class principals over SPIFFE.
- Extract the decider as a standalone library + (optionally) an external policy
  evaluation surface (Cedar/OPA-shaped), fed by the replicated binding/role set.

### Phase E — scoped audit
- Org-level vs tenant-level audit visibility; an org-admin sees their org's audit
  trail, not the platform's. Extends `audit.go`.

---

## 7. Ratified decisions (signed off — gate to Phase A cleared)

The four open decisions are resolved. They are now **design constraints**, not
options; the migration phases below are bound by them.

### 7.1 Operator access posture → **Zero standing access + break-glass**

**Access is an event, not a state.** Operators have **no standing cross-tenant
or elevated access** by default. Elevation is a **break-glass session**:

- modelled as a **time-bound `allow` binding** at the needed scope, with
  `condition.break_glass=true`, mandatory `reason`, and a short `expires_at`;
- **fully audited** as a first-class event (who/what/why/scope/duration);
- **optional approval gate** for sensitive tenants (`OperatorRestricted` becomes
  "break-glass requires approval" rather than "hidden");
- self-expiring — no manual cleanup, no lingering privilege.

This keeps **one consistent model across humans and agents** (access = a binding
with a lifetime), gives a clean SOC2/ISO narrative ("no hidden privilege paths"),
and is the single most important decision — the whole architecture already
assumes access-as-event (binding-based authz, audit-first, scope separation).
*Replaces today's standing platform-owner cross-tenant read.*

### 7.2 Custom/tenant-defined roles → **Allowed, but sandboxed policy bundles**

Tenants may author roles, but only as **constrained rule bundles validated by the
platform schema** (via the existing `policy/` write gate). Hard guardrails — a
custom role **may NOT**:

- use **free-form / arbitrary** permission graphs (must conform to the rule
  schema: `{effect, resource_type, actions[], condition?}`);
- **override platform security invariants** (e.g. can't grant `infra_stack`,
  can't self-grant `administration:admin` at a scope above its own);
- define **custom `deny`-bypass** rules (deny-wins is platform-owned, §2);
- express **cross-scope escalation** (a rule whose scope exceeds the role's
  assignable scope is rejected at validation).

"Flexible inside a sandboxed policy language" — enough for enterprise pushback
("network-ops-lite: ack alerts + read devices"), never enough to make the system
un-auditable.

### 7.3 Binding replication → **Event-driven, versioned, eventually consistent**

- **Writes** are strongly consistent in the **control plane** (source of truth =
  an append binding **event log**).
- Replicated to each region via an **event stream** (Kafka/NATS/Pulsar preferred;
  Postgres CDC acceptable) into a **local replicated binding store + versioned
  snapshot cache**.
- **Reads** in the data plane are **eventually consistent**; correctness is
  guaranteed by `bindings_version` + short token TTL + the **L0 embedded scope
  set** (SPIFFE/SVID / token).
- **Hard rule: authorization NEVER blocks on a cross-region call.**
- **Acceptable lag:** 5–30 s typical for control operations; **revocation
  worst-case < 1–2 min** (bounded by token TTL + version bump). Documented as the
  SLO.

### 7.4 Scope ids → **`type:slug` canonical ids, hybrid eager/lazy creation**

- Canonical ids: `platform`, `org:acme`, `tenant:acme-prod`, `resource:device-123`.
  Human-readable (incidents / audits / logs / support), not UUID-debugging-hell,
  and maps cleanly onto ancestor-or-self traversal.
- **Creation strategy by type:**

  | Scope type | Strategy | Why |
  |------------|----------|-----|
  | `org` | **eager** | identity boundary |
  | `tenant` | **eager** | isolation boundary |
  | `resource` | **lazy** (on first ACL / first observation) | high cardinality (devices/alerts/metrics) |

- **Invariant (do not skip): once a scope id is created it is STABLE — never
  re-mapped.** Lazy creation mints once; the id is immutable thereafter.

### 7.5 Maturity note

This is no longer "RBAC for a SaaS" — it is **a distributed identity +
authorization system with control-plane separation**. At this stage the
**consistency model (7.3), the scope-identity model (7.4), and the access model
(7.1)** matter more than feature completeness, and are treated as the load-bearing
invariants of every phase below.

---

## 8. What we reuse (not greenfield)

- **`authz.go`** — the pure `Authorize` chokepoint is the exact seam the decider
  evolves into.
- **`policy/`** engine + write-validation gate — role-rule schema + custom-role
  validation.
- **`tlsconfig/` + `federation.go`** (SPIFFE/mTLS) — service/agent/device
  identity and the L0 ingest fast path.
- **Redis** (already in the stack) — the per-region versioned result cache.
- **Postgres RLS** + **OpenSearch index routing** + **VM scoping** — the data-
  plane enforcement the decider drives.
- **`audit.go`** — extended to scoped audit (Phase E).
- **Org layer** (`orgs.go`, `tenancy.go: principalOrg`) — the org scope node.
```
