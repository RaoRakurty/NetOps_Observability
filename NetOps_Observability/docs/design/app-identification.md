# Application Identification Engine — Design (#81)

> **Scope (owner, 2026-06-24):** **flow→app *enrichment*, NOT DPI.** Attach an
> application label to a flow/log record from the metadata already present (IPs,
> ports, ASN, SNI-if-exported, vendor app-id-if-exported), matched against
> catalogs (vendor IP ranges, DNS correlation, cloud tags) + operator-declared
> services + SoT. A **lookup** problem, not payload analysis. Confidence-scored,
> with **"unknown" first-class** — never a false `app = X`.
>
> **Companion research:** `docs/design/research/app-identity-research.md`.
> **Peer of:** device identity (`EntityResolver`, IP→device) and tenant identity.
> **Coordinates / subsumes:** #69 service-semantics model. **Unblocks:** the L7
> fault column + `owner=app_team` attribution, app-centric cloud-log value
> ("which app is affected?"), and #82 overlay VNI/tenant/**app** attribution.

---

## 1. Why this is foundational (not a feature bolt-on)

Today we **cannot identify applications**. What exists is thin and not it:

- A cosmetic **port→name map** (`dependency_view.go:198`, ~29 ports) — useless
  for SaaS where everything is 443.
- The syslog **`appname`/program field** — the *device process* (`bgpd`,
  `sr_evpn_mgr`), not a business application.
- The **#69 service-semantics layer** (`migrations/0011_service_catalog.sql`) —
  real and RLS-forced, but **operator-declared** (you must *declare* the app), the
  `svc_flow_rollup` is unbuilt, and it's **flow-scoped only**.

So "which application is affected?" — the question that makes the product
app-centric — has no answer today. Cloud logs without this layer are just
searchable raw IPs/resource-IDs. App identity is the **data-plane identity layer**
that a lot hangs off; it deserves its own design (like the #80 fault-coverage
matrix), which this is.

---

## 2. The foundation already exists (~70%) — verified

The big finding: we are **not** greenfield. The engine should **extend** the
existing service-catalog + correlation-evidence machinery, not stand up a
parallel system. Verified against the codebase (2026-06-24):

| Engine concept we need | What already exists to reuse | Location (verified) |
|---|---|---|
| App / service registry | `services` + `service_selectors` + `service_bindings` (versioned, `effective_from`, JSONB spec: `dst_prefixes/ports/protocols/remote_asns/domains/tags`, FORCE-RLS) | `src/backend/migrations/0011_service_catalog.sql` |
| Match rules (selectors) | `service_selectors` — append-only, monotonic `version`, replay-safe | `migrations/0011` (`service_selectors`) |
| Flow→service attribution | `buildSelectorCondition` — query-time, injection-safe (bounded ints + shape-validated CIDR; names never in SQL) | `src/backend/flows_services.go:99–189` |
| Evidence roles | `corr_evidence.role Enum8('supports','contradicts','discriminates')` | `clickhouse/init.sql:331` |
| Confidence bands | `VerdictTier{undetermined,suspected,confirmed}` + `scoring.py` (coverage×graph×direction, `CONTRADICTION_PENALTY`, mechanical `evidence_missing`) | `src/correlation/verdicts.py:57`, `scoring.py` |
| IP→x resolver pattern | `EntityResolver` (IP→device, **tenant-scoped**, atomic 60s JSON export, honest `None` on ambiguity) | `entity_resolver_enrichment.go`, `entity_resolver.py` |
| Tenant non-negotiables | `principalTenant` + `tenant_iso` FORCE-RLS + `chTenantScope` + `org_isolation_test.go` | `tenancy.go:62`, `flows.go:553`, `org_isolation_test.go` |

**So the design's real job:** add a **confidence/evidence *scoring* layer + the
catalog/enrichment fields** on top of machinery we already trust — reusing
`VerdictTier` + `corr_evidence` so app-identity verdicts flow into RCA /
evidence-bundles / replay **natively**.

---

## 3. The one honest constraint that shapes everything

**Our flow record is 5-tuple-only today.** Verified — `netops.flows`
(`clickhouse/init.sql:17–48`) has 20 columns: `ts, sampler_address, src/dst_addr,
src/dst_port, proto, bytes, packets, in/out_if, src/dst_as, sampling_rate,
vlan_id, tcp_flags, flow_type, tenant_id`. It has **none** of `dns, sni, http_host,
vendor_app_id, app_id, vni`, or inner headers.

This forces the same **Layer-2 (collect) vs Layer-3 (identify)** split we used for
#80 fault coverage. Be honest about it so we never claim DNS/SNI confidence we
can't yet source:

- **Phase-1 — evidence we can act on NOW** (no new collection):
  IP/prefix catalogs (vendor ranges), ASN (`src/dst_as`), `service_selectors`
  prefixes/ports/protocols/domains, port/protocol (weak), manual registry /
  SoT / NetBox.
- **Contract-ready but COLLECTION-GATED** (contract lands now, evidence lights up
  when the source is wired): **NGFW app-id** (documented in `fw_event` schema at
  `telemetry-coverage-reference.md:105` but **not parsed today** — needs a Vector
  pass), **DNS-flow correlation** (no DNS collection exists today), **TLS-SNI**,
  **HTTP-Host**, **cloud/K8s/OTel** metadata.

---

## 4. Architecture

### 4.1 Identification core (the pragmatic 2–3, not all 8)

1. **IP/prefix catalogs** → in-memory **LPM (radix/patricia) trie**, dst IP → app
   (M365 endpoints API, AWS/Azure/GCP ranges, ASN→org). The spine. Stdlib, cheap.
2. **Consume NGFW / IPFIX `applicationId` (IE 95)** where traffic crosses capable
   gear — **highest accuracy, zero compute for us** (someone else did the DPI).
3. **Operator-declared services (#69) + SoT/NetBox** — the authority for
   **internal** apps that have no public catalog.

Precise tier (DNS-flow correlation → SNI) is collection-gated and lands after.

### 4.2 Fusion → reuse the verdict engine

Map identification confidence onto the **existing** `VerdictTier` and record each
contributing signal as a `corr_evidence`-shaped row with a `role`:

- Authoritative (NGFW/IPFIX app-id, SoT, operator-declared) or agreeing-strong →
  **confirmed**.
- Single medium signal (IP-range only) → **suspected**.
- Coarse-only / contradiction / below floor → **undetermined / unknown** (first
  class — emit the broadest honest label, e.g. `CDN: Cloudflare`, never a guess).
- **Contradiction demotes; agreement promotes** — straight reuse of the engine's
  `CONTRADICTION_PENALTY` philosophy. Verdicts carry `evidence_missing` so the
  honesty is mechanical, not editorial.

### 4.3 Resolution path — query-time first

- **Query-time attribution, like `flows_services.go`.** **MV-over-flows is banned**
  (it regresses ingestion); resolve app at read time over the catalog index.
  Catalog changes apply retroactively; zero ingestion impact.
- **Hot in-memory LPM index + LRU(dst-IP→app) cache + negative cache/Bloom** for
  the inline path; **catalog-version invalidation, not TTL** (no expiry spikes).
- **Inline enrichment is a measured scale follow-up only** — a Go enricher writing
  a resolved `app_id` *column* (never a heavy MV), added when read-time resolution
  over high cardinality is proven to be the bottleneck.

### 4.4 Catalog lifecycle

Pluggable feed loaders → normalized `(prefix|domain|asn, app, confidence, source,
version)`. Loaded into a **new trie generation off the hot path, atomically
swapped** (the EntityResolver pattern). Feed-fetch is an **opt-in background job**;
the engine runs on the on-disk snapshot → **offline/air-gap buildable, no new
runtime dependency** (radix trie + suffix automata are stdlib).

### 4.5 Data model — thin parent, don't rebuild #69

- Add **`applications`** as a **thin parent** over the existing `services` table
  (business capability over technical service) rather than a separate registry.
  `services.application_id` (nullable) links them; #69 stays intact.
- New **`app_catalog`** table(s): versioned `(prefix/domain/asn → app, source,
  confidence)`; public catalogs are tenant-shared **read-only** (the data is
  public — only *results* are tenant-scoped), per-tenant overrides are RLS-scoped.
- **Code placement (codebase convention):** flat Go — `src/backend/appid.go`
  (+ `appid_catalog.go`, `appid_test.go`); frontend types in
  `src/frontend/services/api.ts`. **Not** `internal/...`.

---

## 5. Tenant isolation (mandatory — CLAUDE.md §3a)

- Public catalogs are global read-only; **every resolved result and every
  per-tenant override is scoped by `principalTenant`, default-closed.**
- `app_catalog` per-tenant overrides + `applications` get the `tenant_iso`
  FORCE-RLS migration and `withTenant`; ClickHouse joins use `chTenantScope`.
- App label is **stamped from resolution context**, never from a request body;
  cross-tenant app/catalog GET by id → 404; cross-tenant write refused.
- **Ship `appid_isolation_test.go`** (the `org_isolation_test.go` template):
  own-only list, cross-tenant get/override → 404, `as_tenant` into another org
  ignored. No feature complete without it.

---

## 6. Phased build (MVP → scale → futuristic)

| Phase | Deliverable | Gated on |
|---|---|---|
| **P0 — contract** | `applications` thin parent + `app_catalog` schema + `AppVerdict` type reusing `VerdictTier`/`corr_evidence`; isolation test scaffold | — |
| **P1 — MVP core** | LPM trie over **free vendor IP-range feeds** (M365/AWS/Azure/GCP) + ASN; query-time resolver alongside `flows_services.go`; `unknown` first-class; flow→app in the flows API | P0 |
| **P-NGFW** | Parse the `fw_event` **`app-id`** field (Vector) → join firewall-crossing flows to the free vendor app label | NGFW log parse |
| **P2 — precise tier** | **DNS-flow correlation** (needs a DNS source) → SNI where exported; suffix-automaton domain matcher; agreement/contradiction fusion | DNS/SNI collection |
| **P3 — internal + cloud** | SoT/NetBox enrichment for internal apps; cloud resource-id/tag → app from cloud logs | cloud-log ingest |
| **P4 — scale** | hot LRU + negative cache; optional inline enricher writing `app_id` column (measured); per-tenant override catalogs | measured need |
| **P5 — futuristic** | ML-on-flow-feature residue (explainable), LLM-assisted catalog curation (§15 guardrails), operator-confirm feedback loop → SoT | later |

**Dependencies:** none new at runtime (stdlib trie/automata; feed-fetch is opt-in
background). A commercial IP→app feed (Netify/IPinfo) is an *optional later*
premium input, not a build dependency.

---

## 7. Where it exceeds the market

Per the standing exceed-market bar: the agentless leaders (Kentik especially)
land on the same catalog + DNS + cloud-metadata + consume-vendor-app-id core. Our
differentiation is **not** the lookup — it's that app identity is **evidence-
grounded and fused into RCA**: every app label carries its confidence band,
contributing signals, and `evidence_missing`, and feeds the correlation engine so
the platform can answer **"which app is affected, by what, and how sure are we"**
— with an honest "unknown" instead of a brittle guess. That honesty + RCA
integration is the moat.

---

## 8. Open decisions (carried from research §8)

1. **`applications` thin parent over `services`** — recommended; confirm.
2. **First feeds:** M365 + AWS/Azure/GCP (free) for P1; commercial IP→app later?
3. **NGFW app-id extraction** (P-NGFW) — promote the documented `fw_event` field
   to a real parse + join. Own sub-task.
4. **DNS collection source** (P2 gate) — resolver logs vs passive-DNS vs
   flow-to-DNS join; which is realistic for an agentless customer?
