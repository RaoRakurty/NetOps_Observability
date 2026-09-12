# Cloud Monitoring Product Review — Principal Staff Engineer Assessment

**Date:** 2026-07-15
**Scope:** Correlix Cloud Monitoring product (Service View + cloud API surface + cloud topology + connectors), reviewed as if shipping to Fortune 100 enterprises. The RCA engine itself is out of scope except where the cloud product hands off to it.
**Method:** Grounded in the live implementation — every claim below traces to code (`src/frontend/src/pages/AppObservability.tsx`, `src/frontend/src/pages/appobs/*`, `src/backend/cloud_*.go`, `src/backend/cloud/`, `src/backend/cloudconn/`) or to live API payloads from the running tri-cloud stack (AWS + Azure + GCP pollers, probed 2026-07-15 via authenticated GETs against `:8000`). Design docs consulted: `cloud-provider-parity.md`, `cloud-telemetry-catalog.md`, `cloud-connectors-architecture.md`, `cloud-demo-traffic-program.md`.
**Reviewer stance:** Brutally honest, workflow-first. Compliments only where earned.

---

## 1. Executive Summary

Correlix's cloud monitoring is a **telemetry-first, honesty-first foundation wearing the clothes of a product**. The parts that are hard to retrofit are genuinely excellent: a measured ingestion-readiness model that never claims data it doesn't have, a five-source attribution ladder with confidence provenance on every row, evidence-grounded investigations with true (not page-length) counts, tri-cloud signal lanes that are live today (21k flow-log signals, 229 health signals, 90 change-audit events, 5 open investigations in the probed 24h window), and a connector architecture document that is better than what most shipping products actually implement.

The parts that make it a *product* are missing or broken:

1. **There is no onboarding.** The entire federated connector framework (719-line handler file, lifecycle state machine, identity broker with tenant-keyed token cache, isolation tests) has **zero UI and zero live connectors** — `GET /api/cloud/connectors` returns `{"connectors":[]}` on a stack that is actively polling three clouds. Real ingestion runs through an ops-managed Python sidecar writing fixture files that a 2-minute ticker loads into an **in-memory map** (`cloud_store.go`), stamped to a **single env-var tenant** (`CLOUD_FIXTURE_TENANT`). A Fortune 100 customer cannot connect an account without SSH access to the deployment host. This is the single biggest gap between the architecture docs and the shipped product.
2. **It does not scale past a demo.** `/api/cloud/resources` returns the entire inventory (plus a live-state map and a console-URL map per resource) with no pagination, no server-side filtering, and no search. Apps are re-derived from the full resource list on every request. Every tab loads everything and filters in the browser. At the stated 6 resources this is invisible; at 100k resources every page load is a multi-hundred-MB JSON transfer into client-side `Array.filter`.
3. **The operational loop is one-directional.** Detection is real; triage is absent. There is no acknowledge, assign, snooze, mute, note, or status transition anywhere in the cloud surface. Investigations deep-link *out* of the cloud product into a different page (`#/monitoring/correlations`), losing all cloud context. The remediation queue's only actions are "open the provider console" and "open a generic Integrations page."
4. **Settings is decorative.** All five Settings cards (Catalog Sources, Cloud Connectors, Attribution Rules, Required Tags, RCA Windows) render hard-coded strings and route their differently-labeled CTAs to the **same** generic Integrations page. "Edit required tags" edits nothing. For a governance-conscious enterprise buyer this is worse than absence — it promises controls that do not exist.
5. **One honesty violation stands out precisely because the rest of the product is so disciplined:** the Cloud topology tab **falls back to a hard-coded mock** when `/api/topology/cloud` returns empty or errors (`CloudTopologyView.tsx`), meaning a tenant that owns no cloud fixtures is shown a fabricated network with no distinguishing badge. In a product whose signature virtue is "we never fabricate," this is the one place it fabricates.
6. **A live cross-provider bug:** the backend builds GCP console deep-links (`cloud_console.go`, verified in the live payload: `console.cloud.google.com/...`), but the frontend's zero-trust URL allowlist (`appobs/api.ts safeConsoleUrl`) only admits `portal.azure.com` and `*.console.aws.amazon.com` — **every GCP console and Logs Explorer pivot is silently dropped in the UI**. The parity matrix marks GCP console links ✅; the rendered product disagrees.

**Verdict:** as a *demonstration of an honest observability data plane* this exceeds much of the market. As a *cloud monitoring product an enterprise NOC operates daily*, it is roughly 18–24 months of focused product engineering away — and the gap is almost entirely in workflow, scale plumbing, and self-service, not in telemetry, where the team's instincts are its greatest asset.

---

## 2. Overall Product Score: **4.5 / 10**

| Weighting rationale | |
|---|---|
| Telemetry depth & truthfulness (best-in-class instincts, tri-cloud lanes live) | pulls up |
| Attribution/confidence model (unique; no mainstream product exposes provenance this way) | pulls up |
| Onboarding (none, UI-wise), scale (in-memory, unpaginated), triage loop (absent) | pulls down hard |
| Multi-tenant cloud inventory (env-var single tenant in practice) vs the platform's own §3a bar | pulls down |

A 4.5 is not an insult here: Datadog's cloud product at an equivalent age scored similarly on workflow; the difference is they had self-serve onboarding on day one. The foundation justifies optimism; the product surface does not yet justify a Fortune 100 PO.

## 3. Information Architecture Score: **5 / 10**

The 2026 consolidation from 11 tabs to 5 + Settings (`AppObservability.tsx` `TABS`, with alias-preserving deep links — a genuinely professional migration touch) fixed the worst of it. What remains wrong:

- **The cloud product has no home.** It is a leaf called "Service View" filed under **Monitor → Event Management**, sandwiched between "Correlations" and "Recovery Scorecard" (`nav.tsx:148`). A NOC operator hunting for "cloud" in the nav finds nothing containing the word. Cloud *topology* lives on an entirely different page (Topology Canvas → Cloud tab, under Maps). Cloud *connectors* (when they get a UI) are slated for Admin → Integrations. Three homes, none labeled Cloud.
- **"Service View" is a misleading name** for a surface whose strongest tabs are Resources, Data sources, and Investigations. It is a cloud observability workspace, not a service catalog.
- The flyout sub-items still advertise the *old* IA ("Attribution", "Unknowns", "Evidence" — `nav.tsx` subItems) while the page renders the new one ("Service mapping", "Untagged", "Findings"). Two vocabularies for the same five destinations.
- Within the page, the grouping is sound: Overview → Services → Investigations → Resources → Data sources reads in descending altitude, and sub-tabs (Timeline/Alerts/Changes/Findings/Network) are correctly scoped.

## 4. Operations Workflow Score: **4 / 10**

What works: readiness-before-verdict (the `ReadinessStrip` renders *before* the Impact cards on Overview — the correct trust sequence, and almost no competitor does this), measured source freshness inside the Alerts/Changes views, and every table row carrying its evidence category and confidence.

What fails an on-call engineer at 3 a.m.:

- **No triage verbs.** Nothing can be acknowledged, assigned, muted, or annotated. The Alerts sub-tab is a raw signal table (200-row page of `corr_signals`), not an alert queue — the live payload shows the same `cloud_resource_health` critical firing repeatedly with no grouping, dedup, or flap suppression at the view layer.
- **Investigation continuity breaks.** Clicking an open investigation navigates to `#/monitoring/correlations?id=…` — a different product area with different chrome. The engineer loses the cloud scope bar, the source-freshness context, and the back path. Evidence rows do the same.
- **No time control.** Every surface is hard-windowed to 24h (`cloudSignalWindowHours = 24`); the scope bar displays a static "Last 1h" label (`readiness.ts deriveScope` default) that no view honors — the one dishonest *label* in an otherwise honest product. An incident that started 26 hours ago is unreachable.
- **No alert→notification wiring visible from the cloud surface.** The platform has a quad-destination notifier; the cloud product exposes no route from "cloud health signal" to "who gets paged."

## 5. Enterprise Readiness Score: **3.5 / 10**

- **Tenancy:** the signal read path is genuinely enterprise-grade (CH row policies + `safeScopeLiteral` fail-closed scoping, `principalTenant` on every handler, isolation tests for connectors and topology). But the cloud *inventory* — the spine of the whole product — is loaded for one env-var tenant into process memory, and `/api/topology/cloud` gates on `CLOUD_FIXTURE_TENANT` equality: an all-or-nothing, single-customer arrangement that fails the platform's own §3a 1000-tenant bar. The design docs know this ("real per-tenant SDK connectors replace this loader later"); the review must still score what ships.
- **RBAC:** read/write split on `infrastructure` perms is consistent. But there is no separation between *operator* actions and *governance* actions (required-tag policy, attribution precedence) — moot today only because those editors don't exist.
- **Audit:** connector lifecycle defines audit event names (`CONNECTOR_CREATED`, `TRUST_VALIDATED`, …), good. No cloud-surface audit view; no record of who assigned a resource mapping (the API stamps `claims.Sub`, but no UI shows it).
- **Compliance/data governance:** no data-residency story per connector scope, no retention surface, no export.
- **Secret custody:** the broker design (envelope Vault, never-logged, 1h cap, fail-closed lifecycle) is *above* market bar — on paper and in tests. It has never minted a real token in this deployment.

## 6. Scalability Score: **3 / 10**

Named bottlenecks, from code, in the order they will fall over (see §"Scale review" for the 500-account/1M-resource walkthrough):

1. `memCloudStore` (`cloud_store.go`) — the entire multi-cloud inventory in a Go map, rebuilt by full replacement every 2 minutes, lost on restart. No pagination contract exists *anywhere above it* because the store can't serve one.
2. `handleCloudResources` — returns every resource **plus** a parallel `live` array **plus** a `console_urls` map, per request, no `limit`/`offset`/`filter` params. Every tab and the shell hook (`useCloudShell`) each call it independently — Overview alone triggers it three times (shell + `loadOverview` + nothing cached).
3. `handleCloudApps` — `cloud.DeriveApps(res)` over the full inventory per request; app health fold in Go per request.
4. `cloudLiveStates` — four instant PromQL queries (`last_over_time(cloud_*[30m])`) with **no tenant label filter** (join-by-resource_id makes it correct, but the query cost is all-tenants) + one CH probe aggregate, per resources/apps request.
5. Client-side everything: filter option lists are built with `new Set(all.map(...))` over the full dataset in the browser; `DataTable` heights are computed from `rows.length`.
6. The good news: the *signals* path already learned these lessons (24h window + LIMIT + dedicated COUNTs + bounded archive join with granule-pruned prefilter after the 27.8M-row incident, all documented in `cloud_handlers.go` comments). The inventory path just hasn't had its incident yet.

## 7. UX Score: **6 / 10**

The strongest score, and deserved: empty/loading/error states are uniformly designed (skeletons, `EmptyState` with a *next action*), "—" for not-measured is enforced by a typed sentinel (`NOT_MEASURED = -1`) rather than convention, badges carry basis text ("provider status checks pass, but 13 active checks failed…" — verified live), and customer-facing language discipline is real (no store names, "Mapped by: Tag / Resource graph / Operator"). Deductions:

- Display-only scope bar (provider/account/region/env are *summaries*, not filters) while each tab reinvents its own `FilterBar`.
- Dead permanent cards on the flagship Overview ("Network Impact —", "Deploy-linked Incidents —").
- No free-text search on any table; no column chooser; no saved views; no CSV export.
- Row-click opens drawers (good) but there is no keyboard path to them; `role="tab"` is used but arrow-key tab navigation is absent; virtualization unverified for large row counts.
- The mock-fallback topology tab (see §1.5) and the silently-dropped GCP console links (§1.6) are UX-visible honesty/correctness defects.
- Mobile: dense NOC layout with fixed column widths; unusable below ~1100px. Acceptable for a NOC product, but state it.

---

## Per-page review (owner's rubric)

### Overview — is it the right landing page?

**Half right.** Readiness-strip-first is the correct and differentiated choice. The Impact group leads the cards, which is the right *order* — but the content is telemetry-shaped, not impact-shaped: "Services Degraded 2" with no *which*, no *since when*, no *customer/business weight* (the `BusinessService.Criticality` field exists in the API and is rendered nowhere). "Would an operator know if action is needed?" — they would know *something* is degraded and would then click twice to find out what. The Open Investigations table is the best element (engine-formed, true counts, truncation labeled). Two permanently-dash cards spend the most valuable real estate in the product saying "we don't do this yet." Honest, but a landing page should lead with what it *can* answer. **Missing:** a "worst first" degraded-services strip with duration and blast radius, a top-mover (new-in-last-hour) rail, and an SLO/error-budget lane when SLOs exist.

### Services — truly service-centric?

**No — it is inventory-centric with a service veneer.** A "service" here is a merge of resources sharing an `app_id` tag (`DeriveApps` + frontend `mergeApps`). That's attribution, not a service model: no dependencies, no endpoints, no SLIs, no owner escalation path, no criticality, no relationship to the `business-services` API (which — measured — has **zero frontend consumers**; you can create a Business Service via curl and no page will ever show it). Health is a worst-of-resources fold with an honest basis string (good), but there are no health *indicators* beyond the single badge: no availability %, no error-rate sparkline, no latency trend (all honestly "—" pending flow/trace lanes — correct, but it means the page cannot rank services by pain). The Service map sub-tab is app→resource *grouping cards*, not a map; dependencies are honestly deferred to flow-log ingestion — but flow logs are **flowing today** (21k signals/24h, `flow_logs: flowing` in the live ingestion payload) and still unconsumed by this view: the data has outrun the UI. Topology placement: the service map belongs here; the network topology (VPC/subnet/gateway) correctly lives on the Topology canvas, but nothing cross-links a service to its VPCs.

### Resources — does it survive 100k? 1M?

**The page design survives; the data path does not.** Columns are right (identity, mapping provenance, confidence, power state as lifecycle truth, missing tags with a fix chip). Attribution confidence as a first-class column is the best resource-inventory idea in this product — Datadog shows tags, not *why it believes them*. The failure modes: (a) full-inventory fetch with client filters (§6) — at 100k rows the tab dies at the network layer before React gets a chance; (b) filter model is three fixed dropdowns — no tag-key/value query, no type facet, no account/region facet, no free text; (c) the tagging workflow dead-ends: "Recommended action: Tag X with app/owner/env" has no bulk path, despite `PUT /api/cloud/resource-mappings` accepting 5,000 ids — **the backend shipped bulk assignment and the frontend never called it**; (d) ownership is a display string with no directory link; (e) at 1M resources the *concept* must change from table to facet-first explorer (type/account/region/tag rollups with drill-in) — redesign required, see §Recommended IA. Verdict: right skeleton, wrong plumbing, missing the one workflow (bulk attribution) its own API already supports.

### Data Sources — can an operator see WHY telemetry is missing?

**Closest page to market-leading.** The account × region × source matrix with measured flowing/stale/off, per-source volume + last-seen, and the crucial `capability: available|planned` split (so "no producer exists yet" never reads as "broken") is better than CloudWatch's nothing and competitive with Datadog's integration-health tiles. Live payload confirms it tells the truth: `change_audit: stale (27m)`, `lb_logs: off/available`, `traces: off/planned`. Three failures: (a) **onboarding is a button to a different product area** — "Connect a cloud account · Integrations" leaves the cloud product for a generic integrations admin, and the actual connector wizard (7 backend steps, provider catalog, trust templates — all live API, verified) has no UI at all; (b) *why*-granularity stops at "off" — the model defines `permission_denied` and `misconfigured` (`readiness.ts`) but no producer ever emits them, so the operator sees "Not configured" when the truth may be "IAM denied `logs:FilterLogEvents` since Tuesday"; (c) accounts are *derived from discovered resources* (`buildAccounts(rows, …)`), so an account whose ingestion is fully broken — the exact case the page exists for — **disappears from the Accounts table** instead of showing red. Connector health (identity vs telemetry, already modeled separately in `cloudconn`) is not rendered anywhere.

### Investigations — would engineers solve incidents faster?

**Marginally, and only because of evidence honesty.** Strengths: unified timeline (change + health interleaved — the "what changed right before" question answered by layout), Findings ledger with grounded-vs-gap categories and true totals, change rows with actor + provider log deep-link (CloudTrail/Activity Log pivots verified in payloads). Failures: (a) **alert fatigue is unaddressed** — Alerts is a flat 200-row signal dump; the same resource's `cloud_resource_health` critical appears dozens of times with no grouping-by-episode, no "first seen/last seen/count" compression; (b) no cross-filtering — clicking a timeline item doesn't scope the other sub-tabs; filters reset between sub-tabs; (c) the handoff *out* to the correlations page severs context (§4); (d) Network Connectivity is an enablement card (honest, correctly done) but it's been "set up in Data sources" for a while — the CTA opens a page that can't actually set it up; (e) no incident object exists at this layer: findings and signals are evidence *for* investigations that live elsewhere; the engineer has nowhere to write down what they concluded.

### Settings — operational vs cloud-admin vs governance separation?

**No separation because no settings.** Five cards, five hard-coded value strings, five CTAs with five different labels all invoking `openIntegrations()` (`AppObservability.tsx` Settings). Attribution precedence ("cloud tag → resource graph → firewall App-ID → domain → IP catalog"), required tags ("app · owner · env"), and the RCA deploy window ("30 minutes") are real resolver behaviors — presented as if configurable, configurable nowhere. Governance settings (required tags, precedence) belong to a platform/org admin persona; operational settings (connector scopes, source toggles like the metered-metrics cost gate that already exists as env vars `AWS_METERED_METRICS`/`GCP_METERED_METRICS`) belong to cloud admins; none of this separation can exist until the controls do. This tab should either become real or become documentation.

---

## Enterprise Architecture review — does the navigation scale?

No. "One page with six tabs under Monitor" is a 1-provider/6-resource IA. The moment a second enterprise domain lands (identity, security findings, cost), the tabs multiply or the product fragments. Pages to create/merge (target state, respecting the current design system):

- **Cloud Assets** (evolve Resources): facet-first inventory across compute/network/data/identity resource classes; the current table becomes the drill-in level. Merge "Untagged" into it as a saved facet (`attribution=unknown`), keep the remediation drawer.
- **Topology** (merge): the Cloud tab of Topology Canvas and the Service map should be one graph with layers (service / VPC-network / hybrid-seam), entered from either nav home but the same surface. Today they share zero code paths and zero links.
- **Identity** (new, later): connector identities + workload identities + who-can-reach-what; the `cloudconn` identity/health split is the seed.
- **Security** (new): the WAF/firewall/DNS-deny rollup lanes (`cloud_waf_log`, REJECT rollups — parsers built per parity doc) deserve a security-findings view, not burial inside Investigations.
- **Governance / Compliance** (new): required-tag policy + coverage reporting (the Attribution funnel is 80% of a compliance report already), plus data-residency and audit views.
- **Deployments / Changes**: promote the Changes lane; correlate with the deploy-linked-incidents card that today is permanently "—".
- **Cost** (new, phase 3): the metered-lane toggles and the telemetry-catalog's $-flags are the embryo of cost-aware observability; a real cost page needs billing-export ingestion.
- **Service Catalog** (new): make Business Services real — UI over the existing CRUD API, criticality, ownership, SLOs; Services tab then reads from the catalog instead of deriving identity-only apps.

Navigation recommendation in §11.

---

## The 10-step operations workflow review

Where the product guides, where it abandons:

| # | Step | State | Verdict |
|---|---|---|---|
| 1 | **Onboarding** | No UI. Backend wizard APIs complete (catalog→draft→auth→setup templates→scopes→validate→activate, all tenant-scoped + audited). Actual path: ops edits env/compose. | **Fails.** The #1 gap in the product. |
| 2 | **Telemetry validation** | Best step. Ingestion matrix is measured, per provider × region × source, honest capability split. | **Guides well.** Needs `permission_denied` producers + absent-account visibility. |
| 3 | **Inventory** | Real tri-cloud inventory with lifecycle truth (`power_state`, stopped ≠ broken). No pagination/search/facets. | **Guides at demo scale only.** |
| 4 | **Attribution** | The differentiator: 5-source ladder, per-row provenance + confidence, coverage funnel, untagged queue with fix text. But remediation = "go tag it in the console"; the bulk-assign API is UI-orphaned; manual overlay works and is invisible. | **Half-guides.** Closes the *diagnosis*, abandons the *fix*. |
| 5 | **Health** | Live and honest (provider verdict > active checks > silence=unknown, worst-wins with basis strings). No trends, no SLIs, no thresholds an operator can set. | **Guides for "is it broken now", not "is it getting worse".** |
| 6 | **Detection** | Signals land and form investigations engine-side; no cloud-side monitor authoring (the platform's Monitor Rules are device-centric). | **Partially** — detection exists, tuning doesn't. |
| 7 | **Investigation** | Timeline + findings strong; no cross-filter, no grouping, context lost on handoff. | **Half-guides.** |
| 8 | **RCA** | Handoff to the correlation engine with real verdicts/confidence. Cloud context (console links, change actors) rides along. | **Guides** (the platform's strength). |
| 9 | **Resolution** | Nothing. No runbooks, no actions, no ITSM link *from the cloud surface* (the platform has ITSM lanes; the cloud pages don't reach them), no "restart instance" even as a deep-link with intent. | **Fails.** |
| 10 | **Verification** | Nothing explicit. Recovery is observable (health returns green) but never *asserted* — no "incident resolved, signal cleared for 30m" confirmation loop. | **Fails.** |

Score pattern: strong 2–5, cliff at 9–10. The product detects and explains; it does not help anyone *finish*.

---

## Multi-cloud review — does the provider model generalize?

**The signal contract generalizes; the inventory/topology plumbing does not yet.**

- **Genuinely provider-neutral:** the signal kinds (`cloud_flow_log`, `cloud_lb_log`, `cloud_waf_log`, `cloud_dns_log`, `cloud_metric`, `cloud_change`…) are provider-blind — GCP's five log lanes landed with **zero** new kinds (parity doc, verified in `cloud_ingestion.go`'s kind map). The ingestion matrix auto-facets any provider that stamps itself. The connector model (`cloudconn.Provider`, capability packs, federated-first auth ranking) is cleanly extensible. This is the right architecture.
- **Hard-coded three-cloud assumptions:** frontend `provider()` coerces anything not aws/azure/gcp to "—" (`appobs/api.ts:41`); `safeConsoleUrl` allowlists two providers' hosts (and already breaks the third — §1.6); `ParseProvider` accepts `aws|azure|gcp` only.
- **Oracle/Alibaba:** fit the model (inventory poller + audit lane + flow rollups + console-link builder + one `cloudconn` adapter each). Realistic effort M per provider *because* the kind contract holds. Nothing structural blocks them.
- **VMware/bare-metal:** the product already has a stronger story than most competitors — the device/SNMP/gNMI estate *is* the underlay half of this platform. What's missing is treating vSphere as "a provider" (inventory + events + metrics through the same connector contract) rather than a device pile.
- **K8s/OpenShift:** the real test, and the model bends: "resource" here is fine (nodes, LBs), but pods/deployments need a *workload* layer with churn rates that will kill the full-replace in-memory inventory and the 2-minute snapshot cadence. The attribution ladder actually shines for K8s (labels ≈ tags, owner refs ≈ resource graph) — but only after the store supports incremental updates and watch semantics.
- **Verdict:** contract A−, implementation C. Generalization is one store-rewrite away from credible, and the honesty rules ("n/a with a reason, never fake parity") are exactly the right cross-provider governance.

---

## Scale review — 500 accounts, 10k apps, 1M resources, 100M findings, 50 concurrent engineers

Concrete failure sequence from the code:

1. **1M resources:** `memCloudStore.ReplaceInventory` copies the full slice per refresh; `ListResources` copies it again per request; `handleCloudResources` JSON-encodes resources + live rows + console URLs (~1–2 KB/resource ⇒ **1–2 GB per page load**). Dead at ~50k resources. The fixture files themselves (poller rewrites whole JSON files every cycle) die earlier.
2. **500 accounts:** the ingestion matrix groups per (provider, kind) globally, fine — but `buildMatrix` runs client-side over all resources, and the Accounts table derives from resources (§Data Sources), so 500 accounts × 20 regions = a 10k-row unvirtualized matrix in the browser.
3. **10k apps:** `DeriveApps` + per-request live fold is O(resources) per hit; the Applications table has no server paging; the Services filter dropdowns enumerate 10k options.
4. **100M findings:** the signals path is the *prepared* one — windowed, LIMIT-capped (max 1000), dedicated counts, projection-backed (`corr_current FINAL` with named columns, archive join prefiltered). This survives, though the UI offers no cursor past the first page: `count: 171` today, but at 100M-in-24h the operator can see 1,000 and *no more* — truncation is labeled, pagination doesn't exist.
5. **50 concurrent engineers:** every session independently fires the full-resource fetch 3–5× per page visit (shell + tabs, zero caching, `useAsync` refetches on every mount). 50 engineers × 1–2 GB payloads is a self-DoS. The four unscoped VM instant queries per inventory request multiply across sessions.
6. **The fix shape** (not optional at this bar): inventory to a paginated store (PG per the store's own comment "migration 0016 is the next step") with server-side facet counts; an `apps` materialization instead of per-request derivation; ETag/short-TTL caching on inventory reads; cursor pagination on findings; a resource-search endpoint. None of this is research — it's the roadmap the code comments already admit.

---

## UX review (detail)

- **Density:** good NOC density, consistent with the platform kit (`ao-*` classes on the ds tokens). Tables lead; cards are summaries. Right choice for persona.
- **Filters:** per-tab, dropdown-only, options data-derived (nice touch: dead filters never appear — a provider with no inventory isn't offered). Missing: free text, multi-select, negation, tag queries, URL-persisted filter state (deep-link aliases exist for *tabs* but not *filter state* — a shared investigation link loses the filters).
- **Tables:** consistent `DataTable` with sort on selected columns; row-click drawers; honest truncation ("showing X of Y (true count — the page is bounded)" — verbatim UI copy, and better honesty than any competitor's silent cap). Missing: column chooser, export, sticky first column at overflow, bulk-select (blocks the bulk-assign workflow).
- **Badges/status colors:** disciplined tone tokens (`--ok/--warn/--crit/--accent`); confidence and health ladders are consistent everywhere; `SourceStatusBadge` has a real 7-state model. Power state colors running=ok/stopped=warn — correct lifecycle honesty.
- **Progressive disclosure:** drawers with kv-tables + provenance + recommended action are the pattern done right. The Findings drawer (grounded-vs-gap explanation inline) teaches the mental model as you use it.
- **Empty/loading:** uniformly excellent; every empty state names the next action; error states offer a path ("check the cloud connector status in Settings" — though Settings can't actually help, see above).
- **A11y/WCAG/keyboard:** `role="tab"`/`aria-selected` present, `ariaLabel` on tables — but no roving tabindex or arrow-key tab navigation, drawer focus-trap unverified, row-click without keyboard equivalent, funnel bars and status dots communicate by color alone at several points (dot + label in matrix cells is fine; the funnel fill and the power-state coloring lack non-color encoding). Not WCAG 2.2 AA today.
- **Dark mode:** token-based, follows the platform's binary theme knob. Fine.
- **Mobile:** not designed for; fixed widths. Acceptable if declared out of scope; it isn't declared.

---

## 8. Biggest Strengths

1. **Honesty as architecture, not aspiration** — `NOT_MEASURED` sentinels, measured ingestion status with `capability` provenance, "silence is not health" folds (unknown outranks healthy in the app fold — `cloud_handlers.go` rank map), true counts vs page lengths, basis strings on every health verdict. This is a durable, marketable differentiator no incumbent can claim.
2. **Attribution provenance ladder** — five sources, per-row confidence, coverage funnel, operator overrides that beat inference (`overlayManualMappings`). Materially better than tag-string-display in Datadog/CloudWatch.
3. **Trust-gate ingestion UX** — account × region × source matrix answering "is data actually arriving" before any verdict. Peers: Datadog integration tiles (shallower), Dynatrace (buried), CloudWatch (absent).
4. **Tri-cloud signal contract that already proved itself** — GCP onboarded five log families with zero new kinds; the parity matrix + acceptance-drill discipline is engineering governance most vendors don't have internally.
5. **Security architecture of the connector plane** — federated-first, ExternalId anti-confused-deputy, tenant-keyed broker cache with isolation tests, prohibited admin-password method. On paper + tests: above market.
6. **Evidence-grounded investigations** — findings tied to engine-formed objects with declared gaps ("missing" category) instead of vendor-magic correlations; provider log deep-links (CloudTrail event, Activity Log) on change rows.
7. **Bounded-read discipline on the hot path** — the #100/#101 lessons are visibly encoded in the cloud signal SQL (windows, LIMITs, projection reads, prefiltered joins). The team learns from incidents and writes it down.

## 9. Biggest Weaknesses

1. **No self-service onboarding** — complete connector backend, zero UI, zero live connectors; real ingestion is ops-configured. Disqualifying for enterprise sale on its own.
2. **Demo-scale data plane** — in-memory single-tenant inventory, unpaginated full-dump endpoints, per-request derivation, client-side joins. Fails at ~50k resources.
3. **No closure loop** — no triage verbs, no resolution actions, no verification step; the product observes and explains but never helps finish, and hands off mid-investigation to a different page.
4. **Governance theater in Settings** — five fake controls routing to one generic page. Erodes the exact trust the honesty architecture builds.
5. **Services aren't services** — tag-merge apps with no catalog, criticality, dependencies, SLOs; the Business Services API is a UI orphan; flow data flowing but not shaping the map.
6. **Honesty regression at the topology seam** — mock fallback on the Cloud topology tab; plus the static "Last 1h" scope label over 24h data.
7. **Cross-provider polish gaps that contradict the parity program** — GCP console links dropped by the frontend allowlist; nav vocabulary drift; provider enums closed to three.
8. **Cloud product has no identity in the IA** — a leaf named "Service View" under Event Management; topology and connectors elsewhere; the word "Cloud" appears in no nav item.

---

## 10. Top 25 Actionable Improvements (ranked)

| # | Improvement | Why | Effort |
|---|---|---|---|
| 1 | **Ship the connector onboarding wizard UI** over the existing 7-step API (provider catalog → draft → auth method (federated dominant) → trust templates → scopes → validate with findings → activate) | The product cannot be bought without it; backend is done; highest leverage-per-line in the codebase | L (3–4 wk) |
| 2 | **Move cloud inventory to the Postgres store with pagination + server filters** (the migration the store's own comment promises), add `limit/cursor/provider/account/region/type/tag/attribution` params to `/api/cloud/resources` | Every scale failure in §6 roots here | L |
| 3 | **Fix the GCP console-link allowlist** (`safeConsoleUrl`: add `console.cloud.google.com`; better — drive the allowlist from the provider catalog) | Live bug; contradicts the shipped parity claim; 1-line fix + test | S (hours) |
| 4 | **Remove the mock fallback from Cloud topology** — render the honest empty/enablement state the rest of the product uses | The one fabrication in an honesty-first product; reputational risk in any customer demo | S |
| 5 | **In-product bulk attribution**: row-select on Resources/Untagged → "Assign to service" drawer calling the existing `PUT /api/cloud/resource-mappings` (5k cap already enforced) + Business Services picker | Converts the diagnosis (untagged queue) into the fix; API already shipped | M (1 wk) |
| 6 | **Make the scope bar interactive** (provider/account/region/env as global filters feeding all tabs) and make the time-range real (1h/24h/7d param through the signal endpoints — they already take a window server-side) | Kills the dishonest "Last 1h" label; the single biggest daily-driver UX upgrade | M |
| 7 | **Alert episode grouping**: collapse repeated (resource, signal, state) into episodes with first/last/count, flap detection | The Alerts tab is unusable during any real incident storm (verified: same critical repeated across the 200-row page) | M |
| 8 | **Embed the investigation view** (open the correlation object in a drawer/split-pane within Service View instead of navigating to `#/monitoring/correlations`) | Preserves cloud context mid-incident; workflow continuity | M |
| 9 | **Real Settings**: required-tags editor (drives `missingTags` + coverage), attribution precedence editor, RCA window editor — per-tenant, persisted, audited; delete the fake CTAs meanwhile | Governance credibility; currently negative value | M–L |
| 10 | **Account-level connector health on Data Sources**: accounts from connectors (not discovered resources), red rows for silent accounts, identity-vs-telemetry health split (model exists in `cloudconn`) | The page's core question — "why is telemetry missing" — currently unanswerable for a fully-dark account | M |
| 11 | **Emit `permission_denied`/`misconfigured` from pollers** into ingestion status (the UI states already exist, unfed) | Turns "Not configured" into "IAM denied X since Tuesday" — the actual operator question | M |
| 12 | **Service catalog UI** over `business-services` CRUD: criticality, owner, description; Services tab joins catalog + derived apps | Unlocks impact-over-telemetry everywhere (Overview can say "2 degraded, 1 business-critical") | M |
| 13 | **Nav: name the product** — rename the leaf "Cloud" or "Cloud Monitoring", align flyout sub-items to the real 5 tabs, cross-link Topology Canvas Cloud tab ↔ Service View | Findability; vocabulary drift is visible confusion | S |
| 14 | **Cache the inventory read** (shared client cache for the 3–5 duplicate fetches per page visit; ETag/60s TTL server-side) | 5× payload reduction before pagination even lands | S–M |
| 15 | **Wire flow logs into the Service map** (talks_to edges from the flowing `cloud_flow_*` signals, volume-weighted) | The map's own caption promises this "when flow logs are ingested" — they are; the promise is past due | M–L |
| 16 | **Findings/health pagination cursors** in the UI (server already returns true totals) | 100M-findings readiness; today the operator hard-stops at 1,000 rows | S–M |
| 17 | **URL-persist filter + drawer state** (shareable deep links into a filtered view/selected finding) | Incident collaboration ("look at this") currently loses state | S |
| 18 | **Notification routing from cloud signals**: a "Notify/route" affordance on health signals + investigations reusing the platform's existing notifier lanes | Detection→paging is invisible from the cloud surface | M |
| 19 | **Resolution actions v1**: per-resource action menu — open console (existing), create ITSM ticket (platform lanes exist), attach runbook URL per service | Starts closing steps 9–10 of the workflow | M |
| 20 | **Verification loop**: investigation close requires/records "signal clear for N minutes", rendered as a recovery banner | Honest recovery is on-brand and nearly free (health data exists) | M |
| 21 | **Keyboard + WCAG pass**: arrow-key tabs, focus-trapped drawers, ESC to close, non-color status encodings, `aria-live` on freshness | Fortune 100 procurement checks WCAG 2.2 AA; currently fails | M |
| 22 | **Overview impact rework**: degraded-services strip (name, duration, criticality, blast radius) replaces the two permanently-dash cards; move those to a roadmap-honest "Coming soon" footnote pattern | Landing page must answer "what do I act on" in one glance | M |
| 23 | **Provider-extensibility cleanup**: provider enums/allowlists/labels from one registry (backend catalog already exists at `/api/cloud/providers`) | Oracle/Alibaba/vSphere become adapter work, not UI surgery | S–M |
| 24 | **Free-text search across resources/apps** (server-side once #2 lands) | Table-scanning 100k rows with three dropdowns isn't search | M |
| 25 | **Export**: CSV/JSON on Resources + Findings, honoring filters + tenancy | Every enterprise asks in the first PoC week | S |

---

## Top 50 missing enterprise features

**Critical (blocks enterprise adoption):**
1. Self-service connector onboarding UI (see Imp #1)
2. Paginated, searchable, facet-first inventory at 100k–1M scale
3. Per-tenant cloud inventory (replace env-var single-tenant fixture loading)
4. Alert triage: ack/assign/mute/snooze/notes with audit trail
5. Alert episode grouping + dedup + flap suppression
6. Notification routing (cloud signal → pager/Slack/ITSM policy)
7. Service catalog with criticality + ownership (API exists, UI doesn't)
8. Required-tag governance policy editor + enforcement reporting
9. Connector health surfacing (identity vs telemetry, silent-account alarms)
10. Permission-denied diagnostics per source ("what IAM to fix, exact ARN")
11. Time-range control across all cloud surfaces
12. RBAC separation for governance vs operational cloud settings
13. Investigation workspace continuity (no context-losing page jumps)
14. Incident/investigation lifecycle states visible + editable from cloud view
15. Multi-account onboarding at org level (AWS Organizations / Azure management groups / GCP folders — scope types exist in the catalog, no flow)

**Important (competitive necessity):**
16. Service dependency map from flow telemetry (data already flowing)
17. Metric charts: CPU/network trends per resource/app (data in the metrics store today; zero charts in the cloud product)
18. SLOs/error budgets per service
19. Monitor authoring for cloud metrics/signals (thresholds, anomaly toggles)
20. K8s/container workload layer (EKS/AKS/GKE inventory + health)
21. Serverless + PaaS resource classes (Lambda/Functions/Cloud Run, RDS/SQL/Cloud SQL) — inventory is VM-only today (verified: 6 resources, all instances)
22. LB/WAF/DNS security-findings view over the built rollup lanes
23. Change→incident correlation card made real (deploy-linked incidents)
24. Cloud cost ingestion + cost-of-degradation context
25. Saved views + shareable filtered links
26. Bulk operations UX (select-all-matching, background jobs, progress)
27. Resource detail page (permanent URL per resource, not just a drawer)
28. Search-first global nav ("find resource/app/account by name/id/IP")
29. Audit view for cloud-surface actions (mappings, settings, connector ops)
30. Provider incident/maintenance lane (AWS Health events are free — catalog #2 rank; none ingested)
31. Hybrid-seam gateway telemetry rendered (BGP/tunnel/NAT metrics — built, awaiting infra; the topology draws these nodes unmeasured)
32. Data residency + region pinning per connector
33. Ingestion-lag SLA reporting ("change events arrive ≤5 min p95")
34. Report/export pipeline for coverage + compliance (platform has async reporting; cloud pages don't use it)
35. API tokens/read API documentation for customers (programmatic inventory access)

**Nice-to-have (differentiators/маturity):**
36. Attribution rule simulator ("if precedence changes, 214 resources re-map")
37. Tag hygiene scoring trend over time (coverage funnel has no history)
38. Topology time-travel (config as of T, diff view)
39. What-changed diff on change events (property-level before/after — Azure ARG `resourcechanges` ranked in catalog)
40. Reachability analysis as an on-demand RCA action (catalog: AWS Reachability Analyzer $0.10/run)
41. Internet/egress path health (catalog: Internet Monitor, GCP Performance Dashboard)
42. Synthetic checks authoring against cloud endpoints from the product
43. Runbook attachments per service/signal type
44. Auto-remediation hooks (webhook/SSM/Logic Apps, opt-in, audited)
45. Multi-cloud resource normalization view ("all load balancers" across providers)
46. Anomaly baselines on cloud metrics with operator feedback loop
47. Capacity/forecast lane (quota usage — GCP `quota/exceeded` already cataloged)
48. Mobile/on-call read view for investigations
49. Public status-page integration (correlate provider incidents with own findings)
50. Demo/sandbox tenant one-click (the honesty-labeled demo mode already half-exists via `deriveDataMode`)

---

## Workflow comparison vs the market

Codes: **B**etter · **E**qual · **−** Behind · **M**issing. Judged on *workflows*, not visuals. DD=Datadog, DT=Dynatrace, NR=New Relic, CW=CloudWatch, AM=Azure Monitor, GO=Google Cloud Ops, TE=ThousandEyes, SP=Splunk IM/Observability, EL=Elastic, GC=Grafana Cloud.

| Capability | DD | DT | NR | CW | AM | GO | TE | SP | EL | GC | Why |
|---|---|---|---|---|---|---|---|---|---|---|---|
| Account onboarding | M | M | M | − | − | − | M | M | M | M | No UI at all; even CloudWatch's "already inside AWS" beats a wizard that doesn't exist. Backend contract would score B if shipped (federated-first + ExternalId discipline exceeds DD's role template). |
| Telemetry validation / "is data arriving" | **B** | **B** | **B** | **B** | **B** | **B** | E | **B** | **B** | **B** | The measured account×region×source matrix with capability provenance is genuinely the best-articulated trust gate in this set. |
| Inventory at scale | M | M | M | − | − | − | n/a | − | − | − | Unpaginated in-memory store vs everyone's indexed, queryable inventories. |
| Attribution/tag provenance & confidence | **B** | E | **B** | **B** | **B** | **B** | n/a | **B** | **B** | **B** | Nobody exposes *why* a resource maps to a service with a confidence ladder; DT's Smartscape infers better but explains less. |
| Service model (catalog/SLO/dependencies) | M | M | M | − | − | − | − | − | − | − | Tag-merge apps only; DT Smartscape/NR service maps/DD service catalog all far ahead. |
| Dashboards/metric charting (cloud) | M | M | M | M | M | M | − | M | − | M | Zero charts in the cloud product while metrics flow into the TSDB. |
| Alert triage & fatigue management | M | − | − | − | − | − | − | − | − | − | No verbs, no grouping; even CloudWatch has alarm states + actions. |
| Change→incident correlation | E | − | E | − | E | E | n/a | E | E | E | Change lane with actor + provider-log pivot is solid; DT's automated causation is ahead. |
| Evidence transparency in RCA | **B** | **B** | **B** | **B** | **B** | **B** | E | **B** | **B** | **B** | Grounded-vs-gap findings with true counts beats every black-box correlation in this list; TE's path evidence is the only peer. |
| Network/underlay ↔ cloud correlation | **B**? | **B** | **B** | **B** | **B** | **B** | − | **B** | **B** | **B** | The hybrid-seam + device-estate story is the platform's unique asset (probe-corroborated). "?" on DD (NPM+NDM closing in). TE still leads on internet path. |
| Multi-cloud parity governance | **B** | **B** | **B** | n/a | n/a | n/a | E | **B** | **B** | **B** | The parity matrix + 7-drill acceptance suite is internal governance no vendor demonstrates; caveat — several cells are 🔧 not ✅. |
| K8s/container observability | M | M | M | − | − | − | n/a | − | − | − | Absent entirely. |
| Cost awareness | M | M | M | − | − | − | n/a | M | M | − | Only internal metered-lane env toggles. |
| Security findings (WAF/FW/DNS) | − | − | − | − | − | − | n/a | − | − | − | Lanes built, no view; everyone else at least renders these. |
| Honest empty/degraded states | **B** | **B** | **B** | **B** | **B** | **B** | **B** | **B** | **B** | **B** | Category win. No one else refuses to render a fabricated zero as policy. |

Net: **wins on truthfulness, provenance, validation, and network-seam depth; loses on everything an operator does after detection, and on every scale/self-service axis.** Against the exceed-market bar: exceeds on 4 rows, at parity on ~2, behind/missing on ~9.

---

## 11. Recommended Navigation Architecture

Top-level (within the existing Monitor/Infrastructure/Admin zones, per the nav IA memory):

```
Monitor
├─ Command Center                    (existing)
├─ Cloud                             ← promoted section, the word "Cloud" in the nav
│  ├─ Overview                       (impact-first landing; readiness strip retained)
│  ├─ Services                       (catalog-backed; map = flow-fed dependency graph)
│  ├─ Investigations                 (episodes, embedded correlation view, lifecycle verbs)
│  ├─ Assets                         (facet-first inventory; Untagged = saved facet)
│  ├─ Security                       (WAF/FW/DNS findings — when lanes render)
│  └─ Data Sources                   (accounts+connectors health, sources matrix, onboarding entry)
├─ Events / Incidents / Correlations (existing)
Infrastructure
├─ Topology Canvas                   (Cloud layer cross-linked ⇄ Monitor→Cloud→Services)
Admin
├─ Cloud Connectors                  (the wizard + lifecycle + broker audit)  [operational-admin]
├─ Governance                        (required tags, attribution precedence, RCA windows, residency) [org-admin]
```

Rules: the word "Cloud" appears exactly once as a section; Settings splits by persona (operator config stays near the workflow, governance goes to Admin); every cloud entity (service, resource, account, investigation) gets a stable URL.

## 12. Recommended Information Architecture

- **Entity model:** Account → Resource → Service (catalog-owned, attribution-fed) → Investigation, each with a permanent page/URL and a consistent header (identity, health+basis, provenance, actions). Drawers remain for peek; pages for work.
- **Inventory:** facet-first (provider/account/region/type/tag/attribution-state counts server-computed), table as drill-in, resource page as leaf. This is the redesign that survives 1M resources.
- **Signals:** episode layer between raw signals and investigations (group key: resource+signal+state), with raw rows one click below — preserves the honesty ledger while making the queue humane.
- **Scope:** one global cloud scope object (provider/account/region/env/time) owned by the shell, persisted in the URL, honored by every endpoint (`?scope=` params server-side); per-tab filters compose on top.
- **Readiness:** keep readiness-first ordering everywhere; extend the capability taxonomy with *why* (`permission_denied`, `misconfigured`, `disabled_by_cost_policy` — the metered toggle deserves an honest badge).
- **Language:** keep the existing discipline (no store/vendor plumbing names in UI); add the missing *_LABEL maps for resource types (raw `ec2:instance` leaks today via `shortType` only partially).

## 13. Long-term Product Vision

**Positioning:** the only cloud monitoring product that (a) proves its data before it renders a verdict, (b) shows *why* it believes every attribution and every root cause, and (c) natively correlates cloud symptoms with the physical/hybrid network underneath — the seam where AWS+Azure+GCP tooling all go blind and where this platform already has probes, seam telemetry, and an RCA engine. Don't out-dashboard Datadog; out-*trust* everyone.

### 3-year roadmap, 4 phases

**Phase 1 — "Sellable" (Q3–Q4 2026, ~3–4 eng)**
Objectives: a customer connects a cloud account and operates a real incident without SSH or a second product area.
Features: connector wizard UI (Imp#1) + PG inventory/pagination (#2) + per-tenant inventory (#3-critical) + interactive scope/time (#6) + episode grouping (#7) + embedded investigations (#8) + bug/honesty fixes (#3, #4) + bulk attribution (#5) + real Settings v1 (#9).
Engineering effort: ~2 quarters; mostly UI over existing APIs + one store migration.
Customer impact: PoC-able by a design partner without hand-holding.
Business value: converts the platform from demo to product; unblocks the licensing tiers already designed.

**Phase 2 — "Operable at enterprise scale" (H1 2027, ~5–6 eng)**
Objectives: 500 accounts / 100k resources / 50 engineers concurrently; the 10-step loop closes.
Features: org-level onboarding (Organizations/mgmt groups/folders), connector-health alarms + permission diagnostics, service catalog + criticality + SLO v1, flow-fed dependency map, metric charting on cloud entities, notification routing + ITSM handoff from cloud surfaces, verification loop, K8s workload layer v1, findings cursors + search + export, WCAG AA pass.
Effort: 2 quarters, includes the K8s data-model work (incremental inventory).
Customer impact: daily-driver NOC tool; measurable MTTR deltas (the RCA time-intelligence lane already measures phases — use it as the proof instrument).
Business value: enterprise deals defensible; the accuracy-bench + scale-proof items from the market-analysis plan get their substrate.

**Phase 3 — "Exceed" (H2 2027, ~6–8 eng)**
Objectives: the trust differentiators nobody else can copy quickly.
Features: hybrid-seam gateway plane fully measured + rendered (the telemetry catalog's #1 on all three providers), provider-incident lanes (free on all 3) with suppression windows, security findings view over WAF/FW/DNS rollups, change diffs (property-level before/after), attribution simulator + tag-governance reporting, cost ingestion v1 with cost-of-incident context, Oracle/Alibaba + vSphere providers on the connector contract, evidence-book automation productized as customer-facing "proof of detection" reports.
Customer impact: RCA that names the seam ("your ExpressRoute BGP peer, not your app") with provider-log receipts — the demo no competitor can follow.
Business value: premium tier; competitive displacement vs TE (path) + DD (breadth) on hybrid-cloud accounts.

**Phase 4 — "Autonomous & governed" (2028, ~8–10 eng)**
Objectives: from explaining to finishing.
Features: guarded auto-remediation (audited, entitlement-gated, §3/§15-compliant), topology/config time-travel and drift, forecast/capacity lanes, compliance packs (tag policy → evidence reports), Iris AI over the evidence ledger (grounded answers only — the ledger's grounded/gap structure is purpose-built for LLM grounding without fabrication), marketplace of connector packs.
Customer impact: the loop closes without a human for the routine 60%; the rest arrives pre-investigated.
Business value: seat expansion → platform contract; the honesty ledger becomes the moat AI-washing competitors can't fake.

**North-star metric per phase:** P1 time-to-first-telemetry (target <15 min from signup), P2 MTTI/MTTR delta measured in-product, P3 % investigations with provider-receipt evidence, P4 % incidents closed with zero human diagnostic steps.

---

*Grounding appendix — key files reviewed:* `src/frontend/src/pages/AppObservability.tsx` (941 lines, all 6 tabs), `src/frontend/src/pages/appobs/{api,types,readiness,ingestion,attribution}.ts`, `Ingestion.tsx`, `AppDetail.tsx`, `shell.tsx`, `useCloudShell.ts`, `src/frontend/src/features/topology/renderers/react-flow/CloudTopologyView.tsx`, `src/frontend/src/nav.tsx`; `src/backend/cloud_handlers.go`, `cloud_signals.go`, `cloud_ingestion.go`, `cloud_enrich.go`, `cloud_store.go`, `cloud_topology_api.go`, `cloud_console.go`, `cloud_connectors_{handlers,broker,store,pg}.go`, `business_service_handlers.go`, `src/backend/cloud/`, `src/backend/cloudconn/` (via architecture doc + handlers). *Live probes:* `/api/cloud/{resources,apps,attribution/coverage,ingestion,health,changes,evidence,business-services,connectors,providers}`, `/api/topology/cloud` on the running tri-cloud stack, 2026-07-15.
