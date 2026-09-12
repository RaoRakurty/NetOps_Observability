# DEM — plumbing of record (2026-09-05)

The **design of record** is `docs/design/DEM_2026-09-05.md` (Correlix half, to
be merged with the owner's own document); the identity/series model is
`docs/design/DEM_DATA_MODEL_2026-09-05.md`. This file is neither. It records
**what actually shipped underneath them** — the per-tenant catalogue, the prober
kinds, the series, the score maths, the alert rules and the correlation
grounding — so the design, when it is ratified, has something real to drive.

**The page is HELD.** `src/frontend/src/pages/DigitalExperience.tsx` is a route
stub that says the design is in progress, and there is no nav entry. The
intended one, for whoever wires it: section **Operations** (the 2026-08 IA
dissolved "Monitoring" into it), leaf **Digital Experience**, route
`#/operations/digital-experience`.

✅ built · 🟡 partial · ⛔ deliberately not built (reason given).

---

## 1. What shipped

| # | Capability | Status | What exists | What is missing / next |
|---|---|---|---|---|
| 1 | Per-tenant synthetics catalogue | ✅ | `internal/dem` — `Target{id, tenant, name, kind, host, port, resolver, interval, site, app, expect_status, latency_budget_ms, availability_budget_pct, paused}`. Two backends behind one `Catalogue` interface: Postgres (migration `0043_dem_targets.sql`, `tenant_iso` FORCE-RLS, every statement inside `WithTenant`) and a tenant-keyed file store through the platform KV seam (`DEM_TARGETS_FILE`, default `/data/dem_targets.json`). Bounded: 500 targets/tenant, 15s..1h intervals, every field validated at the boundary AND again in the store. | Nothing outstanding. A kind change is a delete + create by design — changing it would orphan every series already recorded under the target's id. |
| 2 | CRUD routes | ✅ | `GET/POST /api/dem/targets`, `GET/PUT/DELETE /api/dem/targets/{id}`, gated `requirePerm(infrastructure, read/write)`. Owner stamped from the token — the create wire type has **no** tenant field, so a tenant claim cannot be expressed and an unknown field is refused outright. Cross-tenant id → 404. Cross-tenant principal → refused, never served the fleet. `as_tenant` accepted (narrowing only); every other unknown query parameter refused. Classified `scoped` in the route-isolation ledger; advertised in the OpenAPI document under tag *Digital Experience*. | — |
| 3 | Prober kinds | ✅ | `collectors/dem.go` — a catalogue-driven runner that **reuses** the existing synthetics check functions for HTTP / TCP / ICMP and adds **DNS** (resolution time; `nxdomain` / `timeout` / `no_answer` / `dns` fail classes; an optional pinned resolver, which is what makes "our resolver is slow" separable from "the internet is slow"). HTTP honours a declared `expect_status`, keeps the bounded body read and capped redirects, and verifies TLS against the system trust store — the lab's re-signing SASE proxy is exactly why an exception would be the wrong answer. Per-target scheduling on a 15s resolution, bounded concurrency 8, `safego` around every check. | Path measurement is read from the traceroute collector rather than run per target (see #5). |
| 4 | Work queue (api → prober) | ✅ | `internal/dem.Projector` publishes the fleet's ACTIVE targets to the same key-value channel the WAN-circuit projector uses, with a TTL of 3× the interval — so a prober that loses the api stops measuring a stale list instead of measuring deleted targets forever. The prober needs no new credential and stays off the authenticated surface. `dem.WireTarget` carries what a check needs plus the budgets, and nothing else — no operator name, no created-by. Paused targets are not published: pausing STOPS the measurement, it does not merely hide the row. | — |
| 5 | Series | ✅ | `dem_probe_success` · `dem_probe_latency_ms` · `dem_probe_loss_pct` · `dem_probe_ttfb_ms` · `dem_path_fingerprint` · `dem_path_hops` · `dem_targets` · `dem_target_availability_budget_pct` · `dem_target_latency_budget_ms`, all labelled `{tenant,target,kind,site,app,source}`. Plus `collector_up{collector="dem"}` — the probe collectors historically emitted **none**, which is why "the prober is not running" was invisible to every rule. | Path fingerprints exist only where the traceroute collector has a fresh (<30m) trace to the same host; otherwise path stability is honestly *not measured*. A per-target trace is the next step. |
| 6 | Experience score | ✅ | `internal/dem/score.go`, pure and table-tested. Availability as **error-budget burn** (99.0% against a 99.9% budget is a tenfold overrun and must not read as "99 out of 100"); p95 against the **declared** latency budget only; path stability from fingerprint changes. An unmeasured component contributes nothing and its weight is redistributed. Site and app rollups weight the **worst** target at 0.4 so one hard outage cannot vanish into a green tile, and count what they could not score separately. | The score's shape is deliberately simple pending the design of record's published-score definition; the maths lives in one pure file so replacing it is a contained change. |
| 7 | Honest states | ✅ | `GET /api/dem/experience?window=1h\|24h` returns `measured:false` plus a stable `reason` and an operator sentence for: feature off · no targets declared · target paused · prober not reporting · metrics store did not answer. Never an empty table, never a fabricated 0 or 100. | — |
| 8 | Alerts | ✅ | `noc-experience` group in `src/config/rules.yaml`: `ExperienceAvailabilityBelowBudget`, `ExperienceLatencyOverBudget`, `ExperiencePathUnstable`, `ExperienceProberNotReporting`. All `tier: warning` — the owner's four-page ruling stands, and "an application is slow" is not one of the four. Thresholds are the budget **gauges**, so each comparison is pure PromQL and keeps evaluating while the api, which owns the catalogue, is the thing that is down. promtool unit tests (`src/config/rules-tests/digital-experience.test.yaml`) prove each fires on the fault AND stays silent on the false-positive shape. | — |
| 9 | Notification routing | ✅ | Delivered by the **product notifier** (the in-API alerts engine, which reads the same rules file). `alertTenant` gains one narrow exception: a device-less alert whose rule name begins `Experience` takes its tenant from the `tenant` label — a value our own prober writes from the catalogue, not device-supplied telemetry. The platform vmalert→webhook lane refuses these on sight, as it refuses every customer-identity alert, and that is correct: a tenant's slow application is not a platform page. | — |
| 10 | Correlation grounding | ✅ | `producers.probe_signals` grounds `target:<id>`, `site:<site>` and `app:<app>` tokens, sets `Signal.site` (which `engine.Node.tokens()` promotes for a `PATH` entity) and `Observer.location`, and carries `target_id` / `site_id` / `app` in `attrs`. `handle_probe` accepts the prober's `tenant` as a CLAIM, still adjudicated by `verified_tenant`. Additive: an event without the DEM fields grounds exactly as before, pinned by a test. | The saas-experience catalogue template's verdict text is still static strings; naming the site per incident is a template change, not a grounding one. |
| 11 | The page | ⛔ **held** | A route stub. | The merged design of record comes first. |

## 2. Why the catalogue, and not the env lists

The env-driven `synthetics` collector (`SYNTHETIC_HTTP_TARGETS` &c.) stays and is
untouched. It structurally cannot be the DEM feature:

1. **An env list has no owner**, so its results can never be scoped to a tenant —
   and its `synthetic_*` series carry only `dst` + `check`, which matches none of
   the platform's device/hostname/source scoping filters. A scoped tenant sees
   nothing from them at all, today.
2. **An env list has no budget**, so there is nothing to be over or under, and
   any alert on it would fire against a threshold nobody set.
3. **An env list cannot be edited by an operator** without redeploying a
   privileged container.

## 3. Isolation posture (CLAUDE.md §3a)

| rule | how it is held |
|---|---|
| 1 — scope by the principal, default-closed | `API.scoped()` resolves ONE concrete tenant and refuses a cross-tenant principal; the file store's rows are a tenant-keyed map, so a lookup for A cannot walk B's bucket; a scopeless read returns nothing, which is what an empty RLS GUC does on the Postgres twin |
| 2 — stamp the owner from the token | the create wire type has no tenant field at all; `TenantID` comes from `principalTenant(claims)` |
| 3 — the right gate | `requirePerm(infrastructure, …)` + tenant filter. Experience targets are per-tenant operator data about the tenant's own services, not platform plumbing — a platform gate would lock tenant admins out of their own targets and let a cross-tenant principal manage everyone's |
| 4 — storage enforces it | Postgres: migration 0043 `tenant_iso` FORCE-RLS + `WithTenant` on every statement. File: tenant-keyed map, no unscoped list. VictoriaMetrics: `dem.TenantFilter` emits `extra_filters[]={tenant="…"}` on every query and a **match-nothing sentinel** when it cannot — there is no code path that issues an unfiltered one |
| 5 — ship an isolation test | `src/backend/dem_isolation_test.go` (real router, real gate mapping) and the store-level half in `internal/dem/store_test.go` |

The one cross-tenant path is `Catalogue.ListAll`, used **only** by the projector
to build the prober's fleet work queue. It is unreachable from any HTTP handler.

## 4. What is deliberately absent

* **A per-target traceroute.** Path stability reads the traceroute collector's
  registry. Where no fresh trace exists the score says *path stability not
  measured* — it never says "stable", because we did not look.
* **A `device` label on the experience series.** A target is a service; the
  device in front of it is a hypothesis about why it is slow, not the thing
  being measured. Joining the two is RCA's job, and RCA now has the tokens.
* **The page.** See #11.
