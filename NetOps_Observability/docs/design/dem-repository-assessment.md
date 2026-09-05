# DEM — repository assessment (Phase A, 2026-09-05)

**Purpose.** The owner's implementation contract (`docs/design/research/DEM_OWNER_DESIGN_2026-09-05.md`,
Phase A) requires a written assessment of the repository *before* Digital Experience
Monitoring is built into it, so that DEM extends what exists instead of becoming a
parallel silo. This is that assessment. The design of record it serves is
`docs/design/DEM_2026-09-05.md` — **§M is authoritative** and this document defers to it
everywhere.

**Method.** Every claim below was read out of the code on 2026-09-05 at `c8bce9aa`, not
inferred from the design documents. Where a design document and the code disagreed, the
code is recorded and the disagreement is called out.

---

## 1. Current architecture (what DEM lands on)

### 1.1 Backend

| Concern | Where | Notes that mattered to DEM |
|---|---|---|
| Entry point / wiring | `src/backend/main.go` (`newServer()`, `routes()`) | Routes are `mux.HandleFunc` with **string literals** — the isolation ledger's scanner reads those literals out of this file, so a route registered through a constant is a route nobody classified. Domain code may not live here: `TestFlatPackageMainDoesNotGrow` pins the root at 208 non-test `.go` files. |
| Domain packages | `src/backend/internal/*` | 80+ packages. The house pattern is a self-contained module with its own `http.go` (an injected `Deps` struct: `Authz`, stores, `Now`, `WriteJSON`, `WriteError`, `LogWarn`), its own store seam with a Postgres and a file backend, and a thin `*server` method in the root that wires them. |
| Authorization | `requirePerm(module, level)`, `requirePlatformAdmin`, `requireCrossTenant` | `principalTenant(claims) → (tenant, cross)` is applied *inside* the handler, never as the gate. |
| Relational store | `internal/platformdb` | `//go:embed migrations/*.sql`, applied in lexical order under an advisory lock. `WithTenant(ctx, tenant, cross, fn)` sets `app.tenant_id` for the FORCE-RLS `tenant_iso` policies. Migrations need no registration beyond the filename. |
| Time series | VictoriaMetrics via `vmInstantScoped(ctx, expr, filters)` | Tenant scoping is `extra_filters[]`, AND'd in by the backend, so a crafted expression cannot evade it. |
| Columnar store | ClickHouse (`netops.*`) | Written by **Vector** (Kafka → `clickhouse` sink) and by the Python correlation service's own HTTP inserts. There is **no Go Kafka client** (allowlist); the Go API produces onto the bus through `bus_producer.go`'s `produceJSON` → the Vector bus-bridge HTTP source. DDL must be kept in **two** places: `deployment/docker/clickhouse/init.sql` (fresh installs) and `internal/chschema/*.go` + `ConvergeStmts()` (live upgrades). Reads go through `chRows(r, sql)` with the `tenant_scope` setting the row policies match. |
| Pagination | `internal/httppage` | `RejectUnknownQuery`, `Parse`, `SliceOf`, `WriteHeaders`, `Complete`. A misspelt page parameter must FAIL, not be swallowed. |
| Incidents | `internal/incident` | Postgres+RLS system of record; `Repo.Ingest` dedups by key. **Nothing promotes a correlation object into it today** — the only caller is `ingestAlertIncident` in `incidents_http.go`, driven by the alert engine. |
| Correlation | `src/correlation/*.py` | Objects live in ClickHouse (`corr_objects`, `corr_signals`, `corr_evidence`); the Go side (`correlations.go`) is **read-only**. |
| Entitlements | `internal/entitlement` | Feature vocabulary is **closed and locked by owner decision (2026-09-04)**: "adding a value takes an owner decision, not a diff". |

### 1.2 The DEM plumbing that already shipped (`internal/dem`, S17)

`Target` catalogue (PG migration `0043` + file store, 500/tenant), the ICMP/TCP/DNS/HTTP
prober driven by an api-published work queue, the `dem_*` series
(`{tenant,target,kind,site,app,source}`), a **pure** three-component score
(availability as error-budget burn, p95 against the *declared* budget, path stability)
with an explicit not-measured discipline, four `warning`-tier alert rules with promtool
tests, and additive `target:`/`site:`/`app:` grounding on the correlation probe lane.
`pages/DigitalExperience.tsx` was a deliberate stub with no nav entry.

### 1.3 The frozen Service Path Graph contract

`docs/design/service-path-graph-contract.md` + `src/backend/pathgraph`:
`Provenance` on every object, `Endpoint` (an address→entity **binding**, time-bounded),
`PathDefinition` (identity = tenant+src+dst+direction+protocol+port+vantage+context),
`PathObservation` (**immutable**, one per run), `PathHop` (1-based ordinal, `missing`
hops preserved), and a server-computed **ordered spine** (`BuildSpine`) that the UI is
forbidden from re-laying-out. The frontend mirror is
`src/frontend/src/components/rca/servicePath.ts` + `topoGraph.ts`.

### 1.4 Frontend

Hand-rolled hash router (`App.tsx` + `nav.tsx`, `#/section/leaf[/sub]`), lazy route
chunks in `ROUTE_CHUNKS`, `SectionCtx` prop bag. Sub-tabs are page-local state seeded
from the third hash segment (`AppObservability.tsx`). One `request<T>` fetch wrapper and
a flat `api` object in `services/api.ts`. Two generations of CSS tokens in `styles.css`.
Vitest + testing-library, with the whole `services/api` module mocked at the boundary.
`pages/appobs/readiness.ts` holds the honest-state vocabulary
(`flowing|stale|off|permission_denied|misconfigured|no_data|not_supported`).

### 1.5 Guards that constrain any change here

`TestEveryRouteClassified` (ledger), `TestEveryScopedRouteHasIsolationCoverage` (a scoped
route needs a real cross-org test, and the baseline is frozen),
`TestFlatPackageMainDoesNotGrow` (root file ratchet 208), `TestNoSscanfIntParsing`,
`TestBlankDiscardsCarryJustification`, `TestErrorIsNotConflatedWithABenignState`,
`tests/test_feature_ui_coverage.py` (every public route family needs a UI or a written
reason; the allowlist entry must be **deleted** the moment the page calls the route).

---

## 2. Reusable components (what DEM extends rather than duplicates)

| Owner's canonical object | Reused | How |
|---|---|---|
| `Endpoint` / `PathDefinition` / `PathObservation` / `PathHop` | **`src/backend/pathgraph`, unchanged** | DEM stores a *reference* (`path_observation_id`) and never copies hops. `GET /api/dem/incidents/{id}/path` returns the reference plus an honest reason when there is none; the ordered spine is still served by the path API, which stays the single source of hop order. |
| Verdict tiers + the independence rule | `src/correlation/verdicts.py` | Re-expressed in Go as `Hypothesis.Grade` over `Independence`, using the **same** modality-class vocabulary (`active_probe`, `passive_flow`, `control_plane`, `device_telemetry`, `management_plane`, `active_verification`, `security`). CONFIRMED still needs two distinct anchor classes, two observers and a concrete independent pair. |
| Incident | `internal/incident` | `ExperienceIncident` carries `incident_id` + `promoted` and is designed to be the DEM *packet* for that record. It is **not** a second lifecycle. |
| Score maths | `internal/dem/score.go` | Untouched. The published experience score is a different subject (journey/app/tenant, six dimensions, policy-versioned); the per-target verdict feeds three of its dimensions. |
| Catalogue + prober + series | `internal/dem` | The journey step→target binding is the whole measurement path; there is no second synthetic registry. |
| Readiness vocabulary | `pages/appobs/readiness.ts` | `SourceHealth.State` uses the identical seven states, plus `coverage` and `confidence_influence`. |
| Pagination, JSON writers, logging, RBAC gate | `internal/httppage`, `writeJSON`/`writeError`, `logWarn`, `s.demAuthz` | Reused verbatim. |
| RCA UI components | `src/frontend/src/components/rca/*` | Composed by import only; not modified (another agent's investigation page depends on them). |

---

## 3. Gaps found (and what this slice did about each)

| # | Gap | Disposition |
|---|---|---|
| G1 | No canonical evidence/hypothesis/confidence model on the Go side; the Python engine's grading is not reachable from the API. | **Built**: `internal/dem/experience` — `EvidenceItem`, `MissingEvidence`, `Independence`, `Hypothesis` + the documented confidence maths. |
| G2 | No journey concept anywhere. | **Built**: `JourneyDefinition` (branching, optional steps, loops), `JourneyHealth` composed **multiplicatively** over required steps; PG migration `0044`. |
| G3 | "What changed" is scattered across config drift, cloud, BGP and deployment surfaces with no common shape. | **Built**: `ChangeEvent` + `POST/GET /api/dem/changes` + correlation-based ranking (`RankChanges`). Adapters that pull the *existing* producers into the feed are next-slice work. |
| G4 | No experience-source health: the readiness model is cloud-inventory-specific. | **Built**: `SourceHealth`/`DataHealth` over the DEM source ladder, with coverage, anchor capability and confidence influence. |
| G5 | No RUM, no flow-derived ART, no SD-WAN SLA, no wireless client feed → **only one anchor-capable modality class is live**, so a live tenant can reach `suspected` and not `confirmed`. | **Made VISIBLE, not hidden**: `DataHealth.CanConfirm` states it in one field with a sentence. Track T0 producers are out of this run. |
| G6 | Nothing produces per-*run* synthetic records, so per-check reliability cannot be graded. | Contracts + `GradeReliability` shipped and tested; the coverage surface reports every check's reliability as **unknown**, never as trustworthy. |
| G7 | No AI investigator contract. | **Built as contract only**: evidence packet, JSON output schema, evidence-id whitelist validator, no-confirmation downgrade, feature flag `FEATURE_DEM_AI_INVESTIGATOR`. No provider call. |
| G8 | `internal/entitlement`'s Feature vocabulary is owner-locked and has no `FeatureDEM`. | **Not added** — see §6. Gating remains the `FEATURE_DEM` env flag. |
| G9 | `internal/incident` has no promotion path from correlation, so an experience incident cannot become a platform incident automatically. | Modelled (`IncidentID`/`Promoted`), not wired. Next slice. |
| G10 | No YAML reader in the Go build (allowlist). | A strict, closed-grammar reader for the score policy's exact three-level shape, which **refuses** everything it does not understand. |

---

## 4. Files to modify / add

**Added** (all new domain code under `internal/dem/experience`, per the root ratchet):
`doc.go`, `provenance.go`, `evidence.go`, `confidence.go`, `hypothesis.go`, `journey.go`,
`change.go`, `score.go`, `policy.go`, `score-policy.yaml`, `incident.go`, `datahealth.go`,
`synthetic.go`, `event.go`, `investigator.go`, `store.go`, `pg.go`, `assemble.go`,
`http.go`, `metrics.go` + tests; migration `0044_dem_experience.sql` and its rollback;
`src/backend/dem_experience_isolation_test.go`; the `pages/experience/` tree and the
seven Phase U design documents.

**Modified** (thin, additive hunks only):
`src/backend/main.go` (fields, construction and eight route literals, inside the existing
`DEM-BEGIN/DEM-END` block), `src/backend/probe_handlers.go` (the wiring, in a
`DEM-EXPERIENCE-BEGIN/END` block — no new root file),
`src/backend/internal/openapi/openapi.go`, `src/backend/route_isolation_test.go`,
`src/frontend/src/{nav.tsx,services/api.ts,styles.css}`,
`src/frontend/src/pages/DigitalExperience.tsx`, `docs/audit/headless-routes.yaml`,
`docs/projects/05-SHIP-READINESS.md`, `docs/TRACKER.md`.

---

## 5. Migration implications

* `0044_dem_experience.sql` is **additive and idempotent**: two new tables
  (`dem_journeys`, `dem_change_events`), each with `ENABLE`+`FORCE ROW LEVEL SECURITY`
  and the `tenant_iso` policy, plus a rollback that drops only those two tables. No
  existing table, column, index or policy is touched.
* Nothing derived is stored, so a rollback loses no analysis: evidence, hypotheses,
  incidents and scores are recomputed from the measurements, the path observations and
  the producers' own records.
* The file backend gains one new file (`DEM_EXPERIENCE_FILE`, default
  `/data/dem_experience.json`). A corrupt file starts empty **and says so**.
* No ClickHouse table and no Kafka topic are added in this slice (see §6).

---

## 6. Compatibility risks and the decisions taken

1. **`FeatureDEM` was NOT added.** `internal/entitlement/entitlement.go` states the
   vocabulary is "CLOSED and LOCKED by the owner spec of 2026-09-04" and that adding a
   value "takes an owner decision, not a diff"; §M.9/§M.11 list DEM packaging as an open
   owner decision. Inventing the constant would have pre-empted a decision the design
   itself defers. DEM stays gated on `FEATURE_DEM`. **Owner decision required.**
2. **`ExperienceEvent` / `ExperienceSession` / `BusinessEvent` landed as contracts, not
   as an ingest lane.** Wiring them end to end needs a Kafka topic, a Vector route, a
   ClickHouse table in *two* places, and a row policy — and **no producer exists**
   (there is no first-party RUM snippet, no desktop agent, no browser runner). Phase P
   says infrastructure is added when there is a requirement, not before. The shapes,
   their validation, the pseudonymous-user discipline and the `EventSink` seam ship now
   so the lane can be added without changing them.
3. **Incidents are DERIVED at read time, not stored.** Same bundle ⇒ same incident, same
   id, same confidence (proven by test); no background writer can drift from what the
   API returns; and there is no window in which a stored conclusion contradicts the
   evidence beneath it. The cost is recomputation per request, bounded by the same
   500-target ceiling the catalogue already has.
4. **The existing `/api/dem/experience` contract is unchanged**, as are the four
   `noc-experience` alert rules and `internal/dem/score.go`'s grade thresholds. The new
   70/30 bands apply to the *published experience score*, a different subject; both are
   named and documented so they cannot be mistaken for each other.
5. **A live tenant will read `suspected`, not `confirmed`, until a second anchor-capable
   source exists.** That is the correct answer, not a limitation to be worked around,
   and the Data Health surface says so in one sentence.
6. **`components/rca/*` was not modified.** The Experience Incident view composes those
   components by import; anything that would have required changing them is deferred and
   listed in the delivery report.
