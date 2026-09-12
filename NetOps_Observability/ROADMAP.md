# NetOps Observability — Frontend/Product Roadmap

Goal: evolve the UI from a strip of tabs into one cohesive product in the
spirit of Splunk / the reference platform / Zabbix / Grafana — both in **information
architecture** and in **visual polish**.

## ✅ Phase 1 — Unified shell (done)
Persistent left sidebar + global top bar; global time-range and omni-search
that flow through every section via `ShellContext`; Copilot as a right-side
slide-over. The 14 legacy tabs were reparented into 7 product sections:
Overview · Search · Analytics · Datasets · Dashboards · Alerts · Reports ·
Topology. See `src/frontend/src/nav.tsx`.

## ▶ Phase 2 — Visual design system (in progress)
Adopt **the reference platform's whole look & feel** — not just for the topology, but the
entire shell: dark nav rail + **light content canvas**, dense-but-legible
type, soft-elevated cards, vibrant accents.
- **Light canvas + dark rail** (the reference platform convention; the earlier all-dark idea
  was retired after reviewing the reference platform references). Brand lockup moved into the
  rail; topbar is now omni-search + global time-range + user.
- **Design tokens** (`styles.css :root`): type scale (`--fs-*`), space
  (`--sp-*`), radius (`--r-*`), rail palette, vivid accent + gradient
  (`--accent-grad`), elevation shadows. Reference tokens, don't hardcode.
- **Severity color system** (critical / error / warning / notice / info /
  debug) applied consistently to **Logs** and **Alerts/Findings** — badges,
  row accents, dots; concrete hex in `theme/severity.ts`.
- A **vivid categorical chart palette** (10 saturated hues) + area-gradient and
  line-series helpers in `theme/charts.ts`, shared across every ECharts view.
- **Topology** redrawn a "network-path"-style: role-tiered node cards
  health-tinted by worst active alert, latency-colored tunnel edges with `ms`
  labels, click-to-inspect detail panel.

## ✅ Phase 3 — Saved-objects backend (done)
`/api/saved` + `/api/saved/{id}` CRUD over a file-backed `savedStore`
(stdlib-only, mirrors the user store; swap to Postgres later with no
API-surface change). One object model for `saved_search` / `dashboard` /
`report` with an opaque JSON body. Wired end-to-end for **saved searches**:
Search has a ★ Save action and a Search → **Saved** sub-view that lists,
re-opens (applies the query to the global omni-search), and deletes them.
Dashboards/reports reuse the same store — their builder UIs are future work.

## ✅ Phase 4 — Native analytics (done)
`/api/metrics/{query,query_range,names}` Go proxy to a Prometheus-compatible
backend (METRICS_URL, defaults to Prometheus; point at VictoriaMetrics once
SNMP/remote_write feeds it). Analytics → Metrics is now a native ECharts
Metrics Explorer (PromQL input + name autocomplete + global-time-range),
with the raw Prometheus UI kept under Analytics → Prometheus.

## ✅ Phase 5 — Reports + global search (done)
- **Global search**: `/api/search/global` resolves a free-text query to jump
  targets — devices, active alerts, saved objects — plus a raw log-search
  handoff. The top-bar omni-search now shows a live, keyboard-navigable results
  dropdown (debounced) that routes straight to the matching section, instead of
  only running a Lucene log query. See `search_global.go` + `TopBar.tsx`.
- **Reports**: a `report` saved object carries `{kind, interval_minutes,
  severity, enabled, description}`; the server-side `reportScheduler`
  (`report_scheduler.go`) ticks each minute, renders a point-in-time summary
  (alerts / device inventory / stack health) from in-memory state, and delivers
  it through the existing `notify/` dispatcher (Slack/email/PagerDuty/…) by
  reusing the `models.Alert` shape. Run-state (last/next fire, status) is
  file-backed in `data/report_runs.json`, kept out of the frontend-owned body.
  `GET /api/reports/runs` + `POST /api/reports/run` back the Reports builder UI
  (create, monitor, **Send now**, delete). Gated by `ENABLE_REPORT_SCHEDULER`
  (default on).

## ✅ Phase 6 — Identity, Access, API & ITSM (done)
Enterprise readiness, all live under **Administration** (`tabs/admin.tsx`) and
the Go API — every piece honors the stdlib-only backend rule (federation is
pushed out to Keycloak; the API only verifies tokens).
- ✅ **Auth + granular RBAC** — file-backed local accounts (→ Postgres later),
  module-level permissions (none/read/write/admin), built-in **and** custom
  roles. See [`docs/IDENTITY_ACCESS.md`](docs/IDENTITY_ACCESS.md).
- ✅ **True multi-tenancy** — every device carries a `tenant_id`; a tenant-bound
  principal can **never** see or mutate another tenant's devices (or their
  alerts). Super-admins / global principals see across tenants; shared/global
  resources stay visible to all. Tokens carry the tenant claim; enforced at the
  API boundary (`tenancy.go`, with `tenancy_test.go` covering the leak cases).
- ✅ **Token auth** — short access token (`ACCESS_TOKEN_TTL`, default 1h) +
  rotating, single-use refresh token (7d) with replay detection that revokes the
  lineage (`refresh.go`); the SPA auto-renews. Keycloak-issued **RS256** tokens
  are verified against the IdP JWKS in pure stdlib (`jwks.go`).
- ✅ **SSO — OIDC, SAML 2.0, LDAP/AD via Keycloak** — Authorization-Code flow
  (`oidc.go`): `/api/auth/sso/{config,login,callback}`. SAML/LDAP IdPs are
  selected with `kc_idp_hint`; the callback verifies the ID token, JIT-provisions
  the user (role mapped from Keycloak roles/groups) and re-issues a native
  session. Login page + Administration → Authentication render the live
  providers. Keycloak ships as an opt-in compose service (`--profile sso`).
- ✅ **API Access** — scoped, tenant-bound API keys (Bearer / `X-API-Key`) whose
  RBAC role is derived from their scopes; a live **OpenAPI 3** document at
  `/api/openapi.json` with an in-app reference. See [`docs/API_ACCESS.md`](docs/API_ACCESS.md).
- ✅ **ITSM — ServiceNow auto-ticketing** — bi-directional: alerts at/above a
  configurable threshold open a deduped incident and **auto-resolve** it when the
  alert clears; open-ticket state is persisted across restarts; live status +
  open incidents surface in Administration → ITSM (`notify/servicenow.go`).
  See [`docs/ITSM_INTEGRATION.md`](docs/ITSM_INTEGRATION.md).

## ✅ Phase 7 — Backlog / cross-cutting ideas (done)
- ✅ **Jira ITSM connector** — `notify/jira.go` mirrors the ServiceNow shape:
  bi-directional auto-ticketing (open at/above threshold via REST v2, transition
  to Done on clear), deduped by fingerprint, file-backed open-ticket state, live
  status in Administration → ITSM (`GET /api/itsm/jira`). Either/both connectors
  run at once. See [`docs/ITSM_INTEGRATION.md`](docs/ITSM_INTEGRATION.md).
- ✅ **Tenant scoping extended** past devices/alerts to **flows** (by device
  address), **findings/tunnels** (by device id/name), **saved objects**
  (`tenant_id`, scoped list + mutate), GraphQL, and global search. Leak cases
  pinned by `tenancy_saved_test.go` + `tenancy_flows_test.go`.
- ✅ **GraphQL explorer + per-key rate limits + usage stats** — an in-app,
  GraphiQL-style console (query editor + examples + JSON pane) over the typed,
  tenant-scoped `/api/graphql`; per-API-key fixed-window rate limiting (429 +
  `Retry-After`) with live current-minute usage and lifetime call counts in
  Administration → API Access. See [`docs/API_ACCESS.md`](docs/API_ACCESS.md).
- ✅ **Postgres-ready identity/saved stores** — all JSON-blob stores persist
  through one pluggable backend (`kvstore.go`): file by default, Postgres with
  `STORE_BACKEND=postgres` (`pgkv.go`, stdlib `database/sql` only — the default
  build stays dependency-free), **no API change**. See the *Storage backend*
  section of [`docs/IDENTITY_ACCESS.md`](docs/IDENTITY_ACCESS.md).
- ✅ **Dark-mode toggle** — `[data-theme]` swap over the centralized tokens
  (`theme/prefs.ts`), in the user menu, persisted, no flash on load.
- ✅ **Density toggle** — comfortable / compact tables via `[data-density]`.
- ✅ **Keyboard command palette (⌘K)** — `components/CommandPalette.tsx`: jump to
  any section, run actions (theme/density/Copilot), or search devices/alerts/
  saved live; arrow-key navigable.
- ✅ **Per-section saved time-range presets** — each section remembers its own
  range, plus user-defined custom presets in the picker (`theme/timeprefs.ts`).

## ▶ Phase 8 — Further backlog
- Promote the GraphQL naïve dispatch to a real schema + resolvers.
- ITSM inbound state-sync loop (poll/webhook) reflecting ticket state onto
  incidents; field-mapping editor; CMDB enrichment for ServiceNow.
- Postgres backend: ship a committed `-tags pg` driver import + migrations.
