# NetOps Observability — Frontend/Product Roadmap

Goal: evolve the UI from a strip of tabs into one cohesive product in the
spirit of Splunk / Datadog / Zabbix / Grafana — both in **information
architecture** and in **visual polish**.

## ✅ Phase 1 — Unified shell (done)
Persistent left sidebar + global top bar; global time-range and omni-search
that flow through every section via `ShellContext`; Copilot as a right-side
slide-over. The 14 legacy tabs were reparented into 7 product sections:
Overview · Search · Analytics · Datasets · Dashboards · Alerts · Reports ·
Topology. See `src/frontend/src/nav.tsx`.

## ▶ Phase 2 — Visual design system (in progress)
Adopt **Datadog's whole look & feel** — not just for the topology, but the
entire shell: dark nav rail + **light content canvas**, dense-but-legible
type, soft-elevated cards, vibrant accents.
- **Light canvas + dark rail** (Datadog convention; the earlier all-dark idea
  was retired after reviewing Datadog references). Brand lockup moved into the
  rail; topbar is now omni-search + global time-range + user.
- **Design tokens** (`styles.css :root`): type scale (`--fs-*`), space
  (`--sp-*`), radius (`--r-*`), rail palette, vivid accent + gradient
  (`--accent-grad`), elevation shadows. Reference tokens, don't hardcode.
- **Severity color system** (critical / error / warning / notice / info /
  debug) applied consistently to **Logs** and **Alerts/Findings** — badges,
  row accents, dots; concrete hex in `theme/severity.ts`.
- A **vivid categorical chart palette** (10 saturated hues) + area-gradient and
  line-series helpers in `theme/charts.ts`, shared across every ECharts view.
- **Topology** redrawn Datadog "Network Path"-style: role-tiered node cards
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

## ▶ Phase 6 — Identity, Access, API & ITSM (design + scaffolding)
Enterprise readiness. UI previews are live under **Administration**
(`tabs/admin.tsx`, clearly marked *Planned*); the build plans are written:
- **Auth + multi-tenancy + granular RBAC** — local accounts → Postgres, tenants,
  module-level permissions (none/read/write/admin), built-in **and** custom
  roles. See [`docs/IDENTITY_ACCESS.md`](docs/IDENTITY_ACCESS.md).
- **SSO** — OAuth2/OIDC, SAML 2.0, LDAP/AD via **Keycloak** as the identity
  broker (keeps the Go backend stdlib-only); JWT RS256 with configurable expiry
  + rotating refresh tokens.
- **API Access** — inbuilt programmatic API: scoped, tenant-bound API keys,
  OpenAPI reference + GraphQL explorer. See [`docs/API_ACCESS.md`](docs/API_ACCESS.md).
- **ITSM** — ServiceNow + Jira bi-directional ticketing on the existing
  `notify/` framework. See [`docs/ITSM_INTEGRATION.md`](docs/ITSM_INTEGRATION.md).

## Backlog / cross-cutting ideas
- Dark-mode toggle (tokens already centralized; add a `[data-theme]` swap).
- Density toggle (comfortable / compact tables).
- Keyboard command palette (⌘K) over the omni-search.
- Per-section saved time-range presets.
