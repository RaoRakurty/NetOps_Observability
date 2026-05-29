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
Make it look "elite, transparent, modern" like Datadog/Grafana.
- A refined dark palette built on **semi-transparent, layered** surfaces.
- **Severity color system** (critical / error / warning / notice / info /
  debug) applied consistently to **Logs** and **Alerts/Findings** — badges,
  row accents, and dots.
- A **varied categorical chart palette** (8–12 modern hues) shared across all
  ECharts views so trends read vividly; a single dark ECharts theme.
- Tokens centralized so future theming (light mode, accent swap) is trivial.

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

## Backlog / cross-cutting ideas
- Light theme + per-user theme preference.
- Density toggle (comfortable / compact tables).
- Keyboard command palette (⌘K) over the omni-search.
- Per-section saved time-range presets.
