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

## Phase 3 — Saved-objects backend (Postgres)
`saved_searches`, `dashboards`, `reports` tables + `/api/saved/*` CRUD. Makes
Search → Dashboard → Report one continuous flow. Native savable Dashboards
section. (Postgres is currently underused.)

## Phase 4 — Native analytics
`/api/metrics/query[_range]` proxy to VictoriaMetrics; an ECharts Metrics
Explorer so Analytics renders natively instead of iframing Prometheus.

## Phase 5 — Reports + global search
Server-side report scheduler delivering via the existing `notify/` dispatcher;
`/api/search/global` omni-box resolving devices, alerts, and saved objects.

## Backlog / cross-cutting ideas
- Light theme + per-user theme preference.
- Density toggle (comfortable / compact tables).
- Keyboard command palette (⌘K) over the omni-search.
- Per-section saved time-range presets.
