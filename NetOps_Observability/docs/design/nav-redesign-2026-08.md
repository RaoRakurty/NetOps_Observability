# Correlix Navigation Redesign — Proposal (2026-08-12)

**Status: PROPOSAL — no code changed.** Grounded in a full route/nav
inventory of the frontend (11 sections, 59 leaves, 13 flyout sub-items,
2 shells, hash routing; every claim file:line-verified). The mapping below
accounts for every existing page — nothing is deleted; every current hash
keeps working via the existing alias mechanism (`resolveRoute` already
carries `#/explain/*` → admin precedents).

## 0. Design thesis

Correlix's differentiator is correlation/RCA, but the current IA is organized
by SIGNAL TYPE and IMPLEMENTATION SURFACE (Metrics / Flows / Logs as
top-level sections; three collector pages split across Administration;
Capacity/Change-Review/Executive hidden as topology "workflow modes";
Action Queue buried inside a dashboard). The proposal reorganizes around the
operator journey:

  Observe → Investigate → Correlate → Evidence → Impact → Owner → Action

Seven primary sections, max depth Section → Page (flyout groups within a
page where already built). The five-word vocabulary split (Correlations /
RCA Candidates / Incidents / Anomalies / Findings) is consolidated.

## 1. Target navigation tree

**OVERVIEW** (landing)
- Operations Dashboard — merge of today's Command Center (KPIs, owner/ticket
  gaps) with Operations Overview's health strip. One page, one route.
  My Dashboard + saved boards remain as personal views under it.

**MONITOR** — "what is happening right now?"
- Incidents (today: Monitoring→Incidents, "Operational Incidents")
- Alerts (today: Monitoring→Active Alerts; episodes model unchanged)
- Events (today: Monitoring→Events — the raw stream)
- Network Health (today: Link Quality + the FrontPage health panels;
  Findings/"Anomalies" fold in here as the deviation feed)
- Service Health (today: Service View / AppObservability, promoted from a
  leaf; its 7 internal tabs stay internal)

**INVESTIGATE** — "why is it happening?" (the RCA heart, visually primary)
- Correlations (today's page, renamed consistently: nav label =
  page H1 = "Correlations"; verdict/confidence/evidence-count columns
  already exist)
- RCA Reports (unchanged — the promoted-outage library)
- Topology (today: Infrastructure→Topology Canvas; its Investigate/Path
  Trace modes are the point — Capacity/Change-Review/Executive modes move
  out, below)
- Path Trace (today: Flow Trace/NetworkPath + the topology Path Trace mode,
  unified entry)
- Evidence Explorer (NEW composite shell over the four EXISTING explorers:
  Metrics Explorer, Flows, Log Search + Cloud Logs + Saved Searches,
  Events — one section with the four planes as tabs, matching the RCA
  evidence-plane vocabulary Device health / Routing & link events / Traffic
  flow / Active checks. The top-level Metrics/Flows/Logs sections dissolve
  into this; their hashes alias here.)
- Inspector stays a DOCKED PANE (shell v2 already has it) — not a page;
  it follows the operator across Monitor/Investigate. ⌘K + omni-search
  unchanged.

**INFRASTRUCTURE** — "what do I own / what is observed?"
- Inventory (Devices page; H1 already says "Inventory & Devices")
- Sites (NEW page — today "Sites" exists only as columns, a geomap manager
  and a broken dashboard tile; promote SitesManager + site-health panels)
- Interfaces & Links (Ports Workbench + Tunnels + WAN Interface Metrics)
- Wireless (unchanged)
- Performance (Device Monitoring, Interface Performance, Protocol
  Monitoring, Troubleshooting — today's "Dashboards" group, one grouped
  page entry)
- Geomap (unchanged)
- Discovery & Collectors (MERGE of the three split surfaces: Admin→
  Collectors (PO), Admin→Data Sources "Collection coverage", SNMP Profile
  Manager; tenant-visible coverage view + PO collector controls, gates
  unchanged)
- Source of Truth (PO, from the one-leaf Automation section, which
  dissolves)

**ACTIONS** — "what happens next?"
- Action Queue (today: a panel inside Command Center with NO route —
  becomes a first-class page; Command Center keeps a summary card linking
  to it)
- Tickets (NEW thin page: the ticketing-gap panel + RcaTicketCard state
  across correlations; policy admin stays in Administration)
- Automations (placeholder honesty: only guarded wireless actions exist
  today — section ships when a real executor does; NOT faked)
- Runbooks (DEBT: only fragments exist — per-service runbook_url + the RCA
  verdict banner steps. Propose a v1 page listing service runbook links;
  flag as new build)

**ANALYTICS** — "trends over time"
- Reports (unchanged)
- Capacity (PROMOTED from topology workflow mode + FrontPage capacity
  outlook + the Capacity Trends report template — one entry that opens the
  topology capacity workspace)
- Change Review (PROMOTED from topology mode + Service View→Investigations→
  Changes)
- Executive View (PROMOTED from topology Executive/Geo mode + Executive RCA
  summary; Recovery Scorecard moves here — it is a management trend view)

**SECURITY** (kept as its own section — it's tenant-facing product
functionality, not admin)
- Vulnerability Management / Threat Detection / Compliance Monitoring
  (unchanged)

**ADMINISTRATION** (footer, visually separated — structure mostly kept)
- Settings; Integrations + Notifications + RCA Auto-Ticketing (moved here
  from the dissolved "Incident Response" section — they are configuration,
  not operations); Identity & Access (+ Authentication, Access Explorer,
  Sessions PO, Audit Log); Data Collection group shrinks (Processors,
  Sensitive Data Access; collectors moved to Infrastructure); Transport
  Security; Data & Retention (Data Protection card promoted from inside
  Settings); Regions (PO); Stack group (PO: Stack Health, Self-Monitoring,
  OpenSearch, GraphQL, API Access).

Iris AI stays a rail action (drawer), not a section.

## 2. Complete Before → After map

Every current leaf; gates unchanged unless noted. (aliases = old hash keeps
resolving)

| Today | Target |
|---|---|
| dashboards/home + incident/overview (duplicate Command Center) | Overview (single route; both hashes alias) |
| dashboards/operations (Operations Overview) | merged into Overview |
| dashboards/board, dashboards/list (+SavedDashboards), dashboards/demo | Overview → My Dashboard / Saved (demo behind a flag) |
| dashboards/reports | Analytics → Reports |
| monitoring/monitors, /new, /maintenance | Monitor → Alerts (rules/create/maintenance as page tabs) |
| monitoring/triggered (Active Alerts) | Monitor → Alerts |
| monitoring/events | Monitor → Events (also surfaced in Evidence Explorer) |
| monitoring/incidents | Monitor → Incidents |
| monitoring/anomalies (Findings.tsx!) | Monitor → Network Health (feed); label unified "Findings" |
| monitoring/quality (Link Quality) | Monitor → Network Health |
| monitoring/correlations | Investigate → Correlations |
| monitoring/rca-reports | Investigate → RCA Reports |
| monitoring/appobs (Service View) | Monitor → Service Health |
| monitoring/reliability (Recovery Scorecard) | Analytics → Executive View |
| incident/notifications, /integrations, /rca-ticketing | Administration (section "Incident Response" dissolves) |
| automation/sot (PO) | Infrastructure → Source of Truth (PO) |
| infrastructure/devices | Infrastructure → Inventory |
| infrastructure/ports | Infrastructure → Interfaces & Links |
| infrastructure/nms | Infrastructure → Discovery & Collectors (flag-gated as today) |
| infrastructure/wireless | Infrastructure → Wireless |
| infrastructure/{monitoring,ifperf,bgpospf,troubleshooting} | Infrastructure → Performance (grouped) |
| infrastructure/topology-canvas | Investigate → Topology (Capacity/Change/Exec modes promoted to Analytics entries that deep-link the same canvas workflows) |
| infrastructure/geomap | Infrastructure → Geomap |
| infrastructure/flowtrace | Investigate → Path Trace |
| infrastructure/wan-circuits | Infrastructure → Interfaces & Links |
| infrastructure/tunnels | Infrastructure → Interfaces & Links |
| security/{vuln,threat,compliance} | Security (unchanged) |
| metrics (section) | Investigate → Evidence Explorer › Metrics |
| flows (section) | Investigate → Evidence Explorer › Flows |
| logs/{logs,cloud,saved} | Investigate → Evidence Explorer › Logs |
| admin/settings | Administration → Settings |
| admin/datasources | Infrastructure → Discovery & Collectors |
| admin/collectors (PO) | Infrastructure → Discovery & Collectors (PO parts keep gate) |
| admin/snmp | Infrastructure → Discovery & Collectors |
| admin/processors, admin/sensitive-data-access | Administration → Data Collection |
| admin/regions (PO), identity, auth, access, sessions (PO), audit | Administration (unchanged) |
| admin/transport | Administration → Security → Transport Security |
| admin/{health,grafana,opensearch,graphql} (PO) | Administration → Stack (unchanged) |
| admin/api (+3 sub-items) | Administration → API Access |
| #/resource/{kind}/{id} | unchanged (first-class route) |
| Command Center "Action Queue" panel | Actions → Action Queue (new route) |
| DataProtection card (inside Settings) | Administration → Data & Retention |
| Sites (no page today) | Infrastructure → Sites (NEW) |

## 3. Shell changes (proposal)

- Keep shell-v2 rail; ADD collapse-to-icons state (tooltips) — rail today
  never collapses.
- UNHIDE breadcrumbs + the SubNav tab bar in v2 (`.main-head` is
  display:none today — in-page tabs are currently invisible to the nav and
  ⌘K; the Service View's Security/Settings tabs are undiscoverable).
- Add a notifications bell (none exists) fed by the episode/incident feed.
- Keep omni-search + ⌘K (already strong); extend ⌘K to in-page tabs once
  SubNav is visible; register the promoted pages.
- ScopeSelector, time-range, health chip, account menu unchanged (theme
  stays login + account menu per the standing rule).
- Kill the dead `?focus=` param (wire it or remove the emitter) and the 7
  stale drill routes in panels.tsx that silently land on Home.
- URL-serialize topology canvas state (mode/overlay/selection…) — the known
  tracker-#133 gap; required for investigation-context preservation.

## 4. Declarative config & compatibility

nav.tsx is already a single declarative table with gating metadata — the
refactor is a re-mapping of that table plus an ALIAS table (old hash → new
route) so every saved deep link and the panel-registry drills keep working.
No backend/API changes; RBAC/tenant gates carried verbatim (platformOnly,
server-side module gates, TenantGate default-closed for new sections).

## 5. New builds required (honest list)

1. Sites page (SitesManager promotion + site health) — M
2. Action Queue as a routed page (extract from Command Center) — S
3. Evidence Explorer shell (tabs over 4 existing explorers) — M
4. Tickets thin page — S
5. Overview merge (Command Center + FrontPage strip) — M
6. Runbooks v1 (links registry) — S, or defer with an honest empty state
7. Rail collapse + SubNav/breadcrumb unhide + notifications bell — M
8. Alias table + panels.tsx drill-route repair — S

## 6. Phasing

P1 nav table re-map + aliases + shell unhide (no page rewrites) ·
P2 promotions (Action Queue, Sites, Evidence Explorer, Analytics entries) ·
P3 Overview merge + vocabulary unification + notifications ·
P4 topology URL state + ⌘K depth.
