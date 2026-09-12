# Frontend Redesign — FAANG-grade Network Observability Cockpit (#24)

> Status: **DESIGN SPEC v2 — for review/lock. Nothing built yet** (we are
> finalizing the design, not coding). Reviewer: Rao.
>
> This document delivers all **20 requested deliverables** (mapped in §0.1).
> Grounded in: the authoritative #24 requirements brief; the **current**
> navigation of a leading observability platform (2024 redesign, verified live
> 2026-06-05 via the vendor's own design blogs — icon-rail + two-column hover
> flyout + ⌘K quick-nav); that vendor's Network Monitoring / SD-WAN / Network
> Path / NDM Topology product references; the
> design-research verdicts on premium "non-AI-looking" UI (Linear/Stripe/Vercel);
> and the existing app (`src/frontend/src/{pages,tabs,components}`).
>
> **Persona / philosophy:** a mission-critical operational cockpit for
> NOC/SRE/NetOps/SecOps/Platform/IR — *not* a marketing site. Feel = reference-grade
> operational density · Linear nav · Raycast speed · VSCode ergonomics · Bloomberg
> efficiency · Apple typographic restraint. North-star metric: **+30–40% more
> operational data per viewport** with sub-100ms interactions and keyboard-first
> flow.

---

## 0.1 Deliverable map

| # | Deliverable | Section |
|---|---|---|
| 1 | Reference-platform UX audit | §1 |
| 2 | Enterprise UI anti-pattern analysis | §2 |
| 3 | New Information Architecture | §3 |
| 4 | Navigation redesign strategy | §4 |
| 5 | Hover sidebar interaction model | §5 |
| 6 | Compact layout strategy | §6 |
| 7 | Typography system | §7 |
| 8 | Design-token architecture | §8 |
| 9 | Dark-mode palette | §9 |
| 10 | Dashboard wireframes | §10 |
| 11 | Split-pane workspace wireframes | §11 |
| 12 | Sidebar flyout diagrams | §12 |
| 13 | React component hierarchy | §13 |
| 14 | Tailwind token configuration | §14 |
| 15 | Accessibility strategy | §15 |
| 16 | Keyboard-navigation strategy | §16 |
| 17 | Performance optimization plan | §17 |
| 18 | Production React architecture | §18 |
| 19 | shadcn/ui component mapping | §19 |
| 20 | Example implementations (sidebar / table / dashboard shell / inspector / palette) | §20 |
| — | Tech-stack decision & phased rollout | §21 |
| — | Open decisions to lock | §22 |

---

## 1. Reference-platform UX audit

> "Reference platform" below = the leading observability vendor whose UI we
> benchmark against; named indirectly on purpose (no vendor names in-repo).

### 1.1 What the reference platform does exceptionally well
1. **Signal density without clutter** — the System-Networking board fits ~9 live
   panels above the fold; compact legends, minimal axes, tabular figures.
2. **Icon rail + two-column hover flyout** (current 2024 nav) — slim rail with an
   icon-only state and an expanded state; hovering a module opens a flyout whose
   **left column = key feature highlights, right column = detailed config/setup**,
   grouped by product area, ordered by usage. No accordion reflow.
3. **Top-of-rail search + recents + pinned** — search bar plus recently visited
   dashboards/monitors/notebooks and direct links (Watchdog, Service Mgmt).
4. **⌘K / Ctrl+K quick-nav** — command palette over recents, pages, products,
   widget-clipboard, "create" actions; real-time filtering.
5. **Sticky, consistent view toolbar** — every telemetry view shares the same top
   strip: scope filter · query bar · **global time-range** · share/configure.
   Muscle memory transfers across modules.
6. **Faceted left filter rail inside views** (Event Mgmt, NetFlow) — checkable
   facets that narrow results live.
7. **NetFlow as a workbench** — a left sub-rail of analyses (Traffic Volume,
   Conversations, Top Talkers, Ports, Protocols, ASN, Geo IP, Flags) over a
   shared filter/time context.
8. **SD-WAN / Tunnels density** (product ref) — single-value KPI tiles (Tunnels
   up `9` / down `2`), top-latency & top-traffic sparkline panels, then a dense
   table with **conditional cell tinting** (amber jitter outliers, green status).
9. **Network Path** — hop-by-hop graph with latency-colored edges, node hover-card
   (IP, hostname, hop TTL, RTT, traversed count), a latency/reachability heatmap
   timeline strip, and correlated per-device metric panels.

### 1.2 What causes unnecessary scrolling
- Oversized global header ("Welcome, Rao!" + trial banner) eats ~90px before any
  content.
- Marketing-style empty-states (full-viewport "No Reports", "Start your first
  notebook with Bits AI").
- Inconsistent sub-nav (flyout vs top tabs vs left sub-rail for similar things).
- Big white cards with thick borders and generous padding on dashboards.

### 1.3 Areas that feel outdated
- Light-mode-default marketing chrome bleeding into operational pages.
- Some legacy config screens are modal-heavy and low-density.
- Mixed iconography weight and spacing between older and newer modules.

### 1.4 What we modernize
- Compress global header to a single **44px** bar.
- Replace empty-state heroes with **dense empty-states** (inline CTA + recents).
- Standardize sub-nav: **flyout for module nav · left sub-rail for in-module
  workbench · top tabs only for ≤4 sibling views**.
- Hairline 1px dividers; card chrome ≤8px; borders instead of shadows for
  elevation (shadows reserved for true overlays).
- Dark-first tokens, single restrained non-indigo accent, severity color sacred.

### 1.6 Current-UI screenshot findings (verified live 2026-06-05, 22 captures)

Reviewing the current product directly confirmed and sharpened the design:
- **Rail** = icon + text label, grouped into zones; bottom = Integrations + account.
  Hovering a module opens its flyout (Monitors → Manage/New/Triggered/Quality/SLOs/
  Check Summary/Event Mgmt/Watchdog/External Provider Status; Security → Cloud SIEM/
  Code Security/Cloud Security/App&API/Workload/Sensitive Data Scanner/AI Guard).
- **Network IA (NDM):** top tabs **Cloud Network · Network Devices · Network Path**;
  within Network Devices: **Devices · Maps · NetFlow · Integrations · Dashboards**.
  **Maps = Device Geomap + Device Topology Map.** → maps directly onto our Network
  module (Flows/Tunnels/Topology) + Fleet.
- **NetFlow = a left workbench sub-rail** (confirmed items): Traffic Volume ·
  Device Health · Flows · Conversations · Autonomous Systems · Geo IP · Source
  Ports · Destination Ports · Protocols · Flags · Configuration. Center panels:
  Top Devices / Top Ingress Interfaces / Top Egress Interfaces.
- **View toolbar (NetFlow):** Views/My View · global time-range · **stream controls
  (play/pause/step)** · query bar with **per-dimension dropdowns** (source.ip,
  ingress.interface.name, device.name, device.ip, egress.interface.name,
  destination.ip) + **Filter** + **Unidirectional/Bidirectional toggle**.
- **Faceted filter rail** (Monitors, Event Mgmt): checkbox facets, "Showing N of M
  + Add", collapsible groups (CORE → Source/Host/Service). → reusable `FacetRail`.
- **Per-vendor Integration dashboards** (e.g. HPE Aruba): left vendor list, a
  **Dashboards** dropdown (NDM · BGP/OSPF Overview · NetFlow Monitoring · NDM
  Troubleshooting), right **Overview** KPI panel (Devices · APIs Offline · Switches
  · Gateways) + Top Devices – Resource Utilization.
- **Severity badge pills** (P1–P5) in monitor lists; **Incidents** detail =
  Properties/Impact with SEV badges + status.
- **Anti-pattern to beat:** their empty-states are still marketing-scale (full-pane
  "No events yet", dashed-border hero) — we replace with dense empty-states.

Design refinements adopted from these: add a reusable **`FacetRail`** primitive;
the **Network** module's NetFlow view uses the confirmed workbench sub-rail + the
multi-dropdown query bar + Bi/Uni toggle; **Maps** offers Geomap + Topology;
**Integrations** gets a per-vendor dashboard pattern with a Dashboards dropdown.

### 1.5 Patterns to retain (renamed)
Icon rail + two-column hover flyout · top-of-rail search/recents/pinned · sticky
view toolbar with global time-range · faceted filter rail · NetFlow-style
workbench sub-rail · tabular numerics · ⌘K palette (we already have
`CommandPalette.tsx`).

---

## 2. Enterprise UI anti-pattern analysis (what we remove)

| Anti-pattern | Why it hurts operators | Our replacement |
|---|---|---|
| Accordion trees / collapsible sidebars | Reflow shifts targets; multi-click depth; state to manage | Persistent **56–64px icon rail + hover flyout** (no collapse btn) |
| Full-viewport hero empty-states | One wasted screen per empty module | Dense empty-state: 1-line message + inline CTA + recent items |
| Giant cards, thick borders, fat padding | ~40% of pixels are chrome | Hairline dividers, ≤8px card chrome, border-not-shadow elevation |
| Oversized headers / breadcrumb bloat | Pushes telemetry below the fold | 44px top bar, 28–36px view toolbar, inline breadcrumbs |
| Modal-heavy configuration | Loses context, blocks the board | Guided **Wizards** (already shipped) + right-dock **Inspector** |
| Duplicate nav (top tabs *and* flyout) | Cognitive ambiguity | One nav source per level (see §1.4 standardization) |
| Playful/animated transitions | Distraction + latency under fatigue | Framer Motion only for ≤120ms functional motion; honor reduced-motion |
| Thin 100/200 type, marketing whitespace | Fails WCAG, fatigues NOC eyes | 12–13px body, 400/500/600 weights, 4px grid |
| Per-page bespoke layouts | No muscle memory | One shell: rail · sub-rail · workspace · inspector · drawer |

---

## 3. Information Architecture

**Existing-app inventory the IA maps onto (no greenfield invention):**
`pages/`: Dashboard(Overview), Devices, DeviceDetail, DeviceTerminal, Reports,
SavedDashboards, Login. `tabs/`: Alerts, Rules, Findings, Incidents, Logs,
MetricsExplorer, Flows, Tunnels, Topology, Collectors, SnmpProfileManager,
Copilot, SavedSearches, SearchDashboards, StackHealth, Grafana, Prometheus,
admin (Tenants/Users/Auth/API), AuditLog, Settings. `components/`: Sidebar,
SubNav, TopBar, CommandPalette, CopilotDrawer, NotificationCenter, Wizard, Icon.

Every IA node is backed by one of these (✅ exists) or marked 🆕 new / 🔭 future.

**Rail = 12 modules in 4 zones.** The brief's example module list
(Infrastructure, Logs, Traces, Security, Incidents, Dashboards, Networking,
Cloud, Devices, APIs) is *inspiration*; we map to what the platform actually has
and rename network-first for uniqueness. Reconciliation:

| Brief example | Our module | Note |
|---|---|---|
| Dashboards | **Pulse** | home board + saved/shared boards |
| Infrastructure + Devices | **Fleet** | inventory + health + discovery + maps (unified) |
| Networking | **Network** | NetFlow/sFlow/IPFIX workbench + Tunnels + Path (marquee) |
| — | **Metrics** | explorer + catalog |
| Logs | **Logs** | live tail + search + pipelines |
| (Monitors/Alerting) | **Monitors** | alerts + rules + findings/anomalies |
| Incidents | **Incidents** | active + ITSM + postmortems |
| — | **Reports** | scheduled + execution history (our differentiator) |
| (Integrations) | **Integrations** | ITSM + notifications + data sources |
| — | **Stack** | platform self-observability (owner-only, strict tenancy) |
| — | **Admin** | tenants/users/auth/API/audit/settings |
| Traces / Cloud / Security / APIs | 🔭 future | not real features yet — omitted to avoid dead nav |

```
ZONE 1 · COMMAND     ◎ Pulse        ✦ Copilot
ZONE 2 · OBSERVE     ▤ Fleet   ◭ Network   ∿ Metrics   ≣ Logs
ZONE 3 · RESPOND     ◔ Monitors   ◇ Incidents   ▦ Reports
ZONE 4 · PLATFORM    ⧉ Integrations   ▥ Stack(owner)   ⚙ Admin   ◯ Account
```

**Uniqueness moves (not a clone):** Network-first ordering with **Network** as
a first-class marquee (the reference platform buries NDM under Infrastructure); **Fleet** unifies the
"boxes" mental model; **Tunnels** (IPsec/SD-WAN) elevated; **Stack**
self-observability gated to the parent-tenant owner (our strict-tenancy model);
tiny rail labels under icons for lower-cognitive-load scanning.

---

## 4. Navigation redesign strategy

- **One nav source per level.** Rail = modules. Flyout = sub-items within a
  module. In-module **sub-rail** = workbench analyses (NetFlow-style). Top tabs
  only when ≤4 sibling views. Never two sources for the same thing.
- **No reflow.** The rail never collapses/expands the document; flyout overlays.
- **Persistent context.** Global `timeRange`, `tenant/env scope`, and `selection`
  live in stores and survive module switches (deep-linkable in the URL).
- **Keyboard-first.** `g` + module key jumps modules; `⌘K` is the universal
  entity jump; arrows + `Enter` drive the flyout (see §16).
- **Pinned / favorites / recents** surface at the top of each flyout and in ⌘K.
- **Owner-gated module** (Stack) is hidden, not disabled, for non-owner tenants.

---

## 5. Hover sidebar interaction model

**Rail:** 56–64px, always visible, icon + 10px label per item, 4 zones split by a
hairline. Active item = accent left-border (3px) + filled icon + raised contrast.

**Flyout (matches the reference platform's current nav) — opens right on hover OR focus:**
- **Two-column layout:** left column = primary destinations + key highlights;
  right column = detailed config/setup + secondary actions.
- **Header:** module name + inline search field (filters items live).
- **Sections:** labeled groups (e.g. Network → TRAFFIC / TUNNELS / PATH / ROUTING).
- **Pinned · Favorites · Recents** row at top; **Quick actions** (e.g. "New saved
  view", "Add device") at bottom.
- **Open/close timing:** 80ms open delay, 200ms close grace (so diagonal mouse
  travel to the flyout doesn't dismiss it — "safe triangle"/intent buffer).
- **Pointer + keyboard parity:** hover opens; focus (Tab/`g`) opens the same
  flyout; `Esc` closes and returns focus to the rail icon.
- **No nested accordions** inside the flyout — groups are flat labeled lists.

State machine: `idle → hovering(open delay) → open → (pointer leaves both rail
item & flyout)(close grace) → idle`. Focus-open bypasses the open delay.

---

## 5.1 Hover-flyout nav — implementation plan against the CURRENT code

**Problem (today):** `components/Sidebar.tsx` uses an **inline accordion** (a caret
expands each section's children *in place*, reflowing the rail — `.nav-children`)
plus a **Collapse toggle** that shrinks the rail to 56px icons and pushes leaf
switching into an in-content `SubNav`. The user wants **neither collapse nor
accordion**: a persistent rail where **hovering a section reveals its children in
a flyout** (hover *Monitors* → all Monitor leaves appear), click navigates.

**Target interaction (no reflow, ever):**
- Rail is **always visible at a fixed 60px** (no collapse button, no 208/56
  toggle). Each item = icon (20px) + a tiny label under it.
- **Hover or keyboard-focus** a rail item → a **flyout panel overlays to the
  right** (CSS `position: fixed`, so the page never reflows) listing that
  section's `children` (grouped + the section title header). Leafless sections
  (Reports) show a one-line flyout / navigate directly.
- **Timing:** open after **80ms** hover-intent; close after **200ms** grace so a
  diagonal cursor path into the flyout doesn't dismiss it ("safe triangle").
  Focus-open is immediate. `Esc` closes and returns focus to the rail icon.
- **Click** a rail item → navigate to its active/first leaf *and* keep the flyout
  open for quick leaf switching. Arrow keys + `Enter` traverse the flyout.
- Active section = **module-hued left bar (3px) + filled icon**; active leaf in
  the flyout = module-hued row.

**Code changes (incremental, behind the `?shell=v2` flag):**
| File | Change |
|---|---|
| `components/Sidebar.tsx` → `shell/IconRail.tsx` | Drop `collapsed`/`onToggle`, the caret/accordion (`nav-children`), and the Collapse button. Render icon+label items; on hover/focus mount `<NavFlyout section=…>`. |
| `shell/NavFlyout.tsx` (new) | Fixed-position panel; header = section label (module-hue underline); body = `section.children` rows (+ optional right "config" column per §5/§12). Hover-intent timers live here + on the rail item. |
| `context/shell` | Remove `collapsed` + `setCollapsed`; nav data (`nav.tsx NAV`) is unchanged — the flyout reads `section.children`. |
| `styles.css` | New `.rail`/`.rail-item`/`.rail-label` + `.nav-flyout`; **remove** `.nav-children`, `.nav-caret`, `.nav-collapse`, `.shell.collapsed`. `.shell` grid column becomes a fixed `var(--rail-w)`. |
| `components/SubNav.tsx` | Kept for in-content leaf tabs (≤4 siblings) but no longer the collapsed-mode fallback. |

**Spacing (exact, 4px grid):**
- Rail: width **60px**; item **48px** tall (icon 20 + label 11 + 6/6 padding),
  **2px** gap; zone separators = **1px** hairline with **8px** margin; brand mark
  48px. Active left-bar 3px inset.
- Flyout: offset **4px** right of the rail, top-aligned to the hovered item;
  **min-width 240px** (two-column 360px); padding **8px**; rows **30px** with
  **8px/10px** padding and **6px** radius; group header **8px** top margin.
  Elevation = `--shadow-pop` (overlay is the one place shadow is allowed).

**Typography & elegance (deltas from current):**
- Rail label: **10.5px / weight 500 / letter-spacing 0.01em**, centered, color
  `--rail-fg-muted`; active → `--rail-fg`. (Replaces the 14px inline label.)
- Flyout section header: **11px / 600 / 0.04em / uppercase**, `--rail-fg-muted`,
  with a 2px module-hue underline.
- Flyout leaf row: **13px / 500**, `--fg`; hover bg `--rail-hover`; active row
  tinted with the module hue. Truncate with ellipsis + native title tooltip.
- Keep Inter `cv11`/`ss01`; **tabular-nums** on any flyout counts/badges; mono
  (JetBrains) only for IDs. Honor `prefers-reduced-motion` (flyout fade ≤120ms,
  no slide). All hues paired with text/icon — never color-only.
- Elegance: hairline 1px dividers (no heavy borders), border-not-shadow on the
  rail, one consistent 18–20px icon size + stroke weight, calm muted idle state
  that lifts to full-contrast on hover — the Linear/Raycast "quiet until you
  reach for it" feel.

**Verification:** `npm run build` green; visual check via the run skill that
(a) nothing reflows on hover, (b) flyout opens/closes with correct intent timing,
(c) keyboard parity works, (d) no horizontal scroll, (e) AA contrast in dark.

## 6. Compact layout strategy (zero-waste)

- **Vertical budget (1080p):** TopBar 44px + ViewToolbar 32px = 76px chrome;
  remainder is workspace. (The reference platform spends ~150–180px before content.)
- **4px base grid**; section padding 12–16px; card chrome ≤8px; table rows
  28px default / 24px ultra-dense toggle.
- **Sticky** view toolbar + table headers + time control; body scrolls under them.
- **Inline everything:** filters, thresholds, legends, row actions — no separate
  filter panels stealing a column unless faceting (then a 220px collapsible facet
  rail inside the view).
- **Split-pane** workspace (resizable) + **dockable right inspector** + collapsible
  **bottom drawer** for correlated logs/events/timeline.
- **Density toggle** is a token-level switch (`--row-h`, `--space-unit`), not
  per-component overrides.

---

## 7. Typography system

- **Families:** `Inter` (UI) — fallback `Geist`, then `-apple-system/SF Pro`;
  **`JetBrains Mono`** for telemetry/IDs/logs/IPs.
- **Sizes:** 11 (dense table/caption) · 12–13 (operational body) · 14 (controls) ·
  16 (section head) · 20 (page title). No marketing-scale type.
- **Weights:** 400 body · 500 labels · 600 emphasis. **No 100/200/300.**
- **Numerics:** `font-variant-numeric: tabular-nums` on all metrics/tables so
  columns align and diffs are scannable.
- **Line-height:** 1.35 body, 1.2 dense tables.

**Rationale (brief asks to explain):**
- *Why Inter for observability:* designed for UI at small sizes; large x-height,
  open apertures, true tabular figures, broad weight range, excellent hinting →
  legible at 12–13px in dark mode.
- *Why thin type harms dense tooling:* 100/200 weights have insufficient stroke
  contrast on dark backgrounds; they shimmer/disappear at 11–12px, fail WCAG
  contrast against `--surface`, and fatigue operators over long shifts.
- *WCAG:* body text targets contrast ≥ 4.5:1 (AA), large/heads ≥ 3:1; we tune the
  neutral text ramp against each surface to clear AA in dark, light, and OLED.
- *Long-session optimization:* restrained weight set (3), generous tabular
  spacing, and calm neutral foreground reduce flicker/strain; severity color is
  reserved so the eye isn't trained to ignore it.

---

## 8. Design-token architecture

Single source of truth = CSS custom properties on `:root` + `[data-theme]`,
consumed by Tailwind (§14). Semantic, not raw — components reference roles, never
hex. Three themes: `dark` (default), `light`, `oled`.

```css
:root, [data-theme="dark"] {
  /* surfaces (elevation by lightness, not shadow) */
  --bg:        #0B0E14;   --surface:   #12161F;   --surface-2: #181D28;
  --overlay:   #1E2430;   --border:    #232A38;   --border-strong:#2E3850;
  /* neutral text ramp */
  --fg:        #E6EAF2;   --fg-muted:  #9AA4B8;   --fg-subtle: #6B7488;
  /* single restrained accent (NOT indigo-500) — proposal: cobalt */
  --accent:    #2D6BE0;   --accent-fg: #FFFFFF;   --accent-soft:#16243F;
  /* severity (sacred — only health states) */
  --ok:   #2EA043;  --warn: #D29922;  --crit: #F85149;
  --info: #3B82F6;  --muted:#6B7488;  --ack:  #8957E5;
  /* viz ramp (color-blind-aware, dark-tuned) */
  --viz-1:#4C8DFF; --viz-2:#3FB6B2; --viz-3:#E2A03F;
  --viz-4:#C76FE0; --viz-5:#6FCF97; --viz-6:#F2785C;
  /* geometry */
  --radius-sm:4px; --radius-md:6px; --space-unit:4px;
  --row-h:28px; --topbar-h:44px; --toolbar-h:32px; --rail-w:60px;
  --font-ui:'Inter','Geist',-apple-system,system-ui,sans-serif;
  --font-mono:'JetBrains Mono',ui-monospace,monospace;
}
[data-theme="light"] {
  --bg:#F7F8FA; --surface:#FFFFFF; --surface-2:#F1F3F7; --overlay:#FFFFFF;
  --border:#E3E7EF; --border-strong:#CdD4E0;
  --fg:#1A1F2B; --fg-muted:#5A6478; --fg-subtle:#8A93A6;
  --accent:#2155C7; --accent-soft:#E7EEFB;
  --ok:#1A7F37; --warn:#9A6700; --crit:#CF222E; --info:#0969DA; --ack:#6639BA;
}
[data-theme="oled"] { /* true-black for OLED NOC walls */
  --bg:#000000; --surface:#0A0D12; --surface-2:#10141C; --border:#1B2230;
}
[data-density="compact"] { --row-h:24px; --space-unit:3px; }
```

States map to severity tokens: `healthy→--ok`, `degraded→--warn`,
`warning→--warn` (with pattern), `critical→--crit`, `muted→--muted`,
`acknowledged→--ack`.

---

## 9. Dark-mode palette (primary)

Elevation is expressed by **lightness steps**, not drop shadows:
`--bg #0B0E14` → `--surface #12161F` → `--surface-2 #181D28` → `--overlay
#1E2430`. Hairline `--border #232A38`. Foreground ramp `--fg #E6EAF2` /
`--fg-muted #9AA4B8` / `--fg-subtle #6B7488`. Severity tuned for dark contrast
(`--ok #2EA043`, `--warn #D29922`, `--crit #F85149`). Shadows reserved for
overlays/menus only. OLED variant swaps `--bg`→`#000`.

### 9.1 Per-module / per-category color taxonomy (unique identity)

Instead of one global accent, **each module carries its own accent hue**, and the
hue is chosen from its **zone family** so the rail also reads as 4 categories at a
glance. The module hue tints: the active rail indicator, the flyout header
underline, module-scoped chips/links, and the *default* first chart series within
that module. **Severity (`--ok/--warn/--crit`) is sacred and always overrides**
the module hue for health states — so module hues deliberately avoid the
red/amber/green severity bands.

| Zone (category) | Family | Module | Token | Hex (dark) |
|---|---|---|---|---|
| 1 · Command | Blue–Violet | Pulse | `--mod-pulse` | `#2D6BE0` (cobalt) |
| | | Copilot | `--mod-copilot` | `#8B5CF6` (violet) |
| 2 · Observe | Teal–Cyan–Azure | Fleet | `--mod-fleet` | `#14B8A6` (teal) |
| | | Network | `--mod-network` | `#3B9EFF` (azure — marquee) |
| | | Metrics | `--mod-metrics` | `#22B8CF` (cyan) |
| | | Logs | `--mod-logs` | `#6366F1` (indigo) |
| 3 · Respond | Magenta–Plum | Monitors | `--mod-monitors` | `#EC4899` (pink) |
| | | Incidents | `--mod-incidents` | `#A855F7` (plum) |
| | | Reports | `--mod-reports` | `#818CF8` (periwinkle) |
| 4 · Platform | Neutral steel | Integrations | `--mod-integrations` | `#5B8DB8` (steel-blue) |
| | | Stack | `--mod-stack` | `#06B6D4` (bright cyan, owner) |
| | | Admin | `--mod-admin` | `#64748B` (slate) |

Each view sets `--accent: var(--mod-<name>)` on its module root, so generic
components (`Badge`, focus ring, links, primary series) automatically inherit the
module's identity without per-component hardcoding. A light/oled variant of each
`--mod-*` is defined (≈+8% lightness for light, same hue for oled). All module
hues are verified ≥ 3:1 against `--surface` for non-text UI and paired with a
label/icon so they never carry meaning by color alone.

**Component-family viz mapping:** within a module the chart series ramp starts at
the module hue then walks the shared `--viz-*` ramp, so a Network panel and a
Fleet panel are visually distinguishable at a glance while staying
color-blind-aware.

---

## 10. Dashboard wireframes

```
Pulse (home board) — modular add/remove/resize panels (localStorage today → store)
┌ KPI strip: Devices ↑/↓ · Total bps · Active alerts · Open incidents · Tunnels ↑/↓ ┐
├ throughput (stacked area) │ top talkers (Top-N bars) │ alert volume (by sev) ──────┤
├ topology mini-map         │ findings feed           │ flow protocol distribution ──┤
└ severity-tinted single-value tiles + sparklines, 28px legends ───────────────────┘

Fleet › Device Detail
KPI strip → interface throughput grid (in/out, stacked) → errors/discards heatmap
→ CPU/mem/temp timeseries → interface table (status, speed, util%, errors)
→ neighbors topology mini-map. Right inspector = selected interface.

Network › Traffic (NetFlow/sFlow/IPFIX workbench)
sub-rail: Traffic Volume · Conversations · Top Talkers · Ports · Protocols · ASN ·
Geo IP · Flags.  center: total-bps stacked-area → top talkers/listeners →
conversations Sankey → protocol/port distribution → ASN + Geo map → flow table.

Network › Tunnels  (SD-WAN ref)
tiles: Tunnels up 9 / down 2 → Top latencies + Top traffic sparklines →
dense tunnel table (SYSTEM_IP·HOSTNAME·SITE·LOCAL/REMOTE·LATENCY·JITTER·LOSS·QOE·
STATUS) with conditional cell tinting.

Network › Path  (Network Path ref)
hop-by-hop graph, latency-colored edges, node hover-card (IP/host/TTL/RTT/hops),
latency-reachability heatmap timeline strip, correlated latency/loss panels.

Monitors  alert volume timeseries · by-severity stacked · SLO burn · MTTR.
```

**Widget taxonomy (typed, themed, virtualization-aware):** Timeseries
(line/area/stacked/bar; min/avg/max bands, threshold lines, anomaly shading,
synchronized cursor) · Top-N list (inline bars) · Heatmap · Distribution/histogram
· **Sankey/chord** (conversations, AS-path) 🆕 · **Geomap** 🆕 · Topology graph
(LLDP/CDP edges, vendor icons, hover panel, color = Device/Ping state toggle) ·
Single-value/sparkline tile · Status grid / health matrix (3-state dots) · Data
table w/ inline bars (TanStack virtualized, frozen cols, 28px rows).

**Engine:** keep **ECharts** (vendored; canvas perf; native sankey/heatmap/geo/
graph) wrapped as a typed `<Chart kind=…>` bound to tokens; add **TanStack
Table + Virtual** for grids. No second chart lib.

---

## 11. Split-pane workspace wireframes

```
┌───────────────────────────────────────────────────────────────────────┐
│ TOP BAR  logo · ⌘K search · time-range · tenant/env · bell · account   │ 44px
├──┬───────────────────────────────┬────────────────────────────────────┤
│R │ [in-module SUB-RAIL]          │                                     │
│A │ workbench tabs (NetFlow-style)│      RIGHT INSPECTOR (dockable)      │
│I ├───────────────────────────────┤      entity details, pinned,        │
│L │   CENTER WORKSPACE             │      metrics, related, actions      │
│  │   sticky VIEW TOOLBAR (32px)  │                                     │
│  │   dense panels / table        │                                     │
│  ├───────────────────────────────┴────────────────────────────────────┤
│  │ BOTTOM DRAWER (collapsible): live logs / events / timeline          │
└──┴────────────────────────────────────────────────────────────────────┘
```
- Resizable panes (drag handles); **layout persisted per user per module**.
- Inspector opens on row/node click; **pin** keeps it across selections.
- Bottom drawer = correlated logs/events for whatever's selected (NOC pivot).
- **Multi-monitor:** every module deep-linkable to its own window (URL = state).

---

## 12. Sidebar flyout diagrams

```
RAIL            FLYOUT (two-column, opens right on hover/focus)
─────           ┌──────────────────────────────────────────────────────────┐
◭ Network  ───▶ │ Network                              [ search items… ]     │
                ├───────────────── left: destinations ─┬─ right: config ─────┤
                │ TRAFFIC                               │ Saved views          │
                │  • Traffic Volume                     │ Sampling / rollup    │
                │  • Conversations (Sankey)             │ Flow exporters       │
                │  • Top Talkers / Listeners            │ Retention            │
                │ TUNNELS                               │                      │
                │  • IPsec / SD-WAN circuits            │ Quick actions        │
                │ PATH                                  │  + New saved view    │
                │  • Hop-by-hop path analysis           │  + Add exporter      │
                │ ROUTING 🔭 BGP/OSPF                   │                      │
                ├───────────────────────────────────────┴──────────────────┤
                │ ★ Pinned: Core-fabric traffic   �ট Recent: leaf1 flows      │
                └────────────────────────────────────────────────────────────┘
```
Same skeleton for every module: header+search · left destinations (grouped) ·
right config/secondary · pinned/recents footer · quick actions. Active rail item
shows a 3px accent left-border.

---

## 13. React component hierarchy

```
<AppShell>                         workspace frame, layout persistence (Zustand)
 ├─ <TopBar>                       ⌘K search · time-range · tenant/env · bell · account
 ├─ <IconRail>                     12 modules, 4 zones, keyboard nav
 │   └─ <NavFlyout>                two-column · grouped · searchable · pinned/recents
 ├─ <WorkspaceRouter>
 │   └─ <ModuleView>               <NetworkWorkbench>, <FleetView>, …
 │       ├─ <SubRail?>             in-module workbench nav
 │       ├─ <ViewToolbar>          scope · query · time-range · actions (sticky)
 │       ├─ <PanelGrid>            drag-resize <Chart kind=…> widgets
 │       └─ <DataTable>            TanStack virtualized
 ├─ <Inspector>                    dockable right panel (entity context)
 ├─ <BottomDrawer>                 live logs/events/timeline
 ├─ <CommandPalette>               (exists — extend entity sources)
 └─ <CopilotDrawer>                (exists)
```
Global stores (Zustand): `timeRange · scope(tenant/env) · layout · theme/density ·
selection`. WebSocket-first live feed → panels/tables/inspector.

---

## 14. Tailwind token configuration

Tailwind consumes the CSS variables (§8) so themes switch with `data-theme`/`data-density` and no rebuild.

```ts
// tailwind.config.ts
import type { Config } from 'tailwindcss'
export default {
  darkMode: ['class', '[data-theme="dark"]'],
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        bg: 'var(--bg)', surface: 'var(--surface)', 'surface-2': 'var(--surface-2)',
        overlay: 'var(--overlay)', border: 'var(--border)',
        'border-strong': 'var(--border-strong)',
        fg: 'var(--fg)', 'fg-muted': 'var(--fg-muted)', 'fg-subtle': 'var(--fg-subtle)',
        accent: { DEFAULT: 'var(--accent)', fg: 'var(--accent-fg)', soft: 'var(--accent-soft)' },
        ok: 'var(--ok)', warn: 'var(--warn)', crit: 'var(--crit)',
        info: 'var(--info)', muted: 'var(--muted)', ack: 'var(--ack)',
        viz: { 1:'var(--viz-1)',2:'var(--viz-2)',3:'var(--viz-3)',
               4:'var(--viz-4)',5:'var(--viz-5)',6:'var(--viz-6)' },
      },
      fontFamily: { ui: 'var(--font-ui)', mono: 'var(--font-mono)' },
      fontSize: { '2xs':['11px',{lineHeight:'1.3'}], xs:['12px',{lineHeight:'1.35'}],
                  sm:['13px',{lineHeight:'1.35'}], base:['14px',{lineHeight:'1.4'}],
                  lg:['16px',{lineHeight:'1.3'}], xl:['20px',{lineHeight:'1.25'}] },
      fontWeight: { normal:'400', medium:'500', semibold:'600' },
      borderRadius: { sm:'var(--radius-sm)', md:'var(--radius-md)' },
      spacing: { rail:'var(--rail-w)', topbar:'var(--topbar-h)',
                 toolbar:'var(--toolbar-h)', row:'var(--row-h)' },
    },
  },
  plugins: [require('tailwindcss-animate')],
} satisfies Config
```
Utility helpers: `.tnum { font-variant-numeric: tabular-nums }`, severity chips
`.sev-ok/.sev-warn/.sev-crit` map to tokens.

---

## 15. Accessibility strategy (WCAG 2.2 AA)

- **Contrast:** text ≥ 4.5:1, large/heads & UI affordances ≥ 3:1, verified per
  theme (dark/light/oled) against each surface; severity colors paired with
  **shape/label** (dot + text), never color-only.
- **Keyboard:** every action reachable; visible focus ring (`--accent` 2px),
  logical tab order, focus trap in flyout/palette/dialogs, `Esc` to dismiss,
  focus return to invoker.
- **ARIA / semantics:** rail = `nav` with `aria-current`; flyout = `menu`/
  `menuitem` (Radix handles roles); tables use proper header scope + `aria-sort`;
  live regions (`aria-live="polite"`) for streaming alerts/log tails.
- **Reduced motion:** `prefers-reduced-motion` disables non-essential Framer
  transitions; functional motion capped ≤120ms.
- **Targets:** ≥ 24×24px hit area even at 24px rows (padding/hover zone).
- **Screen-reader labels** on icon-only controls; charts ship an accessible data
  table fallback (`role="img"` + summary + "view as table").

---

## 16. Keyboard-navigation strategy

| Keys | Action |
|---|---|
| `⌘K` / `Ctrl+K` | Command palette / entity jump (hosts, alerts, dashboards, incidents, APIs, configs, traces, devices, logs, users) |
| `g` then `i/n/m/l/o/r/p/…` | Go to module (Fleet/Network/Metrics/Logs/mOnitors/Reports/Pulse…) |
| `t` | Focus global time-range |
| `f` | Focus scope/filter in view toolbar |
| `[` / `]` | Toggle left sub-rail / right inspector |
| `\` | Toggle bottom drawer |
| `j` / `k` | Next / prev table row; `Enter` opens in inspector |
| `x` | Multi-select row; `a` select all in view |
| `p` | Pin inspector / pin current view |
| `?` | Keyboard cheatsheet overlay |
| `Esc` | Close flyout/palette/inspector; clear selection |

Arrow keys + `Enter` drive the flyout; type-ahead filters items. All shortcuts are
remappable and listed in the `?` overlay.

---

## 17. Performance optimization plan

- **Virtualization everywhere:** TanStack Virtual for tables (100K+ rows) and long
  lists; windowed log tail.
- **WebSocket-first:** single multiplexed WS hub (we already have one) → store
  patches; coalesce high-rate streams (e.g. 250ms animation frame batching).
- **Rendering:** memoized selectors (Zustand `useShallow`), `React.memo` on cells/
  panels, `startTransition` for filter/scope changes, `content-visibility:auto`
  on off-screen panels.
- **Charts:** ECharts canvas renderer, `appendData` for streaming, downsample
  (LTTB) to ~viewport-width points, shared time axis to sync cursors without
  re-layout.
- **Loading:** route-level code-split per module; skeletons (not spinners);
  prefetch on rail-hover (intent) so flyout target loads warm.
- **Budgets:** interaction < 100ms; first module paint < 1s warm; table scroll
  60fps. Track via web-vitals + a perf panel in Stack module.

---

## 18. Production React architecture

```
src/frontend/src/
  app/           AppShell, routing, providers, theme/density boot
  shell/         IconRail, NavFlyout, TopBar, Inspector, BottomDrawer, SubRail
  modules/       pulse/ fleet/ network/ metrics/ logs/ monitors/ incidents/
                 reports/ integrations/ stack/ admin/   (one folder per module)
  primitives/    Chart/ DataTable/ Panel/ Tile/ Wizard(exists)/ CommandPalette(exists)
  stores/        timeRange.ts scope.ts layout.ts theme.ts selection.ts (Zustand)
  api/           rest client, ws hub, graphql stub, typed schemas (zod)
  styles/        tokens.css (the §8 vars), tailwind entry
  lib/           keyboard, format(tnum/bytes/bps), a11y helpers
```
- **Boundary:** modules import primitives/shell/stores, **never each other**
  (mirrors the repo's zero-cross-domain rule). Shared state via stores only.
- **Data:** zod-validate all API/WS payloads at the boundary (zero-trust UI).
- **Incremental migration** behind existing routes (see §21).

---

## 19. shadcn/ui component mapping

| Need | shadcn/Radix primitive | Cockpit usage |
|---|---|---|
| Flyout menus | `NavigationMenu` / `HoverCard` + `Popover` | two-column nav flyout |
| Command palette | `Command` (cmdk) | ⌘K (replaces/extends current `CommandPalette`) |
| Right inspector / drawers | `Sheet` / `Resizable` | dockable inspector, bottom drawer |
| Dialogs / wizards | `Dialog` + existing `Wizard` | guided config |
| Tabs | `Tabs` | ≤4 sibling views |
| Tooltips | `Tooltip` | rail labels, truncated cells |
| Select / scope | `Select` / `Combobox` | tenant/env scope, facet pickers |
| Time-range | `Popover` + custom calendar | sticky global time control |
| Dropdown actions | `DropdownMenu` | row hover actions |
| Toggle/density | `Toggle` / `Switch` | density + theme |
| Toasts | `Sonner` | notifications |
| Tables | **TanStack Table + Virtual** (headless) + shadcn styling | telemetry grids |
| Severity chips/badges | `Badge` (tokenized) | health states |
| Accordion | **avoided** in nav; allowed only inside inspector detail sections |

Charts stay **ECharts** (not a shadcn concern), wrapped in `<Chart>`.

---

## 20. Example implementations (illustrative spec — not wired into the live app)

> These are reference snippets to lock the API/feel. They are **not** added to the
> running app until the stack decision (§22) is approved.

### 20.1 IconRail + two-column flyout
```tsx
function IconRail({ modules, active }: { modules: Module[]; active: string }) {
  const [open, setOpen] = useState<string | null>(null)
  const closeTimer = useRef<number>()
  const enter = (id: string) => { clearTimeout(closeTimer.current)
    closeTimer.current = window.setTimeout(() => setOpen(id), 80) }      // open delay
  const leave = () => { clearTimeout(closeTimer.current)
    closeTimer.current = window.setTimeout(() => setOpen(null), 200) }    // close grace
  return (
    <nav className="w-rail bg-surface border-r border-border flex flex-col"
         aria-label="Primary">
      {modules.map(m => (
        <div key={m.id} onMouseEnter={() => enter(m.id)} onMouseLeave={leave}>
          <a href={m.href} aria-current={active === m.id ? 'page' : undefined}
             onFocus={() => setOpen(m.id)}
             className={cn('flex flex-col items-center gap-0.5 py-2 text-2xs text-fg-muted',
               'hover:text-fg focus-visible:ring-2 ring-accent',
               active === m.id && 'text-fg border-l-2 border-accent')}>
            <m.Icon className="size-5" /> <span>{m.label}</span>
          </a>
          {open === m.id && <NavFlyout module={m} onMouseEnter={() => enter(m.id)}
                                       onMouseLeave={leave} />}
        </div>
      ))}
    </nav>
  )
}
// NavFlyout: header+search · 2 cols (left destinations grouped / right config) · pinned+recents
```

### 20.2 Telemetry DataTable (virtualized, 28px rows, conditional tint)
```tsx
function TelemetryTable<T>({ rows, columns }: { rows: T[]; columns: ColumnDef<T>[] }) {
  const table = useReactTable({ data: rows, columns, getCoreRowModel: getCoreRowModel() })
  const parentRef = useRef<HTMLDivElement>(null)
  const v = useVirtualizer({ count: rows.length, getScrollElement: () => parentRef.current,
    estimateSize: () => 28, overscan: 16 })
  return (
    <div ref={parentRef} className="overflow-auto" role="table">
      <div style={{ height: v.getTotalSize() }} className="relative font-mono text-xs tnum">
        {v.getVirtualItems().map(vi => {
          const row = table.getRowModel().rows[vi.index]
          return (
            <div key={row.id} role="row"
                 className="absolute inset-x-0 flex h-row items-center border-b border-border
                            hover:bg-surface-2"
                 style={{ transform: `translateY(${vi.start}px)` }}>
              {row.getVisibleCells().map(c => (
                <div role="cell" key={c.id} className="px-2 truncate"
                     data-sev={c.column.columnDef.meta?.sev?.(c.getValue())}>
                  {flexRender(c.column.columnDef.cell, c.getContext())}
                </div>
              ))}
            </div>
          )
        })}
      </div>
    </div>
  )  // [data-sev="warn"] { background: var(--accent-soft) } etc. for jitter/latency tinting
}
```

### 20.3 Dashboard shell (sticky toolbar + drag-resize panel grid)
```tsx
function DashboardShell({ title, children }: PropsWithChildren<{ title: string }>) {
  return (
    <section className="flex flex-col h-full">
      <header className="sticky top-0 z-10 h-toolbar flex items-center gap-2 px-3
                         bg-surface border-b border-border">
        <h1 className="text-sm font-semibold">{title}</h1>
        <ScopeFilter /> <QueryBar /> <div className="ml-auto" /> <TimeRange /> <ViewActions />
      </header>
      <PanelGrid className="grid gap-2 p-3 auto-rows-[minmax(120px,auto)]
                            grid-cols-12 overflow-auto">{children}</PanelGrid>
    </section>
  )
}
```

### 20.4 Dockable Inspector
```tsx
function Inspector() {
  const sel = useSelection(s => s.entity)
  const pinned = useSelection(s => s.pinned)
  if (!sel && !pinned) return null
  return (
    <aside className="w-[360px] shrink-0 bg-surface border-l border-border
                      flex flex-col" aria-label="Inspector">
      <div className="h-toolbar flex items-center gap-2 px-3 border-b border-border">
        <span className="text-sm font-semibold truncate">{sel?.name}</span>
        <PinToggle className="ml-auto" />
      </div>
      <div className="overflow-auto p-3 space-y-3 text-xs">
        <KeyValueGrid data={sel?.attrs} />  {/* tnum */}
        <MiniChart kind="sparkline" series={sel?.metrics} />
        <RelatedEntities of={sel} /> <InspectorActions on={sel} />
      </div>
    </aside>
  )
}
```

### 20.5 Command palette (entity jump)
```tsx
function CommandPalette() {
  const [open, setOpen] = useState(false)
  useHotkeys('mod+k', e => { e.preventDefault(); setOpen(o => !o) })
  return (
    <CommandDialog open={open} onOpenChange={setOpen}>
      <CommandInput placeholder="Jump to host, alert, dashboard, incident, device…" />
      <CommandList>
        <CommandGroup heading="Recent">{/* recents */}</CommandGroup>
        <CommandGroup heading="Hosts">{/* async entity results */}</CommandGroup>
        <CommandGroup heading="Actions">{/* New saved view, Ack alert… */}</CommandGroup>
      </CommandList>
    </CommandDialog>
  )
}
```

---

## 21. Tech-stack decision & phased rollout

**Stack (⚠️ reverses earlier "no Tailwind"):** React 18 + TS + Vite (keep) +
**Tailwind + shadcn/ui + Radix + TanStack Table/Virtual + Zustand + Framer Motion
(sparingly) + ECharts (keep)**. cmdk for palette; zod for boundary validation.

**Recommended path — incremental:** stand up the new shell (rail/flyout/topbar/
panes) + token layer alongside the current plain-CSS app; migrate module-by-module
behind existing routes; retire old CSS as each module lands. Avoids a big-bang
rewrite and keeps the stack shippable throughout.

**Phases:**
1. Tokens + AppShell (rail, two-column flyout, topbar, 4-pane, theme/density).
2. Chart/Table primitives (`<Chart>`, `<DataTable>`) on tokens.
3. **Fleet** + **Network** (highest value, your graphing focus; Tunnels + Path).
4. Monitors / Incidents / Logs / Metrics.
5. Platform (Integrations / Stack / Admin) — mostly re-skin existing wizards.
6. Polish: keyboard map, layout persistence, OLED, a11y AA pass, perf budgets.

> **Frontend-only change.** Backend stdlib-only/allowlist guardrails are
> untouched — this is `src/frontend` plus its own `package.json`.

---

## 22. Open decisions to lock
1. **Stack scope** — incremental migration (recommended) vs greenfield rebuild.
2. **Accent** — cobalt `#2D6BE0` vs teal `#2DB4C9` (away from indigo).
3. **Module names** — approve/edit Pulse / Fleet / Network / Monitors / Stack…
4. **Rail labels** — tiny labels under icons (proposed) vs icon-only.
5. **Module set** — confirm dropping Traces/Cloud/Security/APIs until real, and
   keeping owner-only **Stack**.
6. **Density default** — 28px standard with 24px toggle (proposed) vs 24px default.
```
