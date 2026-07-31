# Topology & Path-Visualization — vendor UX research (2026-07-31)

Research pass over NetBrain, ContainerLab GUI, ThousandEyes, SolarWinds
NetPath, Kentik, Datadog NPM, Arista CloudVision, Juniper Paragon, Auvik and
LibreNMS, distilled for the Correlix topology canvas enhancement program.
Companion to the 2026-07-31 canvas audit (fixed in `d1dbf940`) and the
archetype/zone work that followed. Written against the topology-ui skill's
resolved-graph architecture — renderer-agnostic.

## (a) Node icons at scale

| Pattern | Who | Adaptation |
|---|---|---|
| Compact geometric SVG glyphs keyed to device ROLE, never vendor art | ContainerLab, Kentik, ThousandEyes | Fixed glyph set per resolved role (router/switch/fw/AP/host/cloud/ISP); legible at 16–24 px |
| **Three independent channels: shape = role · fill = health · ring/badge = exception** | ThousandEyes (fill/ring semantics), Kentik (shape-by-class) | Never encode two meanings in one channel; selection/threshold-breach = ring, counts/alerts = corner badge |
| Numeric count badges on collapsed groups | ThousandEyes, Datadog clusters, Juniper cluster view | Group nodes badge member count + worst-health tint; click to expand |
| LOD label rules: labels off by default at scale; reveal on zoom/selection/hover | ContainerLab link-label toggle; LibreNMS as the failure case | Wire the existing `semanticZoom.ts` ladder to the RF `onMove` zoom; always label selected/hovered/path members |
| Published icon legend, auto-generated per active overlay | Auvik, CloudVision | Generate the legend from the overlay registry, never hand-maintain |

## (b) Inventory + canvas dual-pane (the ContainerLab ask)

- Sidebar rows: **status dot + role glyph + hostname + mgmt IP + observed-since**,
  with the SAME context actions as the canvas node. (Audit finding: every field
  needed is already in the `/view`//`/graph` payloads — zero backend work; true
  SNMP `sysUpTime` is the one missing metric, `first_seen` is the honest
  "continuously observed since" proxy.)
- **Bidirectional selection sync** — selection state lives outside the renderer;
  list row click centres the canvas (reuse `onPick`), canvas click highlights
  the row. The single highest-leverage, lowest-cost pattern found.
- Filter-follows-canvas: the canvas renders the filtered inventory query, never
  the full graph (Datadog's map-is-a-query model; matches the no-hairball rule).
- "Show on map" from any device row seeds a scoped neighbourhood view
  (NetBrain's map-on-demand).
- Alternative: Juniper's table-below-map with Devices/Links/Sites/Paths tabs for
  link-centric list questions.

## (c) End-to-end path UX

- **Dedicated horizontal A→B lane** (NetPath/ThousandEyes), ECMP fanned
  vertically — Correlix already has the ribbon (`NetworkPathView`); upgrades:
  segment coloring green→red on loss/latency vs a VISIBLE threshold, edge
  thickness by traffic/trace share, hop-click → evidence pane (contract already
  carries evidence/confidence per edge).
- **Explainable hops** (NetBrain): annotate WHY each hop is on the path with the
  evidence that put it there; broken hop rendered distinctly (matches the RCA
  broken-red philosophy).
- **Time travel**: history strip of path snapshots, click to re-render as-of;
  v2 = two-snapshot diff; golden-path comparison is roadmap (matches the
  skill's time-diff-golden-path contract).
- **Honest unknowns** (ThousandEyes): unresolved hop = hollow glyph, dotted
  "?"/"X" links for insufficient data — maps directly to our confidence field.
- **Impact weighting** (NetPath "transit likelihood"): % of traffic crossing a
  red segment, from flow data.
- **URL-serialized investigation state** (ThousandEyes): selection/overlay/time
  in the route so findings are shareable.

## Priority order (leverage ÷ effort)

1. Inventory↔canvas selection sync (store-level, trivial)
2. ContainerLab-style sidebar rows
3. Three-channel compact node glyphs (+ fix the 200×88-declared vs 188×56-drawn
   geometry slack — audit §B)
4. Link-label LOD toggle + zoom-threshold labels (wire the dead `semanticZoom.ts`)
5. Filter-drives-canvas
6. A→B path lane segment coloring + hop evidence
7. Dashed/hollow low-confidence rendering
8. URL-serialized state

Medium: count-badged group collapse · overlay layers with auto legend · path
history strip. Roadmap-sized: forwarding-emulation path calc (NetBrain-grade),
golden-path diff, traffic-weighted transit likelihood.

Primary sources: NetBrain A-B Path & Data Views docs · containerlab.dev/manual/gui ·
ThousandEyes Path Visualization docs · SolarWinds NetPath docs · kb.kentik.com
Logical Map · Datadog CNM network map docs · Arista CloudVision topology docs ·
Juniper Paragon topology guide · Auvik network map KB · LibreNMS map docs.
