# Topology + Network Path + RCA Overlay Visualization

Premium, operator-first topology/path visualization that answers, for any
incident: **what path is involved · where does evidence point · confirmed or
suspected · what evidence supports it · what's missing · who owns the fix · what
to do next.** Not a generic pretty map.

## Goal ↔ requirement check

The product goal (RCA-first hybrid network observability — the correlation engine
is the product, see `netops-frontpage-rca-direction`) is **fully aligned** with
this requirement. The visualization is the operator surface for the engine: it
makes the engine's grounded verdict legible on the real network path. Standing
bars it must keep: defense-grade tenancy/no-leaks, premium NOC quality, decision
#76 (internal stack excluded from customer RCA), honesty (no faked data, no
invented broken links), Operator View hides raw IDs.

## Three layers (RCA never rewrites base topology — overlay only)

- **Layer 1 — Base topology** (stable model): LLDP (L2), CDP (Cisco L2), BGP-LS
  (L3/IGP/TE), inventory/SoT (site/role/owner), provider/cloud boundaries.
- **Layer 2 — Observed path**: active probes, traceroute (icmp+tcp, priority/auto
  fill), flow direction, SD-WAN path, BGP next-hop context.
- **Layer 3 — RCA overlay**: corr_objects/signals/edges/evidence →
  `rca_path_annotations` (status/verdict/confidence/owner/visibility/missing
  evidence). Overlay only — never mutates Layer 1/2.

## Stack

React Flow (`@xyflow/react`) for path + medium topology · **elkjs** for layered
LEFT_TO_RIGHT layout · custom React nodes + custom SVG edges · CSS/SVG animation
for flow. ECharts stays for dashboard charts only. No Three.js. Sigma.js +
Graphology only if a future explorer needs 1000s of nodes; PixiJS only if SVG
particles get heavy.

## Backend data model (canonical)

`topology_nodes` (id, tenant_id, scope/site, type, label, display_label, role,
vendor, platform, mgmt_ip, site, zone, owner, health_band, last_seen, metadata) ·
`topology_edges` (… source/target_node, type physical_l2|logical_l3|bgp_ls|
bgp_session|path_segment|provider_boundary|inferred, local/remote_interface,
source_protocol lldp|cdp|bgp_ls|inventory|probe|flow|manual, confidence,
bidirectional, operational_state, speed/util/error/discard/latency/loss/jitter,
last_observed_at, stale) · `topology_edge_observations` (per-protocol raw neighbor
records → normalized edges) · `path_observations` (source/dest, observed_hops,
segments, metrics, collection_method, authority, scope) · `rca_path_annotations`
(corr_object_id, target_type node|edge|path_segment|boundary|path, target_id,
status, verdict, confidence, owner, visibility, reason, evidence_refs,
missing_evidence). All tenant-scoped + FORCE RLS.

## Backend APIs

1. `GET /api/topology/graph?scope&site_id&layer&include_health&include_rca&corr_object_id`
   → {nodes, edges, groups, layoutHints, updated_at, stale_inputs, coverage}
2. `GET /api/network-paths/{path_id}/view` → path-specific graph + segments/metrics/boundaries
3. `GET /api/correlations/{id}/path-overlay` → RCA annotations + evidence/missing summaries
4. `GET /api/correlations/{id}/rca-path-view` → UI-ready combined (path + topo context + overlay)

## Frontend components

TopologyCanvas (generic renderer) · NetworkPathView (L→R src→dst) · RcaPathView
(NetworkPathView + overlay; titles: confirmed "Likely fault location" / suspected
"Where evidence points — not confirmed" / undetermined "Observed path
relationship" / internal "Internal monitoring path") · DeviceNode · PathEndpointNode
· BoundaryNode · **TrafficFlowEdge** · RcaOverlayMarker (⚠ ❌ ? ○ ● ◆) ·
EvidencePopover · TopologyLegend · InspectorSidePanel.

Overlay states: observed (calm) · degraded (amber pulse) · suspected_down (red
dashed + ⚠) · confirmed_down (red break + ✕) · insufficient_visibility (gray
dotted + ?) · missing_evidence (hollow ○) · internal_only (muted, hidden from
customer view). Reduced-motion disables animation → static symbols. Cap ≤25
animated edges.

## Mapping logic (evidence → target)

- `link_state_change` (dev+iface) → exact topology edge by (source_node, local_interface).
- `bgp_adjacency_change` (dev+peer) → BGP session/BGP-LS edge; merge with link on same iface.
- probe loss (src→dst) → path segment if hops known, else whole path "location uncertain".
- flow drop → strengthen confidence on matched path/interface.
- Confidence: one signal class → weak; same device but one observer class → Suspected;
  independent observer → Confirmed. Internal/debug probes never promote to customer RCA.

## Golden fixture

`936cc7fe-efe4-554f-a845-6a48380ee082` → title "Where evidence points — not
confirmed"; path vantage-e2e → e2e-edge1 → Gi0/1 / peer 10.99.0.2; e2e-edge1:Gi0/1
suspected_down; BGP peer shown as affected context; 85% probe loss as supporting;
verdict Suspected, confidence 0.50.

## Implementation status & order

- [x] **3–6 (partial): React Flow path view, glossy shaped nodes, custom edge
  states, animated particles** — `RcaTopology.tsx` + `graph/shapes.tsx` +
  `graph/FlowEdge.tsx` (shapes, healthy/degraded/suspected_down/confirmed_down/
  unknown, reduced-motion, BGP device→peer total-path, fitView sizing). Shipped.
- [x] Live-trace fusion (icmp+tcp parallel, priority/auto fill) — see
  `rca-path-topology.md`.
- [ ] **1–2: UI-ready `/api/correlations/{id}/rca-path-view` + overlay mapping**
  (corr evidence → node/edge/path_segment annotations). NEXT.
- [~] Base-topology backend: **LLDP collector SHIPPED** (`collectors/lldp.go`,
  SNMP LLDP-MIB → Redis) + `/api/topology/links` (tenant-scoped, bidir-dedup,
  source-agnostic `source_protocol`). Validated live on the clos lab (cEOS +
  SR Linux + Cisco). TODO: CDP (CISCO-CDP-MIB) + BGP-LS sources (same link shape);
  persistent `topology_nodes/edges` tables + `/api/topology/graph` (Redis MVP today).
- [ ] NetworkPathView/TopologyCanvas split, BoundaryNode, EvidencePopover,
  InspectorSidePanel, TopologyLegend; elkjs layered layout.
- [x] Device Topology page draws **real LLDP-discovered links** (tabs/Topology.tsx;
  tier-inference now a dashed labelled fallback). Full TopologyCanvas rebuild TBD.
- [~] **7–8: tests** — LLDP DONE (composite-index parse, chassis-vs-port subtype
  render, bidir dedup, sysName/FQDN/mgmt-addr resolution, tenant isolation). TODO:
  CDP/BGP-LS normalize, stale handling, integration (golden render, no-fake-link,
  operator-vs-debug, reduced-motion), Playwright.

## Performance / accessibility

RCA path <500ms for ≤100 nodes · site topology 300 nodes/600 edges in React Flow ·
≤25 animated edges · layout in a worker if it blocks · persist node positions by
graph hash/scope (no jumping) · prefers-reduced-motion honored.

## Non-goals

No 3D · no vendor UI/icons/wording copied · RCA never rewrites topology · no raw
backend names in Operator View · debug/internal checks never shown as customer
failures · no whole-topology animation for flash.
