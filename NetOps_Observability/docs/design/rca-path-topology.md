# RCA End-to-End Path Topology

**Goal.** On the Correlation → RCA screen, show the **end-to-end path** for an
issue and mark **where exactly it's broken / suspected / possible** — and keep it
**dynamic and scalable** as devices, seams, and paths are added to the network.

## Principle: overlay model

The path **structure** and the RCA **verdict** are separate concerns, fused at
render time (validated against ThousandEyes Path Visualization, Kentik path
analysis):

- **Structure (owned by path discovery):** the hop chain `observer → … → target`
  comes from *data*, never hardcoded. It grows automatically as the network grows.
- **Overlay (owned by RCA):** the correlation engine's locus (`shared:X`), verdict
  tier, and per-entity evidence annotate the structure — which node is broken, and
  the precise broken elements (interface, BGP peer) on it.
- **Seams** render as ownership boundaries where the path crosses one.

Rendered with **React Flow** (`@xyflow/react`, already adopted — see
`netops-graph-viz-reactflow`). Custom nodes: observer/target endpoints, a prominent
**fault** node (status-colored, with broken-element chips), co-affected device
branch, and seam boundary chips.

## Honesty rule

Without a live hop trace we do **not** invent a hop sequence. We show only what we
can prove: *"loss observed from `<observer>` to `<target>`; evidence converges on
`<device>`; here is exactly what's broken there,"* with co-affected devices placed
as a branch off the locus (not a fake ordered chain). Status glyphs: ❌ broken
(confirmed) · ⚠ suspected · ? possible (undetermined).

## Phase 1 — SHIPPED (`RcaTopology.tsx`)

Fully data-driven from the correlation object — works for any object, any number of
devices, zero hardcoded entities:

1. **Ends** from the attached probe-path entity `src->dst` (e.g. `vantage-e2e ->
   e2e-edge1`). The path metric (e.g. `85% loss`) labels the degraded segment.
2. **Device evidence** aggregated by base device; interface/BGP/resource signals
   become broken-element chips (`Gi0/1 · link down`, `BGP peer down`).
3. **Locus** = the device the grounded `topo shared:X` edges converge on (fallback:
   worst-severity device, then path destination).
4. **Seam** boundary inserted when a seam-grounded edge exists.
5. **Verdict tier** → fault status + color. If the destination *is* the locus, the
   target node carries the fault badge.

## Phase 2 — live-trace fusion (NEXT, not started)

Replace/augment the contextual structure with **real hop order** from active path
tracing:

- **Source:** `/api/probe/paths` (`ProbePath{ dst, hops[]{ttl, ip, rtt_ms,
  loss_pct}, reached, changed }`) — already collected (traceroute / STAMP). Gives a
  true TTL-ordered hop chain plus per-hop loss/rtt for ThousandEyes-style red-link /
  red-circle marking from the trace itself.
- **Join (the gap):** traceroute hops are **IPs**; RCA entities are **device
  names**. Need an `IP → device` resolver from inventory (NetBox mgmt-IP → device;
  see `netops-netbox-sync`). Add a small backend `path-topology` endpoint that fuses
  trace + inventory + seam endpoints + RCA findings into one resolved path object so
  the frontend stays a pure renderer.
- **Scale:** collapse clean hop runs into a `…N healthy hops…` pill; show ECMP/LAG
  as parallel branches; auto-layout (consider `dagre`/`elk`) only if branching
  exceeds a simple per-path row layout.

## Files

- `src/frontend/src/components/rca/RcaTopology.tsx` — the view (Phase 1).
- `src/frontend/src/tabs/Correlations.tsx` — renders it as "End-to-end path".
- Phase 2: new backend endpoint + `IP→device` resolver; extend `RcaTopology` to
  consume resolved hops.
