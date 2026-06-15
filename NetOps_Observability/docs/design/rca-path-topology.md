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
6. **STAMP metrics knob (opt-in):** the measured segment always shows the loss
   headline (the fault signature); a top-right toggle (**default OFF**, to avoid
   clutter) overlays the fuller active-measurement set — `loss · RTT · jitter` —
   pulled from the path's probe signals (`probe_loss`, `probe_rtt_ms[stamp|icmp|
   tcp|http]`, `probe_jitter`), preferring the STAMP method for RTT. In Phase 2
   this becomes genuine **per-hop** STAMP between adjacent traced hops.

## Phase 2 — live-trace fusion (SHIPPED, frontend)

The topology now uses **real hop order** from active path tracing when available,
falling back to contextual placement otherwise:

- **Source:** `/api/probe/paths` (`ProbePath{ dst, hops[]{ttl, ip, rtt_ms,
  loss_pct}, reached, changed }`) — traceroute / STAMP, already collected. Fetched
  in `Correlations.tsx` and passed to `RcaTopology`.
- **Match:** the RCA path entity's `dst` is matched to a trace's `dst` (exact, or
  either-contains for named dsts). On a hit, `RcaTopology` renders the true
  TTL-ordered hop chain `observer → hop → … → destination` with per-hop RTT and
  per-hop loss; a hop with loss > 2% is flagged red (ThousandEyes-style). The
  **STAMP knob** then shows genuine **per-hop** RTT between adjacent hops.
- **RCA overlay:** the fault lands on the hop whose IP/name matches the locus, else
  on the destination hop (the diagnosed target), carrying the verdict status +
  broken-element chips. Legend shows "● live trace" vs "contextual path".

### Phase 2 follow-ups (not yet done)

- **IP → device naming:** hops currently show **IPs** (standard, like ThousandEyes).
  To label them with device names, add an `IP → device` resolver from inventory
  (NetBox mgmt-IP → device; see `netops-netbox-sync`). Best done server-side: a small
  `path-topology` endpoint that fuses trace + inventory + seam endpoints + RCA into
  one resolved object so the frontend stays a pure renderer (also enables precise
  locus→hop matching instead of the destination-hop fallback).
- **Scale:** collapse clean hop runs into a `…N healthy hops…` pill; show ECMP/LAG
  as parallel branches; auto-layout (`dagre`/`elk`) only if branching exceeds the
  simple per-path row layout.

## Files

- `src/frontend/src/components/rca/RcaTopology.tsx` — the view (Phase 1).
- `src/frontend/src/tabs/Correlations.tsx` — renders it as "End-to-end path".
- Phase 2: new backend endpoint + `IP→device` resolver; extend `RcaTopology` to
  consume resolved hops.
