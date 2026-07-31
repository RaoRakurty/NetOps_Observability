# Hybrid Cloud Map — design

**Status:** design, not built. Filed as TRACKER #130–#132.
**Date:** 2026-07-31.
**Source:** owner observation of Kentik's hybrid-cloud product (Kentik Map, Cloud
Pathfinder, Data Explorer) + `kentik.com/solutions/visualize-all-cloud-and-network-traffic/`.

This document exists because a capability gap became legible as a **story we
cannot currently tell**. It is written around that story rather than around a
feature list, because the feature list is how you build the wrong thing: every
piece below is justified by a beat in the narrative an operator lives through,
and anything that does not serve a beat is not in scope.

---

## 1. The story we must be able to tell

An application team reports that a service in AWS `us-east-1` is slow reaching
an on-prem database in the Chicago DC. The operator should be able to:

1. **Start from everything.** Open one map. See CLOUDS (every provider, every
   region in use) and the INTERNET (the networks traffic originates from and
   leaves through), with traffic volume drawn between them. No prior knowledge
   of which VPC or which circuit is involved.
2. **Narrow by looking.** The AWS block is visibly heavier than usual toward
   on-prem. Click it → *view topology · show details · show connections*.
3. **See both worlds at once.** On-prem topology on one side, AWS regions on the
   other, and **in the middle the things that join them**: Direct Connect,
   DX gateways, VPN connections. Each region is a block; each block shows its
   VPCs and how they attach to the transit gateway.
4. **Follow the traffic, live.** The edges carry real telemetry, so the operator
   can see *where* volume is moving, not just that the objects exist.
5. **Drill to the pair.** Click a VPC↔VPC or VPC↔on-prem edge → the traffic
   detail for exactly that pair.
6. **Ask the question precisely.** Jump to Data Explorer with that context
   pre-loaded and refine: this VPC to that DC, filtered by subnet, ENI, TGW id,
   instance tag, application, BGP next-hop — then switch the visualization to
   whatever shape answers the question.
7. **Get the verdict.** Which side owns the problem — us, the carrier, or the
   provider — with the evidence attached.

Steps 1–6 are Kentik's product. **Step 7 is ours, and it is the reason to build
1–6 rather than to copy them**: the map is how an operator arrives at a
question; the seam verdict is the answer. Today we can answer a question the
operator cannot get to.

---

## 2. Where we are strong — DO NOT REBUILD

These are ahead of the reference product and must not be traded away for
surface parity.

| Capability | Where | Why it stays |
|---|---|---|
| **Seam ownership model** | `internal/seam`, `seam_handlers.go`, `topologyDomains.ts` | We model the *ownership handoff* and place blame at it (ISP vs provider vs us). Kentik draws the boundary and leaves attribution to the operator. This is step 7 and it is the differentiator. |
| **Authoritative cloud route graph** | `cloud/topology.go` | Edges are real route-table entries (`internet_gateway`/`nat_gateway`/`nva`/`vpc_endpoint`/`vpn_gateway`), not inferred adjacency. A drawn edge means a route exists. |
| **Seam-classified cloud objects** | `cloud/kinds.go` (`FamilySeam`) | TGW attachments, VPC/VNet peering, VPN/DX/ER gateways are *already* classified as lateral-link endpoints. The taxonomy for §3 exists. |
| **Evidence + confidence on every edge** | topology contract | Every edge explains itself. A map that cannot say why it drew a line is a diagram, not an instrument. |
| **Hop-by-hop path with per-hop interface metrics** | `path_graph_api.go`, `topology_path_ifmetrics.go`, `pathgraph/` | The backend decides hop order; the UI is a dumb renderer. Correct architecture — reuse it, do not fork it. |
| **Replayable, evidence-bearing RCA** | `src/correlation/` | Same inputs → byte-identical verdict, months later. |
| **Zone classification incl. DX/ExpressRoute/ISP** | `topologyDomains.ts` | The seam vocabulary the middle column of §3 needs already exists. |

---

## 3. Gaps, mapped to the story beats

| # | Beat | Gap | Have today |
|---|---|---|---|
| **G1** | 1 | No provider/region-level map surface. Nothing renders a CLOUDS box, per-provider blocks, or regions as blocks. | `Region` is a field on `TopoCIDR`; never rendered as a grouping. |
| **G2** | 1, 4 | **Map edges carry no traffic volume.** The topology is structural only — it shows what connects, never how much is moving. | `cloud_flow_pair`/`cloud_flow_volume` are ingested but not joined to topology edges. |
| **G3** | 3 | **On-prem and cloud are separate canvases.** No single view with on-prem on one side, regions on the other, and DX/DXGW/VPN in the middle. | Both halves exist independently (topology canvas; cloud service map). |
| **G4** | 5, 6 | **Path is RCA-only.** `GET /api/rca/{correlation_id}/path` requires a detected correlation. There is no ad-hoc "path from A to B right now" — the Cloud Pathfinder equivalent. | The whole path engine exists; only the entry point is missing. |
| **G5** | 6 | **The query surface is 10 allowlisted on-prem dimensions with no cloud dimensions at all.** `flowTopDims` = device, in_if, out_if, src/dst addr, src/dst AS, src/dst port, proto. No vpc_id, subnet, ENI, TGW id, account, region, instance tag. No arbitrary filter stack, no cross-provider query, no switchable visualization. | Pre-defined server-side queries only; OpenSearch Dashboards iframe as the escape hatch. |
| **G6** | 1 | **INTERNET box needs AS-path.** "Origin networks / providers / next-hop networks" is a routing distinction; we have `src_as`/`dst_as` on flows but no RIB/BMP feed, so we cannot distinguish origin from transit. | Top-AS panels only. |

G5 is the same gap the Kentik PDF analysis independently surfaced as the single
highest-value item (tenet 4, "ask any question"). Two separate investigations
converging on it is the strongest signal in this document.

---

## 4. Design

### 4.1 Traffic on the graph (G2) — the enabling primitive

Everything visual depends on this, and it is the smallest piece. A topology edge
gains an optional **volume binding**: the (src, dst) predicate that selects the
flows the edge represents, resolved against ClickHouse over the dashboard
window.

- Structural truth stays authoritative — an edge is drawn because a route
  exists, never because bytes were seen. Volume **decorates** an edge; it never
  creates one. (Inventing edges from traffic is how a map becomes a hairball
  that lies.)
- An edge with no matching flows renders as *no data*, distinctly from zero —
  the honest-empty-state rule that already applies elsewhere.
- Bindings are per-tenant scoped through the existing `chTenantScope`.

### 4.2 The hybrid canvas (G1, G3)

One canvas, three columns, driven by the existing zone classifier:

```
   ON-PREM              SEAMS                    CLOUD
  ┌────────┐     ┌──────────────────┐     ┌──────────────────┐
  │ DC      │────│ Direct Connect   │─────│ AWS us-east-1    │
  │ Campus  │    │ DX Gateway       │     │  ├ VPC-a ──┐     │
  │ Branch  │────│ VPN / ExpressRoute│    │  └ VPC-b ──┴ TGW │
  └────────┘     └──────────────────┘     ├──────────────────┤
                                          │ Azure westeurope │
                                          └──────────────────┘
```

- The middle column is **exactly the seam model we already have**. This is why
  the hybrid view is cheaper for us than it looks: the hard modelling is done,
  and the seam is the one thing our competitor does not model.
- Regions are collapsible blocks; VPCs are nodes inside them; TGW/peering
  attachments are `FamilySeam` nodes that already carry the right kind.
- Reuse the existing semantic-zoom ladder (`semanticZoom.ts`) rather than
  inventing a second one — three disagreeing zoom ladders was a real bug here
  once.
- Click → context actions (*view topology · show details · show connections*).
  "Show connections" is a filter over the same graph, not a new view.

### 4.3 Ad-hoc Pathfinder (G4)

`GET /api/path?from=<endpoint>&to=<endpoint>` returning the **same payload
shape** as the RCA path. The engine, the boundary computation and the renderer
are all reused; only the entry point is new — an operator picks two endpoints
instead of a correlation supplying them.

This is the highest value-per-unit-effort item in the document: it converts an
existing engine from incident-only to investigative, and it is the beat that
makes the map actionable instead of decorative.

### 4.4 Data Explorer (G5)

The large one, and deliberately last in this section because the map is what
gives it context to launch from.

- A **dimension registry** in the same shape as `processors/registry.go`: one
  definition per dimension supplying its validation, its SQL projection and its
  filter compilation, so the API and the UI cannot drift. That pattern is
  already proven here.
- Dimensions span both worlds: on-prem (device, interface, IP, port, proto, AS,
  BGP next-hop, geo) **and** cloud (provider, account, region, VPC, subnet, ENI,
  TGW id, instance tag, security group), plus application context from
  `appid/`.
- Arbitrary filter stacks and multi-dimension group-by compiled **server-side**
  to bounded ClickHouse SQL through the existing `chhttp` discipline — the
  BUILD-tier bounded-query guard is what makes an open query surface safe to
  offer at all.
- Cross-provider queries (provider-1 → provider-2, or intra-provider) come free
  once cloud flow pairs and on-prem flows answer through one dimension registry.
- Switchable visualizations over one result set (time series, stacked, Sankey,
  histogram, table). Sankey lands here rather than as its own feature.

### 4.5 INTERNET box (G6) — gated

Origin-vs-next-hop is a routing distinction requiring a BMP/RIB feed we do not
have. **Do not fake it from `src_as`/`dst_as`** — a box labelled "origin
networks" that is actually showing peer ASNs is worse than no box, because it
looks authoritative. Ship the INTERNET box only after the routing lane lands
(Kentik-PDF gap §3.4); until then the map's internet edge stays a single
honest node.

---

## 5. Sequencing

| Order | Item | Why here |
|---|---|---|
| 1 | **G4 Pathfinder** (#130) | Reuses a finished engine; needs no new data. Immediately makes cloud→on-prem troubleshooting narratable. |
| 2 | **G2 traffic on edges** (#131) | Enabling primitive for every visual beat; small and self-contained. |
| 3 | **G1+G3 hybrid canvas** (#131) | Depends on 2 for the live-telemetry beat; reuses the seam model and zoom ladder. |
| 4 | **G5 Data Explorer** (#132) | Largest; the map gives it launch context, so it lands better after 1–3. Independently the top item from the Kentik-PDF analysis. |
| 5 | **G6 INTERNET box** | Blocked on the routing lane. Do not start early. |

Steps 1–3 are the troubleshooting narrative end to end. Step 4 is what turns it
from a story an operator can follow into a question an operator can ask.

---

## 6. What this deliberately does not do

- **No mitigation orchestration, no OTT/CDN subscriber analytics** — service
  provider features; our ICP is enterprise NetOps.
- **No geoIP for device placement** — placement is operator intent from the SoT.
  RFC 1918 management addresses do not geolocate (`geomap.go`). GeoIP is only
  legitimate for *remote* endpoints, which is a Data Explorer dimension, not a
  map primitive.
- **No traffic-inferred topology edges** — see §4.1.
