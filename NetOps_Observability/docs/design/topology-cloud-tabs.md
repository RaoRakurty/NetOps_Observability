# Topology Canvas — Network‑Domain Tabs + Cloud Topology

Status: **design + reviewable POC** (2026‑07‑15). Additive to the existing
Phase‑1 React Flow + ELK operator canvas; the current canvas stays the default
and visually unchanged.

> Scope note (owner direction): this adds **cloud NETWORK topology** —
> VPCs/VNets, subnets, gateways, NVAs, tunnels, Direct Connect / ExpressRoute /
> Interconnect, transit gateways / cloud routers, NAT, load balancers — rendered
> with the **official provider icons**. Individual cloud **application
> workloads** are **out of scope** (see §7).

---

## 0. Orientation — what already exists

The topology feature (`src/frontend/src/features/topology/`) is a mature
Phase‑1 canvas:

- **One renderer‑agnostic contract** — `api/topologyTypes.ts`
  (`TopologyView { nodes, edges, groups, layout_type, overlays }`, flat, matches
  the skill `topology-contract.json`). Everything renders from this; nothing
  consumes raw facts.
- **One React Flow renderer** — `renderers/react-flow/TopologyCanvas.tsx`
  (`CanvasInner`) → ELK layout (`layout/elkLayout.ts`) → `topologyToReactFlow.ts`
  adapter → custom node/edge components.
- **Two orthogonal switchers today**: a **workflow** selector
  (Explore / Investigate / Path Trace / Dependency, `MapWorkflowSelector`) and a
  **renderer** toggle (Canvas / Overview / Geo). Plus overlay, group‑by, density.
- **Cloud primitives already present but thin**: node kind `cloud`,
  `CloudNode.tsx` (a generic purple cloud glyph — **no official icons**),
  `mock/cloudTopology.ts` (an **app‑dependency** view, includes workloads — the
  thing we exclude), group types incl. `vpc`/`region`/`zone`.
- **Provider marks** — SUPERSEDED 2026-09-04 (licence audit D5): the vendored
  official `assets/cloud/*.svg` marks were deleted. The render pattern is now
  ORIGINAL Correlix artwork drawn inline from
  `src/frontend/src/components/CloudGlyph.tsx` — one cloud silhouette, a plain
  letter tag (`AWS` / `AZ` / `GCP`) as the only difference, untagged for
  anything else. `components/graph/shapes.tsx` embeds the same family.
- **Cloud network DATA exists in the backend** — `src/backend/cloud/topology.go`
  loads `*-topology.json` fixtures (`deployment/docker/cloud-fixtures/
  aws-topology.json`, `azure-topology.json`): **VPC/subnet CIDRs + route‑table
  egress edges** (`subnet --destination--> {internet_gateway | nat_gateway | nva
  | vpc_endpoint | vpn_gateway}`). **But it is NOT exposed on any
  `/api/topology/*` HTTP route** — today it is consumed internally by
  `path_ingest.go` for RCA path grounding only. See §8 for the endpoint to add.

**Design consequence:** we are not inventing a cloud model; we are giving the
existing route‑table facts a first‑class rendering, adding official icons, and
introducing a **network‑domain tab** dimension that is orthogonal to the
existing workflow/renderer switchers.

---

## 1. The tab model

### 1.1 A new orthogonal dimension: *network domain*

The owner asked for tabs describing **different network types**, and explicitly
**not** one merged hairball. The workflow selector answers *"what operator task"*
(explore/investigate/trace); the new tabs answer *"which network domain am I
looking at"*:

| Tab | What it shows | Data source |
|-----|---------------|-------------|
| **LAN** *(default)* | The discovered on‑prem fabric exactly as the canvas shows it today — campus/access/distribution/core, hosts. **Unchanged.** | `GET /api/topology/view` / `/graph` (live), mock `physicalTopology` fallback |
| **SD‑WAN** | The WAN edge: SD‑WAN gateways, VPN/tunnel overlays, transport underlays, hub/spoke. | Domain‑filtered slice of the fabric view (role/kind: `wan`/`gateway`/`vpn`/`tunnel`/`sdwan`/`edge`); production: WAN‑edge projection + tunnels store (`/api/topology/view?domain=sdwan`) |
| **DC** | Data‑center fabric: spine/leaf, ToR, compute/storage rows, DC firewalls/LBs. | Domain‑filtered slice (role/kind: `spine`/`leaf`/`tor`/`server`/`storage`/`dc`); production: same projection scoped to DC sites |
| **Cloud** | **Cloud network topology** (this doc): VPC/VNet → subnets → gateways/NVAs → route‑egress + hybrid seams + transit. **No workloads.** | `cloud/topology.go` fixtures now (mock `cloudNetworkTopology`); production `GET /api/topology/cloud` (§8) |

**Carrier / provider network is NOT a tab — it is a cross‑cutting overlay** (§4),
toggled on top of *any* tab, because the carrier is the thing that ties the
domains together.

### 1.2 Why domain‑tabs and not more workflows

- A workflow is a *lens on one graph*; a domain is *a different graph*. Merging
  them into the workflow selector would conflate "investigate" (a task) with
  "cloud" (a place). Keeping them orthogonal means every workflow (explore,
  investigate, …) is still available *within* each domain later.
- It satisfies "don't merge into one giant graph": each tab is its own coherent,
  legible topology with its own layout preset.
- It is **strictly additive**: LAN renders the current `CanvasInner` untouched,
  so the default view has zero behavioural change.

### 1.3 How the domains merge conceptually

```
        ┌──────────────── Carrier / Provider cloud (overlay) ────────────────┐
        │        (MPLS / Internet / DX transport — add-able to ANY tab)       │
        └───▲──────────────▲───────────────────▲──────────────────▲──────────┘
            │              │                   │                  │
        WAN edge        WAN edge            VGW / DX           WAN edge
            │              │                   │                  │
        ┌───┴───┐     ┌────┴────┐        ┌─────┴──────┐      ┌────┴────┐
        │  LAN  │     │ SD-WAN  │        │   Cloud    │      │   DC    │
        │ fabric│     │ overlay │        │ VPC/VNet   │      │ spine/  │
        │       │     │ hub/spk │        │ subnets/gw │      │ leaf    │
        └───────┘     └─────────┘        └────────────┘      └─────────┘
```

The **carrier overlay** is the shared spine. In each tab it attaches to that
tab's *egress points* (WAN/edge routers on‑prem; VGW/DX/IGW in cloud) and draws
uplinks to a single carrier node — so an operator flipping between tabs sees the
**same carrier** as the interconnection fabric, making the seam between on‑prem,
WAN and cloud legible without drawing all four graphs at once.

---

## 2. Cloud‑tab node & edge taxonomy (mapped to real data)

The Cloud tab renders a `TopologyView` with `layout_type: "cloud_grouped"`.
Containers are groups; everything else is a leaf node of kind `cloud`
(role‑discriminated) so one node component + the official mark covers all of it.

### 2.1 Nodes / groups

| Element | Represented as | `role` | From data? |
|---------|----------------|--------|------------|
| Region | group (`group_type: region`) | — | ✅ `Topology.Region` |
| VPC / VNet | group (`group_type: vpc`) | — | ✅ `Topology.VPCs[]` (id + CIDR) |
| Subnet | **node** (kind `cloud`, container‑ish) | `subnet` | ✅ `Topology.Subnets[]` (id + CIDR + name) |
| Internet Gateway | node | `igw` | ✅ edge `to_kind=internet_gateway` |
| NAT Gateway | node | `nat` | ✅ `to_kind=nat_gateway` |
| VPC endpoint | node | `endpoint` | ✅ `to_kind=vpc_endpoint` |
| NVA (firewall/router appliance) | node | `nva` | ✅ `to_kind=nva` (an instance next‑hop) |
| VPN Gateway (VGW) | node | `vgw` | ✅ `to_kind=vpn_gateway` |
| Direct Connect / ExpressRoute / Interconnect | node | `dx` | ⚠️ **gap** — not in the current fixture; see §2.3 |
| Transit Gateway / vHub / Cloud Router | node | `tgw` | ⚠️ **gap** — not in the current fixture; see §2.3 |
| Load balancer | node (kind `load_balancer`) | `lb` | ⚠️ present in app view, not the network fixture |

Subnet is modelled as a **node** (not a group) because in a network‑only view
(workloads excluded) the subnet *is* the route source — the natural edge
endpoint — and this mirrors `cloud/topology.go`'s `TopoEdge.FromSubnet` exactly.

### 2.2 Edges

| Edge | `relationship` | Style | From data? |
|------|----------------|-------|------------|
| Route egress (`subnet --dest--> target`) | `routed_adjacency` (control‑plane inferred) | solid, **labelled with the destination CIDR** | ✅ `Topology.Edges[]` — 1:1 with route‑table rows |
| Hybrid seam (VGW/DX → carrier / on‑prem) | `inferred` | dashed (logical link) | ⚠️ partial — VGW target exists; the *tunnel* to on‑prem is synthesised by the carrier overlay |
| Transit attachment (VPC ↔ TGW) | `routed_adjacency` | solid | ⚠️ **gap** (§2.3) |
| VPC peering | `connected_to` | solid | ⚠️ **gap** (§2.3) |

Route edges are **honest control‑plane facts** — `cloud/topology.go` itself
documents them as *"a strong explanation of an observed hop, NOT permission to
assert traffic took it."* So they render as `routed_adjacency` at moderate
confidence (~0.7), never as measured traffic.

### 2.3 Honest gaps (data that does NOT exist yet)

- **Direct Connect / ExpressRoute / Interconnect** and **Transit Gateway / vHub
  / Cloud Router** and **VPC peering**: `discover.py` / `cloud-discover-azure.py`
  parse route tables and CIDRs but do **not** yet emit DX/TGW/peering as first
  class resources. The taxonomy above reserves the roles; the POC mock includes
  a VGW + a TGW example to prove the rendering, clearly marked as
  *illustrative until the discovery pollers emit them*.
- **Health / metrics on cloud resources**: the fixtures carry no per‑resource
  telemetry. Cloud nodes render at `health: unknown` (honest) until the gateway‑
  plane telemetry lanes (#105) are joined in.
- **Load balancers in the network view**: LBs appear in the app‑dependency view;
  the network fixture doesn't enumerate them. Reserved, not fabricated.

---

## 3. Icon & rendering strategy

### 3.1 Official marks

- SUPERSEDED 2026-09-04 (licence audit D5). The vendored official marks were
  removed; `features/topology/components/ProviderMark.tsx` now draws the
  ORIGINAL glyph family inline from `components/CloudGlyph.tsx` — one
  silhouette, a plain letter tag (`AWS` / `AZ` / `GCP`) as the ONLY provider
  difference, the untagged generic cloud for anything else. No provider colour,
  no provider asset, no implication of endorsement. Inline SVG means it is
  theme‑aware (`currentColor`) and fetches nothing (CSP / offline rule).
- Provider comes from `node.tags.provider` (`aws` | `azure` | `gcp`), stamped by
  the backend — never guessed in the component.

### 3.2 Cloud resource node

`CloudResourceNode.tsx` reuses the shared `NodeCard` shell (fixed geometry, the
calm health ring, the confidence chip, the no‑shake invariant) but:

- **Icon = the provider‑tagged cloud glyph** (`<ProviderMark>`, original
  artwork), so the card reads as "an AWS/Azure resource" at a glance.
- A small **role chip** (`VPC` · `Subnet` · `IGW` · `NAT` · `VGW` · `DX` · `TGW`
  · `NVA` · `Endpoint`) names the specific network function, with the CIDR in the
  hover tooltip — the operator reads *what kind of cloud box* without reading a
  paragraph.
- A per‑provider accent on the card's left rule, so a multi‑cloud canvas is
  visually sortable by provider without shouting. RE‑KEYED 2026-09-04 (D5) from
  the brand hexes to the PRODUCT's own indigo→violet ramp
  (`#4f46e5` / `#6366f1` / `#8b5cf6`, generic violet) — provider identity is
  carried by the glyph's letter tag, never by a brand hue.

### 3.3 Containers & edges

- **VPC/VNet + Region** render through the existing `GroupNode` (translucent
  backdrop + label chip + collapse). Group `label` carries the CIDR ("VPC
  vpc‑prod · 10.20.0.0/16"). The `subnet` group type is added to the label map.
- **Route edges** use the existing `TopologyEdge` (solid) with the **destination
  CIDR as the edge label** — the single most useful fact on a route.
- **Seam / tunnel edges** use the existing `InferredEdge` (dashed) to read as a
  *logical* link, labelled with the seam type ("IPsec", "ExpressRoute").
- A dedicated tunnel edge style (double‑stroke seam) is a nice‑to‑have follow‑up;
  the POC reuses `InferredEdge` to stay additive.

### 3.4 Isolation from the default canvas

The Cloud tab mounts its **own** React Flow instance (`CloudTopologyView.tsx`)
with its **own** `nodeTypes` map where `cloudNode → CloudResourceNode`. The
global `nodeTypes` (used by the default LAN canvas and every other view) is
**untouched** — so `CloudNode` and the current fabric render exactly as before.
The Cloud view still reuses the shared `layoutView` (ELK) and
`topologyToReactFlow` adapter, so it inherits groups, collapse, spotlight and the
no‑shake invariant for free.

---

## 4. The Carrier overlay (cross‑cutting)

`utils/carrierOverlay.ts` → `withCarrierOverlay(view, opts?)` is a **pure view
transform** that:

1. Finds the active view's **egress points** — nodes whose role/kind marks a WAN
   boundary (`wan`, `edge`, `border`, `uplink`, `transit`, `vgw`, `dx`, `igw`).
2. Appends **one carrier node** (kind `wan`, role `carrier`, generic cloud glyph
   — a *telco/transport* cloud, deliberately **not** a hyperscaler mark) and an
   uplink edge from each egress point to it, each carrying evidence
   (`carrier:uplink:<node>`), so the "never draw a link without evidence" rule
   holds.
3. Is **idempotent** (re‑applying doesn't duplicate the carrier) and **non‑
   mutating** (returns a new view), so it composes with any tab and any workflow.

Because it keys off *roles that exist in every domain*, the same overlay lights
up the WAN seam in LAN/SD‑WAN/DC (edge routers → carrier) and in Cloud (VGW/DX →
carrier). That is the "carrier ties them together" story, shown in‑context per
tab rather than as a fourth merged graph.

Toggle lives in the tab bar (a checkbox‑style segmented control next to the
tabs), off by default (calm‑by‑default rule).

---

## 5. Layout / interaction options considered

**Option A — Domain = tabs, workflow/renderer unchanged (RECOMMENDED).**
Add a `domain` state + a tab bar above the existing toolbar. LAN renders the
current `CanvasInner` with no filter (identical to today); DC/SD‑WAN render
`CanvasInner` with a domain filter; Cloud renders the dedicated
`CloudTopologyView`. Carrier is an overlay flag threaded into whichever view is
active.
*Pros:* strictly additive; default unchanged; each tab is its own coherent
graph; reuses ELK + adapter + edges; provider‑parametric. *Cons:* two selectors
(domain + workflow) — mitigated by placing domain as the primary, left‑most
control (the "where"), workflow as the secondary ("what task").

**Option B — Fold cloud into the existing renderer toggle (Canvas / Overview /
Geo / Cloud).** *Rejected:* conflates *renderer* (how it's drawn) with *domain*
(what's drawn); doesn't give LAN/SD‑WAN/DC a home; and the owner asked for
network‑type tabs, not a renderer.

**Option C — One merged multi‑domain graph with cloud as a super‑group.**
*Rejected outright:* this is the "one giant hairball" the owner explicitly ruled
out, and it buries the cloud seam in the on‑prem fabric.

**Recommendation: Option A.** It is the only option that satisfies *additive +
default‑unchanged + one‑coherent‑graph‑per‑tab + carrier‑as‑cross‑cutting* at
once, and it fits the skill's "calm operating canvas, clean adapter boundaries"
conventions.

---

## 6. Interaction details (fits existing conventions)

- **Default:** LAN tab, carrier off, workflow = Explore, density = Operator —
  byte‑for‑byte the current canvas.
- **Cloud tab:** opens on the cloud‑grouped layout, fit‑to‑view, calm (health
  overlay). Click a resource → the existing side drawer (evidence, CIDR,
  provider, route facts). Collapse a VPC → the existing group collapse.
- **Empty states:** DC/SD‑WAN with no matching nodes show the canvas's existing
  honest "nothing to display for this domain" card — never a fabricated graph
  (memory: *done means rendered; never overclaim*).
- **Provider‑neutral customer copy:** tabs and chips use generic terms
  (VPC/VNet, Subnet, Gateway); the *only* place a provider name surfaces is the
  official mark itself, which is permitted (it marks the provider's own
  resource).

---

## 7. Explicitly excluded — and why

- **Cloud application workloads** (EC2/VM instances as apps, K8s services,
  containers, RDS/DB engines, functions): out of scope by owner direction. This
  is a **network** topology (VPC/subnet/gateway/route), not an app map. The
  existing app‑dependency view (`cloudTopology.ts`, the Dependency workflow)
  already covers workload dependencies; we do not duplicate or merge it here.
- **Per‑workload health / cost / right‑sizing:** belongs to the app/DEM lanes,
  not the network canvas.
- **Live provider auth / discovery UI:** the pollers already exist (#105); this
  work renders their output, it doesn't re‑implement ingestion.

---

## 8. From POC to production — implementation plan

The POC renders from the mock `cloudNetworkTopology` (grounded in the real
`aws-topology.json` ids) with a documented seam to swap in a live endpoint.

**P1 — Backend endpoint (`GET /api/topology/cloud`).** Add
`handleTopologyCloud` in `main.go` that calls `cloud.LoadTopologies(dir)` and
maps each `Topology` → a `TopologyView` (region/VPC groups, subnet/gateway/NVA
nodes, route‑egress edges), **tenant‑scoped** like the other topology routes
(`route_isolation_test.go` marks `/api/topology/*` as `scoped`; the cloud route
MUST be too — one VPC set per tenant, cross‑tenant → 404, ship the org‑isolation
test). Wire `api/topologyApi.ts:fetchCloudTopology()` to it with the same
graceful‑degradation → mock fallback the other fetchers use.

**P2 — Cloud resource telemetry join.** Join the #105 gateway‑plane metrics onto
cloud nodes so `health` is real (currently `unknown`). Same enrichment path the
persistent graph uses.

**P3 — DX / TGW / peering discovery.** Extend `discover.py` /
`cloud-discover-azure.py` (+ `cloud/topology.go` structs) to emit Direct
Connect / ExpressRoute / Interconnect, Transit Gateway / vHub / Cloud Router and
VPC/VNet peering as first‑class resources; the taxonomy roles are already
reserved, so only the mapper grows.

**P4 — Real domain projections for SD‑WAN / DC.** Replace the client‑side domain
filter with a backend `?domain=` parameter on `/api/topology/view` that projects
the WAN‑edge (+ tunnels store) and DC‑fabric slices server‑side.

**P5 — GCP mark.** DONE, then SUPERSEDED by licence audit D5 (2026-09-04):
every provider now renders the original tagged cloud glyph, so there is no
monogram fallback and no vendored official icon left to add.

**P6 — Dedicated tunnel/seam edge component** (double‑stroke) for hybrid seams,
if the reused `InferredEdge` proves too subtle in the field.

---

## 9. Files (POC)

New:
- `docs/design/topology-cloud-tabs.md` (this doc)
- `src/frontend/src/features/topology/components/ProviderMark.tsx`
- `src/frontend/src/features/topology/components/TopologyDomainTabs.tsx`
- `src/frontend/src/features/topology/renderers/react-flow/nodes/CloudResourceNode.tsx`
- `src/frontend/src/features/topology/renderers/react-flow/CloudTopologyView.tsx`
- `src/frontend/src/features/topology/mock/cloudNetworkTopology.ts`
- `src/frontend/src/features/topology/utils/carrierOverlay.ts`
- `src/frontend/src/features/topology/utils/topologyDomains.ts`
- tests alongside each (`*.test.ts[x]`)

Modified (additive):
- `renderers/react-flow/TopologyCanvas.tsx` — domain state + tab bar wrapper
- `renderers/react-flow/nodes/index.ts` — export `CloudResourceNode`
- `api/topologyTypes.ts` — add `subnet` to `GroupType` (label only)
- `styles.css` — `.topo-domain-tabs` styling
</content>
</invoke>
