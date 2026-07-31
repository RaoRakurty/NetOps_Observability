// topologyDomains.ts — the NETWORK-DOMAIN model for the topology tabs.
//
// Domains are a dimension ORTHOGONAL to the workflow selector: workflow = "what
// task" (explore/investigate/trace); domain = "which network am I looking at"
// (LAN / SD-WAN / DC / Cloud). See docs/design/topology-cloud-tabs.md.
//
// LAN is the DEFAULT and renders the current fabric view UNFILTERED (unchanged).
// SD-WAN / DC are client-side filtered slices of the fabric until the backend
// serves per-domain projections (?domain=). Cloud has its own renderer + data.

import type { TopologyView, TopologyNode } from "../api/topologyTypes";

export type NetworkDomain = "lan" | "sdwan" | "dc" | "cloud";

export type DomainMeta = {
  id: NetworkDomain;
  label: string;
  blurb: string;
};

export const DOMAINS: DomainMeta[] = [
  { id: "lan", label: "LAN", blurb: "The discovered on-prem campus/access fabric (the current canvas)." },
  { id: "sdwan", label: "SD-WAN", blurb: "WAN edge: SD-WAN gateways, tunnels/overlays and transport." },
  { id: "dc", label: "DC", blurb: "Data-center fabric: spine/leaf, ToR, compute/storage rows." },
  { id: "cloud", label: "Cloud", blurb: "Cloud network: VPCs/VNets, subnets, gateways, NVAs, seams." },
];

const SDWAN_RE = /(wan|sd-?wan|vpn|tunnel|overlay|dmvpn|mpls|transport|gateway|edge|uplink|carrier)/i;
const DC_RE = /(spine|leaf|tor|fabric|pod|dc[-_ ]|datacenter|data-?center|server|host|storage|compute|aggreg|distribution)/i;

function hay(n: TopologyNode): string {
  return `${n.role ?? ""} ${n.kind} ${n.tags?.role ?? ""} ${n.tags?.tier ?? ""} ${n.label}`.toLowerCase();
}

/** Which domain does a node belong to (best-effort classifier). LAN is the
 *  catch-all so a node is never dropped. */
export function domainOfNode(n: TopologyNode): NetworkDomain {
  if (n.kind === "cloud") return "cloud";
  const h = hay(n);
  if (SDWAN_RE.test(h)) return "sdwan";
  if (DC_RE.test(h)) return "dc";
  return "lan";
}

// ── border/zone classification (owner Step 2) ────────────────────────────────
//
// Zones segregate the canvas by OWNERSHIP BORDER, following the canonical seam
// vocabulary (docs/design/cloud-ingestion.md §4.0 — five FINAL seam types; DIA
// displays "ISP"; wireless+wired = LAN): LAN · WAN (SD-WAN) · Data Center ·
// Cloud · ISP · and the deterministic backbone seams (AWS Direct Connect /
// Azure ExpressRoute — both `DX`-class seams, labelled by provider). Best-effort
// classifier over role/kind/label; a node with no signal stays in LAN (the
// catch-all — a device is never dropped), and unresolved boundary nodes return
// "" so the zone lens leaves them ungrouped rather than asserting an owner.

export type NetworkZone =
  | "LAN"
  | "WAN (SD-WAN)"
  | "Data Center"
  | "Cloud"
  | "ISP"
  | "AWS Direct Connect"
  | "Azure ExpressRoute";

const DX_RE = /(direct[-_ ]?connect|(^|[^a-z])dx([^a-z]|$))/i;
const ER_RE = /(express[-_ ]?route|(^|[^a-z])er[-_]{1}[a-z0-9])/i;
const ISP_RE = /(carrier|isp|provider|transit|internet|dia\b|upstream)/i;

/** Zone (ownership border) of a node. "" = unknown owner → stays ungrouped. */
export function zoneOfNode(n: TopologyNode): NetworkZone | "" {
  if (n.kind === "unresolved") return ""; // never assert an owner we can't prove
  const h = hay(n);
  // Deterministic backbone seams first — a DX/ER edge device names its seam.
  if (DX_RE.test(h)) return "AWS Direct Connect";
  if (ER_RE.test(h)) return "Azure ExpressRoute";
  if (n.kind === "cloud") return "Cloud";
  if (n.kind === "wan" || ISP_RE.test(h)) return "ISP";
  const d = domainOfNode(n);
  if (d === "cloud") return "Cloud";
  if (d === "sdwan") return "WAN (SD-WAN)";
  if (d === "dc") return "Data Center";
  return "LAN"; // wireless + wired access = LAN (settled vocabulary)
}

/**
 * Filter a fabric view to one domain. LAN returns the view UNCHANGED (default,
 * additive). Cloud is handled by its own renderer, so this filter is only used
 * for SD-WAN / DC slices. Edges are kept only when BOTH endpoints survive; groups
 * are pruned to surviving children (empty groups dropped).
 */
export function filterViewByDomain(view: TopologyView, domain: NetworkDomain): TopologyView {
  if (domain === "lan") return view;
  const keep = new Set(view.nodes.filter((n) => domainOfNode(n) === domain).map((n) => n.id));
  const nodes = view.nodes.filter((n) => keep.has(n.id));
  const edges = view.edges.filter((e) => keep.has(e.source) && keep.has(e.target));
  const groups = view.groups
    .map((g) => ({ ...g, children: g.children.filter((c) => keep.has(c)) }))
    .filter((g) => g.children.length > 0);
  return { ...view, nodes, edges, groups };
}
