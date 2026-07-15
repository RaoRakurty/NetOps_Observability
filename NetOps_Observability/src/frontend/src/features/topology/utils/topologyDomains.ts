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
