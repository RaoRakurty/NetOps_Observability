// topologyDomains.ts — the NETWORK-DOMAIN model for the topology tabs.
//
// Domains are a dimension ORTHOGONAL to the workflow selector: workflow = "what
// task" (explore/investigate/trace); domain = "which network am I looking at"
// (LAN / SD-WAN / DC / Cloud). See docs/design/topology-cloud-tabs.md.
//
// ONE CANVAS, FOUR FILTERS (#131). The default is the whole discovered estate —
// the on-prem fabric with the cloud projection merged onto the SAME canvas — and
// SD-WAN / DC / Cloud are client-side slices of it. Cloud used to be a separate
// page with its own renderer; it is a filter now, because cloud↔on-prem
// troubleshooting needs both ends on one canvas and a separate page can never
// provide that.

import type { TopologyView, TopologyNode } from "../api/topologyTypes";

export type NetworkDomain = "lan" | "sdwan" | "dc" | "cloud";

export type DomainMeta = {
  id: NetworkDomain;
  label: string;
  blurb: string;
};

export const DOMAINS: DomainMeta[] = [
  // The id stays "lan" (links, saved layouts and the route serialization carry
  // it); the LABEL is honest about what the unfiltered canvas now holds.
  { id: "lan", label: "All networks", blurb: "The whole discovered estate on one canvas — on-prem fabric plus the projected cloud network. The other options filter this same canvas." },
  { id: "sdwan", label: "SD-WAN", blurb: "WAN edge: SD-WAN gateways, tunnels/overlays and transport." },
  { id: "dc", label: "DC", blurb: "Data-center fabric: spine/leaf, ToR, compute/storage rows." },
  { id: "cloud", label: "Cloud", blurb: "Cloud network: VPCs/VNets, subnets, gateways, NVAs, seams." },
];

const SDWAN_RE = /(wan|sd-?wan|vpn|tunnel|overlay|dmvpn|mpls|transport|gateway|edge|uplink|carrier)/i;
const DC_RE = /(spine|leaf|tor|fabric|pod|dc[-_ ]|datacenter|data-?center|server|host|storage|compute|aggreg|distribution)/i;

function hay(n: TopologyNode): string {
  return `${n.role ?? ""} ${n.kind} ${n.tags?.role ?? ""} ${n.tags?.tier ?? ""} ${n.label}`.toLowerCase();
}

/**
 * Is this node a CLOUD entity? Answered from FACTS the discovery returned — the
 * node kind, and the provider / region / vpc fields the cloud projection stamps
 * on every resource (#131d) — never from its name.
 *
 * This is deliberately NOT a regex over the label. The regexes below are a
 * best-effort classifier for on-prem roles that carry no better signal, and they
 * are the weakest thing in this file: a cloud gateway's role ("vpn_gateway",
 * "transit_gateway") matches the SD-WAN pattern, so a name-based rule would
 * scatter one VPC's gateways across two domains. A VPC is not a naming
 * convention; it is a field.
 */
export function isCloudNode(n: TopologyNode): boolean {
  if (n.kind === "cloud") return true;
  const t = n.tags;
  if (!t) return false;
  return !!(t.provider || t.vpc || t.region);
}

/** Which domain does a node belong to (best-effort classifier). LAN is the
 *  catch-all so a node is never dropped. */
export function domainOfNode(n: TopologyNode): NetworkDomain {
  // Cloud is decided by fact and decided FIRST — a cloud transit/VPN gateway
  // would otherwise match the SD-WAN pattern on its role.
  if (isCloudNode(n)) return "cloud";
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
  if (isCloudNode(n)) return "Cloud";
  if (n.kind === "wan" || ISP_RE.test(h)) return "ISP";
  const d = domainOfNode(n);
  if (d === "cloud") return "Cloud";
  if (d === "sdwan") return "WAN (SD-WAN)";
  if (d === "dc") return "Data Center";
  return "LAN"; // wireless + wired access = LAN (settled vocabulary)
}

/**
 * Filter a fabric view to one domain. LAN returns the view UNCHANGED (it is the
 * whole estate — the identity path, so the default canvas is untouched); SD-WAN,
 * DC and Cloud are slices of that same canvas. Edges are kept only when BOTH
 * endpoints survive.
 *
 * GROUPS ARE PRUNED BY DESCENDANT, not by direct child. A region declares no node
 * children — its members are VPC groups nested via `parent_id` — so dropping
 * "groups with no surviving children" deleted every region boundary from the
 * cloud slice, the same defect #134 fixed in the renderer. A container survives
 * when anything below it does.
 */
export function filterViewByDomain(view: TopologyView, domain: NetworkDomain): TopologyView {
  if (domain === "lan") return view;
  const keep = new Set(view.nodes.filter((n) => domainOfNode(n) === domain).map((n) => n.id));
  const nodes = view.nodes.filter((n) => keep.has(n.id));
  const edges = view.edges.filter((e) => keep.has(e.source) && keep.has(e.target));

  // Which groups keep at least one node, then propagate upward through parent_id.
  const byId = new Map(view.groups.map((g) => [g.id, g]));
  const survives = new Set<string>();
  for (const g of view.groups) if (g.children.some((c) => keep.has(c))) survives.add(g.id);
  for (const id of [...survives]) {
    let parent = byId.get(id)?.parent_id;
    let depth = 0;
    while (parent && depth < 8 && !survives.has(parent)) {
      survives.add(parent);
      parent = byId.get(parent)?.parent_id;
      depth++;
    }
  }
  const groups = view.groups
    .filter((g) => survives.has(g.id))
    .map((g) => ({ ...g, children: g.children.filter((c) => keep.has(c)) }));
  return { ...view, nodes, edges, groups };
}
