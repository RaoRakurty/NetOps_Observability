// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// carrierOverlay.ts — the cross-cutting CARRIER / PROVIDER-network overlay.
//
// A carrier network is the thing that ties LAN, SD-WAN, DC and Cloud together,
// so rather than a fifth merged graph it is an OVERLAY add-able to ANY tab: it
// finds the active view's egress points (WAN/edge routers on-prem; VGW/DX/IGW in
// cloud) and draws uplinks to ONE shared carrier node. Flip between tabs and the
// same carrier reads as the interconnection fabric, in-context.
//
// Pure + idempotent + non-mutating: returns a NEW view; re-applying is a no-op.
// Every injected edge carries evidence (the "never draw a link without evidence"
// rule holds).

import type { TopologyView, TopologyNode, TopologyEdge } from "../api/topologyTypes";

export const CARRIER_NODE_ID = "carrier-cloud";

/**
 * Cloud egress roles matched EXACTLY against the discovered vocabulary the
 * backend emits (`gatewayKinds` in cloud/topology_view.go).
 *
 * These used to be caught only by the substring regex below, and it missed the
 * single most important one: `"vpn_gateway"` does not contain `"vpn_gw"`, so an
 * AWS Site-to-Site VPN gateway or an Azure VirtualNetworkGateway — the ordinary
 * way a cloud is joined to anything else — was NOT an egress point. The Carrier
 * overlay would have stayed empty on the exact topology it exists to draw.
 * `nat_gateway`, `carrier_gateway` and `local_gateway` (Outposts) were missing
 * for the same reason. An exact role match cannot drift like that.
 *
 * Deliberately NOT here:
 *  - `vpc_peering` — a peering is VPC↔VPC inside one provider, not transport to
 *    a carrier; drawing it as an uplink would overstate what it is.
 *  - `nva` — a network virtual appliance is a WORKLOAD that may or may not
 *    terminate a tunnel, and discovery cannot tell which. Attaching every NAT
 *    box to the carrier cloud would assert a fact we do not have (rule 6: never
 *    draw a link without evidence).
 */
const CLOUD_EGRESS_ROLES = new Set([
  "internet_gateway",
  "nat_gateway",
  "vpn_gateway",
  "transit_gateway",
  "expressroute_gateway",
  "dx",
  "egress_only_igw",
  "carrier_gateway",
  "local_gateway",
]);

/** Roles/kinds that mark a WAN egress boundary by NAMING (on-prem//LAN gear). */
const EGRESS_RE = /(wan|edge|border|uplink|transit|vgw|vpn[-_]?gw|dx|expressroute|interconnect|igw|internet)/i;

function isEgress(n: TopologyNode): boolean {
  if (n.kind === "wan") return true;
  const role = (n.role ?? n.tags?.role ?? "").toLowerCase();
  if (CLOUD_EGRESS_ROLES.has(role)) return true;
  const hay = `${n.role ?? ""} ${n.tags?.role ?? ""} ${n.kind}`;
  return EGRESS_RE.test(hay);
}

export type CarrierOptions = {
  /** Display label for the carrier cloud. Provider-neutral by design. */
  label?: string;
  /** Cap how many uplinks to draw (calm-by-default). Default 12. */
  maxUplinks?: number;
};

/**
 * Return a NEW view with a single carrier node + uplink edges from each egress
 * point. If the view already has the carrier node (already applied, or none
 * found), the input view is returned unchanged.
 */
export function withCarrierOverlay(view: TopologyView, opts: CarrierOptions = {}): TopologyView {
  if (view.nodes.some((n) => n.id === CARRIER_NODE_ID)) return view; // idempotent
  const egress = view.nodes.filter(isEgress).slice(0, opts.maxUplinks ?? 12);
  if (egress.length === 0) return view; // nothing to attach → no-op (honest)

  const now = view.generated_at || new Date().toISOString();
  const carrier: TopologyNode = {
    id: CARRIER_NODE_ID,
    label: opts.label ?? "Carrier / Transport",
    kind: "wan",
    role: "carrier",
    health: "unknown",
    confidence: 0.8,
    resolved: true,
    first_seen: now,
    last_seen: now,
    change_state: "unchanged",
    metrics: { link_count: egress.length, alert_count: 0 },
    evidence: [
      {
        source: "cloud_api",
        confidence: 0.8,
        detail: "shared carrier / provider transport network",
        observed_at: now,
        raw_ref: "overlay:carrier",
        summary: "carrier overlay: the shared transport that interconnects the domains",
      },
    ],
    tags: { role: "carrier", overlay: "carrier" },
  };

  const uplinks: TopologyEdge[] = egress.map((n) => ({
    id: `carrier-uplink-${n.id}`,
    source: n.id,
    target: CARRIER_NODE_ID,
    relationship: "inferred",
    protocol: "cloud_api",
    status: "up",
    confidence: 0.6,
    direction: "bi",
    first_seen: now,
    last_seen: now,
    change_state: "unchanged",
    source_port: "uplink",
    evidence: [
      {
        source: "cloud_api",
        confidence: 0.6,
        detail: `${n.label} uplinks to the carrier`,
        observed_at: now,
        raw_ref: `overlay:carrier:uplink:${n.id}`,
        summary: `carrier uplink: ${n.label} → carrier`,
      },
    ],
  }));

  return {
    ...view,
    nodes: [...view.nodes, carrier],
    edges: [...view.edges, ...uplinks],
  };
}
