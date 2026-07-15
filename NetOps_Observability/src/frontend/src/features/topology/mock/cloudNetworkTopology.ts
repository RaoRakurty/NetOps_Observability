// cloudNetworkTopology.ts — mock TopologyView for the CLOUD NETWORK tab.
//
// This is the cloud *network* topology (VPCs/VNets → subnets → gateways/NVAs →
// route-egress + hybrid seams + transit) — NOT the app-dependency view
// (cloudTopology.ts) and deliberately WITHOUT any workloads (owner scope).
//
// GROUNDED in the real discovery fixture deployment/docker/cloud-fixtures/
// aws-topology.json (VPC/subnet ids + CIDRs + route-table egress rows) so the
// shape matches what src/backend/cloud/topology.go actually loads. The Azure
// VNet + the Transit Gateway / ExpressRoute nodes are ILLUSTRATIVE of the
// taxonomy (§2.3 of docs/design/topology-cloud-tabs.md) — the discovery pollers
// don't emit DX/TGW/peering yet; they are marked as such in each node's tags.
//
// FLAT canonical contract (api/topologyTypes.ts). layout_type "cloud_grouped".

import type { TopologyView, TopologyNode, TopologyEdge, Health } from "../api/topologyTypes";

const NOW = "2026-07-15T00:00:00Z";
const SEEN = "2026-01-01T00:00:00Z";

/** Compact cloud-resource node factory. Health defaults to `unknown` (honest:
 *  discovered via cloud API, not yet health-monitored — see design §2.3). */
function cloudNode(
  id: string,
  label: string,
  provider: string,
  role: string,
  vpc: string,
  extraTags: Record<string, string> = {},
  health: Health = "unknown",
  issues?: TopologyNode["issues"],
): TopologyNode {
  return {
    id,
    label,
    kind: "cloud",
    role,
    site: provider,
    zone: vpc,
    group_id: vpc,
    health,
    confidence: 0.95,
    resolved: true,
    first_seen: SEEN,
    last_seen: NOW,
    change_state: "unchanged",
    metrics: { link_count: 1, alert_count: issues?.length ?? 0 },
    evidence: [
      {
        source: "cloud_api",
        confidence: 0.95,
        detail: `${provider} ${role} ${id}`,
        observed_at: NOW,
        raw_ref: `cloud_api:${provider}:${role}:${id}`,
        summary: `Cloud API ${role} ${label}`,
      },
    ],
    ...(issues ? { issues } : {}),
    tags: { provider, role, ...extraTags },
  };
}

/** Route-egress edge: subnet --destination--> next hop. A control-plane FACT
 *  (route table), NOT observed traffic — routed_adjacency at moderate confidence
 *  (mirrors cloud/topology.go's honesty note). */
function routeEdge(source: string, target: string, destination: string, provider: string): TopologyEdge {
  return {
    id: `route-${source}-${target}-${destination}`.replace(/[./]/g, "_"),
    source,
    target,
    relationship: "routed_adjacency",
    protocol: "cloud_api",
    status: "up",
    confidence: 0.7,
    direction: "uni",
    first_seen: SEEN,
    last_seen: NOW,
    change_state: "unchanged",
    evidence: [
      {
        source: "cloud_api",
        confidence: 0.7,
        detail: `route ${destination} → ${target}`,
        observed_at: NOW,
        raw_ref: `cloud_api:${provider}:route:${source}:${destination}`,
        summary: `route table: ${source} sends ${destination} to ${target}`,
      },
    ],
    // The destination CIDR is the single most useful fact on a route — shown as
    // the edge label (see the drawer/edge label renderer). Carried in metrics.
    bandwidth_mbps: undefined,
    errors: 0,
    // stash the human destination on the edge for the label via source_port slot
    source_port: destination,
  };
}

/** Logical hybrid seam (VGW/DX → transit/carrier). Dashed (inferred) — a logical
 *  link, not a wire. */
function seamEdge(source: string, target: string, label: string, provider: string): TopologyEdge {
  return {
    id: `seam-${source}-${target}`,
    source,
    target,
    relationship: "inferred",
    protocol: "cloud_api",
    status: "up",
    confidence: 0.6,
    direction: "bi",
    first_seen: SEEN,
    last_seen: NOW,
    change_state: "unchanged",
    source_port: label,
    evidence: [
      {
        source: "cloud_api",
        confidence: 0.6,
        detail: `${label} seam ${source} ↔ ${target}`,
        observed_at: NOW,
        raw_ref: `cloud_api:${provider}:seam:${source}:${target}`,
        summary: `hybrid seam (${label}): ${source} ↔ ${target}`,
      },
    ],
  };
}

// ── AWS: region us-west-2, VPC correlix-prod (10.60.0.0/16) — from fixture ────
const AWS = "aws";
const VPC_PROD = "vpc-04bea9c06ff23abd9";
const VPC_SHARED = "vpc-067f878070db7c05a";

const awsProdNodes: TopologyNode[] = [
  cloudNode("subnet-01f8d07890ee79e9c", "Subnet · correlix-app-a", AWS, "subnet", VPC_PROD, { cidr: "10.60.10.0/24", az: "us-west-2a" }),
  cloudNode("subnet-0651f2da157e5b5d3", "Subnet · correlix-data-a", AWS, "subnet", VPC_PROD, { cidr: "10.60.30.0/24", az: "us-west-2b" }),
  cloudNode("subnet-0f546d11625f4baa3", "Subnet · correlix-public-a", AWS, "subnet", VPC_PROD, { cidr: "10.60.1.0/27", az: "us-west-2a" }),
  cloudNode("correlix-igw", "IGW · correlix-igw", AWS, "igw", VPC_PROD, {}),
  cloudNode(
    "i-0e8acbf8493d037f9",
    "NVA · correlix-vpn-nat-01",
    AWS,
    "nva",
    VPC_PROD,
    { private_ip: "10.60.1.10", function: "vpn+nat firewall appliance" },
    "warning",
    [{ severity: "warning", summary: "tunnel bounce observed in the last hour", since: NOW }],
  ),
  cloudNode("vpce-07461b8e31b854def", "Endpoint · S3 gateway", AWS, "endpoint", VPC_PROD, { service: "com.amazonaws.us-west-2.s3" }),
];

const awsProdEdges: TopologyEdge[] = [
  routeEdge("subnet-01f8d07890ee79e9c", "i-0e8acbf8493d037f9", "0.0.0.0/0", AWS),
  routeEdge("subnet-01f8d07890ee79e9c", "i-0e8acbf8493d037f9", "10.70.245.0/24", AWS),
  routeEdge("subnet-01f8d07890ee79e9c", "i-0e8acbf8493d037f9", "172.40.40.0/24", AWS),
  routeEdge("subnet-01f8d07890ee79e9c", "vpce-07461b8e31b854def", "pl-68a54001", AWS),
  routeEdge("subnet-0651f2da157e5b5d3", "i-0e8acbf8493d037f9", "0.0.0.0/0", AWS),
  routeEdge("subnet-0651f2da157e5b5d3", "vpce-07461b8e31b854def", "pl-68a54001", AWS),
  routeEdge("subnet-0f546d11625f4baa3", "correlix-igw", "0.0.0.0/0", AWS),
];

// AWS shared-services VPC (172.31.0.0/16) + a Transit Gateway attaching both.
// ILLUSTRATIVE: the pollers don't emit TGW yet (design §2.3).
const awsSharedNodes: TopologyNode[] = [
  cloudNode("subnet-0dacf6578cc3c4f09", "Subnet · shared-a", AWS, "subnet", VPC_SHARED, { cidr: "172.31.0.0/20" }),
  cloudNode("igw-015c28717e1ac8cfd", "IGW · shared-igw", AWS, "igw", VPC_SHARED, {}),
  cloudNode("tgw-0aa11bb22cc33dd44", "Transit GW · core-tgw", AWS, "tgw", VPC_SHARED, { illustrative: "true" }),
];
const awsSharedEdges: TopologyEdge[] = [
  routeEdge("subnet-0dacf6578cc3c4f09", "igw-015c28717e1ac8cfd", "0.0.0.0/0", AWS),
  seamEdge("i-0e8acbf8493d037f9", "tgw-0aa11bb22cc33dd44", "TGW attach", AWS),
  seamEdge("igw-015c28717e1ac8cfd", "tgw-0aa11bb22cc33dd44", "TGW attach", AWS),
];

// ── Azure: region westeurope, VNet vnet-prod (10.30.0.0/16). ILLUSTRATIVE of
//    provider-parametric rendering (VNet-GW + ExpressRoute). ─────────────────
const AZ = "azure";
const VNET_PROD = "vnet-prod-weu";
const azureNodes: TopologyNode[] = [
  cloudNode("snet-app-weu", "Subnet · snet-app", AZ, "subnet", VNET_PROD, { cidr: "10.30.1.0/24" }),
  cloudNode("vgw-prod-weu", "VNet GW · vgw-prod", AZ, "vgw", VNET_PROD, {}),
  cloudNode("nva-az-fw01", "NVA · az-fw01", AZ, "nva", VNET_PROD, { function: "Azure Firewall" }),
  cloudNode("er-weu-01", "ExpressRoute · er-weu", AZ, "dx", VNET_PROD, { illustrative: "true", circuit: "westeurope" }),
];
const azureEdges: TopologyEdge[] = [
  routeEdge("snet-app-weu", "nva-az-fw01", "0.0.0.0/0", AZ),
  routeEdge("snet-app-weu", "vgw-prod-weu", "10.0.0.0/8", AZ),
  seamEdge("vgw-prod-weu", "er-weu-01", "ExpressRoute", AZ),
];

export const cloudNetworkTopology: TopologyView = {
  view_id: "view-cloud-network-001",
  topology_id: "topo-cloud-network",
  mode: "explore",
  scope: { tenant_id: "tenant-acme" },
  generated_at: NOW,
  layout_type: "cloud_grouped",
  nodes: [...awsProdNodes, ...awsSharedNodes, ...azureNodes],
  edges: [...awsProdEdges, ...awsSharedEdges, ...azureEdges],
  groups: [
    {
      id: VPC_PROD,
      label: "VPC · correlix-prod · 10.60.0.0/16",
      group_type: "vpc",
      children: awsProdNodes.map((n) => n.id),
      health: "warning",
      collapsed: false,
      owner: "cloudops",
    },
    {
      id: VPC_SHARED,
      label: "VPC · shared-svcs · 172.31.0.0/16",
      group_type: "vpc",
      children: awsSharedNodes.map((n) => n.id),
      health: "unknown",
      collapsed: false,
      owner: "cloudops",
    },
    {
      id: VNET_PROD,
      label: "VNet · vnet-prod · 10.30.0.0/16",
      group_type: "vpc",
      children: azureNodes.map((n) => n.id),
      health: "unknown",
      collapsed: false,
      owner: "cloudops",
    },
  ],
  overlays: ["health"],
  legend: {},
  renderer_hints: { preferred: "react_flow", max_detail_level: 3 },
};
