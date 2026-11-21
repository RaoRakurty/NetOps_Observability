// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// siteName — how a node's or a group's site READS. The backend groups devices
// by ONE rule (operator binding → discovery site label → the site id the device
// or its controller reports); `node.site` is the grouping KEY, which for a
// discovered site is a tenant-qualified "discovered:…" string nobody should
// read. `site_label` carries the readable name ("Site 50 · from vManage").

import type { TopologyGroup, TopologyNode } from "../api/topologyTypes";

/** The readable site of a node ("" when it has none). */
export function siteName(n: Pick<TopologyNode, "site" | "site_label">): string {
  return n.site_label || n.site || "";
}

/** True when the node's site is DISCOVERED (a reported site id, not declared). */
export function isDiscoveredSite(n: Pick<TopologyNode, "site_source">): boolean {
  return n.site_source === "discovered";
}

/** True for a site group that is a virtual grouping by a reported site id. */
export function isDiscoveredGroup(g: Pick<TopologyGroup, "group_type" | "source">): boolean {
  return g.group_type === "site" && g.source === "discovered";
}

/** One line on how a node's site was decided, for the inspector. */
export function siteProvenance(n: Pick<TopologyNode, "site_source">): string {
  switch (n.site_source) {
    case "manual": return "placed by an operator";
    case "label": return "from the device's site label";
    case "discovered": return "discovered — adopt it in Sites to make it a real site";
    default: return "";
  }
}
