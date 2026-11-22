// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// protocolsModel — the pure rules behind Analytics › Protocol Monitoring.
//
// One leaf, three tabs (BGP · OSPF · IS-IS). It replaced two leaves that asked
// the same question twice: "Protocol Monitoring" drew BGP session charts, and
// "BGP Operations" listed the same sessions down or flapping beside the
// internet-facing prefix checks (owner, 2026-11-22: "lots of verbose … make it
// more elegant and useful"). Each tab now leads with what is broken.

import type { CorrObject, Device, IgpAdjacency } from "../../services/api";
import { parseAffected, isActionableCorr } from "../commandCenter.model";
import { friendlyProblemId, signatureNocTitle } from "../../components/rca/labels";

export type ProtocolTab = "bgp" | "ospf" | "isis";

export const PROTOCOL_TABS: readonly { id: ProtocolTab; label: string }[] = [
  { id: "bgp", label: "BGP" },
  { id: "ospf", label: "OSPF" },
  { id: "isis", label: "IS-IS" },
];

/** The leaf's route; a tab is the third segment. */
export const PROTOCOLS_ROUTE = "analytics/protocols";

export function tabFromHash(hash: string): ProtocolTab {
  const path = hash.replace(/^#\/?/, "").split("?")[0];
  const seg = path.split("/")[2] ?? "";
  return PROTOCOL_TABS.some((t) => t.id === seg) ? (seg as ProtocolTab) : "bgp";
}

export function tabHash(tab: ProtocolTab): string {
  return `#/${PROTOCOLS_ROUTE}/${tab}`;
}

// ── devices ────────────────────────────────────────────────────────────────

export type DeviceIndex = {
  /** id, name or a unique address → the device id */
  idOf: (key: string) => string | undefined;
  /** device id → display name (the id when the device has none) */
  nameOf: (id: string) => string;
  /** device id → site, "" when unknown */
  siteOf: (id: string) => string;
};

/** A lookup over the caller's own inventory. An address two devices share
 *  resolves to neither — it names nobody. */
export function deviceIndex(devices: readonly Device[]): DeviceIndex {
  const byKey = new Map<string, string>();
  const addrCount = new Map<string, number>();
  for (const d of devices) {
    const a = (d.address || "").trim();
    if (a) addrCount.set(a, (addrCount.get(a) ?? 0) + 1);
  }
  const names = new Map<string, string>();
  const sites = new Map<string, string>();
  for (const d of devices) {
    if (!d.id) continue;
    byKey.set(d.id, d.id);
    const n = (d.name || "").trim();
    names.set(d.id, n || d.id);
    if (n && !byKey.has(n)) byKey.set(n, d.id);
    const a = (d.address || "").trim();
    if (a && addrCount.get(a) === 1) byKey.set(a, d.id);
    const site = (d.labels?.site || d.labels?.location || "").trim();
    if (site) sites.set(d.id, site);
  }
  return {
    idOf: (k) => byKey.get(k.trim()),
    nameOf: (id) => names.get(id) ?? id,
    siteOf: (id) => sites.get(id) ?? "",
  };
}

// ── open problems by device ────────────────────────────────────────────────

/** id: the correlation id; handle: the P-… handle; title: the cause in NOC words. */
export type ProblemRef = { id: string; handle: string; title: string };

/** The device part of an engine entity key: `edge-1:Gi1` → edge-1,
 *  `10.0.0.1:if3` → 10.0.0.1. An IPv6 address is kept whole. */
function devicePart(key: string): string {
  const t = key.trim();
  const colons = (t.match(/:/g) ?? []).length;
  return colons > 1 ? t : t.split(":")[0];
}

/** Every open, actionable problem keyed by each inventory device it touches.
 *  The newest problem wins a device (the list arrives newest first). */
export function problemsByDevice(corrs: readonly CorrObject[], idx: DeviceIndex): Map<string, ProblemRef> {
  const out = new Map<string, ProblemRef>();
  for (const c of corrs) {
    if (!isActionableCorr(c)) continue;
    const a = parseAffected(c.affected);
    const keys = [
      ...a.devices,
      ...a.paths.flatMap((p) => p.split(/->|→/)),
      ...a.interfaces.map(devicePart),
    ];
    for (const k of keys) {
      const id = idx.idOf(k);
      if (id && !out.has(id)) {
        out.set(id, {
          id: c.correlation_id,
          handle: friendlyProblemId(c.correlation_id),
          title: c.top_hypothesis ? signatureNocTitle(c.top_hypothesis) : "Open problem",
        });
      }
    }
  }
  return out;
}

// ── what needs attention ───────────────────────────────────────────────────

/** True when an adjacency is down now (live), or flapped in the window, or
 *  its newest reported change was a down. Steady and up is not shown first. */
export function needsAttention(a: IgpAdjacency): boolean {
  if (a.state_source === "live_series" && a.up === false) return true;
  if (a.flaps > 0) return true;
  if (a.state_source === "events" && a.timeline[0]?.state === "down") return true;
  return false;
}

/** Why an adjacency is listed, in two or three words. */
export function attentionReason(a: IgpAdjacency): string {
  if (a.state_source === "live_series" && a.up === false) return "Down now";
  if (a.state_source === "events" && a.timeline[0]?.state === "down") return "Last reported down";
  return a.flaps === 1 ? "Flapped once" : `Flapped ${a.flaps}×`;
}
