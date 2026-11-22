// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// incidentsModel.ts — Operations → Incidents as a pure presenter (the Logs
// redesign pattern, owner 2026-11-22). Every rule here is unit-tested.
//
// What an incident IS here, stated so the page never implies otherwise: an
// owned, tracked record — minted by a firing alert rule, opened by a person, or
// promoted from Digital Experience. It is NOT a promoted correlated problem
// (those are on Operations → Problems; the two lanes share no id).
//
//   • source tabs and status tiles narrow the LOADED page, and say so;
//   • the list endpoint's envelope gives the true total, so a page that is not
//     the whole set says "Showing a–b of N";
//   • owner is a column, "Unassigned" when nobody has it.

import type { Incident } from "../services/api";
import type { DevicePlaces } from "../lib/deviceNames";

/** WHERE an incident is (tracker 438): the firing device by its inventory name
 *  and its site. `id` is the raw device id, shown beside the name when they
 *  differ. A device the caller's inventory does not hold keeps its id; an
 *  incident with no device (stack, Digital Experience, a person) is empty. */
export type IncidentWhere = { device: string; site: string; id: string };

export function incidentWhere(i: Pick<Incident, "device_id">, places: DevicePlaces | null): IncidentWhere {
  const id = (i.device_id || "").trim();
  if (!id) return { device: "", site: "", id: "" };
  const p = places?.get(id);
  return { device: p?.name || id, site: p?.site || "", id };
}

/** One line for search and sorting: "edge-a · HQ", "edge-a", or "". */
export function whereText(w: IncidentWhere): string {
  return [w.device, w.site].filter(Boolean).join(" · ");
}

export type IncidentSourceTab = "all" | "alert" | "logs" | "manual" | "experience";

export const INCIDENT_SOURCE_TABS: { id: IncidentSourceTab; label: string }[] = [
  { id: "all", label: "All" },
  { id: "alert", label: "From alerts" },
  { id: "logs", label: "From logs and anomalies" },
  { id: "manual", label: "Opened by people" },
  { id: "experience", label: "Digital Experience" },
];

export function inSourceTab(i: Incident, tab: IncidentSourceTab): boolean {
  const s = (i.source_type || "manual").toLowerCase();
  switch (tab) {
    case "all": return true;
    case "alert": return s === "alert";
    case "logs": return s === "log" || s === "anomaly";
    case "manual": return s === "manual";
    case "experience": return s === "experience";
  }
}

export type IncidentStatusTile = "open" | "acknowledged" | "investigating" | "resolved" | "closed";

export const INCIDENT_STATUS_TILES: { id: IncidentStatusTile; label: string; tone: string }[] = [
  { id: "open", label: "Open", tone: "var(--warn)" },
  { id: "acknowledged", label: "Acknowledged", tone: "var(--accent)" },
  { id: "investigating", label: "Investigating", tone: "var(--accent)" },
  { id: "resolved", label: "Resolved", tone: "var(--ok)" },
  { id: "closed", label: "Closed", tone: "var(--fg-subtle)" },
];

export const statusText = (s: string): string => {
  const t = INCIDENT_STATUS_TILES.find((x) => x.id === (s || "").toLowerCase());
  return t ? t.label : s || "—";
};

export const isActiveIncident = (i: Incident): boolean =>
  i.status === "open" || i.status === "acknowledged" || i.status === "investigating";

export const ownerText = (i: Incident): string => (i.owner && i.owner.trim()) || "Unassigned";

export type IncidentFilters = {
  q?: string;
  status?: IncidentStatusTile;
  severity?: string;
  unassigned?: boolean;
};

export function filterIncidents(items: readonly Incident[], tab: IncidentSourceTab, f: IncidentFilters, places: DevicePlaces | null = null): Incident[] {
  const needle = (f.q ?? "").trim().toLowerCase();
  return items.filter((i) => {
    if (!inSourceTab(i, tab)) return false;
    if (f.status && i.status !== f.status) return false;
    if (f.severity && i.severity !== f.severity) return false;
    if (f.unassigned && i.owner && i.owner.trim()) return false;
    if (needle) {
      const w = incidentWhere(i, places);
      const hay = `${i.title} ${i.description ?? ""} ${i.owner ?? ""} ${i.external_ticket_id ?? ""} ${whereText(w)} ${w.id}`;
      if (!hay.toLowerCase().includes(needle)) return false;
    }
    return true;
  });
}

/** Status tile counts over the loaded rows of the current source tab. */
export function statusCounts(items: readonly Incident[], tab: IncidentSourceTab): Record<IncidentStatusTile, number> {
  const out: Record<IncidentStatusTile, number> = { open: 0, acknowledged: 0, investigating: 0, resolved: 0, closed: 0 };
  for (const i of items) {
    if (!inSourceTab(i, tab)) continue;
    const s = (i.status || "").toLowerCase() as IncidentStatusTile;
    if (s in out) out[s] += 1;
  }
  return out;
}

/** The sentence under the tiles: what they counted. */
export function countsNote(loaded: number, total: number): string {
  return loaded < total
    ? `Counted in the ${loaded.toLocaleString()} loaded incidents of ${total.toLocaleString()}.`
    : `Counted across all ${loaded.toLocaleString()} incident${loaded === 1 ? "" : "s"}.`;
}

/** "Showing 1–200 of 1,437 incidents", or "" when the page is the whole set. */
export function pageNote(offset: number, returned: number, total: number): string {
  if (offset === 0 && returned >= total) return "";
  if (returned === 0) return `No incidents on this page of ${total.toLocaleString()}.`;
  return `Showing ${(offset + 1).toLocaleString()}–${(offset + returned).toLocaleString()} of ${total.toLocaleString()} incidents.`;
}

export const activeIncidentFilterCount = (f: IncidentFilters): number =>
  [f.q?.trim(), f.status, f.severity, f.unassigned].filter(Boolean).length;
