// Overview impact strip (Wave 3 #8 / product-review rev #22) — pure logic that
// turns the window's health signals + live app health + inventory + the service
// catalog into the worst-first "degraded services" rows: name, duration,
// criticality, blast radius. Every number is measured from a live surface; what
// is not measured is honestly absent (duration unknown, extent unknown) — never
// a fabricated 0.

import { parseTs } from "../../lib/time";
import type { BusinessServiceRow } from "../../services/api";
import type { App, CloudResource, HealthSignal } from "./types";
import { catalogByName, criticalityRank, nameKey } from "./catalog";

export interface DegradedServiceRow {
  name: string;
  state: "down" | "degraded";
  criticality: string;     // catalog criticality, "" when the service is not in the catalog
  owner: string;           // catalog owner, else the tag-derived owner, else "—"
  sinceIso: string;        // earliest degraded/down signal in the window ("" = no timestamped signal)
  durationMs: number;      // 0 when sinceIso is "" (duration unknown)
  affected: number;        // distinct resources the signals named (0 = none named)
  total: number;           // inventory resources mapped to the service (0 = unknown)
}

// "2h 15m" — coarse on purpose; an incident duration is not a stopwatch.
export function fmtDuration(ms: number): string {
  if (ms <= 0) return "";
  const m = Math.floor(ms / 60000);
  if (m < 1) return "<1m";
  if (m < 60) return `${m}m`;
  const h = Math.floor(m / 60);
  if (h < 48) return `${h}h${m % 60 ? ` ${m % 60}m` : ""}`;
  const d = Math.floor(h / 24);
  return `${d}d${h % 24 ? ` ${h % 24}h` : ""}`;
}

export function buildDegradedRows(
  apps: App[],
  health: HealthSignal[],
  resources: CloudResource[],
  catalog: BusinessServiceRow[],
  nowMs: number,
): DegradedServiceRow[] {
  const byName = catalogByName(catalog);

  // signal facts per service: worst state, earliest onset, distinct resources.
  const sig = new Map<string, { down: boolean; firstMs: number; sinceIso: string; res: Set<string> }>();
  for (const h of health) {
    if (h.state !== "degraded" && h.state !== "down") continue;
    if (!h.app || h.app === "—") continue;
    const k = nameKey(h.app);
    const cur = sig.get(k) ?? { down: false, firstMs: Infinity, sinceIso: "", res: new Set<string>() };
    if (h.state === "down") cur.down = true;
    const t = parseTs(h.time)?.getTime();
    if (t !== undefined && t < cur.firstMs) { cur.firstMs = t; cur.sinceIso = h.time; }
    if (h.resource && h.resource !== "—") cur.res.add(h.resource);
    sig.set(k, cur);
  }

  // live measured app health joins in (provider status checks / probes) — an app
  // can be degraded with no signal row in the window.
  const names = new Map<string, string>(); // nameKey → display name
  for (const k of sig.keys()) names.set(k, k);
  for (const h of health) {
    if ((h.state === "degraded" || h.state === "down") && h.app && h.app !== "—") names.set(nameKey(h.app), h.app);
  }
  const liveState = new Map<string, "degraded" | "down">();
  for (const a of apps) {
    if (a.health === "degraded" || a.health === "down") {
      const k = nameKey(a.name);
      names.set(k, a.name);
      liveState.set(k, a.health);
    }
  }

  const appByKey = new Map(apps.map((a) => [nameKey(a.name), a]));
  const totals = new Map<string, number>();
  for (const r of resources) {
    if (!r.app) continue;
    const k = nameKey(r.app);
    totals.set(k, (totals.get(k) ?? 0) + 1);
  }

  const rows: DegradedServiceRow[] = [];
  for (const [k, display] of names) {
    const s = sig.get(k);
    const live = liveState.get(k);
    if (!s && !live) continue;
    const catRow = byName.get(k);
    const app = appByKey.get(k);
    const down = (s?.down ?? false) || live === "down";
    const sinceIso = s && s.firstMs !== Infinity ? s.sinceIso : "";
    rows.push({
      name: app?.name ?? catRow?.name ?? display,
      state: down ? "down" : "degraded",
      criticality: catRow?.criticality ?? "",
      owner: catRow?.owner || (app && app.owner !== "—" ? app.owner : "") || "—",
      sinceIso,
      durationMs: sinceIso ? Math.max(0, nowMs - (s?.firstMs ?? nowMs)) : 0,
      affected: s?.res.size ?? 0,
      total: totals.get(k) ?? app?.resources ?? 0,
    });
  }

  // worst first: down before degraded, then catalog criticality, then the
  // longest-running, then name for stability.
  rows.sort((a, b) =>
    (a.state === "down" ? 0 : 1) - (b.state === "down" ? 0 : 1) ||
    criticalityRank(a.criticality) - criticalityRank(b.criticality) ||
    b.durationMs - a.durationMs ||
    a.name.localeCompare(b.name));
  return rows;
}
