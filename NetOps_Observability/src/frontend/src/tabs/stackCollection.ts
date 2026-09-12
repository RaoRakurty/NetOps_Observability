// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// stackCollection — the pure model behind Platform → Stack Health's Collection
// section.
//
// WHERE IT CAME FROM. Troubleshooting used to carry a second section, the June
// collection-pipeline board, and a bookmark holding `?section=pipeline` reopened
// it on every refresh (owner, 2026-09-07: "It looks like stale page"). The board
// is gone; the facts it was the only screen to carry are here, on the page that
// already answers "is the platform itself healthy":
//
//   · the fleet counts — monitored devices, SNMP-reachable, flows and traps;
//   · one row per collector — configured, reachable and poll time, which is
//     what the board's four charts said, read now instead of over a window;
//   · the flow sources — per type, how many records and how many exporters.
//
// Pure on purpose: everything that decides WHAT the section says is a function
// over API payloads, unit-testable without a DOM (CLAUDE.md §11).
//
// HONESTY. A metric family that has never been scraped and a collector that
// reported zero are different facts. An absent series yields `null` (rendered as
// "—"), never 0 — a zero on this section means the collector said zero.

import type { PromInstantSeries } from "../services/api";

/** One collector, as the section lists it. */
export interface CollectorRow {
  collector: string;
  /** null when the metric family carried no series for this collector. */
  configured: number | null;
  reachable: number | null;
  pollMs: number | null;
  /** "up" every configured target answered · "degraded" some · "down" none. */
  status: "up" | "degraded" | "down" | "unknown";
}

/** One flow source, as the section lists it. */
export interface FlowSourceRow {
  flowType: string;
  flows: number;
  exporters: number;
}

/** The instant value of a series, or null when it is absent or not a number. */
export function instantValue(series: PromInstantSeries[] | undefined, collector: string): number | null {
  for (const s of series ?? []) {
    if ((s?.metric?.collector ?? "") !== collector) continue;
    const n = Number(s?.value?.[1]);
    if (Number.isFinite(n)) return n;
  }
  return null;
}

/** The single scalar of an aggregate query, or null when it returned nothing. */
export function scalarValue(series: PromInstantSeries[] | undefined): number | null {
  const first = (series ?? [])[0];
  const n = Number(first?.value?.[1]);
  return Number.isFinite(n) ? n : null;
}

/** Every collector named by any of the three families, in a stable order. */
export function collectorNames(...families: (PromInstantSeries[] | undefined)[]): string[] {
  const names = new Set<string>();
  for (const f of families) {
    for (const s of f ?? []) {
      const name = s?.metric?.collector ?? "";
      if (name) names.add(name);
    }
  }
  return [...names].sort();
}

/**
 * The collector rows. `status` is derived only from what was reported: a
 * collector with no `configured` series is "unknown", not "down".
 */
export function collectorRows(
  configured: PromInstantSeries[] | undefined,
  reachable: PromInstantSeries[] | undefined,
  poll: PromInstantSeries[] | undefined,
): CollectorRow[] {
  return collectorNames(configured, reachable, poll).map((collector) => {
    const c = instantValue(configured, collector);
    const r = instantValue(reachable, collector);
    let status: CollectorRow["status"] = "unknown";
    if (c != null && r != null) {
      if (c === 0) status = "unknown";
      else if (r >= c) status = "up";
      else if (r > 0) status = "degraded";
      else status = "down";
    }
    return { collector, configured: c, reachable: r, pollMs: instantValue(poll, collector), status };
  });
}

/** The flow-source rows, largest first — the board's chips, as rows. */
export function flowSourceRows(data: unknown): FlowSourceRow[] {
  const rows = Array.isArray(data) ? data : [];
  return rows
    .map((r) => {
      const rec = (r ?? {}) as Record<string, unknown>;
      return {
        flowType: String(rec.flow_type ?? "").toUpperCase(),
        flows: Number(rec.flows ?? 0) || 0,
        exporters: Number(rec.exporters ?? 0) || 0,
      };
    })
    .filter((r) => r.flowType !== "")
    .sort((a, b) => b.flows - a.flows || a.flowType.localeCompare(b.flowType));
}

/** Total records across every flow source, for the fleet count. */
export function flowsTotal(rows: FlowSourceRow[]): number {
  return rows.reduce((sum, r) => sum + r.flows, 0);
}

/** The PromQL the section evaluates. Aggregated server-side, one read each. */
export const COLLECTION_QUERIES = {
  monitored: 'max(collector_targets{collector="snmpmetrics"}) or vector(0)',
  snmpReachable: 'sum(collector_targets_reachable{collector=~"snmp.*"}) or vector(0)',
  configured: "sum by (collector) (collector_targets)",
  reachable: "sum by (collector) (collector_targets_reachable)",
  poll: "max by (collector) (collector_poll_duration_ms)",
} as const;
