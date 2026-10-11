// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// flowEmpty.tsx — honest empty states for Explore Flows. A panel that has
// nothing to draw used to say "No flow records in this window" even when the
// window held tens of thousands of flows that simply lacked the field the panel
// groups by (AS numbers, TCP flags …). That sent operators to re-check their
// exporters for a problem they did not have. Now an empty panel asks
// /api/flows/coverage what the records DO carry and says which field is missing
// and the usual reason. "No flow records" is kept for the one case it is true.

import { useEffect, useState } from "react";
import { api, type FlowFilters } from "../services/api";
import { EmptyHint } from "../components/board/panels";

export type FlowCoverage = {
  flows: number;
  tcp_flows: number;
  tcp_flows_with_flags: number;
  flows_with_as: number;
  private_only_flows: number;
  exporters: number;
};

/** What the panel groups by — decides which missing field explains it. */
export type FlowDimension = "generic" | "as" | "tcp_flags";

export type FlowEmptyReason = { msg: string; hint?: string };

const n = (v: unknown): number => {
  const x = Number(v);
  return Number.isFinite(x) && x > 0 ? x : 0;
};

/** Parses one coverage row (ClickHouse quotes 64-bit counts as strings). */
export function parseCoverage(row: Record<string, unknown> | undefined): FlowCoverage | null {
  if (!row) return null;
  return {
    flows: n(row.flows),
    tcp_flows: n(row.tcp_flows),
    tcp_flows_with_flags: n(row.tcp_flows_with_flags),
    flows_with_as: n(row.flows_with_as),
    private_only_flows: n(row.private_only_flows),
    exporters: n(row.exporters),
  };
}

const fmt = (x: number) => x.toLocaleString("en-US");
const plural = (x: number, one: string, many: string) => `${fmt(x)} ${x === 1 ? one : many}`;

/**
 * Why a panel over `dim` is empty, given what the window carries. Returns null
 * when the plain "no flow records" message is the truth (no flows at all, or
 * coverage unknown) — the caller then shows the onboarding hint.
 */
export function flowEmptyReason(dim: FlowDimension, cov: FlowCoverage | null): FlowEmptyReason | null {
  if (!cov || cov.flows === 0) return null;
  const total = plural(cov.flows, "flow", "flows");
  const from = cov.exporters > 0 ? ` from ${plural(cov.exporters, "exporter", "exporters")}` : "";
  switch (dim) {
    case "as": {
      if (cov.flows_with_as > 0) break;
      const allPrivate = cov.private_only_flows === cov.flows;
      return {
        msg: `${total}${from} in this window — none carry an AS number.`,
        hint: allPrivate
          ? "Every flow is between private addresses, which have no public AS. AS numbers appear for internet traffic when the exporter fills src/dst AS from its BGP table."
          : "The exporters send AS = 0. Enable BGP-derived AS fields in the flow export (e.g. bgp-nexthop / origin-as on the flow monitor) on routers that carry a BGP table.",
      };
    }
    case "tcp_flags": {
      if (cov.tcp_flows === 0) {
        return {
          msg: `${total}${from} in this window — none are TCP.`,
          hint: "TCP flags exist only on TCP flows. This traffic is UDP/ICMP/other; see Protocols for the mix.",
        };
      }
      if (cov.tcp_flows_with_flags === 0) {
        return {
          msg: `${plural(cov.tcp_flows, "TCP flow", "TCP flows")} in this window — none carry TCP flags.`,
          hint: "The exporter does not send the tcpControlBits field (IPFIX IE 6). Add TCP flags to the flow record on the exporter.",
        };
      }
      break;
    }
    case "generic":
      break;
  }
  return {
    msg: `${total}${from} in this window, but none match this view.`,
    hint: "Clear or widen the filters above to see them.",
  };
}

// ── shared coverage read ────────────────────────────────────────────────────
// Several panels can be empty at once; they share one request per query. The
// cache is short-lived so a refresh after the window moves re-asks.
const TTL_MS = 20_000;
const cache = new Map<string, { at: number; p: Promise<FlowCoverage | null> }>();

function coverageKey(since: number, ftype: string, filters?: FlowFilters): string {
  return JSON.stringify([since, ftype, filters ?? {}]);
}

export function fetchCoverage(since: number, ftype: string, filters?: FlowFilters): Promise<FlowCoverage | null> {
  const key = coverageKey(since, ftype, filters);
  const hit = cache.get(key);
  const now = Date.now();
  if (hit && now - hit.at < TTL_MS) return hit.p;
  // Started inside a promise so any failure, even a synchronous one, becomes
  // "coverage unknown" and never breaks the panel.
  const p = Promise.resolve()
    .then(() => api.flowsCoverage(since, ftype, filters))
    .then((res) => parseCoverage((res?.data as Record<string, unknown>[] | undefined)?.[0]))
    .catch(() => null);
  cache.set(key, { at: now, p });
  return p;
}

/** Test hook: forget cached coverage. */
export function resetCoverageCache(): void {
  cache.clear();
}

type Q = { since: number; ftype: string; filters: FlowFilters; fkey: string };

/** Empty-panel body: explains why, or falls back to the onboarding hint. */
export function FlowEmpty({ q, dim = "generic" }: { q: Q; dim?: FlowDimension }) {
  const [cov, setCov] = useState<FlowCoverage | null | undefined>(undefined);
  useEffect(() => {
    let alive = true;
    fetchCoverage(q.since, q.ftype, q.filters).then((c) => {
      if (alive) setCov(c);
    });
    return () => {
      alive = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [q.since, q.ftype, q.fkey]);

  if (cov === undefined) return <div className="empty board-empty" aria-busy="true" />;
  const why = flowEmptyReason(dim, cov);
  if (!why) return <EmptyHint kind="flows" />;
  return (
    <div className="empty board-empty" data-testid="flow-empty-reason">
      <div className="board-empty-msg">{why.msg}</div>
      {why.hint && <div className="board-empty-hint">{why.hint}</div>}
    </div>
  );
}
