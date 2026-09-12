// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// traffic.ts — per-service traffic telemetry from the cloud load-balancer plane.
//
// WHAT IS ACTUALLY INGESTED — and therefore the only thing this panel may claim.
// The ALB/NLB access-log tailer turns a log line into a signal ONLY when it is an
// ELB-side 5xx: correlation/cloud_log_parsers.py `alb_lb_signal()` returns None
// for 2xx/3xx/4xx ("only ELB-side 5xx is a fault signal"). The successful
// requests are read and dropped — they never become signals and are never stored.
//
// The consequence is precise, and this module exists to hold the line on it:
//   · gateway 5xx COUNT over a window → REAL. Every ELB-side 5xx is a signal, so
//     counting them is a complete, honest measurement.
//   · request THROUGHPUT (req/s) → NOT INGESTED. The 2xx/3xx/4xx that make up
//     nearly all traffic are discarded at parse time.
//   · 5xx RATE (5xx ÷ total requests) → NOT COMPUTABLE. Its denominator is the
//     throughput above. Dividing by the 5xx count alone would yield a fixed 100%
//     — a fabricated statistic, which is exactly what this page forbids.
// So we surface the count we genuinely hold and mark throughput/rate as not
// measured, naming the source that would supply them. When the LB drill is live
// and grounding 5xx, the count is real; with the cloud hosts torn down it is an
// honest zero-in-window, not a blank.
//
// Pure + deterministic (injectable `now`) → unit-tested (traffic.test.ts).

import type { EvidenceRow } from "./types";
import { filterByRange, newestIso } from "./range";
import { cleanVal } from "./timeline";

// The signal kinds that ARE an app-edge HTTP error, across the producers that
// emit one: the cloud LB access-log lane, the device/LB telemetry lane, and the
// synthetic prober's own 5xx observation.
const LB_ERROR_KINDS = new Set([
  "cloud_lb_log",       // ALB/NLB access log — ELB-side 5xx (cloud_log_parsers)
  "lb_5xx",             // load-balancer telemetry lane
  "alb_5xx",
  "synthetic_http_5xx", // active probe saw a 5xx
]);

export function isLbErrorSignal(signalType: string): boolean {
  return LB_ERROR_KINDS.has(cleanVal(signalType).toLowerCase());
}

export interface LbTraffic {
  /** ELB-side 5xx observations in the window — a real, complete count. */
  errors: number;
  /** ISO of the most recent 5xx ("" when none) — the panel's freshness anchor. */
  newest: string;
  /** The load balancers / resources that reported them, deduped. */
  resources: string[];
}

export const EMPTY_TRAFFIC: LbTraffic = { errors: 0, newest: "", resources: [] };

// The app-edge error picture for one service over a window, derived from the
// evidence the engine grounded for it. Only GROUNDED rows count: a "missing"
// gap row is the engine naming what it does not have and is not an observation.
export function lbTraffic(
  rows: readonly EvidenceRow[], minutes: number, now: number = Date.now(),
): LbTraffic {
  const hits = filterByRange(
    rows.filter((r) => r.grounded && isLbErrorSignal(r.signalType)),
    minutes, now,
  );
  if (!hits.length) return EMPTY_TRAFFIC;
  const resources: string[] = [];
  for (const h of hits) {
    const res = cleanVal(h.resource);
    if (res && !resources.includes(res)) resources.push(res);
  }
  return { errors: hits.length, newest: newestIso(hits), resources };
}
