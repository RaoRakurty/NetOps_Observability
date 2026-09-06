// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// timeMetricsSeries.ts — pure logic behind the Recovery Scorecard's detection /
// repair trend (GET /api/reliability/time-metrics, the PERSISTED per-incident
// phase-metric snapshots).
//
// HONESTY RULES (they are the whole point of this file, and they mirror the
// backend's own — `timeintel` never fabricates a zero for a phase it could not
// measure):
//
//   1. Only a COMPLETE metric contributes a duration. An incomplete phase is
//      never coerced to 0 and never silently dropped: it is counted, and the
//      lifecycle event it is still waiting for is carried out so the chart can
//      draw a GAP and the panel can say what is missing.
//   2. A bucket with no complete measurement yields `null`, plus the most
//      common blocking reason among the incomplete rows in that bucket.
//   3. One row per correlation_id. The store keeps a snapshot per calculation
//      version, so the freshest `calculated_at` wins — a version bump must
//      never double-count an incident.
//   4. Internal / platform self-monitoring rows are excluded by default, the
//      same default the rollup, trend and chronic-offender reads use.
//
// The central statistic is the MEDIAN, computed with the same NEAREST-RANK
// method as the backend's `statOf` p50 (timeintel/rollup.go), so a point on
// this chart agrees with the "p50" cards and the MTTI trend on the same page.

import type { IncidentTimeMetricRow, IncidentTimeMetric } from "../services/api";

/** Phase metric names as persisted by timeintel (types.go `MetricName`). */
export const METRIC_TTD = "ttd";
export const METRIC_TTC = "ttc";
export const METRIC_TTI = "tti";
export const METRIC_TTE = "tte";
export const METRIC_TTA = "tta";
export const METRIC_TTM = "ttm";
export const METRIC_TTR_RECOVERY = "ttr_recovery";
export const METRIC_TTR_RESOLUTION = "ttr_resolution";

/**
 * Series names, in the vocabulary already on this page: the Lifecycle Time
 * Breakdown chart's phase words (Correlate / Isolate / Recover / Resolve) and
 * the stat cards' MTTC / MTTI acronyms.
 */
export const PHASE_SERIES_LABEL: Record<string, string> = {
  [METRIC_TTD]: "MTTD — Detect",
  [METRIC_TTC]: "MTTC — Correlate",
  [METRIC_TTI]: "MTTI — Isolate",
  [METRIC_TTE]: "Evidence",
  [METRIC_TTA]: "Acknowledge",
  [METRIC_TTM]: "Mitigate",
  [METRIC_TTR_RECOVERY]: "MTTR — Recover",
  [METRIC_TTR_RESOLUTION]: "Resolution — Close",
};

/**
 * Lifecycle event → the operator's word for it, matching the per-incident Time
 * Impact card (components/rca/RcaTimeImpact.tsx). Phrased to drop into
 * "waiting on …" so an incomplete phase reads as a sentence rather than a
 * wire field name.
 */
const LIFECYCLE_EVENT_PHRASE: Record<string, string> = {
  impact_started: "an impact onset signal",
  first_signal: "a first signal",
  detected: "a detection signal",
  correlation_started: "correlation to start",
  correlation_completed: "correlation to complete",
  rca_candidate_generated: "an RCA candidate",
  root_domain_identified: "root / seam isolation",
  owner_identified: "owner assignment",
  evidence_ready: "the evidence bundle",
  ticket_created: "ticket creation",
  acknowledged: "acknowledgement",
  mitigation_started: "mitigation to start",
  mitigated: "a mitigation record",
  recovered: "a service-recovery signal",
  resolved: "a resolution record",
  closed: "ticket closure",
  postmortem_completed: "the postmortem",
};

/** The operator phrase for a lifecycle event key ("recovered" → "a service-recovery signal"). */
export function missingEventPhrase(event: string): string {
  const key = (event || "").trim();
  if (!key) return "a lifecycle event that was never recorded";
  return LIFECYCLE_EVENT_PHRASE[key] ?? key.replace(/_/g, " ");
}

/** Why a phase has no measured duration, and how many rows say so. */
export type IncompleteReason = {
  /** The raw lifecycle event key, from `missing_event` (or `blocked_by`). */
  event: string;
  /** Operator sentence fragment: "waiting on a service-recovery signal". */
  text: string;
  count: number;
};

/** One time bucket of the trend, aligned exactly as the backend aligns trend buckets. */
export type SeriesBucket = { start: number; label: string };

/** One phase metric charted across the window. */
export type PhaseSeries = {
  metric: string;
  label: string;
  /** Median duration in ms per bucket; `null` = nothing complete to measure. */
  points: (number | null)[];
  /** Complete / incomplete metric counts per bucket (same length as `points`). */
  complete: number[];
  incomplete: number[];
  /** Why a `null` bucket is null; `null` for buckets that do carry a value. */
  reasons: (IncompleteReason | null)[];
  completeTotal: number;
  incompleteTotal: number;
  /** The most common blocking reason across the whole window, if any. */
  topReason: IncompleteReason | null;
};

export type TimeMetricsSeriesResult = {
  buckets: SeriesBucket[];
  series: PhaseSeries[];
  /** Deduplicated snapshots that fell inside the window and passed the filters. */
  incidentCount: number;
  /** Of those, how many carry at least one INCOMPLETE requested phase. */
  incompleteIncidents: number;
  /** Blocking reasons across every requested phase, most common first. */
  blockers: IncompleteReason[];
};

export type TimeMetricsSeriesOptions = {
  snapshots: readonly IncidentTimeMetricRow[] | null | undefined;
  /** Phase metric names to chart, in series order. */
  metrics: readonly string[];
  /** The page's selected window, in seconds (the `since` control). */
  windowSeconds: number;
  /** The page's derived bucket width, in seconds. */
  bucketSeconds: number;
  /** Window end, epoch ms. Injected so bucketing is deterministic under test. */
  now: number;
  /** Platform self-monitoring rows: excluded unless explicitly included. */
  includeInternal?: boolean;
  /** Raw seam owner filter ("" / undefined = every owner), as the page's select. */
  owner?: string;
};

/** Guard rail: a nonsense window/bucket pair must not allocate an enormous axis. */
const MAX_BUCKETS = 500;

function emptyResult(metrics: readonly string[]): TimeMetricsSeriesResult {
  return {
    buckets: [],
    series: metrics.map((m) => ({
      metric: m,
      label: PHASE_SERIES_LABEL[m] ?? m,
      points: [], complete: [], incomplete: [], reasons: [],
      completeTotal: 0, incompleteTotal: 0, topReason: null,
    })),
    incidentCount: 0,
    incompleteIncidents: 0,
    blockers: [],
  };
}

/** Nearest-rank p50 — the same method as timeintel's `statOf`, so this chart's
 *  points agree with the p50 numbers already on the page. */
export function medianMs(values: readonly number[]): number | null {
  if (values.length === 0) return null;
  const sorted = [...values].sort((a, b) => a - b);
  const rank = Math.min(Math.max(Math.ceil(0.5 * sorted.length), 1), sorted.length);
  return sorted[rank - 1];
}

/** Epoch-ms freshness of a snapshot; an unparseable stamp sorts oldest. */
function freshness(row: IncidentTimeMetricRow): number {
  const t = Date.parse(row.calculated_at ?? "");
  return Number.isNaN(t) ? Number.NEGATIVE_INFINITY : t;
}

/**
 * One row per correlation_id, the freshest `calculated_at` winning. Rows with
 * no correlation_id cannot be deduplicated honestly, so they are not counted.
 */
export function dedupeSnapshots(
  snapshots: readonly IncidentTimeMetricRow[],
): IncidentTimeMetricRow[] {
  const best = new Map<string, IncidentTimeMetricRow>();
  for (const row of snapshots) {
    const id = (row?.correlation_id ?? "").trim();
    if (!id) continue;
    const prev = best.get(id);
    if (!prev || freshness(row) > freshness(prev)) best.set(id, row);
  }
  return [...best.values()];
}

/** The blocking lifecycle event of an incomplete phase, as a raw key. */
function blockingEvent(m: IncidentTimeMetric): string {
  const missing = (m.missing_event ?? "").trim();
  if (missing) return missing;
  // `blocked_by` is the backend's human hint and reads "missing <event>".
  const blocked = (m.blocked_by ?? "").trim();
  if (blocked) return blocked.replace(/^missing\s+/i, "");
  return (m.end_event_type ?? "").trim();
}

/** Highest count wins; ties break lexicographically so the output is stable. */
function rankReasons(counts: Map<string, number>): IncompleteReason[] {
  return [...counts.entries()]
    .map(([event, count]) => ({ event, count, text: `waiting on ${missingEventPhrase(event)}` }))
    .sort((a, b) => b.count - a.count || (a.event < b.event ? -1 : a.event > b.event ? 1 : 0));
}

/**
 * Turn persisted phase-metric snapshots into a bucketed trend series.
 *
 * Buckets are floor-aligned to epoch multiples of `bucketSeconds` — exactly how
 * `/api/reliability/trends` aligns its own buckets — so this chart's x axis
 * lines up with the MTTI trend beside it.
 */
export function buildTimeMetricsSeries(opts: TimeMetricsSeriesOptions): TimeMetricsSeriesResult {
  const metrics = opts.metrics ?? [];
  const windowSeconds = Math.floor(opts.windowSeconds);
  const bucketSeconds = Math.floor(opts.bucketSeconds);
  if (!Number.isFinite(opts.now) || windowSeconds <= 0 || bucketSeconds <= 0) return emptyResult(metrics);

  const bucketMs = bucketSeconds * 1000;
  const windowEnd = opts.now;
  const windowStart = windowEnd - windowSeconds * 1000;
  const firstBucket = Math.floor(windowStart / bucketMs) * bucketMs;
  const lastBucket = Math.floor(windowEnd / bucketMs) * bucketMs;
  const count = Math.floor((lastBucket - firstBucket) / bucketMs) + 1;
  if (count <= 0 || count > MAX_BUCKETS) return emptyResult(metrics);

  const buckets: SeriesBucket[] = [];
  for (let i = 0; i < count; i++) {
    const start = firstBucket + i * bucketMs;
    buckets.push({ start, label: new Date(start).toISOString().slice(0, 10) });
  }

  // Per metric, per bucket: the complete durations and the blocking reasons.
  const durations = new Map<string, number[][]>();
  const incompleteCounts = new Map<string, number[]>();
  const bucketReasons = new Map<string, Map<string, number>[]>();
  for (const name of metrics) {
    durations.set(name, buckets.map(() => []));
    incompleteCounts.set(name, buckets.map(() => 0));
    bucketReasons.set(name, buckets.map(() => new Map<string, number>()));
  }
  const windowReasons = new Map<string, Map<string, number>>();
  for (const name of metrics) windowReasons.set(name, new Map<string, number>());
  const allReasons = new Map<string, number>();

  const wanted = new Set(metrics);
  const ownerFilter = (opts.owner ?? "").trim();
  const includeInternal = opts.includeInternal === true;

  let incidentCount = 0;
  let incompleteIncidents = 0;

  for (const row of dedupeSnapshots(opts.snapshots ?? [])) {
    if (row.internal === true && !includeInternal) continue;
    if (ownerFilter && (row.owner ?? "") !== ownerFilter) continue;
    const at = Date.parse(row.occurred_at ?? "");
    if (Number.isNaN(at) || at < windowStart || at > windowEnd) continue;
    const idx = Math.floor((Math.floor(at / bucketMs) * bucketMs - firstBucket) / bucketMs);
    if (idx < 0 || idx >= buckets.length) continue;

    incidentCount++;
    let rowIncomplete = false;
    for (const m of row.metrics ?? []) {
      const name = m?.metric_name;
      if (!name || !wanted.has(name)) continue;
      if (m.complete === true) {
        // A "complete" phase with an unusable duration is neither a measurement
        // nor a stated gap — it is a broken row, and inventing either would lie.
        if (Number.isFinite(m.duration_ms) && m.duration_ms >= 0) durations.get(name)![idx].push(m.duration_ms);
        continue;
      }
      rowIncomplete = true;
      incompleteCounts.get(name)![idx]++;
      const event = blockingEvent(m);
      const perBucket = bucketReasons.get(name)![idx];
      perBucket.set(event, (perBucket.get(event) ?? 0) + 1);
      const perWindow = windowReasons.get(name)!;
      perWindow.set(event, (perWindow.get(event) ?? 0) + 1);
      allReasons.set(event, (allReasons.get(event) ?? 0) + 1);
    }
    if (rowIncomplete) incompleteIncidents++;
  }

  const series: PhaseSeries[] = metrics.map((name) => {
    const durs = durations.get(name)!;
    const inc = incompleteCounts.get(name)!;
    const points = durs.map((xs) => medianMs(xs));
    const reasons = points.map((v, i) =>
      v === null ? (rankReasons(bucketReasons.get(name)![i])[0] ?? null) : null,
    );
    const windowRanked = rankReasons(windowReasons.get(name)!);
    return {
      metric: name,
      label: PHASE_SERIES_LABEL[name] ?? name,
      points,
      complete: durs.map((xs) => xs.length),
      incomplete: inc,
      reasons,
      completeTotal: durs.reduce((a, xs) => a + xs.length, 0),
      incompleteTotal: inc.reduce((a, n) => a + n, 0),
      topReason: windowRanked[0] ?? null,
    };
  });

  return { buckets, series, incidentCount, incompleteIncidents, blockers: rankReasons(allReasons) };
}
