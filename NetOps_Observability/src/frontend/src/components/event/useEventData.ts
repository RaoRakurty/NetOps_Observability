// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// The two live reads the event panel makes, both through endpoints that are already
// tenant-scoped on the server (no new endpoint, nothing unscoped):
//
//   • related records — POST /api/logs/search (logsScope: index pattern + per-document
//     tenant filter), over fields the index can actually answer (eventModel's
//     TIMELINE_SEARCHABLE), in a bounded window around the event;
//   • a measured trend — GET /api/metrics/query_range (server-injected extra_filters[],
//     fail-closed when the upstream cannot enforce them), for the device's own series.
//
// Both report what they found and nothing else: an empty answer is "none found", never
// a flat line or a zero dressed as data.

import { useEffect, useState } from "react";
import { api } from "../../services/api";
import { loadShowRoutine } from "../../lib/routineMgmt";
import { EventView, TimelineEntry, clauseQuery, parseIso, toEventView } from "../../lib/eventModel";

const WINDOW_MS = 24 * 3600_000;
const RELATED_LIMIT = 50;

export interface RelatedState {
  status: "none" | "loading" | "done" | "error";
  /** Other records (this one excluded), oldest first. */
  records: EventView[];
  basis: string;
  error?: string;
}

export function useRelatedRecords(view: EventView): RelatedState {
  const q = view.timelineQuery;
  const at = view.link?.t ?? "";
  const key = q ? `${clauseQuery(q.clauses)}|${q.signal}|${at}|${view.id}` : "";
  const [state, setState] = useState<RelatedState>({ status: q ? "loading" : "none", records: [], basis: q?.basis ?? "" });
  useEffect(() => {
    if (!q) {
      setState({ status: "none", records: [], basis: "" });
      return;
    }
    const t = parseIso(at)?.getTime() ?? Date.now();
    const now = Date.now();
    let alive = true;
    setState({ status: "loading", records: [], basis: q.basis });
    api.searchLogs({
      query: clauseQuery(q.clauses),
      signal: q.signal,
      from: new Date(t - WINDOW_MS).toISOString(),
      to: new Date(Math.min(t + WINDOW_MS, Math.max(now, t))).toISOString(),
      size: RELATED_LIMIT,
      // Related records follow the viewer's Logs choice for routine management
      // sessions, so the same records are shown or folded away in both places.
      include_routine_mgmt: loadShowRoutine(),
    })
      .then((r) => {
        if (!alive) return;
        const records = (r?.hits?.hits ?? [])
          .filter((h) => h && h._id !== view.id)
          .map((h) => toEventView(h))
          .sort((a, b) => (parseIso(a.link?.t ?? "")?.getTime() ?? 0) - (parseIso(b.link?.t ?? "")?.getTime() ?? 0));
        setState({ status: "done", records, basis: q.basis });
      })
      .catch((e: unknown) => {
        if (alive) setState({ status: "error", records: [], basis: q.basis, error: (e as Error)?.message || "The search failed." });
      });
    return () => { alive = false; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key]);
  return state;
}

/** This record's own steps, with each related record's device-time step merged in. */
export function mergedTimeline(view: EventView, related: RelatedState): TimelineEntry[] {
  const out = [...view.timeline];
  for (const r of related.records) {
    const step = r.timeline[0];
    if (step) out.push({ ...step, key: `rel:${r.id}` });
  }
  return out.sort((a, b) => (parseIso(a.time)?.getTime() ?? 0) - (parseIso(b.time)?.getTime() ?? 0));
}

export interface TrendPoint { t: number; v: number }

export interface TrendState {
  status: "none" | "loading" | "done" | "error";
  points: TrendPoint[];
  source: string;
  error?: string;
}

const TREND_BEFORE_S = 6 * 3600;
const TREND_AFTER_S = 3600;
const TREND_STEP_S = 300;

/** A real measured series for the device, when one is stored. Never built from the trap. */
export function useMetricTrend(view: EventView, enabled: boolean): TrendState {
  const s = view.metricSeries;
  const at = view.link?.t ?? "";
  const key = s && enabled ? `${s.metric}|${s.deviceId}|${at}` : "";
  const [state, setState] = useState<TrendState>({ status: "none", points: [], source: "" });
  useEffect(() => {
    if (!s || !enabled) {
      setState({ status: "none", points: [], source: "" });
      return;
    }
    // The device id was checked against a strict label pattern in the presenter.
    const query = `${s.metric}{device="${s.deviceId}"}`;
    const t = Math.floor((parseIso(at)?.getTime() ?? Date.now()) / 1000);
    const end = Math.min(t + TREND_AFTER_S, Math.floor(Date.now() / 1000));
    const start = t - TREND_BEFORE_S;
    let alive = true;
    setState({ status: "loading", points: [], source: query });
    api.metricsQueryRange(query, start, Math.max(end, start + TREND_STEP_S), TREND_STEP_S)
      .then((r) => {
        if (!alive) return;
        const series = r?.data?.result?.[0];
        const points = (series?.values ?? [])
          .map(([ts, v]) => ({ t: Number(ts) * 1000, v: Number(v) }))
          .filter((p) => Number.isFinite(p.t) && Number.isFinite(p.v));
        setState({ status: "done", points, source: query });
      })
      .catch((e: unknown) => {
        if (alive) setState({ status: "error", points: [], source: query, error: (e as Error)?.message || "The metrics query failed." });
      });
    return () => { alive = false; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key]);
  return state;
}

/**
 * Copies text, or when the clipboard is refused, selects `fallback`'s text so the operator
 * can press Ctrl+C. Resolves to what happened, in words.
 */
export async function copyText(text: string, fallback?: HTMLElement | null): Promise<"Copied" | "Selected: press Ctrl+C" | "Copy failed"> {
  try {
    if (!navigator.clipboard?.writeText) throw new Error("no clipboard");
    await navigator.clipboard.writeText(text);
    return "Copied";
  } catch {
    if (fallback && typeof window.getSelection === "function") {
      const range = document.createRange();
      range.selectNodeContents(fallback);
      const sel = window.getSelection();
      sel?.removeAllRanges();
      sel?.addRange(range);
      return "Selected: press Ctrl+C";
    }
    return "Copy failed";
  }
}
