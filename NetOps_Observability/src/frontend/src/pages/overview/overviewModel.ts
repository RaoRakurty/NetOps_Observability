// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// overviewModel.ts — the pure decisions behind Overview (the merged default page
// that replaced Operations Overview + My Dashboard, 2026-11-22). No React, no IO:
// every rule here is unit-tested.

import type { CorrObject, GeoSite, HealthScoreResp } from "../../services/api";
import { isInternalStackAffected, mentionsInternal } from "../../components/rca/labels";

/** Open problems a customer cares about: graded (confirmed or suspected) and not
 *  the platform watching itself (decision #76). */
export function customerProblems(objs: readonly CorrObject[] | undefined): CorrObject[] {
  return (objs ?? []).filter((o) => o.verdict_tier !== "undetermined" && !isInternalStackAffected(o.affected));
}

/** The platform's own self-monitoring objects (shown to a platform admin only). */
export function internalObjects(objs: readonly CorrObject[] | undefined): CorrObject[] {
  return (objs ?? []).filter((o) => isInternalStackAffected(o.affected));
}

/** The problem the page leads with: the first confirmed one, else the first graded. */
export function topProblem(problems: readonly CorrObject[]): CorrObject | undefined {
  return problems.find((o) => o.verdict_tier === "confirmed") ?? problems[0];
}

/** Devices and sites touched by open problems, plus the devices currently driving
 *  the health score: they are impacted even before an RCA names them. Platform
 *  infrastructure is never counted. */
export function impactOf(problems: readonly CorrObject[], health: HealthScoreResp | undefined): { devices: Set<string>; sites: Set<string> } {
  const devices = new Set<string>();
  const sites = new Set<string>();
  const addDev = (d: string) => { const t = d.trim(); if (t && !mentionsInternal(t)) devices.add(t); };
  for (const o of problems) {
    try {
      const a = JSON.parse(o.affected || "{}");
      (a.devices ?? []).forEach((d: string) => addDev(String(d)));
      (a.sites ?? []).forEach((s: string) => { if (s && !mentionsInternal(s)) sites.add(s); });
      (a.paths ?? []).forEach((p: string) => String(p).split(/->|→/).forEach(addDev));
      (a.interfaces ?? []).forEach((i: string) => addDev(String(i).split(":")[0]));
    } catch { /* an unreadable affected list counts nothing */ }
  }
  for (const c of health?.contributions ?? []) if (c.entity) addDev(c.entity);
  return { devices, sites };
}

/** What the "What needs attention" block leads with. "quiet" is only ever said
 *  when health agrees: a degraded score with no confirmed cause is "unhealthy". */
export type Attention = "problem" | "unhealthy" | "insufficient" | "quiet" | "reading";

export function attentionOf(problems: readonly CorrObject[] | undefined, health: HealthScoreResp | undefined): Attention {
  if (problems === undefined || health === undefined) return problems && problems.length ? "problem" : "reading";
  if (problems.length > 0) return "problem";
  if (health.coverage_status === "INSUFFICIENT_TELEMETRY" || health.score == null) return "insufficient";
  if (health.band && health.band !== "healthy") return "unhealthy";
  return "quiet";
}

// ── Health by site (from /api/geomap) ───────────────────────────────────────

export type SiteState = "down" | "partial" | "up" | "empty";
export type SiteHealthRow = { name: string; slug: string; devices: number; up: number; down: number; unknown: number; state: SiteState };

export function siteState(s: Pick<GeoSite, "devices" | "up" | "down">): SiteState {
  if (s.devices <= 0) return "empty";
  if (s.down >= s.devices) return "down";
  if (s.down > 0 || s.up < s.devices) return "partial";
  return "up";
}

const STATE_RANK: Record<SiteState, number> = { down: 0, partial: 1, up: 2, empty: 3 };

/** Sites worst first (all down, then partly down or unknown, then up, then empty),
 *  then by the number of down devices, then by name. `limit` rows are returned with
 *  the full count, so a truncated list says so. */
export function siteHealthRows(sites: readonly GeoSite[] | undefined, limit = 12): { rows: SiteHealthRow[]; total: number } {
  const rows = (sites ?? []).map((s) => {
    const devices = Math.max(0, s.devices | 0);
    const up = Math.max(0, s.up | 0);
    const down = Math.max(0, s.down | 0);
    return { name: s.name || s.slug, slug: s.slug, devices, up, down, unknown: Math.max(0, devices - up - down), state: siteState({ devices, up, down }) };
  });
  rows.sort((a, b) => STATE_RANK[a.state] - STATE_RANK[b.state] || b.down - a.down || b.unknown - a.unknown || a.name.localeCompare(b.name));
  return { rows: rows.slice(0, limit), total: rows.length };
}
