// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// slo.ts — pure view logic for the SLO / error-budget card (Wave 5 #14 slice 2).
// No fetch, no React — unit-testable math and list edits only.

import type { CloudSloDef, CloudSloResponse, CloudSloRow } from "../../services/api";

// sloForApp — the app's SLO row, matched case-insensitively (backend stores
// the app token as written but refuses duplicates that differ only by case).
export function sloForApp(resp: CloudSloResponse | null, appName: string): CloudSloRow | null {
  if (!resp) return null;
  const key = appName.trim().toLowerCase();
  return resp.slos.find((s) => s.app_name.toLowerCase() === key) ?? null;
}

// upsertSlo — replace-or-append the app's objective in the tenant list (the API
// is a whole-list PUT). Pure: returns a new array.
export function upsertSlo(defs: CloudSloDef[], app: string, targetPct: number, windowDays: number): CloudSloDef[] {
  const key = app.trim().toLowerCase();
  const next = defs.filter((d) => d.app_name.toLowerCase() !== key);
  next.push({ app_name: app.trim(), target_pct: targetPct, window_days: windowDays });
  return next;
}

// removeSlo — drop the app's objective. Pure.
export function removeSlo(defs: CloudSloDef[], app: string): CloudSloDef[] {
  const key = app.trim().toLowerCase();
  return defs.filter((d) => d.app_name.toLowerCase() !== key);
}

// validateSloTarget — mirrors the backend bounds (50..99.999). Returns an error
// message or "".
export function validateSloTarget(raw: string): string {
  const n = Number(raw);
  if (!Number.isFinite(n)) return "target must be a number";
  if (n < 50 || n > 99.999) return "target must be between 50 and 99.999";
  return "";
}

// fmtSloPct — availability figures need more precision than a chart axis:
// 99.95 must not render as 100%.
export function fmtSloPct(v: number | undefined): string {
  if (v === undefined || !Number.isFinite(v)) return "—";
  return `${(Math.floor(v * 1000) / 1000).toFixed(3).replace(/0+$/, "").replace(/\.$/, "")}%`;
}

// budgetTone — card tone by budget remaining: gone → bad, under a quarter left
// → warn, else good.
export function budgetTone(status: { measurable: boolean; budget_remaining_pct?: number } | undefined): "good" | "warn" | "bad" | undefined {
  if (!status || !status.measurable) return undefined;
  const rem = status.budget_remaining_pct ?? 0;
  if (rem <= 0) return "bad";
  if (rem < 25) return "warn";
  return "good";
}
