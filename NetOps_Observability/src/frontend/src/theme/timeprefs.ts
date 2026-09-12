// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import { TimeRange, TIME_RANGES } from "../context/shell";

// timeprefs.ts — persistence for the global time picker:
//   · per-section memory — each nav section remembers the range it was last
//     viewed with, so switching sections restores that section's range
//     (localStorage "netops.sectionRange");
//   · custom presets — user-defined ranges added to the picker, shared across
//     sections (localStorage "netops.timePresets").
// Both are pure localStorage helpers; the shell wires them into setRange and the
// section switch in App.tsx, and TopBar renders the merged preset list.

const SECTION_KEY = "netops.sectionRange";
const PRESETS_KEY = "netops.timePresets";

export const DEFAULT_RANGE: TimeRange = TIME_RANGES[1]; // Last 1 hour

function readMap(): Record<string, number> {
  try {
    const v = JSON.parse(localStorage.getItem(SECTION_KEY) || "{}");
    return v && typeof v === "object" ? v : {};
  } catch {
    return {};
  }
}

// rangeForSection returns the remembered range for a section, or the default.
export function rangeForSection(section: string): TimeRange {
  const minutes = readMap()[section];
  if (!minutes) return DEFAULT_RANGE;
  return rangeFromMinutes(minutes);
}

// rememberSectionRange persists the range a section is currently showing.
export function rememberSectionRange(section: string, minutes: number) {
  const m = readMap();
  m[section] = minutes;
  localStorage.setItem(SECTION_KEY, JSON.stringify(m));
}

// customPresets returns the user-defined ranges (sorted by duration).
export function customPresets(): TimeRange[] {
  try {
    const v = JSON.parse(localStorage.getItem(PRESETS_KEY) || "[]");
    if (!Array.isArray(v)) return [];
    return v
      .filter((p) => p && typeof p.minutes === "number" && p.minutes > 0)
      .map((p) => ({ label: String(p.label || labelForMinutes(p.minutes)), minutes: p.minutes }));
  } catch {
    return [];
  }
}

// addCustomPreset stores a new preset (deduped by minutes) and returns the list.
export function addCustomPreset(minutes: number, label?: string): TimeRange[] {
  const cur = customPresets();
  if (
    minutes > 0 &&
    !cur.some((p) => p.minutes === minutes) &&
    !TIME_RANGES.some((p) => p.minutes === minutes)
  ) {
    cur.push({ label: label?.trim() || labelForMinutes(minutes), minutes });
  }
  cur.sort((a, b) => a.minutes - b.minutes);
  localStorage.setItem(PRESETS_KEY, JSON.stringify(cur));
  return cur;
}

export function removeCustomPreset(minutes: number): TimeRange[] {
  const cur = customPresets().filter((p) => p.minutes !== minutes);
  localStorage.setItem(PRESETS_KEY, JSON.stringify(cur));
  return cur;
}

// allRanges is the built-in ranges plus the user's custom presets, de-duplicated
// and ordered by duration — the full set shown in the picker.
export function allRanges(): TimeRange[] {
  const byMin = new Map<number, TimeRange>();
  for (const r of [...TIME_RANGES, ...customPresets()]) byMin.set(r.minutes, r);
  return [...byMin.values()].sort((a, b) => a.minutes - b.minutes);
}

// rangeFromMinutes resolves a minute count to a known range (built-in or custom)
// or synthesizes a label for it.
export function rangeFromMinutes(minutes: number): TimeRange {
  return allRanges().find((r) => r.minutes === minutes) ?? { label: labelForMinutes(minutes), minutes };
}

export function labelForMinutes(minutes: number): string {
  if (minutes % 1440 === 0) return `Last ${minutes / 1440} day${minutes / 1440 > 1 ? "s" : ""}`;
  if (minutes % 60 === 0) return `Last ${minutes / 60} hour${minutes / 60 > 1 ? "s" : ""}`;
  return `Last ${minutes} min`;
}
