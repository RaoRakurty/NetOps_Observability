// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// flowsAppViews — the pure logic behind Explore → Flows' APP and SERVICE views.
//
// WHY IT IS SEPARATE. Both views exist to make an *honest* statement about
// partial knowledge, and every one of those statements is a small decision that
// deserves a test rather than a glance at a rendered panel:
//
//   · "unknown" is a measured bucket, not a missing value — it must rank and
//     total exactly like a named application, and it must say what it means;
//   · a legacy row with no source column is NOT RESOLVED, which is a different
//     fact from "the source is the unknown application";
//   · a service with no usable selector is UNMEASURED — its zero must never
//     sort, total, or read as "no traffic";
//   · both endpoints answer over the WINDOW ONLY, so the filter bar's src/dst/
//     device/interface fields and the direction toggle do not narrow them, and
//     the screen has to say so while filters are active.
//
// Nothing here renders; tabs/Flows.tsx owns the markup and the fetch loops.

import { FlowAppRow, FlowAppsResp, FlowServiceRow } from "../services/api";

/** Coerce anything the wire hands us into a finite, non-negative number. */
function num(v: unknown): number {
  const n = Number(v);
  return Number.isFinite(n) && n > 0 ? n : 0;
}

function txt(v: unknown): string {
  return typeof v === "string" ? v.trim() : "";
}

// ── the unknown bucket ──────────────────────────────────────────────────────

/** The engine's first-class bucket for a destination nothing named. */
export const UNKNOWN_APP = "unknown";

/**
 * What the unknown row MEANS, in one line. Rendered next to the bucket so an
 * operator reads it as a measurement, not as a hole in the data. UI-words sweep
 * 5 (tracker 270): the rest of the lesson is ai/skills/explain/flows.unknown-app.md,
 * reached from the `(i)` beside this line.
 */
export const UNKNOWN_MEANING =
  "Traffic whose far end no naming source claimed — measured, not missing.";

/** True for the unknown bucket, including a row that arrived with no name. */
export function isUnknownApp(app: string | undefined): boolean {
  const a = txt(app).toLowerCase();
  return a === "" || a === UNKNOWN_APP;
}

/** Destination-side label for a row. */
export function appLabel(app: string | undefined): string {
  return isUnknownApp(app) ? "Unknown" : txt(app);
}

/** How the source side of a pair should read. */
export type SourceSide =
  | { kind: "named"; label: string }
  | { kind: "unknown"; label: string }
  /** No source column on the row at all — older data, not an unnamed app. */
  | { kind: "unresolved"; label: string };

export function sourceSide(srcApp: string | undefined): SourceSide {
  const s = txt(srcApp);
  if (s === "") return { kind: "unresolved", label: "Source not resolved" };
  if (s.toLowerCase() === UNKNOWN_APP) return { kind: "unknown", label: "Unknown" };
  return { kind: "named", label: s };
}

/** Why a row shows no source, in the operator's words. */
export const UNRESOLVED_SOURCE_MEANING =
  "Rolled up before the source side was recorded, so only its far end is named.";

// ── attribution tier ────────────────────────────────────────────────────────
//
// Same three words the engine uses and the same wording the app views already
// show (pages/appobs) — deliberately NOT a second vocabulary for one verdict.

export type TierView = { label: string; tone: string; meaning: string };

const TIER_VIEWS: Record<string, TierView> = {
  confirmed: {
    label: "Confirmed",
    tone: "var(--ok)",
    meaning: "An authoritative source named this destination.",
  },
  suspected: {
    label: "Suspected · not confirmed",
    tone: "var(--warn)",
    meaning: "A weaker signal named it — treat the name as a lead.",
  },
  undetermined: {
    label: "Under review",
    tone: "var(--fg-subtle)",
    meaning: "Nothing has settled the name for this destination yet.",
  },
};

/**
 * The strongest verdict seen across an app's destinations. An unrecognised
 * value is shown verbatim rather than mapped to a friendlier lie.
 */
export function tierView(tier: string | undefined): TierView {
  const t = txt(tier).toLowerCase();
  const known = TIER_VIEWS[t];
  if (known) return known;
  if (t === "") return { label: "Not stated", tone: "var(--fg-subtle)", meaning: "This row carried no verdict." };
  return { label: txt(tier), tone: "var(--fg-subtle)", meaning: "This verdict is not one this screen recognises." };
}

// ── applications: ordering and share ────────────────────────────────────────

/** Bytes desc, with a stable tie-break so equal rows never reorder on refresh. */
export function sortAppRows(rows: readonly FlowAppRow[] | undefined | null): FlowAppRow[] {
  return [...(rows ?? [])].sort((a, b) => {
    const d = num(b.bytes) - num(a.bytes);
    if (d !== 0) return d;
    const an = appLabel(a.app).localeCompare(appLabel(b.app));
    if (an !== 0) return an;
    return sourceSide(a.src_app).label.localeCompare(sourceSide(b.src_app).label);
  });
}

/** A stable identity for a src→dst pair (React keys, table rowKey). */
export function appRowKey(row: FlowAppRow): string {
  return `${txt(row.src_app)}→${txt(row.app)}`;
}

export type AppTotals = { bytes: number; flows: number; unknownBytes: number; unknownRows: number };

export function appTotals(rows: readonly FlowAppRow[] | undefined | null): AppTotals {
  let bytes = 0;
  let flows = 0;
  let unknownBytes = 0;
  let unknownRows = 0;
  for (const r of rows ?? []) {
    bytes += num(r.bytes);
    flows += num(r.flows);
    if (isUnknownApp(r.app)) {
      unknownBytes += num(r.bytes);
      unknownRows += 1;
    }
  }
  return { bytes, flows, unknownBytes, unknownRows };
}

/**
 * Share of the measured total, 0–100, or null when there is nothing to divide
 * by. Every application row is measured — the unknown bucket included — so the
 * denominator here is the whole window's resolved volume.
 */
export function appShare(row: FlowAppRow, totalBytes: number): number | null {
  if (!(totalBytes > 0)) return null;
  return (100 * num(row.bytes)) / totalBytes;
}

// ── services: unmeasured is not zero ────────────────────────────────────────

export type ServiceRows = {
  /** Has a usable selector — its bytes are a measurement. */
  measured: FlowServiceRow[];
  /** No usable selector yet — its zero means UNMEASURED. */
  unmeasured: FlowServiceRow[];
};

/**
 * Split, never blend. Unattributed services are grouped and labelled rather
 * than sorted among real zeroes, which is the whole point of the view: a
 * service nobody has taught us to recognise must not read as an idle one.
 */
export function groupServiceRows(rows: readonly FlowServiceRow[] | undefined | null): ServiceRows {
  const measured: FlowServiceRow[] = [];
  const unmeasured: FlowServiceRow[] = [];
  for (const r of rows ?? []) (r?.attributed ? measured : unmeasured).push(r);
  measured.sort((a, b) => num(b.bytes) - num(a.bytes) || txt(a.name).localeCompare(txt(b.name)));
  unmeasured.sort((a, b) => txt(a.name).localeCompare(txt(b.name)));
  return { measured, unmeasured };
}

/** Measured rows first (bytes desc), then the unmeasured group, alphabetical. */
export function sortServiceRows(rows: readonly FlowServiceRow[] | undefined | null): FlowServiceRow[] {
  const g = groupServiceRows(rows);
  return [...g.measured, ...g.unmeasured];
}

/** The denominator excludes unmeasured services — they contribute no evidence. */
export function serviceMeasuredBytes(rows: readonly FlowServiceRow[] | undefined | null): number {
  return groupServiceRows(rows).measured.reduce((n, r) => n + num(r.bytes), 0);
}

/** Share of measured volume, or null when the row is unmeasured (never 0%). */
export function serviceShare(row: FlowServiceRow, measuredBytes: number): number | null {
  if (!row?.attributed) return null;
  if (!(measuredBytes > 0)) return null;
  return (100 * num(row.bytes)) / measuredBytes;
}

/** The label for a service's volume cell — an unmeasured row never shows "0". */
export const UNMEASURED_LABEL = "Not measured";

export const UNMEASURED_MEANING =
  "No selector matches this service yet, so its traffic has never been counted.";

// ── honesty statements ──────────────────────────────────────────────────────

/** "the last hour" — the window as an operator says it. */
export function windowPhrase(seconds: number | undefined): string {
  const s = num(seconds);
  if (s <= 0) return "this window";
  if (s % 86400 === 0) {
    const d = s / 86400;
    return d === 1 ? "the last 24 hours" : `the last ${d} days`;
  }
  if (s % 3600 === 0) {
    const h = s / 3600;
    return h === 1 ? "the last hour" : `the last ${h} hours`;
  }
  const m = Math.max(1, Math.round(s / 60));
  return m === 1 ? "the last minute" : `the last ${m} minutes`;
}

/**
 * The coverage statement: which slice of the window was actually named. It is
 * the honest caption for every number in the table, so it renders even when
 * the endpoint answered without one.
 */
export function coverageSentence(coverage: FlowAppsResp["coverage"] | undefined | null): string {
  if (!coverage || !(num(coverage.top_pairs) > 0)) {
    return "Coverage was not reported, so read these rows as a sample.";
  }
  const pairs = num(coverage.top_pairs).toLocaleString();
  const win = windowPhrase(num(coverage.window_seconds));
  const cat = num(coverage.catalog_prefixes);
  const catPart = cat > 0
    ? ` ${cat.toLocaleString()} catalogued address ranges were available.`
    : " No catalogued address ranges were available.";
  return `Named from the busiest ${pairs} source-to-destination pairs in ${win} — not every flow.${catPart}`;
}

// ── the window-only caveat ──────────────────────────────────────────────────

const FILTER_WORDS: Record<string, string> = {
  src: "source",
  dst: "destination",
  device: "device",
  in_if: "ingress interface",
  out_if: "egress interface",
};

/** "source and destination" — the operator's names for the set filter fields. */
export function filterFieldPhrase(keys: readonly string[]): string {
  const words = keys.map((k) => FILTER_WORDS[k] ?? k);
  if (words.length === 0) return "";
  if (words.length === 1) return words[0];
  return `${words.slice(0, -1).join(", ")} and ${words[words.length - 1]}`;
}

/**
 * What to say when the filter bar is set but this view cannot honour it. Null
 * when nothing is filtered — silence is correct then.
 *
 * @param keys    the committed filter field names (src, dst, device, …)
 * @param subject "Applications" / "Services", for a sentence that names itself
 */
export function windowScopeCaveat(keys: readonly string[], subject: string): string | null {
  if (keys.length === 0) return null;
  return `${subject}: the filters above do not narrow these numbers.`;
}

/** The same fact, stated once with no filters set — always shown. */
export function windowScopeNote(subject: string): string {
  return `${subject} answer over the selected time window only.`;
}

/** The tooltip beside the caveat: exactly which set fields are being ignored. */
export function windowScopeFields(keys: readonly string[]): string {
  return keys.length === 0 ? "" : `Not narrowed by: ${filterFieldPhrase(keys)}, or by the direction toggle.`;
}

// ── the drill ───────────────────────────────────────────────────────────────
//
// These rows carry no addresses, so there is no app→IP filter to hand
// Conversations. The honest drill says exactly that instead of inventing one.

export function drillNote(label: string): string {
  return `Conversations lists the address-level talkers for this window — not narrowed to ${label}.`;
}

/** The action's own words — it changes section, it does not filter. */
export const DRILL_ACTION = "Conversations for this window";
