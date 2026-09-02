// model.ts — the PURE data adapters behind the Security (CTEM) section.
//
// Every number an operator reads on a security screen is computed here, never
// inline in a component, so it is unit-testable and so the honesty rules are
// enforced in ONE place:
//
//  · An unassessed asset is UNKNOWN, never "clear". Coverage renders the gap
//    explicitly; a 0 that means "nothing was measured" is never shown as a 0.
//  · OCSF status 4 (NotApplicable) / 5 (Error) are NOT a pass — they map to
//    "unassessed", so an errored check can never colour a screen green.
//  · Percentages are only ever computed over a denominator the API actually
//    stated. No estimating, no back-filling.
//  · Nothing here trusts the payload: every field is optional-checked and
//    coerced, because the transport is an external boundary (§3 zero-trust).
//
// Tenant isolation (§3a) is a SERVER guarantee: these adapters receive only the
// caller's own rows and never widen a query. There is no "all tenants" path.

import type {
  SecFacets, SecFinding, SecFindingQuery, SecFindingsPage, SecPosture,
  SecRule, SecRuleToggle, SecTrend, CorrObject, Seam,
} from "../../services/api";

// ── verdict / severity vocabulary ───────────────────────────────────────────

export type Verdict = "pass" | "warn" | "fail" | "unassessed";
export type Tone = "" | "good" | "warn" | "bad";

/** OCSF status_id → the four verdicts the UI knows. 4/5 are NOT a pass. */
export function verdictOf(f: Pick<SecFinding, "status_id">): Verdict {
  switch (Number(f.status_id)) {
    case 1: return "pass";
    case 2: return "warn";
    case 3: return "fail";
    default: return "unassessed"; // 4 NotApplicable, 5 Error, anything unknown
  }
}

export const VERDICT_LABEL: Record<Verdict, string> = {
  pass: "Pass",
  warn: "Warning",
  fail: "Fail",
  unassessed: "Unassessed",
};

export function verdictTone(v: Verdict): Tone {
  return v === "fail" ? "bad" : v === "warn" ? "warn" : v === "pass" ? "good" : "";
}

const SEV_RANK: Record<string, number> = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
export const severityRank = (s?: string): number => SEV_RANK[(s ?? "").toLowerCase()] ?? 0;

export function severityTone(s?: string): Tone {
  const x = (s ?? "").toLowerCase();
  if (x === "critical" || x === "high") return "bad";
  if (x === "medium") return "warn";
  if (x === "low" || x === "info") return "";
  return "";
}

/** Operator-facing name for an evidence lane. Never engine wording. */
export function evidenceClassLabel(c?: string): string {
  switch ((c ?? "").toLowerCase()) {
    case "posture": return "Hardening & posture";
    case "exposure": return "Seam exposure";
    case "signal":
    case "threat": return "Threat detections";
    case "": return "Unclassified";
    default: return c as string;
  }
}

/**
 * The evidence_class value the THREAT lane is requested under. The T8 contract
 * names it "threat"; the stored model (secfindings/finding.go) also emits
 * "signal" for the same lane, so reads accept both while writes use the
 * contract's word. Kept as one constant so the divergence lives in one line.
 */
export const THREAT_EVIDENCE_CLASS = "threat";
export const THREAT_EVIDENCE_ALIASES = ["threat", "signal"] as const;
export const isThreatLane = (c?: string): boolean =>
  (THREAT_EVIDENCE_ALIASES as readonly string[]).includes((c ?? "").toLowerCase());

// ── CTEM funnel ─────────────────────────────────────────────────────────────

export type FunnelStage = {
  key: keyof SecPosture["funnel"];
  label: string;
  value: number;
  caption: string;
  /** The Correlix-differentiated stage (live validation) — badged in the UI. */
  correlix?: boolean;
  /** % of the PRECEDING stage, or null when there is no honest denominator. */
  ofPrevious: number | null;
};

const FUNNEL_DEF: { key: keyof SecPosture["funnel"]; label: string; caption: string; correlix?: boolean }[] = [
  { key: "scope", label: "Scope", caption: "assets in scope" },
  { key: "discover", label: "Discover", caption: "current findings" },
  { key: "prioritize", label: "Prioritize", caption: "high or critical" },
  { key: "validate", label: "Validate", caption: "live-confirmed reachable", correlix: true },
  { key: "mobilize", label: "Mobilize", caption: "owner assigned" },
];

const num = (v: unknown): number => {
  const n = Number(v);
  return Number.isFinite(n) && n >= 0 ? n : 0;
};

/**
 * Funnel arithmetic. Each stage carries its share of the PREVIOUS stage — the
 * only ratio the payload can honestly support. A zero (or missing) predecessor
 * yields null, not a divide-by-zero 0% that would read as "nothing got through".
 */
export function funnelStages(p: SecPosture | null): FunnelStage[] {
  const f = p?.funnel;
  return FUNNEL_DEF.map((d, i) => {
    const value = num(f?.[d.key]);
    const prevKey = i > 0 ? FUNNEL_DEF[i - 1].key : null;
    const prev = prevKey ? num(f?.[prevKey]) : 0;
    return {
      ...d,
      value,
      ofPrevious: prevKey && prev > 0 ? Math.round((value / prev) * 100) : null,
    };
  });
}

// ── coverage honesty ────────────────────────────────────────────────────────

export type Coverage = {
  assessed: number;
  total: number;
  unassessed: number;
  /** % of the estate actually assessed, or null when the total is unknown. */
  pct: number | null;
  /** True when part of the estate was never measured — the UI must say so. */
  hasGap: boolean;
  /** True when NOTHING was assessed: the screen must not render any verdict. */
  nothingAssessed: boolean;
  label: string;
};

/**
 * Coverage, stated honestly. `unassessed` is taken from the payload when it is
 * present and consistent; otherwise it is derived from total − assessed. It is
 * never silently folded into "pass".
 */
export function coverageOf(p: SecPosture | null): Coverage {
  const assessed = num(p?.coverage?.assessed_assets);
  const total = num(p?.coverage?.total_assets);
  const stated = p?.coverage?.unassessed;
  const derived = Math.max(0, total - assessed);
  const unassessed = stated === undefined || stated === null ? derived : num(stated);
  const pct = total > 0 ? Math.round((assessed / total) * 100) : null;
  const nothingAssessed = assessed === 0;
  const hasGap = unassessed > 0;
  const label = total === 0
    ? "No assets in scope yet — nothing has been assessed."
    : nothingAssessed
      ? `None of ${total} assets has been assessed — this estate's posture is unknown, not clear.`
      : hasGap
        ? `${assessed} of ${total} assets assessed · ${unassessed} unassessed (unknown, not clear)`
        : `All ${total} assets assessed`;
  return { assessed, total, unassessed, pct, hasGap, nothingAssessed, label };
}

// ── facets ──────────────────────────────────────────────────────────────────

export type FacetRow = { key: string; label: string; count: number; selected: boolean };

export const EMPTY_FACETS: SecFacets = {
  severity: { crit: 0, high: 0, medium: 0, low: 0, info: 0 },
  status: { pass: 0, warn: 0, fail: 0 },
  seam: {},
  framework: {},
  evidence_class: {},
};

/** The severity facet, in ramp order, with the API's short keys expanded. */
const SEVERITY_FACET_ORDER: { key: keyof SecFacets["severity"]; filter: string; label: string }[] = [
  { key: "crit", filter: "critical", label: "Critical" },
  { key: "high", filter: "high", label: "High" },
  { key: "medium", filter: "medium", label: "Medium" },
  { key: "low", filter: "low", label: "Low" },
  { key: "info", filter: "info", label: "Info" },
];

export function severityFacetRows(facets: SecFacets | null, selected?: string): FacetRow[] {
  return SEVERITY_FACET_ORDER.map((d) => ({
    key: d.filter,
    label: d.label,
    count: num(facets?.severity?.[d.key]),
    selected: selected === d.filter,
  }));
}

const STATUS_FACET_ORDER: { key: keyof SecFacets["status"]; label: string }[] = [
  { key: "fail", label: "Fail" },
  { key: "warn", label: "Warning" },
  { key: "pass", label: "Pass" },
];

export function statusFacetRows(facets: SecFacets | null, selected?: string): FacetRow[] {
  return STATUS_FACET_ORDER.map((d) => ({
    key: d.key,
    label: d.label,
    count: num(facets?.status?.[d.key]),
    selected: selected === d.key,
  }));
}

/** A free-keyed facet map (seam / framework / evidence_class) → sorted rows. */
export function mapFacetRows(
  m: Record<string, number> | undefined | null,
  selected?: string,
  labelOf: (k: string) => string = (k) => k,
): FacetRow[] {
  return Object.entries(m ?? {})
    .map(([key, n]) => ({ key, label: labelOf(key), count: num(n), selected: selected === key }))
    .sort((a, b) => b.count - a.count || a.key.localeCompare(b.key));
}

/** Total findings a facet map accounts for (used for "n of m" copy). */
export const facetTotal = (m: Record<string, number> | undefined | null): number =>
  Object.values(m ?? {}).reduce((s, n) => s + num(n), 0);

// ── compliance: hardening findings on the TAGGED control set ────────────────
//
// NOT "framework compliance". The denominator is only the findings that carry
// that standard's tag — a narrow, stated set — so the label must say so and the
// number must never be presented as an audit verdict.

export type FrameworkScore = {
  framework: string;
  /** pass / (pass+warn+fail) over the tagged set, or null when nothing scored. */
  pct: number | null;
  pass: number;
  warn: number;
  fail: number;
  /** Findings tagged with this framework, from the unfiltered facet map. */
  tagged: number;
  tone: Tone;
};

export function frameworkScore(framework: string, tagged: number, facets: SecFacets | null): FrameworkScore {
  const pass = num(facets?.status?.pass);
  const warn = num(facets?.status?.warn);
  const fail = num(facets?.status?.fail);
  const scored = pass + warn + fail;
  const pct = scored > 0 ? Math.round((pass / scored) * 100) : null;
  const tone: Tone = pct === null ? "" : pct >= 90 ? "good" : pct >= 70 ? "warn" : "bad";
  return { framework, pct, pass, warn, fail, tagged: num(tagged), tone };
}

// ── seam map ────────────────────────────────────────────────────────────────

export type SeamCard = {
  seam: string;
  label: string;
  /** null = the seam exists in the inventory but has no findings at all. */
  count: number | null;
  owner: string;
  assessed: boolean;
};

/**
 * The "exposure by seam" strip. A seam the inventory knows but the findings
 * store has never scored renders as UNASSESSED (count null) — a hard zero is
 * reserved for a seam that WAS assessed and came back clean.
 */
export function seamCards(
  facets: SecFacets | null,
  seams: Seam[] | null,
  ownerOf: (s: Seam) => string = (s) => s.control_plane_owner || "",
): SeamCard[] {
  const counts = facets?.seam ?? {};
  const known = new Map<string, Seam>();
  for (const s of seams ?? []) {
    const key = s.seam_type || s.seam_id;
    if (key && !known.has(key)) known.set(key, s);
  }
  const keys = new Set<string>([...Object.keys(counts), ...known.keys()]);
  return [...keys]
    .map((seam) => {
      const s = known.get(seam);
      const scored = Object.prototype.hasOwnProperty.call(counts, seam);
      return {
        seam,
        label: s?.display_name || seam,
        count: scored ? num(counts[seam]) : null,
        owner: s ? ownerOf(s) : "",
        assessed: scored,
      };
    })
    .sort((a, b) => (b.count ?? -1) - (a.count ?? -1) || a.seam.localeCompare(b.seam));
}

// ── cursor pagination ───────────────────────────────────────────────────────

export type PageState = {
  items: SecFinding[];
  cursor: string | null;
  total: number;
  /** True when the server handed back another cursor. */
  hasMore: boolean;
};

export const EMPTY_PAGE: PageState = { items: [], cursor: null, total: 0, hasMore: false };

/**
 * Folds a cursor page into the accumulated list. `append=false` (a filter
 * change) REPLACES rather than grows, so a narrowed filter can never leave
 * stale wider-scoped rows on screen. Duplicate doc ids are dropped — a resumed
 * cursor that overlaps must not double-count.
 */
export function appendPage(prev: PageState, page: SecFindingsPage | null, append: boolean): PageState {
  const incoming = Array.isArray(page?.items) ? page!.items : [];
  const base = append ? prev.items : [];
  const seen = new Set(base.map((f) => f.id));
  const items = [...base];
  for (const f of incoming) {
    if (!f || typeof f.id !== "string" || seen.has(f.id)) continue;
    seen.add(f.id);
    items.push(f);
  }
  const cursor = page?.next_cursor ?? null;
  return { items, cursor, total: num(page?.total), hasMore: !!cursor };
}

// ── current vs history ──────────────────────────────────────────────────────

export type HistoryMode = "current" | "history";

/**
 * The `current` query flag for the toggle. Sent EXPLICITLY in both directions:
 * "history" is a deliberate request for every verdict, not the absence of a
 * preference, and the caller must not depend on a server-side default.
 */
export function historyQuery(mode: HistoryMode, base: SecFindingQuery = {}): SecFindingQuery {
  return { ...base, current: mode === "current" };
}

/**
 * Client-side grouping for the history view: verdicts sharing a native_id are
 * one subject's timeline, newest first. Used only for DISPLAY grouping — the
 * server still decides which rows this tenant may see.
 */
export function groupByNative(items: SecFinding[]): { native_id: string; versions: SecFinding[] }[] {
  const m = new Map<string, SecFinding[]>();
  for (const f of items) {
    const k = f.native_id || f.id;
    const arr = m.get(k);
    if (arr) arr.push(f); else m.set(k, [f]);
  }
  return [...m.entries()]
    .map(([native_id, versions]) => ({
      native_id,
      versions: [...versions].sort((a, b) => (b.time || "").localeCompare(a.time || "")),
    }))
    .sort((a, b) => (b.versions[0]?.time || "").localeCompare(a.versions[0]?.time || ""));
}

// ── rules ───────────────────────────────────────────────────────────────────

/**
 * The PUT body for the rules editor: `{rule_id, enabled}` for the CHANGED rules
 * only, in a stable id order. Server-owned facts (family, fidelity, MITRE tags,
 * seam-awareness) are deliberately absent — a client must not be able to assert
 * them. An empty result means "nothing to save"; the caller skips the request.
 */
export function rulesPutPayload(original: SecRule[], pending: Record<string, boolean>): SecRuleToggle[] {
  const byId = new Map(original.map((r) => [r.rule_id, r]));
  return Object.entries(pending)
    .filter(([id, enabled]) => byId.has(id) && byId.get(id)!.enabled !== enabled)
    .map(([rule_id, enabled]) => ({ rule_id, enabled }))
    .sort((a, b) => a.rule_id.localeCompare(b.rule_id));
}

export function fidelityTone(f?: string): Tone {
  switch ((f ?? "").toLowerCase()) {
    case "high": return "good";
    case "medium": return "warn";
    case "low": return "bad";
    default: return "";
  }
}

// ── exposure stories ────────────────────────────────────────────────────────

/**
 * Normalizes the exposure-story list. The contract returns a bare array; a
 * defensive unwrap of the common envelope shape keeps a backend nuance from
 * blanking the hero, and anything else yields an empty list rather than a
 * render crash (§3: never trust the upstream payload).
 */
export function storyList(raw: unknown): CorrObject[] {
  const arr = Array.isArray(raw)
    ? raw
    : Array.isArray((raw as { items?: unknown })?.items)
      ? (raw as { items: unknown[] }).items
      : [];
  return arr.filter(
    (o): o is CorrObject => !!o && typeof (o as CorrObject).correlation_id === "string",
  );
}

/** Confidence as a percentage, or null when the object states none. */
export function storyConfidence(o: CorrObject): number | null {
  const c = Number(o.top_confidence);
  if (!Number.isFinite(c) || c <= 0) return null;
  return Math.round((c > 1 ? c / 100 : c) * 100);
}

// ── trend ───────────────────────────────────────────────────────────────────

export type TrendPoint = { t: string; fail: number; warn: number; pass: number; total: number };

/** Trend buckets, oldest first, with a per-bucket total. Malformed rows drop. */
export function trendPoints(trend: SecTrend | null): TrendPoint[] {
  return (trend?.buckets ?? [])
    .filter((b) => b && typeof b.t === "string" && b.t.length > 0)
    .map((b) => {
      const fail = num(b.fail), warn = num(b.warn), pass = num(b.pass);
      return { t: b.t, fail, warn, pass, total: fail + warn + pass };
    })
    .sort((a, b) => a.t.localeCompare(b.t));
}

// ── top exposures ───────────────────────────────────────────────────────────

/** The worst current findings first: severity ramp, then newest. */
export function topExposures(items: SecFinding[], limit = 6): SecFinding[] {
  return [...items]
    .filter((f) => verdictOf(f) === "fail" || verdictOf(f) === "warn")
    .sort((a, b) =>
      severityRank(b.severity) - severityRank(a.severity) ||
      (b.time || "").localeCompare(a.time || ""))
    .slice(0, limit);
}

/** A finding's subject as one readable line. */
export function subjectLine(f: SecFinding): string {
  const r = f.resource ?? {};
  const name = r.name || r.hostname || r.uid || "unknown asset";
  return [name, r.platform].filter(Boolean).join(" · ");
}

/**
 * The finding shape the presentation layer consumes. Aliased (rather than used
 * directly) so the components depend on THIS module's contract, not on the
 * transport type — the two are free to diverge if the wire shape ever does.
 */
export type SecFindingLike = SecFinding;
