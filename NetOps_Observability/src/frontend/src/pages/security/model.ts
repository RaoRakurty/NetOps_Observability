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
  SecBenchmarkCitation, SecCompliance, SecFacets, SecFinding, SecFindingQuery,
  SecFindingsPage, SecFramework, SecFrameworkCatalog, SecFrameworkCoverage,
  SecFrameworkToggle, SecPosture, SecRule, SecRuleToggle, SecTrend, CorrObject, Seam,
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

// ── compliance: per-tenant framework SELECTION and its scorecards ───────────
//
// Owner direction, 2026-09-03: "we shouldn\'t be checking all compliances by
// default; compliance is analyzed per customer requirement." The page used to
// derive its framework list from the distinct standards TAGS on findings, which
// is why it showed thirty invented CIS-NET sections as frameworks and could
// never show HIPAA (a projection, never a tag). The list now comes from the
// framework catalogue, and the numbers from the server-side projection.

export type FrameworkRow = {
  id: string;
  name: string;
  version: string;
  /** "Base catalogue" or "Projected from NIST 800-53" — never the wire word. */
  origin: string;
  scope: string;
  enabled: boolean;
  defaultOn: boolean;
};

/** The catalogue split into what this tenant runs and what it may add. */
export function frameworkRows(cat: SecFrameworkCatalog | null): FrameworkRow[] {
  return (cat?.frameworks ?? [])
    .filter((f): f is SecFramework => !!f && typeof f.id === "string" && f.id.length > 0)
    .map((f) => ({
      id: f.id,
      name: String(f.name ?? f.id),
      version: String(f.version ?? ""),
      origin: f.source === "base" ? "Base catalogue" : "Projected from NIST 800-53",
      scope: String(f.scope ?? ""),
      enabled: !!f.enabled,
      defaultOn: !!f.default_on,
    }));
}

/**
 * The PUT body: `{framework_id, enabled}` for the CHANGED frameworks only, in a
 * stable id order. An empty result means "nothing to save" and the caller skips
 * the request. Server-owned facts (name, version, source, scope) are absent —
 * a client must not be able to assert them.
 */
export function frameworksPutPayload(
  original: FrameworkRow[],
  pending: Record<string, boolean>,
): SecFrameworkToggle[] {
  const byId = new Map(original.map((f) => [f.id, f]));
  return Object.entries(pending)
    .filter(([id, enabled]) => byId.has(id) && byId.get(id)!.enabled !== enabled)
    .map(([framework_id, enabled]) => ({ framework_id, enabled }))
    .sort((a, b) => a.framework_id.localeCompare(b.framework_id));
}

export type FrameworkCard = {
  framework: string;
  version: string;
  /** Passing share over ASSESSED controls, or null when nothing was assessed. */
  pct: number | null;
  tone: Tone;
  passed: number;
  warned: number;
  failed: number;
  assessed: number;
  unassessed: number;
  inScope: number;
  withCheck: number;
  coveragePct: number | null;
  /** The sentence to show INSTEAD of a percentage when nothing was assessed. */
  emptyNote: string;
  caption: string;
  controls: SecFrameworkCoverage["controls"];
};

const UNASSESSED_FALLBACK =
  "No assessed control maps to this framework yet — this is an absence of assessment, not a passing or failing result.";

/**
 * One scorecard, stated honestly. `pct` is null whenever the server declined to
 * state a score, and a null is rendered as the sentence rather than as 0% (which
 * reads as total failure) or 100% (which reads as a clean bill).
 */
export function frameworkCard(c: SecFrameworkCoverage): FrameworkCard {
  const passed = num(c?.passed), warned = num(c?.warned), failed = num(c?.failed);
  const scored = passed + warned + failed;
  const raw = c?.score_percent;
  const pct = typeof raw === "number" && Number.isFinite(raw) && scored > 0 ? Math.round(raw) : null;
  const inScope = num(c?.controls_in_scope);
  return {
    framework: String(c?.framework ?? ""),
    version: String(c?.version ?? ""),
    pct,
    tone: pct === null ? "" : pct >= 90 ? "good" : pct >= 70 ? "warn" : "bad",
    passed, warned, failed,
    assessed: num(c?.assessed),
    unassessed: num(c?.unassessed),
    inScope,
    withCheck: num(c?.controls_with_check),
    coveragePct: inScope > 0 ? Math.round(num(c?.coverage_percent)) : null,
    emptyNote: (c?.note && String(c.note)) || UNASSESSED_FALLBACK,
    caption: String(c?.caption ?? ""),
    controls: Array.isArray(c?.controls) ? c.controls : [],
  };
}

export function frameworkCards(cmp: SecCompliance | null): FrameworkCard[] {
  return (cmp?.frameworks ?? []).filter(Boolean).map(frameworkCard);
}

/**
 * Benchmark citations grouped by the 800-53 control they hang off, so a control
 * row can carry its published benchmark references. A citation is a CITATION —
 * benchmark title, version and section heading — and never a framework.
 */
export function benchmarkChipsByControl(
  citations: SecBenchmarkCitation[] | undefined | null,
): Record<string, string[]> {
  const out: Record<string, string[]> = {};
  for (const c of citations ?? []) {
    const label = typeof c?.label === "string" ? c.label.trim() : "";
    if (!label) continue;
    for (const control of Array.isArray(c?.controls) ? c.controls : []) {
      if (typeof control !== "string" || !control) continue;
      const list = out[control] ?? (out[control] = []);
      if (!list.includes(label)) list.push(label);
    }
  }
  for (const k of Object.keys(out)) out[k].sort((a, b) => a.localeCompare(b));
  return out;
}

/** OCSF status_id → the verdict word a control row shows. 4/5 are unassessed. */
export function controlVerdict(statusID: unknown): Verdict {
  return verdictOf({ status_id: Number(statusID) } as Pick<SecFinding, "status_id">);
}

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

/**
 * mitreList — the ATT&CK technique ids a catalog rule carries, as a LIST, from
 * whatever the transport actually delivered.
 *
 * The contract (and the Go type behind it) is `string[]`, but this is an
 * external boundary and §3 says never trust the payload: a backend that served
 * the field as a bare string ("T1071") white-screened the whole Detection Rules
 * page, because the render did `r.mitre.map(...)` on a string. The type is not a
 * runtime guarantee — this function is. A string (single id, or a comma/space
 * separated list) becomes a list; an array is filtered to its string members;
 * anything else — null, a number, an object, a missing field — is an EMPTY list,
 * which the page renders as "—" (no technique claimed) rather than crashing.
 *
 * It never invents a technique: an unparseable value yields nothing, never a
 * placeholder chip, because a fabricated ATT&CK tag on a detection screen is a
 * lie an operator would act on.
 */
export function mitreList(r: { mitre?: unknown } | null | undefined): string[] {
  const raw = r?.mitre;
  const parts: string[] = Array.isArray(raw)
    ? raw.filter((m): m is string => typeof m === "string")
    : typeof raw === "string"
      ? raw.split(/[\s,;]+/)
      : [];
  const out: string[] = [];
  for (const p of parts) {
    const t = p.trim();
    if (t && !out.includes(t)) out.push(t);
  }
  return out;
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

// ── §5g: an unassessed verdict must carry its WHY ───────────────────────────
//
// "Unassessed" on its own is only half the honesty rule. The three reasons a
// hardening control reaches no verdict are entirely different problems with
// entirely different fixes — the running-config was not available, the control
// has no realization on this platform, or the platform itself did not resolve —
// and an operator who cannot tell them apart cannot act on any of them. The
// producer states the reason (secfindings.Finding.Detail → the bus's
// attrs.status_detail → the API's `status_detail`); these adapters are the one
// place the UI decides how to present its presence and its ABSENCE.

/** The reason an unassessed verdict gives, or null when it gave none. */
export function unassessedReason(f: Pick<SecFinding, "status_id" | "status_detail">): string | null {
  if (verdictOf(f) !== "unassessed") return null;
  const why = (f.status_detail ?? "").trim();
  return why === "" ? null : why;
}

/**
 * The sentence shown where a reason is expected. A missing reason is named as
 * missing — never blank, and never a soothing default: "no verdict" with no
 * explanation is precisely the shape an operator reads as "probably fine".
 */
export const NO_REASON_RECORDED =
  "No reason recorded — the provider did not state why this control could not be assessed.";

export function unassessedReasonText(f: Pick<SecFinding, "status_id" | "status_detail">): string {
  return unassessedReason(f) ?? NO_REASON_RECORDED;
}

/** One distinct unassessed reason and how many findings gave it. */
export type ReasonCount = { reason: string; count: number; recorded: boolean };

/**
 * Group unassessed findings by their reason, commonest first (ties broken
 * alphabetically so the order is stable across renders). Assessed findings are
 * ignored; findings that gave no reason collapse into ONE row that says so,
 * because "42 controls were unassessed and we cannot say why" is itself the
 * finding an operator needs to see.
 */
export function unassessedReasons(findings: SecFinding[]): ReasonCount[] {
  const counts = new Map<string, ReasonCount>();
  for (const f of findings ?? []) {
    if (verdictOf(f) !== "unassessed") continue;
    const why = unassessedReason(f);
    const key = why ?? NO_REASON_RECORDED;
    const row = counts.get(key);
    if (row) row.count += 1;
    else counts.set(key, { reason: key, count: 1, recorded: why !== null });
  }
  return [...counts.values()].sort((a, b) =>
    b.count - a.count || a.reason.localeCompare(b.reason));
}
