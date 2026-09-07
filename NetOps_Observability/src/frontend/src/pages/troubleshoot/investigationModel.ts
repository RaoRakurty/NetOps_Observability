// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// investigationModel — the pure model behind the Troubleshooting investigation
// surface (Project 4 §A; design of record
// docs/design/research/TROUBLESHOOTING_PAGE_RESEARCH_2026-08-25.md).
//
// THE PAGE IS THREE BLOCKS (owner, 2026-09-06: "There are two sections which
// look similar … simplify these pages and make it intuitive"):
//
//   1. What's wrong?   — the open cases, plus one box to describe a new one
//   2. The answer      — cause · where it breaks · who it affects · since when
//   3. The evidence    — one disclosure, collapsed, over the lanes
//
// What LEFT the model with the old layout: the nine-symptom picker and the
// lanes-per-symptom map (a case now opens every lane, and a described symptom
// becomes a case), the "how this page works" intro copy, and the symptom-only
// headline. The engine ladder stays — not as a step an operator reads, but as
// what earns the answer card's one "Breaking at" line.
//
// Everything that decides WHAT an operator sees lives here as pure functions so
// it is unit-testable without a DOM: the bisection ladder (physical → L2 → IGP →
// BGP → path/seam → application → logs), the answer card's four facts, and —
// most importantly — the HONEST STATE of a lane.
//
// Honesty is the whole point of the lane contract. A lane is never allowed to
// render a reassuring blank. It is exactly one of:
//   loading        — the fetch is in flight
//   error          — the API said no (the message is shown verbatim)
//   not_connected  — the DATA SOURCE was never wired on this deployment (no
//                    exporter, no probe agent, the metric family has never been
//                    scraped). A product state, not a failure.
//   empty          — the source IS wired and reported nothing in the window.
//   ready          — there are rows.
// "not_connected" and "empty" are different facts and are never collapsed: the
// first means "we cannot see", the second means "we looked and it was quiet".

import type { CorrObject, FeedItem, Incident, PathHealthItem, ProbePath, PromInstantSeries } from "../../services/api";
import { kindLabel, signatureNocTitle } from "../../components/rca/labels";

// ── Lanes ────────────────────────────────────────────────────────────────────

export type LaneId =
  | "dem"
  | "changed"
  | "health"
  | "path"
  | "routing"
  | "flows"
  | "events";

// The lane's name in the operator's words. These are TITLES A NOC ADMIN READS,
// not engine vocabulary: "Devices & links", never "device/protocol health".
export const LANE_TITLE: Record<LaneId, string> = {
  dem: "User experience",
  changed: "Recent changes",
  health: "Devices & links",
  path: "Network path",
  routing: "Routing",
  flows: "Traffic",
  events: "Alerts & events",
};

/** The API each lane reads, named on the card so an operator can go verify it. */
export const LANE_SOURCE: Record<LaneId, string> = {
  dem: "/api/paths/health",
  changed: "/api/events/feed?class=changes",
  health: "/api/metrics/query",
  path: "/api/probe/paths",
  routing: "/api/metrics/query",
  flows: "/api/flows/top",
  events: "/api/events/feed",
};

export const ALL_LANES: LaneId[] = ["dem", "changed", "health", "path", "routing", "flows", "events"];

export type LaneState = "loading" | "error" | "not_connected" | "empty" | "ready";

export interface LaneResult<T> {
  state: LaneState;
  /** The honest one-line explanation shown when state is not "ready". */
  note: string;
  rows: T[];
}

export const laneLoading = <T,>(): LaneResult<T> => ({ state: "loading", note: "Loading…", rows: [] });
export const laneError = <T,>(msg: string): LaneResult<T> => ({ state: "error", note: msg, rows: [] });

// ── The bisection ladder (research §a cross-cutting: Google-SRE bisection) ───

export type LadderLayerId = "physical" | "l2" | "igp" | "bgp" | "path" | "application" | "logs";

export interface LadderLayer {
  id: LadderLayerId;
  label: string;
  /** The lanes whose data can answer this rung. */
  lanes: LaneId[];
}

export const LADDER: LadderLayer[] = [
  { id: "physical", label: "Physical", lanes: ["health"] },
  { id: "l2", label: "L2 / link", lanes: ["health", "events"] },
  { id: "igp", label: "IGP", lanes: ["routing"] },
  { id: "bgp", label: "BGP", lanes: ["routing"] },
  { id: "path", label: "Path / seam", lanes: ["path", "dem"] },
  { id: "application", label: "Application", lanes: ["dem", "flows"] },
  { id: "logs", label: "Logs & changes", lanes: ["events", "changed"] },
];

export type RungState = "has_data" | "no_data" | "not_connected" | "not_opened" | "checking";

export interface LadderRung {
  id: LadderLayerId;
  label: string;
  state: RungState;
  /** Operator-language reason for the rung's state. Never empty. */
  note: string;
}

const RUNG_NOTE: Record<RungState, string> = {
  has_data: "evidence available",
  no_data: "nothing observed in this window",
  not_connected: "no source wired for this layer",
  not_opened: "not part of this symptom",
  checking: "still reading the sources",
};

/**
 * buildLadder — which rungs of the bisection ladder actually have evidence for
 * this investigation. A rung is:
 *   not_opened     — none of its lanes belong to the chosen symptom
 *   has_data       — at least one of its lanes returned rows
 *   not_connected  — every opened lane for it says the source is not wired
 *   checking       — a lane is still in flight, so "nothing observed" would be
 *                    a claim we have not earned yet
 *   no_data        — otherwise (looked, saw nothing)
 * A rung is NEVER reported as answered because it merely has a lane on screen.
 */
export function buildLadder(openLanes: LaneId[], states: Partial<Record<LaneId, LaneState>>): LadderRung[] {
  const open = new Set(openLanes);
  return LADDER.map((l) => {
    const mine = l.lanes.filter((id) => open.has(id));
    let state: RungState;
    if (mine.length === 0) {
      state = "not_opened";
    } else if (mine.some((id) => states[id] === "ready")) {
      state = "has_data";
    } else if (mine.every((id) => states[id] === "not_connected")) {
      state = "not_connected";
    } else if (mine.some((id) => states[id] === "loading" || states[id] === undefined)) {
      state = "checking";
    } else {
      state = "no_data";
    }
    return { id: l.id, label: l.label, state, note: RUNG_NOTE[state] };
  });
}

// ── The PLAIN ladder — step 2, "Where is it breaking?" ───────────────────────
//
// The seven-rung bisection ladder above is the ENGINE's ladder and stays exactly
// as it was (it is what earns a rung its state). This is its OPERATOR reading:
// four rungs a NOC admin recognises without training — Physical link · Routing ·
// Overlay/Service · Application — each with a plain status word instead of an
// engine state name.
//
// "Logs & changes" is deliberately NOT a rung: change and alert evidence is not
// a layer of the network. It reads as its own evidence card in step 3.

export type PlainRungId = "link" | "routing" | "overlay" | "application";

export interface PlainLayer {
  id: PlainRungId;
  label: string;
  /** The engine ladder layers this plain rung reads. */
  layers: LadderLayerId[];
}

export const PLAIN_LADDER: PlainLayer[] = [
  { id: "link", label: "Physical link", layers: ["physical", "l2"] },
  { id: "routing", label: "Routing", layers: ["igp", "bgp"] },
  { id: "overlay", label: "Overlay / Service", layers: ["path"] },
  { id: "application", label: "Application", layers: ["application"] },
];

/**
 * The lanes whose query returns ONLY out-of-state rows: a row on one of them is
 * a fault, so the rung may honestly say "Problem found here". Every other lane
 * returns observations, and rows on it earn the weaker "Evidence to review" —
 * we never upgrade "we have data" into "we found the fault".
 */
export const ANOMALY_LANES: LaneId[] = ["health", "routing"];

export type PlainRungState = "found" | "checking" | "ok" | "blind" | "skipped";

/** The one status only an ANOMALY lane can promote a rung to. */
export const PLAIN_PROBLEM_STATUS = "Problem found here";

export interface PlainRung {
  id: PlainRungId;
  label: string;
  state: PlainRungState;
  /** The status word an operator reads. Never empty. */
  status: string;
  /** One plain sentence saying why it says that. Never empty. */
  note: string;
}

const PLAIN_STATUS: Record<PlainRungState, string> = {
  found: "Evidence to review",
  checking: "Checking…",
  ok: "OK",
  blind: "Can't check",
  skipped: "Not checked yet",
};

const PLAIN_NOTE: Record<PlainRungState, string> = {
  found: "We found something here worth reading.",
  checking: "Still reading this layer.",
  ok: "We looked and found nothing wrong here.",
  blind: "Nothing is feeding us data for this layer.",
  skipped: "This problem does not need this layer.",
};

/** The worst-first order in which a plain rung takes its state from its layers. */
const PLAIN_PRECEDENCE: RungState[] = ["has_data", "checking", "no_data", "not_connected", "not_opened"];

const PLAIN_OF: Record<RungState, PlainRungState> = {
  has_data: "found",
  checking: "checking",
  no_data: "ok",
  not_connected: "blind",
  not_opened: "skipped",
};

/**
 * buildPlainLadder — the four-rung operator reading of buildLadder. A rung takes
 * the most informative state of the engine layers under it (evidence beats
 * "still checking" beats "clean" beats "blind" beats "not needed"), and only an
 * ANOMALY lane may promote "Evidence to review" to "Problem found here".
 */
export function buildPlainLadder(
  openLanes: LaneId[],
  states: Partial<Record<LaneId, LaneState>>,
): PlainRung[] {
  const engine = new Map(buildLadder(openLanes, states).map((r) => [r.id, r.state]));
  const open = new Set(openLanes);
  return PLAIN_LADDER.map((p) => {
    const sub = p.layers.map((l) => engine.get(l) ?? "not_opened");
    const worst = PLAIN_PRECEDENCE.find((c) => sub.includes(c)) ?? "not_opened";
    const state = PLAIN_OF[worst];
    const lanes = p.layers.flatMap((l) => LADDER.find((x) => x.id === l)?.lanes ?? []);
    const problem = state === "found"
      && lanes.some((l) => open.has(l) && ANOMALY_LANES.includes(l) && states[l] === "ready");
    return {
      id: p.id,
      label: p.label,
      state,
      status: problem ? PLAIN_PROBLEM_STATUS : PLAIN_STATUS[state],
      note: problem ? "Something on this layer is out of state right now." : PLAIN_NOTE[state],
    };
  });
}

// ── Evidence cards — plain summaries and the quiet/loud split (step 3) ───────

/**
 * A QUIET lane has nothing to report: the source is wired and was silent, or it
 * was never wired at all. Quiet lanes are collapsed behind one toggle so the
 * page leads with what it actually found — they are never DELETED, because
 * "we cannot see this" is a fact an operator has to be able to reach.
 */
export function laneIsQuiet(state: LaneState): boolean {
  return state === "empty" || state === "not_connected";
}

const LANE_FINDING: Record<LaneId, (n: number) => string> = {
  dem: (n) => `${n} measured user path${n === 1 ? "" : "s"} — the worst are listed first.`,
  changed: (n) => `${n} change${n === 1 ? " was" : "s were"} recorded in this window.`,
  health: (n) => `${n} interface${n === 1 ? " is" : "s are"} down right now.`,
  path: (n) => `${n} traceroute${n === 1 ? "" : "s"} recorded for this scope.`,
  routing: (n) => `${n} routing neighbour${n === 1 ? " is" : "s are"} not up.`,
  flows: (n) => `${n} busiest conversation${n === 1 ? "" : "s"} in this window.`,
  events: (n) => `${n} alert${n === 1 ? "" : "s"} or event${n === 1 ? "" : "s"} in this window.`,
};

/**
 * laneSummary — the ONE plain sentence a lane card leads with. For a lane with
 * rows it says what was found and how much; for every other state the lane's own
 * honest note is already that sentence, so this returns "" and the card prints
 * the note instead of saying the same thing twice.
 */
export function laneSummary(id: LaneId, state: LaneState, rows: number): string {
  return state === "ready" ? LANE_FINDING[id](rows) : "";
}

// ── "What changed" — change kinds and their operator labels ──────────────────

/**
 * The engine kind an on-device configuration change arrives as. NOTE (honest
 * gap): no collector emits `device_config_change` today — the change lane
 * renders it the moment one does, and meanwhile shows the change kinds that ARE
 * produced (cloud change/audit, security policy, adjacency/link changes).
 */
export const DEVICE_CONFIG_CHANGE_KIND = "device_config_change";

/** Kinds the change lane treats as a CONFIGURATION change (vs a state change). */
export function isConfigChangeKind(kind: string): boolean {
  const k = (kind || "").trim();
  return k === DEVICE_CONFIG_CHANGE_KIND || k === "config_change" || k === "cloud_change" || k === "cloud_audit";
}

/**
 * changeLabel — the operator's word for a change row. A device config change is
 * spelled out as "Configuration change" (the design's requirement); everything
 * else keeps the shared RCA kind vocabulary so one word never means two things.
 */
export function changeLabel(kind: string): string {
  const k = (kind || "").trim();
  if (k === DEVICE_CONFIG_CHANGE_KIND || k === "config_change") return "Configuration change";
  return kindLabel(k);
}

/**
 * classifyChangeLane — the change feed is wired for every deployment (it reads
 * the same event store the feed does), so "no rows" is honestly EMPTY, never
 * "not connected". Config changes sort first: they are what an operator came for.
 */
export function classifyChangeLane(items: FeedItem[]): LaneResult<FeedItem> {
  const rows = [...items].sort((a, b) => Number(isConfigChangeKind(b.kind)) - Number(isConfigChangeKind(a.kind)));
  if (rows.length === 0) {
    return { state: "empty", note: "No change was recorded in this window.", rows: [] };
  }
  return { state: "ready", note: "", rows };
}

// ── Metric-backed lanes (device/protocol health, routing) ────────────────────

/**
 * classifyMetricLane — a metric family that has NEVER been scraped is a
 * not-connected source (the collector for it is off or the devices do not
 * expose it); a family that exists but currently matches no series is empty.
 * `known` is /api/metrics/names — the authority on what has ever been ingested.
 */
export function classifyMetricLane(
  known: string[],
  wanted: string[],
  series: PromInstantSeries[],
  notConnectedNote: string,
): LaneResult<PromInstantSeries> {
  const have = new Set(known);
  if (!wanted.some((m) => have.has(m))) {
    return { state: "not_connected", note: notConnectedNote, rows: [] };
  }
  if (series.length === 0) {
    return { state: "empty", note: "The metrics are collected and nothing is out of state right now.", rows: [] };
  }
  return { state: "ready", note: "", rows: series };
}

// ── Probe / DEM lane ─────────────────────────────────────────────────────────

/**
 * classifyDemLane — Path Behavior Health scores every measured path. No paths at
 * all means no probe agent has ever reported, which is a not-connected source,
 * not a healthy network.
 */
export function classifyDemLane(paths: PathHealthItem[]): LaneResult<PathHealthItem> {
  if (paths.length === 0) {
    return {
      state: "not_connected",
      note: "No synthetic probe has reported a path — the probe collector is not measuring anything on this deployment.",
      rows: [],
    };
  }
  const worst = [...paths].sort((a, b) => a.score - b.score);
  return { state: "ready", note: "", rows: worst };
}

/** classifyPathLane — measured traceroute paths (/api/probe/paths). */
export function classifyPathLane(paths: ProbePath[]): LaneResult<ProbePath> {
  if (paths.length === 0) {
    return {
      state: "not_connected",
      note: "No traceroute has been recorded — the path collector is not wired on this deployment.",
      rows: [],
    };
  }
  return { state: "ready", note: "", rows: paths };
}

// ── Flow lane ────────────────────────────────────────────────────────────────

export interface FlowTypeRow { flow_type: string; flows: number; exporters: number }

/**
 * classifyFlowLane — an exporter that has never been seen is a not-connected
 * source; exporters present with no matching conversation is empty. The
 * distinction is the difference between "we are blind here" and "it was quiet".
 */
export function classifyFlowLane<T>(types: FlowTypeRow[], rows: T[]): LaneResult<T> {
  const exporters = types.reduce((s, t) => s + Number(t.exporters || 0), 0);
  if (exporters === 0) {
    return {
      state: "not_connected",
      note: "No flow exporter has been seen — NetFlow / IPFIX / sFlow is not sending to this deployment.",
      rows: [],
    };
  }
  if (rows.length === 0) {
    return { state: "empty", note: "Flow exporters are sending, but no conversation matched this scope.", rows: [] };
  }
  return { state: "ready", note: "", rows };
}

// ── Correlated-events lane ───────────────────────────────────────────────────

export function classifyEventsLane(items: FeedItem[]): LaneResult<FeedItem> {
  if (items.length === 0) {
    return { state: "empty", note: "No event was recorded in this window.", rows: [] };
  }
  return { state: "ready", note: "", rows: items };
}

// ── Step 4: the answer, in plain words ───────────────────────────────────────

/** The five verdict states the RCA adapter can reach, structurally typed so the
 *  model stays independent of the RCA workspace's own module. */
export type AnswerSource = {
  verdictState: "confirmed" | "suspected" | "undetermined" | "contradicted" | "recovered";
  decision: { text: string };
  summary: string;
  possiblyCause?: string;
  title: string;
};

export type AnswerState = "confirmed" | "likely" | "unconfirmed" | "recovered";

export interface PlainAnswer {
  state: AnswerState;
  /** The one-line answer. Never empty. */
  headline: string;
  /** The supporting sentence — may be empty when the engine offered none. */
  detail: string;
}

const NO_ANSWER: PlainAnswer = {
  state: "unconfirmed",
  headline: "No cause confirmed yet",
  detail: "Read the evidence above, or ask Iris to read it for you.",
};

/**
 * plainAnswer — the engine verdict said in NOC words. It never upgrades what the
 * engine said: a suspected verdict reads "Most likely cause", a contradicted one
 * says the leading cause was ruled out, and no verdict at all says exactly that
 * rather than showing a reassuring blank.
 */
export function plainAnswer(c: AnswerSource | null | undefined): PlainAnswer {
  if (!c) return NO_ANSWER;
  const detail = (c.summary || "").trim();
  const lead = (c.decision?.text || "").trim() || (c.title || "").trim();
  switch (c.verdictState) {
    case "confirmed":
      return { state: "confirmed", headline: lead || "Cause confirmed", detail };
    case "recovered":
      return { state: "recovered", headline: "This problem has recovered", detail: detail || lead };
    case "contradicted":
      return {
        state: "unconfirmed",
        headline: "The leading cause was ruled out",
        detail: detail || "The evidence contradicted it. Keep looking, or hand it to the owner.",
      };
    case "suspected":
      return {
        state: "likely",
        headline: (c.possiblyCause || "").trim() || lead || "A likely cause, not yet confirmed",
        detail,
      };
    default:
      return { ...NO_ANSWER, detail: detail || NO_ANSWER.detail };
  }
}

/** The owner sentence for step 4 — plain words, and never an invented owner. */
export function plainOwner(ownershipLabel: string | undefined): string {
  const o = (ownershipLabel || "").trim();
  return o
    ? o
    : "Nobody is named yet — we name an owner only once the evidence points at one.";
}

// ── The one picker — every open case, however it was opened ──────────────────
//
// A correlation object the engine built and an investigation an operator opened
// by describing a symptom are ONE list here. That is the whole point of the
// rewrite: there is no second surface where a problem can be described but not
// acted on (owner, 2026-09-06). The two differ only in what they can already
// tell you, and the row says which.

export type PickKind = "correlation" | "investigation";

export interface PickRow {
  kind: PickKind;
  id: string;
  /** The case in NOC words. Never an engine signature id. */
  title: string;
  /** Who it touches — the same sentence the answer card's "Affects" line uses. */
  affects: string;
  /** Raw onset timestamp; the view formats it in the operator's timezone. */
  since: string;
  /** One-word state. */
  chip: string;
}

/** The engine's verdict tier as ONE word an operator reads without training. */
export function tierChip(tier: string): string {
  switch ((tier || "").trim()) {
    case "confirmed": return "Confirmed";
    case "suspected": return "Likely";
    case "recovered": return "Recovered";
    default: return "Unconfirmed";
  }
}

/** An investigation is still live until somebody resolves or closes it. */
export function isLiveInvestigation(i: Incident): boolean {
  const st = (i.status || "").trim();
  return st !== "resolved" && st !== "closed";
}

const byNewest = (a: PickRow, b: PickRow): number => (a.since < b.since ? 1 : a.since > b.since ? -1 : 0);

/**
 * pickRows — the one list block 1 renders. Correlated cases lead (the engine
 * already did work on them); the operator's own open investigations follow.
 * A record we cannot name is still listed under a plain fallback rather than
 * dropped: a case an operator opened must never vanish from their own list.
 */
export function pickRows(cases: CorrObject[] | undefined, investigations: Incident[] | undefined): PickRow[] {
  const corr: PickRow[] = (cases ?? []).map((c) => ({
    kind: "correlation",
    id: c.correlation_id,
    title: signatureNocTitle(c.top_hypothesis || "") || "Correlated problem",
    affects: affectsLine(c.affected),
    since: c.window_start || c.created_at || "",
    chip: tierChip(c.verdict_tier),
  }));
  const mine: PickRow[] = (investigations ?? []).filter(isLiveInvestigation).map((i) => ({
    kind: "investigation",
    id: i.id,
    title: (i.title || "").trim() || "Described problem",
    affects: affectsLine(""),
    since: i.first_seen_at || i.created_at || "",
    chip: "Described",
  }));
  return [...corr.sort(byNewest), ...mine.sort(byNewest)];
}

// ── The answer card — four facts and one chip ────────────────────────────────
//
// The card answers, in one screen, the four things an operator asks before they
// act: what is it, WHERE is it breaking, WHO does it affect, and SINCE when. Each
// is a stated fact or an honest "we do not know" — never a reassuring default.

/** The plain layer the evidence points at, or "Unknown" while nothing points. */
export const BREAKING_UNKNOWN = "Unknown";

/**
 * breakingAt — the ONE layer line of the answer card, read off the same engine
 * ladder the old step-2 list rendered. A layer is named ONLY when an anomaly
 * lane earned it (buildPlainLadder's "Problem found here"): a lane that merely
 * returned observations — alerts in the window, measured paths, busy talkers —
 * is evidence to read, not a located fault, and naming a layer off it would be
 * exactly the "we have data" → "we found it" upgrade the model forbids
 * everywhere else. Everything short of that is honestly Unknown.
 */
export function breakingAt(states: Partial<Record<LaneId, LaneState>>): string {
  const found = buildPlainLadder(ALL_LANES, states).find((r) => r.status === PLAIN_PROBLEM_STATUS);
  return found ? found.label : BREAKING_UNKNOWN;
}

/** The affected inventory a case names. A malformed blob is an EMPTY one. */
export function affectedEntities(affected: string | undefined): { devices: string[]; sites: string[] } {
  let raw: unknown = null;
  try { raw = JSON.parse(affected || "{}"); } catch { raw = null; }
  const obj = (raw && typeof raw === "object" && !Array.isArray(raw)) ? raw as Record<string, unknown> : {};
  const list = (v: unknown): string[] =>
    (Array.isArray(v) ? v : []).filter((x): x is string => typeof x === "string" && x.trim() !== "");
  return { devices: list(obj.devices), sites: list(obj.sites) };
}

const plural = (n: number, one: string): string => `${n} ${one}${n === 1 ? "" : "s"}`;

/**
 * affectsLine — "2 devices, 1 site". When the case named nothing we say exactly
 * that: an empty inventory is not "0 devices", it is a gap in what we were told.
 */
export function affectsLine(affected: string | undefined): string {
  const { devices, sites } = affectedEntities(affected);
  const parts: string[] = [];
  if (devices.length > 0) parts.push(plural(devices.length, "device"));
  if (sites.length > 0) parts.push(plural(sites.length, "site"));
  return parts.length > 0 ? parts.join(", ") : "Nothing named yet";
}

/**
 * confidenceChip — how sure the engine is, as a band rather than a percentage
 * an operator would over-read. A case the engine never scored says so.
 */
export function confidenceChip(confidence: number | undefined): string {
  const c = Number(confidence);
  if (!Number.isFinite(c) || c <= 0) return "Not scored";
  if (c >= 0.8) return "High confidence";
  if (c >= 0.5) return "Medium confidence";
  return "Low confidence";
}

/**
 * quietLaneLine — a quiet lane collapses to ONE line inside the disclosure, and
 * is never deleted. The two quiet states stay DISTINCT even at one line, because
 * they are different facts: "nothing feeds this" means we cannot see the layer
 * at all, "nothing from this" means we looked and it was silent.
 */
export function quietLaneLine(id: LaneId, state: LaneState): string {
  return state === "not_connected" ? `Nothing feeds ${LANE_TITLE[id]}` : `Nothing from ${LANE_TITLE[id]}`;
}

/** The longest symptom an operator may type before we stop accepting it. */
export const MAX_SYMPTOM_CHARS = 200;

/**
 * describedTitle — the operator's own words, normalised into a case title.
 * Whitespace is collapsed and the text is bounded; nothing else is invented,
 * because the title is what the operator will recognise their case by.
 */
export function describedTitle(text: string): string {
  return String(text || "").replace(/\s+/g, " ").trim().slice(0, MAX_SYMPTOM_CHARS);
}

// ── Deep link ────────────────────────────────────────────────────────────────

// THE PAGE HAS ONE FACE (owner, 2026-09-07: "Whenever I refresh troubleshooting
// page there is a stale page … It looks like stale page"). Troubleshooting used
// to carry a second section — the June collection-pipeline board — and a
// bookmark holding `?section=pipeline` reopened it on every refresh. The board
// is gone: its collector counts, per-collector rows and flow sources now live on
// Platform → Stack Health, beside the rest of the stack's own health.
//
// `?section=` is still PARSED, and always resolves to the investigation, so no
// old bookmark lands on a blank page — `?section=protocol` (the manual bench
// retired on 2026-09-05, docs/design/TAC_ESCALATION_2026-09-05.md §5) and
// `?section=pipeline` both open the work. The page then strips the parameter
// from the address so the next refresh is clean.
export type TroubleshootSection = "investigate";

/**
 * The hash with the retired `section=` parameter removed, or "" when there was
 * nothing to remove. "" is the "leave the address alone" answer: a page hash
 * always carries its route, so a cleaned hash is never empty.
 */
export function hashWithoutSection(hash: string): string {
  const raw = String(hash || "");
  const cut = raw.indexOf("?");
  if (cut < 0) return "";
  const q = new URLSearchParams(raw.slice(cut + 1));
  if (!q.has("section")) return "";
  q.delete("section");
  const rest = q.toString();
  const route = raw.slice(0, cut);
  if (!route) return "";
  return rest ? `${route}?${rest}` : route;
}

/**
 * Reads the case out of the page hash. `section` is reported for the callers
 * that still name it, and is always the investigation — the page has one face.
 * `?symptom=` is no longer a mode either, so an old symptom link lands on the
 * picker rather than on a surface that no longer exists.
 */
export function parseInvestigationHash(hash: string): {
  section: TroubleshootSection;
  caseId: string;
} {
  const q = new URLSearchParams(String(hash || "").split("?")[1] || "");
  // Only an opaque token is accepted as a case id — never rendered as markup.
  const caseId = /^[A-Za-z0-9_-]{1,64}$/.test(q.get("case") || "") ? String(q.get("case")) : "";
  return { section: "investigate", caseId };
}
