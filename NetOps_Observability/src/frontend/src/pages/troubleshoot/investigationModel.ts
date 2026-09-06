// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// investigationModel — the pure model behind the symptom-first Troubleshooting
// investigation surface (Project 4 §A; design of record
// docs/design/research/TROUBLESHOOTING_PAGE_RESEARCH_2026-08-25.md).
//
// Everything that decides WHAT an operator sees lives here as pure functions so
// it is unit-testable without a DOM: the nine canonical NOC workflows, which
// evidence lanes each one opens, the bisection ladder (physical → L2 → IGP →
// BGP → path/seam → application → logs), and — most importantly — the HONEST
// STATE of a lane.
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

import type { FeedItem, PathHealthItem, ProbePath, PromInstantSeries } from "../../services/api";
import { kindLabel } from "../../components/rca/labels";

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

// ── The nine canonical NOC workflows (research §a) ───────────────────────────

export type SymptomId =
  | "app_slow"
  | "site_down"
  | "link_interface"
  | "routing_adjacency"
  | "bgp_upstream"
  | "dns"
  | "wireless"
  | "cloud_saas"
  | "security_exposure";

export interface Symptom {
  id: SymptomId;
  /** The operator's own words, as it appears in the picker. */
  label: string;
  /** One line of what this workflow bisects. */
  hint: string;
  /** The evidence lanes this symptom opens, in reading order. */
  lanes: LaneId[];
}

export const SYMPTOMS: Symptom[] = [
  {
    id: "app_slow",
    label: "An app is slow or unreachable",
    hint: "Exonerate or own the network: probe the app path, compare to baseline, look for a change.",
    lanes: ["dem", "path", "changed", "flows", "health", "events"],
  },
  {
    id: "site_down",
    label: "A site or device is down",
    hint: "Originating vs dependent: check the parent's interface before blaming the leaf.",
    lanes: ["health", "path", "changed", "events", "routing"],
  },
  {
    id: "link_interface",
    label: "A link or interface is erroring",
    hint: "Trend versus baseline, the link partner's counters, flap count and utilization.",
    lanes: ["health", "flows", "changed", "events"],
  },
  {
    id: "routing_adjacency",
    label: "A routing adjacency dropped (OSPF / IS-IS)",
    hint: "Adjacency state and flaps, the underlying interface, a config change at either end.",
    lanes: ["routing", "health", "changed", "events"],
  },
  {
    id: "bgp_upstream",
    label: "BGP or an upstream is unstable",
    hint: "Session state and flaps, prefixes received, upstream reachability and route changes.",
    lanes: ["routing", "path", "changed", "events", "dem"],
  },
  {
    id: "dns",
    label: "DNS, DHCP or authentication is failing",
    hint: "The #1 ticket class: resolve the service, probe it, and look for a change near onset.",
    lanes: ["dem", "changed", "events", "flows"],
  },
  {
    id: "wireless",
    label: "Wireless clients are struggling",
    hint: "Client experience first, then the wired uplink behind the access layer.",
    lanes: ["dem", "health", "events", "changed"],
  },
  {
    id: "cloud_saas",
    label: "A cloud or SaaS service is degraded",
    hint: "Provider-side change and health versus our own seam — who owns the fault.",
    lanes: ["dem", "changed", "path", "events", "flows"],
  },
  {
    id: "security_exposure",
    label: "Something looks exposed or compromised",
    hint: "Security evidence is a corroborating class, never a verdict on its own.",
    lanes: ["events", "changed", "flows", "health"],
  },
];

export function symptomById(id: string | null | undefined): Symptom | null {
  return SYMPTOMS.find((s) => s.id === id) ?? null;
}

/** Lanes a symptom opens; an unknown symptom opens every lane (never fewer). */
export function lanesForSymptom(id: string | null | undefined): LaneId[] {
  return symptomById(id)?.lanes ?? ALL_LANES;
}

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
      status: problem ? "Problem found here" : PLAIN_STATUS[state],
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

// ── Step 0: how the page works, in three lines ───────────────────────────────

/**
 * The whole page in three sentences, in the order the operator will work them.
 * Kept here (not inline in the JSX) so the copy is asserted by a test rather
 * than re-invented every time the layout moves.
 */
export const HOW_IT_WORKS: string[] = [
  "Tell us what is wrong — pick the problem you are seeing, or an open case.",
  "We gather the evidence — Correlix checks each layer of the network for you.",
  "You get an answer — a likely cause, or a clean handoff to the owner or vendor support.",
];

// ── Verdict header (symptom-only) ────────────────────────────────────────────

/**
 * bisectingHeadline — the honest header used when the operator picked a symptom
 * but no correlation case backs it. It states plainly that we do not have the
 * cause; it never borrows RCA's verdict language, and it uses no engine words.
 */
export function bisectingHeadline(symptom: Symptom | null): { title: string; sub: string } {
  return {
    title: symptom ? symptom.label : "What's wrong?",
    sub: symptom
      ? "We do not have the cause yet. We are working through the layers below."
      : "Pick a problem or an open case to start.",
  };
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

// ── Deep link ────────────────────────────────────────────────────────────────

// The page carries TWO sections. "Protocol diagnostics" was removed on
// 2026-09-05 (docs/design/TAC_ESCALATION_2026-09-05.md §5): the manual bench is
// replaced by the escalation flow on the investigation surface, and the issue ×
// command knowledge moved to Iris → Knowledge. An old `?section=protocol` deep
// link therefore resolves to the investigation surface — the same fallback any
// unrecognized section takes, so a bookmark lands on the work, not on a blank.
export type TroubleshootSection = "investigate" | "pipeline";

/**
 * Reads the section, symptom and case out of the page hash. Anything
 * unrecognized falls back to the investigation surface — a deep link never
 * lands on a blank page.
 */
export function parseInvestigationHash(hash: string): {
  section: TroubleshootSection;
  symptom: SymptomId | null;
  caseId: string;
} {
  const q = new URLSearchParams(String(hash || "").split("?")[1] || "");
  const raw = q.get("section");
  const section: TroubleshootSection = raw === "pipeline" ? "pipeline" : "investigate";
  const sym = symptomById(q.get("symptom"));
  // Only an opaque token is accepted as a case id — never rendered as markup.
  const caseId = /^[A-Za-z0-9_-]{1,64}$/.test(q.get("case") || "") ? String(q.get("case")) : "";
  return { section, symptom: sym ? sym.id : null, caseId };
}
