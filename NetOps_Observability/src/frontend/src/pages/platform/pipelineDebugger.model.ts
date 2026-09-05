// pipelineDebugger.model.ts — the pure half of the pipeline debugger screen.
//
// Everything here is a function of data the api returned: the stage order, the
// operator-facing name of each hop, which hops this screen can see at all, the
// latency arithmetic, and the exact command line that does the same thing from
// a terminal. No fetching, no React — so the honesty rules the table depends on
// are unit-testable on their own.
//
// THE ONE RULE THIS FILE EXISTS TO HOLD: a hop the api cannot observe is never
// rendered as a miss. There are four states on this screen, not two — seen, not
// seen, not observable (with the reason), and still waiting — and the third and
// fourth are the ones that keep an operator from chasing a hop that was fine.

import type { DebugKind, DebugStageEntry, DebugVerdict, SessionSummary } from "../../services/api.debug";

/** The pipeline, in order. The value is also the module log file's base name. */
export const STAGE_ORDER = [
  "ingress",
  "parser",
  "kafka",
  "router",
  "opensearch",
  "victoria",
  "clickhouse",
  "correlation",
  "api",
  "ui",
] as const;

export type StageName = (typeof STAGE_ORDER)[number];

/** The stages the api itself gathers evidence for (internal/pipedebug). */
export const SERVER_STAGES: readonly string[] = ["kafka", "opensearch", "victoria", "clickhouse", "correlation", "api"];

/** Answered by the api on demand, not by the follow that runs in the background. */
export const ON_DEMAND_STAGES: readonly string[] = ["parser", "ui"];

/**
 * What each hop is called on screen. The names are the OPERATOR's words for
 * what happens there — a hop is a step in getting a record onto a screen, not a
 * product a store vendor sells.
 */
const STAGE_LABELS: Record<string, string> = {
  ingress: "Ingest edge",
  parser: "Parsing",
  kafka: "Event bus",
  router: "Routing lanes",
  opensearch: "Log search",
  victoria: "Metrics store",
  clickhouse: "Flow and event store",
  correlation: "Correlation",
  api: "Product API",
  ui: "Screen query",
};

export function stageLabel(stage: string): string {
  return STAGE_LABELS[stage] ?? stage;
}

/**
 * Why a hop cannot be answered from this screen, and what does answer it. Two
 * hops are collected on the host by the command-line tool (a live subscription
 * to the routing tier, and the ingest edge's own container output), and saying
 * so — with the command that collects them — is the difference between an
 * honest gap and a screen that looks like the record vanished.
 */
export function hostSideNote(stage: string): string {
  if (stage === "ingress") {
    return "Collected on the host, not here: the ingest edge's own lines come from its container output. Run correlix-debug trace on the host for this hop.";
  }
  if (stage === "router") {
    return "Collected on the host, not here: the routing lane is watched with a live per-event subscription the api does not hold. Run correlix-debug trace on the host for this hop.";
  }
  return "";
}

export type RowState = DebugVerdict | "waiting";

export type StageRow = {
  stage: string;
  label: string;
  index: number;
  state: RowState;
  reason?: string;
  query?: string;
  detail?: Record<string, unknown>;
  firstSeen?: string;
  /** Milliseconds from the previous hop that was SEEN. Null when there is none. */
  latencyMs: number | null;
  /** Whether this screen can ask the api for this hop's evidence again. */
  readableHere: boolean;
  /** Whether the hop is answered only when asked for (parsing and the screen query). */
  onDemand: boolean;
};

/**
 * Build the full ten-row table from whatever entries have arrived.
 *
 * `running` is what separates "waiting" from "not reported": while the follow
 * is still going, a hop with no entry yet has not answered — it has not failed.
 * Once the follow is done, a server hop that never reported says so plainly.
 */
export function buildStageRows(entries: DebugStageEntry[], running: boolean): StageRow[] {
  const byStage = new Map<string, DebugStageEntry>();
  for (const e of entries) byStage.set(e.stage, e);

  const rows: StageRow[] = [];
  let prevSeen: number | null = null;
  STAGE_ORDER.forEach((stage, i) => {
    const e = byStage.get(stage);
    const readableHere = SERVER_STAGES.includes(stage) || ON_DEMAND_STAGES.includes(stage);
    const row: StageRow = {
      stage,
      label: stageLabel(stage),
      index: i + 1,
      state: "waiting",
      latencyMs: null,
      readableHere,
      onDemand: ON_DEMAND_STAGES.includes(stage),
    };
    if (e) {
      row.state = e.verdict;
      row.reason = e.reason;
      row.query = e.query;
      row.detail = e.detail;
      row.firstSeen = e.t_first_seen;
    } else if (!readableHere) {
      row.state = "not_observable";
      row.reason = hostSideNote(stage);
    } else if (!running) {
      row.state = "not_observable";
      row.reason = row.onDemand
        ? "Answered when asked for — read this hop to run its query now."
        : "This hop did not report before the run ended.";
    }
    // Latency is measured between hops that were SEEN, and is absent when there
    // is no earlier seen hop to measure from. A zero would read as "instant".
    if (row.state === "seen" && row.firstSeen) {
      const t = Date.parse(row.firstSeen);
      if (!Number.isNaN(t)) {
        if (prevSeen !== null) row.latencyMs = t - prevSeen;
        prevSeen = t;
      }
    }
    rows.push(row);
  });
  return rows;
}

/** The word for a row's state, and the tone it is drawn in. */
export function stateLabel(state: RowState): string {
  switch (state) {
    case "seen":
      return "Seen";
    case "not_seen":
      return "Not seen";
    case "not_observable":
      return "Not observable";
    default:
      return "Waiting";
  }
}

export type Tone = "good" | "warn" | "bad" | "muted";

export function stateTone(state: RowState): Tone {
  switch (state) {
    case "seen":
      return "good";
    case "not_seen":
      return "bad";
    case "not_observable":
      return "muted";
    default:
      return "warn";
  }
}

/** A short, honest duration. */
export function formatLatency(ms: number | null): string {
  if (ms === null) return "—";
  if (Math.abs(ms) < 1000) return `${ms} ms`;
  return `${(ms / 1000).toFixed(ms < 10000 ? 2 : 1)} s`;
}

export function formatBytes(n: number): string {
  if (!n) return "0 B";
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}

export function formatWhen(iso?: string): string {
  if (!iso) return "—";
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return "—";
  return new Date(t).toISOString().replace("T", " ").replace(/\.\d+Z$/, "Z");
}

/** Seconds until a stamped time, floored at zero. */
export function secondsUntil(iso: string | undefined, now: number): number {
  if (!iso) return 0;
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return 0;
  return Math.max(0, Math.round((t - now) / 1000));
}

/**
 * A needle is a fragment of somebody's real log line, so the screen shows
 * enough to recognise it and nothing more. The length is stated because "how
 * specific is what I armed" is the question an operator actually has.
 */
export function maskNeedle(needle?: string): string {
  const s = (needle ?? "").trim();
  if (!s) return "";
  const head = s.slice(0, 4);
  return `${head}… (${s.length} characters)`;
}

/** The verdict tally, as one sentence. */
export function sessionTally(s: SessionSummary): string {
  return `${s.seen} seen · ${s.not_seen} not seen · ${s.not_observable} not observable`;
}

// ── the command line that does the same thing ───────────────────────────────
//
// Shown next to every action on purpose: an operator who learns the verb here
// can run it from a terminal during an incident, when the screen may be the
// thing that is down.

export function traceCommand(o: { kind: DebugKind; device: string; tenant?: string; ttlSeconds?: number; passive?: boolean; sinceSeconds?: number; path?: string }): string {
  const parts = ["correlix-debug trace", `--kind ${o.kind}`];
  if (o.passive) parts.push("--passive");
  if (o.device) parts.push(`--device ${o.device}`);
  if (o.tenant) parts.push(`--tenant ${o.tenant}`);
  if (o.passive && o.sinceSeconds) parts.push(`--since ${o.sinceSeconds}s`);
  if (o.passive && o.path) parts.push(`--path ${o.path}`);
  if (!o.passive && o.ttlSeconds) parts.push(`--ttl ${o.ttlSeconds}s`);
  return parts.join(" ");
}

export function logsCommand(modules: string[], forSeconds: number): string {
  const list = modules.length ? modules.join(",") : "api";
  return `correlix-debug logs --modules ${list} --for ${forSeconds}s`;
}

export function bundleCommand(sessionId?: string): string {
  return sessionId ? `correlix-debug bundle --session data/debug/${sessionId}` : "correlix-debug bundle --last 1";
}

/**
 * The parser filter has no command-line verb: an injected record carries its
 * own marker and is traced without arming anything, so the switch exists only
 * for a REAL record. The request is shown instead of inventing a verb.
 */
export function parseMarkerCommand(forSeconds: number): string {
  return `PUT /api/debug/parsemarker {"marker":"<needle>","for_seconds":${forSeconds}}`;
}
