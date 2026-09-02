// igpModel.ts — the PURE model behind the OSPF / IS-IS adjacency view.
//
// Everything a reader's verdict depends on is decided here and unit-tested,
// because the panel's whole job is to be honest about a thing that is only
// partly collected:
//
//   • a count that was never measured renders as "not collected", NEVER as 0;
//   • "the source is wired and quiet" (empty) and "the source was never wired"
//     (not_connected) are different facts and are never collapsed into one;
//   • a failed fetch is an error, never a reassuring blank.
//
// The five render states are the InvestigationLanes vocabulary, deliberately
// reused so the two Troubleshooting surfaces read the same way.

import type {
  IgpAdjacenciesResponse,
  IgpAdjacency,
  IgpCoverage,
  IgpHealthResponse,
  IgpProto,
  IgpSummaryResponse,
} from "../../services/api";

export type IgpState = "loading" | "error" | "not_connected" | "empty" | "ready";

/** One panel's outcome: the state, the sentence that state prints, and the
 *  payload (only ever set when state === "ready"). */
export interface IgpResult<T> {
  state: IgpState;
  note: string;
  data?: T;
}

export const igpLoading = <T,>(): IgpResult<T> => ({ state: "loading", note: "" });

/** igpError renders a fetch failure as a failure. It never becomes an empty
 *  list: an unreachable API is not evidence that the network is fine. */
export function igpError<T>(err: unknown): IgpResult<T> {
  const msg = err instanceof Error ? err.message : String(err ?? "request failed");
  return { state: "error", note: `Could not read this protocol's adjacency data: ${msg}` };
}

export const PROTO_LABEL: Record<IgpProto, string> = { ospf: "OSPF", isis: "IS-IS" };

/** The MIB vocabularies the backend decodes to, shown so a reader can check the
 *  state name against the device. */
export const PROTO_STATES: Record<IgpProto, string> = {
  ospf: "1 down · 2 attempt · 3 init · 4 twoWay · 5 exchangeStart · 6 exchange · 7 loading · 8 full",
  isis: "1 down · 2 init · 3 up · 4 failed",
};

/** The neighbour identity each protocol speaks. */
export const PEER_LABEL: Record<IgpProto, string> = {
  ospf: "Neighbour (router/interface address)",
  isis: "Neighbour (IS-IS system-id)",
};

// ── coverage ────────────────────────────────────────────────────────────────

/** One row of the coverage strip. `collected:false` MUST render as
 *  "not collected", never as a zero and never as a green tick. */
export interface CoverageChip {
  id: "events" | "live_series" | "lsdb";
  label: string;
  collected: boolean;
  detail: string;
}

const COVERAGE_LABEL: Record<CoverageChip["id"], string> = {
  events: "Change events",
  live_series: "Live adjacency state",
  lsdb: "LSDB / LSP count",
};

/** coverageChips turns the response's coverage block plus its notes into the
 *  strip. The DETAIL for an absent source is the server's own note when it sent
 *  one — the server knows why the source is absent on THIS deployment, and
 *  inventing a client-side reason is how a UI starts lying. */
export function coverageChips(cov: IgpCoverage | undefined, notes: string[] | undefined): CoverageChip[] {
  const c: IgpCoverage = cov ?? { events: false, live_series: false, lsdb: false };
  const ns = notes ?? [];
  const noteFor = (needle: string) => ns.find((n) => n.toLowerCase().includes(needle)) ?? "";
  return [
    {
      id: "events",
      label: COVERAGE_LABEL.events,
      collected: c.events,
      detail: c.events
        ? "syslog + SNMP-trap adjacency changes, from the correlation spine"
        : noteFor("correlation store") || "The adjacency-change signal store did not answer.",
    },
    {
      id: "live_series",
      label: COVERAGE_LABEL.live_series,
      collected: c.live_series,
      detail: c.live_series
        ? "a live adjacency-state series is collected for these devices"
        : noteFor("live series") || "No live adjacency-state series is collected here.",
    },
    {
      id: "lsdb",
      label: COVERAGE_LABEL.lsdb,
      collected: c.lsdb,
      detail: c.lsdb
        ? "an LSDB / LSP-count series is collected for these devices"
        : noteFor("lsdb") || "No LSDB / LSP-count series is collected on this deployment.",
    },
  ];
}

/** Formats a nullable count. `null` is the module's "nobody is watching" and is
 *  rendered as a phrase, never as a digit — this single function is what keeps
 *  an uncollected source from ever appearing as 0. */
export function countOrNotCollected(n: number | null | undefined): string {
  return typeof n === "number" ? String(n) : "not collected";
}

/** True when the value is a real measurement (so a tone/colour may be applied).
 *  An absent value gets no tone: nothing green, nothing red. */
export const isMeasured = (n: number | null | undefined): n is number => typeof n === "number";

// ── per-panel classification ────────────────────────────────────────────────

/** classifyAdjacencies decides the adjacency panel's state.
 *
 *  not_connected is reserved for the honest case where NEITHER evidence class
 *  answered — the protocol is simply not observed here. If a source answered
 *  and there is nothing in the window, that is `empty`, which is a different
 *  (and much better) fact. */
export function classifyAdjacencies(r: IgpAdjacenciesResponse | undefined): IgpResult<IgpAdjacenciesResponse> {
  if (!r) return { state: "error", note: "The server returned no adjacency payload." };
  const cov = r.coverage ?? { events: false, live_series: false, lsdb: false };
  if (!cov.events && !cov.live_series) {
    return { state: "not_connected", note: notConnectedNote(r.protocol, r.notes) };
  }
  const rows = r.adjacencies ?? [];
  if (rows.length === 0) {
    return {
      state: "empty",
      note: `No ${PROTO_LABEL[r.protocol]} adjacency was reported in this window. The sources answered — there is nothing to show, which is not the same as nothing being collected.`,
      data: r,
    };
  }
  return { state: "ready", note: "", data: r };
}

export function classifySummary(r: IgpSummaryResponse | undefined): IgpResult<IgpSummaryResponse> {
  if (!r) return { state: "error", note: "The server returned no summary payload." };
  const cov = r.coverage ?? { events: false, live_series: false, lsdb: false };
  if (!cov.events && !cov.live_series) {
    return { state: "not_connected", note: notConnectedNote(r.protocol, r.notes) };
  }
  if ((r.devices ?? []).length === 0) {
    return {
      state: "empty",
      note: `No device reported ${PROTO_LABEL[r.protocol]} activity in this window.`,
      data: r,
    };
  }
  return { state: "ready", note: "", data: r };
}

/** health is per-device and stays `ready` whenever the server answered: its
 *  value is the honest null-vs-number distinction in each field, so blanking
 *  the whole panel would hide exactly what it exists to say. */
export function classifyHealth(r: IgpHealthResponse | undefined): IgpResult<IgpHealthResponse> {
  if (!r) return { state: "error", note: "The server returned no health payload." };
  const cov = r.coverage ?? { events: false, live_series: false, lsdb: false };
  if (!cov.events && !cov.live_series) {
    return { state: "not_connected", note: notConnectedNote(r.protocol, r.notes) };
  }
  return { state: "ready", note: "", data: r };
}

function notConnectedNote(proto: IgpProto, notes: string[] | undefined): string {
  const server = (notes ?? []).filter(Boolean);
  const why = server.length ? ` ${server.join(" ")}` : "";
  return `${PROTO_LABEL[proto]} is not observed on this deployment: neither adjacency-change events nor a live adjacency-state series answered.${why}`;
}

// ── per-adjacency presentation ──────────────────────────────────────────────

export type AdjTone = "good" | "bad" | "warn" | "";

/** adjTone colours a row ONLY from the live verdict. An event-only adjacency
 *  gets no colour: the last thing we were told is not the state now. */
export function adjTone(a: Pick<IgpAdjacency, "up" | "state_source">): AdjTone {
  if (a.state_source !== "live_series" || typeof a.up !== "boolean") return "";
  return a.up ? "good" : "bad";
}

/** stateSourceLabel names WHERE the shown state came from, so a reader never
 *  has to guess whether they are looking at "now" or at "last reported". */
export function stateSourceLabel(a: Pick<IgpAdjacency, "state_source" | "last_change">): string {
  switch (a.state_source) {
    case "live_series":
      return "live";
    case "events":
      return a.last_change ? "last reported" : "reported";
    default:
      return "not reported";
  }
}

/** currentStateLabel — the state text, with the honest fallback. */
export function currentStateLabel(a: Pick<IgpAdjacency, "current_state">): string {
  const s = (a.current_state ?? "").trim();
  return s === "" ? "not reported" : s;
}

/** adjKey is a stable React key for an adjacency row. */
export const adjKey = (a: Pick<IgpAdjacency, "device" | "peer">) => `${a.device} ${a.peer ?? ""}`;

/** timelineDots renders the newest-first timeline as oldest→newest ticks, which
 *  is how an operator reads a flap history. It is capped so a 200-event
 *  timeline cannot blow out the row. */
export interface TimelineTick {
  key: string;
  state: "up" | "down" | "unknown";
  ts: string;
  source: string;
}
export function timelineTicks(a: Pick<IgpAdjacency, "timeline">, cap = 40): TimelineTick[] {
  const tl = a.timeline ?? [];
  return tl
    .slice(0, cap)
    .map((e) => ({ key: e.signal_id, state: e.state, ts: e.ts, source: e.source }))
    .reverse();
}

/** worstFirst is the display order for adjacency rows: down-now first, then the
 *  most flaps, then device/peer. The server sorts by (device, peer) for a
 *  stable page; the operator wants the broken ones on top. */
export function worstFirst(rows: IgpAdjacency[]): IgpAdjacency[] {
  const rank = (a: IgpAdjacency) => (a.state_source === "live_series" && a.up === false ? 0 : 1);
  return [...(rows ?? [])].sort((a, b) => {
    if (rank(a) !== rank(b)) return rank(a) - rank(b);
    if (a.flaps !== b.flaps) return b.flaps - a.flaps;
    if (a.device !== b.device) return a.device < b.device ? -1 : 1;
    return (a.peer ?? "") < (b.peer ?? "") ? -1 : 1;
  });
}

/** liveCounts folds the rows into the header tallies. Every field is nullable:
 *  with no live series there is no honest count of what is up or down, only a
 *  count of adjacencies we have HEARD ABOUT. */
export interface AdjCounts {
  reported: number;
  live: number | null;
  up: number | null;
  down: number | null;
  flaps: number;
}
export function adjCounts(rows: IgpAdjacency[] | undefined, liveCollected: boolean): AdjCounts {
  const list = rows ?? [];
  const flaps = list.reduce((n, a) => n + (a.flaps || 0), 0);
  if (!liveCollected) {
    return { reported: list.length, live: null, up: null, down: null, flaps };
  }
  let live = 0;
  let up = 0;
  let down = 0;
  for (const a of list) {
    if (a.state_source !== "live_series" || typeof a.up !== "boolean") continue;
    live++;
    if (a.up) up++;
    else down++;
  }
  return { reported: list.length, live, up, down, flaps };
}

/** windowLabel renders the honored window the server reported back — never the
 *  one the client asked for, because the two can differ. */
export function windowLabel(seconds: number | undefined): string {
  const s = Number(seconds) || 0;
  if (s <= 0) return "—";
  if (s % 86400 === 0) return `${s / 86400}d`;
  if (s % 3600 === 0) return `${s / 3600}h`;
  if (s % 60 === 0) return `${s / 60}m`;
  return `${s}s`;
}

/** The windows the picker offers. Each is inside the server's 1m..7d bound, so
 *  the UI can never send a value it knows will be refused. */
export const IGP_WINDOWS: { value: string; label: string }[] = [
  { value: "1h", label: "1h" },
  { value: "6h", label: "6h" },
  { value: "24h", label: "24h" },
  { value: "7d", label: "7d" },
];
