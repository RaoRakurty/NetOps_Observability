// canvasUrlState.ts — the topology canvas's shareable STATE, serialized into the
// route's query string.
//
// Why this exists: mode / overlay / domain / group-by / arrangement / selection all
// lived in `useState` only. An operator who had narrowed the canvas to exactly the
// thing they were looking at could not send that view to a colleague, and F5 threw
// it away — the investigation existed only in one browser tab. A shared canvas link
// is the cheapest handover an on-call has.
//
// ZERO TRUST (CLAUDE.md §3): the hash is an INPUT. Every value is validated against
// the closed set that owns it — an unknown mode/overlay/domain/dimension/archetype
// is IGNORED (the caller keeps its default), never applied. Selection ids cannot be
// validated here (no view), so they are only length/charset-bounded and the canvas
// applies them solely when the loaded view actually contains that id.
//
// Pure: read/format are side-effect free; only `writeCanvasUrlState` touches history.

import type { OverlayKind, WorkflowMode } from "../api/topologyTypes";
import type { NetworkDomain } from "./topologyDomains";
import type { GroupDimension } from "./topologyRegroup";
import type { Archetype } from "./topologyArchetype";

/** Arrangement control: "auto" (detected) or a forced archetype. */
export type Arrangement = "auto" | Archetype;

export type CanvasUrlState = {
  mode: WorkflowMode;
  overlay: OverlayKind;
  domain: NetworkDomain;
  groupBy: GroupDimension;
  arrange: Arrangement;
  /** Exactly one of these at a time (the canvas's TopologySelection). */
  nodeId?: string;
  edgeId?: string;
  groupId?: string;
};

/** The canvas's own defaults. A value equal to its default is OMITTED from the
 *  query, so the default canvas keeps a clean, unchanged URL. */
export const CANVAS_URL_DEFAULTS: Readonly<Pick<CanvasUrlState, "mode" | "overlay" | "domain" | "groupBy" | "arrange">> = {
  mode: "explore",
  overlay: "health",
  domain: "lan",
  groupBy: "site",
  arrange: "auto",
};

// ── closed sets (the ONLY accepted values) ────────────────────────────────────
const MODES: readonly WorkflowMode[] = [
  "explore", "investigate", "path_trace", "change_review", "capacity", "dependency", "executive_geo",
];
const OVERLAYS: readonly OverlayKind[] = [
  "health", "utilization", "interface_errors", "routing_changes", "config_drift",
  "syslog", "flow", "rca_evidence", "golden_path_delta", "historical_diff",
];
const DOMAINS_SET: readonly NetworkDomain[] = ["lan", "sdwan", "dc", "cloud"];
const GROUP_DIMS: readonly GroupDimension[] = ["site", "zone", "role", "vendor", "owner", "region", "vpc", "none"];
// "irregular" is a DETECTION verdict, never an operator choice — the toolbar
// offers ARCHETYPES only, so it is not accepted from a link either.
const ARRANGEMENTS: readonly Arrangement[] = ["auto", "leaf_spine", "ring", "star", "bus", "mesh"];

/** Selection ids are opaque to this module; bound them so a hostile hash cannot
 *  push an unbounded string into React state or a later fetch. */
const MAX_ID_LEN = 256;
// eslint-disable-next-line no-control-regex
const CONTROL_CHARS = /[\u0000-\u001f\u007f]/;

function pickFrom<T extends string>(raw: string | null, allowed: readonly T[]): T | undefined {
  if (!raw) return undefined;
  return (allowed as readonly string[]).includes(raw) ? (raw as T) : undefined;
}

function pickId(raw: string | null): string | undefined {
  if (!raw) return undefined;
  const v = raw.trim();
  if (!v || v.length > MAX_ID_LEN || CONTROL_CHARS.test(v)) return undefined;
  return v;
}

/** The query string of a hash route ("#/a/b?x=1" → "x=1"). */
export function hashQuery(hash: string): string {
  const i = hash.indexOf("?");
  return i < 0 ? "" : hash.slice(i + 1);
}

/** The path part of a hash route ("#/a/b?x=1" → "#/a/b"). */
export function hashPath(hash: string): string {
  const i = hash.indexOf("?");
  return i < 0 ? hash : hash.slice(0, i);
}

/**
 * Parse the canvas state out of a hash route. Only recognised keys with values
 * from their closed set survive; everything else is dropped silently — a bad link
 * degrades to the default canvas, it never renders a half-applied state.
 */
export function readCanvasUrlState(hash: string): Partial<CanvasUrlState> {
  const p = new URLSearchParams(hashQuery(hash || ""));
  const out: Partial<CanvasUrlState> = {};
  const mode = pickFrom(p.get("mode"), MODES);
  if (mode) out.mode = mode;
  const overlay = pickFrom(p.get("overlay"), OVERLAYS);
  if (overlay) out.overlay = overlay;
  const domain = pickFrom(p.get("domain"), DOMAINS_SET);
  if (domain) out.domain = domain;
  const groupBy = pickFrom(p.get("group"), GROUP_DIMS);
  if (groupBy) out.groupBy = groupBy;
  const arrange = pickFrom(p.get("arrange"), ARRANGEMENTS);
  if (arrange) out.arrange = arrange;
  // Selection is single-valued: node wins over edge wins over group, so a
  // hand-edited link carrying two can never open two inspectors at once.
  const node = pickId(p.get("node"));
  const edge = pickId(p.get("edge"));
  const group = pickId(p.get("group_id"));
  if (node) out.nodeId = node;
  else if (edge) out.edgeId = edge;
  else if (group) out.groupId = group;
  return out;
}

/**
 * Format the canvas state as a query string. Defaults are omitted and the key
 * order is FIXED, so the same canvas always produces the same link (two operators
 * comparing URLs must not see spurious differences).
 */
export function canvasUrlQuery(state: Partial<CanvasUrlState>): string {
  const p = new URLSearchParams();
  if (state.mode && state.mode !== CANVAS_URL_DEFAULTS.mode) p.set("mode", state.mode);
  if (state.overlay && state.overlay !== CANVAS_URL_DEFAULTS.overlay) p.set("overlay", state.overlay);
  if (state.domain && state.domain !== CANVAS_URL_DEFAULTS.domain) p.set("domain", state.domain);
  if (state.groupBy && state.groupBy !== CANVAS_URL_DEFAULTS.groupBy) p.set("group", state.groupBy);
  if (state.arrange && state.arrange !== CANVAS_URL_DEFAULTS.arrange) p.set("arrange", state.arrange);
  if (state.nodeId) p.set("node", state.nodeId);
  else if (state.edgeId) p.set("edge", state.edgeId);
  else if (state.groupId) p.set("group_id", state.groupId);
  return p.toString();
}

/** The query keys this module owns. Anything else on the route belongs to another
 *  component and is preserved verbatim. */
const OWNED_KEYS = ["mode", "overlay", "domain", "group", "arrange", "node", "edge", "group_id"];

/**
 * Write the state back onto the current hash route with `replaceState`.
 *
 * replaceState, not pushState: the canvas rewrites this on every overlay flick and
 * every click, and a back button that walks 40 spotlight changes is worse than no
 * history at all. Query keys the canvas does not own are carried through untouched —
 * the canvas is not the only thing that can be mounted on a route. Returns the hash
 * it wrote (or the unchanged one), so callers/tests do not have to read `location`.
 */
export function writeCanvasUrlState(state: Partial<CanvasUrlState>, hash: string): string {
  const foreign = new URLSearchParams(hashQuery(hash || ""));
  for (const k of OWNED_KEYS) foreign.delete(k);
  const mine = canvasUrlQuery(state);
  const rest = foreign.toString();
  const q = [mine, rest].filter(Boolean).join("&");
  const next = q ? `${hashPath(hash)}?${q}` : hashPath(hash);
  if (next === hash) return hash;
  if (typeof window !== "undefined" && window.history?.replaceState) {
    window.history.replaceState(null, "", next);
  }
  return next;
}
