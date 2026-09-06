// wanCircuits.model.ts — the rules behind the WAN Paths page's three derived
// surfaces (endpoint registry, circuit list, measurement policy).
//
// WHY A SEPARATE MODEL. Everything on this page except the policy is DERIVED on
// read: the server projects interface-IPs × LLDP/CDP neighbours × the tenant's
// policy into endpoints and 1:1 interface→target links. Nothing is stored, so
// there is no row to inspect when the projection comes back empty — the only way
// to keep the screen honest is to make the derivation rules themselves testable.
// That is what lives here.
//
// TWO HOUSE RULES ARE PINNED IN THIS FILE.
//
//   1. PROVENANCE IS NEVER GUESSED. An interface measures to a directly-connected
//      peer, to an operator-declared ISP next-hop, or to a public reachability
//      anchor — and when none of those could be derived, that is its own bucket
//      with its own words. "No target derived" is a real answer about our
//      derivation, not a zero and not a blank.
//   2. AN ISP NEXT-HOP IS AN OWNERSHIP HANDOFF. `next_hop` is the point where the
//      tenant's ownership of the path ends and the ISP's begins, so it is named
//      in the operator's words ("ISP next-hop") everywhere. There is no hub and
//      no spoke here: every interface measures 1:1 to its own derived target.
//
// The PUT body is built by `policyPatch` alone. The server stamps tenant, author
// and time from the token, so those fields must never leave this page.

import type {
  WanCircuit,
  WanEndpoint,
  WanMeasurementPolicy,
  WanTargetKind,
} from "../services/api";

// ── the measurement baseline the server applies to an unconfigured tenant ────

export const DEFAULT_WAN_PATTERN = "wan|edge|gw|dmz";
export const DEFAULT_ANCHORS: readonly string[] = ["1.1.1.1", "8.8.8.8"];

/** Ceilings the form holds so a paste never builds a body the server refuses. */
export const MAX_NEXT_HOPS = 200;
export const MAX_ANCHORS = 16;

// ── provenance ──────────────────────────────────────────────────────────────

/**
 * The four provenance values, in the order the server derives them: an operator
 * override first, then what the wire tells us, then the fallback, then nothing.
 * Summaries and tables read in this order so the screen always ranks "we know
 * this because an operator said so" above "we guessed a public anchor".
 */
export const TARGET_KIND_ORDER: readonly WanTargetKind[] = [
  "direct_peer",
  "next_hop",
  "anchor",
  "",
];

/** The server's own display wording, so both halves of the product agree. */
const KIND_LABEL: Record<string, string> = {
  direct_peer: "Directly-connected peer",
  next_hop: "ISP next-hop",
  anchor: "Reachability anchor",
  "": "No target derived",
};

/** Short form for a chip, where the row already carries the address. */
const KIND_CHIP: Record<string, string> = {
  direct_peer: "Peer",
  next_hop: "ISP next-hop",
  anchor: "Anchor",
  "": "None derived",
};

/** Tooltip per provenance: who owns the measured path. The reasoning behind each
 *  is an authored file (ai/skills/explain/wan.derived-target.md), reachable from
 *  the `(i)` beside the provenance chips — not repeated on every row. */
const KIND_MEANING: Record<string, string> = {
  direct_peer: "A neighbour on the wire, so the whole path is yours.",
  next_hop: "The ISP next-hop you declared.",
  anchor: "No neighbour and no next-hop, so a public anchor.",
  "": "Nothing was derived, so it is not measured.",
};

/**
 * The operator label for a provenance value. An unrecognised value is returned
 * as it arrived — inventing a label for a kind we do not know would hide a
 * server change behind a friendly word.
 */
export function targetKindLabel(kind: string | undefined | null): string {
  const k = kind ?? "";
  return KIND_LABEL[k] ?? k;
}

/** The chip form of {@link targetKindLabel}. */
export function targetKindChip(kind: string | undefined | null): string {
  const k = kind ?? "";
  return KIND_CHIP[k] ?? k;
}

/** What this provenance means for path ownership, as one sentence. */
export function targetKindMeaning(kind: string | undefined | null): string {
  const k = kind ?? "";
  return KIND_MEANING[k] ?? "Derived a way this screen does not recognise.";
}

/** Sort rank; anything unrecognised sorts after every known kind. */
export function targetKindRank(kind: string | undefined | null): number {
  const i = TARGET_KIND_ORDER.indexOf((kind ?? "") as WanTargetKind);
  return i < 0 ? TARGET_KIND_ORDER.length : i;
}

/**
 * The provenance of one endpoint. An endpoint with no target address has no
 * provenance either, whatever kind the wire carried — the honest bucket wins.
 */
export function endpointKind(ep: Pick<WanEndpoint, "target" | "target_kind">): string {
  if (!ep.target) return "";
  return ep.target_kind ?? "";
}

export interface ProvenanceCount {
  kind: string;
  label: string;
  count: number;
}

/**
 * How many interfaces measure to each kind of target. The four known buckets are
 * always present, zero included: an empty "ISP next-hop" row is the fact that
 * nobody has declared one, and dropping it would hide that.
 */
export function provenanceCounts(endpoints: readonly WanEndpoint[]): ProvenanceCount[] {
  const tally = new Map<string, number>();
  for (const k of TARGET_KIND_ORDER) tally.set(k, 0);
  for (const ep of endpoints) {
    const k = endpointKind(ep);
    tally.set(k, (tally.get(k) ?? 0) + 1);
  }
  return [...tally.entries()]
    .sort((a, b) => targetKindRank(a[0]) - targetKindRank(b[0]) || a[0].localeCompare(b[0]))
    .map(([kind, count]) => ({ kind, label: targetKindLabel(kind), count }));
}

/** Interfaces the projection could not derive any target for. */
export function noTargetCount(endpoints: readonly WanEndpoint[]): number {
  return endpoints.filter((ep) => endpointKind(ep) === "").length;
}

// ── stable ordering for the two derived tables ──────────────────────────────

function byDeviceThenInterface(
  a: { device: string; interface: string },
  b: { device: string; interface: string },
): number {
  return a.device.localeCompare(b.device) || a.interface.localeCompare(b.interface);
}

export function sortEndpoints(endpoints: readonly WanEndpoint[]): WanEndpoint[] {
  return [...endpoints].sort(byDeviceThenInterface);
}

export function sortCircuits(circuits: readonly WanCircuit[]): WanCircuit[] {
  return [...circuits].sort((a, b) => byDeviceThenInterface(a.local, b.local) || a.id.localeCompare(b.id));
}

/** Free-text match across everything a person would search a WAN row by. */
export function matchesEndpoint(ep: WanEndpoint, needle: string): boolean {
  const n = needle.trim().toLowerCase();
  if (!n) return true;
  return [ep.device, ep.interface, ep.address, ep.measurable_addr, ep.site, ep.target, ep.target_label]
    .filter(Boolean)
    .join(" ")
    .toLowerCase()
    .includes(n);
}

export function matchesCircuit(c: WanCircuit, needle: string): boolean {
  const n = needle.trim().toLowerCase();
  if (!n) return true;
  return matchesEndpoint(c.local, n) || matchesEndpoint(c.remote, n) || c.id.toLowerCase().includes(n);
}

// ── ISP next-hop overrides: map ⇄ editable rows ──────────────────────────────

/** One editable override row. `id` is local to the form, never sent. */
export interface NextHopRow {
  id: string;
  key: string;
  target: string;
}

export interface NextHopKeyParts {
  device: string;
  ifName: string;
}

/**
 * Splits a `next_hops` key. A bare device applies to every interface on it; a
 * `device/ifName` key applies to that one interface. Only the FIRST slash
 * separates — an interface name may legitimately carry more (Ethernet1/0/1).
 */
export function parseNextHopKey(key: string): NextHopKeyParts {
  const raw = key.trim();
  const i = raw.indexOf("/");
  if (i < 0) return { device: raw, ifName: "" };
  return { device: raw.slice(0, i).trim(), ifName: raw.slice(i + 1).trim() };
}

/** What a key covers, in the operator's words. */
export function nextHopScope(key: string): string {
  const { device, ifName } = parseNextHopKey(key);
  if (!device) return "Nothing — this override has no device.";
  if (!ifName) return `Every WAN interface on ${device}`;
  return `${device} ${ifName}`;
}

let rowSeq = 0;
/** A fresh blank row. Ids are form-local and monotonic, never sent anywhere. */
export function blankNextHopRow(): NextHopRow {
  rowSeq += 1;
  return { id: `nh-${rowSeq}`, key: "", target: "" };
}

/** The stored map as editable rows, ordered so the form is stable across reads. */
export function nextHopRows(map: Record<string, string> | undefined | null): NextHopRow[] {
  const entries = Object.entries(map ?? {}).sort((a, b) => a[0].localeCompare(b[0]));
  return entries.map(([key, target], i) => ({ id: `nh-stored-${i}-${key}`, key, target }));
}

/** Editable rows back to the wire map. Blank rows are dropped, not sent empty. */
export function nextHopMap(rows: readonly NextHopRow[]): Record<string, string> {
  const out: Record<string, string> = {};
  for (const r of rows) {
    const key = r.key.trim();
    const target = r.target.trim();
    if (!key || !target) continue;
    out[key] = target;
  }
  return out;
}

/** Keys entered more than once, lower-cased and in first-seen order. */
export function duplicateNextHopKeys(rows: readonly NextHopRow[]): string[] {
  const seen = new Set<string>();
  const dupes: string[] = [];
  for (const r of rows) {
    const key = r.key.trim();
    if (!key) continue;
    if (seen.has(key)) {
      if (!dupes.includes(key)) dupes.push(key);
      continue;
    }
    seen.add(key);
  }
  return dupes;
}

/** Every problem with the override table, each as a sentence an operator can act on. */
export function validateNextHops(rows: readonly NextHopRow[]): string[] {
  const problems: string[] = [];
  // A half-filled row is the one real mistake here: a wholly blank row is just an
  // unused slot and is dropped, but a row with one side filled is an intent that
  // would be silently discarded, so it is named.
  const halfFilled = rows.filter((r) => (r.key.trim() === "") !== (r.target.trim() === ""));
  if (halfFilled.some((r) => !r.key.trim())) {
    problems.push("An override names an address but no device — give it a device, or a device and interface.");
  }
  if (halfFilled.some((r) => !r.target.trim())) {
    problems.push("An override names a device but no ISP next-hop address to measure to.");
  }
  for (const key of duplicateNextHopKeys(rows)) {
    problems.push(`Two overrides both apply to ${key} — keep one.`);
  }
  const kept = Object.keys(nextHopMap(rows)).length;
  if (kept > MAX_NEXT_HOPS) {
    problems.push(`Keep ISP next-hop overrides to ${MAX_NEXT_HOPS} or fewer; this has ${kept}.`);
  }
  return problems;
}

// ── reachability anchors: text ⇄ list ───────────────────────────────────────

/**
 * A host we are willing to send to the server: an IP or a name, no whitespace,
 * at least one letter or digit. This is a shape check, not a reachability claim.
 */
export function isPlausibleHost(s: string): boolean {
  const v = s.trim();
  if (!v || v.length > 253) return false;
  if (!/[A-Za-z0-9]/.test(v)) return false;
  return /^[A-Za-z0-9._:[\]%-]+$/.test(v);
}

/** Anchors typed as a comma- or newline-separated list: trimmed and deduped. */
export function parseAnchors(text: string): string[] {
  const out: string[] = [];
  for (const part of text.split(/[\s,;]+/)) {
    const v = part.trim();
    if (!v || out.includes(v)) continue;
    out.push(v);
  }
  return out;
}

/** The stored list as the operator edits it. */
export function formatAnchors(list: readonly string[] | undefined | null): string {
  return (list ?? []).join(", ");
}

export function validateAnchors(text: string): string[] {
  const list = parseAnchors(text);
  const problems: string[] = [];
  if (list.length === 0) {
    problems.push(
      `Name at least one reachability anchor; the measurement baseline is ${DEFAULT_ANCHORS.join(" and ")}.`,
    );
    return problems;
  }
  const bad = list.filter((a) => !isPlausibleHost(a));
  if (bad.length) {
    problems.push(`These are not host names or addresses: ${bad.join(", ")}.`);
  }
  if (list.length > MAX_ANCHORS) {
    problems.push(`Keep anchors to ${MAX_ANCHORS} or fewer; this has ${list.length}.`);
  }
  return problems;
}

// ── the WAN device name pattern ─────────────────────────────────────────────

/**
 * A pre-flight on the pattern. The server is the authority — it compiles the
 * pattern its own way and returns its own sentence — so this only catches what
 * is obviously unusable before a round trip.
 */
export function validatePattern(pattern: string): string[] {
  const v = pattern.trim();
  if (!v) return ["Name the pattern that says which devices are WAN devices."];
  try {
    new RegExp(v, "i");
  } catch {
    return ["That device name pattern could not be read. Check the brackets and slashes."];
  }
  return [];
}

// ── the form ────────────────────────────────────────────────────────────────

export interface PolicyForm {
  pattern: string;
  anchorsText: string;
  includeConnected: boolean;
  nextHops: NextHopRow[];
}

/** The stored policy as an editable form. A tenant that never saved gets the baseline. */
export function formFromPolicy(p: WanMeasurementPolicy | null | undefined): PolicyForm {
  return {
    pattern: p?.wan_pattern?.trim() || DEFAULT_WAN_PATTERN,
    anchorsText: formatAnchors(p?.anchors?.length ? p.anchors : [...DEFAULT_ANCHORS]),
    includeConnected: p?.include_connected ?? true,
    nextHops: nextHopRows(p?.next_hops),
  };
}

/**
 * The EXACT PUT body. Only the four intent fields travel: the server stamps the
 * tenant from the token (a tenant in the body is ignored) and stamps the author
 * and the time itself, so sending them back would be us asserting ownership we
 * do not have.
 */
export function policyPatch(form: PolicyForm): WanMeasurementPolicy {
  return {
    wan_pattern: form.pattern.trim(),
    anchors: parseAnchors(form.anchorsText),
    next_hops: nextHopMap(form.nextHops),
    include_connected: form.includeConnected,
  };
}

/** Every problem with the form, in the order the fields appear. */
export function validateForm(form: PolicyForm): string[] {
  return [
    ...validatePattern(form.pattern),
    ...validateAnchors(form.anchorsText),
    ...validateNextHops(form.nextHops),
  ];
}

/**
 * True when the form would change what is stored. Both sides go through
 * `policyPatch`, so re-ordering rows or re-spacing the anchor list is not a
 * change and does not arm the save button.
 */
export function isDirty(form: PolicyForm, stored: WanMeasurementPolicy | null | undefined): boolean {
  const a = policyPatch(form);
  const b = policyPatch(formFromPolicy(stored));
  return (
    a.wan_pattern !== b.wan_pattern ||
    a.include_connected !== b.include_connected ||
    (a.anchors ?? []).join(" ") !== (b.anchors ?? []).join(" ") ||
    stableMap(a.next_hops) !== stableMap(b.next_hops)
  );
}

function stableMap(m: Record<string, string> | undefined): string {
  return Object.entries(m ?? {})
    .sort((x, y) => x[0].localeCompare(y[0]))
    .map(([k, v]) => `${k}${v}`)
    .join(" ");
}
