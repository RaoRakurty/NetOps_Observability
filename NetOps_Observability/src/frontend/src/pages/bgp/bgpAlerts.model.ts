// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// bgpAlerts.model.ts — the PURE model behind the Prefixes, Peers and Bogons
// views. No React, no fetch: everything here is a function of the wire shape,
// which is why it is the part that carries the tests.
//
// The one rule that runs through all of it: an ABSENT measurement never renders
// as a healthy one. `unknown` gets its own presentation, "no router is
// exporting" is a distinct state from "no peer is down", and a disabled
// evaluator is stated rather than shown as an empty list.

import type {
  BgpIncident, BgpIncidentClass, BgpAlertStatus, BgpBogonSighting,
  BgpAlertConfigResp, BgpAlertPolicy, BgpAlertPolicyConfig,
  PromInstantResponse,
} from "../../services/api";

export type ClassTone = { label: string; tone: string; detail: string };

/**
 * Map an incident class onto its chip. Worst-first ordering is the API's; this
 * is only the presentation, and `unknown` is deliberately NOT green.
 *
 * The LABEL is what a NOC admin reads at 2am, so it says what happened in
 * ordinary words ("Origin changed", "Not fully visible"); the protocol name it
 * comes from lives in the `detail` tooltip, which is where an engineer looks.
 * (Owner, 2026-09-06: "too much jargon … NOC admin doesn't need all the
 * jargon.") The class KEY on the wire is untouched — only the wording changed.
 */
export function incidentTone(c: BgpIncidentClass | undefined): ClassTone {
  switch (c) {
    case "origin_change":
      return {
        label: "Origin changed", tone: "var(--crit)",
        detail: "Someone else is announcing this prefix: an AS outside the expected origin set. Possible hijack.",
      };
    case "rpki_invalid":
      return {
        label: "Origin not authorised", tone: "var(--crit)",
        detail: "RPKI invalid — the announcement breaks a published ROA. A stale ROA and a hijack look identical here.",
      };
    case "bogon":
      return {
        label: "Reserved address routed", tone: "var(--crit)",
        detail: "Bogon — this prefix is reserved or undelegated space and must never appear in the global routing table.",
      };
    case "route_leak":
      return {
        label: "Unexpected transit", tone: "var(--warn)",
        detail: "Route leak — a carrier outside your declared upstream set is carrying this prefix.",
      };
    case "visibility_loss":
      return {
        label: "Not fully visible", tone: "var(--warn)",
        detail: "Fewer public route collectors see this prefix than your threshold allows — part of the internet cannot reach it.",
      };
    case "none":
      return {
        label: "Healthy", tone: "var(--ok)",
        detail: "Checked and clean: announced, origin authorised, visible to enough collectors.",
      };
    default:
      return {
        label: "Not checked", tone: "var(--muted)",
        detail: "The routing lookup did not answer. This is a missing check, not a clean prefix.",
      };
  }
}

/** Counts per class for a summary strip. `unknown` is counted separately from
 *  `none` on purpose — collapsing them would overstate coverage. */
export function incidentSummary(incidents: BgpIncident[]): Record<BgpIncidentClass, number> {
  const out: Record<BgpIncidentClass, number> = {
    origin_change: 0, rpki_invalid: 0, bogon: 0, route_leak: 0,
    visibility_loss: 0, none: 0, unknown: 0,
  };
  for (const i of incidents) out[i.class] = (out[i.class] ?? 0) + 1;
  return out;
}

/** Render one AS path as hop labels. Kept here (not in JSX) so the numeric
 *  formatting is testable. */
export function pathLabel(path: number[] | undefined): string {
  return (path ?? []).map((a) => `AS${a}`).join(" → ");
}

/** The one-line honest state of the evaluator, for a status strip. Returns ""
 *  when there is nothing worth saying. */
export function alertStatusLine(st: BgpAlertStatus | undefined): string {
  if (!st) return "";
  if (!st.enabled) return st.note || "BGP alerting is off.";
  if (st.last_error) return `Last pass reported: ${st.last_error}`;
  if (!st.runs) return st.note || "The evaluator has not completed a pass yet.";
  return "";
}

// ── Peers ───────────────────────────────────────────────────────────────────

/** One row of the Peers table, from EITHER source. `source` is kept because a
 *  BMP peer and a device metric are different witnesses and an operator has to
 *  know which one is talking. */
export type PeerRow = {
  key: string;
  device: string;
  peer: string;
  peerAs?: number;
  state: "up" | "down" | "unknown";
  source: "bmp" | "device";
  session?: string;
  changedAt?: string;
  reason?: string;
  rib?: string;
  announced?: number;
  withdrawn?: number;
};

/** BMP session views → peer rows. A peer the receiver has never seen a Peer Up
 *  or Peer Down for is "unknown", NEVER assumed up. */
export function peerRowsFromSessions(
  sessions: { id: string; device_id: string; peers?: { address: string; as: number; state: string; changed_at?: string; down_reason?: string; rib?: string; announced_prefixes?: number; withdrawn_prefixes?: number }[] }[] | undefined,
): PeerRow[] {
  const out: PeerRow[] = [];
  for (const s of sessions ?? []) {
    for (const p of s.peers ?? []) {
      out.push({
        key: `bmp:${s.id}:${p.address}`,
        device: s.device_id, peer: p.address, peerAs: p.as,
        state: p.state === "up" ? "up" : p.state === "down" ? "down" : "unknown",
        source: "bmp", session: s.id, changedAt: p.changed_at, reason: p.down_reason,
        rib: p.rib, announced: p.announced_prefixes, withdrawn: p.withdrawn_prefixes,
      });
    }
  }
  return out;
}

/** `device_bgp_peer_state` samples → peer rows.
 *
 *  The BGP4-MIB bgpPeerState enum is 1..6 and only 6 is `established`. Anything
 *  else is a session that is NOT carrying routes, so it renders as down; a
 *  sample we cannot read as a number is "unknown", never "up" — a metric we
 *  could not parse is an absent measurement. */
export function peerRowsFromMetrics(resp: PromInstantResponse | null | undefined): PeerRow[] {
  const out: PeerRow[] = [];
  for (const s of resp?.data?.result ?? []) {
    const device = s.metric.device || s.metric.instance || "";
    const peer = s.metric.peer || s.metric.index || s.metric.neighbor || "";
    if (!device && !peer) continue;
    const raw = Number(s.value?.[1]);
    const state: PeerRow["state"] = Number.isFinite(raw) ? (raw === 6 ? "up" : "down") : "unknown";
    out.push({ key: `dev:${device}:${peer}`, device, peer, state, source: "device" });
  }
  return out;
}

/** Merge both sources into one table. A BMP row WINS over a device-metric row
 *  for the same (device, peer): BMP carries the transition reason and the
 *  counters, and showing the same peer twice would double-count the fleet. */
export function mergePeerRows(bmp: PeerRow[], device: PeerRow[]): PeerRow[] {
  const seen = new Set(bmp.map((r) => `${r.device}|${r.peer}`));
  const out = [...bmp];
  for (const r of device) {
    if (seen.has(`${r.device}|${r.peer}`)) continue;
    out.push(r);
  }
  const rank = { down: 0, unknown: 1, up: 2 } as const;
  return out.sort((a, b) =>
    rank[a.state] - rank[b.state] ||
    a.device.localeCompare(b.device) ||
    a.peer.localeCompare(b.peer));
}

/** The five honest states of the Peers tab. Each one is a DIFFERENT sentence,
 *  because "the feature is off", "nothing is exporting" and "every peer is up"
 *  must never look alike. */
export type PeersState =
  | "bmp_off"          // FEATURE_BMP is off — the receiver is not even running
  | "no_exporter"      // the receiver is up but no router is pushing to it
  | "no_peers"         // sessions exist but carry no peers we have seen state for
  | "rows"             // we have rows to show
  | "error";           // the read itself failed

export function peersState(args: {
  error?: boolean;
  bmpAvailable: boolean;
  sessions: number;
  rows: number;
}): PeersState {
  if (args.error) return "error";
  if (!args.bmpAvailable && args.rows === 0) return "bmp_off";
  if (args.sessions === 0 && args.rows === 0) return "no_exporter";
  if (args.rows === 0) return "no_peers";
  return "rows";
}

/** The transit set observed for a prefix, newest observation first, with the
 *  hop adjacent to the origin marked — that hop is the tenant's actual upstream
 *  and is what a "transit changed" chip is about. */
export function transitSet(inc: BgpIncident | undefined): { asn: number; adjacent: boolean }[] {
  const seen = new Map<number, boolean>();
  for (const p of inc?.evidence?.paths ?? []) {
    if (p.length < 2) continue;
    const adj = p[p.length - 2];
    for (let i = 0; i < p.length - 1; i++) {
      const asn = p[i];
      seen.set(asn, (seen.get(asn) ?? false) || asn === adj);
    }
  }
  return [...seen.entries()]
    .map(([asn, adjacent]) => ({ asn, adjacent }))
    .sort((a, b) => Number(b.adjacent) - Number(a.adjacent) || a.asn - b.asn);
}

// ── Bogons ──────────────────────────────────────────────────────────────────

/** Group sightings by the reserved block that matched, so the table reads as
 *  "who is announcing 10/8 at us" rather than as an undifferentiated list. */
export function groupSightings(rows: BgpBogonSighting[]): { block: string; why: string; rows: BgpBogonSighting[] }[] {
  const by = new Map<string, { block: string; why: string; rows: BgpBogonSighting[] }>();
  for (const r of rows) {
    const key = r.entry?.block || r.prefix;
    const g = by.get(key) ?? { block: key, why: r.entry?.why ?? "", rows: [] };
    g.rows.push(r);
    by.set(key, g);
  }
  return [...by.values()].sort((a, b) => b.rows.length - a.rows.length || a.block.localeCompare(b.block));
}

// ── Alert policy (thresholds + declared sets) ────────────────────────────────
//
// The policy is the only OPERATOR INTENT the BGP alerting evaluator reads. Two
// of its four fields carry a consequence that an empty value does not announce,
// and the editor is where that has to be said, because the wire cannot say it:
//
//   * `expected_origins` empty  ⇒ the origin baseline is LEARNED from the first
//     observation and marked as learned. That is not "no origin checking"; it
//     is a weaker check whose baseline nobody declared.
//   * `upstreams` empty         ⇒ the route-leak heuristic DOES NOT RUN. There
//     is nothing to call unexpected, so a quiet leak column means unmeasured,
//     not clean.
//
// Everything below is pure so those rules are testable without a browser. The
// server (internal/bgpwatch/http.go + state.go Normalize) remains the authority
// and re-validates every PUT; these mirrors exist so a typo says WHICH field is
// wrong inline instead of coming back as an opaque 400.

/** One policy block as the operator edits it: ASN sets stay TEXT so the
 *  notation typed ("AS64500" or "64500") survives until it is parsed. */
export interface PolicyConfigForm {
  expectedOrigins: string;
  upstreams: string;
  minVisibility: string;
  minVantages: string;
}

export interface PolicyForm {
  def: PolicyConfigForm;
  /** Per-prefix overrides, kept as an ORDERED list so a row can be edited and
   *  removed without a map's key churn reordering the table under the cursor. */
  prefixes: { key: string; cfg: PolicyConfigForm }[];
}

export const EMPTY_POLICY_CONFIG: PolicyConfigForm = {
  expectedOrigins: "", upstreams: "", minVisibility: "", minVantages: "",
};

/** The server's caps, with the documented fallbacks for a response that did not
 *  carry them. Never invent a looser cap than the server enforces. */
export interface PolicyLimits {
  minVisibility: number;
  minVantages: number;
  maxPrefixes: number;
  maxAsnsPerSet: number;
}

export const POLICY_LIMIT_FALLBACK: PolicyLimits = {
  minVisibility: 0.5, minVantages: 2, maxPrefixes: 200, maxAsnsPerSet: 32,
};

export function policyLimits(resp: BgpAlertConfigResp | null): PolicyLimits {
  const d = resp?.defaults;
  return {
    minVisibility: typeof d?.min_visibility === "number" ? d.min_visibility : POLICY_LIMIT_FALLBACK.minVisibility,
    minVantages: typeof d?.min_vantages === "number" ? d.min_vantages : POLICY_LIMIT_FALLBACK.minVantages,
    maxPrefixes: typeof d?.max_prefixes === "number" ? d.max_prefixes : POLICY_LIMIT_FALLBACK.maxPrefixes,
    maxAsnsPerSet: typeof d?.max_asns_per_set === "number" ? d.max_asns_per_set : POLICY_LIMIT_FALLBACK.maxAsnsPerSet,
  };
}

const num = (n: number | undefined): string => (n === undefined || n === 0 ? "" : String(n));

export function configForm(c: BgpAlertPolicyConfig | undefined): PolicyConfigForm {
  return {
    expectedOrigins: (c?.expected_origins ?? []).join(", "),
    upstreams: (c?.upstreams ?? []).join(", "),
    minVisibility: num(c?.min_visibility),
    minVantages: num(c?.min_vantages),
  };
}

/** The stored policy as a form. Prefix rows come back in the key order the
 *  server sorted them into, which is the order Normalize() guarantees. */
export function policyForm(resp: BgpAlertConfigResp | null): PolicyForm {
  const cfg: BgpAlertPolicy | undefined = resp?.config;
  const prefixes = Object.entries(cfg?.prefixes ?? {})
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([key, c]) => ({ key, cfg: configForm(c) }));
  return { def: configForm(cfg?.default), prefixes };
}

/** ASN list parsing that mirrors ParseASN (helpers.go): an optional "AS"
 *  prefix, a 32-bit decimal, and AS0 refused as reserved (RFC 7607). The
 *  operator's own notation is what goes back on the wire. */
export function parseAsnList(raw: string, cap: number): { list: string[]; error?: string } {
  const tokens = raw.split(/[\s,;]+/).map((t) => t.trim()).filter(Boolean);
  const list: string[] = [];
  const seen = new Set<string>();
  for (const t of tokens) {
    const digits = t.replace(/^[Aa][Ss]/, "");
    if (!/^\d{1,10}$/.test(digits)) {
      return { list: [], error: `${t} is not an AS number.` };
    }
    const n = Number(digits);
    if (n === 0) return { list: [], error: "AS0 is reserved and is never a real AS number." };
    if (n > 4294967295) return { list: [], error: `${t} is above the largest AS number (4294967295).` };
    if (seen.has(digits)) continue; // the server dedupes too; do it before the cap
    seen.add(digits);
    list.push(t);
  }
  if (list.length > cap) return { list: [], error: `At most ${cap} AS numbers per set; this one has ${list.length}.` };
  return { list };
}

/** A policy key must be a prefix — the server parses it and stores the
 *  CANONICAL form, so "193.0.0.1/21" comes back as "193.0.0.0/21". */
export function isPrefixKey(raw: string): boolean {
  const s = raw.trim();
  const slash = s.indexOf("/");
  if (slash <= 0) return false;
  const addr = s.slice(0, slash);
  const bits = s.slice(slash + 1);
  if (!/^\d{1,3}$/.test(bits)) return false;
  const b = Number(bits);
  if (addr.includes(":")) return b <= 128 && /^[0-9A-Fa-f:.]+$/.test(addr);
  const octets = addr.split(".");
  return b <= 32 && octets.length === 4 && octets.every((o) => /^\d{1,3}$/.test(o) && Number(o) <= 255);
}

export type PolicyFieldErrors = Record<string, string>;

function validateConfig(c: PolicyConfigForm, limits: PolicyLimits, keyPrefix: string, errs: PolicyFieldErrors): void {
  const origins = parseAsnList(c.expectedOrigins, limits.maxAsnsPerSet);
  if (origins.error) errs[`${keyPrefix}expected_origins`] = origins.error;
  const upstreams = parseAsnList(c.upstreams, limits.maxAsnsPerSet);
  if (upstreams.error) errs[`${keyPrefix}upstreams`] = upstreams.error;
  if (c.minVisibility.trim() !== "") {
    const v = Number(c.minVisibility);
    if (!Number.isFinite(v) || v < 0 || v > 1) {
      errs[`${keyPrefix}min_visibility`] = "Visibility is a share between 0 and 1 — 0.5 means half the route collectors.";
    }
  }
  if (c.minVantages.trim() !== "") {
    const v = Number(c.minVantages);
    if (!Number.isInteger(v) || v < 0 || v > 64) {
      errs[`${keyPrefix}min_vantages`] = "Vantage points are a whole number between 0 and 64.";
    }
  }
}

export function validatePolicy(form: PolicyForm, limits: PolicyLimits): PolicyFieldErrors {
  const errs: PolicyFieldErrors = {};
  validateConfig(form.def, limits, "default.", errs);
  if (form.prefixes.length > limits.maxPrefixes) {
    errs.prefixes = `At most ${limits.maxPrefixes} per-prefix policies; this one has ${form.prefixes.length}.`;
  }
  const seen = new Set<string>();
  for (const row of form.prefixes) {
    const key = row.key.trim();
    if (key === "") {
      errs[`${row.key}.key`] = "A per-prefix policy needs the prefix it applies to.";
      continue;
    }
    if (!isPrefixKey(key)) {
      errs[`${key}.key`] = `${key} is not a prefix.`;
      continue;
    }
    if (seen.has(key)) errs[`${key}.key`] = `${key} appears twice — one policy per prefix.`;
    seen.add(key);
    validateConfig(row.cfg, limits, `${key}.`, errs);
  }
  return errs;
}

function configBody(c: PolicyConfigForm, limits: PolicyLimits): BgpAlertPolicyConfig {
  const out: BgpAlertPolicyConfig = {};
  const origins = parseAsnList(c.expectedOrigins, limits.maxAsnsPerSet).list;
  if (origins.length) out.expected_origins = origins;
  const upstreams = parseAsnList(c.upstreams, limits.maxAsnsPerSet).list;
  if (upstreams.length) out.upstreams = upstreams;
  if (c.minVisibility.trim() !== "") out.min_visibility = Number(c.minVisibility);
  if (c.minVantages.trim() !== "") out.min_vantages = Number(c.minVantages);
  return out;
}

/**
 * The exact PUT body. Empty optionals are OMITTED rather than sent as empty
 * arrays or zeros: on this wire an absent set is the meaningful state (learned
 * baseline · leak heuristic off), and there is no tenant field to fill — the
 * server stamps the owner from the token (§3a rule 2).
 */
export function policyBody(form: PolicyForm, limits: PolicyLimits): BgpAlertPolicy {
  const body: BgpAlertPolicy = { default: configBody(form.def, limits) };
  const prefixes: Record<string, BgpAlertPolicyConfig> = {};
  for (const row of form.prefixes) {
    const key = row.key.trim();
    if (key === "") continue;
    prefixes[key] = configBody(row.cfg, limits);
  }
  if (Object.keys(prefixes).length) body.prefixes = prefixes;
  return body;
}

/** Nothing to save — the button stays inert rather than issuing a no-op PUT. */
export function policyDirty(form: PolicyForm, original: PolicyForm): boolean {
  return JSON.stringify(form) !== JSON.stringify(original);
}

/** What an empty set means, said next to the field that is empty. */
export function emptySetConsequence(field: "expected_origins" | "upstreams", value: string): string | null {
  if (value.trim() !== "") return null;
  return field === "expected_origins"
    ? "No AS is declared here, so the baseline is guessed from the first observation and every result built on it is marked as guessed."
    : "No carriers are declared here, so the unexpected-transit check does not run — a quiet result means unmeasured, not clean.";
}

/** One sentence about whether a saved policy is currently being evaluated. */
export function policyEvaluationNote(status: BgpAlertStatus | undefined): string {
  if (status?.enabled) return "These rules are applied on every automatic check.";
  return (
    (status?.note ? status.note + " " : "") +
    "The rules are stored either way, and take effect as soon as BGP checks run."
  );
}
