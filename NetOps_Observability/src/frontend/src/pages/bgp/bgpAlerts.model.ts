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
  PromInstantResponse,
} from "../../services/api";

export type ClassTone = { label: string; tone: string; detail: string };

/** Map an incident class onto its chip. Worst-first ordering is the API's; this
 *  is only the presentation, and `unknown` is deliberately NOT green. */
export function incidentTone(c: BgpIncidentClass | undefined): ClassTone {
  switch (c) {
    case "origin_change":
      return {
        label: "ORIGIN CHANGE", tone: "var(--crit)",
        detail: "An AS outside the expected origin set is announcing this prefix — possible hijack.",
      };
    case "rpki_invalid":
      return {
        label: "RPKI INVALID", tone: "var(--crit)",
        detail: "The announcement violates a published ROA. A stale ROA and a hijack look identical here.",
      };
    case "bogon":
      return {
        label: "BOGON", tone: "var(--crit)",
        detail: "This prefix falls inside reserved or undelegated space and must never be in the global table.",
      };
    case "route_leak":
      return {
        label: "ROUTE LEAK", tone: "var(--warn)",
        detail: "An unexpected transit AS carries this prefix — it is not in the declared upstream set.",
      };
    case "visibility_loss":
      return {
        label: "VISIBILITY LOSS", tone: "var(--warn)",
        detail: "Fewer route-collector peers see this prefix than the configured threshold.",
      };
    case "none":
      return { label: "OK", tone: "var(--ok)", detail: "Measured: announced, RPKI not invalid, visibility above threshold." };
    default:
      return {
        label: "NOT MEASURED", tone: "var(--muted)",
        detail: "The routing lookup did not answer. This is an absent measurement, not a clean prefix.",
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
