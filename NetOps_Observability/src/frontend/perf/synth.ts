// perf/synth.ts — synthetic high-EPS payload generators for the render budget.
//
// These build the SHAPES the real endpoints return, at the volumes a busy
// network produces during a storm. They are deterministic (a small LCG, no
// Math.random) so a budget run is repeatable and a regression is a real
// regression, not sampling noise.

import type {
  TopologyView,
  TopologyNode,
  TopologyEdge,
} from "../src/features/topology/api/topologyTypes";

// ── deterministic pseudo-random ───────────────────────────────────────────────
let seed = 0x2f6e2b1;
export function resetRand(): void {
  seed = 0x2f6e2b1;
}
function rnd(): number {
  // 32-bit LCG (Numerical Recipes); deterministic across node versions.
  seed = (seed * 1664525 + 1013904223) >>> 0;
  return seed / 0x100000000;
}
function pick<T>(xs: readonly T[]): T {
  return xs[Math.floor(rnd() * xs.length)];
}

const VENDORS = ["cisco", "juniper", "arista", "nokia", "fortinet"] as const;
const SEVERITIES = ["critical", "error", "warning", "notice", "info"] as const;
const HEALTH = ["ok", "warning", "critical", "unknown", "maintenance"] as const;
const ROLES = ["core_router", "dc_leaf", "dc_spine", "wan_edge", "access_switch", "firewall"] as const;
const SITES = ["lon-dc1", "fra-dc2", "nyc-edge", "sin-pop", "syd-branch"] as const;

const T0 = Date.UTC(2026, 8, 2, 12, 0, 0);

// ── OpenSearch log/trap hits ─────────────────────────────────────────────────

export type OsHit = { _id: string; _index: string; _source: Record<string, unknown> };

/** `n` syslog hits in the OpenSearch envelope the log search returns. */
export function syslogHits(n: number, indexName = "netops-syslog"): OsHit[] {
  const out: OsHit[] = new Array(n);
  for (let i = 0; i < n; i++) {
    const dev = `${pick(SITES)}-${pick(ROLES)}-${i % 250}`;
    out[i] = {
      _id: `sl-${i}`,
      _index: indexName,
      _source: {
        "@timestamp": new Date(T0 - i * 137).toISOString(),
        host: dev,
        hostname: dev,
        severity: pick(SEVERITIES),
        level: pick(SEVERITIES),
        appname: pick(VENDORS),
        message: `%LINEPROTO-5-UPDOWN: Line protocol on Interface GigabitEthernet0/${i % 48}, changed state to ${i % 3 ? "up" : "down"} (seq ${i})`,
      },
    };
  }
  return out;
}

/** `n` SNMP-trap hits in the same envelope. */
export function trapHits(n: number): OsHit[] {
  const out: OsHit[] = new Array(n);
  for (let i = 0; i < n; i++) {
    const dev = `${pick(SITES)}-${pick(ROLES)}-${i % 250}`;
    out[i] = {
      _id: `tr-${i}`,
      _index: "netops-snmptrap",
      _source: {
        "@timestamp": new Date(T0 - i * 211).toISOString(),
        device: dev,
        normalized_severity: pick(SEVERITIES),
        trap_name: "linkDown",
        summary: `Interface Gi0/${i % 48} reported linkDown on ${dev}`,
      },
    };
  }
  return out;
}

/** The full search envelope (`hits.hits` + `hits.total`). */
export function osEnvelope(hits: OsHit[], total = hits.length) {
  return { hits: { hits, total: { value: total } } };
}

// ── alerts ───────────────────────────────────────────────────────────────────

export function alerts(n: number): Record<string, unknown>[] {
  const out: Record<string, unknown>[] = new Array(n);
  for (let i = 0; i < n; i++) {
    out[i] = {
      id: `al-${i}`,
      rule: `interface_errors_${i % 12}`,
      device_id: `${pick(SITES)}-${pick(ROLES)}-${i % 250}`,
      severity: pick(SEVERITIES),
      summary: `Error rate above threshold on Gi0/${i % 48}`,
      fired_at: new Date(T0 - i * 4_000).toISOString(),
      resolved_at: "",
    };
  }
  return out;
}

// ── correlation objects ──────────────────────────────────────────────────────

const TIERS = ["confirmed", "suspected", "undetermined"] as const;
const GROUNDS = ["seam", "topo", "seam+topo", "none"] as const;

export function correlations(n: number): Record<string, unknown>[] {
  const out: Record<string, unknown>[] = new Array(n);
  for (let i = 0; i < n; i++) {
    const start = new Date(T0 - i * 17_000);
    const dev = `${pick(SITES)}-${pick(ROLES)}-${i % 250}`;
    out[i] = {
      correlation_id: `${hex(i, 8)}-0000-4000-8000-${hex(i, 12)}`,
      version: 1,
      state: "closed",
      window_start: start.toISOString(),
      window_end: new Date(start.getTime() + 90_000).toISOString(),
      trigger_signal: `sig-${i}`,
      top_hypothesis: pick(["link_down", "bgp_session_flap", "isp_degradation", "device_unreachable"]),
      top_confidence: 0.2 + (i % 8) / 10,
      verdict_tier: pick(TIERS),
      hypotheses: "[]",
      evidence_missing: "[]",
      affected: JSON.stringify({ devices: [dev], interfaces: [`Gi0/${i % 48}`] }),
      signal_count: 3 + (i % 40),
      node_count: 1 + (i % 9),
      engine_version: "v2",
      catalog_version: "2026-09-01",
      created_at: start.toISOString(),
      edge_count: i % 11,
      grounding: pick(GROUNDS),
      plane_count: 1 + (i % 3),
      owner: pick(["netops", "isp", ""]),
      debug_excluded: 0,
      low_authority: i % 17 === 0 ? 1 : 0,
    };
  }
  return out;
}

function hex(n: number, width: number): string {
  return n.toString(16).padStart(width, "0").slice(-width);
}

// ── devices ──────────────────────────────────────────────────────────────────

export function devices(n: number): Record<string, unknown>[] {
  const out: Record<string, unknown>[] = new Array(n);
  for (let i = 0; i < n; i++) {
    const site = pick(SITES);
    out[i] = {
      id: `${site}-${pick(ROLES)}-${i}`,
      name: `${site}-${pick(ROLES)}-${i}`,
      address: `10.${(i >> 8) & 255}.${i & 255}.1`,
      vendor: pick(VENDORS),
      model: "generic",
      site,
      last_seen: new Date(T0 - (i % 900) * 1_000).toISOString(),
      reachable: i % 13 !== 0,
      status: i % 13 !== 0 ? "up" : "down",
    };
  }
  return out;
}

// ── topology view ────────────────────────────────────────────────────────────

/** A `n`-node / ~1.5n-edge resolved topology view, the shape the canvas renders. */
export function topologyView(n: number): TopologyView {
  const nodes: TopologyNode[] = new Array(n);
  for (let i = 0; i < n; i++) {
    const site = pick(SITES);
    const role = pick(ROLES);
    nodes[i] = {
      id: `n-${i}`,
      label: `${site}-${role}-${String(i).padStart(4, "0")}`,
      kind: i % 7 === 0 ? "router" : i % 5 === 0 ? "firewall" : "switch",
      role,
      device_role: role,
      vendor: pick(VENDORS),
      site,
      mgmt_ip: `10.${(i >> 8) & 255}.${i & 255}.1`,
      health: pick(HEALTH),
      confidence: 0.9,
      first_seen: new Date(T0 - (i % 4000) * 60_000).toISOString(),
      last_seen: new Date(T0 - (i % 60) * 60_000).toISOString(),
      evidence: [],
      issues: i % 9 === 0 ? [{ severity: "critical", summary: `Gi0/${i % 48} down` }] : [],
      metrics: { cpu_pct: i % 100, link_count: 2 + (i % 6) },
    };
  }
  const edges: TopologyEdge[] = [];
  for (let i = 0; i + 1 < n; i++) {
    edges.push({
      id: `e-${i}`,
      source: `n-${i}`,
      target: `n-${(i + 1) % n}`,
      relationship: "connected_to",
      status: i % 11 === 0 ? "down" : "up",
      confidence: 0.9,
      evidence: [],
    });
  }
  return {
    view_id: "perf-view",
    mode: "explore",
    layout_type: "layered",
    generated_at: new Date(T0).toISOString(),
    nodes,
    edges,
    groups: [],
    overlays: [],
  };
}
