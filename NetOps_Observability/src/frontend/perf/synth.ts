// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

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

// ── BGP operations (single-screen outage view, 2026-09-03) ───────────────────
//
// The BGP page is not fed by ONE endpoint: it is a dozen independent panels on
// one screen, and its render cost is the SUM of them. So the scenario builds
// the whole set at the volume an operator with a real watchlist sees during an
// outage — 50 watched prefixes, a 500-update near-live buffer, 30 BGP peers and
// 20 bogon sightings — and the budget covers the page with all of it on screen
// at once. That is the property the tab layout used to hide: three tabs each
// paid for a third of this, and no single view ever paid for all of it.

const BGP_CLASSES = ["origin_change", "rpki_invalid", "route_leak", "visibility_loss", "bogon", "none"] as const;
const BGP_RPKI_STATES = ["invalid", "unavailable", "unknown", "valid"] as const;

/** `n` watched prefixes, deterministic and CIDR-valid. */
export function bgpPrefixes(n: number): string[] {
  const out: string[] = new Array(n);
  for (let i = 0; i < n; i++) out[i] = `198.${18 + (i >> 8)}.${i & 255}.0/24`;
  return out;
}

/** The watchlist response: entries plus one incident per prefix. */
export function bgpWatchlist(prefixes: string[]) {
  const incidents: Record<string, unknown> = {};
  prefixes.forEach((prefix, i) => {
    const cls = BGP_CLASSES[i % BGP_CLASSES.length];
    incidents[prefix] = {
      prefix,
      class: cls,
      severity: cls === "none" ? "info" : "warning",
      summary: `${prefix} is announced by AS${64500 + (i % 7)} and seen by ${200 + (i % 90)} collector peers.`,
      evidence: {
        detail: `Measured across ${3 + (i % 4)} route-collector vantage points.`,
        vantages: [`rrc0${i % 10}`, `rrc1${i % 10}`],
        paths: [[3333, 1299, 64500 + (i % 7)], [6939, 174, 64500 + (i % 7)]],
        peers_seeing: 200 + (i % 90),
        peers_total: 335,
      },
      learned_origin: i % 5 === 0,
      first_seen: new Date(T0 - 86_400_000).toISOString(),
      last_seen: new Date(T0).toISOString(),
      since: new Date(T0 - (i % 12) * 3_600_000).toISOString(),
    };
  });
  return {
    watchlist: prefixes.map((resource, i) => ({
      resource, kind: "prefix" as const, note: `site ${i % 9}`,
      added_by: "perf", created_at: new Date(T0 - i * 60_000).toISOString(),
    })),
    incidents,
  };
}

/** The alert history the incidents section renders beneath the watchlist. */
export function bgpAlerts(prefixes: string[]) {
  return {
    alerts: prefixes.map((resource, i) => ({
      id: `a-${i}`, rule: "bgp.visibility", severity: i % 3 ? "warning" : "critical",
      resource, class: BGP_CLASSES[i % BGP_CLASSES.length],
      summary: `Visibility for ${resource} fell to ${40 + (i % 50)}% of full-feed peers.`,
      fired_at: new Date(T0 - i * 300_000).toISOString(),
      resolved: i % 4 === 0, resolved_at: new Date(T0 - i * 290_000).toISOString(),
    })),
    incidents: [],
    classes: [],
    status: { enabled: true, interval: "5m", cooldown: "30m", runs: 120 },
  };
}

/** RIPEstat routing-status + rpki + collector paths for the selected prefix. */
export function bgpStatus(resource: string, rrcs = 12, peersPerRrc = 8) {
  return {
    resource, kind: "prefix" as const,
    routing_status: {
      announced: true,
      last_seen: { origin: "AS64500", prefix: resource, time: new Date(T0).toISOString() },
      visibility: {
        v4: { total_ris_peers: 335, ris_peers_seeing: 214 },
        v6: { total_ris_peers: 120, ris_peers_seeing: 96 },
      },
    },
    rpki: { status: "invalid_asn" },
    rpki_origin: "AS64500",
    paths: {
      rrcs: Array.from({ length: rrcs }, (_, r) => ({
        rrc: `RRC${String(r).padStart(2, "0")}`,
        peers: Array.from({ length: peersPerRrc }, (_, p) => ({
          as_path: `${3333 + p} ${1299 + (r % 5)} ${174} 64500`,
        })),
      })),
    },
  };
}

/** RIPEstat bgp-updates for the churn strip. */
export function bgpUpdates(resource: string, n: number) {
  return {
    resource,
    updates: {
      nr_updates: n,
      updates: Array.from({ length: n }, (_, i) => ({
        type: i % 3 === 0 ? "W" : "A",
        timestamp: new Date(T0 - i * 60_000).toISOString(),
        attrs: { path: [3333, 1299, 64500], source_id: `rrc0${i % 10}` },
      })),
    },
  };
}

/** `n` buffered near-live updates (the client ring's full capacity). */
export function bgpFeed(prefixes: string[], n: number) {
  return {
    updates: Array.from({ length: n }, (_, i) => ({
      seq: i,
      time: new Date(T0 - (n - i) * 1_000).toISOString(),
      type: i % 4 === 0 ? "W" : "A",
      resource: prefixes[i % prefixes.length],
      prefix: prefixes[i % prefixes.length],
      peer: `10.0.${i % 250}.1`,
      path: [3333, 1299, 174, 64500 + (i % 7)],
      origin: 64500 + (i % 7),
    })),
    next: n,
    status: {
      enabled: true, polling: true, resources: prefixes,
      buffered: n, written: n, dropped: 0, ring_size: 2000,
      interval: "60s", producer: "ripestat",
    },
  };
}

/** One BMP session carrying `n` peers — the Peers section's first witness. */
export function bgpBmpSessions(n: number) {
  return {
    sessions: [{
      id: "sess-1", device_id: "lon-dc1-core-01", remote_addr: "10.0.0.1",
      router: "lon-dc1-core-01", state: "up",
      opened_at: new Date(T0 - 3_600_000).toISOString(),
      peers: Array.from({ length: n }, (_, i) => ({
        address: `10.10.${i}.1`, as: 64500 + i, rib: "adj-rib-in",
        state: i % 6 === 0 ? "down" : "up",
        changed_at: new Date(T0 - i * 60_000).toISOString(),
        down_reason: i % 6 === 0 ? "hold timer expired" : undefined,
        announced_prefixes: 1000 + i * 7,
        withdrawn_prefixes: i * 3,
      })),
      peers_partial: false, messages: {}, updates_held: 0, updates_dropped: 0,
      parse_errors: 0, unsupported_elements: 0,
    }],
    count: 1,
    coverage: { receiver_enabled: true, sessions_up: 1, complete: true, notes: [] },
  };
}

/** `device_bgp_peer_state` samples — the Peers section's second witness. */
export function bgpPeerMetrics(n: number) {
  return {
    status: "success",
    data: {
      resultType: "vector",
      result: Array.from({ length: n }, (_, i) => ({
        metric: { device: `fra-dc2-wan-edge-0${i % 9}`, peer: `10.20.${i}.1` },
        value: [T0 / 1000, i % 5 === 0 ? "3" : "6"] as [number, string],
      })),
    },
  };
}

/** `n` bogon sightings across a handful of reserved blocks. */
export function bgpBogons(n: number) {
  const blocks = [
    { block: "10.0.0.0/8", reason: "private-use", rfc: "RFC 1918", why: "Private space must never appear in the global table." },
    { block: "192.168.0.0/16", reason: "private-use", rfc: "RFC 1918", why: "Private space must never appear in the global table." },
    { block: "100.64.0.0/10", reason: "shared-address-space", rfc: "RFC 6598", why: "Carrier-grade NAT space is not globally routable." },
  ];
  return {
    sightings: Array.from({ length: n }, (_, i) => {
      const e = blocks[i % blocks.length];
      return {
        prefix: `${e.block.split("/")[0].split(".").slice(0, 2).join(".")}.${i}.0/24`,
        entry: e, source: i % 2 ? "bmp" : "feed", peer: `10.0.${i}.1`, origin: 64500 + i,
        first_seen: new Date(T0 - i * 600_000).toISOString(),
        last_seen: new Date(T0 - i * 60_000).toISOString(),
        count: 1 + i,
      };
    }),
    set: { source: "IANA special-purpose registries", date: "2026-09-02", blocks: 42, note: "Embedded set, transcribed from the IANA registries." },
    feed: { enabled: false, entries: 0, note: "The optional full-bogons feed is off." },
  };
}

/** RPKI validation results for the whole watchlist. */
export function bgpRpki(prefixes: string[]) {
  return {
    results: prefixes.map((prefix, i) => ({
      prefix, origin: `AS${64500 + (i % 7)}`,
      state: BGP_RPKI_STATES[i % BGP_RPKI_STATES.length],
      reason: i % 4 === 0 ? "origin_as" : undefined,
      validator: "routinator",
      roas: [{ origin: `AS${64500 + (i % 7)}`, prefix, max_length: 24, validity: "valid" }],
      fetched_at: new Date(T0 - i * 1_000).toISOString(),
    })),
    from_watchlist: true, truncated: false, max_prefixes: 50,
  };
}

/** The AS-path graph for the selected prefix. */
export function bgpAsPathGraph(prefix: string, nodes = 24) {
  return {
    prefix,
    nodes: Array.from({ length: nodes }, (_, i) => ({
      asn: 3000 + i, name: `Transit ${i}`, depth: i % 4,
      origin: i === nodes - 1, vantage: i % 4 === 0, paths: 1 + (i % 9),
    })),
    edges: Array.from({ length: nodes - 1 }, (_, i) => ({ from: 3000 + i, to: 3001 + i, peers: 1 + (i % 5) })),
    origins: [3000 + nodes - 1], paths: 96, paths_seen: 96,
    max_edges: 200, edges_capped: false, nodes_capped: false,
    source: "bgp-state", fetched_at: new Date(T0).toISOString(),
  };
}

/** A published geofeed for the selected prefix. */
export function bgpGeofeed(resource: string, rows = 40) {
  return {
    resource, published: true, source_url: "https://example.net/geofeed.csv",
    entries: Array.from({ length: rows }, (_, i) => ({
      prefix: `198.51.${i}.0/24`, country: ["GB", "DE", "US", "SG"][i % 4],
      region: `R${i % 6}`, city: `City ${i % 12}`, postal: `PC${i}`,
    })),
    rows_scanned: rows + 3, rows_kept: rows, rows_dropped: 3, truncated: false,
    fetched_at: new Date(T0).toISOString(),
  };
}

/** RDAP ownership for the selected prefix. */
export function bgpWhois(resource: string) {
  return {
    resource,
    rdap: {
      name: "EXAMPLE-NET",
      entities: Array.from({ length: 6 }, (_, i) => ({
        roles: [["registrant", "abuse", "technical", "noc"][i % 4]],
        vcardArray: ["vcard", [["fn", {}, "text", `Example Contact ${i}`]]],
      })),
    },
  };
}

// ── Data Protection console ──────────────────────────────────────────────────
//
// The volume that matters on this surface is the restore-point list: a daily
// policy with a long retention, or a repository shared with an operator's own
// ad-hoc copies, reaches several hundred quickly. The budget exists to prove
// the table stays windowed rather than rendering every row. Shapes mirror
// src/backend/system_backup_contract.go, holes included — the honest "not
// measured" cells are part of what the page has to render.

const DP_ENGINES = [
  "opensearch", "system_bundle", "clickhouse", "postgres",
  "victoriametrics", "secrets_tls", "device_configs",
] as const;

/** GET /api/system/backup/coverage with one row per engine. */
export function backupCoverage() {
  return {
    generated_at: new Date(T0).toISOString(),
    engines: DP_ENGINES.map((id, i) => ({
      id, name: id,
      covered: i === 4 ? "no" : i === 6 ? "not_applicable" : i === 5 ? "unknown" : "yes",
      covered_reason: "the daily policy produced a successful copy",
      schedule: i % 2
        ? { enabled: true, cron: "30 1 * * *", governed_by_gui: i !== 1, detail: "a host cron runs it" }
        : null,
      last_attempt: { at: new Date(T0 - i * 3600_000).toISOString(), result: i === 4 ? "failed" : "success" },
      last_success_at: i === 4 ? "" : new Date(T0 - i * 3600_000).toISOString(),
      last_verified: i < 3 ? { at: new Date(T0 - 86400_000).toISOString(), result: "pass" } : null,
      size_bytes: i === 4 ? null : (i + 1) * 1024 ** 3,
      size_detail: i === 4 ? "nothing has been written yet" : "",
      retention: { max_count: 14, max_age_days: 30, detail: "" },
      target: {
        kind: ["offsite", "remote", "local"][i % 3],
        location: "rsync://nas/correlix/",
        immutable: i % 2 === 0 ? false : null,
        immutable_detail: "a filesystem repository cannot be made immutable",
        encrypted: true, encrypted_detail: "",
      },
      rpo_hours: i === 4 ? null : (i + 1) * 1.5,
      rpo_detail: i === 4 ? "no successful copy exists" : "",
    })),
    external: [{
      name: "Nightly rsync to the NAS", source: "host crontab", schedule: "0 3 * * *",
      detail: "It was installed by hand and this page does not control it.",
    }],
  };
}

/** `n` restore points in the shape the console's table renders. */
export function snapshotList(n: number) {
  return {
    repository: { name: "netops-fs", registered: true, type: "fs", verified: true, verified_detail: "" },
    total: n,
    snapshots: Array.from({ length: n }, (_, i) => {
      const start = T0 - i * 86400_000;
      const failed = i % 37 === 0;
      return {
        name: `netops-daily-${String(100000 + i)}`,
        state: failed ? "PARTIAL" : "SUCCESS",
        indices: [`netops-syslog-${i}`, `netops-traps-${i}`, `netops-flows-${i}`],
        index_count: 3,
        started_at: new Date(start).toISOString(),
        ended_at: new Date(start + 180_000).toISOString(),
        duration_seconds: 120 + (i % 90),
        shards: { total: 6, successful: failed ? 4 : 6, failed: failed ? 2 : 0 },
        failures: failed
          ? [{ index: `netops-syslog-${i}`, shard: i % 5, reason: "NoSuchFileException: indices/0/3/__abc" }]
          : [],
        failures_trimmed: 0,
        size_bytes: null,
        size_detail: "not measured on this read — pass ?sizes=1",
        restorable_verified: i % 11 === 0 ? true : null,
        restorable_verified_at: i % 11 === 0 ? new Date(start + 3600_000).toISOString() : "",
        restorable_detail: i % 11 === 0 ? "" : "no probe has ever run on this restore point",
      };
    }),
  };
}

/** `n` operations for the activity panel. */
export function backupOperations(n: number) {
  const kinds = ["snapshot_create", "snapshot_verify", "snapshot_restore", "snapshot_delete"];
  return {
    capacity: 200,
    operations: Array.from({ length: n }, (_, i) => ({
      id: `op-${String(i).padStart(16, "0")}`,
      kind: kinds[i % 4],
      state: i % 13 === 0 ? "failed" : "succeeded",
      actor: "root",
      started_at: new Date(T0 - i * 3600_000).toISOString(),
      ended_at: new Date(T0 - i * 3600_000 + 60_000).toISOString(),
      target: { snapshot: `netops-daily-${String(100000 + i)}` },
      verify: i % 4 === 1
        ? {
            snapshot: `netops-daily-${String(100000 + i)}`, index: `netops-flows-${i}`,
            temp_index: `probe-${i}`, source_docs: 1200, restored_docs: 1200,
            match: true, temp_deleted: true, duration_seconds: 42,
          }
        : undefined,
      error: i % 13 === 0 ? "repository netops-fs is read-only" : "",
    })),
  };
}
