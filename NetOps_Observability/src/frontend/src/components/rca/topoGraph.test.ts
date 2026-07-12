import { describe, it, expect } from "vitest";
import { buildTopoGraph, layoutSpine, boundaryOwner } from "./topoGraph";
import { readServicePath, isPathFocused, type ServicePath } from "./servicePath";
import type { CorrTimeline, CorrSignal } from "../../services/api";

// The renderer is a DUMB LAYOUT of the backend's ordered spine (service-path
// contract §7). These tests pin the four properties the contract makes binding:
//   1. the §10 acceptance spine renders IN BACKEND ORDER, boundary-grouped;
//   2. a missing hop is PRESERVED as an explicit unknown segment;
//   3. an edge that cannot state its evidence is NOT rendered;
//   4. no spine ⇒ an honest empty state, NEVER a star;
// plus: existing network-only RCA still renders.

// ── fixtures ──────────────────────────────────────────────────────────────────

const ev = (ref: string, method: string, confidence = "authoritative") => ({
  ref, method, confidence, observed_at: "2026-07-12T10:00:00Z", data_class: "live",
});

function sig(over: Partial<CorrSignal> = {}): CorrSignal {
  return {
    signal_id: "s1", ts: "2026-07-12T10:00:00Z", source: "snmp", kind: "link_state_change",
    observer_type: "device", collection_path: "syslog", modality_class: "control_plane",
    clock_quality: "ntp", entity_type: "device", entity_id: "wan-r2", severity: "crit",
    value: 1, metric_name: "link", onset_uncertainty_s: 1, phase: "onset", clear_ts: "",
    attached: true, is_trigger: true, evidence: null,
    link_status: "attached", link_role: "supporting", link_reason: "", linked_edges: null,
    ...over,
  } as CorrSignal;
}

function timeline(over: Partial<CorrTimeline> & Record<string, unknown> = {}): CorrTimeline {
  return {
    correlation_id: "c1", version: 1, window_start: "", window_end: "", trigger_signal: "s1",
    verdict_tier: "confirmed", top_hypothesis: "h1", top_confidence: 0.9, evidence_missing: "[]",
    signals: [], evidence: [], edges: [],
    counts: {
      total: 0, attached: 0, unattached: 0, recovery: 0, unlinked: 0, attached_observers: 0,
      by_modality: {}, attached_by_modality: {}, by_role: {}, by_grounding: {}, by_status: {},
    },
    ...over,
  } as unknown as CorrTimeline;
}

// The §10 primary acceptance case, exactly as the backend will emit it:
// 172.40.40.92 → 172.40.40.1 → 10.70.245.122 → 10.60.1.10 → 10.60.10.10 → AWS app
function acceptancePath(): Record<string, unknown> {
  return {
    spine: [
      { index: 0, kind: "client", label: "172.40.40.92", address: "172.40.40.92", boundary: "LAN",
        state: "responding", evidence: ev("pv-0", "transaction") },
      { index: 1, kind: "lan_gateway", label: "172.40.40.1", address: "172.40.40.1", boundary: "LAN",
        state: "responding", evidence: ev("pv-1", "traceroute_icmp", "strong") },
      { index: 2, kind: "wan_edge", label: "10.70.245.122", address: "10.70.245.122", boundary: "SD-WAN",
        state: "responding", transformation: "tunnel_ingress", evidence: ev("pv-2", "traceroute_icmp", "strong") },
      { index: 3, kind: "nva", label: "10.60.1.10", address: "10.60.1.10", boundary: "CLOUD",
        state: "responding", seam_id: "sm-aws", evidence: ev("pv-3", "traceroute_icmp", "strong") },
      { index: 4, kind: "app_endpoint", label: "10.60.10.10", address: "10.60.10.10", boundary: "CLOUD",
        state: "responding", evidence: ev("pv-4", "traceroute_icmp", "strong") },
      { index: 5, kind: "application", label: "AWS application", boundary: "CLOUD",
        state: "responding", entity_ref: "cloud:store-api", evidence: ev("pv-5", "transaction") },
    ],
    edges: [
      { from: 0, to: 1, type: "PATH_HAS_HOP", evidence: ev("e-01", "traceroute_icmp", "strong") },
      { from: 1, to: 2, type: "PATH_HAS_HOP", evidence: ev("e-12", "traceroute_icmp", "strong") },
      { from: 2, to: 3, type: "CROSSES_SEAM", seam_id: "sm-aws", transformation: "tunnel_ingress",
        evidence: ev("e-23", "traceroute_icmp", "strong") },
      { from: 3, to: 4, type: "PATH_HAS_HOP", evidence: ev("e-34", "traceroute_icmp", "strong") },
      { from: 4, to: 5, type: "SERVICE_EXPOSED_BY_ENDPOINT", evidence: ev("e-45", "transaction") },
    ],
    boundaries: [
      { name: "LAN", from: 0, to: 1 },
      { name: "SD-WAN", from: 2, to: 2 },
      { name: "CARRIER", from: 2, to: 3 },
      { name: "CLOUD", from: 3, to: 5 },
    ],
    evidence_branches: [
      { attach_index: 2, class: "metrics", label: "Interface counters", summary: "egress discards",
        evidence: ev("br-1", "stamp", "strong") },
      { attach_index: 3, class: "alerts", label: "Cloud alert", evidence: ev("br-2", "transaction", "strong") },
    ],
  };
}

const acceptanceTimeline = () => timeline({ path: acceptancePath(), signals: [sig({ entity_type: "path", entity_id: "172.40.40.92->10.60.10.10", kind: "probe_loss" })] });

// ── 1. the acceptance spine renders IN ORDER, boundary-grouped ────────────────

describe("layoutSpine — the §10 acceptance path", () => {
  const path = readServicePath(acceptanceTimeline()) as ServicePath;

  it("parses the backend spine", () => {
    expect(path).not.toBeNull();
    expect(path.spine.map((n) => n.index)).toEqual([0, 1, 2, 3, 4, 5]);
  });

  it("lays the hops out source→destination, in the BACKEND's order", () => {
    const g = layoutSpine(path, "confirmed");
    const hops = g.nodes.filter((n) => n.data.hopIndex !== undefined).sort((a, b) => a.x - b.x);
    expect(hops.map((n) => n.data.label)).toEqual([
      "172.40.40.92", "172.40.40.1", "10.70.245.122", "10.60.1.10", "10.60.10.10", "AWS application",
    ]);
    // x is a PURE FUNCTION of hop_index — strictly increasing, one row (y=0).
    expect(hops.map((n) => n.x)).toEqual([0, 200, 400, 600, 800, 1000]);
    expect(hops.every((n) => n.y === 0)).toBe(true);
    expect(hops.map((n) => n.data.hopIndex)).toEqual([0, 1, 2, 3, 4, 5]);
  });

  it("is a SPINE, not a star — every hop has at most one in and one out edge", () => {
    const g = layoutSpine(path, "confirmed");
    const spineEdges = g.edges.filter((e) => e.type !== "EVIDENCE_SUPPORTS");
    expect(spineEdges.map((e) => `${e.from}->${e.to}`)).toEqual([
      "h0->h1", "h1->h2", "h2->h3", "h3->h4", "h4->h5",
    ]);
    // a star would have one node with degree 5; the spine's max degree is 2.
    const deg = new Map<string, number>();
    for (const e of spineEdges) {
      deg.set(e.from, (deg.get(e.from) ?? 0) + 1);
      deg.set(e.to, (deg.get(e.to) ?? 0) + 1);
    }
    expect(Math.max(...deg.values())).toBe(2);
  });

  it("groups the hops into LAN / SD-WAN / CARRIER / CLOUD boundary bands", () => {
    const g = layoutSpine(path, "confirmed");
    expect(g.bands.map((b) => b.name)).toEqual(["LAN", "SD-WAN", "CARRIER", "CLOUD"]);
    const lan = g.bands[0], cloud = g.bands[3];
    expect(lan.fromId).toBe("h0");
    expect(lan.toId).toBe("h1");
    expect(cloud.from).toBe(3);
    expect(cloud.to).toBe(5);
    // bands span the hops they group and are tinted by boundary owner
    expect(cloud.width).toBeGreaterThan(lan.width);
    expect(g.bands.every((b) => !!b.color)).toBe(true);
    expect(boundaryOwner("CLOUD")).toBe("cloud");
    expect(boundaryOwner("SD-WAN")).toBe("sdwan_controller");
    expect(boundaryOwner("CARRIER")).toBe("carrier");
    expect(boundaryOwner("LAN")).toBe("enterprise");
  });

  it("exposes evidence (ref · method · confidence · observed_at) on EVERY displayed edge", () => {
    const g = layoutSpine(path, "confirmed");
    for (const e of g.edges) {
      expect(e.evidence?.ref).toBeTruthy();
      expect(e.evidence?.method).toBeTruthy();
      expect(e.evidence?.confidence).toBeTruthy();
      expect(e.evidence?.observed_at).toBeTruthy();
    }
  });

  it("marks transformations (tunnel ingress) explicitly on the hop and the segment", () => {
    const g = layoutSpine(path, "confirmed");
    const wan = g.nodes.find((n) => n.data.hopIndex === 2)!;
    expect(wan.data.transformation).toBe("Tunnel start");
    expect(wan.data.chips).toContain("Tunnel start");
    const seamEdge = g.edges.find((e) => e.from === "h2" && e.to === "h3")!;
    expect(seamEdge.type).toBe("CROSSES_SEAM");
    expect(seamEdge.transformation).toBe("Tunnel start");
    expect(seamEdge.seamId).toBe("sm-aws");
  });

  it("hangs evidence branches OFF the spine without distorting it", () => {
    const g = layoutSpine(path, "confirmed");
    const branches = g.nodes.filter((n) => n.data.branchOf !== undefined);
    expect(branches.map((b) => b.data.branchOf)).toEqual([2, 3]);
    // below the spine (y > 0), and connected from the hop's BOTTOM handle
    expect(branches.every((b) => b.y > 0)).toBe(true);
    const branchEdges = g.edges.filter((e) => e.type === "EVIDENCE_SUPPORTS");
    expect(branchEdges.every((e) => e.fromHandle === "b" && e.state === "unknown")).toBe(true);
    // the spine's own x/y is untouched by the branches
    const hops = g.nodes.filter((n) => n.data.hopIndex !== undefined);
    expect(hops.map((n) => n.x)).toEqual([0, 200, 400, 600, 800, 1000]);
  });

  it("buildTopoGraph routes the whole RCA object through the spine (screen == PDF)", () => {
    const g = buildTopoGraph(acceptanceTimeline(), {}, "operator", false);
    expect(g.mode).toBe("spine");
    expect(g.internal).toBe(false);
    expect(g.nodes.filter((n) => n.data.hopIndex !== undefined)).toHaveLength(6);
    expect(g.bands).toHaveLength(4);
  });
});

// ── 2. a missing hop is preserved as an explicit unknown segment ──────────────

describe("unknown hops", () => {
  const withGap = (): CorrTimeline => {
    const p = acceptancePath() as any;
    p.spine[2] = { index: 2, kind: "transit", label: "", boundary: "CARRIER", state: "missing",
      evidence: ev("pv-2", "traceroute_icmp", "unknown") };
    return timeline({ path: p, signals: [sig({ entity_type: "path", entity_id: "a->b" })] });
  };

  it("keeps the hop's slot, renders it blind, and never bridges it away", () => {
    const g = buildTopoGraph(withGap(), {}, "operator", false);
    const hops = g.nodes.filter((n) => n.data.hopIndex !== undefined);
    expect(hops).toHaveLength(6);                       // NOT dropped
    const gap = hops.find((n) => n.data.hopIndex === 2)!;
    expect(gap.data.kind).toBe("unknown");              // blind shape
    expect(gap.data.hopState).toBe("missing");
    expect(gap.data.label).toBe("Unknown hop");
    expect(gap.x).toBe(400);                            // still in its slot
    // both segments touching the blind hop are "unknown" (grey, non-animated)
    expect(g.edges.find((e) => e.to === "h2")!.state).toBe("unknown");
    expect(g.edges.find((e) => e.from === "h2" && e.to === "h3")!.state).toBe("unknown");
    // and the neighbours are NOT silently joined
    expect(g.edges.some((e) => e.from === "h1" && e.to === "h3")).toBe(false);
  });
});

// ── 3. an edge with no evidence is NOT rendered ───────────────────────────────

describe("evidence admission (contract §5)", () => {
  it("drops an edge with no evidence object and one with an empty ref", () => {
    const p = acceptancePath() as any;
    delete p.edges[1].evidence;                                 // 1→2: no evidence at all
    p.edges[3].evidence = { ref: "", method: "traceroute_icmp" }; // 3→4: cannot state its ref
    const g = buildTopoGraph(timeline({ path: p, signals: [sig({ entity_type: "path", entity_id: "a->b" })] }), {}, "operator", false);
    const ids = g.edges.map((e) => `${e.from}->${e.to}`);
    expect(ids).not.toContain("h1->h2");
    expect(ids).not.toContain("h3->h4");
    expect(ids).toContain("h0->h1");
    expect(ids).toContain("h2->h3");
    // the hops themselves are still all there — we drop the claim, not the fact
    expect(g.nodes.filter((n) => n.data.hopIndex !== undefined)).toHaveLength(6);
  });

  it("drops an evidence branch that cannot state its evidence", () => {
    const p = acceptancePath() as any;
    delete p.evidence_branches[0].evidence;
    const g = buildTopoGraph(timeline({ path: p, signals: [sig({ entity_type: "path", entity_id: "a->b" })] }), {}, "operator", false);
    expect(g.nodes.filter((n) => n.data.branchOf !== undefined).map((b) => b.data.branchOf)).toEqual([3]);
  });
});

// ── 4. no spine ⇒ honest empty state, NEVER a star ────────────────────────────

describe("no spine on a path-focused RCA", () => {
  const pathOnly = () => timeline({
    signals: [
      sig({ entity_type: "path", entity_id: "172.40.40.92->10.60.10.10", kind: "probe_loss", value: 0.12 }),
      sig({ signal_id: "s2", entity_type: "app", entity_id: "store-api", kind: "cloud_health", is_trigger: false }),
    ],
  });

  it("is path-focused but renders NOTHING — no invented hops, no star", () => {
    const t = pathOnly();
    expect(isPathFocused(t)).toBe(true);
    expect(readServicePath(t)).toBeNull();
    const g = buildTopoGraph(t, {}, "operator", false);
    expect(g.mode).toBe("empty");
    expect(g.nodes).toHaveLength(0);
    expect(g.edges).toHaveLength(0);
  });

  it("ignores a malformed spine rather than half-rendering it", () => {
    const t = timeline({ path: { spine: [{ label: "no index" }], edges: [], boundaries: [] },
      signals: [sig({ entity_type: "path", entity_id: "a->b" })] });
    expect(readServicePath(t)).toBeNull();
    expect(buildTopoGraph(t, {}, "operator", false).mode).toBe("empty");
  });
});

// ── 5. existing network-only RCA does not regress ─────────────────────────────

describe("network-only RCA (no service path) still renders", () => {
  it("renders the affected device area + co-affected context", () => {
    const t = timeline({
      verdict_tier: "confirmed",
      signals: [
        sig({ entity_type: "interface", entity_id: "wan-r2:Ethernet1", kind: "link_state_change", severity: "crit" }),
        sig({ signal_id: "s2", entity_type: "device", entity_id: "leaf1", kind: "device_resource_anomaly", severity: "warn", is_trigger: false }),
      ],
    });
    expect(isPathFocused(t)).toBe(false);
    const g = buildTopoGraph(t, {}, "operator", false);
    expect(g.mode).toBe("context");
    const fault = g.nodes.find((n) => n.id === "fault")!;
    expect(fault.data.label).toBe("wan-r2");          // worst-severity locus, not degree
    expect(fault.data.badge).toContain("Broken");
    expect(g.nodes.some((n) => n.id === "aff0")).toBe(true);
    expect(g.bands).toHaveLength(0);
  });

  it("renders a declared routing peer as the far end of the segment", () => {
    const t = timeline({
      verdict_tier: "suspected",
      signals: [sig({ entity_type: "device", entity_id: "wan-r2", kind: "bgp_adjacency_change",
        attrs: JSON.stringify({ peer: "10.255.0.1", state: "down" }) })],
    });
    const g = buildTopoGraph(t, {}, "operator", false);
    expect(g.mode).toBe("context");
    expect(g.nodes.map((n) => n.id)).toContain("peer");
    const e = g.edges.find((x) => x.to === "peer")!;
    expect(e.state).toBe("suspected_down");
    expect(e.label).toBe("BGP neighbor changed");
  });

  it("keeps platform self-monitoring objects out of the customer path view", () => {
    const t = timeline({ signals: [sig({ entity_type: "device", entity_id: "clickhouse", kind: "metric_anomaly" })] });
    const g = buildTopoGraph(t, {}, "operator", false);
    expect(g.mode).toBe("internal");
    expect(g.internal).toBe(true);
  });
});

// ── the C5 drill shape: the tunnel dies, the backend folds the drop-point ladder
// into one node with repeat_count and states the terminal failure as a branch. ──
describe("dying path (collapsed drop-point ladder)", () => {
  const dyingTimeline = () => timeline({
    path: {
      status: "partial",
      spine: [
        { index: 0, kind: "client", label: "172.40.40.200", address: "172.40.40.200", boundary: "LAN",
          state: "responding", evidence: ev("pv-0", "traceroute_icmp") },
        { index: 1, kind: "lan_gateway", label: "172.40.40.1", address: "172.40.40.1", boundary: "LAN",
          state: "responding", evidence: ev("pv-1", "traceroute_icmp", "strong") },
        { index: 2, kind: "wan_edge", label: "10.70.245.122", address: "10.70.245.122", boundary: "SD-WAN",
          state: "responding", transformation: "tunnel_ingress", seam_id: "sm-aws",
          repeat_count: 28, evidence: ev("pv-2", "traceroute_icmp", "strong") },
        { index: 3, kind: "application", label: "AWS application", boundary: "CLOUD",
          state: "missing", entity_ref: "cloud:store-api", evidence: ev("pv-3", "transaction") },
      ],
      edges: [
        { from: 0, to: 1, type: "PATH_HAS_HOP", evidence: ev("e-01", "traceroute_icmp", "strong") },
        { from: 1, to: 2, type: "PATH_HAS_HOP", evidence: ev("e-12", "traceroute_icmp", "strong") },
        { from: 2, to: 3, type: "SERVICE_EXPOSED_BY_ENDPOINT", evidence: ev("e-23", "transaction") },
      ],
      boundaries: [{ name: "LAN", from: 0, to: 1 }, { name: "SD-WAN", from: 2, to: 2 }],
      evidence_branches: [
        { attach_index: 2, class: "observed", note: "destination never responded in this run (partial) — the measured path terminates at this node",
          evidence: ev("br-t", "traceroute_icmp") },
        { attach_index: 2, class: "inferred", note: "seam sm-aws known from this path's last complete observation — the current run dies at its near endpoint; the crossing itself is not asserted",
          evidence: ev("pv-prior", "prior_complete_observation", "candidate") },
      ],
    },
    signals: [sig({ entity_type: "path", entity_id: "172.40.40.200->10.60.10.10", kind: "probe_loss" })],
  });

  it("renders the folded drop node with its repeat chip, not a ladder", () => {
    const path = readServicePath(dyingTimeline()) as ServicePath;
    expect(path).not.toBeNull();
    expect(path.spine).toHaveLength(4);
    expect(path.spine[2].repeat_count).toBe(28);

    const g = layoutSpine(path, "confirmed");
    const drop = g.nodes.find((n) => n.data.hopIndex === 2)!;
    expect(drop.data.chips).toContain("answered 28 probes in a row");
    expect(drop.data.chips).toContain("Tunnel start");
  });

  it("renders the unreached application as missing and keeps the terminal notes", () => {
    const path = readServicePath(dyingTimeline()) as ServicePath;
    const g = layoutSpine(path, "confirmed");
    const app = g.nodes.find((n) => n.data.hopIndex === 3)!;
    expect(app.data.hopState).toBe("missing");

    const branches = path.evidence_branches.filter((b) => b.attach_index === 2);
    expect(branches.some((b) => (b.summary ?? "").includes("destination never responded"))).toBe(true);
    expect(branches.some((b) => (b.summary ?? "").includes("last complete observation"))).toBe(true);
  });
});
