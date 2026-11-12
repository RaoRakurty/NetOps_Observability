// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// topologyContext.test.ts — the topology context contract (RCA document v2 §2):
// validation is zero-trust (malformed → dropped, never guessed), the four
// states and three layers read from the fixtures, the layout derives ONLY from
// what the context carries, and the words mirror the server document.

import { describe, it, expect } from "vitest";
import {
  readTopologyContext, topoStateLabel, topoSourcesLine, readAndEmptySources, unreadSources,
  devicePeak, severityTone, causalRelationLabel, topoTS, type TopologyContext,
} from "./topologyContext";
import { deriveContextModel, derivePathModel } from "./pathModel";
import {
  P3E0400_CONTEXT, TOPOLOGY_ONLY_CONTEXT, TOPOLOGY_WITH_PATH_CONTEXT, NO_ASSET_MAPPING_CONTEXT,
} from "./testdata/topologyFixtures";
import type { CorrTimeline } from "../../services/api";

const read = (v: unknown): TopologyContext => {
  const tc = readTopologyContext(v);
  if (!tc) throw new Error("fixture did not validate");
  return tc;
};

describe("readTopologyContext — zero-trust validation", () => {
  it("reads the context off a whole report or the value itself", () => {
    expect(readTopologyContext({ title: "x", topology_context: P3E0400_CONTEXT })?.state).toBe("device_only");
    expect(readTopologyContext(P3E0400_CONTEXT)?.state).toBe("device_only");
  });

  it("returns null for an absent, malformed or unknown-state context (never a guess)", () => {
    expect(readTopologyContext(null)).toBeNull();
    expect(readTopologyContext({})).toBeNull();
    expect(readTopologyContext({ topology_context: "device_only" })).toBeNull();
    expect(readTopologyContext({ topology_context: { state: "probably_fine" } })).toBeNull();
    expect(readTopologyContext({ topology_context: [] })).toBeNull();
  });

  it("drops an edge whose endpoint is not a drawn node — it never adds the node", () => {
    const tc = read({
      state: "topology_only",
      nodes: [{ id: "a", label: "a", anchor: true, managed: true }],
      edges: [{ id: "e1", a: "a", b: "ghost", relationship: "physical", sources: ["lldp"] }],
    });
    expect(tc.nodes.map((n) => n.id)).toEqual(["a"]);
    expect(tc.edges).toEqual([]);
  });

  it("de-duplicates a repeated node id and drops entries with no id / bad types", () => {
    const tc = read({
      state: "device_only",
      nodes: [{ id: "a" }, { id: "a", label: "dup" }, { label: "no id" }, "string", 7],
      faults: [{ target_type: "port", target_id: "x", device: "a" }, { target_type: "node", target_id: "a", device: "a", kinds: ["k"], peak_severity: "CRIT" }],
      causal: [{ from: "a", to: "b", relation: "certain" }, { from: "a", to: "a:Gi1", relation: "unknown" }],
    });
    expect(tc.nodes).toHaveLength(1);
    expect(tc.faults).toHaveLength(1);
    expect(tc.faults[0].peak_severity).toBe("crit");
    expect(tc.causal).toHaveLength(1);
  });

  it("bounds lists and strings — a hostile payload cannot blow up the render", () => {
    const nodes = Array.from({ length: 500 }, (_, i) => ({ id: `n${i}` }));
    const tc = read({ state: "topology_only", nodes, reason: "x".repeat(10_000) });
    expect(tc.nodes.length).toBeLessThanOrEqual(64);
    expect(tc.reason.length).toBeLessThanOrEqual(2000);
  });
});

describe("the four states from the fixtures", () => {
  it("P-3E0400 is device_only — never 'not path-shaped'", () => {
    const tc = read(P3E0400_CONTEXT);
    expect(tc.state).toBe("device_only");
    expect(JSON.stringify(tc)).not.toMatch(/path-shaped/);
    expect(tc.nodes.map((n) => n.id)).toEqual(["cedge-60-07ae8615"]);
    expect(tc.edges).toEqual([]);
    expect(readAndEmptySources(tc).map((s) => s.kind)).toEqual(["lldp", "cdp", "bgp_ls", "topology_graph", "sdwan_overlay", "controller"]);
    expect(unreadSources(tc)).toEqual([]);
    expect(topoSourcesLine(tc)).toBe("inventory only");
    expect(devicePeak(tc, "cedge-60-07ae8615")).toBe("crit");
  });

  it("topology_only / topology_with_path / no_asset_mapping validate with their layers", () => {
    const only = read(TOPOLOGY_ONLY_CONTEXT);
    expect(only.state).toBe("topology_only");
    expect(only.has_spine).toBe(false);
    expect(topoSourcesLine(only)).toBe("LLDP, CDP (stale), inventory");
    const withPath = read(TOPOLOGY_WITH_PATH_CONTEXT);
    expect(withPath.has_spine).toBe(true);
    expect(topoSourcesLine(withPath)).toBe("measured path, LLDP, CDP (stale), inventory");
    const none = read(NO_ASSET_MAPPING_CONTEXT);
    expect(none.unmapped).toEqual(["ghost-9"]);
    expect(none.remediation).toHaveLength(2);
  });
});

describe("wording mirrors the server document", () => {
  it("state labels are the server's topoStateLabel words", () => {
    expect(topoStateLabel("topology_with_path")).toBe("topology with measured path");
    expect(topoStateLabel("topology_only")).toBe("known topology, no measured path");
    expect(topoStateLabel("device_only")).toBe("device only — no neighbour or path data");
    expect(topoStateLabel("no_asset_mapping")).toBe("no asset mapping");
  });

  it("keeps the '?' on an unknown relation and prints UTC minutes", () => {
    expect(causalRelationLabel("unknown")).toBe("? unknown");
    expect(causalRelationLabel("suspected")).toBe("suspected");
    expect(topoTS("2026-11-12T04:57:31Z")).toBe("2026-11-12 04:57 UTC");
    expect(severityTone("")).toBe("none");
    expect(severityTone("crit")).toBe("red");
    expect(severityTone("warn")).toBe("amber");
  });
});

describe("deriveContextModel — layout from the context only (never invents)", () => {
  it("P-3E0400: no ego-graph (no links), one device panel with its four evidence interfaces", () => {
    const m = deriveContextModel(read(P3E0400_CONTEXT));
    expect(m.ego).toBeNull();
    expect(m.panels).toHaveLength(1);
    const p = m.panels[0];
    expect(p.ports.map((x) => x.fault.port)).toEqual(["Gi3", "Gi4", "Tu1", "Tu2"]);
    // device → Gi4/Tu1/Tu2 are suspected (directed); Gi3 ↔ device is undirected
    // ("?" — they only occurred together), exactly as the server golden draws it
    const rels = p.connectors.map((c) => c.relation ?? "none");
    expect(rels).toEqual(["unknown", "suspected", "suspected", "suspected"]);
    // the same count the server partial prints under its picture
    expect(p.undirectedPortPairs).toBe(6);
    expect(p.devTone).toBe("red");
  });

  it("topology_only: every drawn node and edge id comes from the context", () => {
    const tc = read(TOPOLOGY_ONLY_CONTEXT);
    const m = deriveContextModel(tc);
    expect(m.ego).not.toBeNull();
    const ids = new Set(tc.nodes.map((n) => n.id));
    expect(m.ego!.nodes.every((n) => ids.has(n.node.id))).toBe(true);
    expect(m.ego!.nodes).toHaveLength(tc.nodes.length);
    expect(m.ego!.edges.map((e) => e.edge.id).sort()).toEqual(tc.edges.map((e) => e.id).sort());
    // the known link with no engine edge carries the "?" mark; the cross-device
    // engine edge is drawn as suspected
    expect(m.ego!.edges.find((e) => e.edge.id === "e-edge1-isp")?.unknownMark).toBeDefined();
    expect(m.ego!.causal.map((c) => c.relation)).toEqual(["suspected"]);
  });

  it("no_asset_mapping draws nothing — there is nothing placed to draw", () => {
    const m = deriveContextModel(read(NO_ASSET_MAPPING_CONTEXT));
    expect(m.ego).toBeNull();
    expect(m.panels).toEqual([]);
  });
});

describe("derivePathModel — the context decides, the legacy guesses step aside", () => {
  const routingTimeline = (): CorrTimeline => ({
    correlation_id: "c", verdict_tier: "suspected", top_hypothesis: "", edges: [],
    signals: [{
      signal_id: "s1", ts: "2026-11-12T04:50:00Z", source: "syslog", kind: "bgp_adjacency_change", severity: "warn",
      entity_type: "device", entity_id: "wan-r2", site: "", value: 0, metric_name: "", attached: true,
      modality_class: "control_plane", attrs: JSON.stringify({ peer: "10.0.0.1" }),
    }],
  } as unknown as CorrTimeline);

  it("without a context the pre-v2 adjacency fallback still applies", () => {
    expect(derivePathModel(null, routingTimeline()).mode).toBe("adjacency");
  });

  it("with a context the adjacency is never guessed — the context state renders", () => {
    const m = derivePathModel(null, routingTimeline(), read(P3E0400_CONTEXT));
    expect(m.mode).toBe("context");
    expect(m.adjacency).toBeUndefined();
    expect(m.context?.state).toBe("device_only");
    expect(m.contextModel?.panels).toHaveLength(1);
  });

  it("each of the four states yields a context model", () => {
    for (const fx of [P3E0400_CONTEXT, TOPOLOGY_ONLY_CONTEXT, TOPOLOGY_WITH_PATH_CONTEXT, NO_ASSET_MAPPING_CONTEXT]) {
      const tc = read(fx);
      const m = derivePathModel(null, null, tc);
      expect(m.context?.state).toBe(tc.state);
      expect(m.contextModel).toBeDefined();
    }
  });
});
