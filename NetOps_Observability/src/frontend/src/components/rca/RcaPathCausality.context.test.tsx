// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// RcaPathCausality.context.test.tsx — section 6 from the server's topology
// context (RCA document v2 §2): the four states, the three layers, the server's
// own state words, and NOTHING drawn that the context does not carry.

import { describe, it, expect, afterEach } from "vitest";
import { render, screen, cleanup, within } from "@testing-library/react";
import RcaPathCausality from "./RcaPathCausality";
import { signal, timeline } from "../../test/factories";
import { readTopologyContext } from "./topologyContext";
import {
  P3E0400_CONTEXT, TOPOLOGY_ONLY_CONTEXT, TOPOLOGY_WITH_PATH_CONTEXT, NO_ASSET_MAPPING_CONTEXT,
} from "./testdata/topologyFixtures";

afterEach(cleanup);

const ctx = (v: unknown) => {
  const tc = readTopologyContext(v);
  if (!tc) throw new Error("fixture did not validate");
  return tc;
};

// A routing signal the pre-v2 fallback would have turned into a guessed
// "router → peer" chain. With a context present it must never appear.
const routingTl = () => timeline({
  verdict_tier: "suspected",
  signals: [signal({ kind: "bgp_state_anomaly", modality_class: "control_plane", entity_id: "cedge-60-07ae8615:10.9.9.9", attrs: '{"peer":"10.9.9.9"}' })],
});

describe("RcaPathCausality — topology context (four states)", () => {
  it("device_only (P-3E0400): the device diagnostic card with the server's state words", () => {
    render(<RcaPathCausality data={null} timeline={routingTl()} context={ctx(P3E0400_CONTEXT)} />);
    expect(screen.getByTestId("topo-state")).toHaveTextContent("device only — no neighbour or path data");
    expect(screen.getByTestId("topo-reason")).toHaveTextContent("cedge-60-07ae8615 is in the inventory, but no neighbour or path data was found for it.");
    const card = screen.getByTestId("topo-device-card");
    expect(within(card).getByText("Device diagnostic — cedge-60-07ae8615")).toBeTruthy();
    expect(card).toHaveTextContent("wan edge");
    expect(card).toHaveTextContent("the inventory");
    expect(card).toHaveTextContent("LLDP, CDP, BGP-LS, the persisted topology graph, the SD-WAN overlay, the SD-WAN controller");
    for (const p of ["Gi3", "Gi4", "Tu1", "Tu2"]) expect(within(card).getByText(p)).toBeTruthy();
    expect(screen.getByTestId("topo-remediation")).toHaveTextContent(/Enable LLDP or CDP on cedge-60-07ae8615/);
    // never "not path-shaped", never the guessed adjacency
    expect(document.body.textContent).not.toMatch(/path-shaped/);
    expect(screen.queryByText(/localizes to this routing adjacency/i)).toBeNull();
    expect(screen.queryByText("10.9.9.9")).toBeNull();
  });

  it("topology_only: known topology, the causal path marked unverified", () => {
    render(<RcaPathCausality data={null} timeline={null} context={ctx(TOPOLOGY_ONLY_CONTEXT)} />);
    expect(screen.getByTestId("topo-state")).toHaveTextContent("known topology, no measured path");
    expect(screen.getByTestId("topo-unverified")).toHaveTextContent("Causal path unverified");
    expect(screen.getByText("2 more neighbours not drawn")).toBeTruthy();
    expect(screen.queryByTestId("topo-device-card")).toBeNull();
  });

  it("topology_with_path: the measured path chain AND the known topology", () => {
    const tl = timeline({ verdict_tier: "suspected", signals: [] }) as ReturnType<typeof timeline> & { path?: unknown };
    tl.path = {
      spine: [
        { index: 0, kind: "client", label: "client-01", boundary: "LAN", state: "responding" },
        { index: 1, kind: "wan_edge", label: "edge-1", boundary: "SD-WAN", state: "responding" },
      ],
      edges: [{ from: 0, to: 1, type: "PATH_HAS_HOP", evidence: { ref: "ev1", method: "traceroute_icmp" } }],
      boundaries: [], evidence_branches: [],
    };
    render(<RcaPathCausality data={null} timeline={tl} context={ctx(TOPOLOGY_WITH_PATH_CONTEXT)} />);
    expect(screen.getByTestId("topo-state")).toHaveTextContent("topology with measured path");
    expect(screen.getByText("client-01")).toBeTruthy();                 // the measured chain
    expect(screen.queryByTestId("topo-unverified")).toBeNull();
  });

  it("a derived spine is NOT drawn as a measured path when the context says there is none", () => {
    const tl = timeline({ verdict_tier: "suspected", signals: [] }) as ReturnType<typeof timeline> & { path?: unknown };
    tl.path = {
      spine: [{ index: 0, kind: "client", label: "client-01", boundary: "LAN", state: "responding" }],
      edges: [], boundaries: [], evidence_branches: [],
    };
    render(<RcaPathCausality data={null} timeline={tl} context={ctx(TOPOLOGY_ONLY_CONTEXT)} />);
    expect(screen.queryByText("client-01")).toBeNull();
    expect(screen.getByTestId("topo-unverified")).toBeTruthy();
  });

  it("no_asset_mapping: an explicit data-availability error with remediation, nothing drawn", () => {
    const { container } = render(<RcaPathCausality data={null} timeline={routingTl()} context={ctx(NO_ASSET_MAPPING_CONTEXT)} />);
    expect(screen.getByTestId("topo-state")).toHaveTextContent("no asset mapping");
    expect(screen.getByRole("alert")).toHaveTextContent(/Data-availability error/);
    expect(screen.getByRole("alert")).toHaveTextContent("Not in the inventory: ghost-9.");
    expect(screen.getByTestId("topo-remediation")).toHaveTextContent(/Add the device to the inventory/);
    expect(container.querySelectorAll("[data-node]").length).toBe(0);
  });

  it("never renders a node, edge or port absent from the contract", () => {
    for (const fx of [P3E0400_CONTEXT, TOPOLOGY_ONLY_CONTEXT, TOPOLOGY_WITH_PATH_CONTEXT, NO_ASSET_MAPPING_CONTEXT]) {
      const tc = ctx(fx);
      const { container, unmount } = render(<RcaPathCausality data={null} timeline={routingTl()} context={tc} />);
      const nodeIds = new Set(tc.nodes.map((n) => n.id));
      const drawnNodes = [...container.querySelectorAll("[data-node]")].map((e) => e.getAttribute("data-node"));
      expect(drawnNodes.every((id) => id !== null && nodeIds.has(id))).toBe(true);
      const edgeIds = new Set(tc.edges.map((e) => e.id));
      const drawnEdges = [...container.querySelectorAll("[data-edge]")].map((e) => e.getAttribute("data-edge"));
      expect(drawnEdges.every((id) => id !== null && edgeIds.has(id))).toBe(true);
      expect(drawnEdges.length).toBe(tc.edges.length);
      const portIds = new Set(tc.faults.filter((f) => f.target_type === "interface").map((f) => f.target_id));
      const drawnPorts = [...container.querySelectorAll("[data-port]")].map((e) => e.getAttribute("data-port"));
      expect(drawnPorts.every((id) => id !== null && portIds.has(id))).toBe(true);
      // the legacy guessed chain never appears beside a context
      expect(container.querySelectorAll(".rpc-dev").length).toBe(0);
      unmount();
    }
  });

  it("draws the causal overlay distinctly: suspected dashed, unknown with '?'", () => {
    const { container } = render(<RcaPathCausality data={null} timeline={null} context={ctx(TOPOLOGY_ONLY_CONTEXT)} />);
    expect(container.querySelectorAll('.rtc-causal[data-relation="suspected"]').length).toBeGreaterThan(0);
    const unknown = container.querySelectorAll('.rtc-causal[data-relation="unknown"]');
    expect(unknown.length).toBeGreaterThan(0);
    expect(unknown[0].textContent).toContain("?");
  });

  it("escapes context text — a hostile label is text, never markup", () => {
    const hostile = {
      ...TOPOLOGY_ONLY_CONTEXT,
      reason: '<img src=x onerror="alert(1)">',
      nodes: TOPOLOGY_ONLY_CONTEXT.nodes.map((n, i) => (i === 0 ? { ...n, label: "<script>alert(1)</script>" } : n)),
    };
    const { container } = render(<RcaPathCausality data={null} timeline={null} context={ctx(hostile)} />);
    expect(container.querySelector("script")).toBeNull();
    expect(container.querySelector("img")).toBeNull();
    expect(screen.getByTestId("topo-reason")).toHaveTextContent('<img src=x onerror="alert(1)">');
  });
});
