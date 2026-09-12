// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// EvidencePopover.test.tsx — the hover peek shows WHY a node/edge is here: its
// state, the driving issue, and the top evidence rows (source · summary · conf),
// without a click. Proves the pixels + that it renders nothing for an unknown id.

import { describe, it, expect, afterEach } from "vitest";
import { render, screen, cleanup } from "@testing-library/react";
import EvidencePopover from "./EvidencePopover";
import type { TopologyView } from "../api/topologyTypes";

afterEach(cleanup);

const view: TopologyView = {
  view_id: "v1", topology_id: "t1", mode: "explore", scope: { tenant_id: "t1" },
  generated_at: "", layout_type: "spine_leaf",
  nodes: [
    {
      id: "leaf1", label: "leaf1", kind: "switch", role: "leaf", vendor: "Arista",
      health: "critical", confidence: 1,
      issues: [{ severity: "critical", summary: "BGP session down to spine1" }],
      evidence: [
        { source: "lldp", confidence: 0.9, summary: "neighbor spine1 on Ethernet1" },
        { source: "snmp", confidence: 0.8, summary: "ifOperStatus down" },
      ],
    },
    { id: "spine1", label: "spine1", kind: "switch", health: "ok", confidence: 1, evidence: [] },
  ],
  edges: [
    {
      id: "e1", source: "leaf1", target: "spine1", relationship: "connected_to",
      protocol: "lldp", status: "degraded", utilization_pct: 82, confidence: 0.9,
      evidence: [{ source: "lldp", confidence: 0.9, summary: "bidirectional LLDP adjacency" }],
    },
  ],
  groups: [], overlays: [],
};

describe("EvidencePopover", () => {
  it("shows a node's state, driving issue and top evidence", () => {
    render(<EvidencePopover view={view} nodeId="leaf1" x={100} y={100} />);
    expect(screen.getByText("leaf1")).toBeTruthy();
    expect(screen.getByText("Critical")).toBeTruthy();           // health label
    expect(screen.getByText(/BGP session down/)).toBeTruthy();   // the WHY (issue)
    expect(screen.getByText("LLDP")).toBeTruthy();               // evidence source label
    expect(screen.getByText(/neighbor spine1/)).toBeTruthy();    // evidence summary
    expect(screen.getByText("90%")).toBeTruthy();                // evidence confidence
  });

  it("shows an edge's endpoints, status/util and evidence", () => {
    render(<EvidencePopover view={view} edgeId="e1" x={100} y={100} />);
    expect(screen.getByText(/leaf1 → spine1/)).toBeTruthy();
    expect(screen.getByText(/82% util/)).toBeTruthy();
    expect(screen.getByText(/bidirectional LLDP/)).toBeTruthy();
  });

  it("renders nothing for an unknown id", () => {
    const { container } = render(<EvidencePopover view={view} nodeId="ghost" x={0} y={0} />);
    expect(container.querySelector(".topo-evpop")).toBeNull();
  });
});
