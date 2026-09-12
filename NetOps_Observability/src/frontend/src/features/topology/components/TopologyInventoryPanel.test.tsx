// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import { describe, it, expect, beforeAll, afterAll, afterEach, vi } from "vitest";
import { render, screen, cleanup, fireEvent, act } from "@testing-library/react";
import { TopologyInventoryPanel } from "./TopologyInventoryPanel";
import type { TopologyView, TopologyNode } from "../api/topologyTypes";

// The panel is windowed (perf wave 2 — it used to build ~15 000 DOM elements for
// a 1 000-device fleet). happy-dom does no layout, so a 0px viewport would let a
// broken implementation pass by rendering almost nothing; report a real one, as
// perf/setup.ts does.
const VIEWPORT = 320;
let restore: PropertyDescriptor | undefined;
beforeAll(() => {
  restore = Object.getOwnPropertyDescriptor(HTMLElement.prototype, "clientHeight");
  Object.defineProperty(HTMLElement.prototype, "clientHeight", { configurable: true, get: () => VIEWPORT });
});
afterAll(() => {
  if (restore) Object.defineProperty(HTMLElement.prototype, "clientHeight", restore);
});
afterEach(cleanup);

function node(i: number, over: Partial<TopologyNode> = {}): TopologyNode {
  return {
    id: `n-${i}`,
    // Zero-padded so the label sort is the same as the numeric order.
    label: `leaf-${String(i).padStart(4, "0")}`,
    kind: "switch",
    role: "dc_leaf",
    vendor: "arista",
    site: "lon-dc1",
    mgmt_ip: `10.0.${(i >> 8) & 255}.${i & 255}`,
    health: "ok",
    confidence: 1,
    evidence: [],
    ...over,
  };
}

function view(nodes: TopologyNode[]): TopologyView {
  return {
    view_id: "v", mode: "explore", layout_type: "layered",
    generated_at: "2026-09-02T12:00:00Z",
    nodes, edges: [], groups: [], overlays: [],
  };
}

const fleet = (n: number) => view(Array.from({ length: n }, (_, i) => node(i)));

function Panel({ v, onPick = () => {} }: { v: TopologyView; onPick?: (id: string) => void }) {
  return <TopologyInventoryPanel view={v} selection={{}} onPick={onPick} />;
}

describe("TopologyInventoryPanel — counts describe the whole fleet", () => {
  it("shows the total and the critical count, not the rendered slice", () => {
    const nodes = Array.from({ length: 300 }, (_, i) =>
      node(i, { health: i % 10 === 0 ? "critical" : "ok" }),
    );
    render(<Panel v={view(nodes)} />);
    expect(screen.getByText("300")).toBeInTheDocument();
    expect(screen.getByText(/30 critical/)).toBeInTheDocument();
  });

  it("counts only devices — groups and sites are not inventory rows", () => {
    const nodes = [
      node(0), node(1),
      node(2, { kind: "group", label: "rack-a" }),
      node(3, { kind: "site", label: "lon-dc1" }),
    ];
    render(<Panel v={view(nodes)} />);
    expect(screen.getByText("2")).toBeInTheDocument();
    expect(screen.queryByText("rack-a")).not.toBeInTheDocument();
    expect(screen.queryByText("lon-dc1")).not.toBeInTheDocument();
  });
});

describe("TopologyInventoryPanel — the list is windowed", () => {
  it("renders a screenful of a 1,000-device fleet, not 1,000 rows", () => {
    render(<Panel v={fleet(1000)} />);
    const options = screen.getAllByRole("option");
    expect(options.length).toBeGreaterThan(0);
    expect(options.length).toBeLessThan(40);
    // The fleet is still fully addressable: the count says 1000 and the
    // scroller is sized for all of it.
    expect(screen.getByText("1000")).toBeInTheDocument();
  });

  it("keeps the DOM flat as the fleet grows — the regression perf wave 2 fixed", () => {
    const { container, unmount } = render(<Panel v={fleet(40)} />);
    const small = container.querySelectorAll("*").length;
    unmount();
    const { container: c2 } = render(<Panel v={fleet(2000)} />);
    const large = c2.querySelectorAll("*").length;
    expect(large).toBe(small);
  });

  it("rows stay clickable and report the device they represent", () => {
    const onPick = vi.fn();
    render(<Panel v={fleet(500)} onPick={onPick} />);
    fireEvent.click(screen.getByText("leaf-0000"));
    expect(onPick).toHaveBeenCalledWith("n-0");
  });
});

describe("TopologyInventoryPanel — filtering", () => {
  it("narrows on hostname, management IP, vendor and site", () => {
    const nodes = [
      node(0, { label: "core-a", vendor: "juniper", site: "fra-dc2", mgmt_ip: "10.9.9.9" }),
      node(1, { label: "leaf-b", vendor: "arista", site: "lon-dc1", mgmt_ip: "10.1.1.1" }),
    ];
    const type = (s: string) =>
      act(() => {
        fireEvent.change(screen.getByLabelText("Filter the device inventory"), { target: { value: s } });
      });

    render(<Panel v={view(nodes)} />);
    type("juniper");
    expect(screen.getByText("core-a")).toBeInTheDocument();
    expect(screen.queryByText("leaf-b")).not.toBeInTheDocument();

    type("10.1.1.1");
    expect(screen.getByText("leaf-b")).toBeInTheDocument();
    expect(screen.queryByText("core-a")).not.toBeInTheDocument();

    type("fra");
    expect(screen.getByText("core-a")).toBeInTheDocument();
  });

  it("says the filter matched nothing, distinctly from an empty view", () => {
    render(<Panel v={fleet(10)} />);
    act(() => {
      fireEvent.change(screen.getByLabelText("Filter the device inventory"), { target: { value: "zzz" } });
    });
    expect(screen.getByText("No devices match the filter.")).toBeInTheDocument();

    cleanup();
    render(<Panel v={view([])} />);
    expect(screen.getByText("No devices in this view.")).toBeInTheDocument();
  });

  it("leaves the fleet TOTAL alone while a filter narrows the list", () => {
    render(<Panel v={fleet(200)} />);
    act(() => {
      fireEvent.change(screen.getByLabelText("Filter the device inventory"), { target: { value: "leaf-0001" } });
    });
    // The count is the fleet, not the match: an operator must never read a
    // filtered list as "the network shrank".
    expect(screen.getByText("200")).toBeInTheDocument();
  });
});
