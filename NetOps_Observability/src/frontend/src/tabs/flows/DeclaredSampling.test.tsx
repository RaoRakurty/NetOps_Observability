// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";

const flowsSampling = vi.fn();
const setFlowSampling = vi.fn();
const removeFlowSampling = vi.fn();
vi.mock("../../services/api", () => ({
  api: {
    flowsSampling: (...a: unknown[]) => flowsSampling(...a),
    setFlowSampling: (...a: unknown[]) => setFlowSampling(...a),
    removeFlowSampling: (...a: unknown[]) => removeFlowSampling(...a),
  },
}));

import DeclaredSampling from "./DeclaredSampling";

const exporters = [
  { exporter: "10.1.0.1", device_name: "edge-1", flows: 100, flows_rate_reported: 0, can_declare: true },
  { exporter: "10.1.0.2", device_name: "edge-2", flows: 50, flows_rate_reported: 50, can_declare: true },
  { exporter: "10.1.0.3", device_name: "edge-3", flows: 10, flows_rate_reported: 0, declared_rate: 500, can_declare: false },
];

beforeEach(() => {
  flowsSampling.mockReset();
  setFlowSampling.mockReset();
  removeFlowSampling.mockReset();
  flowsSampling.mockResolvedValue({ declarations: [], exporters });
});

describe("DeclaredSampling", () => {
  it("lists only routers that report no rate, and the ones already declared", async () => {
    render(<DeclaredSampling />);
    expect(await screen.findByText("edge-1")).toBeInTheDocument();
    expect(screen.queryByText("edge-2")).toBeNull(); // reports its rate
    expect(screen.getByText("edge-3")).toBeInTheDocument();
    expect(screen.getByText("100 of 100")).toBeInTheDocument();
    // A router the workspace cannot declare for shows the rate, read-only.
    expect(screen.getByText("500")).toBeInTheDocument();
    expect(screen.getAllByRole("button", { name: "Save" })).toHaveLength(1);
  });

  it("saves a whole number of 2 or more and refuses anything else", async () => {
    setFlowSampling.mockResolvedValue({ exporter: "10.1.0.1", rate: 1000 });
    render(<DeclaredSampling />);
    const input = await screen.findByLabelText("Sampling rate for edge-1, 1 in N");
    fireEvent.change(input, { target: { value: "1" } });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    expect(await screen.findByRole("status")).toHaveTextContent("Enter a whole number of 2 or more.");
    expect(setFlowSampling).not.toHaveBeenCalled();
    fireEvent.change(input, { target: { value: "1000" } });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(setFlowSampling).toHaveBeenCalledWith("10.1.0.1", 1000));
    expect(await screen.findByRole("status")).toHaveTextContent("Saved: edge-1 counts 1 in 1,000.");
  });

  it("says plainly when the server refuses", async () => {
    setFlowSampling.mockRejectedValue(Object.assign(new Error("no exporter with that address in your workspace"), { status: 404 }));
    render(<DeclaredSampling />);
    fireEvent.change(await screen.findByLabelText("Sampling rate for edge-1, 1 in N"), { target: { value: "64" } });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    expect(await screen.findByRole("status")).not.toBeEmptyDOMElement();
  });

  it("states it when every router reports its rate", async () => {
    flowsSampling.mockResolvedValue({ declarations: [], exporters: [exporters[1]] });
    render(<DeclaredSampling />);
    expect(await screen.findByText("Every router here reports its rate.")).toBeInTheDocument();
  });
});
