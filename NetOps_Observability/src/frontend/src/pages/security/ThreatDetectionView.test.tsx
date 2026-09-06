// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// ThreatDetectionView.test.tsx — the two sub-views. The existing flow panels
// are REUSED as "Network Behavior"; the detections list is the threat evidence
// lane of the findings store.

import { describe, it, expect, vi, afterEach, beforeEach } from "vitest";
import { render, screen, cleanup, fireEvent, waitFor } from "@testing-library/react";

const securityFindings = vi.fn();
const openInspector = vi.fn();

vi.mock("../../services/api", () => ({
  api: { securityFindings: (...a: unknown[]) => securityFindings(...a) },
}));
vi.mock("../ThreatDetection", () => ({ default: () => <div>flow panels</div> }));
vi.mock("../../context/workspace", () => ({ useWorkspace: () => ({ enabled: true, openInspector }) }));

import ThreatDetectionView from "./ThreatDetectionView";
import { FINDINGS, finding } from "./fixtures";

afterEach(cleanup);
beforeEach(() => {
  securityFindings.mockReset(); openInspector.mockReset();
  securityFindings.mockResolvedValue({ items: FINDINGS, next_cursor: null, total: FINDINGS.length });
});

describe("Threat Detection", () => {
  it("opens on Detections and lists ONLY the threat evidence lane", async () => {
    render(<ThreatDetectionView />);
    expect(await screen.findByText("Outbound beacon to a rare destination")).toBeTruthy();
    expect(screen.queryByText("Non-TLS HTTP server")).toBeNull();
    expect(screen.getByText(/1 current detection$/)).toBeTruthy();
  });

  it("treats the store's 'signal' lane as the same lane as the contract's 'threat'", async () => {
    securityFindings.mockResolvedValue({
      items: [finding({ id: "s1", evidence_class: "signal", control_title: "Logging disabled" })],
      next_cursor: null, total: 1,
    });
    render(<ThreatDetectionView />);
    expect(await screen.findByText("Logging disabled")).toBeTruthy();
  });

  it("shows the MITRE technique tags, and says untagged when there are none", async () => {
    securityFindings.mockResolvedValue({
      items: [FINDINGS[4], finding({ id: "s2", evidence_class: "threat", control_title: "Odd login", standards: [] })],
      next_cursor: null, total: 2,
    });
    render(<ThreatDetectionView />);
    expect(await screen.findByText("T1071")).toBeTruthy();
    expect(screen.getByText("untagged")).toBeTruthy();
  });

  it("an empty detections list says no rule matched, not that the estate is clean", async () => {
    securityFindings.mockResolvedValue({ items: [], next_cursor: null, total: 0 });
    render(<ThreatDetectionView />);
    expect(await screen.findByText(/No detection fired in this window/i)).toBeTruthy();
    expect(screen.getByRole("button", { name: /Ask Iris about an empty detections list/i })).toBeTruthy();
  });

  it("Network Behavior renders the existing flow panels, unchanged", async () => {
    render(<ThreatDetectionView />);
    await screen.findByText("Outbound beacon to a rare destination");
    fireEvent.click(screen.getByRole("button", { name: "Network Behavior" }));
    expect(screen.getByText("flow panels")).toBeTruthy();
    expect(screen.getByText(/Flow-derived behavior/i)).toBeTruthy();
    expect(screen.getByRole("button", { name: /Ask Iris about Threat detection/i })).toBeTruthy();
  });

  it("opens the same Finding detail in the Inspector", async () => {
    render(<ThreatDetectionView />);
    fireEvent.click(await screen.findByText("Outbound beacon to a rare destination"));
    await waitFor(() => expect(openInspector).toHaveBeenCalled());
    expect(openInspector.mock.calls[0][1].title).toBe("Outbound beacon to a rare destination");
  });
});
