// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// ThreatDetectionView.test.tsx — the two sub-views. The existing flow panels
// are REUSED as "Network Behavior"; the detections list is the threat evidence
// lane of the findings store.
//
// The lane is now selected AT THE STORE (review 2026-09-08, 3.3-03), so the
// stand-in below HONOURS the evidence_class parameter the way the server does.
// It used to answer every call with the same all-lanes fixture, which meant the
// "lists ONLY the threat lane" case passed while proving only that a browser
// filter ran — the browser filter WAS the defect. A double that ignores the
// query cannot tell a page that asked the right question from one that did not.

import { describe, it, expect, vi, afterEach, beforeEach } from "vitest";
import { render, screen, cleanup, fireEvent, waitFor } from "@testing-library/react";
import type { SecFinding, SecFindingQuery } from "../../services/api";

const securityFindings = vi.fn();
const openInspector = vi.fn();

vi.mock("../../services/api", () => ({
  api: { securityFindings: (...a: unknown[]) => securityFindings(...a) },
}));
vi.mock("../ThreatDetection", () => ({ default: () => <div>flow panels</div> }));
vi.mock("../../context/workspace", () => ({ useWorkspace: () => ({ enabled: true, openInspector }) }));

import ThreatDetectionView from "./ThreatDetectionView";
import { FINDINGS, finding } from "./fixtures";

// serveLanes is the server's own behaviour: the evidence_class parameter selects
// the lane, "threat" and "signal" name the SAME lane, and `total` is the lane's
// size rather than the size of the page.
function serveLanes(corpus: SecFinding[], page = 200) {
  securityFindings.mockImplementation((q: SecFindingQuery = {}) => {
    const asked = (q.evidence_class ?? "").split(",").map((s) => s.trim().toLowerCase()).filter(Boolean);
    const wanted = new Set(asked.flatMap((c) => (c === "threat" || c === "signal" ? ["threat", "signal"] : [c])));
    const lane = wanted.size === 0
      ? corpus
      : corpus.filter((f) => wanted.has((f.evidence_class ?? "").toLowerCase()));
    // Newest first, the way the store answers.
    const sorted = [...lane].sort((a, b) => String(b.time ?? "").localeCompare(String(a.time ?? "")));
    return Promise.resolve({ items: sorted.slice(0, page), next_cursor: null, total: sorted.length });
  });
}

// postureBurst is the failure this page was losing detections to: one detection,
// buried under `n` posture verdicts that are all NEWER than it.
function postureBurst(n: number): SecFinding[] {
  const detection = finding({
    id: "detect-1", evidence_class: "signal", control_title: "Outbound beacon to a rare destination",
    standards: ["T1071"], time: "2026-09-01T10:00:00Z",
  });
  const posture = Array.from({ length: n }, (_, i) => finding({
    id: `p${i}`, evidence_class: "posture", control_title: `Telnet on VTY ${i}`,
    time: `2026-09-0${2 + (i % 8)}T10:00:00Z`,
  }));
  return [detection, ...posture];
}

afterEach(cleanup);
beforeEach(() => {
  securityFindings.mockReset(); openInspector.mockReset();
  serveLanes(FINDINGS);
});

describe("Threat Detection", () => {
  it("asks the SERVER for the threat lane, by both of its spellings", async () => {
    render(<ThreatDetectionView />);
    await screen.findByText("Outbound beacon to a rare destination");
    const q = securityFindings.mock.calls[0][0] as SecFindingQuery;
    const asked = (q.evidence_class ?? "").split(",").map((s) => s.trim());
    expect(asked).toContain("threat");
    expect(asked).toContain("signal");
    expect(q.current).toBe(true);
  });

  it("opens on Detections and lists ONLY the threat evidence lane", async () => {
    render(<ThreatDetectionView />);
    expect(await screen.findByText("Outbound beacon to a rare destination")).toBeTruthy();
    expect(screen.queryByText("Non-TLS HTTP server")).toBeNull();
    expect(screen.getByText(/1 current detection$/)).toBeTruthy();
  });

  // THE DEFECT. 250 posture findings, every one newer than the detection. Under
  // the old browser filter the first page held 200 posture rows and no
  // detection, and the screen said no detection had fired.
  it("still finds a detection under a posture scan burst", async () => {
    serveLanes(postureBurst(250));
    render(<ThreatDetectionView />);
    expect(await screen.findByText("Outbound beacon to a rare destination")).toBeTruthy();
    expect(screen.queryByText(/No detection fired in this window/i)).toBeNull();
    expect(screen.getByText(/1 current detection$/)).toBeTruthy();
  });

  it("says when the lane holds more detections than the table shows", async () => {
    const many = Array.from({ length: 320 }, (_, i) => finding({
      id: `d${i}`, evidence_class: "signal", control_title: `Detection ${i}`,
      time: `2026-09-01T10:00:${String(i % 60).padStart(2, "0")}Z`,
    }));
    serveLanes(many);
    render(<ThreatDetectionView />);
    await screen.findByText(/320 current detections/);
    expect(screen.getByText(/showing the newest 200/)).toBeTruthy();
  });

  it("treats the store's 'signal' lane as the same lane as the contract's 'threat'", async () => {
    serveLanes([finding({ id: "s1", evidence_class: "signal", control_title: "Logging disabled" })]);
    render(<ThreatDetectionView />);
    expect(await screen.findByText("Logging disabled")).toBeTruthy();
  });

  it("shows the MITRE technique tags, and says untagged when there are none", async () => {
    serveLanes([
      finding({ id: "s3", evidence_class: "signal", control_title: "Beacon", standards: ["T1071"] }),
      finding({ id: "s2", evidence_class: "threat", control_title: "Odd login", standards: [] }),
    ]);
    render(<ThreatDetectionView />);
    expect(await screen.findByText("T1071")).toBeTruthy();
    expect(screen.getByText("untagged")).toBeTruthy();
  });

  it("an empty detections list says no rule matched, not that the estate is clean", async () => {
    serveLanes([]);
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
