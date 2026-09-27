// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// cards.test.tsx — IncidentCard (engine's RCA contract, honest root cause),
// ChangeCard (honest relation), RecommendationCard (never acts; safe refs).

import { describe, it, expect, afterEach } from "vitest";
import { render, screen, cleanup } from "@testing-library/react";
import { ChangeCard, IncidentCard, RecommendationCard, incidentEvidence, readRecommendation } from "./cards";
import { HOSTILE, RCA_DETAIL, changeRow, incidentResult } from "../test/irisFixtures";

afterEach(cleanup);

const incRow = (incidentResult().rows as Record<string, unknown>[])[0];

describe("IncidentCard", () => {
  it("shows the engine's identified root cause, start time and scope", () => {
    render(<IncidentCard row={incRow} detail={RCA_DETAIL} />);
    expect(screen.getByRole("link", { name: "INC-42 · WAN loss at DFW" })).toHaveAttribute(
      "href",
      "/#/investigate/rca?id=7b0e8c4e-1111-4222-8333-444455556666",
    );
    const cause = screen.getByText("Carrier circuit CKT-9 dropped");
    expect(cause.className).toContain("accent-cause");
    expect(screen.getByText("Confidence: High").className).toContain("accent-evidence");
    expect(screen.getByText("Evidence converges on the DFW WAN edge")).toBeInTheDocument();
    expect(screen.getByText(/2 devices · 1 site/)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "edge-1" })).toHaveAttribute("href", "/#/infrastructure/devices?q=edge-1");
    expect(screen.getByText("Carrier (ISP)")).toBeInTheDocument();
    expect(screen.getByText("Carrier ticket status")).toBeInTheDocument();
  });

  it("does not claim a root cause the engine has not identified", () => {
    const detail = { ...RCA_DETAIL, ConfidenceLabel: "Low", RootCause: { ...RCA_DETAIL.RootCause, Identified: false, PossibleCause: "a carrier fault" } };
    render(<IncidentCard row={incRow} detail={detail} />);
    expect(screen.queryByText("Carrier circuit CKT-9 dropped")).toBeNull();
    expect(screen.getByText(/Not identified yet\./)).toHaveTextContent("Possibly because of: a carrier fault");
    expect(screen.getByText("Confidence: Low").className).not.toContain("accent");
  });

  it("reads snake_case keys too", () => {
    render(<IncidentCard detail={{ title: "snake", root_cause: { identified: true, statement: "cause here" } }} />);
    expect(screen.getByText("snake")).toBeInTheDocument();
    expect(screen.getByText("cause here")).toBeInTheDocument();
  });

  it("states a missing analysis and a missing incident", () => {
    const { rerender } = render(<IncidentCard row={incRow} />);
    expect(screen.getByText(/root-cause analysis for this incident is not available yet/)).toBeInTheDocument();
    rerender(<IncidentCard />);
    expect(screen.getByRole("status")).toHaveTextContent("No incident was found for this question.");
  });

  it("survives malformed detail", () => {
    render(<IncidentCard row={incRow} detail={{ RootCause: "x", Affected: { Devices: [1, null, {}] }, Missing: "no" }} />);
    expect(screen.getByText(/Not identified yet/)).toBeInTheDocument();
  });

  it("renders hostile engine text as text", () => {
    const { container } = render(
      <IncidentCard detail={{ Title: HOSTILE, RootCause: { Identified: true, Statement: HOSTILE }, Affected: { Devices: [HOSTILE] } }} />,
    );
    expect(container.querySelector("script")).toBeNull();
    expect(container.textContent).toContain(HOSTILE);
  });

  it("incidentEvidence reads the known and missing lines", () => {
    expect(incidentEvidence(RCA_DETAIL).known).toHaveLength(2);
    expect(incidentEvidence(null)).toEqual({ known: [], missing: [] });
  });
});

describe("ChangeCard", () => {
  it("shows the change with the honest relation", () => {
    render(<ChangeCard row={changeRow({ incident_id: "i1" })} />);
    expect(screen.getByRole("link", { name: "Config change · core-sw-1" })).toHaveAttribute(
      "href",
      "/#/operations/digital-experience/changes?id=chg-1",
    );
    expect(screen.getByText(/Happened before — not proven cause/)).toBeInTheDocument();
    expect(screen.getByText("Change record · Not recorded")).toBeInTheDocument();
  });

  it("marks a critical change in words", () => {
    render(<ChangeCard row={changeRow()} critical />);
    expect(screen.getByText("Critical change")).toBeInTheDocument();
  });

  it("states a missing change", () => {
    render(<ChangeCard />);
    expect(screen.getByRole("status")).toHaveTextContent("No change was found");
  });
});

describe("RecommendationCard", () => {
  it("lists steps and always says nothing was executed", () => {
    render(<RecommendationCard recommendation={{ title: "Check the circuit", steps: ["Open a carrier ticket", "Watch BGP"], rationale: "Loss on CKT-9" }} />);
    expect(screen.getByText("Check the circuit")).toBeInTheDocument();
    expect(screen.getAllByRole("listitem").map((l) => l.textContent)).toEqual(["Open a carrier ticket", "Watch BGP"]);
    expect(screen.getByText("No action has been executed.")).toBeInTheDocument();
  });

  it("links only same-origin references", () => {
    render(
      <RecommendationCard
        recommendation={{ title: "t", steps: ["s"], refs: [{ label: "Runbook", href: "/docs/runbook" }, { label: "Evil", href: "javascript:alert(1)" }, { label: "Off", href: "https://evil.example" }] }}
      />,
    );
    expect(screen.getByRole("link", { name: "Runbook" })).toHaveAttribute("href", "/docs/runbook");
    expect(screen.queryByRole("link", { name: "Evil" })).toBeNull();
    expect(screen.queryByRole("link", { name: "Off" })).toBeNull();
  });

  it("with nothing to recommend still says nothing was executed", () => {
    render(<RecommendationCard recommendation={42} />);
    expect(screen.getByText("No recommendation was made for this answer.")).toBeInTheDocument();
    expect(screen.getByText("No action has been executed.")).toBeInTheDocument();
  });

  it("reads a nested recommendation and bounds steps", () => {
    const r = readRecommendation({ recommendation: { steps: Array.from({ length: 30 }, (_, i) => `s${i}`) } });
    expect(r?.title).toBe("Suggested next steps");
    expect(r?.steps).toHaveLength(10);
  });

  it("renders hostile steps as text", () => {
    const { container } = render(<RecommendationCard recommendation={{ title: HOSTILE, steps: [HOSTILE] }} />);
    expect(container.querySelector("script")).toBeNull();
    expect(container.textContent).toContain(HOSTILE);
  });
});
