// RcaVerdictBanner.test.tsx — render-level regression for the evidence ledger (gap
// step 2). The banner is the anti-black-box surface: it renders the engine's verdict
// with role-grouped evidence. These pin the PIXELS + the honesty rules:
//   - a confirmation names its TWO independent witnesses with the ⟂ separator;
//   - raw backend vocabulary (modality/owner tokens) is hidden behind operator labels;
//   - an undetermined verdict shows "Why not confirmed" + "Missing to confirm" and
//     NEVER a "Confirmed by" pair (no overclaim);
//   - "Ruled out" surfaces discriminating/contradicting evidence.

import { describe, it, expect, afterEach, vi } from "vitest";
import { render, screen, cleanup } from "@testing-library/react";
import RcaVerdictBanner from "./RcaVerdictBanner";
import type { RcaPathView } from "../../../services/api";

afterEach(cleanup);

function overlay(over: Partial<RcaPathView> = {}): RcaPathView {
  return {
    corr_object_id: "corr-1",
    verdict: "suspected",
    confidence: 0.4,
    internal: false,
    title: "Egress path degraded to Dallas",
    summary: "Loss observed on the Dallas DIA egress.",
    recommended_action: "Confirm impact before ticketing.",
    path: { source: "a", destination: "b", nodes: [], edges: [] },
    annotations: [],
    evidence_summary: {},
    missing_evidence_summary: [],
    ...over,
  };
}

describe("RcaVerdictBanner — confirmed verdict with an independent pair", () => {
  it("names two independent witnesses with the ⟂ separator and operator modality labels", () => {
    render(
      <RcaVerdictBanner
        onClear={vi.fn()}
        overlay={overlay({
          verdict: "confirmed",
          confidence: 0.92,
          evidence_summary: {
            confirming_pair: ["probe-dallas", "leaf-1 syslog"],
            decisive_modalities: ["active_probe", "control_plane"],
            verdict_reason: "Two independent witnesses agree.",
            blast_radius: { devices: 2, paths: 1, interfaces: 0 },
          },
        })}
      />,
    );
    expect(screen.getByText("Confirmed by")).toBeTruthy();
    expect(screen.getByText("probe-dallas")).toBeTruthy();
    expect(screen.getByText("leaf-1 syslog")).toBeTruthy();
    expect(screen.getByText("⟂")).toBeTruthy();
    // Raw-field hiding: tokens map to operator labels, the raw token never renders.
    expect(screen.getByText("Active probe")).toBeTruthy();
    expect(screen.getByText("Control plane")).toBeTruthy();
    expect(document.body.textContent).not.toMatch(/active_probe|control_plane/);
    // Blast radius singularizes correctly.
    expect(screen.getByText(/2 devices · 1 path/)).toBeTruthy();
  });
});

describe("RcaVerdictBanner — undetermined/suspected verdict (no overclaim)", () => {
  it("shows why-not + missing-to-confirm and NO confirming pair", () => {
    render(
      <RcaVerdictBanner
        onClear={vi.fn()}
        overlay={overlay({
          verdict: "suspected",
          evidence_summary: {
            why_not_confirmed: ["Only one independent observer so far."],
            contradicting: ["Isolated device-health change (no traffic impact)"],
          },
          missing_evidence_summary: ["Active probe from a second vantage", "Flow confirmation"],
        })}
      />,
    );
    expect(screen.getByText("Why not confirmed")).toBeTruthy();
    expect(screen.getByText("Only one independent observer so far.")).toBeTruthy();
    expect(screen.getByText("Ruled out")).toBeTruthy();
    expect(screen.getByText("Isolated device-health change (no traffic impact)")).toBeTruthy();
    expect(screen.getByText("Missing to confirm")).toBeTruthy();
    expect(screen.getByText("Active probe from a second vantage")).toBeTruthy();
    // The non-negotiable: a non-confirmed verdict must NOT render a "Confirmed by" pair.
    expect(screen.queryByText("Confirmed by")).toBeNull();
  });

  it("renders the fully-grounded state when nothing is missing", () => {
    render(<RcaVerdictBanner onClear={vi.fn()} overlay={overlay({ missing_evidence_summary: [] })} />);
    expect(screen.getByText(/Fully grounded/)).toBeTruthy();
  });
});

describe("RcaVerdictBanner — C4 causal layer stack", () => {
  const cov = {
    layers: [
      { layer: "device", osi: "device", observed: false, kinds: [], entities: [], peak_severity: "" },
      { layer: "physical", osi: "L1", observed: false, kinds: [], entities: [], peak_severity: "" },
      { layer: "link", osi: "L2", observed: true, kinds: ["link_state_change"], entities: ["dallas-edge:Gi0/1"], peak_severity: "crit" },
      { layer: "network", osi: "L3", observed: false, kinds: [], entities: [], peak_severity: "" },
      { layer: "transport", osi: "L4", observed: true, kinds: ["probe_loss"], entities: ["vantage->dallas-edge"], peak_severity: "high" },
      { layer: "service", osi: "L7", observed: false, kinds: [], entities: [], peak_severity: "" },
      { layer: "application", osi: "L7", observed: false, kinds: [], entities: [], peak_severity: "" },
    ],
    root_layer: "link",
    impact_layer: "transport",
    unmapped_kinds: [] as string[],
  };

  it("renders the stack with root/impact pills and marks the L3 gap a blind spot", () => {
    render(<RcaVerdictBanner onClear={vi.fn()} overlay={overlay({ layer_coverage: cov })} />);
    expect(screen.getByLabelText("Causal layer stack")).toBeTruthy();
    expect(screen.getByText("Root")).toBeTruthy();
    expect(screen.getByText("Impact")).toBeTruthy();
    // L3 routing is unobserved BETWEEN root (L2) and impact (L4) → flagged blind spot.
    expect(screen.getByText("blind spot")).toBeTruthy();
    // operator language only — raw kind tokens never render as visible text.
    expect(document.body.textContent).not.toMatch(/link_state_change|probe_loss/);
  });

  it("is hidden when no layer is mapped (root empty)", () => {
    render(<RcaVerdictBanner onClear={vi.fn()} overlay={overlay({
      layer_coverage: { ...cov, layers: cov.layers.map((l) => ({ ...l, observed: false, kinds: [], entities: [] })), root_layer: "", impact_layer: "" },
    })} />);
    expect(screen.queryByLabelText("Causal layer stack")).toBeNull();
  });

  it("surfaces unmapped signal count honestly", () => {
    render(<RcaVerdictBanner onClear={vi.fn()} overlay={overlay({
      layer_coverage: { ...cov, unmapped_kinds: ["vendor_widget_anomaly"] },
    })} />);
    expect(screen.getByText(/1 signal not layer-mapped/)).toBeTruthy();
  });
});

describe("RcaVerdictBanner — internal locus tag", () => {
  it("flags an internal-stack incident", () => {
    render(<RcaVerdictBanner onClear={vi.fn()} overlay={overlay({ internal: true })} />);
    expect(screen.getByText("Internal")).toBeTruthy();
  });
});
