// DeviceNode.test.tsx — render-level guard for the RCA marker visual contract on
// the device card. The adapter/variant tests prove the DATA is right; these prove
// the PIXELS are right: the right glyph shows, suspected ≠ confirmed on screen,
// missing-evidence is a hollow ring, internal_only is never shown, and a node with
// no RCA state keeps its plain health ring (base topology untouched).

import { describe, it, expect, afterEach } from "vitest";
import { render, screen, cleanup } from "@testing-library/react";
import { ReactFlowProvider } from "@xyflow/react";
import { NodeCard, DeviceIcon } from "./DeviceNode";
import type { RFNodeData } from "../rfTypes";
import type { RcaOverlayState } from "../../../api/topologyTypes";

afterEach(cleanup);

function data(rca?: RcaOverlayState): RFNodeData {
  return {
    node: { id: "a", label: "edge1", kind: "router", health: "warning", confidence: 1, evidence: [], rca_status: rca },
    emphasis: "normal",
    showLabel: true,
    overlay: "health",
  };
}

function renderCard(rca?: RcaOverlayState) {
  return render(
    <ReactFlowProvider>
      <NodeCard data={data(rca)} icon={<DeviceIcon />} accent="#64748b" />
    </ReactFlowProvider>,
  );
}

describe("DeviceNode — RCA marker visual contract", () => {
  it("suspected and confirmed render DISTINCT glyphs (not the same red)", () => {
    renderCard("suspected_down");
    const sus = screen.getByLabelText("RCA: Suspected fault");
    expect(sus.textContent).toBe("⚠");

    cleanup();
    renderCard("confirmed_down");
    const conf = screen.getByLabelText("RCA: Confirmed fault");
    expect(conf.textContent).toBe("✕");
  });

  it("missing_evidence is a HOLLOW ring (dashed, no glyph fill)", () => {
    renderCard("missing_evidence");
    const el = screen.getByLabelText("RCA: Missing evidence");
    expect(el.textContent).toBe(""); // hollow — honest "no proof", not an alarm glyph
    expect(el.getAttribute("style")).toContain("dashed");
  });

  it("insufficient_visibility shows the '?' marker", () => {
    renderCard("insufficient_visibility");
    expect(screen.getByLabelText("RCA: Insufficient visibility").textContent).toBe("?");
  });

  it("internal_only is NEVER shown — falls back to the health ring (decision #76)", () => {
    renderCard("internal_only");
    expect(screen.queryByLabelText(/^RCA:/)).toBeNull();
    expect(screen.getByLabelText("Warning")).toBeTruthy(); // node.health = warning
  });

  it("a node with no RCA state keeps its plain health ring (base topology untouched)", () => {
    renderCard(undefined);
    expect(screen.queryByLabelText(/^RCA:/)).toBeNull();
    expect(screen.getByLabelText("Warning")).toBeTruthy();
  });
});
