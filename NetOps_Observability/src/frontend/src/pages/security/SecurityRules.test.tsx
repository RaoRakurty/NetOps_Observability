// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// SecurityRules.test.tsx — the rule editor. The load-bearing assertion is the
// PUT body: enablement only, changed rules only, no server-owned field.

import { describe, it, expect, vi, afterEach, beforeEach } from "vitest";
import { render, screen, cleanup, fireEvent, waitFor } from "@testing-library/react";

const securityRules = vi.fn();
const securityRulesUpdate = vi.fn();

vi.mock("../../services/api", () => ({
  api: {
    securityRules: (...a: unknown[]) => securityRules(...a),
    securityRulesUpdate: (...a: unknown[]) => securityRulesUpdate(...a),
  },
}));

import SecurityRules from "./SecurityRules";
import { RULES, RULES_WIRE, RULES_WIRE_LEGACY } from "./fixtures";

afterEach(cleanup);
beforeEach(() => {
  securityRules.mockReset(); securityRulesUpdate.mockReset();
  securityRules.mockResolvedValue(RULES);
  securityRulesUpdate.mockImplementation(async (updates: { rule_id: string; enabled: boolean }[]) =>
    RULES.map((r) => ({ ...r, enabled: updates.find((u) => u.rule_id === r.rule_id)?.enabled ?? r.enabled })));
});

describe("Detection rules", () => {
  it("lists every rule with its fidelity badge and seam-awareness", async () => {
    render(<SecurityRules />);
    expect(await screen.findByText("netrule.telnet_vty")).toBeTruthy();
    expect(screen.getByText("high")).toBeTruthy();
    expect(screen.getByText("medium")).toBeTruthy();
    expect(screen.getByText("low")).toBeTruthy();
    expect(screen.getAllByText("seam-aware")).toHaveLength(1);
    expect(screen.getByText("T1071")).toBeTruthy();
  });

  it("saving is inert until something actually changes", async () => {
    render(<SecurityRules />);
    await screen.findByText("netrule.telnet_vty");
    expect(screen.getByRole("button", { name: "No changes" }).hasAttribute("disabled")).toBe(true);
  });

  it("PUTs {rule_id, enabled} for the CHANGED rule only", async () => {
    render(<SecurityRules />);
    fireEvent.click(await screen.findByLabelText("Enable netrule.beacon"));
    fireEvent.click(screen.getByRole("button", { name: "Save 1 change" }));
    await waitFor(() => expect(securityRulesUpdate).toHaveBeenCalled());
    expect(securityRulesUpdate.mock.calls[0][0]).toEqual([{ rule_id: "netrule.beacon", enabled: true }]);
  });

  it("never sends a server-owned field back", async () => {
    render(<SecurityRules />);
    fireEvent.click(await screen.findByLabelText("Enable netrule.telnet_vty"));
    fireEvent.click(screen.getByRole("button", { name: "Save 1 change" }));
    await waitFor(() => expect(securityRulesUpdate).toHaveBeenCalled());
    for (const body of securityRulesUpdate.mock.calls[0][0]) {
      expect(Object.keys(body).sort()).toEqual(["enabled", "rule_id"]);
    }
  });

  it("toggling back to the original value cancels the change", async () => {
    render(<SecurityRules />);
    const box = await screen.findByLabelText("Enable netrule.beacon");
    fireEvent.click(box);
    expect(screen.getByRole("button", { name: "Save 1 change" })).toBeTruthy();
    fireEvent.click(screen.getByLabelText("Enable netrule.beacon"));
    await waitFor(() => expect(screen.getByRole("button", { name: "No changes" })).toBeTruthy());
  });

  it("a refused save surfaces the error instead of pretending it applied", async () => {
    securityRulesUpdate.mockRejectedValue(new Error("403 Forbidden: administration:admin required"));
    render(<SecurityRules />);
    fireEvent.click(await screen.findByLabelText("Enable netrule.beacon"));
    fireEvent.click(screen.getByRole("button", { name: "Save 1 change" }));
    expect(await screen.findByRole("alert")).toHaveTextContent(/403 Forbidden/);
  });

  it("an empty inventory says nothing is being evaluated, not that nothing was found", async () => {
    securityRules.mockResolvedValue([]);
    render(<SecurityRules />);
    expect(await screen.findByText(/No rules are registered/i)).toBeTruthy();
    expect(screen.getByRole("button", { name: /Ask Iris about a disabled rule/i })).toBeTruthy();
  });
});

// ── the production regression ───────────────────────────────────────────────
//
// GET /api/security/rules served `"mitre":"T1071"` — a bare STRING — while the
// client type and this page both treat the field as a list. `r.mitre!.map(...)`
// threw during render, React unmounted the tree, and the whole Detection Rules
// screen went blank with no error an operator could read. These two tests mount
// the page against the EXACT bodies the API returns (fixed) and returned
// (broken); the second one fails on the pre-fix component.
describe("Detection rules — the served body", () => {
  it("renders the current wire body with its technique chips", async () => {
    securityRules.mockResolvedValue(RULES_WIRE);
    render(<SecurityRules />);
    expect(await screen.findByText("flow-beaconing")).toBeTruthy();
    expect(screen.getByText("bootp-server")).toBeTruthy();
    expect(screen.getByText("T1071")).toBeTruthy();
    expect(screen.getByText("T1562.001")).toBeTruthy();
    expect(screen.getByText(/4 of 4 rules enabled/)).toBeTruthy();
  });

  it("survives a STRING-valued mitre — the shape that white-screened production", async () => {
    securityRules.mockResolvedValue(RULES_WIRE_LEGACY);
    render(<SecurityRules />);
    // The table renders at all…
    expect(await screen.findByText("flow-beaconing")).toBeTruthy();
    expect(screen.getByText("bootp-server")).toBeTruthy();
    expect(screen.getByText("exposure-ssh")).toBeTruthy();
    // …and the technique still reads as a chip rather than being lost.
    expect(screen.getByText("T1071")).toBeTruthy();
    expect(screen.getByText("T1562.001")).toBeTruthy();
    // The sub-technique id is NOT split on its dot.
    expect(screen.queryByText("T1562")).toBeNull();
    expect(screen.queryByText("001")).toBeNull();
  });

  it("a rule with no technique renders an explicit dash, never a fabricated tag", async () => {
    securityRules.mockResolvedValue(RULES_WIRE);
    render(<SecurityRules />);
    await screen.findByText("bootp-server");
    expect(screen.getAllByText("—").length).toBeGreaterThan(0);
  });
});
