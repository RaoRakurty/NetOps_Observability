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
import { RULES } from "./fixtures";

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
    expect(await screen.findByText(/not looked at/i)).toBeTruthy();
  });
});
