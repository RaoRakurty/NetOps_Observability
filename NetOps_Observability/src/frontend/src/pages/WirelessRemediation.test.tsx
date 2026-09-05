// WirelessRemediation.test.tsx — the guarded wireless approval queue.
//
// The assertions that matter: a dormant feature renders NOTHING (an empty
// approval queue would imply the loop exists and nothing is waiting), a
// rejection cannot be sent without a reason, executing is type-to-confirm on
// the action's own target, the fail-closed "no executor" refusal is shown as
// the recorded outcome rather than hidden, and a read-only operator gets no
// controls at all.

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, cleanup, fireEvent, waitFor, within } from "@testing-library/react";

const wirelessActions = vi.fn();
const wirelessActionApprove = vi.fn();
const wirelessActionReject = vi.fn();
const wirelessActionExecute = vi.fn();
const permissions = vi.fn();

vi.mock("../services/api", () => ({
  api: {
    wirelessActions: (...a: unknown[]) => wirelessActions(...a),
    wirelessActionApprove: (...a: unknown[]) => wirelessActionApprove(...a),
    wirelessActionReject: (...a: unknown[]) => wirelessActionReject(...a),
    wirelessActionExecute: (...a: unknown[]) => wirelessActionExecute(...a),
    permissions: (...a: unknown[]) => permissions(...a),
  },
}));

import WirelessRemediation from "./WirelessRemediation";

const CASE = "11111111-2222-4333-8444-555555555555";

const PROPOSED = {
  id: "wact-1",
  kind: "ap_radio_reset",
  target: "ap-lobby-3",
  correlation_id: CASE,
  state: "proposed",
  proposed_by: "jdoe",
  created_at: "2026-09-05T09:00:00Z",
  updated_at: "2026-09-05T09:00:00Z",
};
const APPROVED = { ...PROPOSED, id: "wact-2", target: "ap-lab-1", state: "approved", approved_by: "asmith" };
const FAILED = {
  ...PROPOSED,
  id: "wact-3",
  target: "ap-dc-9",
  state: "failed",
  approved_by: "asmith",
  error: "gate 4: no executor registered — the vendor write RPC has not earned live validation (Phase 9)",
};

afterEach(cleanup);
beforeEach(() => {
  for (const m of [wirelessActions, wirelessActionApprove, wirelessActionReject, wirelessActionExecute, permissions]) m.mockReset();
  wirelessActions.mockResolvedValue([PROPOSED, APPROVED, FAILED]);
  permissions.mockResolvedValue({ role: "admin", permissions: { infrastructure: 2 } });
});

describe("WirelessRemediation — dormancy and access", () => {
  it("renders NOTHING when the workflow is dormant (404) — never an empty queue", async () => {
    wirelessActions.mockRejectedValue(new Error("404 Not Found: "));
    const { container } = render(<WirelessRemediation />);
    await waitFor(() => expect(container.querySelector("section")).toBeNull());
    expect(screen.queryByText(/wireless remediation/i)).toBeNull();
  });

  it("a failed read says what is proposed is UNKNOWN, not nothing", async () => {
    wirelessActions.mockRejectedValue(new Error("500 Internal Server Error: "));
    render(<WirelessRemediation />);
    expect(await screen.findByText(/unknown, not nothing/i)).toBeTruthy();
  });

  it("a read-only operator sees the queue and no decision controls", async () => {
    permissions.mockResolvedValue({ role: "viewer", permissions: { infrastructure: 1 } });
    render(<WirelessRemediation />);
    await screen.findByRole("table", { name: /waiting on a decision/i });
    expect(screen.getByText(/need infrastructure write access/i)).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Approve" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Execute" })).toBeNull();
  });
});

describe("WirelessRemediation — the approval loop", () => {
  it("splits pending from decided and shows what each action does", async () => {
    render(<WirelessRemediation />);
    const pending = await screen.findByRole("table", { name: /waiting on a decision/i });
    expect(within(pending).getByText("ap-lobby-3")).toBeTruthy();
    expect(within(pending).getByText("ap-lab-1")).toBeTruthy();
    expect(within(pending).getAllByText(/Restart one access point's radio/i).length).toBeGreaterThan(0);

    const history = screen.getByRole("table", { name: /remediation history/i });
    expect(within(history).getByText("ap-dc-9")).toBeTruthy();
  });

  it("approves through the route, carrying the optional note", async () => {
    wirelessActionApprove.mockResolvedValue({ ...PROPOSED, state: "approved" });
    render(<WirelessRemediation />);
    const pending = await screen.findByRole("table", { name: /waiting on a decision/i });
    const row = within(pending).getByText("ap-lobby-3").closest("tr")!;
    fireEvent.change(within(row).getByLabelText("Reason for ap-lobby-3"), { target: { value: "agreed with the seam owner" } });
    fireEvent.click(within(row).getByRole("button", { name: "Approve" }));
    await waitFor(() => expect(wirelessActionApprove).toHaveBeenCalledWith("wact-1", "agreed with the seam owner"));
    expect(await screen.findByText(/does not run until it is executed/i)).toBeTruthy();
  });

  it("will not send a rejection without a reason", async () => {
    render(<WirelessRemediation />);
    const pending = await screen.findByRole("table", { name: /waiting on a decision/i });
    const row = within(pending).getByText("ap-lobby-3").closest("tr")!;
    const reject = within(row).getByRole("button", { name: "Reject" }) as HTMLButtonElement;
    expect(reject.disabled).toBe(true);
    fireEvent.click(reject);
    expect(wirelessActionReject).not.toHaveBeenCalled();

    fireEvent.change(within(row).getByLabelText("Reason for ap-lobby-3"), { target: { value: "scheduled in tonight's window" } });
    fireEvent.click(within(row).getByRole("button", { name: "Reject" }));
    await waitFor(() => expect(wirelessActionReject).toHaveBeenCalledWith("wact-1", "scheduled in tonight's window"));
  });

  it("execution is type-to-confirm on the action's own target", async () => {
    wirelessActionExecute.mockResolvedValue({ ...APPROVED, state: "executed", verify_note: "verification pending" });
    render(<WirelessRemediation />);
    const pending = await screen.findByRole("table", { name: /waiting on a decision/i });
    const row = within(pending).getByText("ap-lab-1").closest("tr")!;
    fireEvent.click(within(row).getByRole("button", { name: "Execute" }));

    const confirm = within(row).getByRole("button", { name: "Execute now" }) as HTMLButtonElement;
    expect(confirm.disabled).toBe(true);
    fireEvent.change(within(row).getByLabelText(/Type ap-lab-1 to confirm/i), { target: { value: "ap-lab" } });
    expect((within(row).getByRole("button", { name: "Execute now" }) as HTMLButtonElement).disabled).toBe(true);

    fireEvent.change(within(row).getByLabelText(/Type ap-lab-1 to confirm/i), { target: { value: "ap-lab-1" } });
    fireEvent.click(within(row).getByRole("button", { name: "Execute now" }));
    await waitFor(() => expect(wirelessActionExecute).toHaveBeenCalledWith("wact-2"));
    expect(await screen.findByText(/Verification is pending/i)).toBeTruthy();
  });

  it("only proposed actions offer Approve; an approved one offers Execute", async () => {
    render(<WirelessRemediation />);
    const pending = await screen.findByRole("table", { name: /waiting on a decision/i });
    const proposedRow = within(pending).getByText("ap-lobby-3").closest("tr")!;
    const approvedRow = within(pending).getByText("ap-lab-1").closest("tr")!;
    expect(within(proposedRow).queryByRole("button", { name: "Execute" })).toBeNull();
    expect(within(approvedRow).queryByRole("button", { name: "Approve" })).toBeNull();
    expect(within(approvedRow).getByRole("button", { name: "Execute" })).toBeTruthy();
  });

  it("shows the fail-closed no-executor refusal as the recorded outcome", async () => {
    render(<WirelessRemediation />);
    const history = await screen.findByRole("table", { name: /remediation history/i });
    expect(within(history).getByText(/no executor registered/i)).toBeTruthy();
    expect(within(history).getByText("failed")).toBeTruthy();
  });

  it("a refused decision shows the server's own gate sentence", async () => {
    wirelessActionApprove.mockRejectedValue(new Error('422 Unprocessable Entity: {"error":"action is not in a state that permits this transition"}'));
    render(<WirelessRemediation />);
    const pending = await screen.findByRole("table", { name: /waiting on a decision/i });
    const row = within(pending).getByText("ap-lobby-3").closest("tr")!;
    fireEvent.click(within(row).getByRole("button", { name: "Approve" }));
    expect(await screen.findByText(/not in a state that permits this transition/i)).toBeTruthy();
  });

  it("an empty queue says why a proposal is rare, not that wireless is healthy", async () => {
    wirelessActions.mockResolvedValue([]);
    render(<WirelessRemediation />);
    expect(await screen.findByText(/not that the wireless estate\s+is healthy/i)).toBeTruthy();
  });
});
