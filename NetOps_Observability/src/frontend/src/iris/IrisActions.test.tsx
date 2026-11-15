// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import IrisActions from "./IrisActions";
import ActionProposalCards, { PROPOSED_NOTICE } from "./ActionProposalCards";
import { NO_ACTION_NOTICE } from "./RecommendationCards";
import { api, type IrisActionRequest, type IrisActionsView } from "../services/api";

afterEach(() => vi.restoreAllMocks());

const waiting: IrisActionRequest = {
  id: "a-1", kind: "itsm_note", kind_label: "Note on the incident's ticket", tool: "propose_itsm_update",
  proposed_by: "alice", proposed_via: "iris", correlation_id: "corr-1", citations: ["ev-1"],
  summary: "Add Iris's finding as a note on ServiceNow INC0012345",
  preview: "Iris investigation finding <script>alert(1)</script>",
  dry_run: { performed: true, ok: true, description: "Ticket INC0012345 exists in ServiceNow." },
  policy: "require_approval", status: "proposed",
  created_at: "2026-11-15T09:00:00Z", expires_at: "2026-11-16T09:00:00Z",
  can_approve: true, can_reject: true, mine: false,
};

function view(over: Partial<IrisActionsView> = {}): IrisActionsView {
  return {
    settings: { enabled: true, kinds: ["itsm_note"], dry_run_only: false },
    available: true, unavailable_reason: "",
    kinds: [
      { kind: "itsm_note", label: "Note on the incident's ticket", tool: "propose_itsm_update" },
      { kind: "investigation_note", label: "Finding saved to investigation memory", tool: "propose_investigation_note" },
    ],
    requests: [waiting], open: 1, ...over,
  };
}

describe("IrisActions", () => {
  it("shows the exact text to be sent as text, and a different person approves it", async () => {
    vi.spyOn(api, "irisActions").mockResolvedValue(view());
    const decide = vi.spyOn(api, "decideIrisAction").mockResolvedValue({ ...waiting, status: "executed" });
    render(<IrisActions />);
    await waitFor(() => expect(screen.getByTestId("iris-action-request")).toBeTruthy());
    expect(screen.getByLabelText("Exact text that will be sent").textContent).toContain("<script>alert(1)</script>");
    expect(document.querySelector("script")).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Approve and send" }));
    await waitFor(() => expect(decide).toHaveBeenCalledWith("a-1", true, ""));
  });

  it("never offers the person Iris answered an approve button; they can withdraw with a reason", async () => {
    vi.spyOn(api, "irisActions").mockResolvedValue(view({ requests: [{ ...waiting, mine: true, can_approve: false }] }));
    const decide = vi.spyOn(api, "decideIrisAction").mockResolvedValue({ ...waiting, status: "rejected" });
    render(<IrisActions />);
    await waitFor(() => expect(screen.getByText(/someone else approves this/)).toBeTruthy());
    expect(screen.queryByRole("button", { name: "Approve and send" })).toBeNull();
    const withdraw = screen.getByRole("button", { name: "Withdraw" }) as HTMLButtonElement;
    expect(withdraw.disabled).toBe(true);
    fireEvent.change(screen.getByLabelText("Reason"), { target: { value: "noted by hand" } });
    fireEvent.click(withdraw);
    await waitFor(() => expect(decide).toHaveBeenCalledWith("a-1", false, "noted by hand"));
  });

  it("will not approve when the dry run found a problem", async () => {
    vi.spyOn(api, "irisActions").mockResolvedValue(view({
      requests: [{ ...waiting, dry_run: { performed: true, ok: false, description: "Asked ServiceNow.", problem: "the ticket no longer exists" } }],
    }));
    render(<IrisActions />);
    await waitFor(() => expect(screen.getByText(/the ticket no longer exists/)).toBeTruthy());
    expect((screen.getByRole("button", { name: "Approve and send" }) as HTMLButtonElement).disabled).toBe(true);
  });

  it("needs the acknowledgement to turn actions on", async () => {
    vi.spyOn(api, "irisActions").mockResolvedValue(view({ settings: { enabled: false, kinds: [], dry_run_only: false }, requests: [], open: 0 }));
    const save = vi.spyOn(api, "saveIrisActionSettings").mockResolvedValue({ settings: { enabled: true, kinds: [], dry_run_only: false } });
    render(<IrisActions />);
    await waitFor(() => expect(screen.getByText("Nothing is waiting.")).toBeTruthy());
    fireEvent.click(screen.getByLabelText("Iris can propose actions for this workspace"));
    const saveBtn = screen.getByRole("button", { name: "Save" }) as HTMLButtonElement;
    expect(saveBtn.disabled).toBe(true);
    fireEvent.click(screen.getByLabelText(/I understand/));
    fireEvent.click(saveBtn);
    await waitFor(() => expect(save).toHaveBeenCalledWith({ enabled: true, kinds: [], dry_run_only: false, acknowledged: true }));
  });

  it("says why when the installation has actions off", async () => {
    vi.spyOn(api, "irisActions").mockResolvedValue(view({ available: false, unavailable_reason: "Iris actions are turned off on this installation", requests: [], open: 0 }));
    render(<IrisActions />);
    await waitFor(() => expect(screen.getByRole("status").textContent).toMatch(/turned off on this installation/));
    expect((screen.getByLabelText("Iris can propose actions for this workspace") as HTMLInputElement).disabled).toBe(true);
  });
});

describe("ActionProposalCards", () => {
  it("is text only and says nothing has been executed", () => {
    render(<ActionProposalCards proposals={[
      { id: "a-1", kind: "itsm_note", label: "Note on the incident's ticket", summary: "Add a note on ServiceNow INC0012345", status: "proposed", policy: "require_approval" },
      { kind: "investigation_note", label: "Finding saved to investigation memory", summary: "", status: "not_proposed", policy: "deny", note: "this workspace has not allowed this kind of action" },
    ]} />);
    expect(screen.getByText(new RegExp(PROPOSED_NOTICE.replace(/[.—]/g, ".")))).toBeTruthy();
    expect(screen.getByText(/has not allowed this kind/)).toBeTruthy();
    expect(screen.getAllByText(NO_ACTION_NOTICE).length).toBe(2);
    expect(screen.queryByRole("button")).toBeNull();
  });

  it("renders nothing for no proposals", () => {
    const { container } = render(<ActionProposalCards proposals={[]} />);
    expect(container.textContent).toBe("");
  });
});
