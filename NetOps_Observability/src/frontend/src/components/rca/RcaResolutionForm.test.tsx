// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, cleanup, fireEvent, waitFor } from "@testing-library/react";

const correlationResolutions = vi.fn();
const correlationResolutionCreate = vi.fn();
vi.mock("../../services/api", () => ({
  api: {
    correlationResolutions: (...a: unknown[]) => correlationResolutions(...a),
    correlationResolutionCreate: (...a: unknown[]) => correlationResolutionCreate(...a),
  },
}));

import RcaResolutionForm, { checkDraft, resolutionErrText, RESOLUTION_CHOICES, RESOLUTION_NOTE_MAX } from "./RcaResolutionForm";

beforeEach(() => vi.clearAllMocks());
afterEach(cleanup);

const empty = { correlation_id: "c-1", resolutions: [], count: 0 };

describe("RcaResolutionForm", () => {
  it("offers the eight closed choices as numbered steps and records one", async () => {
    correlationResolutions.mockResolvedValueOnce(empty).mockResolvedValueOnce({
      correlation_id: "c-1", count: 1,
      resolutions: [{ id: "r1", correlation_id: "c-1", kind: "config_rollback", change_id: "CHG-1",
        created_by: "a@acme", created_at: "2026-11-13T10:00:00Z" }],
    });
    correlationResolutionCreate.mockResolvedValue({});
    render(<RcaResolutionForm correlationId="c-1" />);
    fireEvent.click(await screen.findByRole("button", { name: "Record the fix" }));
    expect(screen.getByText("1. What fixed it?")).toBeTruthy();
    expect(screen.getAllByRole("radio").length).toBe(RESOLUTION_CHOICES.length);
    expect(RESOLUTION_CHOICES.length).toBe(8);
    fireEvent.click(screen.getByLabelText("Rolled back a configuration change"));
    fireEvent.change(screen.getByLabelText(/3\. Change number/), { target: { value: "CHG-1" } });
    fireEvent.click(screen.getAllByRole("button", { name: "Record the fix" }).at(-1)!);
    await waitFor(() => expect(correlationResolutionCreate).toHaveBeenCalledWith("c-1", { kind: "config_rollback", change_id: "CHG-1" }));
    // Shown as recorded only after the server read-back.
    expect(await screen.findByTestId("rw-res-latest")).toBeTruthy();
    expect(screen.getByTestId("rw-res-latest").textContent).toMatch(/Rolled back a configuration change · change CHG-1/);
    expect(screen.getByRole("status").textContent).toMatch(/Fix recorded/);
  });

  it("refuses an empty choice and 'something else' without a note, before calling the server", async () => {
    correlationResolutions.mockResolvedValue(empty);
    render(<RcaResolutionForm correlationId="c-1" />);
    fireEvent.click(await screen.findByRole("button", { name: "Record the fix" }));
    fireEvent.click(screen.getAllByRole("button", { name: "Record the fix" }).at(-1)!);
    expect(screen.getByRole("status").textContent).toBe("Choose what fixed it.");
    fireEvent.click(screen.getByLabelText("Something else (say what below)"));
    fireEvent.click(screen.getAllByRole("button", { name: "Record the fix" }).at(-1)!);
    expect(screen.getByRole("status").textContent).toBe("Say briefly what was done.");
    expect(correlationResolutionCreate).not.toHaveBeenCalled();
  });

  it("says a permission refusal in operator words", async () => {
    correlationResolutions.mockResolvedValue(empty);
    correlationResolutionCreate.mockRejectedValue(new Error("403 Forbidden: insufficient permissions"));
    render(<RcaResolutionForm correlationId="c-1" />);
    fireEvent.click(await screen.findByRole("button", { name: "Record the fix" }));
    fireEvent.click(screen.getByLabelText("Rebooted a device"));
    fireEvent.click(screen.getAllByRole("button", { name: "Record the fix" }).at(-1)!);
    expect(await screen.findByText("You don't have permission to record how this case was fixed.")).toBeTruthy();
  });

  it("renders a recorded note as text, never markup", async () => {
    correlationResolutions.mockResolvedValue({
      correlation_id: "c-1", count: 1,
      resolutions: [{ id: "r1", correlation_id: "c-1", kind: "other", note: "<b>bold</b><script>x</script>",
        created_by: "a@acme", created_at: "2026-11-13T10:00:00Z" }],
    });
    const { container } = render(<RcaResolutionForm correlationId="c-1" />);
    expect(await screen.findByText("<b>bold</b><script>x</script>")).toBeTruthy();
    expect(container.querySelector("b, script")).toBeNull();
    expect(screen.getByRole("button", { name: "Record a correction" })).toBeTruthy();
  });
});

describe("checkDraft", () => {
  it("mirrors the server's rules", () => {
    expect(checkDraft("reboot", "", "")).toBe("");
    expect(checkDraft("", "", "")).toMatch(/Choose/);
    expect(checkDraft("other", "  ", "")).toMatch(/Say briefly/);
    expect(checkDraft("reboot", "x".repeat(RESOLUTION_NOTE_MAX + 1), "")).toMatch(/500/);
    expect(checkDraft("reboot", "x".repeat(RESOLUTION_NOTE_MAX), "")).toBe("");
    expect(checkDraft("reboot", "line\nbreak", "")).toMatch(/hidden/);
    expect(checkDraft("reboot", "zero\u200bwidth", "")).toMatch(/hidden/);
    expect(checkDraft("reboot", "", "CHG 1")).toMatch(/change number/i);
    expect(checkDraft("reboot", "", "CHG-1042")).toBe("");
  });

  it("errText names this action", () => {
    expect(resolutionErrText(new Error("401 Unauthorized"))).toMatch(/session expired/);
    expect(resolutionErrText(new Error("404 Not Found"))).toMatch(/no longer available/);
  });
});
