// SensitiveDataAccess.test.tsx — the compliance surface for sealed fields, and
// the operator-facing key rotation beside it (#129).
//
// Two properties the page must never lose: a failed load is never rendered as an
// empty trail, and no revealed VALUE ever appears. The rotate control adds a
// third: rotation is consequential and tenant-wide, so a single click may not
// perform it, and the result must report the version it landed on rather than a
// green tick — "it worked" is not the fact an operator needs.

import { describe, it, expect, vi, afterEach } from "vitest";
import { render, screen, cleanup, waitFor, fireEvent } from "@testing-library/react";

const sealAccessAudit = vi.fn();
const sealRotate = vi.fn();

vi.mock("../services/api", () => ({
  api: {
    sealAccessAudit: (...a: unknown[]) => sealAccessAudit(...a),
    sealRotate: (...a: unknown[]) => sealRotate(...a),
  },
}));

import SensitiveDataAccess from "./SensitiveDataAccess";

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

const row = {
  id: "a1",
  time: "2026-09-06T10:00:00Z",
  actor: "alice",
  decision: "allow",
  detail: { outcome: "granted", reason: "ticket 4412", data_type: "card", field: "pan", key_version: 1, token_preview: "9f2a" },
};

describe("Sensitive Data Access", () => {
  it("shows the trail, including the key version, and never a value", async () => {
    sealAccessAudit.mockResolvedValue([row]);
    render(<SensitiveDataAccess />);
    expect(await screen.findByText("alice")).toBeTruthy();
    expect(screen.getByText("v1")).toBeTruthy();
    expect(screen.getByText("9f2a")).toBeTruthy(); // a ciphertext fingerprint, not a value
  });

  it("a failed load is an error, NEVER an empty access trail", async () => {
    sealAccessAudit.mockRejectedValue(new Error("boom"));
    render(<SensitiveDataAccess />);
    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toMatch(/not/i);
    expect(screen.queryByText(/No reveal attempts recorded/i)).toBeNull();
  });
});

describe("Sealing key rotation", () => {
  it("one click ARMS it — rotation never happens on a single press", async () => {
    sealAccessAudit.mockResolvedValue([]);
    render(<SensitiveDataAccess />);
    fireEvent.click(await screen.findByRole("button", { name: "Rotate" }));
    expect(sealRotate).not.toHaveBeenCalled();
    expect(screen.getByRole("button", { name: "Confirm rotate" })).toBeTruthy();
  });

  it("cancelling leaves the key alone", async () => {
    sealAccessAudit.mockResolvedValue([]);
    render(<SensitiveDataAccess />);
    fireEvent.click(await screen.findByRole("button", { name: "Rotate" }));
    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
    expect(sealRotate).not.toHaveBeenCalled();
    expect(screen.getByRole("button", { name: "Rotate" })).toBeTruthy();
  });

  it("confirming reports the VERSION it landed on and the server's own caveat", async () => {
    sealAccessAudit.mockResolvedValue([]);
    sealRotate.mockResolvedValue({ key_version: 2, note: "New values seal under this version once the router reloads its config." });
    render(<SensitiveDataAccess />);
    fireEvent.click(await screen.findByRole("button", { name: "Rotate" }));
    fireEvent.click(screen.getByRole("button", { name: "Confirm rotate" }));
    await waitFor(() => expect(sealRotate).toHaveBeenCalledTimes(1));
    expect(await screen.findByText("v2")).toBeTruthy();
    // The delay is the thing operators get wrong; it must not be swallowed.
    expect(screen.getByText(/router reloads/i)).toBeTruthy();
  });

  it("a refused rotation says so and does not claim a new version", async () => {
    sealAccessAudit.mockResolvedValue([]);
    sealRotate.mockRejectedValue(new Error("a tenant-scoped principal is required"));
    render(<SensitiveDataAccess />);
    fireEvent.click(await screen.findByRole("button", { name: "Rotate" }));
    fireEvent.click(screen.getByRole("button", { name: "Confirm rotate" }));
    await waitFor(() => expect(screen.getAllByRole("alert").length).toBeGreaterThan(0));
    expect(screen.queryByText(/^v\d+$/)).toBeNull();
  });

  it("offers the explanation instead of teaching it on screen", async () => {
    sealAccessAudit.mockResolvedValue([]);
    render(<SensitiveDataAccess />);
    expect(await screen.findByRole("button", { name: "Ask Iris about Sealing key" })).toBeTruthy();
  });
});
