// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// ElevatedAccessRow — the account menu's line about elevated access, and the
// ONE thing it must never get wrong.
//
// `End` calls DELETE /api/auth/elevation. It used to clear the row and close
// the menu from a `.finally()`, so a REFUSED step-down was indistinguishable
// from a successful one: the row vanished, the menu shut, and the operator went
// back to work believing they held only their standing role — while the grant
// was still live and no revocation had been audited. An authorization surface
// that lies in the safe-looking direction is worse than one that errors.
//
// Pinned here:
//   * a failed step-down KEEPS the row (the access is still held, so the screen
//     must still say so), SAYS so, and does not close the menu;
//   * the sentence it says is operator words — never the api.ts envelope, which
//     would put an internal hostname and container IP in the account menu;
//   * the button stays usable, so the operator can retry;
//   * a successful step-down still clears the row and closes the menu.

import { describe, it, expect, vi, afterEach, beforeEach } from "vitest";
import { render, screen, cleanup, waitFor, fireEvent, act } from "@testing-library/react";
import type { ElevationStatus } from "../services/api";

const elevation = vi.fn();
const endElevation = vi.fn();

vi.mock("../services/api", () => ({
  api: {
    elevation: (...a: unknown[]) => elevation(...a),
    endElevation: (...a: unknown[]) => endElevation(...a),
  },
}));

import { ElevatedAccessRow } from "./IconRail";

const ACTIVE: ElevationStatus = {
  active: true,
  role: "administrator",
  expires_at: new Date(Date.now() + 20 * 60_000).toISOString(),
} as ElevationStatus;

beforeEach(() => {
  vi.clearAllMocks();
  elevation.mockResolvedValue(ACTIVE);
});
afterEach(cleanup);

describe("ElevatedAccessRow — stepping down", () => {
  it("keeps the row and SAYS the access was not ended when the server refuses", async () => {
    endElevation.mockRejectedValue(new Error("500 Internal Server Error: {\"error\":\"revoke store unavailable\"}"));
    const onStepDown = vi.fn();
    render(<ElevatedAccessRow onStepDown={onStepDown} />);

    await screen.findByTestId("elevated-access");
    fireEvent.click(screen.getByRole("button", { name: "End" }));
    await waitFor(() => expect(endElevation).toHaveBeenCalledTimes(1));
    await act(async () => { await Promise.resolve(); await Promise.resolve(); });

    // The grant is still live, so the row that announces it must still be there.
    expect(
      screen.queryByTestId("elevated-access"),
      "the row vanished on a FAILED step-down — the operator was shown a step-down that did not happen",
    ).toBeTruthy();
    expect(screen.getByText(/Elevated/)).toBeTruthy();
    // …and the menu must NOT have been closed behind the operator's back.
    expect(onStepDown).not.toHaveBeenCalled();
    expect(screen.getByRole("alert").textContent).toMatch(/still have elevated access/i);
    // Retryable.
    expect(screen.getByRole("button", { name: "Try again" })).toBeTruthy();
  });

  it("says it in operator words — the envelope never reaches the account menu", async () => {
    endElevation.mockRejectedValue(new Error(
      '502 Bad Gateway: {"error":"Post http://api:8080/elevation: ' +
      'dial tcp 172.18.0.9:8080: connect: connection refused"}',
    ));
    const { container } = render(<ElevatedAccessRow />);
    await screen.findByTestId("elevated-access");
    fireEvent.click(screen.getByRole("button", { name: "End" }));
    await screen.findByRole("alert");

    const text = container.textContent ?? "";
    expect(text).not.toMatch(/\b\d{1,3}(\.\d{1,3}){3}\b/);
    expect(text).not.toMatch(/dial tcp|connection refused|Bad Gateway|api:8080/);
  });

  it("a retry that succeeds clears the row and closes the menu", async () => {
    endElevation
      .mockRejectedValueOnce(new Error("503 Service Unavailable: try later"))
      .mockResolvedValueOnce(undefined);
    const onStepDown = vi.fn();
    render(<ElevatedAccessRow onStepDown={onStepDown} />);

    await screen.findByTestId("elevated-access");
    fireEvent.click(screen.getByRole("button", { name: "End" }));
    await screen.findByRole("alert");

    fireEvent.click(screen.getByRole("button", { name: "Try again" }));
    await waitFor(() => expect(screen.queryByTestId("elevated-access")).toBeNull());
    expect(onStepDown).toHaveBeenCalledTimes(1);
  });

  it("a step-down that works clears the row and closes the menu", async () => {
    endElevation.mockResolvedValue(undefined);
    const onStepDown = vi.fn();
    render(<ElevatedAccessRow onStepDown={onStepDown} />);

    await screen.findByTestId("elevated-access");
    fireEvent.click(screen.getByRole("button", { name: "End" }));
    await waitFor(() => expect(screen.queryByTestId("elevated-access")).toBeNull());
    expect(onStepDown).toHaveBeenCalledTimes(1);
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("renders nothing at all when no grant is active", async () => {
    elevation.mockResolvedValue({ active: false } as ElevationStatus);
    const { container } = render(<ElevatedAccessRow />);
    await waitFor(() => expect(elevation).toHaveBeenCalled());
    expect(container.querySelector('[data-testid="elevated-access"]')).toBeNull();
  });
});
