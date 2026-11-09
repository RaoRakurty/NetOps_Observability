// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// SourceAuthorityPanel.test.tsx — "Which source Iris believes" (N-F6).
//
// What has to hold: the server's order is shown as given; a move changes
// nothing until it is saved; the save sends only the class list (never a
// tenant); a reset goes back to the default; a deployment without the store
// offers no controls; a failure is shown; labels render as text.

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, cleanup, fireEvent, waitFor } from "@testing-library/react";

const sourceAuthority = vi.fn();
const sourceAuthoritySave = vi.fn();
const sourceAuthorityReset = vi.fn();

vi.mock("../../services/api", () => ({
  api: {
    sourceAuthority: (...a: unknown[]) => sourceAuthority(...a),
    sourceAuthoritySave: (...a: unknown[]) => sourceAuthoritySave(...a),
    sourceAuthorityReset: (...a: unknown[]) => sourceAuthorityReset(...a),
  },
}));

import SourceAuthorityPanel from "./SourceAuthorityPanel";

const C = { class: "controller", label: "the controller" };
const D = { class: "discovered", label: "the device itself (SNMP)" };
const N = { class: "declared", label: "the imported source of truth (NetBox)" };
const M = { class: "manual", label: "a manual entry" };

function view(order = [C, D, N, M], extra: Record<string, unknown> = {}) {
  return { order, default: [C, D, N, M], customized: false, editable: true, ...extra };
}

function labels(): string[] {
  return Array.from(screen.getByRole("list", { name: "Source order" }).querySelectorAll(".disc-text")).map((e) => e.textContent ?? "");
}

beforeEach(() => {
  sourceAuthority.mockReset();
  sourceAuthoritySave.mockReset();
  sourceAuthorityReset.mockReset();
});
afterEach(cleanup);

describe("SourceAuthorityPanel", () => {
  it("shows the server's order, top first", async () => {
    sourceAuthority.mockResolvedValue(view());
    render(<SourceAuthorityPanel />);
    await screen.findByText("the controller");
    expect(labels()).toEqual([C.label, D.label, N.label, M.label]);
    expect(screen.getByText("This workspace uses the platform default order.")).toBeTruthy();
    expect((screen.getByRole("button", { name: "Move the controller up" }) as HTMLButtonElement).disabled).toBe(true);
    expect((screen.getByRole("button", { name: "Move a manual entry down" }) as HTMLButtonElement).disabled).toBe(true);
    expect((screen.getByRole("button", { name: "Use the platform default" }) as HTMLButtonElement).disabled).toBe(true);
  });

  it("a move changes nothing until saved; the save sends only the classes", async () => {
    sourceAuthority.mockResolvedValue(view());
    sourceAuthoritySave.mockResolvedValue(view([D, C, N, M], { customized: true, updated_by: "alice" }));
    render(<SourceAuthorityPanel />);
    await screen.findByText("the controller");
    const save = screen.getByRole("button", { name: "Save order" }) as HTMLButtonElement;
    expect(save.disabled).toBe(true);
    fireEvent.click(screen.getByRole("button", { name: "Move the device itself (SNMP) up" }));
    expect(labels()[0]).toBe(D.label);
    expect(sourceAuthoritySave).not.toHaveBeenCalled();
    expect(save.disabled).toBe(false);
    fireEvent.click(save);
    await screen.findByRole("status");
    expect(sourceAuthoritySave).toHaveBeenCalledWith(["discovered", "controller", "declared", "manual"]);
    expect(screen.getByText("This workspace uses its own order, last set by alice.")).toBeTruthy();
  });

  it("moving back to the saved order leaves nothing to save", async () => {
    sourceAuthority.mockResolvedValue(view());
    render(<SourceAuthorityPanel />);
    await screen.findByText("the controller");
    fireEvent.click(screen.getByRole("button", { name: "Move the controller down" }));
    fireEvent.click(screen.getByRole("button", { name: "Move the controller up" }));
    expect((screen.getByRole("button", { name: "Save order" }) as HTMLButtonElement).disabled).toBe(true);
  });

  it("resets a customised order to the platform default", async () => {
    sourceAuthority.mockResolvedValue(view([M, C, D, N], { customized: true }));
    sourceAuthorityReset.mockResolvedValue(view());
    render(<SourceAuthorityPanel />);
    await screen.findByText("the controller");
    expect(labels()[0]).toBe(M.label);
    fireEvent.click(screen.getByRole("button", { name: "Use the platform default" }));
    await waitFor(() => expect(labels()[0]).toBe(C.label));
    expect(sourceAuthorityReset).toHaveBeenCalledTimes(1);
  });

  it("offers no controls on a deployment without the store", async () => {
    sourceAuthority.mockResolvedValue(view(undefined, { editable: false }));
    render(<SourceAuthorityPanel />);
    await screen.findByText("the controller");
    expect(screen.queryByRole("button")).toBeNull();
    expect(screen.getByText(/needs the Postgres platform store/)).toBeTruthy();
  });

  it("shows a failure, and keeps the order on screen after a refused save", async () => {
    sourceAuthority.mockRejectedValueOnce(new Error("boom"));
    const { unmount } = render(<SourceAuthorityPanel />);
    await screen.findByRole("alert");
    unmount();

    sourceAuthority.mockResolvedValue(view());
    sourceAuthoritySave.mockRejectedValue(new Error("nope"));
    render(<SourceAuthorityPanel />);
    await screen.findByText("the controller");
    fireEvent.click(screen.getByRole("button", { name: "Move the controller down" }));
    fireEvent.click(screen.getByRole("button", { name: "Save order" }));
    await screen.findByRole("alert");
    expect(labels()[0]).toBe(D.label);
  });

  it("renders a label as text, never as markup", async () => {
    const evil = { class: "manual", label: '<img src=x onerror="window.__sa=1">' };
    sourceAuthority.mockResolvedValue(view([C, D, N, evil]));
    const { container } = render(<SourceAuthorityPanel />);
    await screen.findByText("the controller");
    expect(container.querySelector("img")).toBeNull();
  });
});
