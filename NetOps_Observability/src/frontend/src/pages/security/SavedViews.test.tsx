// SavedViews.test.tsx — saved-view CRUD. A view stores a FILTER, never rows.

import { describe, it, expect, vi, afterEach, beforeEach } from "vitest";
import { render, screen, cleanup, fireEvent, waitFor } from "@testing-library/react";

const securityViews = vi.fn();
const securityViewCreate = vi.fn();
const securityViewDelete = vi.fn();

vi.mock("../../services/api", () => ({
  api: {
    securityViews: (...a: unknown[]) => securityViews(...a),
    securityViewCreate: (...a: unknown[]) => securityViewCreate(...a),
    securityViewDelete: (...a: unknown[]) => securityViewDelete(...a),
  },
}));

import SavedViews, { describeFilters } from "./SavedViews";
import { VIEWS } from "./fixtures";

afterEach(cleanup);
beforeEach(() => {
  securityViews.mockReset(); securityViewCreate.mockReset(); securityViewDelete.mockReset();
  securityViews.mockResolvedValue(VIEWS);
  securityViewCreate.mockImplementation(async (name: string, filters: unknown) => ({ id: "v3", name, filters }));
  securityViewDelete.mockResolvedValue(undefined);
});

describe("describeFilters", () => {
  it("summarizes a filter set in operator words", () => {
    expect(describeFilters({ severity: "critical", seam: "ISP", current: true }))
      .toBe("severity critical · seam ISP · current verdicts");
  });
  it("names the history choice explicitly", () => {
    expect(describeFilters({ current: false })).toBe("full history");
  });
  it("an empty filter set is described, not left blank", () => {
    expect(describeFilters(undefined)).toContain("every current finding");
  });
});

describe("Saved views", () => {
  it("lists the saved views with their filter summary", async () => {
    render(<SavedViews />);
    expect(await screen.findByText("ISP criticals")).toBeTruthy();
    expect(screen.getByText(/severity critical · seam ISP · current verdicts/)).toBeTruthy();
    expect(screen.getByText("full history")).toBeTruthy();
  });

  it("creates a view from the composed filters", async () => {
    render(<SavedViews />);
    await screen.findByText("ISP criticals");
    fireEvent.change(screen.getByLabelText("View name"), { target: { value: "  Fail only  " } });
    fireEvent.change(screen.getByLabelText("Verdict"), { target: { value: "fail" } });
    fireEvent.change(screen.getByLabelText("Search text"), { target: { value: "telnet" } });
    fireEvent.click(screen.getByRole("button", { name: "Save view" }));
    await waitFor(() => expect(securityViewCreate).toHaveBeenCalled());
    expect(securityViewCreate.mock.calls[0]).toEqual(["Fail only", { current: true, status: "fail", q: "telnet" }]);
    expect(await screen.findByText("Fail only")).toBeTruthy();
  });

  it("refuses an unnamed view", async () => {
    render(<SavedViews />);
    await screen.findByText("ISP criticals");
    expect(screen.getByRole("button", { name: "Save view" }).hasAttribute("disabled")).toBe(true);
  });

  it("deletes a view and drops it from the list", async () => {
    render(<SavedViews />);
    await screen.findByText("ISP criticals");
    fireEvent.click(screen.getAllByRole("button", { name: "Delete" })[0]);
    await waitFor(() => expect(securityViewDelete).toHaveBeenCalledWith("v1"));
    await waitFor(() => expect(screen.queryByText("ISP criticals")).toBeNull());
  });

  it("a refused delete surfaces the error and keeps the row", async () => {
    securityViewDelete.mockRejectedValue(new Error("404 Not Found"));
    render(<SavedViews />);
    await screen.findByText("ISP criticals");
    fireEvent.click(screen.getAllByRole("button", { name: "Delete" })[0]);
    expect(await screen.findByRole("alert")).toHaveTextContent(/404 Not Found/);
    expect(screen.getByText("ISP criticals")).toBeTruthy();
  });

  it("an empty list explains that a view stores a filter, not rows", async () => {
    securityViews.mockResolvedValue([]);
    render(<SavedViews />);
    // The sentence is ai/skills/explain/views.saved-view.md since the 2026-09-06
    // word sweep; the empty state keeps the fact and the `(i)`.
    expect(await screen.findByText(/No saved view yet/i)).toBeTruthy();
    expect(screen.getByRole("button", { name: /Ask Iris about a saved view/i })).toBeTruthy();
  });
});
