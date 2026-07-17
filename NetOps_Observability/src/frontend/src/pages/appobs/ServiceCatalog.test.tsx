// ServiceCatalog.test.tsx — the catalog CRUD surface: renders ONLY what the
// tenant-scoped API returns, creates/edits through the real endpoints with the
// client-side bounds mirror, deletes only after a confirm that discloses the
// mapping revert, and shows the API's real reason on a 501 (no-store) deployment.

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, fireEvent, waitFor, cleanup } from "@testing-library/react";
import type { BusinessServiceRow } from "../../services/api";

const h = vi.hoisted(() => {
  const svc = (over: Partial<BusinessServiceRow> = {}): BusinessServiceRow => ({
    business_service_id: "b1", tenant_id: "t", name: "payments",
    description: "card processing", criticality: "critical", owner: "payments-sre",
    created_by: "u", created_at: "2026-07-01T00:00:00Z", updated_at: "2026-07-15T00:00:00Z",
    ...over,
  });
  return {
    svc,
    mock: {
      cloudBusinessServices: vi.fn(async () => ({ business_services: [svc()], count: 1 })),
      cloudResourceMappings: vi.fn(async () => ({
        resource_mappings: [
          { tenant_id: "t", resource_id: "r1", business_service_id: "b1", service_name: "payments", source: "manual", confidence: "confirmed", basis: "operator assignment", is_manual_override: true, created_by: "u", created_at: "", updated_at: "" },
          { tenant_id: "t", resource_id: "r2", business_service_id: "b1", service_name: "payments", source: "manual", confidence: "confirmed", basis: "operator assignment", is_manual_override: true, created_by: "u", created_at: "", updated_at: "" },
        ],
        count: 2,
      })),
      cloudCreateBusinessService: vi.fn(async () => h.svc({ business_service_id: "b2" })),
      cloudUpdateBusinessService: vi.fn(async () => ({ updated: "b1" })),
      cloudDeleteBusinessService: vi.fn(async () => ({ deleted: "b1" })),
    },
  };
});
vi.mock("../../services/api", () => ({ api: h.mock }));

import ServiceCatalog from "./ServiceCatalog";

const mock = h.mock;

beforeEach(() => { Object.values(mock).forEach((m) => m.mockClear()); });
afterEach(cleanup);

describe("ServiceCatalog", () => {
  it("renders the catalog with criticality, owner and mapped-resource counts", async () => {
    render(<ServiceCatalog />);
    expect(await screen.findByText("payments")).toBeTruthy();
    expect(screen.getByText("Business-critical")).toBeTruthy();
    expect(screen.getByText("payments-sre")).toBeTruthy();
    expect(screen.getByText("2")).toBeTruthy(); // mapped resources
  });

  it("creates a service through the real POST with the entered fields", async () => {
    render(<ServiceCatalog />);
    fireEvent.click(await screen.findByRole("button", { name: "New service" }));
    fireEvent.change(screen.getByPlaceholderText("e.g. payments"), { target: { value: "checkout" } });
    fireEvent.change(screen.getByLabelText("Criticality"), { target: { value: "high" } });
    fireEvent.change(screen.getByPlaceholderText(/accountable/), { target: { value: "web-team" } });
    fireEvent.click(screen.getByRole("button", { name: "Create service" }));
    await waitFor(() => expect(mock.cloudCreateBusinessService).toHaveBeenCalledWith({
      name: "checkout", description: "", criticality: "high", owner: "web-team",
    }));
  });

  it("blocks an invalid form client-side with a specific message", async () => {
    render(<ServiceCatalog />);
    fireEvent.click(await screen.findByRole("button", { name: "New service" }));
    fireEvent.click(screen.getByRole("button", { name: "Create service" }));
    expect(await screen.findByText(/service name is required/)).toBeTruthy();
    expect(mock.cloudCreateBusinessService).not.toHaveBeenCalled();
  });

  it("edits through the real PUT, prefilled from the row", async () => {
    render(<ServiceCatalog />);
    fireEvent.click(await screen.findByRole("button", { name: "Edit" }));
    const owner = screen.getByPlaceholderText(/accountable/) as HTMLInputElement;
    expect(owner.value).toBe("payments-sre");
    fireEvent.change(owner, { target: { value: "fintech-sre" } });
    fireEvent.click(screen.getByRole("button", { name: "Save changes" }));
    await waitFor(() => expect(mock.cloudUpdateBusinessService).toHaveBeenCalledWith("b1",
      expect.objectContaining({ name: "payments", owner: "fintech-sre" })));
  });

  it("deletes only after a confirm that discloses the mapping revert", async () => {
    const confirmSpy = vi.spyOn(window, "confirm").mockReturnValue(true);
    render(<ServiceCatalog />);
    fireEvent.click(await screen.findByRole("button", { name: "Delete" }));
    await waitFor(() => expect(mock.cloudDeleteBusinessService).toHaveBeenCalledWith("b1"));
    expect(confirmSpy.mock.calls[0][0]).toMatch(/2 mapped resources revert/);
    confirmSpy.mockRestore();
  });

  it("501 (no catalog store) → the API's real reason, never a silent failure", async () => {
    mock.cloudBusinessServices.mockRejectedValueOnce(new Error("501 Not Implemented: business service store requires the Postgres backend"));
    render(<ServiceCatalog />);
    expect(await screen.findByText("The service catalog is unavailable")).toBeTruthy();
  });

  it("empty catalog → honest empty state with the create action", async () => {
    mock.cloudBusinessServices.mockResolvedValueOnce({ business_services: [], count: 0 });
    render(<ServiceCatalog />);
    expect(await screen.findByText("No services in the catalog yet")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Create the first service" }));
    expect(screen.getByRole("button", { name: "Create service" })).toBeTruthy();
  });
});
