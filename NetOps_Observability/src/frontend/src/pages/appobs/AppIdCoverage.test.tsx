// AppIdCoverage.test.tsx — the two Settings cards over the App-ID engine.
//
// What these assert: every control hits the real route helper with the real
// body; the -1 UNKNOWN sentinel renders as unknown WITH its reason and never as
// zero; a tenant that truly has none says so differently; a refused write shows
// the server's reason; and the copy states the audit truth (the platform audit
// log records the request — the row carries no history of its own).

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, fireEvent, waitFor, cleanup } from "@testing-library/react";
import type { AppCatalogEntry, AppIdStatus } from "../../services/api";

const h = vi.hoisted(() => {
  const status = (over: Partial<AppIdStatus> = {}): AppIdStatus => ({
    attribution_precedence: ["operator", "cloud_tag", "firewall_appid", "domain", "ip_catalog"],
    precedence_is_default: true,
    feeds_configured: true,
    catalog_prefixes: 4120,
    catalog_domains: 918,
    ngfw_attributions: 27,
    cloud_attributions: 63,
    tenant_overrides: 2,
    tenant_override_pfx: 1,
    tenant_override_dom: 1,
    ...over,
  });
  const entry = (over: Partial<AppCatalogEntry> = {}): AppCatalogEntry => ({
    catalog_id: "11111111-1111-4111-8111-111111111111", tenant_id: "t",
    match_kind: "prefix", match_value: "52.96.0.0/12", app_label: "Microsoft 365",
    confidence: 0.9, source: "manual", version: 1, created_at: "2026-09-01T00:00:00Z", ...over,
  });
  return {
    status, entry,
    mock: {
      appIdStatus: vi.fn(async () => status()),
      appIdOverrides: vi.fn(async () => ({ entries: [entry()], count: 1 })),
      createAppIdOverride: vi.fn(async () => entry({ catalog_id: "22222222-2222-4222-8222-222222222222" })),
      deleteAppIdOverride: vi.fn(async () => ({ deleted: "11111111-1111-4111-8111-111111111111" })),
    },
  };
});
vi.mock("../../services/api", () => ({ api: h.mock }));

import { AppIdCoverageCard, AppIdOverridesCard } from "./AppIdCoverage";

const mock = h.mock;

beforeEach(() => { Object.values(mock).forEach((m) => m.mockClear()); });
afterEach(cleanup);

describe("AppIdCoverageCard", () => {
  it("reads GET /api/appid/status and shows the active order with the operator layer marked", async () => {
    render(<AppIdCoverageCard />);
    expect(await screen.findByText("Operator catalog / Source of Truth")).toBeTruthy();
    expect(mock.appIdStatus).toHaveBeenCalledTimes(1);
    expect(screen.getByText("Firewall App-ID (NGFW / IPFIX)")).toBeTruthy();
    expect(screen.getByText("your overrides, below")).toBeTruthy();
    expect(screen.getByText(/platform default order · read-only/)).toBeTruthy();
  });

  it("shows each layer's size, and separates the shared layers from this tenant's", async () => {
    render(<AppIdCoverageCard />);
    expect(await screen.findByText((4120).toLocaleString())).toBeTruthy();
    expect(screen.getByText((918).toLocaleString())).toBeTruthy();
    expect(screen.getByText("27")).toBeTruthy();
    expect(screen.getByText("63")).toBeTruthy();
    expect(screen.getByText(/shared platform-wide; the counts below are this tenant/)).toBeTruthy();
  });

  it("a tenant order is labelled as one rather than as the default", async () => {
    mock.appIdStatus.mockResolvedValueOnce(h.status({ precedence_is_default: false }));
    render(<AppIdCoverageCard />);
    expect(await screen.findByText(/tenant order · read-only/)).toBeTruthy();
  });

  // THE POINT OF THIS SURFACE.
  it("-1 renders as unknown WITH the reason, never as zero or as no overrides", async () => {
    mock.appIdStatus.mockResolvedValueOnce(h.status({
      tenant_overrides: -1, tenant_override_pfx: -1, tenant_override_dom: -1,
      tenant_overrides_unavailable: true,
    }));
    render(<AppIdCoverageCard />);
    expect(await screen.findAllByText("unknown")).toHaveLength(3);
    expect(screen.getByText(/could not read the operator override store/)).toBeTruthy();
    expect(screen.getByText(/not a statement that this tenant has none/)).toBeTruthy();
    // the count cells must not have become zeros
    expect(screen.queryByText("0")).toBeNull();
  });

  it("a real zero is a real zero — no unknown reason attached", async () => {
    mock.appIdStatus.mockResolvedValueOnce(h.status({
      tenant_overrides: 0, tenant_override_pfx: 0, tenant_override_dom: 0,
    }));
    render(<AppIdCoverageCard />);
    expect(await screen.findAllByText("0")).toHaveLength(3);
    expect(screen.queryByText(/could not read the operator override store/)).toBeNull();
  });

  it("says so when no managed vendor feed directory is configured", async () => {
    mock.appIdStatus.mockResolvedValueOnce(h.status({ feeds_configured: false }));
    render(<AppIdCoverageCard />);
    expect(await screen.findByText(/No managed vendor feed directory is configured/)).toBeTruthy();
  });

  it("a failed read shows an operator sentence, never the raw failure or an internal address", async () => {
    mock.appIdStatus.mockRejectedValueOnce(
      new Error('500 Internal Server Error: {"error":"appid: dial tcp 10.0.0.5:9000: connect: connection refused"}'));
    render(<AppIdCoverageCard />);
    expect(await screen.findByText(/The service did not answer\./)).toBeTruthy();
    expect(screen.queryByText(/10\.0\.0\.5/)).toBeNull();
  });

  it("a failure carrying no usable explanation falls back to what WE were doing", async () => {
    mock.appIdStatus.mockRejectedValueOnce(new Error("TypeError: x is not a function"));
    render(<AppIdCoverageCard />);
    expect(await screen.findByText(/The identification coverage could not be read\./)).toBeTruthy();
  });
});

describe("AppIdOverridesCard", () => {
  it("lists this tenant's overrides from GET /api/appid/catalog", async () => {
    render(<AppIdOverridesCard />);
    expect(await screen.findByText("52.96.0.0/12")).toBeTruthy();
    expect(mock.appIdOverrides).toHaveBeenCalledTimes(1);
    expect(screen.getByText("Microsoft 365")).toBeTruthy();
    expect(screen.getByText("IP prefix")).toBeTruthy();
  });

  it("states the real audit position — the request is logged, the row keeps no history", async () => {
    render(<AppIdOverridesCard />);
    expect(await screen.findByText(/the row itself carries no separate history/)).toBeTruthy();
  });

  it("creates through POST /api/appid/catalog with the entered body and no tenant", async () => {
    render(<AppIdOverridesCard />);
    fireEvent.click(await screen.findByRole("button", { name: "New override" }));
    fireEvent.change(screen.getByLabelText("Match on"), { target: { value: "domain" } });
    fireEvent.change(screen.getByLabelText("Match value"), { target: { value: " teams.microsoft.com " } });
    fireEvent.change(screen.getByLabelText("Application name"), { target: { value: " Teams " } });
    fireEvent.change(screen.getByLabelText("Confidence"), { target: { value: "0.8" } });
    fireEvent.click(screen.getByRole("button", { name: "Add override" }));
    await waitFor(() => expect(mock.createAppIdOverride).toHaveBeenCalledWith({
      match_kind: "domain", match_value: "teams.microsoft.com", app_label: "Teams", confidence: 0.8,
    }));
    // and the list is re-read so the new row appears
    await waitFor(() => expect(mock.appIdOverrides).toHaveBeenCalledTimes(2));
  });

  it("omits confidence when the operator left it blank", async () => {
    render(<AppIdOverridesCard />);
    fireEvent.click(await screen.findByRole("button", { name: "New override" }));
    fireEvent.change(screen.getByLabelText("Match value"), { target: { value: "10.0.0.0/8" } });
    fireEvent.change(screen.getByLabelText("Application name"), { target: { value: "Billing" } });
    fireEvent.click(screen.getByRole("button", { name: "Add override" }));
    await waitFor(() => expect(mock.createAppIdOverride).toHaveBeenCalledWith({
      match_kind: "prefix", match_value: "10.0.0.0/8", app_label: "Billing",
    }));
  });

  it("blocks an invalid draft client-side and never calls the route", async () => {
    render(<AppIdOverridesCard />);
    fireEvent.click(await screen.findByRole("button", { name: "New override" }));
    fireEvent.change(screen.getByLabelText("Match value"), { target: { value: "not-an-address" } });
    fireEvent.change(screen.getByLabelText("Application name"), { target: { value: "x" } });
    fireEvent.click(screen.getByRole("button", { name: "Add override" }));
    expect(await screen.findByText(/valid IPv4 address or CIDR/)).toBeTruthy();
    expect(mock.createAppIdOverride).not.toHaveBeenCalled();
  });

  it("a write refused by permission shows the refusal, not a silent no-op", async () => {
    mock.createAppIdOverride.mockRejectedValueOnce(new Error("403 Forbidden: {}"));
    render(<AppIdOverridesCard />);
    fireEvent.click(await screen.findByRole("button", { name: "New override" }));
    fireEvent.change(screen.getByLabelText("Match value"), { target: { value: "10.0.0.0/8" } });
    fireEvent.change(screen.getByLabelText("Application name"), { target: { value: "Billing" } });
    fireEvent.click(screen.getByRole("button", { name: "Add override" }));
    expect(await screen.findByText("You do not have access to this.")).toBeTruthy();
  });

  it("deletes by id only after a confirm that names the row and the consequence", async () => {
    const confirmSpy = vi.spyOn(window, "confirm").mockReturnValue(true);
    render(<AppIdOverridesCard />);
    fireEvent.click(await screen.findByRole("button", { name: /Remove the override for 52\.96\.0\.0\/12/ }));
    await waitFor(() => expect(mock.deleteAppIdOverride)
      .toHaveBeenCalledWith("11111111-1111-4111-8111-111111111111"));
    expect(confirmSpy.mock.calls[0][0]).toMatch(/falls back to the next source/);
    confirmSpy.mockRestore();
  });

  it("a declined confirm calls nothing", async () => {
    const confirmSpy = vi.spyOn(window, "confirm").mockReturnValue(false);
    render(<AppIdOverridesCard />);
    fireEvent.click(await screen.findByRole("button", { name: /Remove the override for/ }));
    expect(mock.deleteAppIdOverride).not.toHaveBeenCalled();
    confirmSpy.mockRestore();
  });

  it("an empty override list says the ladder falls through, not that something is broken", async () => {
    mock.appIdOverrides.mockResolvedValueOnce({ entries: [], count: 0 });
    render(<AppIdOverridesCard />);
    expect(await screen.findByText(/declared no overrides/)).toBeTruthy();
  });
});
