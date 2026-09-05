// Registries.test.tsx — the operator-authored service catalog + application
// registry sub-tab.
//
// What these assert: every control hits the real route helper with the real
// body; the 501 no-store answer renders the API's own reason instead of an empty
// list; a service with no usable selector says nothing is attributed to it;
// archived rows read as archived and DELETE is described as an archive; the two
// registries are stated to be separate lists (no invented parent link); and a
// refused write shows the refusal.

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, fireEvent, waitFor, cleanup } from "@testing-library/react";
import type {
  ApplicationRow, CatalogServiceBinding, CatalogServiceRow, CatalogServiceSelector,
} from "../../services/api";

const SVC_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const APP_ID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const BIND_ID = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";

const h = vi.hoisted(() => {
  const SVC_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
  const APP_ID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
  const BIND_ID = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
  const svc = (over: Partial<CatalogServiceRow> = {}): CatalogServiceRow => ({
    service_id: SVC_ID, tenant_id: "t", name: "payments", criticality: "critical",
    description: "card processing", created_at: "2026-08-01T00:00:00Z", ...over,
  });
  const app = (over: Partial<ApplicationRow> = {}): ApplicationRow => ({
    application_id: APP_ID, tenant_id: "t", name: "billing", owner_team: "payments-sre",
    criticality: "high", description: "invoicing", created_at: "2026-08-02T00:00:00Z", ...over,
  });
  const sel = (over: Partial<CatalogServiceSelector> = {}): CatalogServiceSelector => ({
    service_id: SVC_ID, version: 1, effective_from: "2026-08-01T00:00:00Z",
    spec: { ports: [443] }, created_by: "u", created_at: "2026-08-01T00:00:00Z", ...over,
  });
  const bind = (over: Partial<CatalogServiceBinding> = {}): CatalogServiceBinding => ({
    binding_id: BIND_ID, service_id: SVC_ID, kind: "probe", ref: "http-checkout",
    created_at: "2026-08-03T00:00:00Z", ...over,
  });
  return {
    svc, app, sel, bind,
    mock: {
      catalogServices: vi.fn(async () => [svc()]),
      createCatalogService: vi.fn(async () => svc({ service_id: "new" })),
      archiveCatalogService: vi.fn(async () => ({ archived: SVC_ID })),
      catalogServiceSelectors: vi.fn(async () => [sel()]),
      addCatalogServiceSelector: vi.fn(async () => sel({ version: 2 })),
      catalogServiceBindings: vi.fn(async () => [bind()]),
      addCatalogServiceBinding: vi.fn(async () => bind({ binding_id: "new" })),
      deleteCatalogServiceBinding: vi.fn(async () => ({ deleted: BIND_ID })),
      applications: vi.fn(async () => [app()]),
      createApplication: vi.fn(async () => app({ application_id: "new" })),
      archiveApplication: vi.fn(async () => ({ archived: APP_ID })),
    },
  };
});
vi.mock("../../services/api", () => ({ api: h.mock }));

import Registries from "./Registries";

const mock = h.mock;
const noop = () => {};

beforeEach(() => { Object.values(mock).forEach((m) => m.mockClear()); });
afterEach(cleanup);

describe("Registries — what each registry drives", () => {
  it("names all three registries and says the two here are separate lists", async () => {
    render(<Registries onOpenCloudCatalog={noop} />);
    expect(await screen.findByText("Which registry drives what")).toBeTruthy();
    expect(screen.getByText(/a service cannot be attached to an application in the product/)).toBeTruthy();
    expect(screen.getByText(/Its selector is what/)).toBeTruthy();
  });

  it("cross-links to the cloud business-service registry through the page's own sub-tab", async () => {
    const open = vi.fn();
    render(<Registries onOpenCloudCatalog={open} />);
    fireEvent.click(await screen.findByRole("button", { name: "Open the Catalog view" }));
    expect(open).toHaveBeenCalledTimes(1);
  });
});

describe("Registries — the service catalog", () => {
  it("lists services from GET /api/services (active only by default)", async () => {
    render(<Registries onOpenCloudCatalog={noop} />);
    expect(await screen.findByText("payments")).toBeTruthy();
    expect(mock.catalogServices).toHaveBeenCalledWith(false);
  });

  it("re-reads with ?archived=true when archived rows are asked for, and marks them archived", async () => {
    render(<Registries onOpenCloudCatalog={noop} />);
    await screen.findByText("payments");
    mock.catalogServices.mockResolvedValueOnce([h.svc({ archived_at: "2026-08-20T00:00:00Z" })]);
    fireEvent.click(screen.getAllByRole("checkbox")[0]);
    await waitFor(() => expect(mock.catalogServices).toHaveBeenLastCalledWith(true));
    expect(await screen.findByText(/^archived /)).toBeTruthy();
    // an archived row offers no archive action
    expect(screen.queryByRole("button", { name: "Archive payments" })).toBeNull();
  });

  it("creates through POST /api/services with the entered body", async () => {
    render(<Registries onOpenCloudCatalog={noop} />);
    await screen.findByText("payments");
    fireEvent.click(screen.getByRole("button", { name: "New service" }));
    fireEvent.change(screen.getByLabelText("Service name"), { target: { value: " checkout " } });
    fireEvent.change(screen.getByLabelText("Service criticality"), { target: { value: "high" } });
    fireEvent.change(screen.getByLabelText("Service description"), { target: { value: "web checkout" } });
    fireEvent.click(screen.getByRole("button", { name: "Create service" }));
    await waitFor(() => expect(mock.createCatalogService).toHaveBeenCalledWith({
      name: "checkout", criticality: "high", description: "web checkout",
    }));
  });

  it("blocks a nameless service client-side and never calls the route", async () => {
    render(<Registries onOpenCloudCatalog={noop} />);
    await screen.findByText("payments");
    fireEvent.click(screen.getByRole("button", { name: "New service" }));
    fireEvent.click(screen.getByRole("button", { name: "Create service" }));
    expect(await screen.findByText(/a service name is required/)).toBeTruthy();
    expect(mock.createCatalogService).not.toHaveBeenCalled();
  });

  it("archives (never hard-deletes) after a confirm that says what survives", async () => {
    const confirmSpy = vi.spyOn(window, "confirm").mockReturnValue(true);
    render(<Registries onOpenCloudCatalog={noop} />);
    fireEvent.click(await screen.findByRole("button", { name: "Archive payments" }));
    await waitFor(() => expect(mock.archiveCatalogService).toHaveBeenCalledWith(SVC_ID));
    expect(confirmSpy.mock.calls[0][0]).toMatch(/Archive the service "payments"\?/);
    expect(confirmSpy.mock.calls[0][0]).toMatch(/selector versions and past attribution are kept/);
    confirmSpy.mockRestore();
  });

  it("a 501 deployment shows the API's own reason instead of an empty list", async () => {
    mock.catalogServices.mockRejectedValueOnce(
      new Error('501 Not Implemented: {"error":"service catalog requires the PostgreSQL backend"}'));
    render(<Registries onOpenCloudCatalog={noop} />);
    expect(await screen.findByText("The service catalog is not available on this deployment")).toBeTruthy();
    expect(screen.getByText(/Service catalog requires the PostgreSQL/)).toBeTruthy();
    expect(screen.queryByText("No services defined yet")).toBeNull();
  });

  it("an empty catalog is an empty catalog, not a failure", async () => {
    mock.catalogServices.mockResolvedValueOnce([]);
    render(<Registries onOpenCloudCatalog={noop} />);
    expect(await screen.findByText("No services defined yet")).toBeTruthy();
  });

  it("an archive refused by permission shows the refusal", async () => {
    const confirmSpy = vi.spyOn(window, "confirm").mockReturnValue(true);
    mock.archiveCatalogService.mockRejectedValueOnce(new Error("403 Forbidden: {}"));
    render(<Registries onOpenCloudCatalog={noop} />);
    fireEvent.click(await screen.findByRole("button", { name: "Archive payments" }));
    expect(await screen.findByText("You do not have access to this.")).toBeTruthy();
    confirmSpy.mockRestore();
  });
});

describe("Registries — a service's grouping rule (selectors)", () => {
  const openDrawer = async () => {
    render(<Registries onOpenCloudCatalog={noop} />);
    fireEvent.click(await screen.findByRole("button", { name: "Open payments" }));
  };

  it("reads the versions from GET /api/services/{id}/selectors and marks the one in force", async () => {
    mock.catalogServiceSelectors.mockResolvedValueOnce([h.sel({ version: 2, spec: { ports: [443, 8443] } }), h.sel()]);
    await openDrawer();
    expect(await screen.findByText("2 · in force")).toBeTruthy();
    expect(mock.catalogServiceSelectors).toHaveBeenCalledWith(SVC_ID);
    expect(screen.getByText("ports 443, 8443")).toBeTruthy();
  });

  // The `attributed:false` consequence, made visible.
  it("a service whose latest version has no usable predicate says nothing is attributed", async () => {
    mock.catalogServiceSelectors.mockResolvedValueOnce([h.sel({ spec: { domains: ["example.com"] } })]);
    await openDrawer();
    expect((await screen.findAllByText(/Nothing is attributed to this service until a selector matches/)).length)
      .toBeGreaterThan(0);
    expect(screen.getByText(/also carries domains, which the/)).toBeTruthy();
    expect(screen.getByText("nothing")).toBeTruthy();
  });

  it("a service with no selector at all says the same thing", async () => {
    mock.catalogServiceSelectors.mockResolvedValueOnce([]);
    await openDrawer();
    expect((await screen.findAllByText(/Nothing is attributed to this service until a selector matches/)).length)
      .toBeGreaterThan(0);
  });

  it("posts a NEW VERSION with the parsed spec, never an edit in place", async () => {
    await openDrawer();
    await screen.findByText("1 · in force");
    fireEvent.change(screen.getByLabelText("Destination ports"), { target: { value: "443, 8443" } });
    fireEvent.change(screen.getByLabelText("Destination prefixes"), { target: { value: "10.0.0.0/8" } });
    fireEvent.change(screen.getByLabelText("Protocol numbers"), { target: { value: "6" } });
    fireEvent.click(screen.getByRole("button", { name: "Save version 2" }));
    await waitFor(() => expect(mock.addCatalogServiceSelector).toHaveBeenCalledWith(SVC_ID, {
      ports: [443, 8443], dst_prefixes: ["10.0.0.0/8"], protocols: [6],
    }));
  });

  it("refuses to save a rule that would attribute nothing, and says why", async () => {
    await openDrawer();
    await screen.findByText("1 · in force");
    const save = screen.getByRole("button", { name: "Save version 2" }) as HTMLButtonElement;
    expect(save.disabled).toBe(true);
    fireEvent.change(screen.getByLabelText("Destination ports"), { target: { value: "70000" } });
    expect(await screen.findByText(/is not a port/)).toBeTruthy();
    expect((screen.getByRole("button", { name: "Save version 2" }) as HTMLButtonElement).disabled).toBe(true);
    expect(mock.addCatalogServiceSelector).not.toHaveBeenCalled();
  });
});

describe("Registries — a service's attachments (bindings)", () => {
  const openDrawer = async () => {
    render(<Registries onOpenCloudCatalog={noop} />);
    fireEvent.click(await screen.findByRole("button", { name: "Open payments" }));
  };

  it("lists them from GET /api/services/{id}/bindings", async () => {
    await openDrawer();
    expect(await screen.findByText("http-checkout")).toBeTruthy();
    expect(mock.catalogServiceBindings).toHaveBeenCalledWith(SVC_ID);
  });

  it("attaches through POST with kind and ref", async () => {
    await openDrawer();
    await screen.findByText("http-checkout");
    fireEvent.change(screen.getByLabelText("Attachment kind"), { target: { value: "seam" } });
    fireEvent.change(screen.getByLabelText("Attachment reference"), { target: { value: " dia-lumen " } });
    fireEvent.click(screen.getByRole("button", { name: "Attach" }));
    await waitFor(() => expect(mock.addCatalogServiceBinding).toHaveBeenCalledWith(SVC_ID, "seam", "dia-lumen"));
  });

  it("detaches through DELETE by binding id", async () => {
    await openDrawer();
    fireEvent.click(await screen.findByRole("button", { name: "Remove the attachment http-checkout" }));
    await waitFor(() => expect(mock.deleteCatalogServiceBinding).toHaveBeenCalledWith(SVC_ID, BIND_ID));
  });

  it("no attachments reads as none attached, not as a failure", async () => {
    mock.catalogServiceBindings.mockResolvedValueOnce([]);
    await openDrawer();
    expect(await screen.findByText(/Nothing is attached to this service yet/)).toBeTruthy();
  });
});

describe("Registries — the application registry", () => {
  it("lists applications from GET /api/applications with owner and criticality", async () => {
    render(<Registries onOpenCloudCatalog={noop} />);
    expect(await screen.findByText("billing")).toBeTruthy();
    expect(mock.applications).toHaveBeenCalledWith(false);
    expect(screen.getByText("payments-sre")).toBeTruthy();
    expect(screen.getByText("High")).toBeTruthy();
  });

  it("creates through POST /api/applications with the entered body", async () => {
    render(<Registries onOpenCloudCatalog={noop} />);
    await screen.findByText("billing");
    fireEvent.click(screen.getByRole("button", { name: "New application" }));
    fireEvent.change(screen.getByLabelText("Application name"), { target: { value: " ledger " } });
    fireEvent.change(screen.getByLabelText("Owner team"), { target: { value: " fin-eng " } });
    fireEvent.change(screen.getByLabelText("Application criticality"), { target: { value: "low" } });
    fireEvent.change(screen.getByLabelText("Application description"), { target: { value: "the ledger" } });
    fireEvent.click(screen.getByRole("button", { name: "Create application" }));
    await waitFor(() => expect(mock.createApplication).toHaveBeenCalledWith({
      name: "ledger", owner_team: "fin-eng", criticality: "low", description: "the ledger",
    }));
  });

  it("blocks a nameless application client-side", async () => {
    render(<Registries onOpenCloudCatalog={noop} />);
    await screen.findByText("billing");
    fireEvent.click(screen.getByRole("button", { name: "New application" }));
    fireEvent.click(screen.getByRole("button", { name: "Create application" }));
    expect(await screen.findByText(/an application name is required/)).toBeTruthy();
    expect(mock.createApplication).not.toHaveBeenCalled();
  });

  it("archives after a confirm that says the record is kept", async () => {
    const confirmSpy = vi.spyOn(window, "confirm").mockReturnValue(true);
    render(<Registries onOpenCloudCatalog={noop} />);
    fireEvent.click(await screen.findByRole("button", { name: "Archive billing" }));
    await waitFor(() => expect(mock.archiveApplication).toHaveBeenCalledWith(APP_ID));
    expect(confirmSpy.mock.calls[0][0]).toMatch(/the record is kept/);
    confirmSpy.mockRestore();
  });

  it("re-reads with ?archived=true on request", async () => {
    render(<Registries onOpenCloudCatalog={noop} />);
    await screen.findByText("billing");
    fireEvent.click(screen.getAllByRole("checkbox")[1]);
    await waitFor(() => expect(mock.applications).toHaveBeenLastCalledWith(true));
  });

  it("an empty registry is an empty registry", async () => {
    mock.applications.mockResolvedValueOnce([]);
    render(<Registries onOpenCloudCatalog={noop} />);
    expect(await screen.findByText("No applications registered yet")).toBeTruthy();
  });
});
