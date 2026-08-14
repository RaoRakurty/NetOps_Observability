// TenantGate contract (owner 2026-07-21 — "cross-tenant reach is not
// cross-tenant display"):
//  · a single-tenant principal is NEVER gated (they are already one tenant)
//  · a platform admin with no scope IS gated on telemetry sections — the point
//    of the feature: ten tenants' rows must not merge into one table
//  · a platform admin WITH a scope passes through (door open)
//  · platform/estate sections (Administration) are never gated — that is where
//    you manage tenants and choose which one to open
//  · choosing a tenant sets the acting scope, so every later API call carries it
//  · a failed /api/scopes call fails OPEN (organising device, not a security
//    control — the server enforces isolation regardless)
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, cleanup, waitFor, fireEvent } from "@testing-library/react";
import TenantGate, { isTenantScopedSection } from "./TenantGate";
import { api, getActiveScope, setActiveScope } from "../services/api";

const SCOPES = [
  { tenant_id: "t_wal", tenant_name: "Walmart Retail", org_id: "o_wal", org_name: "Walmart Inc", region: "us-east" },
  { tenant_id: "t_tgt", tenant_name: "Target Retail", org_id: "o_tgt", org_name: "Target Corp", region: "us-west" },
];

beforeEach(() => {
  localStorage.clear();
  setActiveScope("");
});
afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

const mockScopes = (all_tenants: boolean, scopes = SCOPES) =>
  vi.spyOn(api, "myScopes").mockResolvedValue({ scopes, all_tenants });

describe("section classification", () => {
  it("gates telemetry sections and leaves the estate sections open", () => {
    expect(isTenantScopedSection("logs")).toBe(true);
    expect(isTenantScopedSection("metrics")).toBe(true);
    expect(isTenantScopedSection("infrastructure")).toBe(true);
    expect(isTenantScopedSection("admin")).toBe(false);
    expect(isTenantScopedSection("copilot")).toBe(false);
  });

  it("gates an unknown/new section by default (safe direction)", () => {
    expect(isTenantScopedSection("some-future-section")).toBe(true);
  });
});

describe("TenantGate", () => {
  it("never gates a single-tenant principal", async () => {
    mockScopes(false, [SCOPES[0]]);
    render(
      <TenantGate sectionId="logs" sectionLabel="Logs">
        <div>TENANT DATA</div>
      </TenantGate>,
    );
    expect(await screen.findByText("TENANT DATA")).toBeTruthy();
  });

  it("gates a platform admin who has not opened a tenant", async () => {
    mockScopes(true);
    render(
      <TenantGate sectionId="logs" sectionLabel="Logs">
        <div>TENANT DATA</div>
      </TenantGate>,
    );
    await waitFor(() => expect(screen.getByRole("region", { name: /select a tenant/i })).toBeTruthy());
    // The whole point: the merged data is NOT rendered.
    expect(screen.queryByText("TENANT DATA")).toBeNull();
    // Both tenants are offered, grouped under their orgs.
    expect(screen.getByText("Walmart Retail")).toBeTruthy();
    expect(screen.getByText("Target Corp")).toBeTruthy();
  });

  it("lets a platform admin through once a tenant is open", async () => {
    mockScopes(true);
    setActiveScope("t_wal");
    render(
      <TenantGate sectionId="logs" sectionLabel="Logs">
        <div>TENANT DATA</div>
      </TenantGate>,
    );
    expect(await screen.findByText("TENANT DATA")).toBeTruthy();
  });

  it("never gates the estate sections, even unscoped", async () => {
    mockScopes(true);
    render(
      <TenantGate sectionId="admin" sectionLabel="Administration">
        <div>ESTATE PAGE</div>
      </TenantGate>,
    );
    expect(await screen.findByText("ESTATE PAGE")).toBeTruthy();
  });

  it("opening a tenant sets the acting scope and reveals the page", async () => {
    mockScopes(true);
    render(
      <TenantGate sectionId="flows" sectionLabel="Flows">
        <div>TENANT DATA</div>
      </TenantGate>,
    );
    const pick = await screen.findByText("Target Retail");
    fireEvent.click(pick);
    // Scope persisted → every subsequent request carries X-Acting-Tenant.
    expect(getActiveScope()).toBe("t_tgt");
    expect(await screen.findByText("TENANT DATA")).toBeTruthy();
  });

  it("filters the picker by org or tenant name", async () => {
    mockScopes(true);
    render(
      <TenantGate sectionId="logs" sectionLabel="Logs">
        <div>TENANT DATA</div>
      </TenantGate>,
    );
    const box = await screen.findByLabelText("Filter organizations and tenants");
    fireEvent.change(box, { target: { value: "walmart" } });
    expect(screen.getByText("Walmart Retail")).toBeTruthy();
    expect(screen.queryByText("Target Retail")).toBeNull();
  });

  // A persisted scope is a claim, not a fact: the tenant may have been deleted
  // or unbound since it was stored. The backend ignores an unresolvable
  // X-Acting-Tenant, so honouring the stale claim would render the forbidden
  // merged cross-tenant view. The gate must validate `active` against the
  // myScopes fetch it already makes, clear the stale key, and LOCK.
  it("re-locks when the persisted scope is no longer among the principal's scopes", async () => {
    mockScopes(true);
    setActiveScope("t_deleted");
    render(
      <TenantGate sectionId="logs" sectionLabel="Logs">
        <div>TENANT DATA</div>
      </TenantGate>,
    );
    await waitFor(() => expect(screen.getByRole("region", { name: /select a tenant/i })).toBeTruthy());
    expect(screen.queryByText("TENANT DATA")).toBeNull();
    // The stale key is cleared so API calls stop carrying a dead X-Acting-Tenant.
    expect(getActiveScope()).toBe("");
  });

  it("still honours a persisted scope that IS among the principal's scopes", async () => {
    mockScopes(true);
    setActiveScope("t_tgt");
    render(
      <TenantGate sectionId="logs" sectionLabel="Logs">
        <div>TENANT DATA</div>
      </TenantGate>,
    );
    expect(await screen.findByText("TENANT DATA")).toBeTruthy();
    expect(getActiveScope()).toBe("t_tgt");
  });

  it("fails OPEN when scopes cannot be loaded", async () => {
    vi.spyOn(api, "myScopes").mockRejectedValue(new Error("network"));
    render(
      <TenantGate sectionId="logs" sectionLabel="Logs">
        <div>TENANT DATA</div>
      </TenantGate>,
    );
    // The gate organises the UI; it is not the isolation boundary, so a
    // metadata failure must not blank the app.
    expect(await screen.findByText("TENANT DATA")).toBeTruthy();
  });
});
