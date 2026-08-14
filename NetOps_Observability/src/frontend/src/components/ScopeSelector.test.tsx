// ScopeSelector contract — the top-bar control exists to state WHICH door is
// open. Two truthfulness rules ratcheted here:
//  · when TenantGate (or anything else) opens a tenant and dispatches
//    netops:scope, the selector label must follow in-tab — "All organizations"
//    over tenant-scoped pages is a misread waiting to happen;
//  · when the persisted scope is stale (tenant deleted/unbound), the cleanup
//    must ANNOUNCE itself via netops:scope so TenantGate re-locks in-tab,
//    not just silently clear localStorage.
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, cleanup, waitFor, act } from "@testing-library/react";
import ScopeSelector from "./ScopeSelector";
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

describe("ScopeSelector", () => {
  it("follows a netops:scope pick in-tab (TenantGate opened a door)", async () => {
    mockScopes(true);
    render(<ScopeSelector />);
    // Unscoped platform owner → estate view label.
    expect(await screen.findByText("All organizations")).toBeTruthy();

    // TenantGate's open(): persist + announce, no reload.
    act(() => {
      setActiveScope("t_wal");
      window.dispatchEvent(new CustomEvent("netops:scope", { detail: "t_wal" }));
    });
    await waitFor(() => expect(screen.getByText("Walmart Inc · Walmart Retail")).toBeTruthy());
    expect(screen.queryByText("All organizations")).toBeNull();
  });

  it("follows a cross-tab storage change", async () => {
    mockScopes(true);
    render(<ScopeSelector />);
    expect(await screen.findByText("All organizations")).toBeTruthy();
    act(() => {
      setActiveScope("t_tgt");
      window.dispatchEvent(new Event("storage"));
    });
    await waitFor(() => expect(screen.getByText("Target Corp · Target Retail")).toBeTruthy());
  });

  it("clears a stale persisted scope AND announces it via netops:scope", async () => {
    mockScopes(true);
    setActiveScope("t_deleted");
    const events: string[] = [];
    const spy = (e: Event) => events.push(String((e as CustomEvent).detail ?? ""));
    window.addEventListener("netops:scope", spy);
    try {
      render(<ScopeSelector />);
      await waitFor(() => expect(getActiveScope()).toBe(""));
      // The announcement is what lets TenantGate re-lock in-tab.
      expect(events).toContain("");
      expect(await screen.findByText("All organizations")).toBeTruthy();
    } finally {
      window.removeEventListener("netops:scope", spy);
    }
  });
});
