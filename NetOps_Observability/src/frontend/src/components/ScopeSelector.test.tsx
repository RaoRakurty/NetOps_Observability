// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// ScopeSelector contract — the top-bar control exists to state WHICH door is
// open. Two truthfulness rules ratcheted here:
//  · when TenantGate (or anything else) opens a tenant and dispatches
//    netops:scope, the selector label must follow in-tab — "All tenants"
//    over tenant-scoped pages is a misread waiting to happen;
//  · when the persisted scope is stale (tenant deleted/unbound), the cleanup
//    must ANNOUNCE itself via netops:scope so TenantGate re-locks in-tab,
//    not just silently clear localStorage.
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, cleanup, waitFor, act, fireEvent } from "@testing-library/react";
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
    expect(await screen.findByText("All tenants")).toBeTruthy();

    // TenantGate's open(): persist + announce, no reload.
    act(() => {
      setActiveScope("t_wal");
      window.dispatchEvent(new CustomEvent("netops:scope", { detail: "t_wal" }));
    });
    await waitFor(() => expect(screen.getByText("Walmart Inc · Walmart Retail")).toBeTruthy());
    expect(screen.queryByText("All tenants")).toBeNull();
  });

  it("follows a cross-tab storage change", async () => {
    mockScopes(true);
    render(<ScopeSelector />);
    expect(await screen.findByText("All tenants")).toBeTruthy();
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
      expect(await screen.findByText("All tenants")).toBeTruthy();
    } finally {
      window.removeEventListener("netops:scope", spy);
    }
  });
});

// Tracker 365: "All tenants" is the only cross view; "Provider" is an ordinary
// entry that narrows to the platform's own data.
describe("ScopeSelector menu (tracker 365)", () => {
  const WITH_PROVIDER = [
    { tenant_id: "global", tenant_name: "Provider", org_id: "global", org_name: "Global", region: "" },
    ...SCOPES,
  ];

  it("names the cross view All tenants and says rows are labelled", async () => {
    mockScopes(true, WITH_PROVIDER);
    render(<ScopeSelector />);
    fireEvent.click(await screen.findByRole("button", { name: /All tenants/ }));
    expect(screen.getByText("Every tenant, each row labelled with its tenant")).toBeTruthy();
    expect(screen.queryByText("All organizations")).toBeNull();
  });

  it("offers Provider as its own, narrowing scope", async () => {
    mockScopes(true, WITH_PROVIDER);
    render(<ScopeSelector />);
    fireEvent.click(await screen.findByRole("button", { name: /All tenants/ }));
    expect(screen.getByText("Provider")).toBeTruthy();
    expect(screen.getByText("Your own (platform) data only")).toBeTruthy();
  });

  it("labels the button with Provider once it is the active scope", async () => {
    mockScopes(true, WITH_PROVIDER);
    setActiveScope("global");
    render(<ScopeSelector />);
    expect(await screen.findByText("Global · Provider")).toBeTruthy();
    expect(screen.queryByText("All tenants")).toBeNull();
  });
});
