// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Identity & Access: the Provider is an organization like any other (owner
// 2026-10-18). Its drill-in carries the same tabs as a customer org — Users,
// Access, roles, SSO roles, Security and Tenants — and its Tenants tab lists
// ONLY the Provider organization's tenants, never another organization's (an
// empty org id would have meant "no filter" and listed them all).
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, fireEvent, cleanup, within } from "@testing-library/react";

const mockUseAuth = vi.fn();
vi.mock("../hooks/useAuth", () => ({ useAuth: (...a: unknown[]) => mockUseAuth(...a) }));
vi.mock("../components/AskIris", () => ({ default: () => null }));

const apiMock = vi.hoisted(() => ({
  listOrgs: vi.fn(),
  listRegions: vi.fn(),
  listTenants: vi.fn(),
  listUsers: vi.fn(),
  listRoles: vi.fn(),
  listBindings: vi.fn(),
}));
vi.mock("../services/api", async (orig) => {
  const real = (await orig()) as Record<string, unknown>;
  return { ...real, api: new Proxy(apiMock, { get: (t, k: string) => (k in t ? (t as Record<string, unknown>)[k] : vi.fn().mockResolvedValue([])) }) };
});

import { IdentityAccess } from "./admin";

beforeEach(() => {
  mockUseAuth.mockReturnValue({ user: { username: "admin", platform_admin: true }, loading: false });
  apiMock.listOrgs.mockResolvedValue([
    { id: "global", name: "Provider" },
    { id: "org-walmart", name: "WALMART" },
  ]);
  apiMock.listRegions.mockResolvedValue([]);
  apiMock.listTenants.mockResolvedValue([
    { id: "global", name: "Provider", org_id: "global" },
    { id: "t_retail", name: "RETAIL", org_id: "global" },
    { id: "t_store", name: "STORES", org_id: "org-walmart" },
  ]);
  apiMock.listUsers.mockResolvedValue([]);
  apiMock.listRoles.mockResolvedValue({ roles: [] });
  apiMock.listBindings.mockResolvedValue([]);
});
afterEach(() => cleanup());

const tabNames = () => screen.getAllByRole("tab").map((t) => t.textContent);

describe("Identity & Access — the Provider organization", () => {
  it("has the same tabs as a customer organization", async () => {
    render(<IdentityAccess />);
    fireEvent.click(await screen.findByRole("button", { name: "WALMART" }));
    const orgTabs = tabNames();
    fireEvent.click(screen.getByRole("button", { name: /Organizations/ }));
    fireEvent.click(await screen.findByRole("button", { name: "Provider" }));
    expect(tabNames()).toEqual(orgTabs);
    expect(tabNames()).toEqual(expect.arrayContaining(["Users", "Access", "User Roles", "Custom User Roles", "External SSO Roles", "Security Settings", "Tenants"]));
  });

  it("its Tenants tab lists the Provider organization's tenants only", async () => {
    render(<IdentityAccess />);
    fireEvent.click(await screen.findByRole("button", { name: "Provider" }));
    fireEvent.click(screen.getByRole("tab", { name: "Tenants" }));
    expect(await screen.findByText("RETAIL")).toBeTruthy();
    expect(screen.queryByText("STORES")).toBeNull();
  });

  it("a customer organization's Tenants tab still lists its own tenants only", async () => {
    render(<IdentityAccess />);
    fireEvent.click(await screen.findByRole("button", { name: "WALMART" }));
    fireEvent.click(screen.getByRole("tab", { name: "Tenants" }));
    expect(await screen.findByText("STORES")).toBeTruthy();
    expect(screen.queryByText("RETAIL")).toBeNull();
  });
});
