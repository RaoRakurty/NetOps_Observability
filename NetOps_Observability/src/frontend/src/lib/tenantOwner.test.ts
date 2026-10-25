// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// tenantOwner (tracker 365) — the SPA's owner rule and the confirm text that
// would have stopped the 2026-10-25 deletion: a row owned by another tenant is
// named before anything happens to it.
import { describe, it, expect } from "vitest";
import {
  actingOwner, confirmText, foreignOwnerNote, isAllTenantsView, ownerOf, sameOwner, tenantLabel, tenantNames,
} from "./tenantOwner";

const NAMES = tenantNames([
  { tenant_id: "global", tenant_name: "Provider", org_id: "global", org_name: "Global", region: "" },
  { tenant_id: "t_retail", tenant_name: "RETAIL", org_id: "global", org_name: "Global", region: "us-east" },
]);

describe("owner rule", () => {
  it("treats no tenant and global as the one Provider owner", () => {
    expect(ownerOf(undefined)).toBe("global");
    expect(ownerOf("")).toBe("global");
    expect(ownerOf(" GLOBAL ")).toBe("global");
    expect(sameOwner("", "global")).toBe(true);
  });
  it("never collapses real tenants", () => {
    expect(sameOwner("t_retail", "global")).toBe(false);
    expect(sameOwner("t_retail", "")).toBe(false);
    expect(sameOwner("t_a", "t_b")).toBe(false);
  });
});

describe("tenantLabel", () => {
  it("names the Provider for a row with no tenant", () => {
    expect(tenantLabel(undefined, NAMES)).toBe("Provider");
    expect(tenantLabel("", {})).toBe("Provider");
  });
  it("names a tenant, or shows its id when no name is known", () => {
    expect(tenantLabel("t_retail", NAMES)).toBe("RETAIL");
    expect(tenantLabel("t_unknown", NAMES)).toBe("t_unknown");
  });
});

describe("the All-tenants view", () => {
  it("is cross-tenant with no scope selected, and only that", () => {
    expect(isAllTenantsView(true, "")).toBe(true);
    expect(isAllTenantsView(true, "global")).toBe(false);
    expect(isAllTenantsView(true, "t_retail")).toBe(false);
    expect(isAllTenantsView(false, "")).toBe(false);
  });
  it("acts as the Provider", () => {
    expect(actingOwner("")).toBe("global");
    expect(actingOwner("t_retail")).toBe("t_retail");
  });
});

describe("confirm text", () => {
  it("names the owning tenant when the row is another tenant's", () => {
    const txt = confirmText({
      verb: "Delete", name: "SDWAN", noun: "integration", rowTenant: "t_retail", activeScope: "", names: NAMES,
      consequence: "Checkpoints, health and state history go with it.",
    });
    expect(txt).toContain('Delete "SDWAN"?');
    expect(txt).toContain('This integration belongs to the tenant "RETAIL", not Provider.');
    expect(txt).toContain("The change affects RETAIL.");
    expect(txt).toContain("Checkpoints, health and state history go with it.");
  });
  it("stays plain for your own row", () => {
    const own = confirmText({ verb: "Delete", name: "Mine", noun: "integration", rowTenant: "global", activeScope: "", names: NAMES });
    expect(own).toBe('Delete "Mine"?');
    const blank = confirmText({ verb: "Delete", name: "Mine", noun: "integration", rowTenant: undefined, activeScope: "global", names: NAMES });
    expect(blank).toBe('Delete "Mine"?');
  });
  it("names the Provider when a tenant scope meets a Provider row", () => {
    expect(foreignOwnerNote("global", "t_retail", NAMES, "integration"))
      .toBe('This integration belongs to the tenant "Provider", not RETAIL.');
    expect(foreignOwnerNote("t_retail", "t_retail", NAMES, "integration")).toBeNull();
  });
});
