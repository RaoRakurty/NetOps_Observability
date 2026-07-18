// catalog.ts — the pure logic behind the Service Catalog UI: criticality
// ranking, mapping counts, the name-keyed join, and the client-side mirror of
// the backend form bounds.

import { describe, it, expect } from "vitest";
import type { BusinessServiceRow, ResourceMappingRow } from "../../services/api";
import { criticalityRank, mappingCounts, catalogByName, nameKey, safeRunbookUrl, validateServiceForm } from "./catalog";

const svc = (over: Partial<BusinessServiceRow>): BusinessServiceRow => ({
  business_service_id: "b1", tenant_id: "t", name: "payments", description: "",
  criticality: "normal", owner: "", runbook_url: "", created_by: "u", created_at: "", updated_at: "",
  ...over,
});
const map = (over: Partial<ResourceMappingRow>): ResourceMappingRow => ({
  tenant_id: "t", resource_id: "r", service_name: "payments", source: "manual",
  confidence: "confirmed", basis: "operator assignment", is_manual_override: true,
  created_by: "u", created_at: "", updated_at: "",
  ...over,
});

describe("criticalityRank", () => {
  it("orders worst-first and puts unset last", () => {
    expect(criticalityRank("critical")).toBeLessThan(criticalityRank("high"));
    expect(criticalityRank("high")).toBeLessThan(criticalityRank("normal"));
    expect(criticalityRank("normal")).toBeLessThan(criticalityRank("low"));
    expect(criticalityRank("")).toBeGreaterThan(criticalityRank("low"));
    expect(criticalityRank("bogus")).toBeGreaterThan(criticalityRank("low"));
  });
});

describe("mappingCounts", () => {
  it("counts by service id when bound, by name key otherwise", () => {
    const counts = mappingCounts([
      map({ resource_id: "r1", business_service_id: "b1" }),
      map({ resource_id: "r2", business_service_id: "b1" }),
      map({ resource_id: "r3", service_name: "Legacy CRM" }), // unbound → name key
    ]);
    expect(counts.get("b1")).toBe(2);
    expect(counts.get(nameKey("Legacy CRM"))).toBe(1);
  });
});

describe("catalogByName", () => {
  it("joins case-insensitively on the trimmed name", () => {
    const idx = catalogByName([svc({ name: "Payments", criticality: "critical" })]);
    expect(idx.get(nameKey(" payments "))?.criticality).toBe("critical");
    expect(idx.get(nameKey("checkout"))).toBeUndefined();
  });
});

describe("validateServiceForm", () => {
  it("accepts a normal form and an empty owner", () => {
    expect(validateServiceForm({ name: "payments", owner: "" })).toBe("");
    expect(validateServiceForm({ name: "payments", owner: "payments-sre" })).toBe("");
  });
  it("rejects a missing/oversized/control-char name and an invalid owner", () => {
    expect(validateServiceForm({ name: "   ", owner: "" })).toMatch(/required/);
    expect(validateServiceForm({ name: "a".repeat(129), owner: "" })).toMatch(/128/);
    expect(validateServiceForm({ name: "two\nlines", owner: "" })).toMatch(/single line/);
    expect(validateServiceForm({ name: "ok", owner: "two\nlines" })).toMatch(/owner/);
    expect(validateServiceForm({ name: "ok", owner: "a".repeat(129) })).toMatch(/owner/);
  });
  it("accepts an empty or https runbook link, rejects anything else", () => {
    expect(validateServiceForm({ name: "ok", owner: "", runbook: "" })).toBe("");
    expect(validateServiceForm({ name: "ok", owner: "", runbook: "https://wiki.corp/runbooks/pay" })).toBe("");
    expect(validateServiceForm({ name: "ok", owner: "", runbook: "http://wiki.corp/pay" })).toMatch(/https/);
    expect(validateServiceForm({ name: "ok", owner: "", runbook: "not a url" })).toMatch(/https/);
  });
});

describe("safeRunbookUrl (zero-trust href gate)", () => {
  it("passes only bounded absolute https URLs", () => {
    expect(safeRunbookUrl("https://runbooks.example.com/payments")).toBe("https://runbooks.example.com/payments");
    expect(safeRunbookUrl(" https://runbooks.example.com/x ")).toBe("https://runbooks.example.com/x");
  });
  it("drops unset, non-https, script schemes, relative and oversized values", () => {
    expect(safeRunbookUrl(undefined)).toBe("");
    expect(safeRunbookUrl("")).toBe("");
    expect(safeRunbookUrl("http://runbooks.example.com/x")).toBe("");
    expect(safeRunbookUrl("javascript:alert(1)")).toBe("");
    expect(safeRunbookUrl("data:text/html,x")).toBe("");
    expect(safeRunbookUrl("/relative/runbook")).toBe("");
    expect(safeRunbookUrl("https://runbooks.example.com/" + "a".repeat(512))).toBe("");
  });
});
