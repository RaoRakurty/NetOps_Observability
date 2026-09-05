// App-ID coverage + override editor: pure-helper contracts.
//
// The load-bearing one is readCount/unavailableReason: -1 is the engine's
// UNKNOWN sentinel and must never collapse into "none".

import { describe, expect, it } from "vitest";
import type { AppCatalogEntry } from "../../services/api";
import {
  EMPTY_OVERRIDE_DRAFT, MATCH_KIND_LABELS, OPERATOR_CLASS, UNKNOWN_COUNT,
  deleteOverridePrompt, isIPv4CidrToken, overrideInput, precedenceOrigin,
  precedenceRows, readCount, sortOverrides, unavailableReason, validateOverride,
} from "./appIdCoverage";

describe("readCount (the -1 UNKNOWN sentinel)", () => {
  it("reads a real count as itself", () => {
    expect(readCount(0)).toEqual({ known: true, value: 0, text: "0" });
    expect(readCount(7)).toEqual({ known: true, value: 7, text: "7" });
    expect(readCount(1234).text).toBe((1234).toLocaleString());
  });
  it("never renders -1 as zero or as none", () => {
    const r = readCount(UNKNOWN_COUNT);
    expect(r.known).toBe(false);
    expect(r.text).toBe("unknown");
    expect(r.text).not.toMatch(/0|none/i);
  });
  it("treats any other nonsense as unknown rather than inventing a number", () => {
    expect(readCount(-42).known).toBe(false);
    expect(readCount(Number.NaN).known).toBe(false);
    expect(readCount(Number.POSITIVE_INFINITY).known).toBe(false);
  });
});

describe("unavailableReason (why the count is unknown)", () => {
  it("explains the unknown when the store did not answer", () => {
    const why = unavailableReason({ tenant_overrides: -1, tenant_overrides_unavailable: true });
    expect(why).toMatch(/could not read the operator override store/);
    expect(why).toMatch(/not a statement that this tenant has none/);
  });
  it("fires on the sentinel even without the flag, and on the flag even without the sentinel", () => {
    expect(unavailableReason({ tenant_overrides: -1 })).not.toBeNull();
    expect(unavailableReason({ tenant_overrides: 3, tenant_overrides_unavailable: true })).not.toBeNull();
  });
  it("stays silent when the store answered — including a true zero", () => {
    expect(unavailableReason({ tenant_overrides: 0 })).toBeNull();
    expect(unavailableReason({ tenant_overrides: 12 })).toBeNull();
  });
});

describe("precedenceRows (the active ladder, highest first)", () => {
  it("labels known classes, ranks them, and marks the operator layer", () => {
    const rows = precedenceRows(["operator", "cloud_tag", "domain"]);
    expect(rows.map((r) => r.rank)).toEqual([1, 2, 3]);
    expect(rows[0]).toMatchObject({ cls: OPERATOR_CLASS, isOperator: true });
    expect(rows[0].label).toMatch(/Operator catalog/);
    expect(rows[1].isOperator).toBe(false);
  });
  it("shows an unlabelled class by its raw name rather than hiding it", () => {
    expect(precedenceRows(["brand_new_source"])[0].label).toBe("brand_new_source");
  });
  it("names where the order came from", () => {
    expect(precedenceOrigin(true)).toBe("platform default order");
    expect(precedenceOrigin(false)).toBe("tenant order");
  });
});

describe("isIPv4CidrToken (mirror of appid.catalogIsCIDRToken)", () => {
  it("accepts bare addresses and masked prefixes", () => {
    expect(isIPv4CidrToken("10.0.0.1")).toBe(true);
    expect(isIPv4CidrToken("52.96.0.0/12")).toBe(true);
    expect(isIPv4CidrToken("0.0.0.0/0")).toBe(true);
    expect(isIPv4CidrToken("255.255.255.255/32")).toBe(true);
  });
  it("rejects bad octets, bad masks, leading zeros and IPv6", () => {
    expect(isIPv4CidrToken("10.0.0.256")).toBe(false);
    expect(isIPv4CidrToken("10.0.0.1/33")).toBe(false);
    expect(isIPv4CidrToken("10.0.0.01")).toBe(false);
    expect(isIPv4CidrToken("10.0.0")).toBe(false);
    expect(isIPv4CidrToken("2001:db8::1")).toBe(false);
    expect(isIPv4CidrToken("")).toBe(false);
  });
});

describe("validateOverride (mirror of appid.ValidateCatalogInput + the confidence CHECK)", () => {
  const draft = (over: Partial<typeof EMPTY_OVERRIDE_DRAFT> = {}) => ({ ...EMPTY_OVERRIDE_DRAFT, ...over });

  it("accepts a well-formed entry of each kind", () => {
    expect(validateOverride(draft({ match_kind: "prefix", match_value: "52.96.0.0/12", app_label: "Microsoft 365" }))).toBe("");
    expect(validateOverride(draft({ match_kind: "domain", match_value: "teams.microsoft.com", app_label: "Teams" }))).toBe("");
    expect(validateOverride(draft({ match_kind: "asn", match_value: "8075", app_label: "Microsoft" }))).toBe("");
    expect(validateOverride(draft({ match_kind: "port", match_value: "3389", app_label: "Remote desktop" }))).toBe("");
    expect(validateOverride(draft({ match_kind: "port", match_value: "0", app_label: "x" }))).toBe("");
  });
  it("requires a match value and an application name", () => {
    expect(validateOverride(draft({ match_value: "  ", app_label: "x" }))).toMatch(/match value is required/);
    expect(validateOverride(draft({ match_value: "10.0.0.0/8", app_label: "  " }))).toMatch(/application name is required/);
  });
  it("holds the per-kind rules the server holds", () => {
    expect(validateOverride(draft({ match_kind: "prefix", match_value: "not-an-address", app_label: "x" })))
      .toMatch(/valid IPv4 address or CIDR/);
    expect(validateOverride(draft({ match_kind: "port", match_value: "70000", app_label: "x" })))
      .toMatch(/0 to 65535/);
    expect(validateOverride(draft({ match_kind: "port", match_value: "https", app_label: "x" })))
      .toMatch(/0 to 65535/);
    expect(validateOverride(draft({ match_kind: "nonsense", match_value: "x", app_label: "x" })))
      .toMatch(/what this override matches on/);
  });
  it("bounds confidence to 0..1 and treats blank as the engine's own default", () => {
    const base = { match_kind: "domain", match_value: "example.com", app_label: "x" };
    expect(validateOverride(draft({ ...base, confidence: "" }))).toBe("");
    expect(validateOverride(draft({ ...base, confidence: "0.75" }))).toBe("");
    expect(validateOverride(draft({ ...base, confidence: "1.5" }))).toMatch(/between 0 and 1/);
    expect(validateOverride(draft({ ...base, confidence: "-0.1" }))).toMatch(/between 0 and 1/);
    expect(validateOverride(draft({ ...base, confidence: "high" }))).toMatch(/between 0 and 1/);
  });
  it("offers every match kind the server accepts, and no others", () => {
    expect(Object.keys(MATCH_KIND_LABELS).sort()).toEqual(["asn", "domain", "port", "prefix"]);
  });
});

describe("overrideInput (the POST body)", () => {
  it("trims, and never carries a tenant — the server stamps it from the token", () => {
    const body = overrideInput({ match_kind: "prefix", match_value: " 10.0.0.0/8 ", app_label: " Billing ", confidence: "" });
    expect(body).toEqual({ match_kind: "prefix", match_value: "10.0.0.0/8", app_label: "Billing" });
    expect(Object.keys(body)).not.toContain("tenant_id");
  });
  it("sends confidence only when the operator set one", () => {
    expect(overrideInput({ match_kind: "asn", match_value: "8075", app_label: "x", confidence: "0.9" }).confidence).toBe(0.9);
    expect(overrideInput({ match_kind: "asn", match_value: "8075", app_label: "x", confidence: " " }).confidence).toBeUndefined();
  });
});

describe("override list rendering helpers", () => {
  const entry = (over: Partial<AppCatalogEntry>): AppCatalogEntry => ({
    catalog_id: "c1", tenant_id: "t", match_kind: "prefix", match_value: "10.0.0.0/8",
    app_label: "Billing", confidence: 0.9, source: "manual", version: 1,
    created_at: "2026-09-01T00:00:00Z", ...over,
  });
  it("sorts newest first without mutating the input", () => {
    const rows = [entry({ catalog_id: "old", created_at: "2026-01-01T00:00:00Z" }),
      entry({ catalog_id: "new", created_at: "2026-09-01T00:00:00Z" })];
    expect(sortOverrides(rows).map((r) => r.catalog_id)).toEqual(["new", "old"]);
    expect(rows[0].catalog_id).toBe("old");
  });
  it("confirms a delete by naming the row and the consequence", () => {
    const p = deleteOverridePrompt({ app_label: "Billing", match_value: "10.0.0.0/8" });
    expect(p).toContain("10.0.0.0/8");
    expect(p).toContain("Billing");
    expect(p).toMatch(/falls back to the next source/);
  });
});
