// investigationUrl.test — the ?inv=<id> hash param that makes the embedded
// investigation drawer refresh/share-safe. Pure functions, exhaustive edges.

import { describe, it, expect } from "vitest";
import { invFromHash, hashWithInv, hashWithoutInv } from "./investigationUrl";

describe("investigation URL state", () => {
  it("reads the inv param from a hash", () => {
    expect(invFromHash("#/monitoring/appobs?inv=abc-123")).toBe("abc-123");
    expect(invFromHash("#/monitoring/appobs?foo=1&inv=abc")).toBe("abc");
    expect(invFromHash("#/monitoring/appobs")).toBe("");
    expect(invFromHash("")).toBe("");
  });

  it("sets the inv param, preserving path and other params", () => {
    expect(hashWithInv("#/monitoring/appobs", "x1")).toBe("#/monitoring/appobs?inv=x1");
    expect(hashWithInv("#/monitoring/appobs?foo=1", "x1")).toBe("#/monitoring/appobs?foo=1&inv=x1");
    // replaces an existing id
    expect(invFromHash(hashWithInv("#/p?inv=old", "new"))).toBe("new");
  });

  it("removes the inv param and drops an empty query", () => {
    expect(hashWithoutInv("#/monitoring/appobs?inv=x1")).toBe("#/monitoring/appobs");
    expect(hashWithoutInv("#/monitoring/appobs?foo=1&inv=x1")).toBe("#/monitoring/appobs?foo=1");
    expect(hashWithoutInv("#/monitoring/appobs")).toBe("#/monitoring/appobs");
  });

  it("round-trips ids that need URL encoding", () => {
    const id = "corr id/with?chars&=";
    expect(invFromHash(hashWithInv("#/p", id))).toBe(id);
  });
});
